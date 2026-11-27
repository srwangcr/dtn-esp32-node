#![no_std]
#![no_main]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is generally not safe to do with esp_hal types, especially those \
    holding buffers for the duration of a data transfer."
)]
#![deny(clippy::large_stack_frames)]

use dtn_core::bpsec::{BibScope, BibSigner, BibVerifier};
use dtn_core::cla::reliable::{ReliableSerialCla, RxEvent};
use dtn_core::processor::fragmentation::ReassemblySlot;
use dtn_core::processor::pipeline::{IngestionPipeline, RouteDecision};
use dtn_core::routing::interval_tree::{CgrIntervalTree, ContactInterval};
use dtn_core::storage::outbound::OutboundBundleQueue;
use dtn_core::storage::wal::{
    read_page, scan_pages, scan_wal_ring, wal_slot_offset, DirectWal, PAGE_SIZE, WAL_SECTOR_COUNT,
};
use dtn_core::telemetry::metrics::SystemMetrics;
use esp_backtrace as _;
use esp_hal::clock::CpuClock;
use esp_hal::main;
use esp_hal::time::{Duration, Instant};
use esp_hal::uart::{Config as UartConfig, Uart};
use esp_storage::FlashStorage;
use log::{info, warn};

#[cfg(feature = "stress-test")]
mod stress;

esp_bootloader_esp_idf::esp_app_desc!();

/// Clave simétrica del banco de pruebas BPSec (RFC 9173 BIB-HMAC-SHA2).
const DEMO_KEY: [u8; 32] = [0x42; 32];

/// Timeout del ARQ Stop-and-Wait sobre UART2, en microsegundos de tick inyectado.
const LINK_TIMEOUT_US: u64 = 50_000;

/// Reintentos antes de declarar fallo de enlace y retener el bundle en el WAL.
const MAX_LINK_RETRIES: u8 = 3;

/// Salto por defecto del plan de contactos para bundles recuperados del WAL.
const DEFAULT_NEXT_HOP: u32 = 42;

/// Bundle BPv7 mínimo para auto-validación en arranque.
const TEST_BUNDLE: &[u8] = &[
    0x9f, 0x88, 0x07, 0x00, 0x00, 0x82, 0x01, 0x00, 0x82, 0x01, 0x00, 0x82, 0x01, 0x00, 0x82,
    0x00, 0x01, 0x19, 0xea, 0x60, 0x85, 0x01, 0x01, 0x00, 0x00, 0x41, 0x58, 0xff,
];

/// Erase + write + read-back de un sector del anillo WAL (4 KiB) en NOR Flash.
///
/// El ACK del ARQ **no** puede prepararse hasta que esta función confirma que
/// la página contiene el magic, la secuencia y el CRC32C esperados. El buffer
/// `verify` es distinto de `page`, así que la comparación es contra los bytes
/// leídos realmente de Flash y no contra la copia en SRAM.
fn write_and_verify_wal_sector(
    flash: &mut FlashStorage<'_>,
    page: &[u8; PAGE_SIZE],
    verify: &mut [u8; PAGE_SIZE],
    slot: usize,
) -> bool {
    let expected = match read_page(page) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };
    let offset = wal_slot_offset(slot);
    if flash.erase(offset, offset + PAGE_SIZE as u32).is_err() {
        return false;
    }
    if flash.write(offset, page).is_err() {
        return false;
    }
    if flash.read(offset, verify).is_err() {
        return false;
    }

    let mut visits = 0usize;
    let mut payload_matches = false;
    let (report, valid, last_seq) = scan_pages(core::slice::from_ref(&*verify), &mut |payload| {
        visits += 1;
        if payload == expected.1 {
            payload_matches = true;
        }
    });
    report.pages_valid == 1
        && valid == 1
        && last_seq == expected.0
        && visits == 1
        && payload_matches
}

/// Persiste las páginas selladas rotando el sector del anillo.
///
/// Reutiliza los dos únicos buffers de 4096 B del llamador (escritura y
/// read-back): no hay copias adicionales en stack. `release_ready()` se llama
/// **solo** después de verificar la página recién escrita.
fn persist_ready_pages(
    wal: &mut DirectWal<1>,
    page: &mut [u8; PAGE_SIZE],
    verify: &mut [u8; PAGE_SIZE],
    flash: &mut FlashStorage<'_>,
    next_slot: &mut usize,
) -> bool {
    if wal.full_pages() == 0 {
        return true;
    }
    if !wal.write_first_sealed_page(page) {
        return false;
    }
    let slot = *next_slot;
    if !write_and_verify_wal_sector(flash, page, verify, slot) {
        return false; // la página sigue en el WAL: se reintentará en el próximo ciclo
    }
    *next_slot = (slot + 1) % WAL_SECTOR_COUNT;
    wal.release_ready();
    true
}

#[allow(
    clippy::large_stack_frames,
    reason = "Static DTN buffers live on the main stack; the two 4096 B page buffers are shared by boot scan, write and verified read-back"
)]
#[main]
fn main() -> ! {
    esp_println::logger::init_logger_from_env();

    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    // 1. Flash SPI, Crash-Recovery y reinyección de bundles recuperados.
    //    La cola estática se crea ANTES del escaneo para que cada registro
    //    válido vuelva a entrar en el pipeline de reenvío con su next_hop.
    let mut flash = FlashStorage::new(peripherals.FLASH);
    let mut flash_page = [0u8; PAGE_SIZE];
    let mut verify_page = [0u8; PAGE_SIZE];
    let mut outbound = OutboundBundleQueue::<16, 256>::new();
    let mut recovered_count = 0usize;
    let mut reinjected_count = 0usize;
    let recovery = scan_wal_ring(
        |slot, page| flash.read(wal_slot_offset(slot), page).is_ok(),
        &mut |slot, seq, record| {
            recovered_count += 1;
            info!(
                "[BOOT] Bundle recuperado slot={} seq={} ({} bytes)",
                slot,
                seq,
                record.len()
            );
            match outbound.enqueue(u64::from(DEFAULT_NEXT_HOP), record) {
                Ok(()) => reinjected_count += 1,
                Err(e) => warn!("[BOOT] No se pudo reinyectar bundle recuperado: {:?}", e),
            }
        },
    );
    info!(
        "[BOOT] Crash-Recovery anillo WAL (0x{:X}..0x{:X}): validos={} descartados={} recuperados={} reinyectados={} max_seq={} active_slot={} -> next_slot={}",
        wal_slot_offset(0),
        wal_slot_offset(WAL_SECTOR_COUNT - 1) + PAGE_SIZE as u32 - 1,
        recovery.pages_valid,
        recovery.pages_discarded,
        recovered_count,
        reinjected_count,
        recovery.max_seq,
        recovery.active_slot,
        recovery.next_write_slot
    );
    let mut next_slot = recovery.next_write_slot;

    // 2. UART2 en GPIO16 (RX) / GPIO17 (TX) a 115200 bps.
    let uart_config = UartConfig::default().with_baudrate(115_200);
    let mut uart = Uart::new(peripherals.UART2, uart_config)
        .expect("Failed to init UART2")
        .with_rx(peripherals.GPIO16)
        .with_tx(peripherals.GPIO17);

    // 3. Estructuras estáticas zero-allocation.
    let mut router = CgrIntervalTree::<8>::new();
    let mut wal = DirectWal::<1>::new();
    wal.set_next_sequence(recovery.max_seq.wrapping_add(1));
    let mut reassembly = ReassemblySlot::<128>::new();
    let metrics = SystemMetrics::new();

    // CLA confiable: RX=256, TX=288 (COBS del mensaje de 256 B), payload=256
    // incluyendo la cabecera de enlace de 3 bytes.
    let mut link = ReliableSerialCla::<256, 288, 256>::new(LINK_TIMEOUT_US, MAX_LINK_RETRIES);
    let verifier = BibVerifier::opportunistic(DEMO_KEY);
    let signer = BibSigner::new(DEMO_KEY, BibScope::PrimaryAndPayload);
    let mut signed_bundle = [0u8; 128];
    let signed_len = match signer.attach(TEST_BUNDLE, &mut signed_bundle) {
        Ok(len) => len,
        Err(e) => {
            warn!("[BPSEC] No se pudo firmar el bundle de prueba: {:?}", e);
            0
        }
    };
    let signed_bundle = &signed_bundle[..signed_len];

    // 4. Auto-test en silicio: Store-and-Forward con BIB + WAL + NOR Flash.
    let t0 = Instant::now();
    let decision = IngestionPipeline::ingest_and_route_with_security::<8, 16, 256, 128, 1>(
        signed_bundle,
        1_000,
        &router,
        &mut outbound,
        Some(&mut reassembly),
        Some(&mut wal),
        Some(&metrics),
        Some(&verifier),
    );
    let elapsed_us = t0.elapsed().as_micros();
    info!(
        "[SELF-TEST] Pipeline Xtensa 240MHz + BPSec BIB-HMAC-SHA2 completado en {} us -> {:?}",
        elapsed_us, decision
    );
    if persist_ready_pages(
        &mut wal,
        &mut flash_page,
        &mut verify_page,
        &mut flash,
        &mut next_slot,
    ) {
        info!(
            "[FLASH] Página WAL (4096 B + CRC32C) verificada en sector {}",
            (next_slot + WAL_SECTOR_COUNT - 1) % WAL_SECTOR_COUNT
        );
    } else {
        warn!("[FLASH] No se pudo persistir/verificar la página WAL sellada");
    }

    #[cfg(feature = "stress-test")]
    stress::run_hardware_stress_suite(
        &mut flash,
        &mut uart,
        signed_bundle,
        &verifier,
        &mut flash_page,
        &mut verify_page,
        &mut next_slot,
    );

    let _ = router.insert(ContactInterval::new(0, 86_400, DEFAULT_NEXT_HOP));
    info!(
        "[READY] UART2 (GPIO16 RX / GPIO17 TX): COBS + Stop-and-Wait ARQ + BPSec BIB-HMAC-SHA2; WAL ring next_slot={}, cola={}",
        next_slot,
        outbound.len()
    );

    let boot_instant = Instant::now();
    let mut rx_byte = [0u8; 1];
    let mut rx_buf = [0u8; 256];
    let mut last_bundle_len = 0usize;
    let mut last_committed: Option<(u16, usize)> = None;
    let mut ack_buf = [0u8; 8];
    let mut last_report = Instant::now();

    loop {
        let now_us = boot_instant.elapsed().as_micros();

        if let Ok(1) = uart.read_buffered(&mut rx_byte) {
            match link.push_byte(rx_byte[0], now_us) {
                Ok(Some(RxEvent::Data { seq, payload_len })) => {
                    // Copiamos el payload antes de cualquier ACK: la decisión
                    // de confirmar depende del resultado del pipeline y de la
                    // verificación en Flash.
                    let payload = link.rx_payload();
                    let n = payload.len().min(rx_buf.len());
                    rx_buf[..n].copy_from_slice(&payload[..n]);
                    last_bundle_len = n;

                    let t_in = Instant::now();
                    // El WAL se gestiona explícitamente abajo: exactamente un
                    // registro persistido y verificado por bundle aceptado.
                    let res = IngestionPipeline::ingest_and_route_with_security::<
                        8,
                        16,
                        256,
                        128,
                        1,
                    >(
                        &rx_buf[..n],
                        now_us / 1_000,
                        &router,
                        &mut outbound,
                        Some(&mut reassembly),
                        None,
                        Some(&metrics),
                        Some(&verifier),
                    );
                    let dt_us = t_in.elapsed().as_micros();

                    let accepted = matches!(
                        res,
                        RouteDecision::ForwardNextHop { .. }
                            | RouteDecision::StoreLocal
                            | RouteDecision::PersistedToWal
                            | RouteDecision::PendingReassembly
                    );
                    let durable = accepted
                        && n == payload_len
                        && wal.append(&rx_buf[..n]).is_ok()
                        && persist_ready_pages(
                            &mut wal,
                            &mut flash_page,
                            &mut verify_page,
                            &mut flash,
                            &mut next_slot,
                        );

                    if durable {
                        if let Err(e) = link.commit_rx_ack() {
                            warn!("[ARQ] No se pudo preparar ACK seq={}: {:?}", seq, e);
                        } else {
                            last_committed = Some((seq, n));
                            let ack_len = link.encoded_frame().len().min(ack_buf.len());
                            ack_buf[..ack_len].copy_from_slice(&link.encoded_frame()[..ack_len]);
                            let _ = uart.write(&ack_buf[..ack_len]);
                        }
                        info!(
                            "[RX] ACK durable seq={} -> {:?} ({} B en {} us, payload_len={})",
                            seq, res, n, dt_us, payload_len
                        );
                    } else {
                        last_committed = None;
                        if let Err(e) = link.reject_rx_nack() {
                            warn!("[ARQ] No se pudo preparar NACK seq={}: {:?}", seq, e);
                        }
                        let ack_len = link.encoded_frame().len().min(ack_buf.len());
                        ack_buf[..ack_len].copy_from_slice(&link.encoded_frame()[..ack_len]);
                        let _ = uart.write(&ack_buf[..ack_len]);
                        warn!(
                            "[RX] NACK seq={}: decisión={:?} o persistencia/verificación fallida ({} B en {} us)",
                            seq, res, n, dt_us
                        );
                    }
                }
                Ok(Some(RxEvent::DuplicateData { seq, payload_len })) => {
                    // Un duplicado solo se confirma si los bytes coinciden con
                    // un bundle ya persistido y verificado en esta sesión.
                    let payload = link.rx_payload();
                    let same = last_committed == Some((seq, payload_len))
                        && payload.len() == last_bundle_len
                        && payload == &rx_buf[..last_bundle_len];
                    if same {
                        let _ = link.commit_rx_ack();
                        info!("[ARQ] Duplicado seq={} -> ACK confirmado por WAL verificado", seq);
                    } else {
                        let _ = link.reject_rx_nack();
                        warn!("[ARQ] Duplicado seq={} -> NACK (sin registro durable)", seq);
                    }
                    let ack_len = link.encoded_frame().len().min(ack_buf.len());
                    ack_buf[..ack_len].copy_from_slice(&link.encoded_frame()[..ack_len]);
                    let _ = uart.write(&ack_buf[..ack_len]);
                }
                Ok(Some(RxEvent::Ack { seq })) => {
                    info!("[ARQ] ACK seq={} recibido -> state={:?}", seq, link.state());
                }
                Ok(Some(RxEvent::Nack { seq })) => {
                    info!(
                        "[ARQ] NACK seq={} -> retransmisión inmediata (retries={})",
                        seq,
                        link.retries()
                    );
                    if link.retries() > 0 {
                        let _ = uart.write(link.encoded_frame());
                    }
                }
                Ok(Some(RxEvent::OutOfWindow { seq, expected })) => {
                    warn!("[ARQ] Frame seq={} fuera de ventana (esperado={}) -> NACK", seq, expected);
                    let ack_len = link.encoded_frame().len().min(ack_buf.len());
                    ack_buf[..ack_len].copy_from_slice(&link.encoded_frame()[..ack_len]);
                    let _ = uart.write(&ack_buf[..ack_len]);
                }
                Ok(Some(RxEvent::Invalid)) => warn!("[ARQ] Trama de enlace inválida descartada"),
                Ok(None) => {}
                Err(e) => warn!("[ARQ] Error de framing COBS: {:?}", e),
            }
        }

        // Reenvío real: se envían los bytes completos del bundle BPv7 con su
        // next_hop. El slot solo se libera después de copiarlos en el CLA.
        if link.state() == dtn_core::cla::reliable::ArqState::Idle
            && let Some((next_hop, bundle)) = outbound.front_parts()
        {
            match link.send(bundle, now_us) {
                Ok(()) => {
                    let _ = uart.write(link.encoded_frame());
                    info!(
                        "[TX] BPv7 completo ({} B) encolado para next_hop={} -> UART2",
                        bundle.len(),
                        next_hop
                    );
                    outbound.pop();
                }
                Err(e) => warn!("[TX] No se pudo enviar bundle (next_hop={}): {:?}", next_hop, e),
            }
        }

        if link.on_tick(now_us) {
            info!("[ARQ] Timeout -> retransmitiendo seq={}", link.seq_id());
            let _ = uart.write(link.encoded_frame());
        }

        if last_report.elapsed() >= Duration::from_secs(5) {
            let snap = metrics.snapshot();
            info!(
                "[TELEMETRY] processed={} dropped={} avg_latency_ns={} arq_failures={} outbound={}",
                snap.packets_processed,
                snap.packets_dropped,
                snap.latency_avg_ns,
                link.failures(),
                outbound.len()
            );
            last_report = Instant::now();
        }
    }
}
