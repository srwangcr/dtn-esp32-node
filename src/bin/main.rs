#![no_std]
#![no_main]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is generally not safe to do with esp_hal types, especially those \
    holding buffers for the duration of a data transfer."
)]
#![deny(clippy::large_stack_frames)]

use dtn_core::bpsec::{BibScope, BibSigner, BibVerifier, SecurityContext};
use dtn_core::cla::reliable::{ReliableSerialCla, RxEvent};
use dtn_core::processor::fragmentation::ReassemblySlot;
use dtn_core::processor::pipeline::{IngestionPipeline, RouteDecision};
use dtn_core::routing::interval_tree::{CgrIntervalTree, ContactInterval};
use dtn_core::storage::ring_buffer::LockFreeRingBuffer;
use dtn_core::storage::wal::{
    scan_wal_ring, wal_slot_offset, DirectWal, PAGE_SIZE, WAL_SECTOR_COUNT,
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

/// Clave simétrica del banco de pruebas BPSec (HMAC-SHA-256).
const DEMO_KEY: [u8; 32] = [0x42; 32];

/// Timeout del ARQ Stop-and-Wait sobre UART2, en microsegundos de tick inyectado.
const LINK_TIMEOUT_US: u64 = 50_000;

/// Reintentos antes de declarar fallo de enlace y retener el bundle en el WAL.
const MAX_LINK_RETRIES: u8 = 3;

/// Bundle BPv7 mínimo para auto-validación en arranque.
const TEST_BUNDLE: &[u8] = &[
    0x9f, 0x88, 0x07, 0x00, 0x00, 0x82, 0x01, 0x00, 0x82, 0x01, 0x00, 0x82, 0x01, 0x00, 0x82,
    0x00, 0x01, 0x19, 0xea, 0x60, 0x85, 0x01, 0x01, 0x00, 0x00, 0x41, 0x58, 0xff,
];

/// Erase + write de un sector del anillo WAL (4 KiB) en NOR Flash.
fn write_wal_sector(flash: &mut FlashStorage<'_>, page: &[u8; PAGE_SIZE], slot: usize) -> bool {
    let offset = wal_slot_offset(slot);
    if flash.erase(offset, offset + PAGE_SIZE as u32).is_err() {
        return false;
    }
    flash.write(offset, page).is_ok()
}

/// Persiste las páginas selladas rotando el sector del anillo.
///
/// Reutiliza el único buffer de 4096 B del llamador: no hay copias adicionales
/// en stack y los otros 15 sectores quedan intactos (wear-leveling 16x).
fn persist_ready_pages(
    wal: &mut DirectWal<1>,
    page: &mut [u8; PAGE_SIZE],
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
    if !write_wal_sector(flash, page, slot) {
        return false; // el page sigue en el WAL: se reintentará en el próximo ciclo
    }
    *next_slot = (slot + 1) % WAL_SECTOR_COUNT;
    wal.release_ready();
    true
}

#[allow(
    clippy::large_stack_frames,
    reason = "Static DTN buffers (<5 KB) live on main stack; the single 4096 B page is shared by boot scan and WAL flush"
)]
#[main]
fn main() -> ! {
    esp_println::logger::init_logger_from_env();

    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    // 1. Flash SPI y Crash-Recovery del anillo circular de 16 sectores (64 KB).
    //    Un único buffer de 4096 B se reutiliza en las dos pasadas del escaneo.
    let mut flash = FlashStorage::new(peripherals.FLASH);
    let mut flash_page = [0u8; PAGE_SIZE];
    let mut recovered_count = 0usize;
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
        },
    );
    info!(
        "[BOOT] Crash-Recovery anillo WAL (0x{:X}..0x{:X}): validos={} descartados={} recuperados={} max_seq={} active_slot={} -> next_slot={}",
        wal_slot_offset(0),
        wal_slot_offset(WAL_SECTOR_COUNT - 1) + PAGE_SIZE as u32 - 1,
        recovery.pages_valid,
        recovery.pages_discarded,
        recovered_count,
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

    // 3. Estructuras estáticas zero-allocation (< 5 KB SRAM).
    let mut router = CgrIntervalTree::<8>::new();
    let mut ring = LockFreeRingBuffer::<16>::new();
    let (mut producer, mut consumer) = ring.split();
    let mut wal = DirectWal::<1>::new();
    wal.set_next_sequence(recovery.max_seq.wrapping_add(1));
    let mut reassembly = ReassemblySlot::<128>::new();
    let metrics = SystemMetrics::new();

    // CLA confiable: RX=256, TX=288 (COBS del mensaje de 256 B), payload=256
    // incluyendo la cabecera de enlace de 3 bytes.
    let mut link = ReliableSerialCla::<256, 288, 256>::new(LINK_TIMEOUT_US, MAX_LINK_RETRIES);
    let verifier = BibVerifier::opportunistic(DEMO_KEY);
    let signer = BibSigner::new(DEMO_KEY, SecurityContext::HmacSha256, BibScope::PrimaryAndPayload);
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
    let decision = IngestionPipeline::ingest_and_route_with_security::<8, 16, 128, 1>(
        signed_bundle,
        1_000,
        &router,
        &mut producer,
        Some(&mut reassembly),
        Some(&mut wal),
        Some(&metrics),
        Some(&verifier),
    );
    let elapsed_us = t0.elapsed().as_micros();
    info!(
        "[SELF-TEST] Pipeline Xtensa 240MHz + BPSec BIB completado en {} us -> {:?}",
        elapsed_us, decision
    );
    if persist_ready_pages(&mut wal, &mut flash_page, &mut flash, &mut next_slot) {
        info!(
            "[FLASH] Página WAL (4096 B + CRC32C) escrita en sector {} del anillo",
            (next_slot + WAL_SECTOR_COUNT - 1) % WAL_SECTOR_COUNT
        );
    } else {
        warn!("[FLASH] No se pudo persistir la página WAL sellada");
    }

    #[cfg(feature = "stress-test")]
    stress::run_hardware_stress_suite(
        &mut flash,
        &mut uart,
        signed_bundle,
        &verifier,
        &mut next_slot,
    );

    let _ = router.insert(ContactInterval::new(0, 86_400, 42));
    info!(
        "[READY] UART2 (GPIO16 RX / GPIO17 TX): COBS + Stop-and-Wait ARQ + BPSec BIB; WAL ring next_slot={}",
        next_slot
    );

    let boot_instant = Instant::now();
    let mut rx_byte = [0u8; 1];
    let mut rx_buf = [0u8; 256];
    let mut ack_buf = [0u8; 8];
    let mut out = [0u8; 16];
    let mut last_report = Instant::now();

    loop {
        let now_us = boot_instant.elapsed().as_micros();

        if let Ok(1) = uart.read_buffered(&mut rx_byte) {
            match link.push_byte(rx_byte[0], now_us) {
                Ok(Some(RxEvent::Data { seq, payload_len })) => {
                    // Copiamos el payload antes de preparar el ACK: ambos viven
                    // en buffers distintos del CLA y no se solapan.
                    let payload = link.rx_payload();
                    let n = payload.len().min(rx_buf.len());
                    rx_buf[..n].copy_from_slice(&payload[..n]);

                    let t_in = Instant::now();
                    let res = IngestionPipeline::ingest_and_route_with_security::<8, 16, 128, 1>(
                        &rx_buf[..n],
                        now_us / 1_000,
                        &router,
                        &mut producer,
                        Some(&mut reassembly),
                        Some(&mut wal),
                        Some(&metrics),
                        Some(&verifier),
                    );
                    let dt_us = t_in.elapsed().as_micros();

                    let ack_len = link.encoded_frame().len().min(ack_buf.len());
                    ack_buf[..ack_len].copy_from_slice(&link.encoded_frame()[..ack_len]);
                    let _ = uart.write(&ack_buf[..ack_len]);

                    if !persist_ready_pages(&mut wal, &mut flash_page, &mut flash, &mut next_slot) {
                        warn!("[FLASH] Fallo al persistir bundle RX; se reintentará");
                    }

                    match res {
                        RouteDecision::ForwardNextHop { node_id, .. } => {
                            let count = consumer.pop(&mut out);
                            if count > 0 && link.send(&out[..count], now_us).is_ok() {
                                let _ = uart.write(link.encoded_frame());
                            }
                            info!(
                                "[RX] ACK seq={} -> nodo {} ({} B en {} us, payload_len={})",
                                seq, node_id, n, dt_us, payload_len
                            );
                        }
                        other => {
                            info!(
                                "[RX] ACK seq={} decision={:?} en {} us ({} B)",
                                seq, other, dt_us, n
                            );
                        }
                    }
                }
                Ok(Some(RxEvent::Ack { seq })) => {
                    info!("[ARQ] ACK seq={} recibido -> state={:?}", seq, link.state());
                }
                Ok(Some(RxEvent::Nack { seq })) => {
                    info!(
                        "[ARQ] NACK seq={} -> retransmision inmediata (retries={})",
                        seq,
                        link.retries()
                    );
                    if link.retries() > 0 {
                        let _ = uart.write(link.encoded_frame());
                    }
                }
                Ok(Some(RxEvent::OutOfWindow { seq, expected })) => {
                    warn!("[ARQ] Frame seq={} fuera de ventana (esperado={})", seq, expected);
                    let ack_len = link.encoded_frame().len().min(ack_buf.len());
                    ack_buf[..ack_len].copy_from_slice(&link.encoded_frame()[..ack_len]);
                    let _ = uart.write(&ack_buf[..ack_len]);
                }
                Ok(Some(RxEvent::DuplicateData { seq, .. })) => {
                    info!("[ARQ] Duplicado seq={} -> ACK repetido sin reencolar", seq);
                    let ack_len = link.encoded_frame().len().min(ack_buf.len());
                    ack_buf[..ack_len].copy_from_slice(&link.encoded_frame()[..ack_len]);
                    let _ = uart.write(&ack_buf[..ack_len]);
                }
                Ok(Some(RxEvent::Invalid)) => warn!("[ARQ] Trama de enlace inválida descartada"),
                Ok(None) => {}
                Err(e) => warn!("[ARQ] Error de framing COBS: {:?}", e),
            }
        }

        if link.on_tick(now_us) {
            info!("[ARQ] Timeout -> retransmitiendo seq={}", link.seq_id());
            let _ = uart.write(link.encoded_frame());
        }

        if last_report.elapsed() >= Duration::from_secs(5) {
            let snap = metrics.snapshot();
            info!(
                "[TELEMETRY] processed={} dropped={} avg_latency_ns={} arq_failures={}",
                snap.packets_processed,
                snap.packets_dropped,
                snap.latency_avg_ns,
                link.failures()
            );
            last_report = Instant::now();
        }
    }
}
