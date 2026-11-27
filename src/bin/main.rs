#![no_std]
#![no_main]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is generally not safe to do with esp_hal types, especially those \
    holding buffers for the duration of a data transfer."
)]
#![deny(clippy::large_stack_frames)]

use dtn_core::bpsec::{BibScope, BibSigner, BibVerifier};
use dtn_core::cla::reliable::{ArqState, ReliableSerialCla, RxEvent};
use dtn_core::processor::fragmentation::ReassemblySlot;
use dtn_core::parser::primary_block::parse_primary_block;
use dtn_core::processor::pipeline::{IngestionPipeline, RouteDecision};
use dtn_core::routing::interval_tree::{CgrIntervalTree, ContactInterval};
use dtn_core::storage::outbound::OutboundBundleQueue;
use dtn_core::storage::wal::{
    bundle_uid, decode_wal_record, read_page, scan_forwarding_wal_ring, scan_pages, wal_slot_offset,
    DirectWal, BUNDLE_UID_LEN, PAGE_SIZE, WAL_NEXT_HOP_NONE, WAL_SECTOR_COUNT,
    WAL_STATE_DELIVERED, WAL_STATE_PENDING, WAL_STATE_PENDING_ROUTE,
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

/// Backoff no bloqueante antes de `link.reset_transport()` y reintento del frente.
const LINK_BACKOFF_US: u64 = 500_000;

/// Salto del plan de contactos usado al re-evaluar `PendingRoute` en el boot.
///
/// Nunca se aplica a registros sin envelope: esos se descartan.
const DEFAULT_NEXT_HOP: u32 = 42;

/// Bundle BPv7 mínimo para auto-validación en arranque.
const TEST_BUNDLE: &[u8] = &[
    0x9f, 0x88, 0x07, 0x00, 0x00, 0x82, 0x01, 0x00, 0x82, 0x01, 0x00, 0x82, 0x01, 0x00, 0x82,
    0x00, 0x01, 0x19, 0xea, 0x60, 0x85, 0x01, 0x01, 0x00, 0x00, 0x41, 0x58, 0xff,
];

/// Erase + write + read-back de un sector del anillo WAL (4 KiB) en NOR Flash.
///
/// El ACK del ARQ **no** puede prepararse hasta que esta función confirma que
/// la página contiene el magic, la secuencia, el CRC32C y el `WalEnvelope`
/// esperados. El buffer `verify` es distinto de `page`, así que la comparación
/// es contra los bytes leídos realmente de Flash y no contra la copia en SRAM.
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
    if decode_wal_record(expected.1).is_err() {
        return false; // el camino de reenvío siempre escribe un envelope
    }
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

    // 1. Flash, Crash-Recovery y reinyección transaccional desde el anillo WAL.
    //    El plan de contactos se construye ANTES del replay para poder
    //    re-evaluar los registros `PendingRoute` sin inventar un next_hop.
    //    Primero recopilamos los `bundle_uid` con tombstone `Delivered`; una
    //    segunda pasada reinyecta solo los bundles aún no entregados.
    let mut flash = FlashStorage::new(peripherals.FLASH);
    let mut flash_page = [0u8; PAGE_SIZE];
    let mut verify_page = [0u8; PAGE_SIZE];
    let mut outbound = OutboundBundleQueue::<16, 256>::new();
    let mut router = CgrIntervalTree::<8>::new();
    let _ = router.insert(ContactInterval::new(0, 86_400, DEFAULT_NEXT_HOP));
    let mut delivered_uids = [[0u8; BUNDLE_UID_LEN]; WAL_SECTOR_COUNT];
    let mut delivered_count = 0usize;

    // Solo se visitan registros con magic y estado de envelope válidos: un
    // bundle CBOR crudo o un registro heredero NUNCA se interpreta como ruta.
    let tombstone_scan = scan_forwarding_wal_ring(
        |slot, page| flash.read(wal_slot_offset(slot), page).is_ok(),
        &mut |_slot, _seq, envelope, _bundle| {
            if envelope.is_delivered() && delivered_count < WAL_SECTOR_COUNT {
                delivered_uids[delivered_count] = envelope.bundle_uid;
                delivered_count += 1;
            }
        },
    );
    if tombstone_scan.records_rejected > 0 {
        warn!(
            "[BOOT] {} registros sin WalEnvelope valido descartados (1a pasada)",
            tombstone_scan.records_rejected
        );
    }

    let mut recovered_count = 0usize;
    let mut reinjected_count = 0usize;
    let mut delivered_skipped = 0usize;
    let mut deferred_count = 0usize;
    let mut fragment_skipped = 0usize;
    let recovery = scan_forwarding_wal_ring(
        |slot, page| flash.read(wal_slot_offset(slot), page).is_ok(),
        &mut |slot, seq, envelope, bundle| {
            recovered_count += 1;
            if envelope.is_delivered() {
                return; // tombstone compacto: nunca se reinyecta
            }
            let uid = envelope.bundle_uid;
            let needs_route =
                envelope.is_pending_route() || envelope.next_hop == WAL_NEXT_HOP_NONE;
            let stored_hop = envelope.next_hop;
            if delivered_uids[..delivered_count].contains(&uid) {
                delivered_skipped += 1;
                return;
            }
            // Un fragmento incompleto nunca se reinyecta como bundle encaminable.
            if parse_primary_block(bundle)
                .map(|header| header.is_fragment())
                .unwrap_or(false)
            {
                fragment_skipped += 1;
                return;
            }
            let hop = if needs_route {
                match router.find_next(0) {
                    Some(interval) => u64::from(interval.target_node_id),
                    None => {
                        // Sin contacto: permanece persistido en el WAL, sin
                        // cola y sin asignar un salto arbitrario.
                        deferred_count += 1;
                        return;
                    }
                }
            } else {
                stored_hop
            };
            info!(
                "[BOOT] Bundle recuperado slot={} seq={} ({} bytes, next_hop={})",
                slot,
                seq,
                bundle.len(),
                hop
            );
            match outbound.enqueue_persisted(hop, bundle) {
                Ok(()) => reinjected_count += 1,
                Err(e) => warn!("[BOOT] No se pudo reinyectar bundle recuperado: {:?}", e),
            }
        },
    );
    info!(
        "[BOOT] Crash-Recovery anillo WAL (0x{:X}..0x{:X}): validos={} descartados={} sin_envelope={} recuperados={} reinyectados={} entregados_omitidos={} sin_ruta={} fragmentos_omitidos={} max_seq={} active_slot={} -> next_slot={}",
        wal_slot_offset(0),
        wal_slot_offset(WAL_SECTOR_COUNT - 1) + PAGE_SIZE as u32 - 1,
        recovery.pages_valid,
        recovery.pages_discarded,
        recovery.records_rejected,
        recovered_count,
        reinjected_count,
        delivered_skipped,
        deferred_count,
        fragment_skipped,
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

    // 3. Estructuras estáticas zero-allocation (el router ya se creó en 1).
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
        if outbound.has_pending() {
            let _ = outbound.mark_last_persisted();
        }
        info!(
            "[FLASH] Página WAL (4096 B + envelope + CRC32C) verificada en sector {}",
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

    // `(seq del CLA, bundle_uid de 128 bits)` de la trama actualmente en vuelo.
    let mut inflight: Option<(u16, [u8; BUNDLE_UID_LEN])> = None;
    // Instante en que el enlace falló o no se pudo sellar el `Delivered`.
    let mut link_failed_at: Option<u64> = None;

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

                    // Clasificación transaccional. `ForwardNextHop` entra en la
                    // cola; sin contacto o con cola llena se persiste como
                    // `PendingRoute` y se ACK sin encolar (store-and-forward).
                    // `PendingReassembly` solo vive en ReassemblySlot (RAM):
                    // nunca se persiste como bundle encaminable en el WAL.
                    let (store_in_wal, queued, wal_state, route_hop) = match res {
                        RouteDecision::ForwardNextHop { node_id, .. } => {
                            (true, true, WAL_STATE_PENDING, node_id)
                        }
                        RouteDecision::PersistedToWal
                        | RouteDecision::StoredPendingForward
                        | RouteDecision::StoreLocal
                        | RouteDecision::DropNoRoute => {
                            (true, false, WAL_STATE_PENDING_ROUTE, WAL_NEXT_HOP_NONE)
                        }
                        RouteDecision::PendingReassembly
                        | RouteDecision::DropExpiredOrMalformed
                        | RouteDecision::DropIntegrityFailed
                        | RouteDecision::DropBackpressure => {
                            (false, false, WAL_STATE_PENDING_ROUTE, WAL_NEXT_HOP_NONE)
                        }
                    };
                    let integrity_ok = !matches!(
                        res,
                        RouteDecision::DropExpiredOrMalformed
                            | RouteDecision::DropIntegrityFailed
                            | RouteDecision::DropBackpressure
                    );

                    // Reintentar una página WAL aún no verificada antes de
                    // aceptar un registro nuevo (DirectWal<1> tiene un slot).
                    let wal_ready = wal.full_pages() == 0
                        || persist_ready_pages(
                            &mut wal,
                            &mut flash_page,
                            &mut verify_page,
                            &mut flash,
                            &mut next_slot,
                        );
                    let durable = integrity_ok
                        && n == payload_len
                        && if store_in_wal {
                            wal_ready
                                && wal
                                    .append_bundle(wal_state, route_hop, &rx_buf[..n])
                                    .is_ok()
                                && persist_ready_pages(
                                    &mut wal,
                                    &mut flash_page,
                                    &mut verify_page,
                                    &mut flash,
                                    &mut next_slot,
                                )
                        } else {
                            true // reensamblado experimental: únicamente en RAM
                        };

                    if durable {
                        // Validated -> Persisted -> OutboundQueue: la entrada
                        // solo se vuelve visible al TX tras read-back OK.
                        if queued && outbound.has_pending() {
                            let _ = outbound.mark_last_persisted();
                        }
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
                        // Persistencia fallida: descartar la entrada pendiente
                        // para que el TX no pueda emitir un bundle no durable.
                        if queued && outbound.has_pending() {
                            let _ = outbound.discard_last_pending();
                        }
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
                    // El ACK del siguiente salto convierte el registro en
                    // Delivered y solo entonces libera el frente de la cola.
                    let matches_inflight = inflight.is_some_and(|(sent, _)| sent == seq);
                    let mut sealed_delivered = false;
                    if matches_inflight
                        && let Some((next_hop, _bundle)) = outbound.front_parts()
                        && let Some((_, uid)) = inflight
                    {
                        // Tombstone compacto: solo el envelope de 28 B con el
                        // bundle_uid de 128 bits del bundle en vuelo.
                        let wal_ready = wal.full_pages() == 0
                            || persist_ready_pages(
                                &mut wal,
                                &mut flash_page,
                                &mut verify_page,
                                &mut flash,
                                &mut next_slot,
                            );
                        sealed_delivered = wal_ready
                            && wal
                                .append_record(WAL_STATE_DELIVERED, uid, next_hop, &[])
                                .is_ok()
                            && persist_ready_pages(
                                &mut wal,
                                &mut flash_page,
                                &mut verify_page,
                                &mut flash,
                                &mut next_slot,
                            );
                    }
                    if sealed_delivered {
                        outbound.pop();
                        inflight = None;
                        link_failed_at = None;
                        info!("[WAL] Delivered sellado seq={} -> frente de cola liberado", seq);
                    } else if matches_inflight {
                        // No se pudo sellar el tombstone: mantener el bundle y
                        // reenviarlo tras el backoff, nunca hacer pop() antes.
                        inflight = None;
                        link_failed_at = Some(now_us);
                        warn!("[WAL] ACK seq={} recibido pero Delivered no verificado; se retiene el frente", seq);
                    }
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

        if link.state() == ArqState::Failed && link_failed_at.is_none() {
            link_failed_at = Some(now_us);
        }

        // Backoff no bloqueante: el frente de la cola permanece intacto hasta
        // que el enlace se reinicia y el bundle se reenvía.
        let mut blocked = false;
        if let Some(failed_at) = link_failed_at {
            if now_us.wrapping_sub(failed_at) >= LINK_BACKOFF_US {
                // Nunca reset_session(): el receptor ya pudo hacer commit del
                // ACK perdido y espera el siguiente seq. Solo se reinicia el
                // transporte para que el reintento avance de seq.
                link.reset_transport();
                link_failed_at = None;
                inflight = None;
                info!("[ARQ] Backoff cumplido -> link.reset_transport(), reintentando frente de cola");
            } else {
                blocked = true;
            }
        }

        // Reenvío transaccional: el bundle sigue en el frente mientras el CLA
        // está en AwaitingAck. El pop() solo ocurre tras ACK + Delivered WAL.
        if !blocked
            && link.state() == ArqState::Idle
            && let Some((next_hop, bundle)) = outbound.front_parts()
        {
            let uid = bundle_uid(bundle);
            match link.send(bundle, now_us) {
                Ok(()) => {
                    let _ = uart.write(link.encoded_frame());
                    inflight = Some((link.seq_id(), uid));
                    info!(
                        "[TX] BPv7 completo ({} B) reenviado a next_hop={} -> UART2 (seq={})",
                        bundle.len(),
                        next_hop,
                        link.seq_id()
                    );
                }
                Err(e) => warn!("[TX] No se pudo enviar bundle (next_hop={}): {:?}", next_hop, e),
            }
        }

        if link.on_tick(now_us) {
            info!("[ARQ] Timeout -> retransmitiendo seq={}", link.seq_id());
            let _ = uart.write(link.encoded_frame());
        } else if link.state() == ArqState::Failed && link_failed_at.is_none() {
            link_failed_at = Some(now_us);
        }

        if last_report.elapsed() >= Duration::from_secs(5) {
            let snap = metrics.snapshot();
            info!(
                "[TELEMETRY] processed={} dropped={} avg_latency_ns={} arq_failures={} outbound={} in_flight={}",
                snap.packets_processed,
                snap.packets_dropped,
                snap.latency_avg_ns,
                link.failures(),
                outbound.len(),
                inflight.is_some()
            );
            last_report = Instant::now();
        }
    }
}
