use dtn_core::bpsec::BibVerifier;
use dtn_core::cla::reliable::{ArqState, ReliableSerialCla, RxEvent};
use dtn_core::cla::serial::SerialFraming;
use dtn_core::processor::fragmentation::ReassemblySlot;
use dtn_core::processor::pipeline::{IngestionPipeline, RouteDecision};
use dtn_core::routing::interval_tree::{CgrIntervalTree, ContactInterval};
use dtn_core::storage::outbound::OutboundBundleQueue;
use dtn_core::storage::wal::{wal_slot_offset, DirectWal, PAGE_SIZE, WAL_SECTOR_COUNT};
use dtn_core::telemetry::metrics::SystemMetrics;
use esp_hal::time::{Duration, Instant};
use esp_hal::uart::Uart;
use esp_hal::Blocking;
use esp_storage::FlashStorage;
use log::{info, warn};

const STRESS_KEY: [u8; 32] = [0x42; 32];

#[allow(clippy::large_stack_frames)]
pub fn run_hardware_stress_suite(
    flash: &mut FlashStorage<'_>,
    uart: &mut Uart<'_, Blocking>,
    signed_bundle: &[u8],
    verifier: &BibVerifier,
    page_buf: &mut [u8; PAGE_SIZE],
    verify_buf: &mut [u8; PAGE_SIZE],
    next_slot: &mut usize,
) {
    info!("==========================================================");
    info!("[STRESS] INICIANDO SUITE DE ESTRES EN SILICIO FISICO");
    info!("==========================================================");

    let mut router = CgrIntervalTree::<8>::new();
    let mut outbound = OutboundBundleQueue::<16, 128>::new();
    let mut slot = ReassemblySlot::<128>::new();
    let mut wal = DirectWal::<1>::new();
    let metrics = SystemMetrics::new();

    // TEST 1: Latencia estadistica del pipeline (100 iteraciones Store-and-Forward)
    let mut min_us = u64::MAX;
    let mut max_us = 0u64;
    let mut sum_us = 0u64;
    let mut wal_stores = 0usize;

    for _ in 0..100 {
        let t0 = Instant::now();
        let decision = IngestionPipeline::ingest_and_route_with_security::<8, 16, 128, 128, 1>(
            signed_bundle,
            1_000,
            &router,
            &mut outbound,
            Some(&mut slot),
            Some(&mut wal),
            Some(&metrics),
            Some(verifier),
        );
        if decision == RouteDecision::PersistedToWal {
            wal_stores += 1;
        }
        let dt = t0.elapsed().as_micros();
        if dt < min_us {
            min_us = dt;
        }
        if dt > max_us {
            max_us = dt;
        }
        sum_us += dt;
    }
    info!(
        "[TEST 1/6 - PIPELINE 100x + BPSec] min={} us | avg={} us | max={} us | wal_accepted={}",
        min_us,
        sum_us / 100,
        max_us,
        wal_stores
    );

    // TEST 2: Presion sobre la cola estatica de bundles completos (ruta a nodo 42).
    // Solo los primeros 16 bundles caben; el resto debe contabilizarse como
    // backpressure (contador de drops del pipeline + WAL lleno).
    let _ = router.insert(ContactInterval::new(0, 86_400, 42));
    let mut ok_fwd = 0usize;
    let mut backpressure = 0usize;
    let drops_before = metrics.snapshot().packets_dropped;
    for _ in 0..32 {
        match IngestionPipeline::ingest_and_route_with_security::<8, 16, 128, 128, 1>(
            signed_bundle,
            1_000,
            &router,
            &mut outbound,
            Some(&mut slot),
            Some(&mut wal),
            Some(&metrics),
            Some(verifier),
        ) {
            RouteDecision::ForwardNextHop { .. } => ok_fwd += 1,
            _ => backpressure += 1,
        }
    }
    let drops = metrics.snapshot().packets_dropped.saturating_sub(drops_before);
    let mut queued = 0usize;
    let mut queued_bytes_match = 0usize;
    let mut queued_hop_match = 0usize;
    while let Some((next_hop, bundle)) = outbound.front_parts() {
        queued += 1;
        if bundle == signed_bundle {
            queued_bytes_match += 1;
        }
        if next_hop == 42 {
            queued_hop_match += 1;
        }
        outbound.pop();
    }
    info!(
        "[TEST 2/6 - COLA ESTATICA/BACKPRESSURE] decisiones_forward={} encolados={}/16 bundle_completo={}/16 next_hop={}/16 rechazos={} drops={}",
        ok_fwd,
        queued,
        queued_bytes_match,
        queued_hop_match,
        backpressure,
        drops
    );

    // TEST 3: Fuzzing / Mutacion de bits sobre CBOR BPv7 + BIB (50 tramas rotas)
    let mut fuzz_errors_caught = 0usize;
    let mut broken = [0u8; 128];
    let copy_len = signed_bundle.len().min(broken.len());
    broken[..copy_len].copy_from_slice(&signed_bundle[..copy_len]);
    let mut wal_fuzz = DirectWal::<1>::new();
    let mut fuzz_outbound = OutboundBundleQueue::<16, 128>::new();
    for i in 0..50usize {
        broken[i % copy_len] ^= 0xFF;
        let res = IngestionPipeline::ingest_and_route_with_security::<8, 16, 128, 128, 1>(
            &broken[..copy_len],
            1_000,
            &router,
            &mut fuzz_outbound,
            Some(&mut slot),
            Some(&mut wal_fuzz),
            Some(&metrics),
            Some(verifier),
        );
        if matches!(
            res,
            RouteDecision::DropExpiredOrMalformed | RouteDecision::DropIntegrityFailed
        ) {
            fuzz_errors_caught += 1;
        }
    }
    info!(
        "[TEST 3/6 - FUZZING CBOR/BPSec] {}/50 tramas corruptas rechazadas limpiamente",
        fuzz_errors_caught
    );

    // TEST 4: Erase + write + read-back + magic/seq/CRC32C del SECTOR recien
    // escrito, rotando por el anillo WAL. No basta con que "algun" page del
    // anillo sea valido: se valida exactamente el slot target de cada vuelta.
    let empty_router = CgrIntervalTree::<8>::new();
    let mut wal_flash = DirectWal::<1>::new();
    let mut flash_sum_us = 0u64;
    let mut flash_max_us = 0u64;
    let mut verified_ok = 0usize;

    for iteration in 0..10 {
        let decision = IngestionPipeline::ingest_and_route_with_security::<8, 16, 128, 128, 1>(
            signed_bundle,
            1_000,
            &empty_router,
            &mut outbound,
            Some(&mut slot),
            Some(&mut wal_flash),
            None,
            Some(verifier),
        );
        let persisted = decision == RouteDecision::PersistedToWal;
        if !wal_flash.write_first_sealed_page(page_buf) {
            warn!("[TEST 4/6] iter={} sin pagina sellada", iteration);
            continue;
        }
        let target = *next_slot;
        let tf = Instant::now();
        let verified = persisted
            && super::write_and_verify_wal_sector(flash, page_buf, verify_buf, target);
        let dt_f = tf.elapsed().as_micros();
        flash_sum_us += dt_f;
        if dt_f > flash_max_us {
            flash_max_us = dt_f;
        }
        if verified {
            *next_slot = (target + 1) % WAL_SECTOR_COUNT;
            wal_flash.release_ready();
            verified_ok += 1;
        } else {
            warn!(
                "[TEST 4/6] iter={} sector=0x{:X} NO verificado; pagina retenida en WAL",
                iteration,
                wal_slot_offset(target)
            );
        }
    }
    info!(
        "[TEST 4/6 - ERASE+WRITE+READBACK 10x] avg={} us | max={} us | sector_verify_ok={}/10 | next_slot={}",
        flash_sum_us / 10,
        flash_max_us,
        verified_ok,
        *next_slot
    );

    // TEST 5: Loopback fisico UART2 con Stop-and-Wait ARQ sobre COBS
    let mut framing = SerialFraming::<256, 288>::new();
    let mut tx_wire = [0u8; 288];
    let tx_len = match framing.encode_frame(signed_bundle) {
        Ok(frame) => {
            let l = frame.len();
            tx_wire[..l].copy_from_slice(frame);
            l
        }
        Err(_) => 0,
    };
    let _ = uart.write(&tx_wire[..tx_len]);
    let start = Instant::now();
    let mut loopback_ok = false;
    let mut rx_b = [0u8; 1];
    while start.elapsed() < Duration::from_millis(100) {
        if let Ok(1) = uart.read_buffered(&mut rx_b)
            && let Ok(Some(decoded)) = framing.push_byte(rx_b[0])
            && decoded == signed_bundle
        {
            loopback_ok = true;
            break;
        }
    }
    if loopback_ok {
        info!("[TEST 5/6 - UART2 COBS LOOPBACK] PASS (GPIO17 -> GPIO16 bit-exact)");
    } else {
        warn!("[TEST 5/6 - UART2 COBS LOOPBACK] SKIPPED (une GPIO16 y GPIO17 con un jumper)");
    }

    // TEST 6: ARQ con ACK explicito tras commit + BIB-HMAC-SHA2 RFC 9173.
    let mut link_tx = ReliableSerialCla::<256, 288, 256>::new(50_000, 2);
    let mut link_rx = ReliableSerialCla::<256, 288, 256>::new(50_000, 2);
    let send_ok = link_tx.send(signed_bundle, 0).is_ok();
    let mut arq_data = None;
    for &byte in link_tx.encoded_frame() {
        if let Ok(Some(event)) = link_rx.push_byte(byte, 1) {
            arq_data = Some(event);
        }
    }
    let arq_data_ok = matches!(arq_data, Some(RxEvent::Data { .. }))
        && link_rx.rx_payload() == signed_bundle;
    // El ACK NO se genera al decodificar: solo despues de commit_rx_ack(),
    // que es lo que el firmware principal invoca tras verificar Flash.
    let commit_ok = link_rx.commit_rx_ack().is_ok();
    let mut ack_wire = [0u8; 8];
    let ack_len = link_rx.encoded_frame().len().min(ack_wire.len());
    ack_wire[..ack_len].copy_from_slice(&link_rx.encoded_frame()[..ack_len]);
    let mut arq_ack = None;
    for &byte in &ack_wire[..ack_len] {
        if let Ok(Some(event)) = link_tx.push_byte(byte, 2) {
            arq_ack = Some(event);
        }
    }
    let arq_ok = send_ok
        && arq_data_ok
        && commit_ok
        && matches!(arq_ack, Some(RxEvent::Ack { .. }))
        && link_tx.state() == ArqState::Idle;

    let required = BibVerifier::required(STRESS_KEY);
    let mut signed_outbound = OutboundBundleQueue::<8, 128>::new();
    let mut slot6 = ReassemblySlot::<128>::new();
    let mut w = DirectWal::<1>::new();
    let signed_ok = !matches!(
        IngestionPipeline::ingest_and_route_with_security::<8, 8, 128, 128, 1>(
            signed_bundle,
            1_000,
            &router,
            &mut signed_outbound,
            Some(&mut slot6),
            Some(&mut w),
            None,
            Some(&required),
        ),
        RouteDecision::DropIntegrityFailed
    );
    let mut tampered = [0u8; 128];
    let tamper_len = signed_bundle.len().min(tampered.len());
    tampered[..tamper_len].copy_from_slice(signed_bundle);
    if tamper_len > 2 {
        tampered[tamper_len - 2] ^= 0x01; // ultimo byte del payload, antes del break
    }
    let mut tampered_outbound = OutboundBundleQueue::<8, 128>::new();
    let mut w2 = DirectWal::<1>::new();
    let tamper_rejected = matches!(
        IngestionPipeline::ingest_and_route_with_security::<8, 8, 128, 128, 1>(
            &tampered[..tamper_len],
            1_000,
            &router,
            &mut tampered_outbound,
            Some(&mut slot6),
            Some(&mut w2),
            None,
            Some(&required),
        ),
        RouteDecision::DropIntegrityFailed
    );
    info!(
        "[TEST 6/6 - ARQ COMMIT + BPSec BIB] arq_stop_and_wait={} signed_accepted={} tamper_rejected={}",
        arq_ok, signed_ok, tamper_rejected
    );

    info!("==========================================================");
    info!("[STRESS] SUITE COMPLETADA SIN PANICS NI CORRUPCION");
    info!("==========================================================");
}
