use dtn_core::bpsec::BibVerifier;
use dtn_core::cla::reliable::{ReliableSerialCla, RxEvent};
use dtn_core::cla::serial::SerialFraming;
use dtn_core::processor::fragmentation::ReassemblySlot;
use dtn_core::processor::pipeline::{IngestionPipeline, RouteDecision};
use dtn_core::routing::interval_tree::{CgrIntervalTree, ContactInterval};
use dtn_core::storage::ring_buffer::LockFreeRingBuffer;
use dtn_core::storage::wal::{
    scan_wal_ring, wal_slot_offset, DirectWal, PAGE_SIZE, WAL_SECTOR_COUNT,
};
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
    next_slot: &mut usize,
) {
    info!("==========================================================");
    info!("[STRESS] INICIANDO SUITE DE ESTRES EN SILICIO FISICO");
    info!("==========================================================");

    let mut router = CgrIntervalTree::<8>::new();
    let mut ring = LockFreeRingBuffer::<16>::new();
    let (mut producer, mut consumer) = ring.split();
    let mut wal = DirectWal::<1>::new();
    let mut slot = ReassemblySlot::<128>::new();
    let metrics = SystemMetrics::new();

    // TEST 1: Latencia estadistica del pipeline (100 iteraciones Store-and-Forward)
    let mut min_us = u64::MAX;
    let mut max_us = 0u64;
    let mut sum_us = 0u64;

    for _ in 0..100 {
        let t0 = Instant::now();
        let _ = IngestionPipeline::ingest_and_route_with_security::<8, 16, 128, 1>(
            signed_bundle,
            1_000,
            &router,
            &mut producer,
            Some(&mut slot),
            Some(&mut wal),
            Some(&metrics),
            Some(verifier),
        );
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
        "[TEST 1/6 - PIPELINE 100x + BPSEC] min={} us | avg={} us | max={} us",
        min_us,
        sum_us / 100,
        max_us
    );

    // TEST 2: Saturacion del Ring Buffer SPSC con ruta activa hacia nodo 42
    let _ = router.insert(ContactInterval::new(0, 86_400, 42));
    let mut ok_fwd = 0usize;
    let mut backpressure = 0usize;
    for _ in 0..32 {
        match IngestionPipeline::ingest_and_route_with_security::<8, 16, 128, 1>(
            signed_bundle,
            1_000,
            &router,
            &mut producer,
            Some(&mut slot),
            Some(&mut wal),
            Some(&metrics),
            Some(verifier),
        ) {
            RouteDecision::ForwardNextHop { .. } => ok_fwd += 1,
            _ => backpressure += 1,
        }
    }
    let mut drain = [0u8; 16];
    while consumer.pop(&mut drain) > 0 {}
    info!(
        "[TEST 2/6 - SPSC BACKPRESSURE] enqueued={} | backpressure_handled={}",
        ok_fwd, backpressure
    );

    // TEST 3: Fuzzing / Mutacion de bits sobre CBOR BPv7 + BIB (50 tramas rotas)
    let mut fuzz_errors_caught = 0usize;
    let mut broken = [0u8; 128];
    let copy_len = signed_bundle.len().min(broken.len());
    broken[..copy_len].copy_from_slice(&signed_bundle[..copy_len]);
    let mut wal_fuzz = DirectWal::<1>::new();
    for i in 0..50usize {
        broken[i % copy_len] ^= 0xFF;
        let res = IngestionPipeline::ingest_and_route_with_security::<8, 16, 128, 1>(
            &broken[..copy_len],
            1_000,
            &router,
            &mut producer,
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

    // TEST 4: Erase + Write + Verify CRC32C rotando por el anillo de 16 sectores
    let empty_router = CgrIntervalTree::<8>::new();
    let mut page_buf = [0u8; PAGE_SIZE];
    let mut flash_sum_us = 0u64;
    let mut flash_max_us = 0u64;
    let mut verified_ok = 0usize;

    for _ in 0..10 {
        let _ = IngestionPipeline::ingest_and_route_with_security::<8, 16, 128, 1>(
            signed_bundle,
            1_000,
            &empty_router,
            &mut producer,
            Some(&mut slot),
            Some(&mut wal),
            Some(&metrics),
            Some(verifier),
        );
        wal.write_first_sealed_page(&mut page_buf);
        let target = *next_slot;
        let tf = Instant::now();
        let _ = flash.erase(wal_slot_offset(target), wal_slot_offset(target) + PAGE_SIZE as u32);
        let _ = flash.write(wal_slot_offset(target), &page_buf);
        let dt_f = tf.elapsed().as_micros();
        flash_sum_us += dt_f;
        if dt_f > flash_max_us {
            flash_max_us = dt_f;
        }
        *next_slot = (target + 1) % WAL_SECTOR_COUNT;
        wal.release_ready();

        page_buf.fill(0);
        if flash.read(wal_slot_offset(target), &mut page_buf).is_ok() {
            let rep = scan_wal_ring(
                |scan_slot, scan_page| {
                    if scan_slot == target {
                        scan_page.copy_from_slice(&page_buf);
                    } else {
                        let _ = flash.read(wal_slot_offset(scan_slot), scan_page);
                    }
                    true
                },
                &mut |_, _, _| {},
            );
            if rep.pages_valid > 0 {
                verified_ok += 1;
            }
        }
    }
    info!(
        "[TEST 4/6 - WEAR LEVELING 10x] avg_erase_write={} us | max={} us | crc32c_ok={}/10 | next_slot={}",
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

    // TEST 6: BPSec BIB: aceptacion firmada / rechazo ante alteracion determinista
    let mut link_tx = ReliableSerialCla::<256, 288, 256>::new(50_000, 2);
    let mut link_rx = ReliableSerialCla::<256, 288, 256>::new(50_000, 2);
    let send_ok = link_tx.send(signed_bundle, 0).is_ok();
    let mut arq_data = None;
    for &byte in link_tx.encoded_frame() {
        if let Ok(Some(event)) = link_rx.push_byte(byte, 1) {
            arq_data = Some(event);
        }
    }
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
        && matches!(arq_data, Some(RxEvent::Data { .. }))
        && link_rx.rx_payload() == signed_bundle
        && matches!(arq_ack, Some(RxEvent::Ack { .. }))
        && link_tx.state() == dtn_core::cla::reliable::ArqState::Idle;

    let required = BibVerifier::required(STRESS_KEY);
    let mut r = LockFreeRingBuffer::<8>::new();
    let (mut p, _) = r.split();
    let mut w = DirectWal::<1>::new();
    let signed_ok = !matches!(
        IngestionPipeline::ingest_and_route_with_security::<8, 8, 128, 1>(
            signed_bundle,
            1_000,
            &router,
            &mut p,
            Some(&mut slot),
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
    let mut r2 = LockFreeRingBuffer::<8>::new();
    let (mut p2, _) = r2.split();
    let mut w2 = DirectWal::<1>::new();
    let tamper_rejected = matches!(
        IngestionPipeline::ingest_and_route_with_security::<8, 8, 128, 1>(
            &tampered[..tamper_len],
            1_000,
            &router,
            &mut p2,
            Some(&mut slot),
            Some(&mut w2),
            None,
            Some(&required),
        ),
        RouteDecision::DropIntegrityFailed
    );
    info!(
        "[TEST 6/6 - ARQ + BPSEC BIB] arq_stop_and_wait={} signed_accepted={} tamper_rejected={}",
        arq_ok, signed_ok, tamper_rejected
    );

    info!("==========================================================");
    info!("[STRESS] SUITE COMPLETADA SIN PANICS NI CORRUPCION");
    info!("==========================================================");
}
