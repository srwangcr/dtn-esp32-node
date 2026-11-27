#![no_std]
#![no_main]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is generally not safe to do with esp_hal types, especially those \
    holding buffers for the duration of a data transfer."
)]
#![deny(clippy::large_stack_frames)]

use dtn_core::cla::serial::SerialFraming;
use dtn_core::processor::fragmentation::ReassemblySlot;
use dtn_core::processor::pipeline::{IngestionPipeline, RouteDecision};
use dtn_core::routing::interval_tree::{CgrIntervalTree, ContactInterval};
use dtn_core::storage::ring_buffer::LockFreeRingBuffer;
use dtn_core::storage::wal::{scan_pages, DirectWal, PAGE_SIZE};
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

/// Offset seguro en la Flash de 4 MB (3 MB) para el WAL DTN sin pisar el firmware.
const WAL_FLASH_OFFSET: u32 = 0x30_0000;

/// Bundle BPv7 mínimo para auto-validación en arranque.
const TEST_BUNDLE: &[u8] = &[
    0x9f, 0x88, 0x07, 0x00, 0x00, 0x82, 0x01, 0x00, 0x82, 0x01, 0x00, 0x82, 0x01, 0x00, 0x82,
    0x00, 0x01, 0x19, 0xea, 0x60, 0x85, 0x01, 0x01, 0x00, 0x00, 0x41, 0x58, 0xff,
];

#[allow(
    clippy::large_stack_frames,
    reason = "Static DTN buffers (<5 KB) live on main stack"
)]
#[main]
fn main() -> ! {
    esp_println::logger::init_logger_from_env();

    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    // 1. Inicializar Flash SPI y ejecutar Crash-Recovery al encendido
    let mut flash = FlashStorage::new(peripherals.FLASH);
    let mut flash_page = [0u8; PAGE_SIZE];
    if flash.read(WAL_FLASH_OFFSET, &mut flash_page).is_ok() {
        let mut recovered_count = 0usize;
        let (report, _, last_seq) = scan_pages(core::slice::from_ref(&flash_page), &mut |record: &[u8]| {
            recovered_count += 1;
            info!("[BOOT] Bundle recuperado de Flash ({} bytes)", record.len());
        });
        info!(
            "[BOOT] Crash-Recovery Flash (0x{:X}): recuperados={} descartados={} last_seq={}",
            WAL_FLASH_OFFSET, recovered_count, report.pages_discarded, last_seq
        );
    }

    // 2. Inicializar UART2 en GPIO16 (RX) y GPIO17 (TX) a 115200 bps
    let uart_config = UartConfig::default().with_baudrate(115_200);
    let mut uart = Uart::new(peripherals.UART2, uart_config)
        .expect("Failed to init UART2")
        .with_rx(peripherals.GPIO16)
        .with_tx(peripherals.GPIO17);

    // 3. Estructuras estáticas zero-allocation (< 5 KB SRAM)
    let mut framing = SerialFraming::<256, 256>::new();
    let mut router = CgrIntervalTree::<8>::new();
    let mut ring = LockFreeRingBuffer::<16>::new();
    let (mut producer, mut consumer) = ring.split();
    let mut wal = DirectWal::<1>::new();
    let mut slot = ReassemblySlot::<128>::new();
    let metrics = SystemMetrics::new();

    // 4. Auto-test en hardware real: Store-and-Forward (sin ruta activa -> persiste en WAL -> Flash SPI)
    let mut wire = [0u8; 256];
    let wire_len = {
        let frame = framing.encode_frame(TEST_BUNDLE).unwrap();
        let len = frame.len();
        wire[..len].copy_from_slice(frame);
        len
    };

    let mut decoded = [0u8; 256];
    let mut decoded_len = 0usize;
    for &b in &wire[..wire_len] {
        if let Ok(Some(frame)) = framing.push_byte(b) {
            decoded_len = frame.len();
            decoded[..decoded_len].copy_from_slice(frame);
        }
    }

    let t0 = Instant::now();
    let decision = IngestionPipeline::ingest_and_route::<8, 16, 128, 1>(
        &decoded[..decoded_len],
        1_000,
        &router,
        &mut producer,
        Some(&mut slot),
        Some(&mut wal),
        Some(&metrics),
    );
    let elapsed_us = t0.elapsed().as_micros();
    info!(
        "[SELF-TEST] Pipeline Xtensa 240MHz completado en {} us -> {:?}",
        elapsed_us, decision
    );

    // Volcar la página sellada con CRC32C reutilizando `flash_page` (0 bytes extra en stack)
    if wal.write_sealed_pages(core::slice::from_mut(&mut flash_page)) > 0 {
        if let Err(e) = flash.erase(WAL_FLASH_OFFSET, WAL_FLASH_OFFSET + PAGE_SIZE as u32) {
            warn!("[FLASH] Error borrando sector: {:?}", e);
        }
        match flash.write(WAL_FLASH_OFFSET, &flash_page) {
            Ok(_) => info!("[FLASH] Página WAL (4096 B + CRC32C) escrita en SPI Flash"),
            Err(e) => warn!("[FLASH] Error escribiendo sector: {:?}", e),
        }
    }

    #[cfg(feature = "stress-test")]
    stress::run_hardware_stress_suite(&mut flash, &mut uart, TEST_BUNDLE);

    // Agregar contacto activo hacia nodo 42 para tráfico entrante por UART2
    let _ = router.insert(ContactInterval::new(0, 86_400, 42));
    info!("[READY] Escuchando tramas COBS en UART2 (GPIO16 RX / GPIO17 TX)...");

    let mut rx_byte = [0u8; 1];
    let mut rx_buf = [0u8; 256];
    let mut last_report = Instant::now();

    loop {
        if let Ok(1) = uart.read_buffered(&mut rx_byte) {
            if let Ok(Some(frame)) = framing.push_byte(rx_byte[0]) {
                let len = frame.len();
                rx_buf[..len].copy_from_slice(frame);

                let t_in = Instant::now();
                let res = IngestionPipeline::ingest_and_route::<8, 16, 128, 1>(
                    &rx_buf[..len],
                    1_000,
                    &router,
                    &mut producer,
                    Some(&mut slot),
                    Some(&mut wal),
                    Some(&metrics),
                );
                let dt_us = t_in.elapsed().as_micros();

                match res {
                    RouteDecision::ForwardNextHop { node_id, .. } => {
                        let mut out = [0u8; 16];
                        let n = consumer.pop(&mut out);
                        if let Ok(tx_frame) = framing.encode_frame(&out[..n]) {
                            let _ = uart.write(&tx_frame);
                        }
                        info!("[RX] Forward -> nodo {} ({} B en {} us)", node_id, n, dt_us);
                    }
                    other => info!("[RX] Decisión en {} us: {:?}", dt_us, other),
                }
            }
        }

        if last_report.elapsed() >= Duration::from_secs(5) {
            let snap = metrics.snapshot();
            info!(
                "[TELEMETRY] processed={} dropped={} avg_latency_ns={}",
                snap.packets_processed, snap.packets_dropped, snap.latency_avg_ns
            );
            last_report = Instant::now();
        }
    }
}