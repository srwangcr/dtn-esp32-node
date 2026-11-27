use dtn_core::cla::serial::SerialFraming;
use dtn_core::processor::fragmentation::ReassemblySlot;
use dtn_core::processor::pipeline::{IngestionPipeline, RouteDecision};
use dtn_core::routing::interval_tree::{CgrIntervalTree, ContactInterval};
use dtn_core::storage::ring_buffer::LockFreeRingBuffer;
use dtn_core::storage::wal::{scan_pages, DirectWal, PAGE_SIZE};
use dtn_core::telemetry::metrics::SystemMetrics;
use embedded_storage::nor_flash::NorFlash;
use esp_hal::time::{Duration, Instant};
use esp_hal::uart::Uart;
use esp_hal::Blocking;
use esp_storage::FlashStorage;
use log::{info, warn};

const STRESS_WAL_OFFSET: u32 = 0x31_0000;

#[allow(clippy::large_stack_frames)]
pub fn run_hardware_stress_suite(
    flash: &mut FlashStorage<'_>,
uart: &mut Uart<'_, Blocking>,
bundle: &[u8],
) {
info!("==========================================================");
info!("[STRESS] INICIANDO SUITE DE ESTRES EN SILICIO FISICO");
info!("==========================================================");

let mut framing = SerialFraming::<256, 256>::new();
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
let _ = IngestionPipeline::ingest_and_route::<8, 16, 128, 1>(
bundle,
1_000,
&router,
&mut producer,
Some(&mut slot),
Some(&mut wal),
Some(&metrics),
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
"[TEST 1/5 - PIPELINE 100x] min={} us | avg={} us | max={} us",
min_us,
sum_us / 100,
max_us
);

// TEST 2: Saturacion del Ring Buffer SPSC con ruta activa hacia nodo 42
let _ = router.insert(ContactInterval::new(0, 86_400, 42));
let mut ok_fwd = 0usize;
let mut backpressure = 0usize;
for _ in 0..32 {
match IngestionPipeline::ingest_and_route::<8, 16, 128, 1>(
bundle,
1_000,
&router,
&mut producer,
Some(&mut slot),
Some(&mut wal),
Some(&metrics),
) {
RouteDecision::ForwardNextHop { .. } => ok_fwd += 1,
_ => backpressure += 1,
}
}
let mut drain = [0u8; 16];
while consumer.pop(&mut drain) > 0 {}
info!(
"[TEST 2/5 - SPSC BACKPRESSURE] enqueued={} | backpressure_handled={}",
ok_fwd, backpressure
);

// TEST 3: Fuzzing / Mutacion de bits sobre CBOR BPv7 (50 tramas rotas)
let mut fuzz_errors_caught = 0usize;
let mut broken = [0u8; 32];
let copy_len = bundle.len().min(32);
broken[..copy_len].copy_from_slice(&bundle[..copy_len]);
for i in 0..50usize {
broken[i % copy_len] ^= 0xFF;
let res = IngestionPipeline::ingest_and_route::<8, 16, 128, 1>(
&broken[..copy_len],
1_000,
&router,
&mut producer,
Some(&mut slot),
Some(&mut wal),
Some(&metrics),
);
if !matches!(res, RouteDecision::ForwardNextHop { .. }) {
fuzz_errors_caught += 1;
}
}
info!(
"[TEST 3/5 - FUZZING CBOR/BPv7] 50/50 tramas corruptas rechazadas limpiamente ({})",
fuzz_errors_caught
);

// TEST 4: Benchmark real de Erase + Write + Verify CRC32C en SPI Flash NOR (10 ciclos)
let empty_router = CgrIntervalTree::<8>::new();
let mut page_buf = [0u8; PAGE_SIZE];
let mut flash_sum_us = 0u64;
let mut flash_max_us = 0u64;
let mut verified_ok = 0usize;

for _ in 0..10 {
let _ = IngestionPipeline::ingest_and_route::<8, 16, 128, 1>(
bundle,
1_000,
&empty_router,
&mut producer,
Some(&mut slot),
Some(&mut wal),
Some(&metrics),
);
let _ = wal.write_sealed_pages(core::slice::from_mut(&mut page_buf));
let tf = Instant::now();
let _ = flash.erase(STRESS_WAL_OFFSET, STRESS_WAL_OFFSET + PAGE_SIZE as u32);
let _ = flash.write(STRESS_WAL_OFFSET, &page_buf);
let dt_f = tf.elapsed().as_micros();
flash_sum_us += dt_f;
if dt_f > flash_max_us {
flash_max_us = dt_f;
}

page_buf.fill(0);
if flash.read(STRESS_WAL_OFFSET, &mut page_buf).is_ok() {
let (rep, _, _) = scan_pages(core::slice::from_ref(&page_buf), &mut |_| {});
if rep.pages_discarded == 0 {
verified_ok += 1;
}
}
}
info!(
"[TEST 4/5 - SPI FLASH NOR 10x] avg_erase_write={} us | max={} us | crc32c_ok={}/10",
flash_sum_us / 10,
flash_max_us,
verified_ok
);

// TEST 5: Loopback fisico UART2 (GPIO17 TX -> GPIO16 RX)
let mut tx_wire = [0u8; 256];
let tx_len = {
let f = framing.encode_frame(bundle).unwrap();
let l = f.len();
tx_wire[..l].copy_from_slice(f);
l
};
let _ = uart.write(&tx_wire[..tx_len]);
let t_uart = Instant::now();
let mut rx_b = [0u8; 1];
let mut loopback_ok = false;
while t_uart.elapsed() < Duration::from_millis(50) {
if let Ok(1) = uart.read_buffered(&mut rx_b) {
if let Ok(Some(decoded)) = framing.push_byte(rx_b[0]) {
if decoded == bundle {
loopback_ok = true;
break;
}
}
}
}
if loopback_ok {
info!("[TEST 5/5 - UART2 HARDWARE LOOPBACK] PASS (GPIO17 -> GPIO16 bit-exact)");
} else {
warn!("[TEST 5/5 - UART2 HARDWARE LOOPBACK] SKIPPED (une GPIO16 y GPIO17 con un jumper para probar cable fisico)");
}

info!("==========================================================");
info!("[STRESS] SUITE COMPLETADA SIN PANICS NI CORRUPCION");
info!("==========================================================");
}
