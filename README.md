# dtn-esp32-node — Nodo BPv7 DTN sobre ESP32-WROOM-32

Firmware `no_std` / cero `alloc` para ESP32-WROOM-32 (Xtensa LX6 @ 240 MHz)
que integra el motor [`../dtn-core`](../dtn-core) (RFC 9171, RFC 9172 ASB y
RFC 9173 BIB-HMAC-SHA2) con `esp-hal` 1.2, `esp-storage` 0.10 y UART2. Todo el
estado del nodo vive en buffers estáticos: no hay heap, no hay RTOS y no hay
timers de sistema.

## Arquitectura completa

```mermaid
flowchart LR
    UART2[UART2 GPIO16/17<br/>115200 bps] --> ARQ[ReliableSerialCla<br/>Stop-and-Wait ARQ]
    ARQ --> COBS[COBS 0x00<br/>SerialFraming]
    COBS --> BIB{BPSec BIB-HMAC-SHA2<br/>RFC 9172 ASB / RFC 9173 §3.7}
    BIB -->|invalido| DROP[Descartado<br/>antes de encolar]
    BIB -->|valido| P[IngestionPipeline<br/>RFC 9171]
    P --> PLAN[Contact Plan Scheduler<br/>Interval Selector]
    PLAN --> Q[OutboundBundleQueue 16x256 B<br/>pending -> persisted -> visible al TX]
    Q --> WAL[DirectWal<br/>WalEnvelope 16 B + bundle + CRC32C]
    WAL --> FLASH[NOR Flash anillo 16 sectores<br/>0x300000..0x30FFFF]
    FLASH --> REC[scan_wal_ring<br/>Crash-Recovery al arranque]
    REC -->|Pending sin Delivered, conserva next_hop| Q
    FLASH -->|ACK solo tras read-back verificado| ARQ
    ARQ -->|Ack del siguiente salto| TOMB[WAL Delivered tombstone]
    TOMB -->|pop() despues de sellar| Q
```

### 1. Wear-leveling circular en SPI Flash NOR (64 KB)

| Parámetro | Valor |
| :--- | :--- |
| `WAL_START_OFFSET` | `0x30_0000` (3 MiB, fuera del firmware) |
| `WAL_SECTOR_COUNT` | `16` sectores de 4096 B |
| Región total | `0x30_0000 .. 0x30_FFFF` (64 KiB) |
| Siguiente slot | `(active_slot + 1) % 16` |

* **Formato de registro:** cada bundle lleva un `WalEnvelope` de **16 bytes**
  delante de sus bytes BPv7:
  `[state: u8 | reserved: [u8; 3] | bundle_id_crc: u32 LE | next_hop: u64 LE]`.
  `0x01 = Pending`, `0x02 = Delivered`. El CRC32C del envelope es un identificador
  estable del bundle (no un contexto BPSec), y `next_hop` conserva la decisión
  original del plan de contactos.
* **Crash-Recovery:** `scan_wal_ring()` hace dos pasadas sobre los 16 sectores
  reutilizando **un único buffer de 4096 B**. La primera localiza el `max_seq`
  y el sector activo; la segunda reproduce los registros válidos en orden de
  secuencia (cruzando el punto de wrap) e invoca el callback de recuperación.
  Al arranque se omiten los registros `Pending` cuyo `bundle_id_crc` ya tiene un
  tombstone `Delivered` posterior; el resto se reinyecta con su `next_hop`
  persistido. Sectores en blanco, escrituras parciales (*torn writes*) y
  generaciones obsoletas se descartan por CRC32C / monotonicidad.
* **En ejecución:** cada página WAL sellada se escribe rotando al siguiente
  sector **sin borrar los otros 15**. La secuencia del `DirectWal` se reanuda en
  `max_seq + 1` para que una página nueva nunca se confunda con una generación
  antigua. Resultado: **16x de vida útil** de la NOR frente a la escritura fija.
* Si un `erase`/`write` falla, la página permanece en el WAL RAM y se reintenta
  en el siguiente ciclo: no se anuncia durabilidad que no existe.

### 2. Capa de convergencia confiable sobre UART2 (COBS + Stop-and-Wait)

Cabecera ligera de enlace dentro de cada frame COBS:

| Offset | Tamaño | Campo |
| :--- | :--- | :--- |
| 0 | 1 | `Data=0x01`, `Ack=0x02`, `Nack=0x03` |
| 1 | 2 | `SeqId` (`u16`, big-endian, wrap-around) |
| 3 | N | Payload (bundle BPv7 o ADU reenviado) |

* **ARQ Stop-and-Wait** una sola trama en vuelo, ventana de timeout de
  `50_000 us` inyectada como tick `u64` desde `Instant::elapsed().as_micros()`
  (sin `std::time`, sin RTOS). `send()` devuelve `QueueFull` si el estado es
  `AwaitingAck` o `Failed`: no sobrescribe la trama pendiente.
* `max_retries = 3`: tras agotar el presupuesto el enlace pasa a `Failed`. El
  bundle **no se hace `pop()`**: aplica un backoff no bloqueante de
  `500_000 us`, llama a `link.reset()` y reenvía el mismo frente de cola.
* **ACK durable, no automático:** decodificar `Data` crea `PendingCommit` pero
  no envía ACK. El firmware copia el payload, ejecuta el pipeline, hace
  `wal.append()` y luego `erase -> write -> read_back -> scan_pages` valida
  magic, secuencia y CRC32C de la página recién escrita. Solo entonces llama a
  `commit_rx_ack()` y emite el ACK. Si falla BPSec o Flash, llama a
  `reject_rx_nack()`; la ventana de recepción no avanza y la retransmisión del
  mismo `seq` puede aceptarse. Las tramas fuera de ventana se NACKEan de
  inmediato porque nunca fueron aceptadas.
* RX/TX: `ReliableSerialCla<256, 288, 256>` — COBS con delimitador `0x00`,
  GPIO16 RX / GPIO17 TX a 115200 bps.

### 3. BPSec BIB-HMAC-SHA2 (RFC 9172 / RFC 9173) antes de encolar

* Bloque de extensión canónico tipo **11**, insertado **antes** del payload para
  conservar la regla RFC 9171 de que el payload es el último bloque canónico.
* Los datos del bloque son un **ASB de RFC 9172**:
  `[targets, context_id, flags, source, params, results]`. El único contexto
  soportado es RFC 9173 `SECURITY_CONTEXT_BIB_HMAC_SHA2 = 1` con SHA Variant
  `5` (HMAC 256/256) y el parámetro de Scope Flags `3`. El perfil fija
  **`Scope Flags = 1`** (`BIB_SCOPE_PRIMARY_BLOCK = 0x01`, Primary + Payload).
  No existe el contexto CRC32C inventado por revisiones anteriores: CRC32C
  protege solo el WAL.
* La IPPT se construye según RFC 9173 §3.7: flags de alcance en CBOR canónico,
  bloque primario canónico cuando el flag está activo y el CBOR byte-string
  canónico del payload. El tag es HMAC-SHA-256 de 32 bytes. La cabecera del
  bloque objetivo (el bloque payload) **no se incluye en el scope actual**; solo
  su datos tipo bloque, más el bloque primario canónico.
* `BibVerifier` se ejecuta dentro de `IngestionPipeline` **antes** de la cola
  de salida y del WAL: integridad inválida produce `DropIntegrityFailed` y
  nunca provoca ACK.
* El firmware usa un verificador *opportunistic* (acepta bundles herederos sin
  BIB pero verifica cualquier BIB presente); el modo `required` está disponible
  y se ejercita en la suite de estrés.

### 4. Reenvío de bundles completos y recuperación

* `IngestionPipeline` devuelve el `next_hop` del *Contact Plan Scheduler /
  Interval Selector* y encola el **bundle BPv7 completo** en
  `OutboundBundleQueue<16, 256>` con el frame
  `[next_hop: u64 LE | len: u16 LE | raw_bundle_bytes]`.
* La inserción es **transaccional**: `enqueue()` crea la entrada como `pending`,
  invisible para `front_parts()`. Solo `mark_last_persisted()`, invocado tras
  `persist_ready_pages()` con read-back verificado, la hace visible al TX. Si la
  Flash falla, `discard_last_pending()` la retira: nunca se transmite un bundle
  no durable (`Validated -> Persisted -> OutboundQueue`).
* El bucle principal toma `front_parts()`, pasa esos bytes reales a
  `link.send(bundle, now_us)` y escribe la trama COBS resultante en UART2. El
  frente permanece en la cola durante `AwaitingAck`; el `pop()` solo ocurre
  cuando llega el `Ack` del siguiente salto **y** se ha sellado y verificado un
  registro WAL `Delivered` con el mismo `bundle_id_crc`.
* Al arrancar, `scan_wal_ring()` filtra los `Pending` ya entregados y reinyecta
  el resto con el `next_hop` original del envelope (los registros herederos sin
  envelope usan `DEFAULT_NEXT_HOP`). Así un bundle persistido antes de un corte
  vuelve a salir por el enlace sin duplicar los que ya fueron acknowledged.
* El reensamblado de fragmentos es **experimental**: `ReassemblySlot` gestiona
  rangos y solapamientos, pero no realiza una reconstrucción multi-fragmento
  end-to-end del ADU. El CGR multi-salto completo también es trabajo futuro.
* El plan de contactos actual hace selección EAT de un salto. El CGR multi-salto
  completo (grafo, rutas alternativas y contactos futuros) es trabajo futuro.

### Presupuesto de memoria

No hay heap. Los arreglos grandes se declaran como locales en `main()` y por
tanto son **buffers temporales en stack**, no `.bss`/`.data`; el estado
estático del crate se reduce a contadores/estado HAL (sin tablas grandes).

| Buffer | Tamaño | Ubicación |
| :--- | :--- | :--- |
| Página WAL a escribir + página de read-back | 4096 + 4096 B | stack de `main()` (temporal, compartido) |
| WAL RAM (`DirectWal<1>`) | 4096 B | stack de `main()` |
| `OutboundBundleQueue<16, 256>` | ~4.2 KB (16 x 256 B + headers + flags) | stack de `main()` |
| COBS RX + RX decodificado + TX + `rx_buf` | 256 + 256 + 288 + 256 B | stack de `main()` / CLA |
| Reensamblado, plan de contactos, adjuntos BIB | < 1 KB | stack de `main()` |
| Arrays grandes en `.bss` / `.data` | **0 B** | no se declaran `static` de este tamaño |
| **Pico típico de SRAM (stack + estática)** | **< 15 KB** | 520 KB disponibles |

## Métricas reales en silicio (ESP32-WROOM-32 rev v3.1, 240 MHz)

| Métrica | Resultado medido |
| :--- | :--- |
| Pipeline BPv7 + BIB-HMAC-SHA2 en SRAM | **260 – 266 us** (max 570 us) |
| Pipeline + BIB + persistencia hasta `PersistedToWal` (IPPT §3.7) | **788 us** |
| Erase + write + read-back en NOR (10 sectores) | **avg = 36.87 ms \| max = 37.35 ms** |
| Verificación de sector recién escrito (magic + seq + CRC32C) | **10/10 OK** |
| Fuzzing CBOR / BPv7 / BIB (50 tramas) | **50/50 rechazadas, 0 panics** |
| Binario release | **150,368 B** (1.81% de partición) |
| Pull-the-Plug / soak test (mediciones históricas) | replay desde WAL confirmado; 1 h 50 min sin panic |

> Las cifras de la tabla son mediciones tomadas en silicio sobre la revisión
> v3.1 con el BIB RFC 9173 y el ACK condicionado a read-back. Las filas de
> *Pull-the-Plug* y *soak* proceden de una revisión anterior y se conservan como
> evidencia histórica, no como resultado de esta compilación. Las cifras son
> observaciones de banco, no una certificación aeroespacial. El anillo de 16
> sectores distribuye el desgaste sin copiar 4096 B adicionales.

### Suite de estrés (`--features stress-test`)

| Prueba | Qué valida |
| :--- | :--- |
| 1/7 Pipeline 100x + BPSec | Latencia min/avg/max con BIB RFC 9173 verificado |
| 2/7 Cola estática / backpressure | 32 envíos con contacto activo: entradas `pending -> persisted`, 16 bundles completos hacia nodo 42, el resto contabilizado como presión/drop |
| 3/7 Fuzzing CBOR/BPSec | 50 mutaciones rechazadas limpiamente |
| 4/7 Wear-leveling 10x | Erase+write+read-back del **sector recién escrito**: envelope, magic, secuencia y CRC32C validados con `scan_pages` |
| 5/7 UART2 COBS loopback | Bit-exact GPIO17 → GPIO16 (requiere jumper) |
| 6/7 ARQ + BPSec BIB | Stop-and-Wait con ACK solo tras `commit_rx_ack()`, firma aceptada, alteración rechazada |
| 7/7 ARQ físico end-to-end | Sobre el loopback UART2 con jumper: `Data -> commit -> ACK -> Idle`, sin ACK automático |

## Comparativa con otras implementaciones DTN

| Implementación | Lenguaje | Destino | Heap | BPv7 | BPSec BIB | CLA principales | Huella / latencia (*) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **dtn-esp32-node (este proyecto)** | Rust `no_std` | ESP32-WROOM-32 (Xtensa) | **0 B** | Sí (bundle completo, cola transaccional) | Sí (RFC 9173 BIB-HMAC-SHA2, Scope Flags = 1) | UART2/COBS + ARQ con ACK durable y tombstone `Delivered` | **150,368 B** (1.81% de partición) binario, **< 15 KB SRAM** pico, 165–173 us pipeline (ver arriba) |
| ION-DTN | C | Linux / RTOS | Sí | Sí (completo) | Sí | UDP, TCP, LTP, BP over multiple CLA | Orden de MB de RAM; latencia dependiente de SO |
| µD3TN | C | Linux embebido / MCU | Sí (pequeño) | Sí | Sí (BIB) | UDP, TCP, serial (dtn) | Decenas de KB a cientos de KB |
| dtn7-rs | Rust (`std`/async) | Linux / servidor | Sí | Sí | Sí (BIB/BCS) | TCP, UDP, WebSockets | Orden de MB; latencia de red dominante |

(*) Las cifras de ION-DTN, µD3TN y dtn7-rs son valores orientativos de su
documentación pública y arquitectura, **no medidas en este banco de pruebas**.
La ventaja comparativa de este firmware es el funcionamiento *bare-metal* con
cero asignaciones, persistencia con OCR y enlace serial confiable sin RTOS.

## Compilación y verificación

```fish
# Comprobación Xtensa (release)
cargo +esp check --release --bin dtn-esp32-node
cargo +esp check --release --bin dtn-esp32-node --features stress-test

# Motor base en host (101 tests unitarios + 2 integración + 13 doctests).
# IMPORTANTE: ejecutarlo desde dtn-core, no desde aquí: Cargo toma la toolchain
# y el target del directorio actual, y el config de este repo apunta a
# xtensa-esp32-none-elf (build-std=core), donde las dependencias de test de
# dtn-core (criterion/serde/clap) no pueden compilar.
cd ../dtn-core && cargo test

# Opcional: mismos checks con Clippy (detecta large_stack_frames)
cargo +esp clippy --release --bin dtn-esp32-node
cargo +esp clippy --release --bin dtn-esp32-node --features stress-test

# Flashing (usa el runner xtensa-esp32-none-elf de .cargo/config.toml)
cargo +esp run --release --bin dtn-esp32-node
```

> Estado verificado en esta revisión: los tres comandos obligatorios
> (`cargo test` en `dtn-core` y los dos `cargo +esp check` de arriba) terminan
> con **0 errores y 0 warnings**. Los dos `cargo +esp clippy` opcionales también
> están limpios.

Para los tests 5/7 y 7/7 conecta un jumper entre GPIO17 (TX) y GPIO16 (RX); sin
él se marcan `SKIPPED` y el resto de la suite continúa.

## Licencia

MIT o Apache-2.0, igual que `dtn-core`.
