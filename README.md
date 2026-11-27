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
    PLAN --> Q[OutboundBundleQueue 16x256 B<br/>bundle BPv7 completo + next_hop]
    Q --> WAL[DirectWal<br/>página 4096 B + CRC32C]
    WAL --> FLASH[NOR Flash anillo 16 sectores<br/>0x300000..0x30FFFF]
    FLASH --> REC[scan_wal_ring<br/>Crash-Recovery al arranque]
    REC -->|reinyeccion| Q
    FLASH -->|ACK solo tras read-back verificado| ARQ
```

### 1. Wear-leveling circular en SPI Flash NOR (64 KB)

| Parámetro | Valor |
| :--- | :--- |
| `WAL_START_OFFSET` | `0x30_0000` (3 MiB, fuera del firmware) |
| `WAL_SECTOR_COUNT` | `16` sectores de 4096 B |
| Región total | `0x30_0000 .. 0x30_FFFF` (64 KiB) |
| Siguiente slot | `(active_slot + 1) % 16` |

* **Crash-Recovery:** `scan_wal_ring()` hace dos pasadas sobre los 16 sectores
  reutilizando **un único buffer de 4096 B**. La primera localiza el `max_seq`
  y el sector activo; la segunda reproduce los registros válidos en orden de
  secuencia (cruzando el punto de wrap) e invoca el callback de recuperación.
  Sectores en blanco, escrituras parciales (*torn writes*) y generaciones
  obsoletas se descartan
  por CRC32C / monotonicidad.
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
* `max_retries = 3`: tras agotar el presupuesto el enlace pasa a `Failed` y el
  bundle se retiene en el WAL en lugar de descartarse.
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
  `5` (HMAC 256/256) y el parámetro de Scope Flags `3`. No existe el contexto
  CRC32C inventado por revisiones anteriores: CRC32C protege solo el WAL.
* La IPPT se construye según RFC 9173 §3.7: flags de alcance en CBOR canónico,
  bloque primario canónico cuando el flag está activo y el CBOR byte-string
  canónico del payload. El tag es HMAC-SHA-256 de 32 bytes.
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
* El bucle principal toma `front_parts()`, pasa esos bytes reales a
  `link.send(bundle, now_us)` y escribe la trama COBS resultante en UART2. El
  slot solo se libera con `pop()` después de copiar los bytes al CLA.
* Al arrancar, `scan_wal_ring()` reinyecta cada registro recuperado en la misma
  cola con `DEFAULT_NEXT_HOP`, de modo que un bundle persistido antes de un
  corte vuelve a salir por el enlace; no se descarta ni se queda solo en RAM.
* El plan de contactos actual hace selección EAT de un salto. El CGR multi-salto
  completo (grafo, rutas alternativas y contactos futuros) es trabajo futuro.

### Presupuesto de memoria

| Buffer | Tamaño |
| :--- | :--- |
| Página WAL / flash compartida | 4096 B |
| COBS RX + RX decodificado + TX | 256 + 256 + 288 B |
| WAL RAM (`DirectWal<1>`) | 4096 B |
| `OutboundBundleQueue<16, 256>` | ~4 KB (16 slots x 256 B + headers) |
| Reensamblado, plan de contactos, adjuntos BIB | < 1 KB |
| **Total estático típico** | **< 15 KB SRAM** (520 KB disponibles) |

## Métricas históricas en silicio físico (ESP32-WROOM-32, 240 MHz)

| Métrica | Resultado |
| :--- | :--- |
| Pipeline BPv7 + selector de contactos + WAL RAM (100x) | `min=10 us` \| `avg=12 us` \| `max=124 us` |
| Pipeline + verificación BPSec BIB (revisión anterior) | `533 - 553 us` hasta sellado WAL completo |
| Erase + write + verify CRC32C en NOR | `avg=43.29 ms` \| `max=45.30 ms` (10/10 OK en esa revisión) |
| Fuzzing CBOR / BPv7 / BIB (50 tramas) | **50/50 rechazadas, 0 panics** |
| Pull-the-Plug | Supervivencia confirmada: replay desde WAL/Flash |
| Soak test | **1 h 50 min** continuo sin panic ni corrupción |

> Estas cifras son mediciones reales de una **revisión anterior** del firmware.
> Después de migrar el BIB a RFC 9172 ASB / RFC 9173 IPPT y de condicionar el
> ACK a `erase -> write -> read_back -> scan_pages`, solo se han repetido las
> comprobaciones de compilación y tests listadas más abajo (**0 errores,
> 0 warnings**); **no se han vuelto a tomar medidas en silicio**. El anillo de
> 16 sectores conserva el coste por página y distribuye el desgaste sin copias
> adicionales de 4096 B.

### Suite de estrés (`--features stress-test`)

| Prueba | Qué valida |
| :--- | :--- |
| 1/6 Pipeline 100x + BPSec | Latencia min/avg/max con BIB RFC 9173 verificado |
| 2/6 Cola estática / backpressure | 32 envíos con contacto activo: 16 bundles completos encolados hacia nodo 42, el resto contabilizado como presión/drop |
| 3/6 Fuzzing CBOR/BPSec | 50 mutaciones rechazadas limpiamente |
| 4/6 Wear-leveling 10x | Erase+write+read-back del **sector recién escrito**: magic, secuencia y CRC32C validados con `scan_pages` |
| 5/6 UART2 COBS loopback | Bit-exact GPIO17 → GPIO16 (requiere jumper) |
| 6/6 ARQ + BPSec BIB | Stop-and-Wait con ACK solo tras `commit_rx_ack()`, firma aceptada, alteración rechazada |

## Comparativa con otras implementaciones DTN

| Implementación | Lenguaje | Destino | Heap | BPv7 | BPSec BIB | CLA principales | Huella / latencia (*) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **dtn-esp32-node (este proyecto)** | Rust `no_std` | ESP32-WROOM-32 (Xtensa) | **0 B** | Sí (bundle completo) | Sí (RFC 9173 BIB-HMAC-SHA2) | UART2/COBS + ARQ con ACK durable | **< 15 KB SRAM**, cifras de latencia históricas (ver arriba) |
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

# Motor base en host (97 tests unitarios + 2 integración + 13 doctests).
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

Para el test 5/6 conecta un jumper entre GPIO17 (TX) y GPIO16 (RX); sin él la
prueba se marca `SKIPPED` y el resto de la suite continúa.

## Licencia

MIT o Apache-2.0, igual que `dtn-core`.
