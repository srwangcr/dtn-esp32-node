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
    COBS --> BIB{BPSec BIB-HMAC-SHA2<br/>RFC 9172 ASB / RFC 9173 §3.7<br/>Scope Flags = 1}
    BIB -->|invalido| DROP[Descartado<br/>antes de encolar]
    BIB -->|valido| P[IngestionPipeline<br/>RFC 9171]
    P --> PLAN[Contact Plan Scheduler<br/>Interval Selector]
    PLAN -->|con contacto| Q[OutboundBundleQueue 16x256 B<br/>pending -> persisted -> visible al TX]
    PLAN -->|sin contacto / cola llena| WAL[DirectWal<br/>WalEnvelope 28 B + bundle + CRC32C]
    Q --> WAL
    WAL --> FLASH[NOR Flash anillo 16 sectores<br/>0x300000..0x30FFFF]
    FLASH --> REC[scan_wal_ring<br/>Crash-Recovery al arranque]
    REC -->|Pending con ruta persistida| Q
    REC -->|PendingRoute: re-evaluar plan, sin next_hop inventado| PLAN
    FLASH -->|ACK solo tras read-back verificado| ARQ
    ARQ -->|Ack del siguiente salto| TOMB[Tombstone Delivered compacto<br/>28 B con bundle_uid de 128 bit]
    TOMB -->|pop() despues de sellar| Q
```

Los fragmentos pendientes de reensamblado viven solo en RAM (`ReassemblySlot`)
y **nunca** se escriben como bundles encaminables en el WAL. Tras agotar los
reintentos de un enlace se aplica el backoff y se usa `reset_transport()`,
que preserva `seq` y `expected_seq`, en lugar de un reinicio de sesión.

### 1. Wear-leveling circular en SPI Flash NOR (64 KB)

| Parámetro | Valor |
| :--- | :--- |
| `WAL_START_OFFSET` | `0x30_0000` (3 MiB, fuera del firmware) |
| `WAL_SECTOR_COUNT` | `16` sectores de 4096 B |
| Región total | `0x30_0000 .. 0x30_FFFF` (64 KiB) |
| Siguiente slot | `(active_slot + 1) % 16` |

* **Formato de registro:** cada bundle lleva un `WalEnvelope` de **28 bytes**
  delante de sus bytes BPv7:
  `[state: u8 | magic b"WE\x01" | bundle_uid: [u8; 16] | next_hop: u64 LE]`.
  Los estados son `0x01 = Pending`, `0x02 = Delivered` y
  `0x03 = PendingRoute`. El magic/versión (`0x57 0x45 0x01`) permite distinguir
  un envelope de 28 B de un bundle CBOR crudo: `scan_forwarding_wal_ring()`
  descarta cualquier registro sin magic válido antes de leer `next_hop`.
  `bundle_uid` son los primeros 16 bytes de SHA-256 sobre
  la identidad canónica BPv7 (EID de origen, timestamp de creación, secuencia y
  coordenadas de fragmento), estable aunque el bundle se recodifique. CRC32C
  protege **únicamente la página física del WAL**: nunca es un ID de bundle ni
  un contexto BPSec.
* **Tombstones compactos:** `Delivered` escribe solo los 28 bytes del envelope
  (sin bytes del bundle) con el `bundle_uid` de 128 bits. Boot compara UIDs de
  16 bytes, no CRCs de 32 bits.
* **Crash-Recovery:** `scan_forwarding_wal_ring()` (sobre `scan_wal_ring()`)
  hace dos pasadas sobre los 16 sectores reutilizando **un único buffer de
  4096 B**. La primera localiza el `max_seq`
  y el sector activo y recopila los UIDs entregados; la segunda reproduce los
  registros válidos en orden de secuencia (cruzando el punto de wrap) e invoca
  el callback de recuperación. Se omiten los bundles cuyo `bundle_uid` tiene un
  tombstone `Delivered` posterior; los fragmentos no se reinyectan como bundles
  encaminables. Los `Pending` conservan su `next_hop` persistido, mientras que
  los `PendingRoute` se re-evalúan contra el plan de contactos: si no hay
  contacto permanecen en el WAL sin cola y **sin asignar `DEFAULT_NEXT_HOP`**.
  Sectores en blanco, escrituras parciales (*torn writes*) y generaciones
  obsoletas se descartan por CRC32C / monotonicidad.
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
  `500_000 us` y llama a `link.reset_transport()`, que limpia la trama en vuelo,
  los reintentos y el frame COBS parcial pero **conserva `seq` y
  `expected_seq`**. Si el par ya hizo commit del ACK perdido y espera el
  siguiente `seq`, reiniciar la sesión provocaría un bucle infinito de
  `DuplicateData`/NACK; por eso el reinicio completo está reservado al arranque
  en frío.
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
  `5` (HMAC 256/256). El perfil fija de forma inequívoca
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
* El firmware usa **por defecto** un verificador *opportunistic* (acepta bundles
  herederos sin BIB pero verifica cualquier BIB presente); el modo `required`
  está disponible y se ejercita en la suite de estrés.

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
* La decisión es explícita: `ForwardNextHop` implica que el bundle **sí** entró
  en la cola. Si la cola está llena, `StoredPendingForward` persiste el bundle
  como `PendingRoute` sin encolarlo (se ACK pero no se transmite); sin WAL
  disponible se devuelve `DropBackpressure` y se rechaza la trama. Con
  `DropNoRoute` el bundle válido también se ACK y se guarda como `PendingRoute`
  (`PersistedToWal`) para esperar un contacto futuro.
* El bucle principal toma `front_parts()`, pasa esos bytes reales a
  `link.send(bundle, now_us)` y escribe la trama COBS resultante en UART2. El
  frente permanece en la cola durante `AwaitingAck`; el `pop()` solo ocurre
  cuando llega el `Ack` del siguiente salto **y** se ha sellado y verificado un
  tombstone `Delivered` con el mismo `bundle_uid` de 128 bits.
* Al arrancar, `scan_wal_ring()` filtra los bundles ya entregados por UID y
  reinyecta los `Pending` con el `next_hop` original del envelope. Los
  `PendingRoute` vuelven a consultar el plan de contactos; si no hay contacto
  siguen persistidos y fuera de la cola, sin un salto inventado. Los registros
  herederos sin envelope se tratan como `PendingRoute` y los fragmentos se
  omiten. Así un bundle persistido antes de un corte vuelve a salir por el
  enlace sin duplicar los que ya fueron acknowledged.
* `PendingReassembly` solo vive en `ReassemblySlot` (RAM): no se escribe como
  bundle encaminable en el WAL. El reensamblado es **experimental** y no
  reconstruye el ADU multi-fragmento end-to-end.
* El plan de contactos actual hace selección EAT de un salto. El CGR multi-salto
  completo (grafo, rutas alternativas y contactos futuros) es trabajo futuro.

### Presupuesto de memoria

No hay heap: el crate no enlaza `alloc`. Los arreglos grandes se declaran como
locales en `main()` y por tanto son **buffers temporales en stack**, no
`.bss`/`.data`; el estado estático se reduce a contadores y estado HAL.

| Buffer | Tamaño | Ubicación |
| :--- | :--- | :--- |
| Página WAL a escribir + página de read-back | 4096 + 4096 B | stack de `main()` (temporal, compartido) |
| WAL RAM (`DirectWal<1>`) | 4096 B | stack de `main()` |
| `OutboundBundleQueue<16, 256>` | ~4.2 KB (16 x 256 B + headers + flags) | stack de `main()` |
| COBS RX + RX decodificado + TX + `rx_buf` | 256 + 256 + 288 + 256 B | stack de `main()` / CLA |
| UIDs entregados (16 x 16 B), plan de contactos, reensamblado, adjuntos BIB | < 1 KB | stack de `main()` |
| Heap (`alloc`) | **0 B** | no se enlaza `alloc` |
| Arrays grandes en `.bss` / `.data` | **0 B** | no se declaran `static` de este tamaño |
| **Pico típico de SRAM (stack + estática)** | **~18.5 KB** | 520 KB disponibles |

## Métricas reales en silicio (ESP32-WROOM-32 rev v3.1, 240 MHz)

| Métrica | Resultado medido |
| :--- | :--- |
| Pipeline BPv7 + BIB-HMAC-SHA2 en SRAM | **165 – 173 us** |
| Pipeline + BIB + persistencia hasta `PersistedToWal` (IPPT §3.7) | **752 us** |
| Erase + write + read-back en NOR (10 sectores) | **avg = 36.87 ms \| max = 37.35 ms** |
| Verificación de sector recién escrito (magic + seq + CRC32C) | **10/10 OK** |
| Fuzzing CBOR / BPv7 / BIB (50 tramas) | **50/50 rechazadas, 0 panics** |
| Binario release | **139,312 B** (1.67% de partición) |
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
| **dtn-esp32-node (este proyecto)** | Rust `no_std` | ESP32-WROOM-32 (Xtensa) | **0 B** | Sí (bundle completo, cola transaccional) | Sí (RFC 9173 BIB-HMAC-SHA2, Scope Flags = 1) | UART2/COBS + ARQ con ACK durable, `reset_transport()` y tombstone `Delivered` de 28 B | **139,312 B** (1.67% de partición) binario, **~18.5 KB SRAM** pico, 165–173 us pipeline (ver arriba) |
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

# Motor base en host (109 tests unitarios + 2 integración + 13 doctests).
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

> Estado verificado en esta revisión: los cuatro comandos obligatorios
> (`cargo test` en `dtn-core`, los dos `cargo +esp check` y el `cargo +esp
> clippy` sin estrés) terminan con **0 errores y 0 warnings**. El `clippy`
> opcional con `--features stress-test` también está limpio.

Para los tests 5/7 y 7/7 conecta un jumper entre GPIO17 (TX) y GPIO16 (RX); sin
él se marcan `SKIPPED` y el resto de la suite continúa.

## Hoja de ruta de madurez tecnológica (TRL 4 -> TRL 9)

Estado actual: **TRL 4** (motor `no_std`, persistencia transaccional y enlace confiable validados en silicio real sobre ESP32-WROOM-32).

- [x] **TRL 4 — Validación de componentes en laboratorio:** Parser BPv7 (RFC 9171), BPSec BIB-HMAC-SHA2 (RFC 9172/9173), anillo WAL de 16 sectores con *read-back*, Stop-and-Wait ARQ sobre COBS y pruebas en hardware (`139,312 B`, `752 us`).
- [ ] **TRL 5 — Subsistema integrado en entorno relevante:** Topología multi-nodo física (3+ nodos por UART2 / LoRa SX1262), interoperabilidad binaria con `dtn7-rs`/`ION-DTN`, reensamblado multi-fragmento end-to-end, CGR multi-salto y confidencialidad BPSec (BCB-AES-GCM).
- [ ] **TRL 6 — Prototipo demostrado en entorno relevante:** Portabilidad a MCU con ECC/FRAM o RISC-V tolerante a radiación (NOEL-V/LEON3), Watchdog/FDIR con particiones A/B, pruebas térmicas/vacío (TVAC) e inyección de fallos SEU en memoria.
- [ ] **TRL 7 — Demostración de prototipo en entorno espacial:** Integración en plataforma CubeSat/PocketQube o globo estratosférico (`> 30 km`) con carga dinámica de planes de contacto desde TLE orbitales.
- [ ] **TRL 8 — Sistema calificado para vuelo:** Cierre de calificación (ECSS-E-ST-40C / NASA-STD-8739.8), ensayos EMC/EMI con radio espacial definitiva y pruebas *End-to-End* en FlatSat/Flight Model.
- [ ] **TRL 9 — Operación nominal en misión:** Operación continua en órbita o espacio profundo con telemetría validada y acreditación de *Flight Heritage*.

## Licencia

MIT o Apache-2.0, igual que `dtn-core`.
