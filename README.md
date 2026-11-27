
### Suite de Estrés en Silicio Físico (\`--features stress-test\`)

| Prueba | Resultado en ESP32-WROOM-32 (240 MHz) |
| :--- | :--- |
| **Pipeline BPv7 + CGR + WAL RAM (100x)** | \`min=10 µs\` \| \`avg=12 µs\` \| \`max=124 µs\` |
| **Fuzzing CBOR / BPv7 (50 tramas mutadas)** | **50/50 rechazadas limpiamente (0 panics)** |
| **SPI Flash NOR Erase+Write+CRC32C (10x)** | \`avg=43.29 ms\` \| \`max=45.30 ms\` \| **10/10 CRC32C OK** |
