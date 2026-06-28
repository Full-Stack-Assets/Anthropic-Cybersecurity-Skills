# RFID/NFC Access-Control Assessment — Tool & Command Reference

## Proxmark3 (Iceman) Commands

| Command | Purpose |
|---------|---------|
| `lf search` | Detect/identify a 125 kHz tag (EM/HID/Indala) |
| `hf search` | Detect/identify a 13.56 MHz tag (ISO14443A) |
| `hf 14a info` | ATQA/SAK/UID → chip type (Classic 1K/4K vs DESFire) |
| `lf hid read` / `lf em 410x reader` | Read LF prox / EM4100 IDs |
| `lf hid clone -w H10301 --fc <n> --cn <n>` | Clone HID Prox to T5577 |
| `lf em 410x clone --id <hex>` | Clone EM4100 to T5577 |
| `hf mf chk *1 ? d <dict>` | Check default/dictionary keys (all sectors) |
| `hf mf autopwn` | Automated nested/hardnested key recovery + dump |
| `hf mf hardnested 0 A <key> 4 A` | Hardnested attack on hardened Classic |
| `hf mf dump` | Dump all sectors with known keys |
| `hf mf cload -f <bin>` | Load a dump onto a Gen1a magic card |
| `hf mf sim --1k -u <uid>` | Emulate a MIFARE Classic card |
| `hf mfdes info` | Inspect a DESFire card (apps, key settings) |
| `hf mfdes auth --aid <id> --kn <n> --algo AES --key <hex>` | Test DESFire AES auth (default-key check) |

## libnfc / nfc-tools

| Tool | Key flags | Purpose |
|------|-----------|---------|
| `nfc-list` | — | Enumerate tags on a libnfc reader |
| `mfoc` | `-O <dump.mfd>`, `-k <key>` | Nested attack, full sector dump |
| `mfcuk` | `-C`, `-R 0:A`, `-s/-S <n>` | Darkside attack to recover a first key |
| `nfc-mfclassic` | `r/w a/b <dump> <blank>` | Read/write MIFARE Classic dumps |

## MIFARE Classic Attack Selection

| Known state | Attack | Tool |
|-------------|--------|------|
| Factory/default keys | dictionary / default-key check | `hf mf chk`, mfoc |
| At least one key known | nested | `hf mf autopwn`, mfoc |
| No keys, weak RNG | darkside | mfcuk |
| Hardened EV1 (better RNG) | hardnested | `hf mf hardnested` |

## Companion Script (`scripts/agent.py`)

| Subcommand | Args | Purpose |
|------------|------|---------|
| `assess` | `--dump <.json/.bin>`, `--keys <file>`, `--json <out>` | Parse a Proxmark3/mfoc dump, identify chip/sectors, default-key exposure, and score cloneability |

## Card Type Identification (SAK)

| SAK | Type |
|-----|------|
| 0x08 | MIFARE Classic 1K |
| 0x18 | MIFARE Classic 4K |
| 0x09 | MIFARE Mini |
| 0x20 | MIFARE DESFire / Plus (ISO14443-4) |
| 0x00 | MIFARE Ultralight / NTAG |

## External References

- Proxmark3 command reference: https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/commands.md
- libnfc wiki: https://github.com/nfc-tools/libnfc/wiki
- NIST SP 800-116 Rev.1: https://csrc.nist.gov/pubs/sp/800/116/r1/final
