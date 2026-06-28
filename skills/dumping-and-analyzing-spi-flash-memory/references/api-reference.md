# SPI Flash Dump & Analysis — Tool & Command Reference

## flashrom

| Command | Purpose |
|---------|---------|
| `flashrom -p ch341a_spi` | Probe via CH341A USB programmer. |
| `flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=8000` | Probe via Raspberry Pi / Linux SPI host at 8 MHz. |
| `flashrom -p ft2232_spi:type=2232H,port=A,divisor=4` | Probe via FT2232H mini-module. |
| `flashrom -p <programmer> -c "<chip>"` | Force a specific chip when probe is ambiguous. |
| `flashrom -p <programmer> -c "<chip>" -r dump.bin` | Read (dump) the chip to a file. |
| `flashrom -p <programmer> -c "<chip>" -v dump.bin` | Verify a file against the chip. |
| `flashrom -p <programmer> -c "<chip>" -w new.bin` | Write (re-flash) — only when authorized. |
| `flashrom -L` | List all supported chips and programmers. |

Programmer drivers of note: `ch341a_spi`, `linux_spi`, `ft2232_spi`, `dediprog`, `serprog`, `raiden_debug_spi`.

## Lowering SPI speed when reads disagree

| `spispeed` (kHz) | Use when |
|------------------|----------|
| 8000 | Short, clean wiring; bench socket. |
| 2000–4000 | In-circuit clip with moderate lead length. |
| 512–1000 | Noisy in-circuit reads; reads not matching. |

## Verification

| Command | Purpose |
|---------|---------|
| `sha256sum dump1.bin dump2.bin` | Compare two reads. |
| `cmp dump1.bin dump2.bin` | Byte-exact comparison of two reads. |

## binwalk (cross-check / carve)

| Command | Purpose |
|---------|---------|
| `binwalk dump.bin` | Signature scan to list embedded file offsets. |
| `binwalk -E dump.bin` | Entropy scan. |
| `binwalk -e dump.bin` | Extract recognized components. |
| `dd if=dump.bin of=part.bin bs=1 skip=<off> count=<len>` | Carve a region at a known offset. |

## Companion script (`scripts/agent.py`)

```
python3 scripts/agent.py map     --image dump.bin --block 4096
python3 scripts/agent.py entropy --image dump.bin --block 4096
python3 scripts/agent.py strings --image dump.bin --min 8 --flag-secrets
```

| Subcommand | Key args | Output |
|------------|----------|--------|
| `map` | `--image`, `--block` | Magic-header + entropy offset map of partitions. |
| `entropy` | `--image`, `--block` | Per-block Shannon entropy (0–8 bits/byte). |
| `strings` | `--image`, `--min`, `--flag-secrets` | Printable strings; flags likely credentials/keys. |

## Magic header table

| Magic (hex/ascii) | Meaning |
|-------------------|---------|
| `27 05 19 56` | uImage (U-Boot legacy header). |
| `d0 0d fe ed` | FIT / device-tree blob. |
| `68 73 71 73` (`hsqs`) | SquashFS (little-endian). |
| `73 71 73 68` (`sqsh`) | SquashFS (big-endian). |
| `85 19` | JFFS2. |
| `45 3d cd 28` | CramFS (LE). |
| `55 42 49 23` (`UBI#`) | UBI volume. |

## External References

- flashrom manual: https://www.flashrom.org/classic_cli_manpage.html
- JEDEC SFDP (JESD216): https://www.jedec.org/
- binwalk usage: https://github.com/ReFirmLabs/binwalk/wiki
