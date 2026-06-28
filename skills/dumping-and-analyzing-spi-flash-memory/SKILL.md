---
name: dumping-and-analyzing-spi-flash-memory
description: Reads SPI/NOR flash memory chips off embedded devices both in-circuit and via chip-off, identifying SOIC8/WSON packages, wiring a CH341A or other flashrom-supported programmer with a test clip, dumping the contents with flashrom, verifying the dump for integrity, and then locating partitions and embedded filesystems by entropy and magic-header analysis. Covers safe chip identification, multi-read verification, and offset mapping of bootloader, kernel, and root filesystem regions.
domain: cybersecurity
subdomain: firmware-analysis
tags:
- firmware
- spi-flash
- flashrom
- ch341a
- chip-off
- hardware-hacking
- nor-flash
- entropy
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.AM-08
- ID.RA-01
- PR.PS-01
- DE.AE-02
mitre_attack:
- T1200
- T1542
- T1078
---
# Dumping and Analyzing SPI Flash Memory

> **Authorized Use Only:** Only read flash from hardware you own or are explicitly authorized in writing to test. Desoldering chips, clipping onto a powered board, or copying firmware can void warranties, violate the DMCA and vendor terms, and brick the device. Respect the copyright and license of any firmware you extract.

## Overview

The non-volatile firmware of most embedded and IoT devices lives in an external **SPI NOR flash** chip — commonly an 8-pin SOIC8 or a leadless WSON8/USON8 package from vendors such as Winbond (W25Q…), Macronix (MX25L…), GigaDevice (GD25Q…), or Micron/Spansion. Reading this chip yields the entire firmware image — bootloader, environment, kernel, and root filesystem — independent of any software protections on the running system. This is a hardware-level acquisition path that maps to MITRE ATT&CK **T1200 — Hardware Additions** (attaching a programmer/clip), with the recovered bootloader implicating **T1542 — Pre-OS Boot** and any recovered credentials enabling **T1078 — Valid Accounts**.

There are two physical approaches. **In-circuit** reading clips a SOIC8 test clip directly onto the chip on the powered-down board and drives it with a programmer such as the ubiquitous **CH341A** (USB) running **flashrom**. This is fast but can fail when other components on the SPI bus or the board's regulators back-feed the chip; holding the SoC in reset or isolating VCC sometimes helps. **Chip-off** removes the flash entirely with hot air, places it in a SOIC8 socket/adapter, and reads it on the bench — slower and riskier to the chip but the most reliable. In both cases, the chip is first identified (flashrom probes the JEDEC ID; the silkscreen part number confirms package, voltage, and size — many parts are **1.8 V**, not 3.3 V, and a 3.3 V programmer will destroy them).

After acquisition, the raw dump is verified by reading at least twice and comparing hashes (a single read can contain bus-noise bit errors), then analyzed structurally. NOR flash images are typically a concatenation of regions with recognizable **magic headers**: U-Boot/uImage (`0x27051956`), the FIT/`device-tree` (`0xd00dfeed`), SquashFS (`hsqs`/`sqsh`), JFFS2 (`0x1985`), CramFS (`0x28cd3d45`), UBI (`UBI#`), and CPIO/initramfs. Combined with **per-block Shannon entropy** (flat low entropy = padding/config; ~8.0 = compressed/encrypted), this produces an offset map that drives downstream extraction and reverse engineering.

## When to Use

- Performing an authorized hardware assessment where the firmware is not downloadable from the vendor.
- A device has no usable UART/JTAG path, or the bootloader console is locked.
- You need a byte-exact, software-independent copy of the firmware (forensic acquisition).
- Recovering NVRAM/config partitions, calibration data, or keys stored only in flash.
- Validating that a product encrypts its flash and does not store plaintext secrets.
- Re-flashing for controlled glitching/fault-injection or recovery testing (when authorized).

## Prerequisites

- A **flashrom-supported programmer**: CH341A (cheap, 3.3 V — beware many clones output 5 V on the data lines), or a more reliable FT2232H/Raspberry Pi `linux_spi`, or a dedicated DediProg/T48.
- A **SOIC8 test clip** (Pomona 5250 or 3M equivalent) plus a SOIC8/WSON8 socket adapter for chip-off.
- Hot-air rework station, flux, and tweezers for chip-off; a multimeter to confirm chip voltage.
- A logic-level shifter or a 1.8 V-capable programmer if the target flash is 1.8 V.
- Software:
  ```bash
  sudo apt install flashrom
  # For Raspberry Pi SPI host:
  # echo 'dtparam=spi=on' | sudo tee -a /boot/config.txt && sudo reboot
  pip install ""   # this skill's analyzer is pure stdlib; binwalk is optional below
  sudo apt install binwalk    # optional, for cross-checking carved partitions
  ```
- Written authorization to open and test the target device.

## Objectives

- Identify the flash chip's part number, package, voltage, and capacity before connecting.
- Wire a flashrom-supported programmer in-circuit or via socket and confirm the JEDEC ID probe.
- Dump the flash and verify integrity with multiple reads and matching hashes.
- Compute per-region entropy and locate partition/magic headers to build an offset map.
- Identify bootloader, kernel, and root filesystem boundaries for downstream extraction.
- Document chip protection (encryption, status-register lock bits) and secrets found in plaintext.

## MITRE ATT&CK Mapping

| ID | Name | Tactic | Where it shows up |
|----|------|--------|-------------------|
| T1200 | Hardware Additions | Initial Access | Attaching a programmer/test clip to read the on-board SPI flash. |
| T1542 | Pre-OS Boot | Defense Evasion / Persistence | Recovering and analyzing the bootloader region from the flash image. |
| T1078 | Valid Accounts | Initial Access / Privilege Escalation | Reusing credentials/keys recovered from the dumped firmware. |

## Workflow

### 1. Identify the flash chip

Read the silkscreen part number under magnification and look it up. The package, voltage, and size determine the clip/adapter and whether a 1.8 V programmer is required.

```bash
# Example part numbers and what they mean:
#   W25Q64FV   -> Winbond, 64 Mbit (8 MiB), 3.3V, SOIC8
#   W25Q64FW   -> Winbond, 64 Mbit (8 MiB), 1.8V  (the 'W' suffix = 1.8V!)
#   MX25L12835F-> Macronix, 128 Mbit (16 MiB), 3.3V
#   GD25Q128   -> GigaDevice, 128 Mbit (16 MiB), 3.3V
# Confirm chip VCC with a multimeter on the powered board before clipping.
```

### 2. Wire the programmer and probe for the JEDEC ID

Align pin 1 (the dot on the chip) to pin 1 of the clip. Probe without writing first — a clean JEDEC ID confirms wiring and voltage.

```bash
# CH341A:
flashrom -p ch341a_spi
# Raspberry Pi SPI host at 8 MHz:
flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=8000
# FT2232H mini-module:
flashrom -p ft2232_spi:type=2232H,port=A,divisor=4
# A successful probe prints e.g.:
#   Found Winbond flash chip "W25Q64.V" (8192 kB, SPI) on ch341a_spi.
# If multiple chips match, pin the exact one with -c:
flashrom -p ch341a_spi -c "W25Q64.V"
```

### 3. Dump the flash and verify integrity

Read at least twice and compare hashes. Bus noise (long clip leads, marginal voltage) shows up as differing reads — lower `spispeed` and retry until two reads agree.

```bash
flashrom -p ch341a_spi -c "W25Q64.V" -r dump1.bin
flashrom -p ch341a_spi -c "W25Q64.V" -r dump2.bin
sha256sum dump1.bin dump2.bin     # the two hashes MUST match
cmp dump1.bin dump2.bin && echo "OK: reads identical"
# Verify the trusted dump back against the chip:
flashrom -p ch341a_spi -c "W25Q64.V" -v dump1.bin
```

### 4. Map partitions and entropy with the analyzer

Scan the verified dump for known magic headers and per-block entropy to produce an offset map of bootloader, kernel, and filesystem regions.

```bash
python3 scripts/agent.py map --image dump1.bin --block 4096
# Example output:
#   0x000000  4.2  u-boot / raw code (low entropy)
#   0x040000  7.9  uImage  magic 0x27051956 (LZMA kernel)
#   0x150000  7.5  SquashFS magic 'hsqs'
#   0x7F0000  1.1  config/NVRAM (mostly 0xFF)
```

### 5. Cross-check and carve with binwalk

Confirm the analyzer's findings and carve the regions for downstream work.

```bash
binwalk dump1.bin                 # signature scan to confirm offsets
binwalk -e dump1.bin              # extract recognized components
# Manually carve a region the analyzer flagged (offset 0x150000, len 0x6A0000):
dd if=dump1.bin of=rootfs.squashfs bs=1 skip=$((0x150000)) count=$((0x6A0000))
unsquashfs -d rootfs rootfs.squashfs
```

### 6. Triage secrets and document protection state

Pull strings and look for plaintext secrets, then record whether the chip/image was encrypted or write-protected.

```bash
python3 scripts/agent.py strings --image dump1.bin --min 8 --flag-secrets
strings -n 10 dump1.bin | grep -iE "password|BEGIN .*PRIVATE KEY|api[_-]?key"
# Document: was the image encrypted (high uniform entropy everywhere)?
# Were status-register block-protect (BP) bits set (flashrom warns on write-protect)?
```

## Tools and Resources

| Resource | Link |
|----------|------|
| flashrom (official site) | https://www.flashrom.org/ |
| flashrom supported hardware | https://www.flashrom.org/supported_hw/index.html |
| binwalk | https://github.com/ReFirmLabs/binwalk |
| sigrok (verify SPI wiring) | https://sigrok.org/ |
| OWASP Firmware Security Testing Methodology (FSTM) | https://github.com/scriptingxss/owasp-fstm |
| NIST SP 800-193 Platform Firmware Resiliency | https://csrc.nist.gov/pubs/sp/800/193/final |

## Flash Chip Family Reference

| Family prefix | Vendor | Voltage clue | Common sizes | Package |
|---------------|--------|--------------|--------------|---------|
| W25Q…V / W25Q…W | Winbond | `V`=3.3 V, `W`=1.8 V | 8–256 Mbit | SOIC8 / WSON8 |
| MX25L… / MX25U… | Macronix | `L`=3.3 V, `U`=1.8 V | 8–256 Mbit | SOIC8 / WSON8 |
| GD25Q… / GD25LQ… | GigaDevice | `Q`=3.3 V, `LQ`=1.8 V | 8–256 Mbit | SOIC8 / WSON8 |
| S25FL… | Spansion/Cypress | check datasheet | 16–512 Mbit | SOIC8 / SOIC16 |
| EN25Q… | Eon | 3.3 V typical | 8–128 Mbit | SOIC8 |

| Magic | Bytes | Meaning |
|-------|-------|---------|
| uImage | `0x27051956` | U-Boot legacy image header (kernel/ramdisk). |
| FIT / DTB | `0xd00dfeed` | Flattened device tree / FIT image. |
| SquashFS | `hsqs` / `sqsh` | Compressed read-only root filesystem. |
| JFFS2 | `0x1985` (LE `85 19`) | Journalling flash filesystem. |
| CramFS | `0x28cd3d45` | Compressed ROM filesystem. |
| UBI | `UBI#` | UBI volume on raw NAND. |

## Validation Criteria

- [ ] Chip part number, package, voltage, and capacity identified before connecting.
- [ ] Programmer wired with correct pin-1 orientation and JEDEC ID probed cleanly.
- [ ] At least two reads taken and their SHA-256 hashes match.
- [ ] Dump verified back against the chip with `flashrom -v`.
- [ ] Per-block entropy computed and partition/magic offset map produced.
- [ ] Bootloader, kernel, and root filesystem boundaries identified and carved.
- [ ] Plaintext secrets triaged; encryption / write-protection state documented.
- [ ] Image hashed and stored with chain-of-custody notes.
