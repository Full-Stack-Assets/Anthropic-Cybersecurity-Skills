---
name: analyzing-bare-metal-firmware-with-ghidra
description: Reverse engineers raw bare-metal and RTOS firmware that has no filesystem in Ghidra by determining the CPU architecture and endianness, recovering the correct load/base address, fixing the memory map, locating the ARM Cortex-M vector table and reset handler, importing peripheral definitions with SVD-Loader to label memory-mapped I/O, and finding cryptographic constants and strings. Covers the heuristics for orienting an opaque binary blob that other tools cannot carve.
domain: cybersecurity
subdomain: firmware-analysis
tags:
- firmware
- ghidra
- bare-metal
- rtos
- cortex-m
- reverse-engineering
- svd-loader
- memory-map
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.RA-01
- PR.PS-01
- DE.AE-02
- ID.AM-08
mitre_attack:
- T1542
- T1601
- T1059
---
# Analyzing Bare-Metal Firmware with Ghidra

> **Authorized Use Only:** Only reverse engineer firmware you own or are explicitly authorized in writing to analyze. Firmware is typically copyrighted; respect licensing, the DMCA, and any anti-reverse-engineering clauses applicable to your jurisdiction and engagement.

## Overview

Not all firmware contains a Linux filesystem. Microcontroller and RTOS targets — sensors, motor controllers, smart-home endpoints, automotive ECUs — run **bare-metal** code or a small real-time OS (FreeRTOS, Zephyr, ThreadX) directly from flash, with no `passwd` file to grep and no SquashFS to carve. The image is an opaque blob of machine code, vector tables, and data. Reverse engineering it in **Ghidra** (the NSA's open-source SRE suite) is the only way to understand its behavior, and it begins with three orientation problems that, if gotten wrong, make the decompiler produce garbage: the **CPU architecture/endianness**, the **load/base address**, and the **memory map** (where flash, SRAM, and memory-mapped I/O live). This work supports MITRE ATT&CK **T1542 — Pre-OS Boot** (the firmware *is* the pre-OS layer) and is the analysis basis for detecting **T1601 — Modify System Image** (malicious firmware modification) and **T1059 — Command and Scripting Interpreter** style command handlers in firmware that accept external input.

Orientation uses well-known heuristics. For **ARM Cortex-M** (by far the most common 32-bit MCU family), the image typically begins with a **vector table**: the first 32-bit word is the **initial stack pointer** (a plausible value points into SRAM, e.g. `0x2000xxxx`), and the second word is the **reset handler address** (a code pointer into flash with the Thumb bit set, i.e. odd, e.g. `0x080001xx`). Confirming both, and that subsequent entries are odd code pointers clustered in a sensible flash range, both verifies "this is Cortex-M" *and* reveals the **base address** (the flash region the reset vector points into — commonly `0x08000000` on STM32, `0x00000000` on many others). Loading the blob at the wrong base leaves every absolute pointer dangling; loading at the right base makes Ghidra's references resolve.

With the base set, the next task is the **memory map and peripherals**. MCU firmware is dense with **memory-mapped I/O** accesses (e.g. reads/writes to `0x40000000`–`0x5FFFFFFF` on Cortex-M). Hand-labeling these is tedious, so the **SVD-Loader** Ghidra script imports a vendor **CMSIS-SVD** file and automatically creates labeled memory blocks and structures for every peripheral register (GPIO, UART, crypto, flash controller), turning anonymous `*(0x40021000)` writes into `RCC->CR`. From there, standard RE applies: cross-reference the strings and **cryptographic constants** (AES S-box, SHA-2 round constants, known IVs) the script and built-in analyzers surface, identify the main loop/scheduler, and map command handlers and update routines that process external data.

## When to Use

- The firmware has no extractable filesystem (binwalk finds nothing carve-able) — it is raw MCU/RTOS code.
- You recovered a bare-metal image via SPI flash dump or a JTAG/SWD memory read and need to understand it.
- Determining the architecture, endianness, and correct load address of an opaque blob.
- Labeling memory-mapped peripheral registers to make the decompilation readable.
- Locating crypto routines, hardcoded keys, or firmware-update/verification logic.
- Assessing whether a device validates firmware updates (signature/secure boot) — relevant to T1601.

## Prerequisites

- **Ghidra** (download from the official site; requires a JDK):
  ```bash
  # https://ghidra-sre.org/  (or https://github.com/NationalSecurityAgency/ghidra/releases)
  sudo apt install openjdk-21-jdk
  unzip ghidra_*_PUBLIC.zip && cd ghidra_*_PUBLIC && ./ghidraRun
  ```
- The **SVD-Loader** Ghidra script and a matching CMSIS-SVD file for the target MCU:
  ```bash
  git clone https://github.com/leveldown-security/SVD-Loader-Ghidra
  git clone https://github.com/cmsis-svd/cmsis-svd      # vendor .svd files
  ```
- The raw firmware blob (from the SPI-flash or JTAG/SWD skills) and, ideally, the MCU part number.
- Optional: `capstone`/`pip install capstone` for quick out-of-Ghidra disassembly sanity checks.
- Python 3.8+ (the companion architecture-detection helper is pure stdlib).
- Written authorization to analyze the firmware.

## Objectives

- Determine CPU architecture and endianness of the raw blob.
- Validate the ARM Cortex-M vector table and recover the correct load/base address.
- Configure Ghidra's language and memory map (flash, SRAM, peripheral regions).
- Run SVD-Loader to label memory-mapped peripheral registers.
- Identify strings, cryptographic constants, and firmware-update/verification logic.
- Document the device's command surface and secure-boot posture.

## MITRE ATT&CK Mapping

| ID | Name | Tactic | Where it shows up |
|----|------|--------|-------------------|
| T1542 | Pre-OS Boot | Defense Evasion / Persistence | The bare-metal firmware is the pre-OS execution layer being analyzed. |
| T1601 | Modify System Image | Defense Evasion | Assessing/finding unsigned or tamper-able firmware update logic. |
| T1059 | Command and Scripting Interpreter | Execution | Firmware command handlers that act on externally supplied input. |

## Workflow

### 1. Detect architecture, endianness, and a candidate base address

Before importing, sanity-check the blob. The companion script applies the Cortex-M vector-table heuristic to propose a base address.

```bash
python3 scripts/agent.py arch --image firmware.bin
# Example output:
#   [+] Cortex-M vector table looks valid
#       initial SP  = 0x20010000  (plausible SRAM)
#       reset addr  = 0x08000191  (Thumb code pointer, odd)
#   [+] suggested base/load address: 0x08000000  (ARM Cortex-M, little-endian)
```

### 2. Import into Ghidra with the right language and base address

Create a project, import the raw binary, and choose the language. For Cortex-M use **ARM Cortex little endian** and set the base to the address from step 1.

```bash
# Headless import (or do this in the GUI import dialog):
$GHIDRA_HOME/support/analyzeHeadless /tmp/proj fwproj \
  -import firmware.bin \
  -processor "ARM:LE:32:Cortex" \
  -loader BinaryLoader -loader-baseAddr 0x08000000 \
  -analysisTimeoutPerFile 600
# In the GUI: Language = "ARM / Cortex / little"; Options > Base Address = 0x08000000
```

### 3. Define the memory map (flash, SRAM, peripherals)

Tell Ghidra where flash, SRAM, and the peripheral region live so absolute references resolve. Use Window > Memory Map to add blocks.

```text
# Typical STM32F4 memory map (Window > Memory Map > +):
#   FLASH   0x08000000  length 0x00100000  r-x   (mapped to the file bytes)
#   SRAM    0x20000000  length 0x00020000  rw-   (uninitialized block)
#   PERIPH  0x40000000  length 0x20000000  rw-   volatile (MMIO)
#   SYSTEM  0xE0000000  length 0x10000000  rw-   (Cortex-M system / SCB / NVIC)
```

### 4. Mark the vector table and reset handler

Apply a function at the reset address and let Ghidra follow it. Disassembling the vector table turns the entry pointers into navigable functions (IRQ handlers).

```text
# In the GUI:
#   Go To (G) -> 0x08000004, read the reset vector value, Go To it, press F (create function).
#   Select the vector-table region -> Data > pointer array to auto-create handler refs.
#   Analysis > One Shot > "ARM Aggressive Instruction Finder" to recover Thumb code.
```

### 5. Label peripherals with SVD-Loader

Run the SVD-Loader script with the vendor SVD for the exact MCU. Every peripheral register becomes a named symbol.

```text
# Window > Script Manager > add the SVD-Loader script directory, then run:
#   SVD-Loader.py  ->  select STM32F407.svd
# Result: blocks like RCC, GPIOA, USART1, CRYP, FLASH get created and labeled,
# so *(0x40023800) reads now show as RCC->CR in the decompiler.
```

### 6. Find strings, crypto constants, and update logic

Surface secrets and the security-relevant routines.

```bash
# Out-of-Ghidra quick pass for strings + crypto constants + entropy:
python3 scripts/agent.py strings --image firmware.bin --min 6 --crypto
# In Ghidra:
#   Search > For Strings (look for version banners, AT commands, "OK"/"ERROR", URLs).
#   Search > Memory for known constants: AES S-box (0x63 0x7c 0x77 0x7b ...),
#     SHA-256 K[0]=0x428a2f98, CRC32 poly 0xEDB88320.
#   Follow xrefs from a firmware-update routine to see if it verifies a signature
#     (RSA/ECDSA) before writing flash -- absence indicates T1601 exposure.
```

## Tools and Resources

| Resource | Link |
|----------|------|
| Ghidra (official) | https://ghidra-sre.org/ |
| Ghidra releases (NSA) | https://github.com/NationalSecurityAgency/ghidra/releases |
| SVD-Loader for Ghidra | https://github.com/leveldown-security/SVD-Loader-Ghidra |
| CMSIS-SVD device files | https://github.com/cmsis-svd/cmsis-svd |
| Capstone disassembler | https://www.capstone-engine.org/ |
| ARM Cortex-M reference (vector table) | https://developer.arm.com/documentation/ |
| OWASP Firmware Security Testing Methodology (FSTM) | https://github.com/scriptingxss/owasp-fstm |

## Cortex-M Orientation Reference

| Item | Heuristic |
|------|-----------|
| Initial stack pointer (offset 0x00) | Points into SRAM (e.g. `0x2000xxxx`); top of RAM, word-aligned. |
| Reset handler (offset 0x04) | Code pointer into flash with Thumb bit set (value is **odd**). |
| Vector table entries | A run of odd code pointers in a tight flash range → confirms Cortex-M. |
| Base/load address | The flash region the reset vector targets (`0x08000000` STM32; varies). |
| Endianness | Almost always little-endian on Cortex-M. |

| Constant | Value | Indicates |
|----------|-------|-----------|
| AES S-box start | `63 7c 77 7b f2 6b 6f c5` | AES implementation. |
| SHA-256 K[0] | `0x428a2f98` | SHA-256. |
| CRC32 reflected poly | `0xEDB88320` | CRC32 integrity check. |
| MD5 init A | `0x67452301` | MD5. |

## Validation Criteria

- [ ] Architecture and endianness determined and justified.
- [ ] Cortex-M vector table validated (plausible SP + odd reset pointer) or alternative arch confirmed.
- [ ] Correct base/load address recovered and used at import.
- [ ] Memory map defined (flash, SRAM, peripheral, system regions).
- [ ] Reset handler and IRQ vectors turned into functions.
- [ ] SVD-Loader run; peripheral registers labeled.
- [ ] Strings and cryptographic constants identified; key/update logic located.
- [ ] Secure-boot / update-signature posture documented.
