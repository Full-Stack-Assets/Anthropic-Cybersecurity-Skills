---
name: emulating-firmware-for-dynamic-analysis-with-qemu
description: Performs dynamic analysis of extracted embedded firmware by emulating it with QEMU, choosing between user-mode (chroot + qemu-user-static) and full-system emulation, automating the workflow with FirmAE or Firmadyne, bringing up network interfaces and NVRAM shims, and then triaging and fuzzing the running web and network services for vulnerabilities. Covers architecture/endianness detection from busybox, init-service discovery, and constructing the correct qemu-system invocation.
domain: cybersecurity
subdomain: firmware-analysis
tags:
- firmware
- qemu
- emulation
- firmae
- firmadyne
- dynamic-analysis
- iot-security
- fuzzing
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.RA-01
- DE.CM-01
- PR.PS-01
- DE.AE-02
mitre_attack:
- T1190
- T1059
- T1505
---
# Emulating Firmware for Dynamic Analysis with QEMU

> **Authorized Use Only:** Only emulate and test firmware you own or are explicitly authorized in writing to analyze. Emulated services may contain copyrighted vendor code; respect licensing and the DMCA. Run emulation in an isolated VM/network namespace so a vulnerable or malicious firmware cannot reach production systems.

## Overview

Once a firmware image has been extracted (via binwalk, chip-off, or a debug interface), static analysis only goes so far — many vulnerabilities live in the *runtime behavior* of the web server, UPnP daemon, or custom binary services. **QEMU** lets an analyst run that firmware on a workstation without the physical device, enabling live request fuzzing, debugging, and exploit development. This is dynamic analysis of the very services an attacker would target for **T1190 — Exploit Public-Facing Application**; gaining code execution against an emulated shell-spawning binary corresponds to **T1059 — Command and Scripting Interpreter**, and discovering or implanting a web backdoor maps to **T1505 — Server Software Component**.

There are two emulation modes. **User-mode** emulation (`qemu-<arch>-static` + `chroot` over the extracted root filesystem, using `binfmt_misc`) runs a single foreign-architecture binary on the host kernel — fast and ideal for poking one daemon (e.g. `httpd`) or a CGI handler, but it cannot model device-specific hardware, NVRAM, or `/proc` quirks. **Full-system** emulation (`qemu-system-arm`, `qemu-system-mips`, etc.) boots a complete kernel + the firmware's filesystem as a virtual machine — slower and fiddlier (you must supply a compatible kernel/DTB and bring up networking) but it faithfully reproduces the device, including its init scripts and inter-process behavior.

Because getting full-system emulation right by hand is tedious, the field uses orchestration frameworks. **Firmadyne** (the original research system) and the more robust **FirmAE** automate filesystem inference, kernel selection, NVRAM emulation (via a `libnvram` shim that intercepts `nvram_get`/`nvram_set`), network-interface bring-up, and a "best-effort" boot that reaches a pingable IP and a reachable web UI. The **Firmware Analysis Toolkit (FAT)** wraps Firmadyne for convenience. The analyst's job is to pick the mode, detect the target architecture/endianness (most reliably from the ELF header of `busybox`), enumerate network-facing init services, launch the emulator, and then triage and fuzz the live services.

## When to Use

- You have an extracted root filesystem and want to exercise its services live, not just read them.
- Developing or validating an exploit for an embedded web server, UPnP, or custom TCP service.
- Fuzzing CGI handlers or binary protocols without risking (or even possessing) physical hardware.
- Reproducing a reported CVE against a specific firmware version in a controlled VM.
- Scaling analysis across many firmware images where physical bring-up is impractical.
- Verifying that a vendor patch actually removes a runtime vulnerability.

## Prerequisites

- A Linux host (ideally a disposable VM/container) with QEMU:
  ```bash
  sudo apt install qemu-user-static qemu-system-arm qemu-system-mips binfmt-support
  sudo apt install binwalk     # to extract the rootfs first
  ```
- For user-mode chroot: the matching `qemu-<arch>-static` binary and `binfmt_misc` enabled.
- For orchestrated full-system emulation, FirmAE or Firmadyne:
  ```bash
  git clone --recursive https://github.com/pr0v3rbs/FirmAE && cd FirmAE && ./download.sh && ./install.sh
  # or Firmadyne:
  git clone --recursive https://github.com/firmadyne/firmadyne
  # or the Firmware Analysis Toolkit wrapper:
  git clone https://github.com/attify/firmware-analysis-toolkit
  ```
- The extracted root filesystem (e.g. from `binwalk -e`), and root/sudo for `binfmt_misc` and TAP networking.
- Written authorization to analyze the firmware.

## Objectives

- Determine the firmware's CPU architecture and endianness from the busybox ELF header.
- Enumerate network-facing init services (init scripts, inetd, web servers) before launch.
- Choose user-mode vs. full-system emulation appropriate to the analysis goal.
- Bring up the emulated firmware to a reachable IP and a responsive web/network service.
- Triage and fuzz the running services and capture crashes for follow-up.
- Document reachable attack surface and any runtime vulnerabilities found.

## MITRE ATT&CK Mapping

| ID | Name | Tactic | Where it shows up |
|----|------|--------|-------------------|
| T1190 | Exploit Public-Facing Application | Initial Access | Fuzzing/exploiting the emulated web server and network daemons. |
| T1059 | Command and Scripting Interpreter | Execution | Achieving command execution against a vulnerable emulated binary/CGI. |
| T1505 | Server Software Component | Persistence | Discovering or planting a web shell/backdoor module in the firmware's web stack. |

## Workflow

### 1. Extract the rootfs and detect architecture/endianness

Carve the filesystem, then read the ELF header of `busybox` (or any core binary) — it tells you the architecture and byte order, which determine the QEMU binary and kernel you need.

```bash
binwalk -Me firmware.bin                     # recursive extract -> _firmware.bin.extracted/
ROOT=$(find . -name busybox -type f | head -1 | xargs dirname | xargs dirname)
file "$ROOT/bin/busybox"
# e.g. "ELF 32-bit LSB executable, MIPS, MIPS-I ... " -> mipsel (little-endian MIPS)
# Or use the helper for a structured summary + a suggested qemu invocation:
python3 scripts/agent.py inspect --rootfs "$ROOT"
```

### 2. Enumerate network-facing init services

Read the init scripts and inetd config so you know what should come up and what to target.

```bash
python3 scripts/agent.py services --rootfs "$ROOT"
# Manual cross-check:
cat "$ROOT/etc/init.d/rcS" 2>/dev/null
grep -RniE "httpd|lighttpd|uhttpd|telnetd|dropbear|upnpd|miniupnpd" "$ROOT/etc" "$ROOT/etc/init.d"
cat "$ROOT/etc/inetd.conf" 2>/dev/null
```

### 3. User-mode emulation of a single service

Fastest path to poke one daemon. Copy in the static QEMU binary, then `chroot` and run the target.

```bash
sudo cp "$(which qemu-mipsel-static)" "$ROOT/usr/bin/"
sudo chroot "$ROOT" /usr/bin/qemu-mipsel-static /bin/busybox     # sanity check
# Launch the web server inside the chroot (foreground, verbose):
sudo chroot "$ROOT" /usr/bin/qemu-mipsel-static /usr/sbin/httpd -p 8080 -h /www
# Then fuzz/curl it from the host:
curl -s http://127.0.0.1:8080/ | head
```

### 4. Full-system emulation with FirmAE

Let FirmAE infer the kernel/NVRAM and bring the device up on a tap interface to a reachable IP.

```bash
cd FirmAE
# 'run' mode: extract, infer, and boot to an interactive emulated device
sudo ./run.sh -r netgear firmware.bin
# FirmAE prints the assigned IP, e.g.:  [*] firmware - emulation IP: 192.168.0.1
ping -c2 192.168.0.1
curl -s http://192.168.0.1/ | head        # the device web UI, now reachable
# 'check' mode just reports whether emulation+network succeeds (good for triage at scale):
sudo ./run.sh -c netgear firmware.bin
```

### 5. Manual full-system invocation (when you need control)

For non-orchestrated targets, construct the qemu-system command directly with a Debian/Firmadyne kernel and a TAP device.

```bash
sudo ip tuntap add dev tap0 mode tap && sudo ip addr add 192.168.0.2/24 dev tap0 && sudo ip link set tap0 up
qemu-system-mipsel \
  -M malta -kernel vmlinux-3.2.0-4-4kc-malta -m 256 \
  -drive file=rootfs.ext2,format=raw -append "root=/dev/sda1 console=ttyS0" \
  -netdev tap,id=n0,ifname=tap0,script=no,downscript=no \
  -device pcnet,netdev=n0 -nographic
```

### 6. Triage and fuzz the live services

With a reachable IP, enumerate then fuzz. Attach `gdb`/`gdb-multiarch` via QEMU's `-g` stub for crash triage.

```bash
nmap -sV -p- 192.168.0.1                                   # map open services
ffuf -u http://192.168.0.1/FUZZ -w /usr/share/wordlists/dirb/common.txt   # content discovery
# Fuzz a CGI parameter for command injection / overflow:
ffuf -u "http://192.168.0.1/cgi-bin/admin?cmd=FUZZ" -w payloads.txt -mc all
# Debug a crashing binary under user-mode QEMU (gdb stub on :1234):
qemu-mipsel-static -g 1234 ./vuln_cgi & gdb-multiarch -ex 'target remote :1234' ./vuln_cgi
```

## Tools and Resources

| Resource | Link |
|----------|------|
| QEMU | https://www.qemu.org/ |
| FirmAE | https://github.com/pr0v3rbs/FirmAE |
| Firmadyne | https://github.com/firmadyne/firmadyne |
| Firmware Analysis Toolkit (FAT) | https://github.com/attify/firmware-analysis-toolkit |
| binwalk | https://github.com/ReFirmLabs/binwalk |
| ffuf (fuzzer) | https://github.com/ffuf/ffuf |
| OWASP Firmware Security Testing Methodology (FSTM) | https://github.com/scriptingxss/owasp-fstm |

## Emulation Mode Reference

| Aspect | User-mode (`qemu-<arch>-static`) | Full-system (`qemu-system-<arch>`) |
|--------|----------------------------------|------------------------------------|
| Scope | One binary at a time | Whole device (kernel + rootfs) |
| Speed | Fast | Slower |
| Hardware/NVRAM | Not modeled | Modeled (with shims via FirmAE/Firmadyne) |
| Networking | Host network | TAP/virtual NIC |
| Best for | CGI/daemon fuzzing, quick triage | Faithful device repro, multi-service flows |

| Architecture (from `file busybox`) | QEMU user binary | qemu-system binary |
|------------------------------------|------------------|--------------------|
| ARM LSB (little-endian) | `qemu-arm-static` | `qemu-system-arm` |
| ARM MSB (big-endian) | `qemu-armeb-static` | `qemu-system-arm` |
| MIPS LSB (mipsel) | `qemu-mipsel-static` | `qemu-system-mipsel` |
| MIPS MSB (mips) | `qemu-mips-static` | `qemu-system-mips` |
| AArch64 | `qemu-aarch64-static` | `qemu-system-aarch64` |

## Validation Criteria

- [ ] Architecture and endianness determined from the busybox ELF header.
- [ ] Network-facing init services enumerated before launch.
- [ ] Emulation mode (user vs. full-system) chosen and justified for the goal.
- [ ] Firmware emulated to a reachable IP and a responsive service (or documented why not).
- [ ] Live services enumerated (`nmap`) and fuzzed (`ffuf`/custom).
- [ ] Crashes captured and triaged with a gdb stub where applicable.
- [ ] Emulation isolated from production networks throughout.
- [ ] Reachable attack surface and runtime findings documented.
