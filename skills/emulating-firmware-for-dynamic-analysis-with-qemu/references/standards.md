# Standards and References — Emulating Firmware for Dynamic Analysis with QEMU

## MITRE ATT&CK Techniques

| ID | Name | Tactic | Rationale |
|----|------|--------|-----------|
| T1190 | Exploit Public-Facing Application | Initial Access | Fuzzing/exploiting the emulated web server and network daemons exposes input-handling flaws. |
| T1059 | Command and Scripting Interpreter | Execution | Achieving command/shell execution against a vulnerable emulated binary or CGI handler. |
| T1505 | Server Software Component | Persistence | Discovering or planting a web shell/backdoor component in the firmware's web stack. |

## NIST CSF 2.0

| ID | Function | Rationale |
|----|----------|-----------|
| ID.RA-01 | Identify (Risk Assessment) | Vulnerabilities in firmware services are identified through dynamic testing. |
| DE.CM-01 | Detect (Continuous Monitoring) | Emulated services are observed for anomalous/exploitable behavior. |
| PR.PS-01 | Protect (Platform Security) | Validating that platform/firmware services are hardened and patched. |
| DE.AE-02 | Detect (Adverse Event Analysis) | Crash/behavior analysis of emulated services characterizes adverse events. |

## Official Resources

- QEMU: https://www.qemu.org/
- FirmAE: https://github.com/pr0v3rbs/FirmAE
- Firmadyne: https://github.com/firmadyne/firmadyne
- Firmware Analysis Toolkit (FAT): https://github.com/attify/firmware-analysis-toolkit
- binwalk: https://github.com/ReFirmLabs/binwalk
- ffuf: https://github.com/ffuf/ffuf
- OWASP Firmware Security Testing Methodology (FSTM): https://github.com/scriptingxss/owasp-fstm
- NIST SP 800-193 Platform Firmware Resiliency: https://csrc.nist.gov/pubs/sp/800/193/final

## Key Standards / Research

- Chen et al., "Towards Automated Dynamic Analysis for Linux-based Embedded Firmware" (Firmadyne, NDSS 2016).
- Kim et al., "FirmAE: Towards Large-Scale Emulation of IoT Firmware for Dynamic Analysis" (ACSAC 2020).
- NIST SP 800-193 — Platform Firmware Resiliency Guidelines.
- QEMU system and user-mode emulation documentation.

## Related Skills

- performing-firmware-extraction-with-binwalk — produce the rootfs that gets emulated.
- dumping-and-analyzing-spi-flash-memory — acquire the firmware image to emulate.
- reverse-engineering-iot-firmware-filesystems — static triage before/after emulation.
- analyzing-bare-metal-firmware-with-ghidra — for firmware without a Linux filesystem.
- extracting-firmware-via-uart-and-jtag-interfaces — on-device acquisition path.
