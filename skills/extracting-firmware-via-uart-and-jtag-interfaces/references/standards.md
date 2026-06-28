# Standards and References — Extracting Firmware via UART and JTAG Interfaces

## MITRE ATT&CK Techniques

| ID | Name | Tactic | Rationale |
|----|------|--------|-----------|
| T1200 | Hardware Additions | Initial Access | Physically attaching a UART/JTAG probe or programmer to the target board to interact with it. |
| T1542 | Pre-OS Boot | Defense Evasion / Persistence | Interrupting the bootloader (U-Boot) before the OS loads to obtain a shell and read flash. |
| T1078 | Valid Accounts | Initial Access / Privilege Escalation | Reusing credentials and keys recovered from the console or extracted flash image. |

## NIST CSF 2.0

| ID | Function | Rationale |
|----|----------|-----------|
| ID.AM-08 | Identify (Asset Management) | Hardware and firmware components are inventoried; debug-interface exposure is part of the asset profile. |
| ID.RA-01 | Identify (Risk Assessment) | Vulnerabilities such as exposed/unlocked debug interfaces are identified and recorded. |
| PR.PS-01 | Protect (Platform Security) | Configuration management — disabling production debug interfaces and enabling read-out protection. |
| DE.CM-01 | Detect (Continuous Monitoring) | Networks and physical environment are monitored; physical tampering/probing is a detectable event. |

## Official Resources

- OpenOCD: https://openocd.org/
- OpenOCD source and target configs: https://github.com/openocd-org/openocd
- JTAGulator: http://www.grandideastudio.com/jtagulator/
- JTAGenum: https://github.com/cyphunk/JTAGenum
- sigrok / PulseView: https://sigrok.org/
- U-Boot documentation: https://docs.u-boot.org/
- OWASP Firmware Security Testing Methodology (FSTM): https://github.com/scriptingxss/owasp-fstm
- NIST SP 800-193 Platform Firmware Resiliency Guidelines: https://csrc.nist.gov/pubs/sp/800/193/final

## Key Standards / Research

- NIST SP 800-193 — Platform Firmware Resiliency Guidelines (protection, detection, recovery).
- IEEE 1149.1 — Standard Test Access Port and Boundary-Scan Architecture (JTAG).
- ARM Debug Interface Architecture Specification (ADIv5/ADIv6, SWD/JTAG-DP).
- Joe Grand, "JTAGulator: Assisted Discovery of On-Chip Debug Interfaces" (DEF CON 21).
- OWASP IoT Security Testing Guide / Top 10 (insecure/exposed debug interfaces).

## Related Skills

- dumping-and-analyzing-spi-flash-memory — off-board chip-off and in-circuit SPI flash reads.
- performing-firmware-extraction-with-binwalk — carving filesystems from a recovered image.
- emulating-firmware-for-dynamic-analysis-with-qemu — running the extracted firmware.
- reverse-engineering-iot-firmware-filesystems — triaging the extracted root filesystem.
- analyzing-bare-metal-firmware-with-ghidra — reversing a bare-metal/RTOS dump from JTAG.
