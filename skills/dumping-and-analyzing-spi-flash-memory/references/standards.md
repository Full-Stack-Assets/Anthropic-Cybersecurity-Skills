# Standards and References — Dumping and Analyzing SPI Flash Memory

## MITRE ATT&CK Techniques

| ID | Name | Tactic | Rationale |
|----|------|--------|-----------|
| T1200 | Hardware Additions | Initial Access | Attaching a programmer/test clip to the board to read the SPI flash. |
| T1542 | Pre-OS Boot | Defense Evasion / Persistence | Recovering and analyzing the bootloader region from the flash image. |
| T1078 | Valid Accounts | Initial Access / Privilege Escalation | Reusing credentials/keys recovered from the dumped firmware. |

## NIST CSF 2.0

| ID | Function | Rationale |
|----|----------|-----------|
| ID.AM-08 | Identify (Asset Management) | Hardware/firmware components, including the flash chip, are inventoried. |
| ID.RA-01 | Identify (Risk Assessment) | Vulnerabilities such as plaintext secrets in flash and missing write-protection are identified. |
| PR.PS-01 | Protect (Platform Security) | Configuration management — flash encryption and status-register lock bits. |
| DE.AE-02 | Detect (Adverse Event Analysis) | Analysis of acquired firmware to understand potentially malicious or weak content. |

## Official Resources

- flashrom: https://www.flashrom.org/
- flashrom supported hardware: https://www.flashrom.org/supported_hw/index.html
- binwalk: https://github.com/ReFirmLabs/binwalk
- sigrok / PulseView: https://sigrok.org/
- OWASP Firmware Security Testing Methodology (FSTM): https://github.com/scriptingxss/owasp-fstm
- NIST SP 800-193 Platform Firmware Resiliency Guidelines: https://csrc.nist.gov/pubs/sp/800/193/final

## Key Standards / Research

- JEDEC JESD216 — Serial Flash Discoverable Parameters (SFDP).
- NIST SP 800-193 — Platform Firmware Resiliency (protection, detection, recovery).
- SquashFS, JFFS2, UBI/UBIFS on-flash format specifications.
- Shannon, "A Mathematical Theory of Communication" (entropy used for region classification).

## Related Skills

- extracting-firmware-via-uart-and-jtag-interfaces — alternative on-device extraction paths.
- performing-firmware-extraction-with-binwalk — carving filesystems from the dump.
- reverse-engineering-iot-firmware-filesystems — triaging the extracted root filesystem.
- emulating-firmware-for-dynamic-analysis-with-qemu — running the recovered firmware.
- analyzing-bare-metal-firmware-with-ghidra — reversing bare-metal regions of the dump.
