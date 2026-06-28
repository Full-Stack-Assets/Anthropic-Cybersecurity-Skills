# Standards and References — Analyzing Bare-Metal Firmware with Ghidra

## MITRE ATT&CK Techniques

| ID | Name | Tactic | Rationale |
|----|------|--------|-----------|
| T1542 | Pre-OS Boot | Defense Evasion / Persistence | Bare-metal firmware is the pre-OS execution layer under analysis. |
| T1601 | Modify System Image | Defense Evasion | Assessing/identifying unsigned or tamper-able firmware update logic. |
| T1059 | Command and Scripting Interpreter | Execution | Firmware command handlers that act on externally supplied input. |

## NIST CSF 2.0

| ID | Function | Rationale |
|----|----------|-----------|
| ID.RA-01 | Identify (Risk Assessment) | Vulnerabilities in firmware logic and update validation are identified. |
| PR.PS-01 | Protect (Platform Security) | Evaluating platform/firmware integrity controls (secure boot, signed updates). |
| DE.AE-02 | Detect (Adverse Event Analysis) | Static analysis characterizes malicious or tamper-able firmware behavior. |
| ID.AM-08 | Identify (Asset Management) | Firmware components and their architecture are inventoried. |

## Official Resources

- Ghidra: https://ghidra-sre.org/
- Ghidra releases (NSA): https://github.com/NationalSecurityAgency/ghidra/releases
- SVD-Loader for Ghidra: https://github.com/leveldown-security/SVD-Loader-Ghidra
- CMSIS-SVD device files: https://github.com/cmsis-svd/cmsis-svd
- Capstone disassembler: https://www.capstone-engine.org/
- ARM developer documentation: https://developer.arm.com/documentation/
- OWASP Firmware Security Testing Methodology (FSTM): https://github.com/scriptingxss/owasp-fstm
- NIST SP 800-193 Platform Firmware Resiliency: https://csrc.nist.gov/pubs/sp/800/193/final

## Key Standards / Research

- ARMv7-M / ARMv8-M Architecture Reference Manual (vector table, exception model).
- CMSIS-SVD (System View Description) schema for peripheral register definitions.
- NIST SP 800-193 — Platform Firmware Resiliency (protection, detection, recovery).
- NIST SP 800-147 — BIOS Protection Guidelines (firmware update authentication principles).

## Related Skills

- dumping-and-analyzing-spi-flash-memory — acquire the bare-metal blob.
- extracting-firmware-via-uart-and-jtag-interfaces — JTAG/SWD memory dump of MCU flash.
- performing-firmware-extraction-with-binwalk — confirm there is no carve-able filesystem.
- reverse-engineering-iot-firmware-filesystems — for Linux-based firmware (contrast).
- emulating-firmware-for-dynamic-analysis-with-qemu — dynamic complement to static RE.
