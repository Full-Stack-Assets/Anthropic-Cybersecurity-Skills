# Standards and References — Reverse Engineering IoT Firmware Filesystems

## MITRE ATT&CK Techniques

| ID | Name | Tactic | Rationale |
|----|------|--------|-----------|
| T1552 | Unsecured Credentials | Credential Access | Hardcoded passwords, private keys, and secrets stored in firmware files and configs. |
| T1078 | Valid Accounts | Initial Access / Privilege Escalation | Reusing recovered or backdoor accounts and keys to authenticate. |
| T1505 | Server Software Component | Persistence | Backdoor or vulnerable web/CGI components present in the firmware web stack. |

## NIST CSF 2.0

| ID | Function | Rationale |
|----|----------|-----------|
| ID.RA-01 | Identify (Risk Assessment) | Vulnerabilities such as weak hashes and embedded secrets are identified. |
| PR.AA-01 | Protect (Identity Management & Authentication) | Assessing identity/credential management — accounts, hashes, and keys. |
| DE.CM-01 | Detect (Continuous Monitoring) | The filesystem is examined for malicious/weak content and exposed services. |
| ID.AM-08 | Identify (Asset Management) | Firmware components and their embedded artifacts are inventoried. |

## Official Resources

- firmwalker: https://github.com/craigz28/firmwalker
- John the Ripper: https://www.openwall.com/john/
- hashcat: https://hashcat.net/hashcat/
- Ghidra: https://ghidra-sre.org/
- OpenSSL: https://www.openssl.org/
- OWASP Firmware Security Testing Methodology (FSTM): https://github.com/scriptingxss/owasp-fstm
- OWASP IoT Top 10 / IoT Project: https://owasp.org/www-project-internet-of-things/
- NIST SP 800-193 Platform Firmware Resiliency: https://csrc.nist.gov/pubs/sp/800/193/final

## Key Standards / Research

- NIST IR 8259 — Foundational Cybersecurity Activities for IoT Device Manufacturers.
- NISTIR 8228 — Considerations for Managing IoT Cybersecurity and Privacy Risks.
- OWASP IoT Top 10 (I1 Weak/Guessable/Hardcoded Passwords; I2 Insecure Network Services).
- crypt(3) / yescrypt password-hashing references (Openwall).

## Related Skills

- performing-firmware-extraction-with-binwalk — produces the filesystem analyzed here.
- dumping-and-analyzing-spi-flash-memory — acquire the image to extract.
- emulating-firmware-for-dynamic-analysis-with-qemu — dynamically test the discovered services.
- analyzing-bare-metal-firmware-with-ghidra — for firmware without a filesystem.
- extracting-firmware-via-uart-and-jtag-interfaces — on-device acquisition path.
