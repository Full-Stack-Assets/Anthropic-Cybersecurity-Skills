# Standards and References — Assessing RFID and NFC Access Control Systems

## MITRE ATT&CK Techniques

| ID | Name | Tactic | Rationale |
|----|------|--------|-----------|
| T1200 | Hardware Additions | Initial Access | A cloned/magic card or Proxmark3/Flipper emulator is presented to a physical reader. |
| T1078 | Valid Accounts | Initial Access / Defense Evasion | A working badge clone grants legitimate physical access as the badge holder. |
| T1557 | Adversary-in-the-Middle | Credential Access | Capturing/relaying the reader-card CRYPTO1 exchange to recover keys. |
| T1110 | Brute Force | Credential Access | Default-key trials and CRYPTO1 key-recovery against MIFARE Classic. |

## NIST CSF 2.0

| ID | Function | Rationale |
|----|----------|-----------|
| PR.AA-01 | Protect — Identities and credentials are managed | Badge credentials and their cryptographic keys are the managed identities under test. |
| PR.AA-06 | Protect — Physical access is managed | Access-control readers/badges enforce physical access; cloning defeats it. |
| ID.RA-01 | Identify — Vulnerabilities are identified | Cloneability assessment identifies and records PACS vulnerabilities. |
| DE.CM-01 | Detect — Continuous Monitoring | Reader/PACS event monitoring detects anomalous or cloned-badge use. |

## Official Resources

- Proxmark3 (Iceman/RRG): https://github.com/RfidResearchGroup/proxmark3
- libnfc: https://github.com/nfc-tools/libnfc
- mfoc: https://github.com/nfc-tools/mfoc
- mfcuk: https://github.com/nfc-tools/mfcuk
- NXP MIFARE DESFire EV3: https://www.nxp.com/products/MF3DHX3
- NIST Cybersecurity Framework 2.0: https://www.nist.gov/cyberframework

## Key Standards / Research

- ISO/IEC 14443 — Proximity cards (13.56 MHz, MIFARE/DESFire air interface).
- ISO/IEC 18000-2 — Low-frequency (125 kHz) RFID air interface.
- NIST SP 800-116 Rev.1 — Guidelines for the Use of PIV Credentials in PACS: https://csrc.nist.gov/pubs/sp/800/116/r1/final
- Nohl, Evans, Starbug & Plötz, "Reverse-Engineering a Cryptographic RFID Tag" (USENIX Security 2008) — CRYPTO1 break.
- Garcia et al., "Dismantling MIFARE Classic" (ESORICS 2008) and "Wirelessly Pickpocketing a MIFARE Classic Card" (IEEE S&P 2009).
- Courtois, "The Dark Side of Security by Obscurity" (darkside attack, 2009).

## Related Skills

- detecting-rogue-access-points-and-evil-twins — adjacent physical/wireless attack surface.
- performing-sdr-signal-analysis-with-gnuradio — RF capture context for proximity protocols.
- attacking-wpa3-sae-with-dragonblood — related credential/key-recovery methodology.
