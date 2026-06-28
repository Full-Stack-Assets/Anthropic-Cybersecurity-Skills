# Standards and References — Performing SDR Signal Analysis with GNU Radio

## MITRE ATT&CK Techniques

| ID | Name | Tactic | Rationale |
|----|------|--------|-----------|
| T1040 | Network Sniffing | Discovery / Credential Access | Passive RF capture (spectrum survey, IQ recording) of device transmissions. |
| T1200 | Hardware Additions | Initial Access | An SDR or recorded signal driven as a transmitter against a target device. |
| T1557 | Adversary-in-the-Middle | Credential Access / Collection | Replay/relay of a captured fixed-code transmission to impersonate a transmitter. |
| T1059 | Command and Scripting Interpreter | Execution | GNU Radio flowgraphs and Python scripts orchestrate capture and demodulation. |

## NIST CSF 2.0

| ID | Function | Rationale |
|----|----------|-----------|
| ID.RA-01 | Identify — Vulnerabilities are identified | Fixed-code / replay-risk findings identify and record RF device vulnerabilities. |
| DE.CM-01 | Detect — Continuous Monitoring | Spectrum survey monitors the RF environment for unexpected emitters. |
| ID.AM-03 | Identify — Asset Management (communication/data flows) | The survey inventories the RF emitters and links in the environment. |
| PR.DS-02 | Protect — Data Security (data-in-transit) | Replay/encryption findings concern protection of data in transit over RF. |

## Official Resources

- GNU Radio: https://www.gnuradio.org/
- RTL-SDR (Osmocom): https://osmocom.org/projects/rtl-sdr/wiki
- HackRF: https://greatscottgadgets.com/hackrf/
- gqrx: https://gqrx.dk/
- inspectrum: https://github.com/miek/inspectrum
- Universal Radio Hacker: https://github.com/jopohl/urh
- rtl_433: https://github.com/merbanan/rtl_433
- NIST Cybersecurity Framework 2.0: https://www.nist.gov/cyberframework

## Key Standards / Research

- ITU Radio Regulations and national allocations (e.g. NTIA US chart: https://www.ntia.gov/page/2011/united-states-frequency-allocation-chart).
- US 47 CFR Part 15 — unlicensed/ISM device rules (315/433/868/915 MHz operation).
- ETSI EN 300 220 — Short Range Devices in the 25 MHz to 1000 MHz band.
- Kamkar, "Drive It Like You Hacked It" (DEF CON 23, 2015) — RollJam rolling-code attack.
- Garcia, Oswald, Kasper & Pavlidès, "Lock It and Still Lose It" / keyless-entry RF research.

## Related Skills

- detecting-rogue-access-points-and-evil-twins — RF-layer monitoring and direction-finding context.
- assessing-rfid-and-nfc-access-control-systems — adjacent proximity-RF assessment.
- attacking-wpa3-sae-with-dragonblood — Wi-Fi PHY/MAC capture context.
