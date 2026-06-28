# Standards and References — Detecting Rogue Access Points and Evil Twins

## MITRE ATT&CK Techniques

| ID | Name | Tactic | Rationale |
|----|------|--------|-----------|
| T1557 | Adversary-in-the-Middle | Credential Access / Collection | An evil twin inserts itself between victim clients and the legitimate network. |
| T1040 | Network Sniffing | Discovery / Credential Access | Once clients associate to the rogue AP, cleartext traffic is captured. |
| T1200 | Hardware Additions | Initial Access | A physical rogue AP is connected to an internal switch/wall jack. |
| T1071 | Application Layer Protocol | Command and Control / Collection | Captive portals / HTTP(S) harvesting on the rogue AP (Karma). |

## NIST CSF 2.0

| ID | Function | Rationale |
|----|----------|-----------|
| DE.CM-01 | Detect — Continuous Monitoring (networks) | Continuous monitor-mode capture of the RF environment is the primary control. |
| DE.AE-02 | Detect — Adverse Event Analysis | Scoring beacon anomalies against the allowlist analyzes detected events. |
| ID.AM-03 | Identify — Asset Management (communication/data flows) | The trusted-AP allowlist inventories authorized wireless assets. |
| PR.AA-03 | Protect — Authentication | Detecting impersonation protects the authentication boundary of the WLAN. |

## Official Resources

- Kismet: https://www.kismetwireless.net/
- Aircrack-ng: https://www.aircrack-ng.org/
- Wireshark: https://www.wireshark.org/
- sensepost MANA toolkit: https://github.com/sensepost/mana
- NIST Cybersecurity Framework 2.0: https://www.nist.gov/cyberframework

## Key Standards / Research

- IEEE 802.11-2020 — beacon/probe frame format, RSN information element, MAC layer.
- NIST SP 800-153 — Guidelines for Securing Wireless Local Area Networks (WLANs): https://csrc.nist.gov/pubs/sp/800/153/final
- NIST SP 800-97 — Establishing Wireless Robust Security Networks (802.11i): https://csrc.nist.gov/pubs/sp/800/97/final
- Dino A. Dai Zovi & Shane Macaulay, "Attacking Automatic Wireless Network Selection" (Karma, 2005).
- sensepost, "Improvements in rogue AP attacks — MANA" (2014).

## Related Skills

- attacking-wpa3-sae-with-dragonblood — the rogue/evil-twin AP is the downgrade vector this skill detects.
- testing-8021x-eap-wireless-authentication — rogue RADIUS / enterprise evil twins.
- performing-sdr-signal-analysis-with-gnuradio — RF-layer survey and direction-finding context.
