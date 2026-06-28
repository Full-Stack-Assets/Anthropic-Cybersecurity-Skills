# Standards and References — Attacking WPA3-SAE with Dragonblood

## MITRE ATT&CK Techniques

| ID | Name | Tactic | Rationale |
|----|------|--------|-----------|
| T1557 | Adversary-in-the-Middle | Credential Access / Collection | Rogue WPA2-only AP and SAE/handshake relaying place the attacker between client and AP to force a downgrade. |
| T1040 | Network Sniffing | Discovery / Credential Access | Monitor-mode capture of beacons, SAE commit/confirm, and WPA2 four-way handshake frames. |
| T1110 | Brute Force | Credential Access | Offline dictionary attack on a downgraded WPA2 handshake or a side-channel-partitioned password space. |
| T1499 | Endpoint Denial of Service | Impact | Dragondrain floods SAE commit frames to exhaust the AP's expensive handshake computation. |

## NIST CSF 2.0

| ID | Function | Rationale |
|----|----------|-----------|
| PR.AA-03 | Protect — Identity Management, Authentication and Access Control | SAE/PMF posture and authentication strength are the core controls being validated. |
| PR.DS-02 | Protect — Data Security (data-in-transit) | WPA3 encryption protects wireless data in transit; downgrade undermines it. |
| DE.CM-01 | Detect — Continuous Monitoring (networks) | Monitoring for rogue WPA2 APs and SAE floods is the detective control. |
| ID.RA-01 | Identify — Risk Assessment (vulnerabilities identified) | Dragonblood CVE assessment identifies and records vulnerabilities in the WPA3 deployment. |

## Official Resources

- Dragonblood research site: https://wpa3.mathyvanhoef.com/
- dragonblood-tools: https://github.com/vanhoefm/dragonblood-tools
- dragondrain-and-time: https://github.com/vanhoefm/dragondrain-and-time
- hostap project (hostapd/wpa_supplicant): https://w1.fi/hostapd/
- Wi-Fi Alliance WPA3 security: https://www.wi-fi.org/discover-wi-fi/security
- NIST Cybersecurity Framework 2.0: https://www.nist.gov/cyberframework

## Key Standards / Research

- IEEE 802.11-2020 — SAE authentication and the RSN information element.
- IEEE 802.11w-2009 — Protected Management Frames (folded into 802.11-2020).
- RFC 7664 — Dragonfly Key Exchange (the PAKE underlying SAE): https://www.rfc-editor.org/rfc/rfc7664
- Vanhoef & Ronen, "Dragonblood: Analyzing the Dragonfly Handshake of WPA3 and EAP-pwd" (IEEE S&P 2020).
- Wi-Fi Alliance, WPA3 Specification v3.x — Hash-to-Element (H2E) PWE derivation.
- CVE-2019-9494, CVE-2019-9495, CVE-2019-9496, CVE-2019-9497, CVE-2019-9498, CVE-2019-9499.

## Related Skills

- detecting-rogue-access-points-and-evil-twins — detecting the rogue AP used for transition-mode downgrade.
- testing-8021x-eap-wireless-authentication — enterprise WPA3 and the related EAP-pwd Dragonblood flaws.
- performing-sdr-signal-analysis-with-gnuradio — RF-layer capture and survey context.
