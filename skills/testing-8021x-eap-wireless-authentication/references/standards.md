# Standards and References — Testing 802.1X/EAP Wireless Authentication

## MITRE ATT&CK Techniques

| ID | Name | Tactic | Rationale |
|----|------|--------|-----------|
| T1557 | Adversary-in-the-Middle | Credential Access / Collection | Evil-twin AP + rogue RADIUS sit between supplicant and the real auth server. |
| T1556 | Modify Authentication Process | Credential Access / Defense Evasion | Impersonating the trusted RADIUS authenticator subverts the auth flow to harvest the inner handshake. |
| T1078 | Valid Accounts | Initial Access / Privilege Escalation | A cracked MSCHAPv2 password is a working domain credential. |
| T1110 | Brute Force | Credential Access | Offline dictionary / DES cracking of the captured MSCHAPv2 challenge/response. |

## NIST CSF 2.0

| ID | Function | Rationale |
|----|----------|-----------|
| PR.AA-03 | Protect — Authentication | 802.1X/EAP authentication strength and server-cert validation are the controls under test. |
| PR.AA-01 | Protect — Identities and credentials managed | Domain credentials exposed via EAP are the managed identities at risk. |
| DE.CM-01 | Detect — Continuous Monitoring | Monitoring for rogue RADIUS / evil-twin enterprise APs is the detective control. |
| ID.RA-01 | Identify — Vulnerabilities identified | Credential-theft testing identifies and records EAP configuration vulnerabilities. |

## Official Resources

- hostapd-wpe: https://github.com/aircrack-ng/hostapd-wpe
- eaphammer: https://github.com/s0lst1c3/eaphammer
- asleap: https://github.com/joswr1ght/asleap
- FreeRADIUS: https://www.freeradius.org/
- hashcat: https://hashcat.net/hashcat/
- NIST Cybersecurity Framework 2.0: https://www.nist.gov/cyberframework

## Key Standards / Research

- IEEE 802.1X-2020 — Port-Based Network Access Control.
- IEEE 802.11-2020 — WPA-Enterprise (RSN with 802.1X AKM).
- RFC 3748 — Extensible Authentication Protocol (EAP): https://www.rfc-editor.org/rfc/rfc3748
- RFC 5216 — EAP-TLS Authentication Protocol: https://www.rfc-editor.org/rfc/rfc5216
- RFC 2759 — Microsoft PPP CHAP Extensions, Version 2 (MSCHAPv2): https://www.rfc-editor.org/rfc/rfc2759
- Marlinspike & Hulton, "Defeating PPTP/MSCHAPv2" (DEF CON 20, 2012) — DES reduction / chapcrack.
- NIST SP 800-153 — Guidelines for Securing WLANs: https://csrc.nist.gov/pubs/sp/800/153/final

## Related Skills

- detecting-rogue-access-points-and-evil-twins — detecting the evil twin used to host rogue RADIUS.
- attacking-wpa3-sae-with-dragonblood — WPA3-Personal / EAP-pwd Dragonblood counterpart.
- performing-sdr-signal-analysis-with-gnuradio — RF-layer capture and survey context.
