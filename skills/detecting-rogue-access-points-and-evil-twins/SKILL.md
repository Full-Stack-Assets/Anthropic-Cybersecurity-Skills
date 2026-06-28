---
name: detecting-rogue-access-points-and-evil-twins
description: Detect rogue access points and evil-twin or Karma attacks by monitoring BSSID, SSID, channel, and beacon anomalies against a trusted-AP allowlist, building a lightweight wireless intrusion detection capability from airodump-ng and Kismet captures and alerting on impersonation and signal anomalies.
domain: cybersecurity
subdomain: wireless-security
tags:
- wireless-security
- rogue-ap
- evil-twin
- karma-attack
- wids
- beacon-analysis
- kismet
- bssid-allowlist
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.AE-02
- ID.AM-03
- PR.AA-03
mitre_attack:
- T1557
- T1040
- T1200
- T1071
---
# Detecting Rogue Access Points and Evil Twins

> **Authorized Use Only:** Wireless monitoring captures frames from every device in radio range, including neighbors and bystanders. Run these techniques only on networks and in physical areas you own or are authorized to assess, retain only the metadata you need (BSSID/SSID/channel, not payloads), and follow your jurisdiction's wiretap and privacy law. Deauthenticating or interfering with a suspected rogue AP may itself be unlawful — detect and report, do not attack.

## Overview

A **rogue access point** is any AP attached to (or impersonating) your network without authorization. The most dangerous variant is the **evil twin**: an attacker stands up an AP that copies a legitimate network's SSID (and often its BSSID and channel), lures clients to associate, and then sits between them and the internet. This is textbook **Adversary-in-the-Middle (T1557)**, enabling **Network Sniffing (T1040)** of any cleartext traffic and credential capture via captive portals. A related class is the **Karma / MANA** attack, in which the rogue AP answers every directed probe request a client broadcasts ("is *HomeWiFi* here? is *Airport_Free* here?") and impersonates whichever network the device is willing to auto-join, abusing **Application Layer Protocol (T1071)** captive portals to harvest data. A physical rogue AP plugged into a wall jack is **Hardware Additions (T1200)**.

Because an evil twin deliberately mimics legitimate identifiers, single-attribute matching (SSID alone, or BSSID alone) is insufficient. Effective detection correlates a **tuple of observable beacon attributes** — SSID, BSSID, channel, RSN/encryption suite, supported rates, beacon interval, and tagged-parameter fingerprint — against a curated **trusted-AP allowlist**, and then flags anomalies: a known SSID broadcasting from an unknown BSSID, a known BSSID appearing on an unexpected channel, two BSSIDs claiming the same SSID with wildly different signal strength, a sudden flood of new SSIDs (Karma), or a beacon whose security suite is weaker than the corporate baseline. This is the core logic of a **Wireless Intrusion Detection System (WIDS)**.

This skill builds that detection capability from open tools: continuous monitor-mode capture with **Kismet** or **airodump-ng**, an explicit allowlist of authorized BSSIDs/SSIDs/channels, and an anomaly-scoring engine that turns capture exports into prioritized rogue/evil-twin candidates. The emphasis is defensive — establishing a baseline, detecting deviations, alerting, and feeding a response playbook — aligned with NIST CSF Detect functions DE.CM-01 (network monitoring) and DE.AE-02 (analyzing detected events).

## When to Use

- When you operate corporate, campus, retail, or guest Wi-Fi and need ongoing rogue-AP and evil-twin detection.
- When building or tuning a WIDS/WIPS sensor deployment and need a vendor-neutral detection baseline.
- When investigating reports of clients connecting to a spoofed network or seeing duplicate SSIDs.
- When performing a periodic wireless site survey to inventory authorized vs. unauthorized APs.
- When hunting for Karma/MANA-style mass-impersonation activity at a venue or event.
- When validating that a captured environment matches a known-good trusted-AP allowlist after a move/change.

## Prerequisites

- Linux host with a Wi-Fi adapter supporting **monitor mode** — e.g. Alfa AWUS036ACM (mt7612u), AWUS036NHA (ath9k_htc), or a Panda PAU09. GPS dongle optional for war-walking.
- Capture and analysis tooling:
  ```bash
  sudo apt update
  sudo apt install -y kismet aircrack-ng tshark iw gpsd python3-pip
  # Kismet provides continuous, channel-hopping capture with a web UI + CSV/JSON export
  ```
- A maintained **trusted-AP allowlist** (CSV): authorized BSSID, SSID, channel, and expected encryption for every sanctioned AP.
- Authorization to monitor the radio environment at the site, and a documented data-handling policy.

## Objectives

- Continuously capture beacons/probes across all channels in monitor mode.
- Maintain a trusted-AP allowlist of authorized BSSID/SSID/channel/encryption.
- Detect evil twins: a known SSID broadcasting from an un-allowlisted BSSID.
- Detect rogue/anomalous APs: unexpected channel, weakened encryption, signal anomalies, or Karma SSID floods.
- Score and prioritize candidates and route alerts into a SIEM/response workflow.
- Validate the detector against a controlled lab evil-twin so true/false positives are understood.

## MITRE ATT&CK Mapping

| ID | Name | Tactic | Where it shows up |
|----|------|--------|-------------------|
| T1557 | Adversary-in-the-Middle | Credential Access / Collection | Evil twin positions itself between client and the real network |
| T1040 | Network Sniffing | Discovery / Credential Access | Rogue AP captures cleartext client traffic once associated |
| T1200 | Hardware Additions | Initial Access | Physical rogue AP plugged into an internal wall jack/switch |
| T1071 | Application Layer Protocol | Command and Control / Collection | Karma captive portal / HTTP(S) data harvesting on the rogue AP |

## Workflow

### 1. Build the trusted-AP allowlist (the baseline)
Detection is anomaly-based, so first capture a clean inventory of every authorized AP and freeze it as the allowlist. Each row is the BSSID, the SSID it should broadcast, its expected channel, and the corporate encryption baseline.

```bash
# Quick baseline scan to seed the allowlist, then hand-verify each entry
sudo airmon-ng start wlan0
sudo airodump-ng -w baseline --output-format csv wlan0mon
# Produce a reviewed allowlist (BSSID,SSID,channel,enc)
cat > trusted-aps.csv <<'EOF'
bssid,ssid,channel,encryption
AA:BB:CC:11:22:33,CorpWiFi,36,WPA3
AA:BB:CC:11:22:34,CorpWiFi,149,WPA3
AA:BB:CC:44:55:66,CorpGuest,6,WPA2
EOF
```

### 2. Run continuous monitor-mode capture
Use Kismet for long-running, channel-hopping detection with structured export; airodump-ng works for shorter spot checks. Both produce CSV/JSON the detector consumes.

```bash
# Kismet: hops channels, logs to ~/.kismet, exposes a web UI on :2501
sudo kismet -c wlan0mon
# Or a time-boxed airodump capture exporting CSV
sudo airodump-ng --band abg -w survey --output-format csv,pcap wlan0mon
# Export Kismet detected devices/SSIDs to CSV for offline scoring:
kismetdb_dump_devices --in ~/.kismet/*.kismet --out devices.json
```

### 3. Score captures against the allowlist
Feed the airodump CSV (or Kismet export) plus the allowlist into the detector. It flags evil-twin candidates (known SSID, unknown BSSID), off-channel known BSSIDs, weakened encryption, and signal anomalies.

```bash
python3 scripts/agent.py detect \
  --capture survey-01.csv \
  --allowlist trusted-aps.csv \
  --json rogue-findings.json
# Output ranks candidates: EVIL_TWIN > ROGUE_BSSID > OFF_CHANNEL > ENC_DOWNGRADE
```

### 4. Detect Karma / MANA mass-impersonation
Karma APs answer many distinct probe-request SSIDs from a single BSSID, producing an abnormal SSID-per-BSSID fan-out. Extract probe/beacon SSIDs grouped by transmitter and flag any BSSID broadcasting an implausible number of distinct SSIDs.

```bash
# Pull (BSSID, SSID) pairs from beacons + probe responses
tshark -r survey-01.pcap \
  -Y "wlan.fc.type_subtype==0x08 || wlan.fc.type_subtype==0x05" \
  -T fields -e wlan.sa -e wlan.ssid | sort -u > bssid_ssid_pairs.txt
python3 scripts/agent.py karma --pairs bssid_ssid_pairs.txt --max-ssids 5
```

### 5. Triangulate and confirm physically
A high-scoring candidate needs physical confirmation before action. Use RSSI trends and (with a directional antenna) signal-strength gradients to walk toward the transmitter; a rogue plugged into your switch can also be found by correlating its uplink MAC on managed switch ports.

```bash
# Watch live RSSI for the suspect BSSID to direction-find it
sudo airodump-ng -d DE:AD:BE:EF:00:01 --band abg wlan0mon
# Correlate on the wired side: find the switch port a rogue MAC appears on
#   (run on the managed switch / via SNMP) e.g. 'show mac address-table | include dead.beef'
```

### 6. Alert, document, and respond
Wire detector output into your SIEM (syslog/JSON). On a confirmed rogue: capture evidence, locate and physically remove or disable the device/switch port, notify affected users, and add the legitimate-but-new AP to the allowlist (or escalate the impersonator). Never deauth/jam a suspected rogue.

```bash
# Emit findings as JSON lines to a syslog collector
python3 scripts/agent.py detect --capture survey-01.csv \
  --allowlist trusted-aps.csv --json - | logger -t wids-rogue-ap
```

## Tools and Resources

| Resource | Link |
|----------|------|
| Kismet wireless detector / WIDS | https://www.kismetwireless.net/ |
| Aircrack-ng (airodump-ng) | https://www.aircrack-ng.org/ |
| Wireshark / tshark | https://www.wireshark.org/ |
| MANA / Karma toolkit (sensepost) | https://github.com/sensepost/mana |
| NIST SP 800-153 — Guidelines for Securing WLANs | https://csrc.nist.gov/pubs/sp/800/153/final |
| NIST SP 800-97 — Establishing Robust Security Networks (802.11i) | https://csrc.nist.gov/pubs/sp/800/97/final |

## Rogue / Evil-Twin Detection Signal Reference

| Signal | Benign explanation | Rogue / evil-twin indicator |
|--------|--------------------|-----------------------------|
| Known SSID, unknown BSSID | New authorized AP (update allowlist) | Evil twin impersonating the SSID |
| Known BSSID, unexpected channel | Auto-channel change | BSSID spoofing on a different channel |
| Same SSID, two very different RSSIs | Two legit APs far apart | Nearby evil twin shadowing a distant AP |
| Weaker encryption than baseline | Misconfig | Downgrade lure (open/WPA2 vs corp WPA3) |
| Many distinct SSIDs from one BSSID | — | Karma/MANA mass impersonation |
| Beacon interval / fingerprint mismatch | Firmware variance | Software AP (hostapd) faking hardware AP |

## Validation Criteria

- [ ] Continuous monitor-mode capture running across all bands/channels.
- [ ] Trusted-AP allowlist (BSSID/SSID/channel/encryption) curated and version-controlled.
- [ ] Evil-twin detection (known SSID + unknown BSSID) verified against a lab evil twin.
- [ ] Off-channel, encryption-downgrade, and signal-anomaly detections exercised.
- [ ] Karma/MANA SSID-fan-out detection tested.
- [ ] Findings scored, prioritized, and routed to SIEM/response workflow.
- [ ] Physical confirmation/direction-finding procedure documented (no deauth/jam).
- [ ] False-positive rate measured and allowlist tuned.
