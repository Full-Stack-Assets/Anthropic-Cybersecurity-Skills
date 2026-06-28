# WPA3-SAE / Dragonblood — Tool & Command Reference

## Core CLI Tools

| Tool | Key flags | Purpose |
|------|-----------|---------|
| `airmon-ng` | `start <iface>`, `check kill` | Enable monitor mode; kill interfering processes |
| `airodump-ng` | `-c <chan>`, `--bssid`, `-w <prefix>` | Capture beacons/handshakes on a target channel |
| `hostapd` | config file: `wpa_key_mgmt=SAE`, `ieee80211w`, `sae_pwe` | Stand up rogue WPA2 AP or hardened WPA3 AP |
| `wpa_supplicant` | `-c <conf>`, `key_mgmt=SAE`, `ieee80211w=2` | Drive a test client through SAE |
| `hcxdumptool` | `-i <iface>`, `-o <pcapng>`, `--enable_status=1` | Capture SAE / WPA2 / PMKID material |
| `hcxpcapngtool` | `-o <hc22000>` | Convert capture to hashcat `-m 22000` format |
| `tshark` | `-Y <filter>`, `-T fields -e <field>` | Dissect RSN IE, AKM, PMF bits, SAE frames |
| `hashcat` | `-m 22000 <hash> <wordlist>` | Offline crack of downgraded WPA2 handshake |

## Dragonblood Tooling

| Tool | Flags | Purpose |
|------|-------|---------|
| `dragonslayer` | `-i <iface>` | EAP-pwd / downgrade proof-of-concept |
| `dragondrain` | `-i <iface>`, `-d <bssid>`, `-r <rate>`, `-p <mode>` | SAE commit flood (DoS) |
| `dragontime` | `-i <iface>`, `-a <bssid>`, `-g <group>` | Timing side-channel measurement against a group |
| `dragonforce.py` | `--measurements <csv>`, `--wordlist <file>` | Password partitioning / dictionary from leaks |

## Key hostapd Hardening Parameters

| Parameter | Value | Effect |
|-----------|-------|--------|
| `wpa_key_mgmt` | `SAE` | WPA3-Personal only (no `WPA-PSK` transition) |
| `ieee80211w` | `2` | PMF **required** (1 = capable, 0 = off) |
| `sae_pwe` | `1` | Hash-to-Element only (2 = both, 0 = legacy H&P) |
| `sae_require_mfp` | `1` | Reject SAE associations without PMF |
| `sae_groups` | `19 20 21` | Restrict to strong EC groups; avoid weak MODP |

## tshark Fields / Detection Signals

| Field | Meaning |
|-------|---------|
| `wlan.rsn.akms.type` | AKM selector (2=PSK, 8=SAE, 9=SAE-FT) |
| `wlan.rsn.capabilities.mfpr` | MFP Required bit (1 = PMF required) |
| `wlan.rsn.capabilities.mfpc` | MFP Capable bit |
| `wlan.fixed.auth.alg==3` | SAE authentication algorithm |
| `wlan.fixed.status_code==126` | H2E negotiation in SAE exchange |
| `wlan.fixed.finite_cyclic_group` | Negotiated SAE group (watch for downgrade to weak group) |

## Companion Script (`scripts/agent.py`)

| Subcommand | Args | Purpose |
|------------|------|---------|
| `analyze` | `--scan <cap/csv>`, `--json <out>` | Parse a tshark-exported AP/SAE summary and flag transition-mode / missing-PMF / legacy-PWE weaknesses |
| `audit-conf` | `--conf <hostapd.conf>` | Score a hostapd config for WPA3 hardening (PMF, sae_pwe, transition) |

## External References

- Dragonblood: https://wpa3.mathyvanhoef.com/
- hostapd config reference: https://w1.fi/cgit/hostap/tree/hostapd/hostapd.conf
- hcxtools: https://github.com/ZerBea/hcxtools
- hashcat WPA modes: https://hashcat.net/wiki/doku.php?id=example_hashes
