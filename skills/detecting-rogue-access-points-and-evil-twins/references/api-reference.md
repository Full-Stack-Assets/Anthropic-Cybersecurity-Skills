# Rogue AP / Evil-Twin Detection — Tool & Command Reference

## Core CLI Tools

| Tool | Key flags | Purpose |
|------|-----------|---------|
| `airmon-ng` | `start <iface>` | Enable monitor mode |
| `airodump-ng` | `--band abg`, `-w <prefix>`, `--output-format csv,pcap`, `-d <bssid>` | Capture beacons/probes; CSV export; lock onto a suspect |
| `kismet` | `-c <iface>` | Continuous channel-hopping capture, web UI, structured logs |
| `kismetdb_dump_devices` | `--in <.kismet>`, `--out <json>` | Export detected devices/SSIDs from a Kismet log |
| `tshark` | `-Y <filter>`, `-T fields -e <field>` | Extract (BSSID, SSID, channel) from captures |
| `iw` | `dev <iface> scan` | Quick managed-mode scan of nearby APs |
| `logger` | `-t <tag>` | Ship JSON findings to syslog/SIEM |

## airodump-ng CSV Columns (allowlist mapping)

| CSV column | Meaning |
|------------|---------|
| BSSID | AP MAC address |
| channel | Operating channel |
| Privacy / Cipher / Authentication | Encryption suite (compare to baseline) |
| Power | RSSI (signal anomaly detection) |
| ESSID | Network name (SSID) |

## tshark Fields / Detection Signals

| Field | Meaning |
|-------|---------|
| `wlan.fc.type_subtype==0x08` | Beacon frame |
| `wlan.fc.type_subtype==0x05` | Probe response |
| `wlan.fc.type_subtype==0x04` | Probe request (Karma target SSIDs) |
| `wlan.sa` | Transmitter (BSSID) |
| `wlan.ssid` | Advertised SSID |
| `wlan.ds.current_channel` | Current channel from DS parameter set |
| `radiotap.dbm_antsignal` | RSSI for signal-anomaly/triangulation |

## Companion Script (`scripts/agent.py`)

| Subcommand | Args | Purpose |
|------------|------|---------|
| `detect` | `--capture <airodump.csv>`, `--allowlist <csv>`, `--json <out\|->` | Score capture vs. allowlist; flag evil-twin / rogue / off-channel / downgrade |
| `karma` | `--pairs <file>`, `--max-ssids <n>` | Flag BSSIDs broadcasting an abnormal number of distinct SSIDs |

## Allowlist CSV Schema

| Column | Example | Notes |
|--------|---------|-------|
| bssid | AA:BB:CC:11:22:33 | Authorized AP MAC |
| ssid | CorpWiFi | Expected network name |
| channel | 36 | Expected operating channel |
| encryption | WPA3 | Baseline cipher/auth suite |

## External References

- Kismet docs: https://www.kismetwireless.net/docs/
- airodump-ng manual: https://www.aircrack-ng.org/doku.php?id=airodump-ng
- NIST SP 800-153: https://csrc.nist.gov/pubs/sp/800/153/final
