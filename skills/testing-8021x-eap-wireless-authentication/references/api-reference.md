# 802.1X/EAP Testing — Tool & Command Reference

## Core CLI Tools

| Tool | Key flags | Purpose |
|------|-----------|---------|
| `hostapd-wpe` | config file: `eap_server=1`, `eap_user_file`, `server_cert` | Rogue AP + rogue RADIUS capturing inner MSCHAPv2 |
| `eaphammer` | `--cert-wizard`, `-i`, `--essid`, `--auth wpa-eap`, `--creds` | Automated evil-twin + credential capture chain |
| `asleap` | `-C <challenge>`, `-R <response>`, `-W <wordlist>` | Crack MSCHAPv2 challenge/response |
| `hashcat` | `-m 5500 <hash> <wordlist>` | Crack NetNTLMv1 / MSCHAPv2 |
| `chapcrack` | `parse`, `crack` | Reduce MSCHAPv2 to a single DES key |
| `airodump-ng` | `-c <chan>`, `--bssid`, `-w <prefix>` | Capture EAP negotiation frames |
| `tshark` | `-Y eap`, `-T fields -e eap.type` | Inspect EAP method negotiation |

## EAP Type Codes (eap.type)

| Code | Method |
|------|--------|
| 1 | Identity |
| 4 | MD5-Challenge |
| 13 | EAP-TLS |
| 21 | EAP-TTLS |
| 25 | PEAP |
| 26 | MSCHAPv2 (often inner) |
| 6 / 31 | GTC (cleartext inner) |
| 43 | EAP-FAST |

## hostapd-wpe Key Config

| Parameter | Purpose |
|-----------|---------|
| `wpa_key_mgmt=WPA-EAP` | Enterprise (802.1X) AKM |
| `ieee8021x=1` | Enable 802.1X authenticator |
| `eap_server=1` | Act as the (rogue) RADIUS/EAP server |
| `eap_user_file` | EAP user/method policy (controls offered methods) |
| `server_cert` / `private_key` / `ca_cert` | TLS identity presented to supplicants |

## Hardened Supplicant Settings (wpa_supplicant)

| Parameter | Hardened value | Effect |
|-----------|----------------|--------|
| `ca_cert` | path to pinned private CA | Validate RADIUS server cert chain |
| `domain_suffix_match` | `radius.corp.example.com` | Pin expected server name |
| `eap` | `TLS` (preferred) | Mutual cert auth, no crackable password |
| `client_cert` / `private_key` | client cert/key | EAP-TLS identity |
| `phase2` | `auth=MSCHAPV2` | If staying on PEAP, lock the inner method |

## Companion Script (`scripts/agent.py`)

| Subcommand | Args | Purpose |
|------------|------|---------|
| `analyze` | `--log <hostapd-wpe.log>`, `--json <out>` | Parse captured EAP creds; classify method weakness + crackability |
| `audit-supplicant` | `--conf <wpa_supplicant.conf>` | Check ca_cert / domain_suffix_match / EAP-TLS enforcement |

## hashcat -m 5500 Hash Format

```
username::::<24-byte-response-hex>:<8-byte-challenge-hex>
```

## External References

- hostapd-wpe: https://github.com/aircrack-ng/hostapd-wpe
- eaphammer wiki: https://github.com/s0lst1c3/eaphammer/wiki
- hashcat example hashes (mode 5500): https://hashcat.net/wiki/doku.php?id=example_hashes
- RFC 5216 (EAP-TLS): https://www.rfc-editor.org/rfc/rfc5216
