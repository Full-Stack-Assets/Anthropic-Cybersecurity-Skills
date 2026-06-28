#!/usr/bin/env python3
# For authorized WPA3 assessment of access points and clients you own or are
# permitted in writing to test. Forcing downgrades, partitioning passphrases,
# or flooding SAE state machines on networks you do not control may violate
# computer-misuse, wiretap, and telecommunications law.
"""WPA3-SAE / Dragonblood posture helper.

Two modes:
  analyze    - Parse a tshark-exported AP/SAE summary (CSV-ish, one row per
               beacon/auth observation) and flag WPA3 transition-mode,
               missing-PMF, weak-group, and legacy-PWE (hunting-and-pecking)
               weaknesses. Pure stdlib.
  audit-conf - Score a hostapd.conf for WPA3 hardening (PMF required,
               Hash-to-Element, no PSK transition).

Expected analyze input (whitespace- or comma-separated, header optional):
  ssid  bssid  akm  mfpr  mfpc  sae_status  group
where:
  akm        = comma-list of RSN AKM selectors (e.g. "8,2" => SAE+PSK)
  mfpr/mfpc  = 1/0  (MFP required / capable)
  sae_status = SAE status_code seen (126 => Hash-to-Element)
  group      = negotiated finite cyclic group (19/20/21 strong EC; 1/2/5/22 weak)
"""
import argparse
import csv
import json
import re
import sys

AKM_NAMES = {"2": "PSK", "8": "SAE", "9": "SAE-FT", "1": "802.1X", "5": "802.1X-SHA256"}
STRONG_GROUPS = {"19", "20", "21"}      # NIST P-256/384/521 elliptic curves
WEAK_GROUPS = {"1", "2", "5", "22", "23", "24"}  # legacy MODP / small groups


_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$")


def _split_row(line):
    """Split a summary row into fields.

    The AKM field may itself contain commas (e.g. "8,2"), so a naive
    comma-split would misalign whitespace-separated rows. Prefer whitespace
    splitting when it yields a BSSID in field 2; otherwise treat the row as
    CSV (and re-join any AKM sub-list later).
    """
    ws = line.split()
    if len(ws) >= 2 and _MAC_RE.match(ws[1]):
        return [c.strip() for c in ws]
    return [c.strip() for c in next(csv.reader([line]))]


def parse_summary(path):
    rows = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            cols = _split_row(line)
            # skip a header row if present
            if cols and cols[0].lower() in ("ssid", "essid"):
                continue
            if len(cols) < 3:
                continue
            row = {
                "ssid": cols[0],
                "bssid": cols[1],
                "akm": [a for a in cols[2].replace(";", ",").split(",") if a],
                "mfpr": cols[3] if len(cols) > 3 else "",
                "mfpc": cols[4] if len(cols) > 4 else "",
                "sae_status": cols[5] if len(cols) > 5 else "",
                "group": cols[6] if len(cols) > 6 else "",
            }
            rows.append(row)
    return rows


def assess(rows):
    findings = []
    for r in rows:
        issues = []
        akm = set(r["akm"])
        has_sae = "8" in akm or "9" in akm
        has_psk = "2" in akm
        # transition mode: SAE and PSK advertised together
        if has_sae and has_psk:
            issues.append("TRANSITION_MODE (SAE+PSK => downgrade-to-WPA2 risk)")
        # PMF
        if has_sae and r["mfpr"] not in ("1", "true", "True"):
            issues.append("PMF_NOT_REQUIRED (set ieee80211w=2)")
        # PWE / Hash-to-Element
        if has_sae and r["sae_status"] and r["sae_status"] != "126":
            issues.append("LEGACY_PWE (no H2E status 126 => side-channel risk)")
        # weak negotiated group
        if r["group"] and r["group"] in WEAK_GROUPS:
            issues.append(f"WEAK_GROUP ({r['group']} => group-downgrade/timing risk)")
        severity = "HIGH" if any("TRANSITION" in i or "LEGACY" in i for i in issues) \
            else "MEDIUM" if issues else "OK"
        findings.append({
            "ssid": r["ssid"],
            "bssid": r["bssid"],
            "akm": [AKM_NAMES.get(a, a) for a in r["akm"]],
            "severity": severity,
            "issues": issues,
        })
    return findings


def cmd_analyze(args):
    rows = parse_summary(args.scan)
    if not rows:
        print("[!] no usable rows parsed from", args.scan, file=sys.stderr)
        return 1
    findings = assess(rows)
    flagged = [f for f in findings if f["issues"]]
    print(f"[+] analysed {len(rows)} AP observation(s); {len(flagged)} with weaknesses\n")
    for f in sorted(findings, key=lambda x: x["severity"] != "HIGH"):
        mark = "[!!]" if f["severity"] == "HIGH" else "[! ]" if f["issues"] else "[ok]"
        print(f"{mark} {f['ssid']:<20} {f['bssid']:<18} {'/'.join(f['akm']) or '-':<10} {f['severity']}")
        for i in f["issues"]:
            print(f"       - {i}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2)
        print(f"\n[+] findings written to {args.json}")
    return 0


def cmd_audit_conf(args):
    cfg = {}
    try:
        with open(args.conf, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    cfg[k.strip()] = v.strip()
    except OSError as exc:
        print(f"[!] cannot read {args.conf}: {exc}", file=sys.stderr)
        return 1

    issues = []
    akm = cfg.get("wpa_key_mgmt", "")
    if "WPA-PSK" in akm and "SAE" in akm:
        issues.append("Transition mode: both SAE and WPA-PSK enabled (drop WPA-PSK)")
    if "SAE" not in akm:
        issues.append("SAE not enabled in wpa_key_mgmt (not WPA3-Personal)")
    if cfg.get("ieee80211w") != "2":
        issues.append("PMF not required: set ieee80211w=2")
    if cfg.get("sae_pwe") not in ("1",):
        issues.append("Hash-to-Element not enforced: set sae_pwe=1 (H2E only)")
    if cfg.get("sae_require_mfp") != "1":
        issues.append("sae_require_mfp not set to 1")

    print(f"[+] audited {args.conf}")
    if not issues:
        print("[ok] config is hardened (WPA3-only, PMF required, H2E).")
        return 0
    print(f"[!] {len(issues)} hardening gap(s):")
    for i in issues:
        print(f"     - {i}")
    return 0


def main():
    p = argparse.ArgumentParser(description="WPA3-SAE / Dragonblood posture helper")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="flag WPA3 weaknesses in a scan summary")
    a.add_argument("--scan", required=True, help="tshark-exported AP/SAE summary")
    a.add_argument("--json", help="write findings JSON")
    a.set_defaults(func=cmd_analyze)

    c = sub.add_parser("audit-conf", help="score a hostapd.conf for WPA3 hardening")
    c.add_argument("--conf", required=True, help="path to hostapd.conf")
    c.set_defaults(func=cmd_audit_conf)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
