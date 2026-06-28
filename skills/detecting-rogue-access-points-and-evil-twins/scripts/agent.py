#!/usr/bin/env python3
# For authorized wireless monitoring of networks and physical areas you own or
# are permitted to assess. Capture only the metadata you need, follow wiretap
# and privacy law, and detect-and-report rogue APs rather than attacking them.
"""Rogue-AP / evil-twin detector.

Two modes:
  detect - Parse an airodump-ng CSV (the AP section) and compare every observed
           AP against a trusted-AP allowlist CSV. Flags evil twins (known SSID,
           unknown BSSID), rogue BSSIDs, off-channel known BSSIDs, encryption
           downgrades, and signal anomalies. Pure stdlib.
  karma  - Given (BSSID, SSID) pairs (e.g. from tshark), flag any BSSID
           broadcasting an abnormal number of distinct SSIDs (Karma / MANA).

airodump-ng CSV format has two sections separated by a blank line; the first
section lists APs with a header row beginning with "BSSID".
Allowlist CSV header: bssid,ssid,channel,encryption
"""
import argparse
import collections
import csv
import json
import sys


def load_allowlist(path):
    by_bssid = {}
    by_ssid = collections.defaultdict(set)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            bssid = (row.get("bssid") or "").strip().upper()
            ssid = (row.get("ssid") or "").strip()
            if not bssid:
                continue
            entry = {
                "ssid": ssid,
                "channel": (row.get("channel") or "").strip(),
                "encryption": (row.get("encryption") or "").strip().upper(),
            }
            by_bssid[bssid] = entry
            if ssid:
                by_ssid[ssid].add(bssid)
    return by_bssid, by_ssid


def parse_airodump_csv(path):
    """Return list of observed APs from the AP section of an airodump CSV."""
    aps = []
    header = None
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        reader = csv.reader(fh)
        for cols in reader:
            if not cols or not any(c.strip() for c in cols):
                # blank line — end of AP section (clients follow)
                if header is not None:
                    break
                continue
            first = cols[0].strip()
            if first == "BSSID":
                header = [c.strip() for c in cols]
                continue
            if header is None:
                continue
            row = dict(zip(header, [c.strip() for c in cols]))
            bssid = row.get("BSSID", "").upper()
            if not bssid:
                continue
            aps.append({
                "bssid": bssid,
                "channel": row.get("channel", row.get("CH", "")).strip(),
                "encryption": (row.get("Privacy", "") + " " +
                               row.get("Authentication", "")).strip().upper(),
                "power": row.get("Power", "").strip(),
                "ssid": row.get("ESSID", "").strip(),
            })
    return aps


def assess(aps, by_bssid, by_ssid):
    findings = []
    for ap in aps:
        issues = []
        bssid, ssid = ap["bssid"], ap["ssid"]
        known_bssid = bssid in by_bssid
        # evil twin: SSID is one we own, but this BSSID is not authorized for it
        if ssid and ssid in by_ssid and bssid not in by_ssid[ssid]:
            issues.append(f"EVIL_TWIN (SSID '{ssid}' from unauthorized BSSID)")
        # rogue BSSID broadcasting a known SSID? handled above; otherwise:
        if not known_bssid and ssid and ssid not in by_ssid:
            issues.append("UNKNOWN_AP (BSSID and SSID not in allowlist)")
        if known_bssid:
            exp = by_bssid[bssid]
            if exp["channel"] and ap["channel"] and exp["channel"] != ap["channel"]:
                issues.append(f"OFF_CHANNEL (expected {exp['channel']}, saw {ap['channel']})")
            if exp["encryption"] and _enc_weaker(ap["encryption"], exp["encryption"]):
                issues.append(f"ENC_DOWNGRADE (expected {exp['encryption']}, saw {ap['encryption']})")
            if exp["ssid"] and ssid and exp["ssid"] != ssid:
                issues.append(f"SSID_MISMATCH (BSSID expected '{exp['ssid']}', saw '{ssid}')")
        sev = "HIGH" if any(i.startswith("EVIL_TWIN") for i in issues) else \
              "MEDIUM" if issues else "OK"
        findings.append({
            "bssid": bssid, "ssid": ssid, "channel": ap["channel"],
            "encryption": ap["encryption"], "power": ap["power"],
            "severity": sev, "issues": issues,
        })
    return findings


def _enc_weaker(observed, expected):
    rank = {"OPN": 0, "OPEN": 0, "WEP": 1, "WPA": 2, "WPA2": 3, "WPA3": 4}
    def score(s):
        best = 0
        for tok, v in rank.items():
            if tok in s:
                best = max(best, v)
        return best
    return score(observed) < score(expected)


def cmd_detect(args):
    by_bssid, by_ssid = load_allowlist(args.allowlist)
    aps = parse_airodump_csv(args.capture)
    if not aps:
        print("[!] no APs parsed from", args.capture, file=sys.stderr)
        return 1
    findings = assess(aps, by_bssid, by_ssid)
    flagged = [f for f in findings if f["issues"]]
    order = {"HIGH": 0, "MEDIUM": 1, "OK": 2}
    findings.sort(key=lambda f: order[f["severity"]])

    if args.json == "-":
        for f in findings:
            if f["issues"]:
                print(json.dumps(f))
    else:
        print(f"[+] {len(aps)} AP(s) observed; {len(flagged)} flagged\n")
        for f in findings:
            mark = "[!!]" if f["severity"] == "HIGH" else "[! ]" if f["issues"] else "[ok]"
            print(f"{mark} {f['ssid'] or '<hidden>':<22} {f['bssid']:<18} "
                  f"ch={f['channel'] or '-':<4} {f['severity']}")
            for i in f["issues"]:
                print(f"       - {i}")
        if args.json:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(findings, fh, indent=2)
            print(f"\n[+] findings written to {args.json}")
    return 0


def cmd_karma(args):
    pairs = collections.defaultdict(set)
    with open(args.pairs, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) >= 2:
                bssid = parts[0].strip().upper()
                ssid = " ".join(parts[1:]).strip()
                if ssid:
                    pairs[bssid].add(ssid)
    print(f"[+] {len(pairs)} transmitter(s) analysed (Karma threshold {args.max_ssids})\n")
    flagged = 0
    for bssid, ssids in sorted(pairs.items(), key=lambda kv: -len(kv[1])):
        if len(ssids) > args.max_ssids:
            flagged += 1
            print(f"[!!] {bssid} broadcasts {len(ssids)} distinct SSIDs (Karma/MANA suspect)")
            for s in list(ssids)[:10]:
                print(f"       - {s}")
    if not flagged:
        print("[ok] no Karma-style mass impersonation detected")
    return 0


def main():
    p = argparse.ArgumentParser(description="Rogue-AP / evil-twin detector")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("detect", help="score airodump CSV against an allowlist")
    d.add_argument("--capture", required=True, help="airodump-ng CSV export")
    d.add_argument("--allowlist", required=True, help="trusted-AP allowlist CSV")
    d.add_argument("--json", help="write findings JSON ('-' for JSON lines to stdout)")
    d.set_defaults(func=cmd_detect)

    k = sub.add_parser("karma", help="flag Karma/MANA SSID fan-out")
    k.add_argument("--pairs", required=True, help="file of 'BSSID SSID' lines")
    k.add_argument("--max-ssids", type=int, default=5)
    k.set_defaults(func=cmd_karma)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
