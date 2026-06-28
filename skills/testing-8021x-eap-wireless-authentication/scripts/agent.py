#!/usr/bin/env python3
# For authorized enterprise Wi-Fi assessment of networks, users, and devices you
# own or are permitted in writing to test. A rogue RADIUS server captures the
# domain credentials of everyone who connects; capture only what scope permits
# and store harvested material as you would the production secrets it represents.
"""802.1X / EAP credential-theft analysis helper.

Two modes:
  analyze          - Parse a hostapd-wpe-style credential log, classify the EAP
                     method weakness (PEAP/TTLS-MSCHAPv2, GTC, PAP, EAP-TLS),
                     estimate crackability, and emit hashcat-ready guidance.
  audit-supplicant - Check a wpa_supplicant client profile for RADIUS
                     server-certificate validation / EAP-TLS enforcement.

hostapd-wpe log lines of interest look like:
  username:    bob
  challenge:   1122334455667788
  response:    aabbcc...   (24 bytes)
  jtr NETNTLM: bob:$NETNTLM$1122334455667788$aabbcc...
"""
import argparse
import re
import sys

WEAK_INNER = {
    "MSCHAPV2": ("HIGH", "NT hash is DES-reducible; dictionary-crackable (hashcat -m 5500)"),
    "MSCHAP": ("HIGH", "MSCHAPv1 weaker still; crackable"),
    "GTC": ("CRITICAL", "GTC sends the password in cleartext inside the tunnel"),
    "PAP": ("CRITICAL", "EAP-TTLS-PAP sends the password in cleartext inside the tunnel"),
}
STRONG = {"TLS": ("LOW", "EAP-TLS uses mutual certificates; no crackable password")}


def parse_log(path):
    """Return list of captured-credential dicts."""
    creds = []
    cur = {}
    method = "PEAP-MSCHAPV2"
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            low = line.lower()
            m = re.search(r"(peap|ttls|eap-tls|gtc|pap|mschapv2|mschap)", low)
            if "eap" in low and m:
                method = m.group(1).upper()
            if low.startswith("username"):
                if cur.get("username"):
                    creds.append(cur)
                    cur = {}
                cur["username"] = line.split(":", 1)[1].strip()
                cur["method"] = method
            elif low.startswith("challenge"):
                cur["challenge"] = line.split(":", 1)[1].strip()
            elif low.startswith("response"):
                cur["response"] = line.split(":", 1)[1].strip()
            elif "netntlm" in low and "$" in line:
                cur["netntlm"] = line.split(":", 1)[-1].strip()
    if cur.get("username"):
        creds.append(cur)
    return creds


def classify(method):
    m = method.upper()
    for key, (sev, note) in WEAK_INNER.items():
        if key in m:
            return sev, note
    for key, (sev, note) in STRONG.items():
        if key in m and "TLS" in m:
            return sev, note
    return "UNKNOWN", "EAP method not recognised; enumerate inner method"


def cmd_analyze(args):
    creds = parse_log(args.log)
    if not creds:
        print("[!] no captured credentials parsed from", args.log, file=sys.stderr)
        return 1
    print(f"[+] {len(creds)} captured EAP credential(s)\n")
    results = []
    for c in creds:
        sev, note = classify(c.get("method", ""))
        crackable = sev in ("HIGH", "CRITICAL")
        print(f"[{'!!' if crackable else 'ok'}] user={c.get('username','?'):<16} "
              f"method={c.get('method','?'):<16} risk={sev}")
        print(f"      - {note}")
        if c.get("response") and c.get("challenge"):
            print(f"      - hashcat: hashcat -m 5500 "
                  f"'{c['username']}::::{c['response']}:{c['challenge']}' wordlist.txt")
        elif c.get("netntlm"):
            print(f"      - crack:   hashcat -m 5500 '{c['netntlm']}' wordlist.txt")
        results.append({**c, "risk": sev, "note": note, "crackable": crackable})
    if args.json:
        import json
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        print(f"\n[+] findings written to {args.json}")
    return 0


def cmd_audit_supplicant(args):
    cfg = {}
    try:
        with open(args.conf, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        print(f"[!] cannot read {args.conf}: {exc}", file=sys.stderr)
        return 1
    for m in re.finditer(r'(\w+)\s*=\s*"?([^"\n]+)"?', text):
        cfg[m.group(1).lower()] = m.group(2).strip()

    issues = []
    eap = cfg.get("eap", "").upper()
    if "TLS" not in eap:
        if not cfg.get("ca_cert"):
            issues.append("No ca_cert: supplicant will NOT validate the RADIUS server cert")
        if not cfg.get("domain_suffix_match") and not cfg.get("subject_match"):
            issues.append("No domain_suffix_match/subject_match: server name not pinned")
        issues.append(f"Using {eap or 'password-based EAP'} (MSCHAPv2 crackable); prefer EAP-TLS")
    else:
        if not (cfg.get("client_cert") and cfg.get("private_key")):
            issues.append("EAP-TLS without client_cert/private_key")
    print(f"[+] audited {args.conf}  (eap={eap or '?'})")
    if not issues:
        print("[ok] supplicant enforces server-cert validation / EAP-TLS.")
        return 0
    print(f"[!] {len(issues)} hardening gap(s):")
    for i in issues:
        print(f"     - {i}")
    return 0


def main():
    p = argparse.ArgumentParser(description="802.1X/EAP credential-theft analysis helper")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="classify captured EAP credentials")
    a.add_argument("--log", required=True, help="hostapd-wpe credential log")
    a.add_argument("--json", help="write findings JSON")
    a.set_defaults(func=cmd_analyze)

    s = sub.add_parser("audit-supplicant", help="audit a wpa_supplicant profile")
    s.add_argument("--conf", required=True, help="wpa_supplicant.conf path")
    s.set_defaults(func=cmd_audit_supplicant)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
