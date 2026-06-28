#!/usr/bin/env python3
# For authorized physical-security assessment of cards, readers, and facilities
# you own or are permitted in writing to test, using badges issued to you for
# the engagement. Cloning another person's badge or entering a controlled area
# without authorization is trespass, fraud, and a computer-misuse offence.
"""RFID/NFC access-control cloneability assessor.

Mode:
  assess - Parse a Proxmark3 / mfoc MIFARE Classic dump and a recovered-keys
           file, identify the chip type (from a JSON dump's SAK if present),
           count how many sectors opened under default/known keys, infer the
           recovery method, and score cloneability. Pure stdlib.

Dump input:
  - Proxmark3 JSON dump (hf-mf-<uid>-dump.json) with a "blocks" map, OR
  - a raw .bin (1K = 1024 bytes, 4K = 4096 bytes).
Keys file (optional): one key per line, optionally "sector:KEY" or
  "FFFFFFFFFFFF" lines; default keys are recognised automatically.
"""
import argparse
import json
import os
import sys

DEFAULT_KEYS = {
    "FFFFFFFFFFFF", "000000000000", "A0A1A2A3A4A5", "D3F7D3F7D3F7",
    "B0B1B2B3B4B5", "4D3A99C351DD", "1A982C7E459A", "AABBCCDDEEFF",
    "714C5C886E97", "587EE5F9350F", "A0478CC39091", "533CB6C723F6",
    "8FD0A4F256E9",
}

SAK_TYPES = {
    0x08: ("MIFARE Classic 1K", 16),
    0x18: ("MIFARE Classic 4K", 40),
    0x09: ("MIFARE Mini", 5),
    0x20: ("MIFARE DESFire / Plus", 0),
    0x00: ("MIFARE Ultralight / NTAG", 0),
}


def load_dump(path):
    info = {"chip": "Unknown", "sectors": 0, "uid": "", "size": 0}
    if path.lower().endswith(".json"):
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        card = data.get("Card", data.get("card", {}))
        sak = card.get("SAK") or card.get("sak")
        info["uid"] = card.get("UID") or card.get("uid", "")
        if isinstance(sak, str):
            try:
                sak = int(sak, 16)
            except ValueError:
                sak = None
        if isinstance(sak, int) and sak in SAK_TYPES:
            info["chip"], info["sectors"] = SAK_TYPES[sak]
        blocks = data.get("blocks", data.get("Blocks", {}))
        info["size"] = len(blocks) * 16 if blocks else 0
        if not info["sectors"] and info["size"]:
            info["sectors"] = 16 if info["size"] <= 1024 else 40
    else:
        size = os.path.getsize(path)
        info["size"] = size
        if size <= 1024:
            info["chip"], info["sectors"] = "MIFARE Classic 1K", 16
        elif size <= 4096:
            info["chip"], info["sectors"] = "MIFARE Classic 4K", 40
    return info


def load_keys(path):
    keys = []
    if not path:
        return keys
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip().upper()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                line = line.split(":", 1)[1].strip()
            keys.append(line)
    return keys


def score(info, keys):
    n_keys = len(keys)
    n_default = sum(1 for k in keys if k in DEFAULT_KEYS)
    chip = info["chip"]
    issues = []
    if chip.startswith("MIFARE Classic"):
        issues.append("CRYPTO1 cipher is broken (48-bit key, weak RNG)")
        if n_default:
            issues.append(f"{n_default} recovered key(s) are factory/default keys")
        method = "default-key" if n_default == n_keys and n_keys else \
                 "nested/darkside/hardnested" if n_keys else "key recovery required"
        if n_default:
            cloneability = "TRIVIAL"
        elif n_keys:
            cloneability = "HIGH"
        else:
            cloneability = "HIGH (CRYPTO1 always recoverable)"
        rec = "Migrate to MIFARE DESFire EV2/EV3 (AES, diversified per-card keys)."
    elif "DESFire" in chip:
        method = "none practical (AES mutual auth)"
        cloneability = "LOW"
        rec = "Confirm non-default AES keys + diversification; prefer EV2/EV3."
    elif "Ultralight" in chip or "NTAG" in chip:
        method = "direct read"
        cloneability = "HIGH" if "NTAG" in chip else "MEDIUM"
        issues.append("Ultralight/NTAG often lacks crypto auth")
        rec = "Do not use for access control; use DESFire EV2/EV3."
    else:
        method = "unknown"
        cloneability = "UNKNOWN"
        rec = "Identify chip type before assessing."
    return {
        "chip": chip,
        "uid": info["uid"],
        "sectors": info["sectors"],
        "keys_recovered": n_keys,
        "default_keys": n_default,
        "recovery_method": method,
        "cloneability": cloneability,
        "issues": issues,
        "recommendation": rec,
    }


def cmd_assess(args):
    info = load_dump(args.dump)
    keys = load_keys(args.keys)
    result = score(info, keys)
    print(f"[+] credential: {result['chip']}  UID={result['uid'] or '?'}")
    print(f"[+] sectors: {result['sectors']}  keys recovered: {result['keys_recovered']} "
          f"(default: {result['default_keys']})")
    print(f"[+] recovery method : {result['recovery_method']}")
    print(f"[+] cloneability    : {result['cloneability']}")
    for i in result["issues"]:
        print(f"     - {i}")
    print(f"[+] recommendation  : {result['recommendation']}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        print(f"[+] written to {args.json}")
    return 0


def main():
    p = argparse.ArgumentParser(description="RFID/NFC cloneability assessor")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("assess", help="score a MIFARE dump for cloneability")
    a.add_argument("--dump", required=True, help="Proxmark3 JSON or raw .bin dump")
    a.add_argument("--keys", help="recovered-keys file (one per line)")
    a.add_argument("--json", help="write result JSON")
    a.set_defaults(func=cmd_assess)
    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
