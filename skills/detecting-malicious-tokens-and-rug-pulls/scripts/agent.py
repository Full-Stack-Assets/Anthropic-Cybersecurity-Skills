#!/usr/bin/env python3
# For defensive token triage only. Use this to protect users, wallets, and
# listing pipelines from scam tokens. Do not deploy honeypots or use these
# techniques to defraud.
"""Malicious-token / rug-pull triage scanner.

Stdlib-only. Scans an ERC-20's verified Solidity source (or its ABI JSON) for
rug-pull red flags and emits a weighted risk score and verdict.

  scan --source Token.sol            # source-level heuristic scan
  scan --abi token_abi.json          # ABI-based selector scan (no source)
  scan --source Token.sol --output report.json
"""
import argparse
import json
import os
import re
import sys

# (regex, weight, label). Higher weight = stronger rug signal.
SOURCE_FLAGS = [
    (r"\bfunction\s+mint\s*\(", 25, "callable mint() (supply inflation)"),
    (r"\bfunction\s+set(Fee|Tax|Taxes|Fees)\s*\(", 25, "uncapped fee/tax setter (fee trap)"),
    (r"\b(blacklist|addBot|setBlacklist|setBots|_blacklist)\b", 25, "blacklist / anti-bot sell blocking"),
    (r"\bfunction\s+(pause|unpause|enableTrading|setTrading)\s*\(", 15, "pausable / trading toggle (freeze sells)"),
    (r"\bfunction\s+(withdraw|rescue|drain|sweep)\s*\(", 20, "owner-only fund extraction"),
    (r"\bfunction\s+set(MaxTx|MaxWallet|MaxTransaction)\s*\(", 10, "max-tx/wallet limiter (throttle sells)"),
    (r"\bexcludeFromFee", 8, "asymmetric fee exemption"),
    (r"\bupgradeTo\b|\b_implementation\b|\bdelegatecall\b", 15, "upgradeable proxy / delegatecall (swap-in logic)"),
    (r"_transfer\s*\([^)]*\)\s*internal[^{]*\{[^}]*onlyOwner", 20, "owner-gated transfer hook (honeypot)"),
    (r"\btx\.origin\b", 8, "tx.origin usage (auth anti-pattern)"),
]

# ABI function names that are red flags.
ABI_FLAGS = {
    "mint": (25, "callable mint() (supply inflation)"),
    "setfee": (25, "fee/tax setter (fee trap)"),
    "settax": (25, "fee/tax setter (fee trap)"),
    "settaxes": (25, "fee/tax setter (fee trap)"),
    "blacklist": (25, "blacklist (sell blocking)"),
    "addbot": (25, "anti-bot blacklist"),
    "setbots": (25, "anti-bot blacklist"),
    "pause": (15, "pausable transfers"),
    "enabletrading": (15, "trading toggle"),
    "withdraw": (20, "owner fund extraction"),
    "rescue": (20, "owner fund extraction"),
    "drain": (20, "owner fund extraction"),
    "setmaxtx": (10, "max-tx limiter"),
    "upgradeto": (15, "upgradeable proxy"),
}


def strip_comments(src):
    src = re.sub(r"//[^\n]*", "", src)
    return re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)


def scan_source(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        code = strip_comments(fh.read())
    findings = []
    for pattern, weight, label in SOURCE_FLAGS:
        if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
            findings.append({"weight": weight, "flag": label})
    # ownership renouncement hint
    renounced = bool(re.search(r"renounceOwnership", code))
    findings.append({"weight": 0 if renounced else 10,
                     "flag": "renounceOwnership present" if renounced
                     else "no renounceOwnership found (owner likely retained)"})
    return findings


def scan_abi(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        abi = json.load(fh)
    if isinstance(abi, dict) and "abi" in abi:
        abi = abi["abi"]
    findings = []
    names = {e.get("name", "").lower() for e in abi if isinstance(e, dict) and e.get("type") == "function"}
    for name in sorted(names):
        if name in ABI_FLAGS:
            weight, label = ABI_FLAGS[name]
            findings.append({"weight": weight, "flag": f"{name}() — {label}"})
    if not findings:
        findings.append({"weight": 0, "flag": "no red-flag selectors in ABI (source review still advised)"})
    return findings


def verdict(score):
    if score >= 70:
        return "CRITICAL"
    if score >= 45:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


def cmd_scan(args):
    if args.source:
        if not os.path.isfile(args.source):
            print(f"[!] no such file: {args.source}", file=sys.stderr)
            return 1
        findings = scan_source(args.source)
        target = args.source
    elif args.abi:
        if not os.path.isfile(args.abi):
            print(f"[!] no such file: {args.abi}", file=sys.stderr)
            return 1
        findings = scan_abi(args.abi)
        target = args.abi
    else:
        print("[!] provide --source or --abi", file=sys.stderr)
        return 1

    score = min(sum(f["weight"] for f in findings), 100)
    v = verdict(score)
    print(f"[+] target  : {target}")
    print(f"[+] flags   : {len([f for f in findings if f['weight'] > 0])}\n")
    for f in sorted(findings, key=lambda x: -x["weight"]):
        mark = "[!]" if f["weight"] >= 15 else "[*]" if f["weight"] > 0 else "[ ]"
        print(f"    {mark} (+{f['weight']:>2}) {f['flag']}")
    print(f"\n[+] rug-pull risk score : {score}/100")
    print(f"[+] verdict             : {v}")
    if v in ("HIGH", "CRITICAL"):
        print("[i] recommend BLOCK / manual review before any user interaction")

    if args.output:
        report = {"target": target, "score": score, "verdict": v, "findings": findings}
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"[+] report written to {args.output}")
    return 0


def main():
    p = argparse.ArgumentParser(description="Malicious-token / rug-pull triage scanner")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan token source or ABI for rug-pull traits")
    s.add_argument("--source", help="path to verified Solidity source")
    s.add_argument("--abi", help="path to ABI JSON (when source unavailable)")
    s.add_argument("--output", help="write JSON report")
    s.set_defaults(func=cmd_scan)
    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
