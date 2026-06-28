#!/usr/bin/env python3
# For authorized smart-contract auditing only. Demonstrate unprotected upgrades,
# uninitialized proxies, or selfdestruct only against contracts you own or are
# permitted to assess. Use this to harden contracts, not to seize control.
"""Access-control / upgradeability red-flag scanner.

Stdlib-only. Scans Solidity source for access-control and proxy hazards:
missing guards on sensitive setters, tx.origin auth, unprotected initializers,
unprotected UUPS upgrades, reachable selfdestruct, and delegatecall, then emits
a prioritized risk report.

  scan --source Contract.sol
  scan --source Logic.sol --output report.json
"""
import argparse
import json
import os
import re
import sys

GUARD_KEYWORDS = ("onlyOwner", "onlyRole", "onlyAdmin", "onlyGovernance",
                  "requiresAuth", "authorized", "_checkRole", "onlyProxy")

# Function-name fragments that should be access-controlled.
SENSITIVE_FRAGMENTS = ("setowner", "transferownership", "setadmin", "grantrole",
                       "setfee", "settax", "withdraw", "mint", "pause", "upgrade",
                       "setimplementation", "rescue", "drain", "setpaused",
                       "addminter", "setrouter")

FUNC_RE = re.compile(
    r"function\s+(\w+)\s*\(([^)]*)\)\s*([^{;]*?)(\{|;)", re.DOTALL)


def strip_comments(src):
    src = re.sub(r"//[^\n]*", "", src)
    return re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)


def line_of(src, pos):
    return src.count("\n", 0, pos) + 1


def scan(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    src = strip_comments(raw)
    findings = []

    # 1. sensitive external/public functions lacking a guard
    for m in FUNC_RE.finditer(src):
        name, params, quals, _ = m.group(1), m.group(2), m.group(3), m.group(4)
        ql = quals.lower()
        visible = ("public" in ql) or ("external" in ql)
        is_view = any(k in ql for k in ("view", "pure"))
        if not visible or is_view:
            continue
        if any(frag in name.lower() for frag in SENSITIVE_FRAGMENTS):
            guarded = any(g.lower() in ql for g in GUARD_KEYWORDS)
            if not guarded:
                findings.append({"sev": "HIGH", "weight": 25,
                                 "line": line_of(src, m.start()),
                                 "issue": f"sensitive function '{name}' has no access-control modifier (SWC-105)"})

    # 2. tx.origin authorization
    for m in re.finditer(r"tx\.origin", src):
        findings.append({"sev": "HIGH", "weight": 20, "line": line_of(src, m.start()),
                         "issue": "tx.origin used (phishable authorization, SWC-115)"})

    # 3. initializer protection
    has_initialize = re.search(r"function\s+initialize\s*\(", src)
    if has_initialize:
        guarded_init = re.search(r"function\s+initialize\s*\([^)]*\)[^{]*\binitializer\b", src)
        if not guarded_init:
            findings.append({"sev": "HIGH", "weight": 25, "line": line_of(src, has_initialize.start()),
                             "issue": "initialize() not guarded by `initializer` (re-init / takeover risk)"})
        if "_disableInitializers" not in src:
            findings.append({"sev": "MEDIUM", "weight": 15, "line": line_of(src, has_initialize.start()),
                             "issue": "no _disableInitializers() in constructor (impl can be claimed)"})

    # 4. unprotected UUPS upgrade
    auth_upg = re.search(r"_authorizeUpgrade\s*\([^)]*\)[^{]*\{", src)
    if auth_upg:
        seg = src[auth_upg.start():auth_upg.start() + 200]
        if not any(g.lower() in seg.lower() for g in GUARD_KEYWORDS):
            findings.append({"sev": "HIGH", "weight": 25, "line": line_of(src, auth_upg.start()),
                             "issue": "_authorizeUpgrade has no access-control guard (UUPS takeover)"})
    pub_upg = re.search(r"function\s+upgradeTo(AndCall)?\s*\(", src)
    if pub_upg:
        seg = src[pub_upg.start():pub_upg.start() + 200].lower()
        if "external" in seg or "public" in seg:
            if not any(g.lower() in seg for g in GUARD_KEYWORDS):
                findings.append({"sev": "HIGH", "weight": 25, "line": line_of(src, pub_upg.start()),
                                 "issue": "public/external upgradeTo without guard (proxy takeover)"})

    # 5. selfdestruct
    for m in re.finditer(r"selfdestruct\s*\(|suicide\s*\(", src):
        findings.append({"sev": "HIGH", "weight": 20, "line": line_of(src, m.start()),
                         "issue": "selfdestruct present (can brick implementation, SWC-106)"})

    # 6. delegatecall
    for m in re.finditer(r"\.delegatecall\s*\(", src):
        findings.append({"sev": "MEDIUM", "weight": 15, "line": line_of(src, m.start()),
                         "issue": "delegatecall present (verify target is trusted, SWC-112)"})

    return findings


def cmd_scan(args):
    if not os.path.isfile(args.source):
        print(f"[!] no such file: {args.source}", file=sys.stderr)
        return 1
    findings = scan(args.source)
    score = min(sum(f["weight"] for f in findings), 100)
    level = "CRITICAL" if score >= 70 else "HIGH" if score >= 45 else "MEDIUM" if score >= 20 else "LOW"

    print(f"[+] target : {args.source}")
    print(f"[+] findings: {len(findings)}\n")
    if not findings:
        print("[+] no access-control / upgrade red flags detected (manual review still required)")
    for f in sorted(findings, key=lambda x: -x["weight"]):
        print(f"    [{f['sev']:<8}] line {f['line']:<5} {f['issue']}")
    print(f"\n[+] access-control / upgrade risk score: {score}/100 ({level})")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump({"target": args.source, "score": score,
                       "level": level, "findings": findings}, fh, indent=2)
        print(f"[+] report written to {args.output}")
    return 0


def main():
    p = argparse.ArgumentParser(description="Access-control / upgradeability red-flag scanner")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan Solidity source for access-control/proxy hazards")
    s.add_argument("--source", required=True)
    s.add_argument("--output", help="write JSON report")
    s.set_defaults(func=cmd_scan)
    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
