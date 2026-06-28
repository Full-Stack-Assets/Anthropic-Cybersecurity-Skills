#!/usr/bin/env python3
# For authorized bridge security assessment only. Test contracts you own,
# testnets, or systems you are explicitly permitted to assess. Never aim
# forged-proof or signature-bypass techniques at a live bridge.
"""Cross-chain bridge security helper.

Two stdlib-only modes:
  score - Ingest a bridge's trust configuration (validator count, threshold,
          verification method, upgradeability, timelock) and produce a trust
          risk score with concrete weaknesses flagged.
  scan  - Scan a bridge's Solidity source for missing replay protection, weak
          signature verification, and missing chain-ID binding.

No external dependencies are required.
"""
import argparse
import re
import os
import sys


def str2bool(v):
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")


def cmd_score(args):
    findings = []
    score = 0  # higher = more risk

    n = args.validators
    t = args.threshold
    ratio = (t / n) if n else 0.0

    if n <= 1:
        findings.append("CRITICAL: single attester (1 validator/relayer) — single point of failure")
        score += 40
    elif n < 5:
        findings.append(f"HIGH: small validator set (n={n}) — limited diversity")
        score += 25
    if ratio < 0.5:
        findings.append(f"HIGH: low threshold ratio {t}/{n} = {ratio:.2f} (< 0.5)")
        score += 25
    elif ratio < 0.66:
        findings.append(f"MEDIUM: threshold ratio {t}/{n} = {ratio:.2f} (< 2/3 recommended)")
        score += 12

    method = args.verification.lower()
    if method in ("multisig", "signers", "relayer"):
        findings.append("MEDIUM: off-chain multisig verification — trusts signer honesty/keys")
        score += 15
    elif method in ("optimistic",):
        findings.append("INFO: optimistic verification — depends on watchers + challenge window")
        score += 5
    elif method in ("light-client", "lightclient", "merkle", "zk"):
        findings.append("GOOD: on-chain proof verification (lower trust assumption)")
    else:
        findings.append(f"WARN: unknown verification method '{args.verification}'")
        score += 10

    if str2bool(args.upgradeable):
        if args.timelock_hours <= 0:
            findings.append("CRITICAL: upgradeable WITHOUT timelock — admin can swap verifier instantly")
            score += 30
        elif args.timelock_hours < 24:
            findings.append(f"HIGH: short upgrade timelock ({args.timelock_hours}h < 24h)")
            score += 15
        else:
            findings.append(f"INFO: upgradeable with {args.timelock_hours}h timelock")
            score += 5

    score = min(score, 100)
    level = "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"
    print(f"[+] validators={n} threshold={t} ratio={ratio:.2f} method={args.verification}")
    print(f"[+] upgradeable={args.upgradeable} timelock={args.timelock_hours}h\n")
    for f in findings:
        print(f"    - {f}")
    print(f"\n[+] bridge trust risk score: {score}/100 ({level})")
    return 0


REPLAY_PATTERNS = ("processed[", "consumed[", "usedNonce", "seen[", "nonces[",
                   "executed[", "isProcessed")
SIG_OK = ("ecrecover", "ECDSA.recover", "isValidator", "isSigner")
CHAINID = ("chainid", "chainId", "block.chainid", "CHAIN_ID")


def cmd_scan(args):
    if not os.path.isfile(args.source):
        print(f"[!] no such file: {args.source}", file=sys.stderr)
        return 1
    with open(args.source, "r", encoding="utf-8", errors="replace") as fh:
        src = fh.read()
    code = re.sub(r"//[^\n]*", "", src)
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)

    issues = []
    if not any(p in code for p in REPLAY_PATTERNS):
        issues.append("HIGH: no replay-protection map (processed/consumed/usedNonce) found")
    if "ecrecover" in code:
        if "address(0)" not in code:
            issues.append("HIGH: ecrecover used without an address(0) check (malformed-sig bypass)")
        if not any(s in code for s in ("isValidator", "isSigner", "validators[")):
            issues.append("HIGH: signature verified without checking signer against an authorized set")
    elif not any(s in code for s in SIG_OK):
        issues.append("INFO: no signature recovery found — confirm proof/light-client verification path")
    if not any(c in code for c in CHAINID):
        issues.append("MEDIUM: no chain-ID binding found (cross-chain replay / wrong-chain execution)")
    if "EIP712" not in code and "DOMAIN_SEPARATOR" not in code and "_domainSeparator" not in code.lower():
        issues.append("MEDIUM: no EIP-712 domain separator detected (weak message binding)")

    print(f"[+] scanning {args.source}\n")
    if not issues:
        print("[+] no obvious verification/replay gaps detected (manual review still required)")
        return 0
    for i in issues:
        print(f"    - {i}")
    sev = sum(20 if i.startswith("HIGH") else 10 if i.startswith("MEDIUM") else 2 for i in issues)
    print(f"\n[+] indicative risk: {min(sev,100)}/100 — verify each finding manually")
    return 0


def main():
    p = argparse.ArgumentParser(description="Cross-chain bridge security helper (score config / scan source)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("score", help="score a bridge trust configuration")
    s.add_argument("--validators", type=int, required=True)
    s.add_argument("--threshold", type=int, required=True)
    s.add_argument("--verification", default="multisig",
                   help="multisig|light-client|merkle|zk|optimistic|relayer")
    s.add_argument("--upgradeable", default="false")
    s.add_argument("--timelock-hours", type=float, default=0)
    s.set_defaults(func=cmd_score)

    c = sub.add_parser("scan", help="scan bridge source for replay/signature gaps")
    c.add_argument("--source", required=True)
    c.set_defaults(func=cmd_scan)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
