#!/usr/bin/env python3
# Defensive supply-chain tooling. The pickle-opcode heuristic is detection-only;
# never load an untrusted model outside an isolated sandbox.
"""ML model supply-chain guard.

Two modes:
  scan  - Scan a model artifact for unsafe deserialization. Uses `modelscan` if
          installed; otherwise falls back to a pure-stdlib pickle-opcode
          heuristic that flags GLOBAL/REDUCE references to dangerous modules.
  hash  - Print or verify a model's SHA-256 for integrity/provenance checks.

Maps to MITRE ATLAS AML.T0010 (AI Supply Chain Compromise) / AML.T0058.
"""
import argparse
import hashlib
import io
import pickletools
import shutil
import subprocess
import sys
import zipfile

DANGEROUS = ("os", "subprocess", "posix", "nt", "socket", "shutil", "sys",
             "builtins.eval", "builtins.exec", "builtins.__import__",
             "builtins.getattr", "runpy", "pty", "commands")

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def cmd_hash(args):
    digest = sha256(args.path)
    print(f"sha256: {digest}")
    if args.expected:
        if digest.lower() == args.expected.lower():
            print("[+] hash MATCHES expected — integrity verified")
            return 0
        print("[!] hash MISMATCH — artifact integrity FAILED", file=sys.stderr)
        return 2
    return 0


def _iter_pickle_streams(path):
    """Yield raw pickle byte streams from a file: the file itself, plus any
    .pkl/data members inside a zip-based artifact (PyTorch .bin/.pt are zips)."""
    with open(path, "rb") as f:
        head = f.read(4)
    if head[:2] == b"PK":  # zip container (torch save format)
        try:
            with zipfile.ZipFile(path) as zf:
                for name in zf.namelist():
                    if name.endswith((".pkl", "data.pkl")) or "/data" in name:
                        yield name, zf.read(name)
        except zipfile.BadZipFile:
            return
    else:
        with open(path, "rb") as f:
            yield path, f.read()


def heuristic_scan(path):
    """Stdlib fallback: disassemble pickle opcodes, flag dangerous GLOBAL refs."""
    findings = []
    for member, data in _iter_pickle_streams(path):
        try:
            for op, arg, _pos in pickletools.genops(io.BytesIO(data)):
                if op.name in ("GLOBAL", "STACK_GLOBAL") and arg:
                    ref = str(arg).replace(" ", ".")
                    if any(d in ref for d in DANGEROUS):
                        findings.append((member, f"{op.name} -> {ref}"))
                if op.name == "REDUCE":
                    findings.append((member, "REDUCE (callable invoked on load)"))
        except Exception as exc:  # not a pickle / truncated — skip member
            continue
    return findings


def cmd_scan(args):
    if shutil.which("modelscan"):
        print("[*] modelscan found — delegating")
        cmd = ["modelscan", "-p", args.path]
        rc = subprocess.run(cmd).returncode
        if rc != 0:
            print("[!] modelscan reported findings (non-zero exit)", file=sys.stderr)
        return rc

    print("[*] modelscan not installed — using stdlib pickle-opcode heuristic")
    findings = heuristic_scan(args.path)
    if not findings:
        print("[+] no dangerous pickle opcodes detected (heuristic, not exhaustive)")
        return 0

    print(f"[!] {len(findings)} suspicious construct(s) — artifact may execute code on load:")
    for member, detail in findings:
        print(f"    {member}: {detail}")
    # heuristic findings are treated as HIGH for gating
    threshold = SEVERITY_ORDER.get(args.fail_on, 2)
    return 2 if threshold <= SEVERITY_ORDER["high"] else 0


def main():
    p = argparse.ArgumentParser(description="ML model supply-chain guard")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a model artifact for unsafe deserialization")
    s.add_argument("--path", required=True, help="model file (pickle/.bin/.pt/...)")
    s.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="high",
                   help="minimum severity that causes a non-zero exit (heuristic mode)")
    s.set_defaults(func=cmd_scan)

    h = sub.add_parser("hash", help="print or verify SHA-256")
    h.add_argument("--path", required=True)
    h.add_argument("--expected", help="expected SHA-256 to verify against")
    h.set_defaults(func=cmd_hash)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
