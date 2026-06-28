#!/usr/bin/env python3
# For authorized analysis of firmware you own or are permitted to test.
# Recovered credentials, keys, and certificates are sensitive: handle them under
# your engagement's data-handling rules.
"""IoT firmware root-filesystem triage scanner (pure stdlib).

Walks an extracted root filesystem and reports security findings:
  - account inventory + password-hash strength (/etc/passwd, /etc/shadow)
  - empty-password / backdoor-style accounts
  - private keys, certificates, and hardcoded credentials   (--secrets)
  - setuid / setgid binaries                                 (--suid)
  - references to telnet/ftp/ssh services in configs         (--services)
"""
import argparse
import os
import re
import stat
import sys

HASH_GRADE = {
    "$1$": ("MD5 crypt", "WEAK"),
    "$2a$": ("bcrypt", "STRONG"),
    "$2b$": ("bcrypt", "STRONG"),
    "$2y$": ("bcrypt", "STRONG"),
    "$5$": ("SHA-256 crypt", "MODERATE"),
    "$6$": ("SHA-512 crypt", "MODERATE"),
    "$y$": ("yescrypt", "STRONG"),
}


def grade_hash(field):
    if field in ("", "!", "*", "x", "!!"):
        return ("locked/none-in-shadow", "INFO") if field in ("!", "*", "x", "!!") \
            else ("EMPTY PASSWORD", "CRITICAL")
    for prefix, (algo, strength) in HASH_GRADE.items():
        if field.startswith(prefix):
            return (algo, strength)
    if re.fullmatch(r"[./0-9A-Za-z]{13}", field):
        return ("DES crypt", "VERY WEAK")
    return ("unknown", "INFO")


def analyze_accounts(rootfs):
    findings = []
    passwd = os.path.join(rootfs, "etc/passwd")
    shadow = os.path.join(rootfs, "etc/shadow")
    shadow_map = {}
    if os.path.isfile(shadow):
        for line in _readlines(shadow):
            parts = line.split(":")
            if len(parts) >= 2:
                shadow_map[parts[0]] = parts[1]
    if not os.path.isfile(passwd):
        return ["[!] no etc/passwd found"]
    for line in _readlines(passwd):
        parts = line.split(":")
        if len(parts) < 7:
            continue
        user, pwfield, uid, _gid, _gecos, _home, shell = parts[:7]
        pw = shadow_map.get(user, pwfield)
        algo, strength = grade_hash(pw)
        flags = []
        if strength in ("CRITICAL", "VERY WEAK", "WEAK"):
            flags.append(strength)
        if uid == "0" and user != "root":
            flags.append("UID-0 (root-equivalent backdoor?)")
        if shell.strip() in ("/bin/sh", "/bin/bash", "/bin/ash") and user not in ("root",):
            flags.append("interactive shell")
        tag = ("  <-- " + ", ".join(flags)) if flags else ""
        findings.append(f"    {user:<14} uid={uid:<5} hash={algo:<16} shell={shell}{tag}")
    return findings


def _readlines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return [ln.rstrip("\n") for ln in fh if ln.strip()]
    except OSError:
        return []


SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key block"),
    (re.compile(r"(?i)\bpassword\s*[=:]\s*\S+"), "password assignment"),
    (re.compile(r"(?i)\bapi[_-]?key\s*[=:]\s*\S+"), "api key"),
    (re.compile(r"(?i)\bsecret\s*[=:]\s*\S+"), "secret assignment"),
]
KEY_EXT = (".pem", ".key", ".p12", ".pfx", ".crt", ".cer", ".der")
SERVICE_RE = re.compile(r"\b(telnetd|ftpd|vsftpd|dropbear|sshd|tftpd)\b", re.IGNORECASE)


def scan_tree(rootfs, want_secrets, want_suid, want_services):
    secrets, suid, services = [], [], {}
    for dirpath, _dirs, files in os.walk(rootfs):
        for fname in files:
            path = os.path.join(dirpath, fname)
            rel = os.path.relpath(path, rootfs)
            if want_suid:
                try:
                    mode = os.lstat(path).st_mode
                    if mode & (stat.S_ISUID | stat.S_ISGID):
                        kind = "setuid" if mode & stat.S_ISUID else "setgid"
                        suid.append(f"    {kind:<7} {rel}")
                except OSError:
                    pass
            if want_secrets and fname.lower().endswith(KEY_EXT):
                secrets.append(f"    [key/cert file] {rel}")
            if want_secrets or want_services:
                if not _looks_text(path):
                    continue
                content = _read_text(path, limit=200_000)
                if want_secrets:
                    for pat, name in SECRET_PATTERNS:
                        if pat.search(content):
                            secrets.append(f"    [{name}] {rel}")
                            break
                if want_services:
                    for m in SERVICE_RE.finditer(content):
                        services.setdefault(m.group(1).lower(), set()).add(rel)
    return secrets, suid, services


def _looks_text(path):
    try:
        if os.path.getsize(path) > 2_000_000:
            return False
        with open(path, "rb") as fh:
            chunk = fh.read(512)
        return b"\x00" not in chunk
    except OSError:
        return False


def _read_text(path, limit):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def cmd_scan(args):
    root = args.rootfs
    if not os.path.isdir(root):
        print(f"[!] not a directory: {root}", file=sys.stderr)
        return 1
    print(f"[+] triaging rootfs: {root}\n")

    print("[ACCOUNTS]")
    for line in analyze_accounts(root):
        print(line)

    if args.secrets or args.suid or args.services:
        secrets, suid, services = scan_tree(root, args.secrets, args.suid, args.services)
        if args.secrets:
            print("\n[SECRETS]")
            for line in secrets or ["    (none found)"]:
                print(line)
        if args.suid:
            print("\n[SETUID/SETGID]")
            for line in suid or ["    (none found)"]:
                print(line)
        if args.services:
            print("\n[EXPOSED SERVICES]")
            if not services:
                print("    (none found)")
            for svc in sorted(services):
                locs = ", ".join(sorted(services[svc])[:4])
                print(f"    {svc:<10} -> {locs}")
    print("\n[i] re-run with --secrets --suid --services for full coverage")
    return 0


def main():
    p = argparse.ArgumentParser(description="IoT firmware filesystem triage scanner")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="triage an extracted root filesystem")
    s.add_argument("--rootfs", required=True)
    s.add_argument("--secrets", action="store_true", help="hunt keys/certs/credentials")
    s.add_argument("--suid", action="store_true", help="list setuid/setgid binaries")
    s.add_argument("--services", action="store_true", help="find telnet/ftp/ssh refs")
    s.set_defaults(func=cmd_scan)
    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
