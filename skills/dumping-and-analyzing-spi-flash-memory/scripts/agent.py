#!/usr/bin/env python3
# For authorized hardware security testing of devices you own or are permitted to test.
# Reading flash, desoldering chips, or copying firmware without authorization may
# violate the DMCA, vendor terms, and warranty.
"""SPI/NOR flash dump analyzer (pure stdlib).

Subcommands:
  map      Scan a flash dump for known partition/magic headers and report a
           per-region entropy + magic offset map.
  entropy  Per-block Shannon entropy of a dump (bytes/byte, 0..8).
  strings  Extract printable strings; optionally flag likely secrets.
"""
import argparse
import math
import re
import struct
import sys

# magic -> (label, match-kind). 'le4'/'be4' = 4-byte int at block start; 'bytes' = literal.
MAGICS = [
    (0x27051956, "uImage (U-Boot legacy header)", "be4"),
    (0xd00dfeed, "FIT / device-tree blob", "be4"),
    (b"hsqs", "SquashFS (LE)", "bytes"),
    (b"sqsh", "SquashFS (BE)", "bytes"),
    (b"\x85\x19", "JFFS2", "bytes"),
    (0x28cd3d45, "CramFS", "le4"),
    (b"UBI#", "UBI volume", "bytes"),
    (b"\x1f\x8b\x08", "gzip stream", "bytes"),
    (b"\xfd7zXZ\x00", "XZ stream", "bytes"),
    (b"\x5d\x00\x00", "LZMA stream", "bytes"),
    (b"070701", "CPIO (newc/initramfs)", "bytes"),
]


def read_image(path):
    with open(path, "rb") as fh:
        return fh.read()


def shannon_entropy(block):
    if not block:
        return 0.0
    counts = [0] * 256
    for byte in block:
        counts[byte] += 1
    n = len(block)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def classify(ent):
    if ent < 1.0:
        return "padding/empty (0x00/0xFF)"
    if ent < 5.0:
        return "code/config/plaintext"
    if ent < 7.0:
        return "compressed"
    return "strongly compressed or encrypted"


def find_magics(data):
    """Return list of (offset, label) for magic hits anywhere in the image."""
    hits = []
    for magic, label, kind in MAGICS:
        if kind == "bytes":
            start = 0
            while True:
                idx = data.find(magic, start)
                if idx == -1:
                    break
                hits.append((idx, label))
                start = idx + 1
        else:
            # 4-byte int magics: scan aligned positions for speed
            packed = struct.pack(">I" if kind == "be4" else "<I", magic)
            start = 0
            while True:
                idx = data.find(packed, start)
                if idx == -1:
                    break
                hits.append((idx, label))
                start = idx + 1
    return sorted(hits)


def cmd_map(args):
    data = read_image(args.image)
    print(f"[+] image: {args.image}  ({len(data):,} bytes)\n")

    hits = find_magics(data)
    print("[+] magic-header hits:")
    if not hits:
        print("    (none found)")
    for off, label in hits[:200]:
        local = shannon_entropy(data[off:off + args.block])
        print(f"    0x{off:08x}  entropy={local:4.2f}  {label}")

    print("\n[+] entropy band map (per {0}-byte block, transitions only):".format(args.block))
    prev = None
    for i in range(0, len(data), args.block):
        ent = shannon_entropy(data[i:i + args.block])
        band = classify(ent)
        if band != prev:
            print(f"    0x{i:08x}  {ent:4.2f}  {band}")
            prev = band
    return 0


def cmd_entropy(args):
    data = read_image(args.image)
    for i in range(0, len(data), args.block):
        ent = shannon_entropy(data[i:i + args.block])
        bar = "#" * int(ent * 5)
        print(f"0x{i:08x}  {ent:4.2f}  {bar}")
    return 0


SECRET_PATTERNS = [
    (re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
    (re.compile(rb"(?i)password\s*[=:]\s*\S+"), "password assignment"),
    (re.compile(rb"(?i)api[_-]?key\s*[=:]\s*\S+"), "api key"),
    (re.compile(rb"(?i)secret\s*[=:]\s*\S+"), "secret assignment"),
    (re.compile(rb"\$[1256ay]\$[^\s:]{8,}"), "unix password hash"),
    (re.compile(rb"(?i)(ssh-rsa|ssh-ed25519)\s+[A-Za-z0-9+/=]{20,}"), "ssh public key"),
]


def iter_strings(data, min_len):
    cur = bytearray()
    start = 0
    for i, b in enumerate(data):
        if 32 <= b < 127:
            if not cur:
                start = i
            cur.append(b)
        else:
            if len(cur) >= min_len:
                yield start, bytes(cur)
            cur = bytearray()
    if len(cur) >= min_len:
        yield start, bytes(cur)


def cmd_strings(args):
    data = read_image(args.image)
    count = 0
    flagged = 0
    for off, s in iter_strings(data, args.min):
        count += 1
        tag = ""
        if args.flag_secrets:
            for pat, name in SECRET_PATTERNS:
                if pat.search(s):
                    tag = f"  <-- [SECRET: {name}]"
                    flagged += 1
                    break
        if args.flag_secrets and not tag:
            continue
        try:
            text = s.decode("ascii")
        except UnicodeDecodeError:
            text = repr(s)
        print(f"0x{off:08x}  {text}{tag}")
    if args.flag_secrets:
        print(f"\n[+] {flagged} likely secret(s) flagged out of {count} strings", file=sys.stderr)
    return 0


def main():
    p = argparse.ArgumentParser(description="SPI/NOR flash dump analyzer (stdlib)")
    sub = p.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("map", help="partition/magic + entropy offset map")
    m.add_argument("--image", required=True)
    m.add_argument("--block", type=int, default=4096)
    m.set_defaults(func=cmd_map)

    e = sub.add_parser("entropy", help="per-block Shannon entropy")
    e.add_argument("--image", required=True)
    e.add_argument("--block", type=int, default=4096)
    e.set_defaults(func=cmd_entropy)

    s = sub.add_parser("strings", help="extract printable strings")
    s.add_argument("--image", required=True)
    s.add_argument("--min", type=int, default=8)
    s.add_argument("--flag-secrets", action="store_true")
    s.set_defaults(func=cmd_strings)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
