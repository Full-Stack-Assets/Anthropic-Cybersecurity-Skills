#!/usr/bin/env python3
# For authorized reverse engineering of firmware you own or are permitted to analyze.
# Firmware is typically copyrighted; respect licensing, the DMCA, and engagement terms.
"""Bare-metal firmware orientation helper for Ghidra (pure stdlib).

Subcommands:
  arch      Apply the ARM Cortex-M vector-table heuristic to a raw blob and
            suggest a load/base address.
  vectors   Dump and validate the first N vector-table entries at a given base.
  strings   Extract printable strings; optionally flag known crypto constants.
"""
import argparse
import math
import struct
import sys

# Known crypto constants (4-byte little-endian words / byte runs).
CRYPTO_BYTES = [
    (b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5", "AES S-box"),
    (b"\x98\x2f\x8a\x42", "SHA-256 K[0] (0x428a2f98, LE)"),
    (b"\x01\x23\x45\x67", "MD5/SHA-1 init A (0x67452301, LE)"),
    (b"\x20\x83\xb8\xed", "CRC32 reflected poly (0xEDB88320, LE)"),
    (b"\x67\x45\x23\x01", "MD5 init A (0x67452301, BE)"),
]


def read_image(path):
    with open(path, "rb") as fh:
        return fh.read()


def le32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def cortex_m_heuristic(data):
    """Return dict with vector-table validity + a suggested base address."""
    if len(data) < 64:
        return {"valid": False, "reason": "image too small"}
    init_sp = le32(data, 0)
    reset = le32(data, 4)

    # initial SP should point into SRAM, typically 0x20000000..0x20040000, word-aligned
    sp_ok = (0x20000000 <= init_sp <= 0x20080000) and (init_sp % 4 == 0)
    # reset handler should be a Thumb code pointer (odd) into a flash-like region
    reset_ok = (reset & 1) == 1 and (
        0x00000000 <= reset <= 0x00100000 or 0x08000000 <= reset <= 0x08200000
    )

    # subsequent vectors should also look like odd code pointers in the same region
    odd_ptrs = 0
    for off in range(8, 64, 4):
        v = le32(data, off)
        if v and (v & 1) == 1:
            odd_ptrs += 1

    base = 0x08000000 if reset >= 0x08000000 else 0x00000000
    valid = sp_ok and reset_ok and odd_ptrs >= 4
    return {
        "valid": valid,
        "init_sp": init_sp,
        "reset": reset,
        "sp_ok": sp_ok,
        "reset_ok": reset_ok,
        "odd_ptrs": odd_ptrs,
        "base": base,
    }


def cmd_arch(args):
    data = read_image(args.image)
    h = cortex_m_heuristic(data)
    if h.get("valid"):
        print("[+] Cortex-M vector table looks valid")
        print(f"    initial SP  = 0x{h['init_sp']:08x}  ({'plausible SRAM' if h['sp_ok'] else 'unexpected'})")
        print(f"    reset addr  = 0x{h['reset']:08x}  (Thumb code pointer, odd)")
        print(f"    odd ptrs in first 16 vectors: {h['odd_ptrs']}")
        print(f"[+] suggested base/load address: 0x{h['base']:08x}  (ARM Cortex-M, little-endian)")
        print("[+] Ghidra language: ARM:LE:32:Cortex")
    else:
        reason = h.get("reason", "vector-table heuristic did not match")
        print(f"[!] not a confident Cortex-M match ({reason})")
        if "init_sp" in h:
            print(f"    init word   = 0x{h['init_sp']:08x}  (sp_ok={h['sp_ok']})")
            print(f"    second word = 0x{h['reset']:08x}  (reset_ok={h['reset_ok']})")
        print("[i] try other architectures (MIPS/ARM v7/RISC-V) or another base in Ghidra.")
    return 0


def cmd_vectors(args):
    data = read_image(args.image)
    n = min(args.count, len(data) // 4)
    names = ["Initial SP", "Reset", "NMI", "HardFault", "MemManage",
             "BusFault", "UsageFault", "Rsvd", "Rsvd", "Rsvd", "Rsvd",
             "SVCall", "DebugMon", "Rsvd", "PendSV", "SysTick"]
    print(f"[+] vector table (base 0x{args.base:08x}):")
    for i in range(n):
        v = le32(data, i * 4)
        label = names[i] if i < len(names) else f"IRQ{i-16}"
        note = ""
        if i == 0:
            note = "SRAM?" if 0x20000000 <= v <= 0x20080000 else "(unexpected SP)"
        elif v:
            note = "code (odd/Thumb)" if v & 1 else "(even - not Thumb?)"
        print(f"    [{i:2}] 0x{i*4:04x}  {label:<12} = 0x{v:08x}  {note}")
    return 0


def shannon(block):
    if not block:
        return 0.0
    counts = [0] * 256
    for b in block:
        counts[b] += 1
    n = len(block)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


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
    print(f"[+] overall entropy: {shannon(data):.2f} bits/byte")
    if args.crypto:
        print("\n[+] crypto constant scan:")
        any_hit = False
        for needle, name in CRYPTO_BYTES:
            idx = data.find(needle)
            if idx != -1:
                print(f"    0x{idx:08x}  {name}")
                any_hit = True
        if not any_hit:
            print("    (no known crypto constants found)")
    print("\n[+] strings:")
    for off, s in iter_strings(data, args.min):
        print(f"    0x{off:08x}  {s.decode('ascii', 'replace')}")
    return 0


def main():
    p = argparse.ArgumentParser(description="Bare-metal firmware orientation helper")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("arch", help="Cortex-M vector-table heuristic + base address")
    a.add_argument("--image", required=True)
    a.set_defaults(func=cmd_arch)

    v = sub.add_parser("vectors", help="dump/validate vector-table entries")
    v.add_argument("--image", required=True)
    v.add_argument("--base", type=lambda x: int(x, 0), default=0x08000000)
    v.add_argument("--count", type=int, default=16)
    v.set_defaults(func=cmd_vectors)

    s = sub.add_parser("strings", help="strings + crypto constant scan")
    s.add_argument("--image", required=True)
    s.add_argument("--min", type=int, default=6)
    s.add_argument("--crypto", action="store_true")
    s.set_defaults(func=cmd_strings)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
