#!/usr/bin/env python3
# For authorized analysis of firmware you own or are permitted to test.
# Emulate in an isolated VM/namespace; emulated services may be vulnerable or contain
# copyrighted vendor code.
"""Firmware-emulation prep helper (pure stdlib).

Subcommands:
  inspect   Detect CPU architecture and endianness from the ELF header of a core
            binary (busybox preferred) in an extracted rootfs, and suggest a
            matching QEMU invocation.
  services  Enumerate likely network-facing init/inetd services in the rootfs.
"""
import argparse
import os
import re
import struct
import sys

# e_machine -> name. (subset relevant to embedded firmware)
EM = {
    0x08: "MIPS",
    0x28: "ARM",
    0xB7: "AArch64",
    0x14: "PowerPC",
    0x15: "PowerPC64",
    0x3E: "x86-64",
    0x03: "x86",
    0xF3: "RISC-V",
}

QEMU_MAP = {
    ("ARM", "little"): ("qemu-arm-static", "qemu-system-arm"),
    ("ARM", "big"): ("qemu-armeb-static", "qemu-system-arm"),
    ("AArch64", "little"): ("qemu-aarch64-static", "qemu-system-aarch64"),
    ("MIPS", "little"): ("qemu-mipsel-static", "qemu-system-mipsel"),
    ("MIPS", "big"): ("qemu-mips-static", "qemu-system-mips"),
    ("PowerPC", "big"): ("qemu-ppc-static", "qemu-system-ppc"),
    ("x86-64", "little"): ("qemu-x86_64-static", "qemu-system-x86_64"),
}


def parse_elf(path):
    """Return (arch, endianness, bits) from an ELF header, or None."""
    with open(path, "rb") as fh:
        hdr = fh.read(20)
    if len(hdr) < 20 or hdr[:4] != b"\x7fELF":
        return None
    bits = 32 if hdr[4] == 1 else 64
    endian = "little" if hdr[5] == 1 else "big"
    e_machine = struct.unpack("<H" if endian == "little" else ">H", hdr[18:20])[0]
    arch = EM.get(e_machine, f"unknown(0x{e_machine:x})")
    return arch, endian, bits


def find_core_binary(rootfs):
    for cand in ("bin/busybox", "bin/sh", "sbin/init", "bin/ls"):
        p = os.path.join(rootfs, cand)
        if os.path.isfile(p):
            return p
    # fall back: first ELF we find
    for dirpath, _dirs, files in os.walk(rootfs):
        for f in files:
            p = os.path.join(dirpath, f)
            try:
                with open(p, "rb") as fh:
                    if fh.read(4) == b"\x7fELF":
                        return p
            except OSError:
                continue
    return None


def cmd_inspect(args):
    binpath = find_core_binary(args.rootfs)
    if not binpath:
        print("[!] no ELF binary found under rootfs", file=sys.stderr)
        return 1
    info = parse_elf(binpath)
    if not info:
        print(f"[!] {binpath} is not a valid ELF", file=sys.stderr)
        return 1
    arch, endian, bits = info
    print(f"[+] sampled binary : {binpath}")
    print(f"[+] architecture   : {arch} ({bits}-bit, {endian}-endian)")
    user, system = QEMU_MAP.get((arch, endian), ("qemu-<arch>-static", "qemu-system-<arch>"))
    print(f"[+] user-mode qemu : {user}")
    print(f"[+] full-system    : {system}")
    print("\n[i] user-mode quick start:")
    print(f"    sudo cp $(which {user}) {args.rootfs}/usr/bin/")
    print(f"    sudo chroot {args.rootfs} /usr/bin/{user} /bin/busybox")
    return 0


SERVICE_RE = re.compile(
    r"\b(httpd|lighttpd|uhttpd|mini_httpd|boa|goahead|telnetd|dropbear|sshd|"
    r"upnpd|miniupnpd|tr069|cwmpd|ftpd|vsftpd|smbd|dnsmasq|inetd|xinetd)\b",
    re.IGNORECASE,
)


def cmd_services(args):
    targets = []
    for rel in ("etc/init.d", "etc/rc.d", "etc"):
        d = os.path.join(args.rootfs, rel)
        if os.path.isdir(d):
            for dirpath, _dirs, files in os.walk(d):
                for f in files:
                    targets.append(os.path.join(dirpath, f))
    found = {}
    for path in targets:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        for m in SERVICE_RE.finditer(text):
            svc = m.group(1).lower()
            found.setdefault(svc, set()).add(os.path.relpath(path, args.rootfs))
    inetd = os.path.join(args.rootfs, "etc/inetd.conf")
    if os.path.isfile(inetd):
        found.setdefault("(inetd.conf present)", set()).add("etc/inetd.conf")

    if not found:
        print("[!] no recognizable network services referenced in init scripts")
        return 0
    print(f"[+] network-facing services referenced in {args.rootfs}:\n")
    for svc in sorted(found):
        locs = ", ".join(sorted(found[svc])[:4])
        print(f"    {svc:<16} -> {locs}")
    return 0


def main():
    p = argparse.ArgumentParser(description="QEMU firmware-emulation prep helper")
    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("inspect", help="detect arch/endianness + suggest qemu")
    i.add_argument("--rootfs", required=True, help="path to extracted root filesystem")
    i.set_defaults(func=cmd_inspect)

    s = sub.add_parser("services", help="enumerate network-facing init services")
    s.add_argument("--rootfs", required=True)
    s.set_defaults(func=cmd_services)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
