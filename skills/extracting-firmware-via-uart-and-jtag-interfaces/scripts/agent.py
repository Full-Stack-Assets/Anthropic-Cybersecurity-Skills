#!/usr/bin/env python3
# For authorized hardware security testing of devices you own or are permitted to test.
# Probing UART/JTAG, opening hardware, or reading firmware without authorization may
# violate the DMCA, vendor terms, and warranty, and can damage the device.
"""UART/JTAG firmware-extraction helper.

Subcommands (all stdlib except `console`, which needs pyserial):
  baud     Estimate the nearest standard baud rate from a measured shortest
           pulse (one bit time) seen on a logic analyzer.
  pinout   Rank a 4-pad header into GND / VCC / TX / RX from DC voltage notes.
  console  Minimal serial reader to capture a boot log (requires pyserial).
"""
import argparse
import sys

STANDARD_BAUDS = [
    300, 1200, 2400, 4800, 9600, 19200, 38400, 57600,
    115200, 230400, 460800, 500000, 576000, 921600, 1000000, 1500000,
]


def nearest_baud(bit_time_s):
    """Return (baud, candidate_table) for a measured bit time in seconds."""
    if bit_time_s <= 0:
        raise ValueError("bit time must be positive")
    measured = 1.0 / bit_time_s
    ranked = sorted(STANDARD_BAUDS, key=lambda b: abs(b - measured))
    return measured, ranked


def cmd_baud(args):
    if args.bit_time_s is not None:
        bit_time = args.bit_time_s
    elif args.pulse_us is not None:
        bit_time = args.pulse_us * 1e-6
    else:
        print("[!] provide --pulse-us or --bit-time-s", file=sys.stderr)
        return 1
    measured, ranked = nearest_baud(bit_time)
    best = ranked[0]
    err = abs(best - measured) / best * 100.0
    print(f"[+] measured bit time : {bit_time*1e6:.3f} us")
    print(f"[+] raw baud estimate : {measured:,.0f}")
    print(f"[+] nearest standard  : {best:,} baud  ({err:.1f}% off)")
    print(f"[+] try, in order     : {', '.join(str(b) for b in ranked[:4])}")
    return 0


def parse_pads(spec):
    pads = {}
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        name, _, val = item.partition("=")
        pads[name.strip()] = float(val)
    return pads


def rank_pinout(pads, vcc_nominal):
    """Heuristic scoring of which pad is GND/VCC/TX/RX from steady DC volts.

    Heuristics:
      GND ~ 0 V; VCC ~ nominal and steady; TX idles just under VCC (driven high
      but dips during traffic, so an averaged meter reads slightly below VCC);
      RX floats around mid-rail.
    """
    results = {}
    for name, v in pads.items():
        scores = {
            "GND": max(0.0, 1.0 - abs(v - 0.0) / 0.5),
            "VCC": max(0.0, 1.0 - abs(v - vcc_nominal) / 0.15),
            "TX": max(0.0, 1.0 - abs(v - (vcc_nominal * 0.88)) / 0.4),
            "RX": max(0.0, 1.0 - abs(v - (vcc_nominal * 0.55)) / 0.6),
        }
        best = max(scores, key=scores.get)
        results[name] = (v, best, scores[best])
    return results


def cmd_pinout(args):
    pads = parse_pads(args.pads)
    if not pads:
        print("[!] no pads parsed; use --pads 'p1=0.0,p2=3.3,...'", file=sys.stderr)
        return 1
    ranked = rank_pinout(pads, args.voltage)
    print(f"[+] nominal logic voltage: {args.voltage} V\n")
    print(f"{'pad':<8}{'volts':<10}{'best guess':<12}{'confidence'}")
    print("-" * 42)
    for name, (v, guess, conf) in ranked.items():
        print(f"{name:<8}{v:<10.2f}{guess:<12}{conf:.2f}")
    print("\n[i] cross-wire adapter RX<->device TX, GND<->GND; leave VCC disconnected.")
    return 0


def cmd_console(args):
    try:
        import serial  # type: ignore
    except ImportError:
        print("[!] install: pip install pyserial", file=sys.stderr)
        return 1
    try:
        ser = serial.Serial(args.port, args.baud, timeout=1)
    except Exception as exc:  # noqa: BLE001 - surface any serial error to the user
        print(f"[!] could not open {args.port}: {exc}", file=sys.stderr)
        return 1
    log = open(args.log, "ab") if args.log else None
    print(f"[+] reading {args.port} @ {args.baud} (Ctrl-C to stop)")
    try:
        while True:
            chunk = ser.read(256)
            if not chunk:
                continue
            sys.stdout.write(chunk.decode("utf-8", "replace"))
            sys.stdout.flush()
            if log:
                log.write(chunk)
                log.flush()
    except KeyboardInterrupt:
        print("\n[+] stopped")
    finally:
        ser.close()
        if log:
            log.close()
    return 0


def main():
    p = argparse.ArgumentParser(description="UART/JTAG firmware-extraction helper")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("baud", help="estimate baud from a measured bit time")
    b.add_argument("--pulse-us", type=float, help="shortest pulse width in microseconds")
    b.add_argument("--bit-time-s", type=float, help="bit time in seconds")
    b.set_defaults(func=cmd_baud)

    o = sub.add_parser("pinout", help="rank a 4-pad header from DC voltage notes")
    o.add_argument("--pads", required=True, help="e.g. 'p1=0.0,p2=3.3,p3=3.28,p4=1.9'")
    o.add_argument("--voltage", type=float, default=3.3, help="nominal logic voltage")
    o.set_defaults(func=cmd_pinout)

    c = sub.add_parser("console", help="capture a serial boot log (needs pyserial)")
    c.add_argument("--port", required=True, help="e.g. /dev/ttyUSB0")
    c.add_argument("--baud", type=int, default=115200)
    c.add_argument("--log", help="append raw bytes to this file")
    c.set_defaults(func=cmd_console)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
