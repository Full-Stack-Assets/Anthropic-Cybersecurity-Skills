#!/usr/bin/env python3
# For authorized RF security assessment of devices and spectrum you own or are
# permitted in writing to test. Receiving across the spectrum and especially
# transmitting (including replaying a captured signal) are tightly regulated;
# never transmit on licensed/shared spectrum without authorization and a license.
"""SDR signal-analysis helper.

Two modes:
  peaks  - Parse an rtl_power CSV sweep, aggregate power per frequency bin, and
           rank the most active peaks / bands of interest. Pure stdlib.
  replay - Compare decoded frames across multiple device transmissions and
           classify fixed-code (replayable) vs rolling-code behaviour.

rtl_power CSV row format:
  date, time, Hz_low, Hz_high, Hz_step, samples, dB, dB, dB, ...
Frames file: one decoded frame per line (hex or bit string), in capture order.
"""
import argparse
import collections
import csv
import json
import sys


def parse_rtl_power(path):
    """Return dict: center_freq_hz -> list of dB readings."""
    bins = collections.defaultdict(list)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for cols in csv.reader(fh):
            if len(cols) < 7:
                continue
            try:
                hz_low = float(cols[2])
                hz_step = float(cols[4])
                dbs = [float(x) for x in cols[6:] if x.strip()]
            except ValueError:
                continue
            for i, db in enumerate(dbs):
                freq = hz_low + i * hz_step
                bins[round(freq)].append(db)
    return bins


def rank_peaks(bins, threshold, top):
    rows = []
    for freq, dbs in bins.items():
        if not dbs:
            continue
        peak = max(dbs)
        mean = sum(dbs) / len(dbs)
        if threshold is not None and peak < threshold:
            continue
        rows.append({
            "freq_hz": freq,
            "freq_mhz": round(freq / 1e6, 4),
            "peak_db": round(peak, 1),
            "mean_db": round(mean, 1),
            "activity_db": round(peak - mean, 1),  # burstiness above its own floor
            "samples": len(dbs),
        })
    # rank by peak power, then by burstiness
    rows.sort(key=lambda r: (r["peak_db"], r["activity_db"]), reverse=True)
    return rows[:top]


def cmd_peaks(args):
    bins = parse_rtl_power(args.csv)
    if not bins:
        print("[!] no usable rows parsed from", args.csv, file=sys.stderr)
        return 1
    peaks = rank_peaks(bins, args.threshold, args.top)
    print(f"[+] {len(bins)} frequency bins; top {len(peaks)} active peaks"
          + (f" (>= {args.threshold} dB)" if args.threshold is not None else ""))
    print(f"{'MHz':>12}  {'peak dB':>8}  {'mean dB':>8}  {'activity':>8}")
    for r in peaks:
        print(f"{r['freq_mhz']:>12}  {r['peak_db']:>8}  {r['mean_db']:>8}  {r['activity_db']:>8}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(peaks, fh, indent=2)
        print(f"[+] written to {args.json}")
    return 0


def cmd_replay(args):
    frames = []
    with open(args.frames, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            f = line.strip().replace(" ", "")
            if f and not f.startswith("#"):
                frames.append(f)
    if len(frames) < 2:
        print("[!] need >= 2 frames to compare", file=sys.stderr)
        return 1
    distinct = set(frames)
    n, d = len(frames), len(distinct)
    if d == 1:
        verdict, risk = "FIXED_CODE", "HIGH"
        note = "Identical payload every transmission => trivially replayable."
    elif d == n:
        verdict, risk = "ROLLING_OR_ENCRYPTED", "LOW"
        note = "Every transmission differs => rolling/encrypted (verify against RollJam)."
    else:
        verdict, risk = "PARTIAL/WEAK_ROLLING", "MEDIUM"
        note = (f"{d} distinct of {n} frames => repeats/short counter; "
                "weak rolling, add crypto/auth.")
    # detect simple incrementing counter (monotone hex)
    counterish = False
    try:
        vals = [int(f, 16) for f in frames]
        diffs = {vals[i + 1] - vals[i] for i in range(len(vals) - 1)}
        if len(diffs) == 1 and diffs.pop() not in (0,):
            counterish = True
    except ValueError:
        pass
    print(f"[+] frames analysed   : {n} ({d} distinct)")
    print(f"[+] verdict           : {verdict}")
    print(f"[+] replay risk       : {risk}")
    if counterish:
        print("[+] note              : constant-step counter detected (predictable rolling)")
    print(f"[+] {note}")
    return 0


def main():
    p = argparse.ArgumentParser(description="SDR signal-analysis helper")
    sub = p.add_subparsers(dest="cmd", required=True)

    pk = sub.add_parser("peaks", help="rank active peaks from an rtl_power CSV")
    pk.add_argument("--csv", required=True, help="rtl_power CSV sweep")
    pk.add_argument("--top", type=int, default=15)
    pk.add_argument("--threshold", type=float, help="minimum peak dB to include")
    pk.add_argument("--json", help="write ranked peaks JSON")
    pk.set_defaults(func=cmd_peaks)

    rp = sub.add_parser("replay", help="classify fixed vs rolling code from frames")
    rp.add_argument("--frames", required=True, help="decoded frames, one per line")
    rp.set_defaults(func=cmd_replay)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
