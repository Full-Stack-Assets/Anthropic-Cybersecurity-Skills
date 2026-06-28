#!/usr/bin/env python3
# For assessing the resilience of LLM services you own or are authorized to test.
# Flooding a third-party model with expensive requests is an attack, not a test.
"""Unbounded-consumption (OWASP LLM10) usage-log analyzer.

Aggregates an LLM usage log per principal, converts tokens to cost, and flags
denial-of-wallet / denial-of-service patterns (MITRE ATLAS AML.T0034 / T0029).
Pure Python stdlib — no external dependencies.

Usage log format (JSONL, one object per line):
  {"ts": 1700000000.0, "principal": "key-123",
   "prompt_tokens": 1200, "completion_tokens": 800}
"""
import argparse
import collections
import json
import statistics
import sys


def load_log(path):
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for ln, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                print(f"[!] skip malformed line {ln}: {exc}", file=sys.stderr)
    return rows


def aggregate(rows, price_in, price_out):
    agg = collections.defaultdict(
        lambda: {"requests": 0, "in_tok": 0, "out_tok": 0})
    for r in rows:
        p = agg[r.get("principal", "unknown")]
        p["requests"] += 1
        p["in_tok"] += int(r.get("prompt_tokens", 0))
        p["out_tok"] += int(r.get("completion_tokens", 0))
    for p in agg.values():
        p["cost"] = round(p["in_tok"] * price_in + p["out_tok"] * price_out, 4)
        p["mean_out"] = round(p["out_tok"] / p["requests"], 1) if p["requests"] else 0
    return agg


def analyze(agg, max_cost, anomaly_factor):
    costs = [p["cost"] for p in agg.values()]
    median_cost = statistics.median(costs) if costs else 0.0
    findings = []
    for principal, p in agg.items():
        reasons = []
        if max_cost is not None and p["cost"] > max_cost:
            reasons.append(f"cost ${p['cost']} > ceiling ${max_cost}")
        if median_cost > 0 and p["cost"] > anomaly_factor * median_cost:
            reasons.append(f"cost {p['cost']/median_cost:.1f}x cohort median")
        findings.append({
            "principal": principal,
            "requests": p["requests"],
            "in_tokens": p["in_tok"],
            "out_tokens": p["out_tok"],
            "mean_out": p["mean_out"],
            "cost": p["cost"],
            "flagged": bool(reasons),
            "reasons": reasons,
        })
    return sorted(findings, key=lambda f: (-f["flagged"], -f["cost"])), median_cost


def cmd_analyze(args):
    rows = load_log(args.log)
    if not rows:
        print("[!] no usable rows in log", file=sys.stderr)
        return 1
    agg = aggregate(rows, args.price_in / 1000.0, args.price_out / 1000.0)
    findings, median_cost = analyze(agg, args.max_cost, args.anomaly_factor)
    flagged = [f for f in findings if f["flagged"]]

    print(f"[+] {len(rows)} requests across {len(findings)} principals")
    print(f"[+] cohort median cost: ${median_cost:.4f}")
    print(f"[+] {len(flagged)} principal(s) flagged (DoW/DoS pattern)\n")
    print(f"{'':7}{'PRINCIPAL':<24}{'REQ':<7}{'OUT_TOK':<10}{'MEAN_OUT':<10}COST($)")
    for f in findings:
        mark = "[ALERT]" if f["flagged"] else "       "
        print(f"{mark}{f['principal']:<24}{f['requests']:<7}"
              f"{f['out_tokens']:<10}{f['mean_out']:<10}{f['cost']}")
        for reason in f["reasons"]:
            print(f"         -> {reason}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2)
        print(f"\n[+] findings written to {args.output}")
    return 0


def main():
    p = argparse.ArgumentParser(
        description="OWASP LLM10 unbounded-consumption usage-log analyzer")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="aggregate per-principal cost and flag anomalies")
    a.add_argument("--log", required=True, help="path to JSONL usage log")
    a.add_argument("--price-in", type=float, default=0.003,
                   help="$ per 1K input tokens (default 0.003)")
    a.add_argument("--price-out", type=float, default=0.015,
                   help="$ per 1K output tokens (default 0.015)")
    a.add_argument("--max-cost", type=float, default=None,
                   help="per-principal cost ceiling that triggers an alert")
    a.add_argument("--anomaly-factor", type=float, default=5.0,
                   help="flag principals above N x cohort median cost")
    a.add_argument("--output", help="write findings JSON")
    a.set_defaults(func=cmd_analyze)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
