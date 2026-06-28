#!/usr/bin/env python3
# For authorized smart-contract testing only. Fuzz contracts you own or are
# explicitly permitted to assess; never aim a discovered counterexample at a
# live contract or other people's funds.
"""Echidna fuzzing helper.

Two stdlib-only modes:
  suggest  - Parse a Solidity source file, list public/external state-changing
             functions (the fuzz entry points), and suggest candidate invariants
             based on common token/vault patterns.
  coverage - Summarize an Echidna coverage corpus directory: count lines that
             were reached vs. reverted and report an approximate coverage %.

No external dependencies are required.
"""
import argparse
import glob
import os
import re
import sys

# Solidity function declaration: function name(...) <modifiers> [returns(...)]
FUNC_RE = re.compile(
    r"function\s+(\w+)\s*\(([^)]*)\)\s*([^{;]*)", re.MULTILINE)

VIEW_KEYWORDS = ("view", "pure", "constant")

# Heuristic invariant suggestions keyed by function-name fragments.
INVARIANT_HINTS = [
    (("deposit", "withdraw", "redeem"),
     "solvency: contract balance >= total tracked deposits"),
    (("mint", "burn", "transfer"),
     "conservation: sum(balances) == totalSupply"),
    (("stake", "unstake", "claim"),
     "no-free-money: rewards out <= rewards accrued"),
    (("rebase", "index", "accrue"),
     "monotonicity: index only increases"),
    (("setfee", "setowner", "pause", "setadmin", "blacklist"),
     "access: only authorized role mutates privileged state"),
    (("swap", "addliquidity", "removeliquidity"),
     "AMM invariant: k (x*y) does not decrease except by fees"),
]


def read_source(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def strip_comments(src):
    src = re.sub(r"//[^\n]*", "", src)
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)
    return src


def find_mutating_functions(src):
    """Return list of (name, params, qualifiers) for public/external,
    non-view, non-pure functions."""
    out = []
    for m in FUNC_RE.finditer(src):
        name, params, quals = m.group(1), m.group(2).strip(), m.group(3)
        ql = quals.lower()
        is_visible = ("public" in ql) or ("external" in ql)
        is_view = any(k in ql for k in VIEW_KEYWORDS)
        if is_visible and not is_view:
            out.append((name, params, quals.strip()))
    return out


def suggest_invariants(func_names):
    suggestions = set()
    lowered = [n.lower() for n in func_names]
    for fragments, hint in INVARIANT_HINTS:
        if any(frag in n for n in lowered for frag in fragments):
            suggestions.add(hint)
    if not suggestions:
        suggestions.add("define a safety property: a state the contract must never reach")
    return sorted(suggestions)


def cmd_suggest(args):
    if not os.path.isfile(args.source):
        print(f"[!] no such file: {args.source}", file=sys.stderr)
        return 1
    src = strip_comments(read_source(args.source))
    funcs = find_mutating_functions(src)
    if not funcs:
        print("[!] no public/external state-changing functions found", file=sys.stderr)
        return 1
    print(f"[+] {len(funcs)} state-changing entry point(s) (fuzz surface):\n")
    for name, params, quals in funcs:
        print(f"    function {name}({params})  [{quals}]")
    print("\n[+] candidate invariants to encode as echidna_* / invariant_*:\n")
    for s in suggest_invariants([f[0] for f in funcs]):
        print(f"    - {s}")
    payable = [f for f in funcs if "payable" in f[2].lower()]
    if payable:
        print(f"\n[!] {len(payable)} payable function(s) — add a solvency invariant on ETH balance:")
        for f in payable:
            print(f"      {f[0]}")
    return 0


def summarize_corpus(corpus_dir):
    """Parse Echidna covered.*.txt files. Each source line is annotated:
       '*' reached, 'r' reverted, 'e' threw, ' ' not reached."""
    files = glob.glob(os.path.join(corpus_dir, "**", "covered.*.txt"), recursive=True)
    files += glob.glob(os.path.join(corpus_dir, "covered.*.txt"))
    files = sorted(set(files))
    if not files:
        return None
    reached = reverted = errored = total = 0
    for path in files:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.strip():
                    continue
                marker = line[0]
                total += 1
                if marker == "*":
                    reached += 1
                elif marker == "r":
                    reverted += 1
                elif marker == "e":
                    errored += 1
    return {"files": len(files), "total": total, "reached": reached,
            "reverted": reverted, "errored": errored}


def cmd_coverage(args):
    stats = summarize_corpus(args.corpus)
    if stats is None:
        print(f"[!] no covered.*.txt files under {args.corpus}", file=sys.stderr)
        return 1
    total = max(stats["total"], 1)
    pct = 100.0 * (stats["reached"] + stats["reverted"] + stats["errored"]) / total
    print(f"[+] corpus files       : {stats['files']}")
    print(f"[+] annotated lines    : {stats['total']}")
    print(f"[+] reached (*)        : {stats['reached']}")
    print(f"[+] reverted (r)       : {stats['reverted']}")
    print(f"[+] errored (e)        : {stats['errored']}")
    print(f"[+] approx. coverage   : {pct:.1f}%")
    if pct < 70:
        print("[!] low coverage — invariants or guards may leave branches unreached")
    return 0


def main():
    p = argparse.ArgumentParser(description="Echidna fuzzing helper (suggest invariants / summarize coverage)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("suggest", help="list fuzz entry points and suggest invariants")
    s.add_argument("--source", required=True, help="path to Solidity source file")
    s.set_defaults(func=cmd_suggest)

    c = sub.add_parser("coverage", help="summarize an Echidna coverage corpus")
    c.add_argument("--corpus", required=True, help="path to corpus directory")
    c.set_defaults(func=cmd_coverage)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
