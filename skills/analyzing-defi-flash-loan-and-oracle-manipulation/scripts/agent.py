#!/usr/bin/env python3
# For authorized DeFi security research only. Model these attacks against
# contracts you own, testnets, or forked state. Executing a flash-loan price
# manipulation against a live protocol to take other people's funds is theft.
"""Flash-loan / oracle-manipulation analysis helper.

Two stdlib-only modes:
  cost  - Given Uniswap-v2-style pool reserves, compute the input amount and
          capital cost required to move the pool's spot price by a target
          fraction, and the resulting price impact. Quantifies cost-to-manipulate.
  scan  - Scan a Solidity source file for manipulable spot-price dependence
          (getReserves/getAmountsOut/slot0/balanceOf-of-pool used for pricing)
          and for missing Chainlink staleness checks; emit a risk score.

No external dependencies are required.
"""
import argparse
import re
import os
import sys


def amount_in_for_target_price(reserve_base, reserve_quote, target_move, fee_bps):
    """For x*y=k, compute base-token input dx (with fee) that raises the spot
    price (quote/base after the trade in the opposite token) by target_move.

    We push price by buying `quote` with `base`: base reserve increases.
    New price ratio target: P_new = P_old * (1 + target_move).
    With fee f, effective input is dx*(1-f). Using k conservation:
        reserveBase_new = reserveBase + dx*(1-f)
        reserveQuote_new = k / reserveBase_new
        P = reserveBase_new / reserveQuote_new   (base per quote rises)
    Solve reserveBase_new = reserveBase * sqrt(1+target_move).
    """
    f = fee_bps / 10000.0
    import math
    factor = math.sqrt(1.0 + target_move)
    new_base_eff = reserve_base * factor
    dx_eff = new_base_eff - reserve_base
    if dx_eff <= 0:
        return None
    dx = dx_eff / (1.0 - f)
    return dx


def cmd_cost(args):
    rb, rq = args.reserve_base, args.reserve_quote
    if rb <= 0 or rq <= 0:
        print("[!] reserves must be positive", file=sys.stderr)
        return 1
    p_old = rq / rb
    dx = amount_in_for_target_price(rb, rq, args.target_move, args.fee_bps)
    if dx is None:
        print("[!] target move not achievable with given inputs", file=sys.stderr)
        return 1
    # approximate resulting price after the swap
    f = args.fee_bps / 10000.0
    k = rb * rq
    rb_new = rb + dx * (1.0 - f)
    rq_new = k / rb_new
    p_new = rq_new / rb_new
    impact = (p_new - p_old) / p_old
    print(f"[+] pool reserves        : base={rb:,.4f}  quote={rq:,.4f}")
    print(f"[+] spot price (q/b)     : {p_old:,.6f}")
    print(f"[+] target price move    : {args.target_move:+.1%}")
    print(f"[+] base input required  : {dx:,.4f} (gross, incl. {args.fee_bps} bps fee)")
    print(f"[+] price after swap     : {p_new:,.6f}  (impact {impact:+.2%})")
    note = ("LOW liquidity -> cheap to manipulate, HIGH risk for a spot oracle"
            if dx < rb else "deep relative to move; manipulation cost is significant")
    print(f"[+] cost-to-manipulate   : {note}")
    print("[i] a spot-price oracle reading these reserves is movable in ONE tx with this capital")
    return 0


SPOT_PATTERNS = {
    "getReserves(": "reads AMM reserves (spot, flash-loan movable)",
    "getAmountsOut": "uses current reserves for pricing (movable)",
    "getAmountOut": "uses current reserves for pricing (movable)",
    ".slot0(": "v3 spot tick (movable in one tx)",
    "balanceOf(": "pool balance ratio can be moved by swap/transfer",
}
TWAP_OK = ("consult(", "observe(", "TWAP", "twap", "Cumulative", "latestRoundData(")


def cmd_scan(args):
    if not os.path.isfile(args.source):
        print(f"[!] no such file: {args.source}", file=sys.stderr)
        return 1
    with open(args.source, "r", encoding="utf-8", errors="replace") as fh:
        src = fh.read()
    no_comments = re.sub(r"//[^\n]*", "", src)
    no_comments = re.sub(r"/\*.*?\*/", "", no_comments, flags=re.DOTALL)

    hits = []
    for pat, why in SPOT_PATTERNS.items():
        for m in re.finditer(re.escape(pat), no_comments):
            line = no_comments.count("\n", 0, m.start()) + 1
            hits.append((line, pat, why))

    uses_twap = any(t in no_comments for t in TWAP_OK)
    uses_chainlink = "latestRoundData(" in no_comments
    has_staleness = uses_chainlink and re.search(r"updatedAt|block\.timestamp\s*-", no_comments)

    score = 0
    print(f"[+] scanning {args.source}\n")
    if hits:
        print("[!] manipulable spot-price indicators:")
        for line, pat, why in sorted(hits):
            print(f"    line {line:<5} {pat:<16} -> {why}")
            score += 25
    else:
        print("[+] no obvious spot-price reads found")

    if uses_chainlink and not has_staleness:
        print("[!] Chainlink latestRoundData() used WITHOUT a staleness (updatedAt) check")
        score += 30
    if uses_twap:
        print("[+] TWAP / cumulative / aggregated price source detected (good)")
        score = max(0, score - 20)

    score = min(score, 100)
    risk = "HIGH" if score >= 60 else "MEDIUM" if score >= 25 else "LOW"
    print(f"\n[+] oracle-manipulation risk score: {score}/100 ({risk})")
    if score >= 25:
        print("[i] prefer TWAP / Chainlink aggregated feeds with staleness + deviation bounds")
    return 0


def main():
    p = argparse.ArgumentParser(
        description="Flash-loan / oracle-manipulation analysis (cost + source scan)")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("cost", help="compute cost-to-manipulate a v2 pool's spot price")
    c.add_argument("--reserve-base", type=float, required=True)
    c.add_argument("--reserve-quote", type=float, required=True)
    c.add_argument("--target-move", type=float, default=0.5, help="fractional price move, e.g. 0.5 = +50%%")
    c.add_argument("--fee-bps", type=float, default=30, help="swap fee in basis points (30 = 0.3%%)")
    c.set_defaults(func=cmd_cost)

    s = sub.add_parser("scan", help="flag spot-price dependence in Solidity source")
    s.add_argument("--source", required=True)
    s.set_defaults(func=cmd_scan)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
