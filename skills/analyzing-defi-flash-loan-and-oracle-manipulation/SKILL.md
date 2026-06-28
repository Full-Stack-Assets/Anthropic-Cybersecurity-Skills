---
name: analyzing-defi-flash-loan-and-oracle-manipulation
description: Analyze and defend against DeFi economic attacks where flash-loan capital manipulates an AMM spot-price oracle, including computing cost-to-manipulate, comparing spot vs TWAP pricing, and hardening protocols with manipulation-resistant oracles.
domain: cybersecurity
subdomain: blockchain-security
tags:
- blockchain
- defi
- flash-loan
- oracle-manipulation
- amm
- twap
- chainlink
- mev
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.RA-01
- PR.DS-01
- DE.CM-01
- DE.AE-02
mitre_attack:
- T1190
- T1657
- T1059
---
# Analyzing DeFi Flash-Loan and Oracle Manipulation

> **Authorized Use Only:** Model and simulate these attacks only against contracts you own, testnets, or forked state for research and defense. Executing a flash-loan price-manipulation attack against a live protocol to extract other people's funds is theft. Use this skill to find and fix the weakness, not to exploit it.

## Overview

A flash loan lets anyone borrow an enormous, uncollateralized amount within a single transaction, provided it is repaid before the transaction ends. On its own this is benign — it democratizes capital for arbitrage. The danger appears when a protocol prices an asset by reading the **spot price** of an on-chain Automated Market Maker (AMM) such as a Uniswap v2 pair. Because an AMM's price is just the ratio of its reserves (`price = reserveQuote / reserveBase`), a single large swap moves it, and a flash loan provides the capital to move it dramatically and atomically. The classic attack: borrow via flash loan, swap to skew an AMM's reserves, call a victim contract that reads that skewed spot price (e.g., to value collateral or mint shares), profit from the mispricing, then unwind and repay — all atomically so there is no inter-block risk. This is financially driven theft, mapping to MITRE ATT&CK **T1657 (Financial Theft)**, executed by exploiting a public-facing contract (**T1190**) through scripted transactions (**T1059**).

The root cause is almost never the flash loan itself; it is using a **manipulable, instantaneous price source**. Spot price from a single AMM pool is trivially moved within one transaction, so any protocol that trusts it for valuation is exposed in proportion to how cheaply the pool can be skewed — a function of its liquidity depth and fee. The cost to manipulate a constant-product pool by a target percentage is computable from the reserves and the swap fee, and comparing that cost to the value a manipulated price unlocks tells you whether the attack is profitable. Defenders quantify this gap.

The defense is **manipulation-resistant pricing**: use a time-weighted average price (TWAP) accumulator (Uniswap v2/v3 cumulative price oracles) so an attacker must hold a skewed price across many blocks (expensive and arbitrage-exposed), use a decentralized oracle network like Chainlink that aggregates off-chain market prices, prefer deep-liquidity references, and validate prices against bounds. This skill covers reading AMM reserves to compute price impact and cost-to-manipulate, identifying contracts that read spot price, simulating a flash-loan manipulation on a fork, and verifying TWAP/Chainlink-based hardening. Related MEV context — sandwiching and back-running — is covered as the broader transaction-ordering threat surface in which these attacks live.

## When to Use

- When auditing a protocol that derives prices, collateral values, or mint/redeem rates from on-chain sources.
- When you find a contract reading `getReserves()`, `getAmountOut`, `balanceOf` of a pool, or a single-pool `slot0`/spot price for valuation.
- When estimating the economic feasibility of a flash-loan attack (cost-to-manipulate vs. profit).
- When validating that a switch to TWAP or Chainlink actually closes the manipulation gap.
- When investigating a suspected price-manipulation incident on a fork of the affected block.
- When reviewing new AMM integrations for spot-price dependence.

## Prerequisites

- Foundry for fork simulation:
  ```bash
  curl -L https://foundry.paradigm.xyz | bash && foundryup
  ```
- An archive RPC endpoint to fork mainnet/L2 state at a specific block (`anvil --fork-url <RPC> --fork-block-number <N>`).
- Slither for spotting spot-price reads:
  ```bash
  pip install slither-analyzer
  ```
- Python 3.9+ for the cost-to-manipulate calculator (companion script, stdlib only).
- Authorization to assess the target protocol.

## Objectives

- Read AMM reserves and compute the price impact and capital cost of moving a pool's price.
- Compare a spot-price oracle's manipulability against a TWAP / deep-liquidity baseline.
- Identify victim contracts that consume manipulable spot prices.
- Simulate a flash-loan manipulation against a forked deployment.
- Verify TWAP/Chainlink hardening and price-bound checks remove the profit.
- Document the cost-to-manipulate vs. value-at-risk for the protocol.

## MITRE ATT&CK Mapping

| ID | Name | Tactic | Where it shows up |
|----|------|--------|-------------------|
| T1190 | Exploit Public-Facing Application | Initial Access | The vulnerable pricing contract is a public-facing app the attacker calls. |
| T1657 | Financial Theft | Impact | Mispriced valuation lets the attacker extract funds — the objective of the attack. |
| T1059 | Command and Scripting Interpreter | Execution | Borrow/swap/exploit/repay is one scripted atomic transaction. |

## Workflow

### 1. Read reserves and compute price impact
For a Uniswap v2-style constant-product pool, price is `reserveQuote/reserveBase`. A swap of `dx` (after fee) moves reserves per `x*y=k`. Compute how much input is needed to push the price by a target percentage.

```bash
# read live reserves from a forked pair
cast call <PAIR_ADDR> "getReserves()(uint112,uint112,uint32)" --rpc-url http://127.0.0.1:8545
# compute cost-to-manipulate with the companion script:
python3 scripts/agent.py cost --reserve-base 1500 --reserve-quote 3000000 \
  --target-move 0.5 --fee-bps 30
```

### 2. Compare spot vs TWAP / deep-liquidity baseline
A spot price is the instantaneous reserve ratio; a TWAP integrates price over time, so a one-block skew barely moves it. Estimate the manipulation cost against each to size the risk gap.

```text
spot oracle      : moving price +50% costs ~X (one transaction)  -> HIGH risk
twap (30 min)    : attacker must sustain skew ~150 blocks         -> cost x150, arb-exposed
deep pool / CL   : aggregates external markets                    -> not movable by one pool
```

### 3. Find contracts that read a manipulable spot price
Scan source for the tell-tale spot-price reads used for valuation. Reading reserves or `getAmountOut` for *pricing* (not just swapping) is the red flag.

```bash
slither src/ --print human-summary
# heuristic source scan for spot-price dependence:
python3 scripts/agent.py scan --source src/LendingPool.sol
# grep-style indicators: getReserves(), getAmountsOut(), slot0(), balanceOf(pool)
```

### 4. Simulate a flash-loan manipulation on a fork
Write a Foundry test that forks the affected block, takes a flash loan (e.g., from a pool that offers them), skews the AMM, calls the victim, and checks profit. This proves exploitability and is the regression test for the fix.

```solidity
// test/FlashManip.t.sol  (run: forge test --fork-url $RPC -vvv)
function test_manipulate() public {
    uint256 before = token.balanceOf(address(this));
    pool.flashLoan(BORROW, "");        // callback skews AMM + calls victim
    assertGt(token.balanceOf(address(this)), before, "no profit => not exploitable");
}
```

### 5. Harden with manipulation-resistant pricing
Replace spot reads with a TWAP accumulator or a Chainlink price feed, add staleness and bounds checks, and prefer the deepest liquidity reference.

```solidity
// Chainlink: reject stale / out-of-bounds prices
(, int256 answer,, uint256 updatedAt,) = feed.latestRoundData();
require(answer > 0, "bad price");
require(block.timestamp - updatedAt <= MAX_DELAY, "stale price");
// Uniswap v3 TWAP example: consult the pool over a window
(int24 meanTick, ) = OracleLibrary.consult(poolV3, 1800 /*sec*/);
uint256 price = OracleLibrary.getQuoteAtTick(meanTick, 1e18, base, quote);
```

### 6. Re-simulate and document the gap
Re-run the fork test against the hardened contract; the profit assertion should now fail (attack unprofitable). Record cost-to-manipulate vs. value-at-risk for the report.

```bash
forge test --match-test test_manipulate --fork-url $RPC -vvv  # expect: revert / no profit
```

## Tools and Resources

| Resource | Link |
|----------|------|
| Foundry Book (fork testing) | https://book.getfoundry.sh/forge/fork-testing |
| Uniswap v2 — Oracles (TWAP) | https://docs.uniswap.org/contracts/v2/concepts/core-concepts/oracles |
| Uniswap v3 — Oracle / OracleLibrary | https://docs.uniswap.org/contracts/v3/reference/core/libraries/Oracle |
| Chainlink Price Feeds | https://docs.chain.link/data-feeds |
| ConsenSys Diligence — Oracle Manipulation | https://consensys.io/diligence/ |
| samczsun — "So you want to use a price oracle" | https://samczsun.com/so-you-want-to-use-a-price-oracle/ |
| SWC Registry | https://swcregistry.io/ |

## Oracle Risk Cheat-Sheet

| Price source | Manipulable in one tx? | Defense posture |
|--------------|------------------------|-----------------|
| Single-pool spot (`getReserves`) | Yes — trivial with flash loan | Avoid for valuation |
| `getAmountsOut` on shallow pool | Yes | Avoid; depth-dependent |
| Uniswap v2/v3 TWAP | No (must sustain across blocks) | Acceptable with adequate window |
| Chainlink aggregated feed | No (off-chain aggregation) | Add staleness + deviation checks |
| Spot bounded vs TWAP | Mitigated | Reject if spot deviates > X% from TWAP |

## Validation Criteria

- [ ] Pool reserves read and cost-to-manipulate computed for the target move.
- [ ] Spot vs TWAP/deep-liquidity manipulability compared and the risk gap quantified.
- [ ] All contracts reading a manipulable spot price for valuation identified.
- [ ] Flash-loan manipulation reproduced on a fork (profit demonstrated).
- [ ] Oracle hardened with TWAP/Chainlink plus staleness and bounds checks.
- [ ] Hardened contract re-simulated; attack now unprofitable.
- [ ] Cost-to-manipulate vs. value-at-risk documented in the report.
- [ ] MEV/sandwich exposure of the integration noted where relevant.
