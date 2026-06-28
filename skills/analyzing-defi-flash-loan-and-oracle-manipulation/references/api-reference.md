# DeFi Flash-Loan / Oracle Analysis — Tool & CLI Reference

## CLI Tools

| Tool | Install | Purpose |
|------|---------|---------|
| foundry (forge/cast/anvil) | `curl -L https://foundry.paradigm.xyz | bash && foundryup` | Fork simulation, reserve reads, exploit PoC tests |
| slither-analyzer | `pip install slither-analyzer` | Static detection of spot-price dependence |
| cast | bundled with Foundry | Read on-chain state (`getReserves`, `latestRoundData`) |
| anvil | bundled with Foundry | Local fork of mainnet/L2 at a block |

## Key Foundry / cast Commands

| Command | Purpose |
|---------|---------|
| `anvil --fork-url <RPC> --fork-block-number <N>` | Fork chain state at a block |
| `cast call <PAIR> "getReserves()(uint112,uint112,uint32)"` | Read AMM reserves |
| `cast call <FEED> "latestRoundData()(uint80,int256,uint256,uint256,uint80)"` | Read Chainlink feed |
| `forge test --fork-url <RPC> -vvv` | Run fork-based exploit/regression tests |
| `forge test --match-test <name>` | Run a single PoC test |

## Constant-Product Math (Uniswap v2)

| Quantity | Formula |
|----------|---------|
| Spot price | `P = reserveQuote / reserveBase` |
| Invariant | `k = reserveBase * reserveQuote` |
| Output for input `dx` (fee `f`) | `dy = (reserveQuote * dx * (1-f)) / (reserveBase + dx * (1-f))` |
| Price impact | `(P_after - P_before) / P_before` |

## Spot-Price Dependence Indicators (source scan)

| Pattern | Why it is risky |
|---------|-----------------|
| `getReserves()` used for valuation | Instantaneous, flash-loan movable |
| `getAmountsOut` / `getAmountOut` for pricing | Depends on current (movable) reserves |
| `slot0()` / single-pool tick for price | v3 spot, movable in one tx |
| `token.balanceOf(pool)` ratios | Manipulable by direct transfer/swap |
| Missing `updatedAt` staleness check on a feed | Stale or manipulated feed accepted |

## Companion Script CLI (`scripts/agent.py`)

| Command | Args | Purpose |
|---------|------|---------|
| `cost` | `--reserve-base --reserve-quote --target-move --fee-bps` | Compute capital cost to move a v2 pool's price by a target fraction |
| `scan` | `--source <Contract.sol>` | Flag spot-price-dependence and missing-staleness patterns; emit a risk note |

```bash
python3 scripts/agent.py cost --reserve-base 1500 --reserve-quote 3000000 --target-move 0.5 --fee-bps 30
python3 scripts/agent.py scan --source src/LendingPool.sol
```

## External References

- Chainlink Data Feeds: https://docs.chain.link/data-feeds
- Uniswap docs: https://docs.uniswap.org/
- samczsun price oracle guide: https://samczsun.com/so-you-want-to-use-a-price-oracle/
