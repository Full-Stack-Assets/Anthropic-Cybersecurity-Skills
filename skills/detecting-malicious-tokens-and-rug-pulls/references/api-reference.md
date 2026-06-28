# Malicious-Token Triage — Tool & CLI Reference

## CLI Tools

| Tool | Install | Purpose |
|------|---------|---------|
| foundry (forge/cast) | `curl -L https://foundry.paradigm.xyz | bash && foundryup` | On-chain reads + buy/sell honeypot simulation |
| cast | bundled with Foundry | Read owner(), totalSupply(), balanceOf(), paused() |
| slither-analyzer | `pip install slither-analyzer` | Deeper source review of privileged functions |

## Useful cast Reads

| Command | Purpose |
|---------|---------|
| `cast call <TOKEN> "owner()(address)"` | Check ownership (0x0 = renounced) |
| `cast call <TOKEN> "totalSupply()(uint256)"` | Total supply |
| `cast call <TOKEN> "balanceOf(address)(uint256)" <ADDR>` | Holder concentration |
| `cast call <TOKEN> "paused()(bool)"` | Pausable-transfer trap |
| `cast call <LP> "balanceOf(address)(uint256)" <DEAD>` | Liquidity burned/locked check |

## Red-Flag Selectors / Patterns

| Selector / pattern | Concern |
|--------------------|---------|
| `mint(` | Hidden supply inflation |
| `setFee(` / `setTaxes(` / `setTax(` | Uncapped fee trap |
| `blacklist(` / `addBot(` / `setBlacklist(` | Per-address sell blocking |
| `pause(` / `unpause(` / `enableTrading(` | Owner can freeze sells |
| `setMaxTx(` / `setMaxWallet(` | Throttle/limit sells |
| `excludeFromFee(` | Owner-only fee exemption asymmetry |
| `withdraw(` / `rescue(` / `drain(` | Owner-only fund extraction |
| `onlyOwner` on `_transfer`/hooks | Conditional sell blocking |
| proxy `upgradeTo(` / `_implementation` | Swap-in malicious logic |

## Risk Scoring Weights (companion script)

| Signal | Default weight |
|--------|----------------|
| Hidden mint + owner retained | high |
| Sell-blocking hook / blacklist | high |
| Uncapped fee setter | high |
| Owner not renounced | medium |
| Pausable transfers | medium |
| Proxy upgradeable | medium |
| Owner-only withdraw/drain | medium |

## Companion Script CLI (`scripts/agent.py`)

| Command | Args | Purpose |
|---------|------|---------|
| `scan` | `--source <Token.sol>` or `--abi <abi.json>` `[--output report.json]` | Detect rug-pull traits and emit a weighted risk score + verdict |

```bash
python3 scripts/agent.py scan --source Token.sol
python3 scripts/agent.py scan --abi token_abi.json --output report.json
```

## External References

- OpenZeppelin ERC-20: https://docs.openzeppelin.com/contracts/api/token/erc20
- Foundry Book: https://book.getfoundry.sh/
- EIP-20: https://eips.ethereum.org/EIPS/eip-20
