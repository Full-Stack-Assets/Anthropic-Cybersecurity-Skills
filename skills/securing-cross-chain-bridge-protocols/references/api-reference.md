# Cross-Chain Bridge Security — Tool & CLI Reference

## CLI Tools

| Tool | Install | Purpose |
|------|---------|---------|
| foundry (forge/cast) | `curl -L https://foundry.paradigm.xyz | bash && foundryup` | Contract tests, signature reproduction, state reads |
| slither-analyzer | `pip install slither-analyzer` | Static review of verification / access-control code |
| cast | bundled with Foundry | Read validator sets, processed-message maps, balances |

## Slither Printers Useful for Bridges

| Command | Purpose |
|---------|---------|
| `slither <file> --print human-summary` | Overview of contracts, functions, issues |
| `slither <file> --print modifiers` | Enumerate access-control modifiers (onlyOwner/onlyAdmin) |
| `slither <file> --print function-summary` | List entry points and state writes |
| `slither <file> --detect unprotected-upgrade` | Flag unprotected upgrade paths |

## Verification-Path Checklist (signature bridges)

| Check | Why |
|-------|-----|
| `ecrecover` result `!= address(0)` | Malformed signatures recover to zero address |
| Signer in authorized validator set | Prevents arbitrary-key attestation |
| Threshold enforced (M-of-N) | Single compromised key cannot pass |
| Signers deduplicated / sorted | Prevents counting one signer multiple times |
| EIP-712 domain binds `chainId` + bridge address | Prevents cross-chain / cross-contract replay |
| Per-message nonce / ID consumed | Prevents replay of a valid message |
| Destination chain ID checked | Message only valid on its target chain |

## Trust-Model Scoring Inputs

| Input | Stronger | Weaker |
|-------|----------|--------|
| Validator count | Large, diverse | 1 relayer / small set |
| Threshold ratio | High (e.g. >= 2/3) | Low (e.g. 1-of-2) |
| Verification method | Light client / Merkle proof | Off-chain multisig only |
| Admin upgradeability | Timelocked, multisig | Single key, instant |

## Companion Script CLI (`scripts/agent.py`)

| Command | Args | Purpose |
|---------|------|---------|
| `score` | `--validators --threshold --verification --upgradeable --timelock-hours` | Score a bridge config's trust assumptions and list weaknesses |
| `scan` | `--source <Bridge.sol>` | Flag missing replay/nonce, `address(0)`, signer-set, and chain-ID checks |

```bash
python3 scripts/agent.py score --validators 8 --threshold 5 --verification multisig --upgradeable true --timelock-hours 0
python3 scripts/agent.py scan --source src/Bridge.sol
```

## External References

- EIP-712: https://eips.ethereum.org/EIPS/eip-712
- OpenZeppelin ECDSA: https://docs.openzeppelin.com/contracts/api/utils#ECDSA
- Building Secure Contracts: https://secure-contracts.com/
