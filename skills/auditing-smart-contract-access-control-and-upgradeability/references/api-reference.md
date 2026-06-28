# Access-Control / Upgradeability Audit — Tool & CLI Reference

## CLI Tools

| Tool | Install | Purpose |
|------|---------|---------|
| slither-analyzer | `pip install slither-analyzer` | Access-control + upgradeability detectors |
| slither-check-upgradeability | bundled with slither | Compare two contract versions for upgrade-safety |
| foundry (forge/cast) | `curl -L https://foundry.paradigm.xyz | bash && foundryup` | Storage-layout inspection, proof-of-control tests |
| @openzeppelin/upgrades-core | `npm i -D @openzeppelin/upgrades-core` | Validate proxy upgrade safety / storage layout |

## Relevant Slither Detectors

| Detector | What it finds |
|----------|---------------|
| `unprotected-upgrade` | Upgradeable contract that can be hijacked (uninitialized) |
| `suicidal` | Function lets anyone destroy the contract (`selfdestruct`) |
| `controlled-delegatecall` | `delegatecall` to a user-controlled address |
| `arbitrary-send-eth` | ETH sent to arbitrary destination |
| `tx-origin` | Use of `tx.origin` for authorization |
| `--print modifiers` | Lists access-control modifiers per function |

```bash
slither src/ --detect unprotected-upgrade,suicidal,controlled-delegatecall,tx-origin
slither-check-upgradeability src/V1.sol V1 --new-contract-name V2
```

## Storage-Layout Inspection (Foundry)

| Command | Purpose |
|---------|---------|
| `forge inspect <path>:<Name> storage-layout` | Dump slot/offset/type per variable |
| diff V1 vs V2 layouts | Confirm V2 only appends (no reorder/insert/type change) |

## Initializer / Upgrade Checklist

| Check | Correct form |
|-------|--------------|
| Logic constructor | `constructor() { _disableInitializers(); }` |
| Initializer guard | `function initialize(...) public initializer` |
| UUPS upgrade auth | `_authorizeUpgrade(address) internal override onlyOwner` |
| No public `upgradeTo` | only via gated `_authorizeUpgrade` |
| Proxy slot standard | EIP-1967 slots used |

## Companion Script CLI (`scripts/agent.py`)

| Command | Args | Purpose |
|---------|------|---------|
| `scan` | `--source <Contract.sol>` `[--output report.json]` | Flag missing guards, `tx.origin` auth, unprotected initializer/upgrade, `selfdestruct`, `delegatecall`; score risk |

```bash
python3 scripts/agent.py scan --source src/Vault.sol
python3 scripts/agent.py scan --source src/Logic.sol --output report.json
```

## External References

- OpenZeppelin Upgrades: https://docs.openzeppelin.com/upgrades-plugins
- EIP-1967: https://eips.ethereum.org/EIPS/eip-1967
- EIP-1822 (UUPS): https://eips.ethereum.org/EIPS/eip-1822
- Slither detectors: https://github.com/crytic/slither/wiki/Detector-Documentation
