# Echidna / Fuzzing — Tool & CLI Reference

## CLI Tools

| Tool | Install | Purpose |
|------|---------|---------|
| echidna | `docker pull ghcr.io/crytic/echidna/echidna` or GitHub release | Property/assertion/optimization fuzzing of Solidity |
| crytic-compile | `pip install crytic-compile` | Build/compilation backend Echidna uses to load contracts |
| slither-analyzer | `pip install slither-analyzer` | Static analysis; `--print function-summary` to enumerate entry points |
| foundry (forge/anvil) | `curl -L https://foundry.paradigm.xyz | bash && foundryup` | Invariant/fuzz testing harness + local chain |
| solc-select | `pip install solc-select` | Pin Solidity compiler version |

## Echidna Key Flags

| Flag | Purpose |
|------|---------|
| `--contract <Name>` | Which contract in the file holds the properties |
| `--config <file.yaml>` | Load campaign configuration |
| `--test-mode <property\|assertion\|optimization\|overflow\|exploration>` | Select fuzzing mode |
| `--test-limit <N>` | Number of transaction sequences to attempt |
| `--seq-len <N>` | Max calls per generated sequence |
| `--corpus-dir <dir>` | Persist/replay the coverage corpus |
| `--coverage` | Emit line-coverage report |
| `--format <text\|json>` | Output format (json for CI parsing) |

## Echidna YAML Config Keys

| Key | Meaning |
|-----|---------|
| `testMode` | property / assertion / optimization / overflow / exploration |
| `testLimit` | sequences to run |
| `seqLen` | max calls per sequence |
| `corpusDir` | corpus persistence directory |
| `coverage` | enable coverage-guided fuzzing |
| `sender` | array of allowed `msg.sender` addresses |
| `deployer` | address that deploys the test contract |
| `balanceContract` / `balanceAddr` | starting balances for contract / senders |
| `filterFunctions` / `filterBlacklist` | include or exclude specific selectors |

## Foundry Invariant Config (foundry.toml `[invariant]`)

| Key | Meaning |
|-----|---------|
| `runs` | number of invariant runs |
| `depth` | calls per run |
| `fail_on_revert` | treat reverts as failures |
| `[fuzz] runs` | stateless fuzz iterations for `testFuzz_*` |

## Companion Script CLI (`scripts/agent.py`)

| Command | Args | Purpose |
|---------|------|---------|
| `suggest` | `--source <Contract.sol>` | List public/external state-changing functions and suggest candidate invariants |
| `coverage` | `--corpus <dir>` | Summarize an Echidna coverage corpus (lines reached/reverted, % covered) |

```bash
python3 scripts/agent.py suggest --source src/Vault.sol
python3 scripts/agent.py coverage --corpus corpus/
```

## External References

- Echidna docs: https://secure-contracts.com/program-analysis/echidna/index.html
- Foundry Book: https://book.getfoundry.sh/
- crytic-compile: https://github.com/crytic/crytic-compile
