---
name: fuzzing-smart-contracts-with-echidna
description: Find logic and economic bugs in Solidity contracts through property-based and assertion-based fuzzing with Echidna, complemented by Foundry invariant testing, using coverage-guided campaigns, persistent corpora, and well-designed invariants.
domain: cybersecurity
subdomain: blockchain-security
tags:
- blockchain
- solidity
- echidna
- fuzzing
- invariant-testing
- foundry
- smart-contract
- property-based-testing
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.RA-01
- PR.DS-01
- PR.DS-02
- DE.CM-01
mitre_attack:
- T1190
- T1059
- T1499
---
# Fuzzing Smart Contracts with Echidna

> **Authorized Use Only:** Fuzz only contracts you own, deployed to a local chain, or are explicitly authorized to assess. Fuzzing campaigns generate large volumes of transactions and may include exploit-shaped sequences; never aim a discovered counterexample at a live contract or other people's funds. Reproduce and report responsibly.

## Overview

Static analyzers catch known *patterns*; fuzzing finds *behaviors*. Echidna is a coverage-guided, property-based fuzzer for Ethereum smart contracts that generates random transaction sequences and tries to break user-written **invariants** — statements that must hold for every reachable state of the contract. Where Slither answers "does this code contain a known anti-pattern?", Echidna answers "can any sequence of calls drive this contract into a state the developer believed impossible?" — for example, total supply diverging from the sum of balances, a vault becoming insolvent, or an attacker withdrawing more than they deposited. These economic and stateful logic bugs are exactly the class that adversaries weaponize against deployed protocols, and they map to MITRE ATT&CK **T1190 (Exploit Public-Facing Application)** since the contract is a public-facing, internet-reachable application whose state machine is the attack surface.

Echidna supports three modes. In **property mode**, you write `echidna_*` boolean functions that must always return true. In **assertion mode** (`--test-mode assertion`), Echidna treats any failing `assert` (or Solidity 0.8 arithmetic/`require` panic, depending on config) inside normal functions as a violation, letting you embed checks directly in business logic. In **optimization mode** it maximizes a returned value to surface worst-case states. The fuzzer is coverage-guided: it instruments the EVM, keeps inputs that reach new code as a persistent **corpus**, and mutates them — this is what lets it discover deep multi-call sequences. Because the campaign drives a real EVM with arbitrary scripted call sequences, the underlying machinery also maps to **T1059 (Command and Scripting Interpreter)** and, since long campaigns and pathological inputs can exhaust gas or block resources, to **T1499 (Endpoint Denial of Service)** in the resource-exhaustion sense relevant to on-chain availability. Foundry's built-in invariant/fuzz testing (`forge test` with `invariant_*` functions and handler contracts) is a complementary, faster-to-iterate harness that shares the same invariant-driven philosophy; mature audits run both.

This skill covers identifying the right invariants for a contract, writing Echidna property and assertion tests, configuring coverage-guided campaigns with a persistent corpus, interpreting shrunk counterexamples, and cross-checking findings with Foundry invariant tests.

## When to Use

- Before deploying a stateful contract (vault, AMM, staking, lending, token) where economic invariants must hold across arbitrary call orderings.
- When static analysis is clean but you suspect logic, accounting, or rounding bugs that only appear over multi-step transaction sequences.
- When you want a regression corpus that re-checks invariants on every change in CI.
- When reproducing a suspected exploit by encoding the broken safety property and letting the fuzzer find the sequence.
- When validating that a fix actually removes a counterexample (re-run the saved corpus).
- When auditing a third-party (authorized) protocol and need behavioral, not just pattern-based, coverage.

## Prerequisites

- A Solidity project, ideally Foundry-based:
  ```bash
  curl -L https://foundry.paradigm.xyz | bash && foundryup
  ```
- Echidna (Trail of Bits). Easiest via the official Docker image or precompiled binary:
  ```bash
  docker pull ghcr.io/crytic/echidna/echidna   # or download from GitHub releases
  # native: install slither + crytic-compile first (Echidna uses them to build)
  pip install slither-analyzer crytic-compile
  ```
- `solc-select` for pinning the compiler version:
  ```bash
  pip install solc-select && solc-select install 0.8.24 && solc-select use 0.8.24
  ```
- A local chain or fork for state-dependent tests (`anvil`, included with Foundry).
- Authorization to test the target contracts.

## Objectives

- Enumerate the contract's state-changing functions and derive safety/liveness invariants.
- Write Echidna property tests (`echidna_*`) and assertion-mode checks.
- Run a coverage-guided campaign with a persistent corpus and read the coverage report.
- Triage and minimize counterexamples into a deterministic reproducer.
- Cross-validate the same invariants with Foundry `invariant_*` tests.
- Wire the corpus and campaign into CI as a regression gate.

## MITRE ATT&CK Mapping

| ID | Name | Tactic | Where it shows up |
|----|------|--------|-------------------|
| T1190 | Exploit Public-Facing Application | Initial Access | The contract is a public-facing app; broken invariants are the exploitable surface fuzzing targets. |
| T1059 | Command and Scripting Interpreter | Execution | Fuzzer drives arbitrary scripted EVM call sequences against the contract. |
| T1499 | Endpoint Denial of Service | Impact | Pathological sequences (gas griefing, unbounded loops) found by fuzzing degrade on-chain availability. |

## Workflow

### 1. Enumerate state-changing functions and pick invariants
List every `public`/`external` non-`view` function — each is an edge the fuzzer can take. For each, ask "what must remain true no matter how often or in what order this is called?" Typical invariants: conservation (sum of balances == totalSupply), solvency (assets >= liabilities), monotonicity (an index only increases), and access (only the owner mutates owner-only state).

```bash
# quick inventory of mutating entry points
slither path/to/Contract.sol --print function-summary 2>/dev/null | grep -iE "external|public"
# or use the companion script in this skill:
python3 scripts/agent.py suggest --source src/Vault.sol
```

### 2. Write an Echidna property contract
Echidna tests are a contract that inherits the target and exposes `echidna_*` boolean properties. Constrain the deployer/sender set so privileged paths are reachable as intended.

```solidity
// test/echidna/VaultProperties.sol
pragma solidity ^0.8.24;
import "../../src/Vault.sol";

contract VaultProperties is Vault {
    // Property mode: must ALWAYS return true.
    function echidna_solvent() public view returns (bool) {
        return address(this).balance >= totalDeposited;
    }

    function echidna_supply_matches_balances() public view returns (bool) {
        // accounting invariant the contract claims to maintain
        return totalShares == _trackedShareSum();
    }
}
```

### 3. Configure and run a coverage-guided campaign
Use a YAML config to set the test mode, sender set, run length, and a persistent corpus directory so coverage carries across runs.

```yaml
# echidna.yaml
testMode: assertion          # also catches asserts inside business logic
testLimit: 100000            # sequences to try
seqLen: 50                   # max calls per sequence
corpusDir: corpus            # persist coverage corpus across runs
coverage: true
sender: ["0x10000", "0x20000"]
deployer: "0x30000"
```

```bash
echidna test/echidna/VaultProperties.sol \
  --contract VaultProperties \
  --config echidna.yaml
# Docker equivalent:
# docker run --rm -v "$PWD":/src ghcr.io/crytic/echidna/echidna \
#   /src/test/echidna/VaultProperties.sol --contract VaultProperties --config /src/echidna.yaml
```

### 4. Read coverage and triage counterexamples
On a failure Echidna prints the *shrunk* (minimized) call sequence that broke the property. The `corpus/covered.*.txt` files annotate which lines were hit (`*` reached, `r`/`e` reverted) — uncovered branches mean weak invariants or unreachable guards.

```text
echidna_solvent: FAILED!
  Call sequence:
    deposit(1000) from: 0x10000
    rebase(-2)    from: 0x10000   <-- drops accounting below balance
    withdraw(1000) from: 0x10000
Coverage: 87% of contract lines reached
```

### 5. Cross-validate with Foundry invariant testing
Re-express the same invariant in Foundry to get a second engine and fast local iteration. Foundry uses `invariant_*` functions plus a handler that bounds inputs.

```solidity
// test/Vault.invariants.t.sol
import {Test} from "forge-std/Test.sol";
contract VaultInvariants is Test {
    Vault vault;
    function setUp() public { vault = new Vault(); targetContract(address(vault)); }
    function invariant_solvent() public view {
        assertGe(address(vault).balance, vault.totalDeposited());
    }
}
```
```bash
forge test --match-contract VaultInvariants -vvv \
  --fuzz-runs 5000   # invariant runs configured via foundry.toml [invariant]
```

### 6. Gate CI on the campaign and corpus
Commit the `corpus/` directory and run a bounded campaign on every PR so regressions resurface immediately. Keep `testLimit` modest in CI and run long campaigns nightly.

```bash
echidna test/echidna/VaultProperties.sol --contract VaultProperties \
  --config echidna.yaml --test-limit 20000 || exit 1
```

## Tools and Resources

| Resource | Link |
|----------|------|
| Echidna (Trail of Bits) | https://github.com/crytic/echidna |
| Echidna documentation | https://secure-contracts.com/program-analysis/echidna/index.html |
| Building Secure Contracts (Trail of Bits) | https://secure-contracts.com/ |
| Foundry Book — Invariant Testing | https://book.getfoundry.sh/forge/invariant-testing |
| Foundry Book — Fuzz Testing | https://book.getfoundry.sh/forge/fuzz-testing |
| crytic-compile | https://github.com/crytic/crytic-compile |
| SWC Registry | https://swcregistry.io/ |

## Invariant Pattern Cheat-Sheet

| Invariant class | Example property | Bug it catches |
|-----------------|------------------|----------------|
| Conservation | `sum(balances) == totalSupply` | Mint/burn accounting errors |
| Solvency | `assets >= liabilities` | Insolvency / under-collateralization |
| Monotonicity | `index_t >= index_{t-1}` | Rebase / interest index regressions |
| Access | only owner mutates owner state | Missing access control (SWC-105) |
| No-free-money | user out <= user in (+yield) | Reentrancy / rounding extraction |
| Bounded fees | `fee <= MAX_FEE` | Fee-trap / honeypot logic |
| Idempotence | double-init reverts | Re-initialization bugs |

## Validation Criteria

- [ ] All `public`/`external` state-changing functions enumerated as fuzz entry points.
- [ ] At least one safety invariant per critical accounting/solvency property is written.
- [ ] Assertion-mode campaign runs with a persistent `corpusDir` and coverage enabled.
- [ ] Coverage report reviewed; uncovered critical branches explained or addressed.
- [ ] Any counterexample minimized into a deterministic reproducer.
- [ ] The same invariants validated independently with Foundry `invariant_*` tests.
- [ ] Corpus committed and a bounded Echidna campaign runs in CI.
- [ ] Fix verified by re-running the saved corpus with no violations.
