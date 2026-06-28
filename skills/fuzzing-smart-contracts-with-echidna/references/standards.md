# Standards and References — Fuzzing Smart Contracts with Echidna

## MITRE ATT&CK Techniques

| ID | Name | Tactic | Rationale |
|----|------|--------|-----------|
| T1190 | Exploit Public-Facing Application | Initial Access | A smart contract is a public-facing application; fuzzing targets the broken invariants an attacker would exploit. |
| T1059 | Command and Scripting Interpreter | Execution | The fuzzer executes arbitrary scripted EVM transaction sequences against the contract. |
| T1499 | Endpoint Denial of Service | Impact | Gas-griefing / unbounded-loop sequences discovered by fuzzing degrade on-chain availability. |

## NIST CSF 2.0

| ID | Function | Rationale |
|----|----------|-----------|
| ID.RA-01 | Identify — Risk Assessment | Fuzzing identifies and characterizes vulnerabilities and invariant violations before deployment. |
| PR.DS-01 | Protect — Data Security (data at rest) | Invariants protect the integrity of on-chain state (balances, accounting). |
| PR.DS-02 | Protect — Data Security (data in transit) | Invariants on call sequences protect state transitions during transaction processing. |
| DE.CM-01 | Detect — Continuous Monitoring | CI fuzzing campaigns continuously monitor for regressions in safety properties. |

## Official Resources

- Echidna: https://github.com/crytic/echidna
- Echidna docs (Building Secure Contracts): https://secure-contracts.com/program-analysis/echidna/index.html
- Building Secure Contracts (Trail of Bits): https://secure-contracts.com/
- Foundry Book — Invariant Testing: https://book.getfoundry.sh/forge/invariant-testing
- Foundry Book — Fuzz Testing: https://book.getfoundry.sh/forge/fuzz-testing
- crytic-compile: https://github.com/crytic/crytic-compile
- SWC Registry (Smart Contract Weakness Classification): https://swcregistry.io/
- OpenZeppelin Contracts: https://docs.openzeppelin.com/contracts
- ConsenSys Diligence — Smart Contract Best Practices: https://consensys.github.io/smart-contract-best-practices/

## Key Standards / Research

- Grieco et al., "Echidna: Effective, Usable, and Fast Fuzzing for Smart Contracts" (ISSTA 2020).
- Trail of Bits, "Building Secure Contracts" — property-based and invariant testing methodology.
- Secureum — Smart Contract Security CARE/RACE materials: https://secureum.substack.com/
- Smart Contract Weakness Classification (SWC) Registry — pattern taxonomy.

## Related Skills

- analyzing-ethereum-smart-contract-vulnerabilities (static + symbolic analysis)
- auditing-foundry-smart-contract-security (Foundry-based audit workflow)
- auditing-smart-contract-access-control-and-upgradeability
- detecting-malicious-tokens-and-rug-pulls
