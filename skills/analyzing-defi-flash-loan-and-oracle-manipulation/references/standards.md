# Standards and References — DeFi Flash-Loan and Oracle Manipulation

## MITRE ATT&CK Techniques

| ID | Name | Tactic | Rationale |
|----|------|--------|-----------|
| T1190 | Exploit Public-Facing Application | Initial Access | The vulnerable pricing/valuation contract is a public-facing application the attacker invokes. |
| T1657 | Financial Theft | Impact | The attacker monetizes a manipulated price to extract funds — the objective of the attack. |
| T1059 | Command and Scripting Interpreter | Execution | The borrow/swap/exploit/repay flow is one scripted atomic transaction. |

## NIST CSF 2.0

| ID | Function | Rationale |
|----|----------|-----------|
| ID.RA-01 | Identify — Risk Assessment | Cost-to-manipulate analysis identifies and quantifies the economic vulnerability. |
| PR.DS-01 | Protect — Data Security (data at rest) | Manipulation-resistant oracles protect the integrity of stored valuation state. |
| DE.CM-01 | Detect — Continuous Monitoring | Spot-vs-TWAP deviation checks continuously monitor for active manipulation. |
| DE.AE-02 | Detect — Adverse Event Analysis | Forked-block reproduction analyzes a suspected manipulation event. |

## Official Resources

- Uniswap v2 Oracles (TWAP): https://docs.uniswap.org/contracts/v2/concepts/core-concepts/oracles
- Uniswap v3 Oracle library: https://docs.uniswap.org/contracts/v3/reference/core/libraries/Oracle
- Chainlink Data Feeds: https://docs.chain.link/data-feeds
- Foundry Book — fork testing: https://book.getfoundry.sh/forge/fork-testing
- ConsenSys Diligence: https://consensys.io/diligence/
- SWC Registry: https://swcregistry.io/
- OpenZeppelin Contracts: https://docs.openzeppelin.com/contracts

## Key Standards / Research

- samczsun, "So you want to use a price oracle" — canonical guide to oracle manipulation.
- Trail of Bits, Building Secure Contracts — oracle and DeFi integration guidance: https://secure-contracts.com/
- Secureum — DeFi and oracle security materials: https://secureum.substack.com/
- Uniswap v2 whitepaper — constant-product AMM and price accumulators.

## Related Skills

- analyzing-ethereum-smart-contract-vulnerabilities
- auditing-foundry-smart-contract-security
- fuzzing-smart-contracts-with-echidna
- detecting-malicious-tokens-and-rug-pulls
