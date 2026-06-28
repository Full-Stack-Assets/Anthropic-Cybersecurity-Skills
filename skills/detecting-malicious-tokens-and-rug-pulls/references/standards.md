# Standards and References — Detecting Malicious Tokens and Rug Pulls

## MITRE ATT&CK Techniques

| ID | Name | Tactic | Rationale |
|----|------|--------|-----------|
| T1657 | Financial Theft | Impact | The token is engineered to take victims' funds — the objective of the scam. |
| T1190 | Exploit Public-Facing Application | Initial Access | The malicious token contract is the public-facing vehicle victims interact with. |
| T1078 | Valid Accounts | Privilege Abuse | An un-renounced owner/deployer account retains the privileges used to spring the trap. |

## NIST CSF 2.0

| ID | Function | Rationale |
|----|----------|-----------|
| ID.RA-01 | Identify — Risk Assessment | Token triage identifies and scores the scam risk before users are exposed. |
| DE.CM-01 | Detect — Continuous Monitoring | Automated scanning continuously screens new token deployments. |
| DE.AE-02 | Detect — Adverse Event Analysis | Buy/sell fork simulation analyzes whether a token traps sellers. |
| PR.DS-01 | Protect — Data Security (data at rest) | Verifying liquidity locks and renounced ownership protects pooled user funds. |

## Official Resources

- OpenZeppelin ERC-20 / Ownable: https://docs.openzeppelin.com/contracts/api/token/erc20
- Foundry Book — fork testing: https://book.getfoundry.sh/forge/fork-testing
- Slither: https://github.com/crytic/slither
- Trail of Bits, Building Secure Contracts: https://secure-contracts.com/
- ConsenSys Diligence: https://consensys.io/diligence/
- SWC Registry: https://swcregistry.io/
- Etherscan: https://etherscan.io/

## Key Standards / Research

- EIP-20 (ERC-20 token standard): https://eips.ethereum.org/EIPS/eip-20
- Trail of Bits — token integration checklist (decimals, fee-on-transfer, hooks).
- Secureum — token and DeFi security materials: https://secureum.substack.com/
- SWC-105 (Unprotected functions), SWC-115 (`tx.origin` auth) — related anti-patterns.

## Related Skills

- analyzing-ethereum-smart-contract-vulnerabilities
- auditing-smart-contract-access-control-and-upgradeability
- analyzing-defi-flash-loan-and-oracle-manipulation
- fuzzing-smart-contracts-with-echidna
