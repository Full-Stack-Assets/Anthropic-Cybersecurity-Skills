# Standards and References — Auditing Access Control and Upgradeability

## MITRE ATT&CK Techniques

| ID | Name | Tactic | Rationale |
|----|------|--------|-----------|
| T1190 | Exploit Public-Facing Application | Initial Access | The contract is public-facing; missing guards or initializers are the exploited surface. |
| T1078 | Valid Accounts | Privilege Escalation | The attacker ends up holding the contract's owner/admin privileges. |
| T1548 | Abuse Elevation Control Mechanism | Privilege Escalation | The core failure is improper enforcement of the privilege-elevation boundary. |

## NIST CSF 2.0

| ID | Function | Rationale |
|----|----------|-----------|
| PR.AA-01 | Protect — Identity Management & Authentication | Access-control modifiers govern which identities may invoke privileged functions. |
| PR.AA-05 | Protect — Access Permissions & Authorizations | Role minimization and least-privilege govern authorization to upgrade/admin actions. |
| ID.RA-01 | Identify — Risk Assessment | The audit identifies and prioritizes access-control and upgrade vulnerabilities. |
| PR.DS-01 | Protect — Data Security (data at rest) | Initializer and storage-layout integrity protect on-chain state from corruption/takeover. |

## Official Resources

- OpenZeppelin Access Control: https://docs.openzeppelin.com/contracts/api/access
- OpenZeppelin Proxies / Upgradeable: https://docs.openzeppelin.com/contracts/api/proxy
- OpenZeppelin Upgrades plugins: https://docs.openzeppelin.com/upgrades-plugins
- EIP-1967 (proxy storage slots): https://eips.ethereum.org/EIPS/eip-1967
- EIP-1822 (UUPS): https://eips.ethereum.org/EIPS/eip-1822
- Slither detector docs: https://github.com/crytic/slither/wiki/Detector-Documentation
- Foundry Book: https://book.getfoundry.sh/
- Trail of Bits, Building Secure Contracts: https://secure-contracts.com/
- SWC Registry: https://swcregistry.io/

## Key Standards / Research

- SWC-105 (Unprotected function), SWC-106 (Unprotected SELFDESTRUCT), SWC-112 (Delegatecall to untrusted callee), SWC-115 (Authorization through tx.origin).
- Trail of Bits — proxy/upgradeability pitfalls and `slither-check-upgradeability`.
- Secureum — access control and proxy security materials: https://secureum.substack.com/
- OpenZeppelin — "Proxy Upgrade Pattern" and "Writing Upgradeable Contracts".

## Related Skills

- analyzing-ethereum-smart-contract-vulnerabilities
- auditing-foundry-smart-contract-security
- securing-cross-chain-bridge-protocols
- fuzzing-smart-contracts-with-echidna
