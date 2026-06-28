# Standards and References — Securing Cross-Chain Bridge Protocols

## MITRE ATT&CK Techniques

| ID | Name | Tactic | Rationale |
|----|------|--------|-----------|
| T1190 | Exploit Public-Facing Application | Initial Access | Forged or replayed messages are submitted to the public-facing bridge contract. |
| T1657 | Financial Theft | Impact | Accepting an invalid message mints/releases unbacked assets and drains pooled funds. |
| T1078 | Valid Accounts | Defense Evasion / Persistence | Compromised validator keys or over-powered admin accounts make malicious actions look legitimate. |

## NIST CSF 2.0

| ID | Function | Rationale |
|----|----------|-----------|
| ID.RA-01 | Identify — Risk Assessment | Trust-model scoring identifies and prioritizes the bridge's risk concentrations. |
| PR.AA-01 | Protect — Identity Management & Authentication | Validator-set and threshold controls govern who may attest cross-chain messages. |
| PR.DS-01 | Protect — Data Security (data at rest) | Replay protection and accounting invariants protect the integrity of locked/minted state. |
| DE.CM-01 | Detect — Continuous Monitoring | Mint-vs-lock reconciliation and config-change alerts monitor for active exploitation. |

## Official Resources

- EIP-712 (typed structured data signing): https://eips.ethereum.org/EIPS/eip-712
- OpenZeppelin ECDSA utilities: https://docs.openzeppelin.com/contracts/api/utils#ECDSA
- Trail of Bits, Building Secure Contracts: https://secure-contracts.com/
- Slither: https://github.com/crytic/slither
- Foundry Book: https://book.getfoundry.sh/
- ConsenSys Diligence: https://consensys.io/diligence/
- SWC Registry: https://swcregistry.io/

## Key Standards / Research

- Vitalik Buterin, "The bridging trilemma" / cross-chain trust-model discussion.
- Trail of Bits — bridge audit methodology and signature-verification pitfalls.
- Secureum — bridge and cross-chain security materials: https://secureum.substack.com/
- SWC-117 (Signature Malleability), SWC-121 (Missing Protection against Signature Replay).

## Related Skills

- analyzing-ethereum-smart-contract-vulnerabilities
- auditing-smart-contract-access-control-and-upgradeability
- auditing-foundry-smart-contract-security
- fuzzing-smart-contracts-with-echidna
