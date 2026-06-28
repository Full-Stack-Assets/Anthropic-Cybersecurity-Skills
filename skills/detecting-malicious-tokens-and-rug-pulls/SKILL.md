---
name: detecting-malicious-tokens-and-rug-pulls
description: Triage ERC-20 tokens for scam and rug-pull traits by scanning source, ABI, and on-chain state for honeypot mechanics, hidden mint, blacklist and fee traps, owner privileges, liquidity-lock status, and proxy upgradeability, producing a risk score.
domain: cybersecurity
subdomain: blockchain-security
tags:
- blockchain
- erc20
- rug-pull
- honeypot
- token-security
- scam-detection
- liquidity-lock
- triage
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.RA-01
- DE.CM-01
- DE.AE-02
- PR.DS-01
mitre_attack:
- T1657
- T1190
- T1078
---
# Detecting Malicious Tokens and Rug Pulls

> **Authorized Use Only:** This skill is for defensive triage — protecting users, an exchange listing pipeline, or a wallet from scam tokens. Analyze token contracts you are assessing for safety; do not deploy honeypots or use these techniques to defraud. The goal is to flag malicious tokens before victims interact with them.

## Overview

A "rug pull" is a scam in which a token's deployer engineers the contract so that buyers can put money in but cannot get it out, or so that the deployer can suddenly drain value — then disappears with the funds. These are pure financial-theft schemes (MITRE ATT&CK **T1657, Financial Theft**) delivered through a public-facing contract (**T1190**) and almost always rely on privileged deployer/owner accounts (**T1078, Valid Accounts**) retaining powers that a legitimate token would renounce. Unlike a code bug, the malice is *intended* and hidden in plain sight: the contract compiles, lists on a DEX, looks like a normal ERC-20, and only reveals its trap when victims try to sell.

The trap mechanics recur. **Honeypots** let buys succeed but make sells revert — via a transfer hook that blocks non-owner sells, a per-address `blacklist`, a sell `fee` set to ~100%, or a `pause` that only the owner can lift. **Hidden mint** functions let the owner inflate supply and dump on holders. **Fee traps** allow the owner to raise the transfer tax arbitrarily after launch (`setFee`/`setTaxes` with no cap). **Ownership and upgradeability** are the force multipliers: an un-renounced `onlyOwner`, a proxy the deployer can upgrade to new malicious logic, or an owner-only `withdraw`/`drain` on the liquidity pool. Finally, **liquidity** that is not locked (or locked only briefly) lets the deployer pull the pooled trading pair and leave holders with worthless tokens.

Detection is layered triage. Source-level analysis (when verified source exists) finds the dangerous functions and modifiers directly. ABI/bytecode heuristics catch suspicious selectors when source is unavailable. On-chain checks confirm owner state, supply behavior, and liquidity-lock status, and a simulated buy-then-sell on a fork is the strongest single signal for honeypots. This skill builds a weighted **risk score** from these signals so a listing/wallet pipeline can auto-flag and a human can review the highest-risk tokens. It complements, rather than duplicates, general vulnerability scanning: the question here is "is this contract designed to rob its users?" not "does it have a bug?".

## When to Use

- When screening a token before listing it, integrating it into a wallet, or recommending it to users.
- When investigating a suspected honeypot or rug-pull report after losses.
- When building an automated scam-token filter for a DEX aggregator, wallet, or scanner.
- When triaging a large list of new token deployments for the highest-risk ones.
- When verifying that a token's owner has renounced privileges and locked liquidity as claimed.
- When reverse-engineering a token whose source is unverified (ABI/bytecode heuristics).

## Prerequisites

- Python 3.9+ for the source/ABI heuristic scanner (companion script, stdlib only).
- Foundry for on-chain checks and buy/sell simulation on a fork:
  ```bash
  curl -L https://foundry.paradigm.xyz | bash && foundryup
  ```
- An archive RPC endpoint to fork the chain and read token/pool state.
- Optional: Slither for deeper source review:
  ```bash
  pip install slither-analyzer
  ```
- The token's verified source (preferred), or its ABI/bytecode.
- Authorization context: defensive triage only.

## Objectives

- Scan token source/ABI for rug-pull red flags (mint, setFee, blacklist, pausable transfers, owner drains).
- Determine whether ownership is renounced and which privileged powers remain.
- Check liquidity-lock status and the proportion of supply held by the deployer.
- Simulate a buy then sell on a fork to detect honeypot sell-blocking.
- Combine signals into a weighted risk score with an actionable verdict.
- Document evidence for each flagged trait.

## MITRE ATT&CK Mapping

| ID | Name | Tactic | Where it shows up |
|----|------|--------|-------------------|
| T1657 | Financial Theft | Impact | The token is engineered to take buyers' funds — the entire purpose of the scam. |
| T1190 | Exploit Public-Facing Application | Initial Access | The malicious token contract is the public-facing vehicle victims interact with. |
| T1078 | Valid Accounts | Privilege Abuse | An un-renounced owner/deployer key retains the powers used to spring the trap. |

## Workflow

### 1. Scan source / ABI for red-flag functions
Look for the privileged functions that enable a rug. Their mere presence is not always malicious, but un-renounced and uncapped versions are the core signal.

```bash
# heuristic scan of verified source (or pass an ABI JSON)
python3 scripts/agent.py scan --source Token.sol
# red-flag selectors: mint(), setFee/setTaxes(), blacklist/addBot(), pause(),
# setMaxTx(), excludeFromFee(), owner-only transfer hooks, withdraw()/rescue()
```

### 2. Check ownership and remaining privileges
A legitimate "renounced" token has `owner() == address(0)`. Confirm on-chain and enumerate what the owner could still do.

```bash
cast call <TOKEN> "owner()(address)" --rpc-url $RPC
# 0x0000...0000 => renounced. Any other address => owner retains privileges.
cast call <TOKEN> "paused()(bool)" --rpc-url $RPC 2>/dev/null
```

### 3. Inspect supply distribution and mint behavior
Heavy deployer/holder concentration plus a callable `mint()` means the owner can dump or inflate. Compare top-holder balance to total supply.

```bash
cast call <TOKEN> "totalSupply()(uint256)" --rpc-url $RPC
cast call <TOKEN> "balanceOf(address)(uint256)" <DEPLOYER> --rpc-url $RPC
# >50% in one non-locked address is a strong rug signal
```

### 4. Verify liquidity-lock status
Check whether the DEX LP tokens are held by a known locker (or burned) versus the deployer. Unlocked LP means the deployer can pull liquidity at will.

```bash
# LP balance of the deployer vs. a locker / burn address
cast call <LP_TOKEN> "balanceOf(address)(uint256)" <DEPLOYER> --rpc-url $RPC
cast call <LP_TOKEN> "balanceOf(address)(uint256)" 0x000000000000000000000000000000000000dEaD --rpc-url $RPC
```

### 5. Simulate buy then sell on a fork (honeypot test)
The definitive honeypot check: fork the chain, buy the token through the router, then immediately try to sell. A revert or near-zero return on sell while buy succeeds is a honeypot.

```solidity
// test/Honeypot.t.sol  (forge test --fork-url $RPC -vvv)
function test_buy_then_sell() public {
    router.swapExactETHForTokens{value: 1 ether}(0, pathBuy, address(this), block.timestamp);
    uint256 bal = token.balanceOf(address(this));
    token.approve(address(router), bal);
    // if this reverts or yields ~0, the token is a honeypot
    router.swapExactTokensForETH(bal, 0, pathSell, address(this), block.timestamp);
}
```

### 6. Score and report
Combine the signals into a weighted risk score and a verdict (e.g., LOW/MEDIUM/HIGH/CRITICAL), with evidence per trait, for the listing/wallet pipeline.

```bash
python3 scripts/agent.py scan --source Token.sol --output report.json
# report.json: per-flag evidence + aggregate risk score + verdict
```

## Tools and Resources

| Resource | Link |
|----------|------|
| Foundry Book (fork testing) | https://book.getfoundry.sh/forge/fork-testing |
| Slither | https://github.com/crytic/slither |
| OpenZeppelin ERC-20 / Ownable | https://docs.openzeppelin.com/contracts/api/token/erc20 |
| Trail of Bits — Building Secure Contracts | https://secure-contracts.com/ |
| ConsenSys Diligence | https://consensys.io/diligence/ |
| SWC Registry | https://swcregistry.io/ |
| Etherscan Token Approval / contract verification | https://etherscan.io/ |

## Rug-Pull Red-Flag Cheat-Sheet

| Trait | Indicator | Risk |
|-------|-----------|------|
| Hidden mint | callable `mint()` with owner retained | Supply inflation / dump |
| Sell blocking | owner-only transfer hook / `blacklist` | Honeypot |
| Fee trap | `setFee`/`setTaxes` uncapped | Sells taxed to ~100% |
| Pausable transfers | owner-only `pause()` | Freeze sells at will |
| Owner not renounced | `owner() != address(0)` | All privileges live |
| Proxy upgradeable | deployer can `upgradeTo` | Swap in malicious logic |
| Unlocked liquidity | LP held by deployer | Liquidity can be pulled |
| Supply concentration | >50% in one address | Dump risk |

## Validation Criteria

- [ ] Source/ABI scanned for mint, setFee, blacklist, pause, and owner-drain functions.
- [ ] Ownership renouncement confirmed on-chain and remaining privileges enumerated.
- [ ] Supply distribution / top-holder concentration measured.
- [ ] Liquidity-lock status verified (locker/burn vs. deployer-held LP).
- [ ] Buy-then-sell simulated on a fork to detect honeypot sell-blocking.
- [ ] Signals combined into a weighted risk score with a verdict.
- [ ] Evidence documented per flagged trait.
- [ ] Triage result routed to the listing/wallet decision (allow/flag/block).
