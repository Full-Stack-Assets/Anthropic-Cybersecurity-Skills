---
name: securing-ml-model-supply-chain
description: Secure the machine-learning model supply chain against compromised or backdoored artifacts (MITRE ATLAS AML.T0010) by scanning model files for unsafe deserialization (pickle/PyTorch/Keras Lambda) with modelscan, preferring safetensors, verifying provenance and signatures with Sigstore/model signing, and pinning trusted model sources before loading.
domain: cybersecurity
subdomain: ai-security
tags:
- ai-security
- ml-supply-chain
- model-provenance
- modelscan
- safetensors
- pickle-security
- sigstore
- atlas
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- MANAGE-3.1
- GOVERN-6.1
mitre_attack:
- AML.T0010
- AML.T0058
---
# Securing the ML Model Supply Chain

> **Authorized Use Only:** The malicious-payload demonstration here builds a deliberately unsafe model file so you can prove your scanner catches it. Build and detonate it only in an isolated sandbox you control. Never load untrusted model files on a production or sensitive host.

## Overview

A machine-learning model is *executable code in disguise*. Many model serialization formats — Python **pickle**, PyTorch `.bin`/`.pt` (pickle under the hood), and Keras H5/`.keras` with `Lambda` layers — can carry arbitrary code that runs **at load time**, before a single inference. Pull a backdoored model from a public hub, call `torch.load()` or `pickle.load()`, and the attacker has code execution on your training or serving host. MITRE ATLAS tracks this as **AML.T0010 — AI Supply Chain Compromise** (with sub-techniques for compromised models, data, and software), and the malicious-model variant overlaps **AML.T0058 — Publish Poisoned Models** to public repositories.

The model supply chain is broad: pretrained weights from hubs, fine-tunes, third-party datasets, and the ML libraries themselves. This skill focuses on the highest-leverage, most overlooked link — the **model artifact** — and the controls that make loading one safe:

1. **Scan before load** with `modelscan` (Protect AI) to detect unsafe operators / embedded code.
2. **Prefer safe formats** — `safetensors` stores only tensors and cannot execute code; convert or reject pickle where possible.
3. **Verify provenance and integrity** — pin the source, check hashes, and verify cryptographic signatures (Sigstore / model signing) so you load only what a trusted publisher signed.
4. **Sandbox the unavoidable** — when you must load a pickle-based artifact from outside, do it in an isolated, network-denied environment first.

This aligns with NIST AI RMF MANAGE-3.1 (managing third-party/supply-chain AI risks) and GOVERN-6.1 (policies for third-party AI resources).

## When to Use

- Before loading any pretrained model, checkpoint, or fine-tune you did not produce yourself.
- When onboarding models from a public hub (Hugging Face, model zoos) into a build or serving pipeline.
- When designing a model registry / MLOps gate that should block unsafe artifacts.
- When establishing a model-signing and provenance policy for internally produced models.
- During an audit of an existing ML pipeline that loads external weights.

## Prerequisites

- Python 3.9+.
- `pip install modelscan safetensors` for scanning and safe conversion.
- For signing/verification: `pip install model-signing` (or Sigstore tooling) and access to your signing identity.
- An isolated sandbox (container with no network, non-root, ephemeral) for detonating untrusted artifacts.
- Hashes / signatures from the model publisher where available.

## Objectives

- Establish a "scan-and-verify before load" gate for every external model artifact.
- Detect unsafe deserialization payloads with `modelscan`.
- Convert eligible models to `safetensors` and prefer it on load.
- Verify model provenance via pinned source, hash check, and signature verification.
- Sandbox any artifact that cannot be proven safe before it touches a real host.

## MITRE ATT&CK Mapping

| ID (MITRE ATLAS) | Name | Tactic | Where it shows up |
|----|------|--------|-------------------|
| AML.T0010 | AI Supply Chain Compromise | Initial Access | Backdoored model / data / library enters the pipeline |
| AML.T0058 | Publish Poisoned Models | Resource Development | Attacker uploads a malicious model to a public hub |

## Workflow

### 1. Understand why model loading is code execution
A pickle stream can include a `__reduce__` that runs any callable on load. This is the root cause — the snippet below (for sandbox demonstration only) shows how a "model" file executes code merely by being loaded.

```python
# DEMO ONLY — run inside an isolated, network-denied sandbox.
import pickle, os

class Evil:
    def __reduce__(self):
        return (os.system, ("echo PWNED > /tmp/proof",))  # arbitrary command

# An attacker ships this as a "model"; the victim's torch.load/pickle.load detonates it.
payload = pickle.dumps(Evil())
```

### 2. Scan every external artifact with modelscan
Run `modelscan` before any load. It inspects pickle/PyTorch/TensorFlow/Keras files for unsafe operators and embedded code and reports severity.

```bash
# Scan a single file or a directory of models
modelscan -p ./downloaded_model.bin
modelscan -p ./models/ --reporting-format json -o scan-report.json
```

Block the pipeline on any HIGH/CRITICAL finding. The included `scripts/agent.py` wraps `modelscan` and enforces a fail-on-severity gate (and falls back to a stdlib pickle-opcode heuristic if modelscan is absent).

### 3. Prefer and enforce safetensors
`safetensors` serializes tensors only — no code path at load — so a malicious payload cannot ride along. Convert trusted models and prefer the safe format on load.

```python
import torch
from safetensors.torch import save_file, load_file

# Convert a (already-verified) state dict to safetensors
state = torch.load("verified_model.bin", map_location="cpu", weights_only=True)
save_file(state, "model.safetensors")

# Load safely — no arbitrary code can execute
weights = load_file("model.safetensors")
```

When you must use PyTorch's own loader, pass `weights_only=True` (PyTorch ≥ 2.0) so it refuses to unpickle arbitrary globals.

### 4. Verify provenance and integrity
Pin the exact source (org/repo + revision/commit hash), verify the file hash against the publisher's value, and verify a cryptographic signature where available. A matching SHA-256 proves *integrity*; a valid signature proves *authenticity*.

```python
import hashlib

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def verify_hash(path, expected):
    actual = sha256(path)
    if actual != expected:
        raise ValueError(f"hash mismatch: {actual} != {expected}")
    return True
```

For signatures, use Sigstore-based **model signing** (e.g., the `model-signing` project) to sign on publish and verify on pull, tying the artifact to a trusted identity.

### 5. Sandbox the unavoidable
If a needed artifact is pickle-based and unsigned, detonate it first in an isolated container: no network, non-root, ephemeral filesystem, strict resource limits. Confirm it produces only the expected tensors and no side effects before promoting it.

### 6. Gate it in the pipeline
Wire steps 2–4 into the model registry / CI: download → `modelscan` → hash + signature verify → convert to safetensors → only then promote to a loadable artifact. Record the provenance (source, revision, hash, signer) for every promoted model.

## Tools and Resources

| Resource | Link |
|----------|------|
| MITRE ATLAS AML.T0010 AI Supply Chain Compromise | https://atlas.mitre.org/techniques/AML.T0010 |
| modelscan (Protect AI) | https://github.com/protectai/modelscan |
| safetensors (Hugging Face) | https://github.com/huggingface/safetensors |
| model signing (Sigstore / OpenSSF) | https://github.com/sigstore/model-transparency |
| PyTorch `weights_only` loading | https://pytorch.org/docs/stable/generated/torch.load.html |
| NIST AI Risk Management Framework | https://www.nist.gov/itl/ai-risk-management-framework |

## Format Risk Reference

| Format | Executes code on load? | Recommendation |
|--------|------------------------|----------------|
| pickle / `.pkl` | Yes | Avoid for untrusted sources; scan + sandbox |
| PyTorch `.bin` / `.pt` | Yes (pickle) | Use `weights_only=True`; convert to safetensors |
| Keras H5 / `.keras` (Lambda) | Yes (Lambda layers) | Scan; disallow Lambda from untrusted models |
| TensorFlow SavedModel | Possible (custom ops) | Scan; restrict custom ops |
| safetensors | No | Preferred format |
| GGUF | No (data only) | Lower risk for weights |

## Validation Criteria

- [ ] Every external model artifact is scanned with `modelscan` before load.
- [ ] Pipeline blocks on HIGH/CRITICAL scan findings.
- [ ] Models are converted to / loaded as `safetensors` where feasible.
- [ ] PyTorch loads use `weights_only=True` when safetensors is not available.
- [ ] File hashes are verified against publisher values; signatures verified where present.
- [ ] Unsigned pickle-based artifacts are detonated in an isolated sandbox before promotion.
- [ ] Provenance (source, revision, hash, signer) is recorded for every promoted model.
