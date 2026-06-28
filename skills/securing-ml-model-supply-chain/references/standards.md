# Standards and References — Securing the ML Model Supply Chain

## MITRE ATLAS Techniques

| ID | Name | Tactic | Rationale |
|----|------|--------|-----------|
| AML.T0010 | AI Supply Chain Compromise | Initial Access | A backdoored model, dataset, or ML library enters the victim pipeline. |
| AML.T0058 | Publish Poisoned Models | Resource Development | Adversary uploads a malicious/backdoored model to a public hub for victims to pull. |

Related sub-technique: **AML.T0010.003 — AI Supply Chain Compromise: Model** (the model-artifact link specifically).

## NIST AI RMF

| ID | Function | Rationale |
|----|----------|-----------|
| MANAGE-3.1 | AI risks from third-party resources are managed | Scanning, provenance, and signing manage third-party model risk. |
| GOVERN-6.1 | Policies for third-party AI resources are in place | A scan-and-verify-before-load gate is the governing policy. |

## Unsafe Serialization Formats

| Format | Code-execution vector |
|--------|-----------------------|
| pickle / `.pkl` | `__reduce__` runs arbitrary callables on load |
| PyTorch `.bin` / `.pt` | Pickle under the hood |
| Keras H5 / `.keras` | `Lambda` layers execute arbitrary Python |
| TensorFlow SavedModel | Custom ops can execute code |

Safe alternatives: **safetensors** (tensors only), GGUF (data only), PyTorch `weights_only=True`.

## Official Resources

- MITRE ATLAS AML.T0010: https://atlas.mitre.org/techniques/AML.T0010
- modelscan (Protect AI): https://github.com/protectai/modelscan
- safetensors: https://github.com/huggingface/safetensors
- Sigstore model transparency / model signing: https://github.com/sigstore/model-transparency
- PyTorch torch.load docs: https://pytorch.org/docs/stable/generated/torch.load.html
- NIST AI Risk Management Framework: https://www.nist.gov/itl/ai-risk-management-framework

## Key Background

- Protect AI, "Hugging Face Pickle Scanning" research on malicious models in public hubs.
- OpenSSF / Sigstore model-signing initiative for model provenance and authenticity.

## Related Skills

- `detecting-data-and-model-poisoning` — training-time poisoning (complements artifact scanning)
- `threat-modeling-agentic-ai-systems` — supply chain appears at the MAESTRO Deployment Infra layer
- `scanning-iac-and-images-with-trivy` — analogous artifact-scanning gate for containers/IaC
