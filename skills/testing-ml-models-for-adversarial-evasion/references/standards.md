# Standards and References — Testing ML Models for Adversarial Evasion

## MITRE ATLAS Techniques

| ID | Name | Tactic | Rationale |
|----|------|--------|-----------|
| AML.T0043 | Craft Adversarial Data | ML Attack Staging | Generating perturbed inputs (FGSM/PGD/boundary) within an Lp budget. |
| AML.T0015 | Evade ML Model | Defense Evasion / Impact | The crafted input causes a misclassification at inference time. |

## NIST AI RMF

| ID | Function | Rationale |
|----|----------|-----------|
| MEASURE-2.7 | AI system security and resilience are evaluated and documented | Robust-accuracy measurement across an epsilon sweep documents resilience. |
| MANAGE-2.1 | Resources are allocated to manage AI risks | Defenses (adversarial training, preprocessing) are the managed mitigation. |

## Robustness Concepts

| Term | Meaning |
|------|---------|
| Robust accuracy | Accuracy on adversarially perturbed inputs at a given epsilon |
| Perturbation budget (epsilon) | Max allowed change under an Lp norm (L-inf, L2) |
| White-box | Attacker has model gradients (FGSM, PGD, C&W) |
| Black-box | Attacker has query access only (HopSkipJump, ZOO, Boundary) |
| Adversarial training | Train on adversarial examples to raise robustness |

## Official Resources

- MITRE ATLAS AML.T0043: https://atlas.mitre.org/techniques/AML.T0043
- MITRE ATLAS AML.T0015: https://atlas.mitre.org/techniques/AML.T0015
- Adversarial Robustness Toolbox: https://github.com/Trusted-AI/adversarial-robustness-toolbox
- NIST AI Risk Management Framework: https://www.nist.gov/itl/ai-risk-management-framework

## Key Research

- Goodfellow et al., "Explaining and Harnessing Adversarial Examples" (ICLR 2015) — FGSM.
- Madry et al., "Towards Deep Learning Models Resistant to Adversarial Attacks" (ICLR 2018) — PGD / adversarial training.
- Carlini & Wagner, "Towards Evaluating the Robustness of Neural Networks" (IEEE S&P 2017) — C&W.
- Chen et al., "HopSkipJumpAttack" (IEEE S&P 2020) — decision-based black-box.

## Related Skills

- `detecting-data-and-model-poisoning` — training-time analogue of evasion
- `detecting-model-extraction-attacks` — also uses ART; inference-API abuse
- `red-teaming-llms-with-garak` — adversarial testing for LLMs specifically
