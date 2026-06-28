---
name: testing-ml-models-for-adversarial-evasion
description: Test machine-learning classifiers for adversarial-example evasion (MITRE ATLAS AML.T0043 Craft Adversarial Data / AML.T0015 Evade ML Model) by generating perturbed inputs with FGSM, PGD, and boundary attacks using the Adversarial Robustness Toolbox, measuring robust accuracy under an Lp budget, and validating defenses like adversarial training and input preprocessing.
domain: cybersecurity
subdomain: ai-security
tags:
- ai-security
- adversarial-examples
- evasion-attacks
- robustness-testing
- fgsm
- pgd
- adversarial-robustness-toolbox
- atlas
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- MEASURE-2.7
- MANAGE-2.1
mitre_attack:
- AML.T0043
- AML.T0015
---
# Testing ML Models for Adversarial Evasion

> **Authorized Use Only:** Generate and submit adversarial examples only against models **you own or are explicitly authorized to test**. Evading a third party's classifier (spam, fraud, content, malware, or safety filters) in production can be illegal and harmful. This skill is for measuring and hardening the robustness of your own models.

## Overview

An **adversarial example** is an input with a small, often human-imperceptible perturbation that flips a model's prediction. A few changed pixels make an image classifier read a stop sign as a speed-limit sign; a few token or byte tweaks make a malware classifier call a trojan "benign." MITRE ATLAS splits this into two linked techniques: **AML.T0043 — Craft Adversarial Data** (the attacker creates the perturbed input) and **AML.T0015 — Evade ML Model** (the input causes a misclassification at inference). Unlike training-time poisoning, evasion happens entirely at inference and needs no access to the training set.

Attacks vary by attacker knowledge:

- **White-box** (gradients available): Fast Gradient Sign Method (**FGSM**) and Projected Gradient Descent (**PGD**) — the standard strong baseline — perturb within an `L∞`/`L2` budget `ε`.
- **Black-box** (query-only): boundary / HopSkipJump and ZOO-style attacks craft evasions from outputs alone.

Robustness is measured as **robust accuracy**: accuracy on adversarially perturbed inputs at a given `ε`. A model can have 98% clean accuracy and ~0% robust accuracy — looking perfect while being trivially evadable. This skill uses the **Adversarial Robustness Toolbox (ART)** to generate attacks, quantify robust accuracy versus the perturbation budget, and validate defenses (adversarial training, input preprocessing, randomized smoothing). It supports NIST AI RMF MEASURE-2.7 (security/resilience evaluation) and MANAGE-2.1 (managing the identified risk).

## When to Use

- Before deploying a classifier whose misclassification has security or safety consequences (malware/spam/fraud detection, content moderation, biometric/vision systems).
- During pre-deployment AI red-teaming to quantify how easily your model is evaded.
- When validating that a robustness defense (adversarial training, preprocessing) actually raises robust accuracy.
- When choosing between candidate models — to compare robustness, not just clean accuracy.
- After an evasion incident, to reproduce the attack and measure the fix.

## Prerequisites

- Python 3.9+.
- `pip install adversarial-robustness-toolbox scikit-learn numpy` (add `torch`/`tensorflow` for DL models).
- A trained model you own (and a wrapper: ART provides `SklearnClassifier`, `PyTorchClassifier`, `KerasClassifier`).
- A held-out test set with ground-truth labels.
- Authorization to test the target model.

## Objectives

- Wrap your model as an ART estimator and establish clean accuracy.
- Generate white-box (FGSM, PGD) and black-box (boundary) adversarial examples within an `Lp` budget.
- Measure robust accuracy as a function of the perturbation budget `ε`.
- Apply and re-measure defenses (adversarial training, input preprocessing).
- Report a robustness profile that gates the deployment decision.

## MITRE ATT&CK Mapping

| ID (MITRE ATLAS) | Name | Tactic | Where it shows up |
|----|------|--------|-------------------|
| AML.T0043 | Craft Adversarial Data | ML Attack Staging | Generating the perturbed input (FGSM/PGD/boundary) |
| AML.T0015 | Evade ML Model | Defense Evasion / Impact | The crafted input causes misclassification at inference |

## Workflow

### 1. Wrap the model and measure clean accuracy
Establish the baseline the attack will erode.

```python
import numpy as np
from art.estimators.classification import SklearnClassifier

clf = SklearnClassifier(model=trained_model)          # your model
clean_pred = clf.predict(x_test).argmax(1)
clean_acc = float(np.mean(clean_pred == y_test))
print(f"clean accuracy: {clean_acc:.2%}")
```

### 2. Craft white-box adversarial examples (FGSM, PGD)
PGD is the standard strong attack: iterative FGSM projected back into the `ε`-ball each step. Robust accuracy under PGD is the headline robustness number.

```python
from art.attacks.evasion import FastGradientMethod, ProjectedGradientDescent

eps = 0.1                                              # L-inf budget
fgsm = FastGradientMethod(estimator=clf, eps=eps)
pgd = ProjectedGradientDescent(estimator=clf, eps=eps, eps_step=eps/10, max_iter=40)

x_adv = pgd.generate(x=x_test)
adv_pred = clf.predict(x_adv).argmax(1)
robust_acc = float(np.mean(adv_pred == y_test))
print(f"robust accuracy @ eps={eps}: {robust_acc:.2%}")
```

### 3. Sweep the perturbation budget
Robustness is a curve, not a point. Measure robust accuracy across increasing `ε` to find where the model collapses.

```python
for eps in [0.0, 0.02, 0.05, 0.1, 0.2]:
    atk = ProjectedGradientDescent(estimator=clf, eps=max(eps, 1e-6),
                                   eps_step=max(eps/10, 1e-6), max_iter=40)
    xa = atk.generate(x=x_test) if eps > 0 else x_test
    acc = float(np.mean(clf.predict(xa).argmax(1) == y_test))
    print(f"eps={eps:<5} robust_acc={acc:.2%}")
```

### 4. Add a black-box attack (query-only)
If the deployed threat model is query-only, evaluate with a decision-based attack that needs no gradients.

```python
from art.attacks.evasion import HopSkipJump

hsj = HopSkipJump(classifier=clf, targeted=False, max_iter=20, max_eval=1000)
x_bb = hsj.generate(x=x_test[:50])
bb_acc = float(np.mean(clf.predict(x_bb).argmax(1) == y_test[:50]))
print(f"black-box (HopSkipJump) robust acc: {bb_acc:.2%}")
```

### 5. Apply and validate defenses
Re-run steps 2–3 after each defense to confirm robust accuracy actually rises (and watch the clean-accuracy trade-off).

```python
from art.defences.trainer import AdversarialTrainerMadryPGD
from art.defences.preprocessor import SpatialSmoothing

# (a) Adversarial training (strongest general defense)
# trainer = AdversarialTrainerMadryPGD(clf, eps=0.1, eps_step=0.01, max_iter=40)
# trainer.fit(x_train, y_train_onehot, nb_epochs=...)

# (b) Input preprocessing as a defense layer
defense = SpatialSmoothing(window_size=3)
x_def, _ = defense(x_adv)
def_acc = float(np.mean(clf.predict(x_def).argmax(1) == y_test))
print(f"robust acc with preprocessing defense: {def_acc:.2%}")
```

### 6. Report the robustness profile
Produce a table of clean vs. robust accuracy across `ε` for each attack and defense, plus the `ε` at which robust accuracy drops below your acceptance threshold. That profile — not clean accuracy alone — is the deployment gate. The included `scripts/agent.py` runs this sweep on a demo model and emits the table.

## Tools and Resources

| Resource | Link |
|----------|------|
| MITRE ATLAS AML.T0043 Craft Adversarial Data | https://atlas.mitre.org/techniques/AML.T0043 |
| MITRE ATLAS AML.T0015 Evade ML Model | https://atlas.mitre.org/techniques/AML.T0015 |
| Adversarial Robustness Toolbox (ART) | https://github.com/Trusted-AI/adversarial-robustness-toolbox |
| ART evasion attacks docs | https://adversarial-robustness-toolbox.readthedocs.io/ |
| NIST AI Risk Management Framework | https://www.nist.gov/itl/ai-risk-management-framework |

## Attack Reference

| Attack | Knowledge | Budget | Use |
|--------|-----------|--------|-----|
| FGSM | White-box | `L∞` | Fast first look at fragility |
| PGD | White-box | `L∞`/`L2` | Standard strong robustness benchmark |
| C&W | White-box | `L2` | Minimal-perturbation evasions |
| HopSkipJump | Black-box (decision) | `L2`/`L∞` | Query-only threat model |
| Boundary / ZOO | Black-box | `L2` | Score/decision-based, no gradients |

## Validation Criteria

- [ ] Model wrapped as an ART estimator; clean accuracy recorded.
- [ ] PGD robust accuracy measured at the deployment-relevant `ε`.
- [ ] Robust accuracy swept across a range of `ε` (curve, not a point).
- [ ] Black-box attack run if the threat model is query-only.
- [ ] At least one defense applied and re-measured for robust-accuracy gain and clean-accuracy cost.
- [ ] A robustness profile (clean vs. robust across `ε`) produced and used as the deployment gate.
