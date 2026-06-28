# Adversarial Evasion Testing — API / Library Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| adversarial-robustness-toolbox | `pip install adversarial-robustness-toolbox` | Evasion attacks + defenses |
| scikit-learn | `pip install scikit-learn` | Demo classifiers, metrics |
| numpy | `pip install numpy` | Array / accuracy math |
| torch / tensorflow | optional | Deep-learning model wrappers |

## ART Evasion Attacks (`art.attacks.evasion`)

| Class | Key params | Knowledge |
|-------|-----------|-----------|
| `FastGradientMethod` | `eps`, `norm` | White-box (single-step) |
| `ProjectedGradientDescent` | `eps`, `eps_step`, `max_iter`, `norm` | White-box (iterative, standard) |
| `CarliniL2Method` | `confidence`, `max_iter` | White-box (minimal L2) |
| `HopSkipJump` | `max_iter`, `max_eval`, `targeted` | Black-box (decision) |
| `ZooAttack` | `confidence`, `max_iter` | Black-box (score) |
| `BoundaryAttack` | `max_iter`, `delta`, `epsilon` | Black-box (decision) |

All expose `.generate(x=...)` returning adversarial inputs.

## ART Estimator Wrappers (`art.estimators.classification`)

| Class | Wraps |
|-------|-------|
| `SklearnClassifier` | scikit-learn models |
| `PyTorchClassifier` | torch.nn models (needs loss, optimizer, input_shape, nb_classes) |
| `KerasClassifier` / `TensorFlowV2Classifier` | Keras / TF models |

## ART Defenses

| Class | Module | Purpose |
|-------|--------|---------|
| `AdversarialTrainerMadryPGD` | `art.defences.trainer` | PGD adversarial training |
| `SpatialSmoothing` | `art.defences.preprocessor` | Input smoothing |
| `FeatureSqueezing` | `art.defences.preprocessor` | Reduce input precision |
| `JpegCompression` | `art.defences.preprocessor` | Compression defense (images) |

## Companion script (`scripts/agent.py`)

| Command | Purpose |
|---------|---------|
| `agent.py sweep` | Run FGSM/PGD robustness sweep on a built-in demo model |
| `agent.py sweep --eps 0.05,0.1,0.2` | Custom epsilon list |
| `agent.py sweep --attack fgsm` | Choose attack (fgsm \| pgd) |

The demo trains a scikit-learn classifier on a public dataset so the sweep runs
with no user-supplied model; swap in your own ART-wrapped estimator for real tests.

## Metric

`robust_accuracy(eps) = mean( argmax(clf.predict(x_adv(eps))) == y_true )`

## External References

- ART docs: https://adversarial-robustness-toolbox.readthedocs.io/
- MITRE ATLAS AML.T0043 / AML.T0015: https://atlas.mitre.org/matrices/ATLAS
