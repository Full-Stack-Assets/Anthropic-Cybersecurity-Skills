#!/usr/bin/env python3
# For measuring/hardening robustness of models you own or are authorized to test.
# Evading a third party's classifier in production may be illegal and harmful.
"""Adversarial-evasion robustness sweep (MITRE ATLAS AML.T0043 / AML.T0015).

Runs an FGSM/PGD perturbation-budget sweep against a model and reports robust
accuracy vs. epsilon. By default it trains a small scikit-learn demo model on a
public dataset so the sweep runs with no user-supplied model; swap in your own
ART-wrapped estimator for real assessments.

Requires: pip install adversarial-robustness-toolbox scikit-learn numpy
"""
import argparse
import sys


def build_demo():
    import numpy as np
    from sklearn.datasets import load_breast_cancer
    from sklearn.preprocessing import StandardScaler
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    from art.estimators.classification import SklearnClassifier

    data = load_breast_cancer()
    x = StandardScaler().fit_transform(data.data).astype("float32")
    y = data.target
    x_tr, x_te, y_tr, y_te = train_test_split(x, y, test_size=0.3, random_state=42)
    model = LogisticRegression(max_iter=2000).fit(x_tr, y_tr)
    clf = SklearnClassifier(model=model)
    return clf, x_te, y_te


def make_attack(name, clf, eps):
    from art.attacks.evasion import FastGradientMethod, ProjectedGradientDescent
    eps = max(eps, 1e-6)
    if name == "fgsm":
        return FastGradientMethod(estimator=clf, eps=eps)
    return ProjectedGradientDescent(estimator=clf, eps=eps,
                                    eps_step=max(eps / 10, 1e-6), max_iter=40)


def cmd_sweep(args):
    try:
        import numpy as np
    except ImportError:
        print("[!] install: pip install adversarial-robustness-toolbox scikit-learn numpy",
              file=sys.stderr)
        return 1
    try:
        clf, x_te, y_te = build_demo()
    except ImportError:
        print("[!] install: pip install adversarial-robustness-toolbox scikit-learn numpy",
              file=sys.stderr)
        return 1

    eps_list = [float(e) for e in args.eps.split(",")]
    clean = float(np.mean(clf.predict(x_te).argmax(1) == y_te))
    print(f"[+] attack: {args.attack}   clean accuracy: {clean:.2%}\n")
    print(f"{'EPS':<8}{'ROBUST_ACC':<12}DROP")
    rows = []
    for eps in eps_list:
        if eps <= 0:
            acc = clean
        else:
            atk = make_attack(args.attack, clf, eps)
            x_adv = atk.generate(x=x_te)
            acc = float(np.mean(clf.predict(x_adv).argmax(1) == y_te))
        drop = clean - acc
        rows.append((eps, acc))
        bar = "#" * int(drop * 40)
        print(f"{eps:<8}{acc:<12.2%}{bar}")

    below = [e for e, a in rows if a < args.threshold]
    if below:
        print(f"\n[!] robust accuracy falls below {args.threshold:.0%} "
              f"at eps >= {min(below)}")
    else:
        print(f"\n[+] robust accuracy stays >= {args.threshold:.0%} across the sweep")
    return 0


def main():
    p = argparse.ArgumentParser(description="Adversarial-evasion robustness sweep")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sweep", help="robust accuracy vs. epsilon")
    s.add_argument("--attack", choices=["fgsm", "pgd"], default="pgd")
    s.add_argument("--eps", default="0.0,0.02,0.05,0.1,0.2",
                   help="comma-separated epsilon budgets")
    s.add_argument("--threshold", type=float, default=0.5,
                   help="acceptable robust-accuracy floor")
    s.set_defaults(func=cmd_sweep)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
