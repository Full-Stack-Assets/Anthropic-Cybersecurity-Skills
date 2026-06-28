#!/usr/bin/env python3
# Defensive design aid for threat-modeling AI agents you own or are authorized to assess.
"""Agentic AI threat-modeling helper.

Three modes (pure stdlib — no external dependencies):

  catalog   - Print a starter MAESTRO threat catalog (per-layer threats with
              OWASP Agentic and MITRE ATLAS mappings) to seed a model.
  template  - Emit a fillable threat-register JSON template.
  score     - Load a completed register, compute risk scores
              (likelihood * impact * autonomy_factor) and print a ranked table.

Register schema: see references/api-reference.md.
"""
import argparse
import json
import sys

# Starter catalog: MAESTRO layer -> list of (description, owasp, atlas, control)
MAESTRO_CATALOG = {
    "L1 Foundation Model": [
        ("Jailbreak / unsafe completion redirects the agent", "T6", "AML.T0054",
         "Guardrails on planner; immutable system goals"),
        ("Hallucinated tool arguments cause wrong action", "T5", "AML.T0054",
         "Typed/validated tool args; dry-run preview"),
    ],
    "L2 Data Operations": [
        ("Long-term memory poisoned by untrusted write", "T1", "AML.T0051",
         "Provenance + signing on memory writes; quarantine"),
        ("Indirect prompt injection via retrieved document", "T1", "AML.T0051",
         "Treat retrieved content as data, not instructions; spotlighting"),
    ],
    "L3 Agent Frameworks": [
        ("Tool misuse / unsafe tool chaining", "T2", "AML.T0053",
         "Per-tool allow-list; human approval for destructive tools"),
        ("Goal manipulation redirects the plan", "T6", "AML.T0054",
         "Plan validation; immutable goals"),
    ],
    "L4 Deployment Infra": [
        ("Over-permissioned tool credentials (excessive agency)", "T3", "AML.T0053",
         "Least-privilege per-tool identity; short-lived scoped tokens"),
        ("Secrets exposed to the model context", "T3", "AML.T0053",
         "Secret broker outside the prompt; never inline credentials"),
    ],
    "L5 Evaluation/Observability": [
        ("No audit trail of tool calls (repudiation)", "T8", "AML.T0053",
         "Immutable, signed tool-call + prompt/response logs"),
    ],
    "L6 Security & Compliance": [
        ("No human-in-the-loop on high-impact action", "T3", "AML.T0053",
         "Mandatory approval gate for irreversible/external effects"),
    ],
    "L7 Agent Ecosystem": [
        ("Peer agent identity spoofing (A2A)", "T9", "AML.T0051",
         "Mutual auth + signed messages; agent identity registry"),
        ("Rogue / compromised peer agent", "T9", "AML.T0053",
         "Zero-trust between agents; validate peer outputs as untrusted"),
    ],
}


def cmd_catalog(_args):
    for layer, threats in MAESTRO_CATALOG.items():
        print(f"\n=== {layer} ===")
        for desc, owasp, atlas, control in threats:
            print(f"  [{owasp:<3} {atlas}] {desc}")
            print(f"        control: {control}")
    return 0


def cmd_template(args):
    register = {"system": "REPLACE-ME", "threats": []}
    for layer, threats in MAESTRO_CATALOG.items():
        for i, (desc, owasp, atlas, control) in enumerate(threats):
            register["threats"].append({
                "id": f"{layer.split()[0]}-{i+1}",
                "layer": layer,
                "owasp": owasp,
                "atlas": atlas,
                "description": desc,
                "likelihood": 3,
                "impact": 3,
                "autonomy_factor": 1.5,
                "control": control,
            })
    out = json.dumps(register, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"[+] template written to {args.output} "
              f"({len(register['threats'])} starter threats)")
    else:
        print(out)
    return 0


def risk_score(likelihood, impact, autonomy_factor):
    return round(float(likelihood) * float(impact) * float(autonomy_factor), 1)


def cmd_score(args):
    try:
        with open(args.input, "r", encoding="utf-8") as fh:
            register = json.load(fh)
    except (IOError, json.JSONDecodeError) as exc:
        print(f"[!] could not load register: {exc}", file=sys.stderr)
        return 1

    threats = register.get("threats", [])
    if not threats:
        print("[!] register has no 'threats'", file=sys.stderr)
        return 1

    for t in threats:
        t["score"] = risk_score(t.get("likelihood", 1), t.get("impact", 1),
                                t.get("autonomy_factor", 1.0))
    ranked = sorted(threats, key=lambda t: (-t["score"], -t.get("impact", 0)))

    print(f"[+] system: {register.get('system', '?')}  "
          f"({len(ranked)} threats)\n")
    print(f"{'SCORE':<7}{'OWASP':<7}{'ATLAS':<13}{'LAYER':<24}DESCRIPTION")
    for t in ranked:
        print(f"{t['score']:<7}{t.get('owasp',''):<7}{t.get('atlas',''):<13}"
              f"{t.get('layer','')[:23]:<24}{t.get('description','')[:50]}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump({"system": register.get("system"), "threats": ranked},
                      fh, indent=2)
        print(f"\n[+] ranked register written to {args.output}")
    return 0


def main():
    p = argparse.ArgumentParser(description="Agentic AI threat-modeling helper")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("catalog", help="print starter MAESTRO threat catalog")
    c.set_defaults(func=cmd_catalog)

    t = sub.add_parser("template", help="emit a fillable threat-register template")
    t.add_argument("--output", help="write JSON template to path")
    t.set_defaults(func=cmd_template)

    s = sub.add_parser("score", help="score and rank a completed register")
    s.add_argument("--input", required=True, help="path to register JSON")
    s.add_argument("--output", help="write ranked register JSON")
    s.set_defaults(func=cmd_score)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
