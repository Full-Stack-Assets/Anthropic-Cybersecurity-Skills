# Agentic Threat Modeling — Helper / API Reference

The companion `scripts/agent.py` is pure Python stdlib — no external dependencies — so it runs in any review environment.

## CLI

| Command | Purpose |
|---------|---------|
| `agent.py catalog` | Print the starter MAESTRO threat catalog (per-layer threats with OWASP/ATLAS mappings) |
| `agent.py score --input threats.json` | Score and rank a threat register (likelihood × impact × autonomy) |
| `agent.py template --output threats.json` | Emit a fillable threat-register template |

## Threat register schema (JSON)

```json
{
  "system": "string — name of the agent system",
  "threats": [
    {
      "id": "string",
      "layer": "L1..L7 MAESTRO layer",
      "owasp": "T1..T10",
      "atlas": "AML.T0051",
      "description": "attack path in one line",
      "likelihood": 1,
      "impact": 5,
      "autonomy_factor": 1.5,
      "control": "primary mitigation"
    }
  ]
}
```

## Scoring model

| Field | Range | Meaning |
|-------|-------|---------|
| `likelihood` | 1–5 | How reachable / probable the attack is |
| `impact` | 1–5 | Blast radius if it succeeds |
| `autonomy_factor` | 1.0–2.0 | 1.0 = human approves the action; 2.0 = fully autonomous + irreversible |
| `score` (derived) | — | `likelihood * impact * autonomy_factor`, rounded to 1 dp |

Ranking is descending by `score`; ties broken by `impact`.

## Autonomy factor guidance

| Action character | Suggested factor |
|------------------|------------------|
| Read-only, human-approved | 1.0 |
| Reversible write, human-approved | 1.2 |
| Reversible write, autonomous | 1.5 |
| Irreversible / external effect, autonomous | 2.0 |

## External References

- OWASP Agentic AI Threats: https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/
- CSA MAESTRO: https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro
- MITRE ATLAS: https://atlas.mitre.org/matrices/ATLAS
