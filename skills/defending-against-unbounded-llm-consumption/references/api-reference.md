# Unbounded Consumption Defense — Helper / API Reference

The companion `scripts/agent.py` analyzes an LLM usage log for denial-of-wallet /
denial-of-service patterns. Pure Python stdlib — no dependencies.

## CLI

| Command | Purpose |
|---------|---------|
| `agent.py analyze --log usage.jsonl` | Aggregate per-principal tokens/cost and flag anomalies |
| `agent.py analyze --log usage.jsonl --price-in 0.003 --price-out 0.015` | Override per-1K-token pricing |
| `agent.py analyze --log usage.jsonl --max-cost 5.0` | Set the per-principal/window cost ceiling |

## Usage log format (JSONL — one object per line)

```json
{"ts": 1700000000.0, "principal": "key-123",
 "prompt_tokens": 1200, "completion_tokens": 800}
```

## Detection signals

| Signal | Heuristic | Indicates |
|--------|-----------|-----------|
| Total cost per principal | Above `--max-cost` ceiling | Denial of wallet |
| Cost vs. cohort median | `> anomaly_factor * median` | Outlier spender |
| Mean output tokens | Far above typical | Output-amplification abuse |
| Request count in window | Above rate baseline | Flooding / DoS attempt |

## Enforcement primitives (from SKILL.md, for app integration)

| Primitive | Symbol |
|-----------|--------|
| Input cap | `MAX_INPUT_TOKENS`, `guard_request()` |
| Output cap | `MAX_OUTPUT_TOKENS` (provider `max_tokens`) |
| Rolling token budget | `TokenBudget.allow(principal, tokens)` |
| Agent recursion bound | `check_agent_budget(depth, calls)` |

## Pricing note

Token prices change and differ per model/provider. Pass `--price-in` / `--price-out`
(dollars per 1,000 tokens) to match your contract; defaults are illustrative only.

## External References

- OWASP LLM10:2025: https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/
- MITRE ATLAS AML.T0034 / AML.T0029: https://atlas.mitre.org/matrices/ATLAS
