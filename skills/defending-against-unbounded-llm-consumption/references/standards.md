# Standards and References — Defending Against Unbounded LLM Consumption

## MITRE ATLAS Techniques

| ID | Name | Tactic | Rationale |
|----|------|--------|-----------|
| AML.T0034 | Cost Harvesting | Impact | Forcing the victim to incur inference cost — the "denial of wallet" angle. |
| AML.T0029 | Denial of ML Service | Impact | Exhausting model throughput so legitimate users are degraded or blocked. |

## NIST AI RMF

| ID | Function | Rationale |
|----|----------|-----------|
| MANAGE-2.1 | Resources are allocated to manage AI risks | Budgets, rate/concurrency limits, and recursion bounds are the managed controls. |
| MEASURE-2.6 | AI system security and resilience are evaluated | Load-testing and cost-anomaly detection measure resilience to consumption abuse. |

## OWASP Top 10 for LLM Applications (2025)

| ID | Risk | Relevance |
|----|------|-----------|
| LLM10:2025 | Unbounded Consumption | Primary mapping: DoS + denial of wallet via uncapped inference cost. |
| LLM04:2025 | Data and Model Poisoning | (Adjacent) different risk; not covered here. |

## Attack Primitives

| Primitive | Effect |
|-----------|--------|
| Oversized input context | High input-token cost per request |
| Output-amplifying prompt ("repeat forever") | High output-token cost |
| Request flooding | Throughput exhaustion (DoS) |
| High concurrency | GPU/queue exhaustion (DoS) |
| Slow-drip under the rate limit | Cumulative DoW |
| Recursive / fan-out agent loops | One request → many model calls |

## Official Resources

- OWASP LLM10:2025 Unbounded Consumption: https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/
- OWASP Top 10 for LLM Applications: https://genai.owasp.org/llm-top-10/
- MITRE ATLAS AML.T0034: https://atlas.mitre.org/techniques/AML.T0034
- MITRE ATLAS AML.T0029: https://atlas.mitre.org/techniques/AML.T0029
- NIST AI Risk Management Framework: https://www.nist.gov/itl/ai-risk-management-framework

## Related Skills

- `detecting-model-extraction-attacks` — another form of inference-API abuse (per-principal query monitoring overlaps)
- `securing-agentic-ai-tool-invocation` — bounding agent tool calls
- `threat-modeling-agentic-ai-systems` — where resource overload (OWASP Agentic T4) is enumerated
