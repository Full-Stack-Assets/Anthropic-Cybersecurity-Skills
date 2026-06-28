---
name: defending-against-unbounded-llm-consumption
description: Detect and defend against unbounded-consumption attacks on LLM applications (OWASP LLM10:2025) — denial of service and "denial of wallet" via floods of expensive requests, oversized inputs, output-amplifying prompts, and recursive agent loops — using per-principal token budgets, rate and concurrency limits, input/output caps, and cost-anomaly alerting.
domain: cybersecurity
subdomain: ai-security
tags:
- ai-security
- llm-security
- denial-of-service
- denial-of-wallet
- rate-limiting
- token-budget
- owasp-llm10
- cost-anomaly
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- MANAGE-2.1
- MEASURE-2.6
mitre_attack:
- AML.T0034
- AML.T0029
---
# Defending Against Unbounded LLM Consumption

> **Authorized Use Only:** The load-generation snippets here are for testing the resilience of LLM services **you own or are authorized to test**. Sending floods of expensive requests at a third-party model is an attack and may violate terms of service and law.

## Overview

LLM inference is unusually expensive per request and the cost is *attacker-controllable*: a single crafted prompt can force the model to read a huge context, emit thousands of output tokens, or trigger a long chain of tool calls. **OWASP LLM10:2025 — Unbounded Consumption** captures this risk family, which has two faces:

- **Denial of Service (DoS):** exhaust GPU/throughput so legitimate users are degraded or blocked.
- **Denial of Wallet (DoW):** drive up the per-token bill on a pay-as-you-go model API until the budget is exhausted — financially damaging even when availability holds.

MITRE ATLAS maps the wallet angle to **AML.T0034 — Cost Harvesting** (forcing the victim to incur inference cost) and the availability angle to **AML.T0029 — Denial of ML Service**. The attack primitives are concrete: very long inputs, "repeat X forever" / verbose-output prompts, high request rates, high concurrency, and — in agentic systems — recursive or fan-out tool loops that multiply one user request into hundreds of model calls.

Defense is layered and quantitative: cap input size, cap output (`max_tokens`), enforce **per-principal token budgets** (not just request-rate), limit concurrency, bound agent recursion, and alert on cost/usage anomalies before the bill lands. This skill aligns with the NIST AI RMF MANAGE-2.1 (managing AI risks) and MEASURE-2.6 (security and resilience) functions.

## When to Use

- When exposing an LLM endpoint (chat, RAG, agent, or completion API) to users or partners.
- When your LLM spend is metered per token and an attacker (or a buggy client) could inflate it.
- When an agent can call itself, fan out to sub-agents, or loop over tools without a hard bound.
- After an unexplained cost or latency spike, to add the controls that would have contained it.
- When load- or resilience-testing your own LLM service before launch.

## Prerequisites

- Python 3.9+ (the helper is pure stdlib for log analysis; the load demo uses `requests`/your client).
- Access to request logs with per-principal tokens (prompt + completion) and timestamps.
- Knowledge of your provider's pricing (cost per 1K input/output tokens) to convert tokens to dollars.
- A place to enforce limits: a gateway/proxy, middleware, or the app layer in front of the model.

## Objectives

- Identify the consumption attack surface: input size, output size, request rate, concurrency, agent recursion.
- Instrument per-principal token + cost accounting.
- Enforce input caps, output caps (`max_tokens`), token budgets, rate and concurrency limits, and recursion bounds.
- Build a cost-anomaly detector that flags principals whose spend deviates from baseline.
- Validate controls with a (self-authorized) load test that confirms limits trip before damage.

## MITRE ATT&CK Mapping

| ID (MITRE ATLAS) | Name | Tactic | Where it shows up |
|----|------|--------|-------------------|
| AML.T0034 | Cost Harvesting | Impact | Forcing the victim to incur inference cost (denial of wallet) |
| AML.T0029 | Denial of ML Service | Impact | Exhausting throughput so the service degrades (denial of service) |

## Workflow

### 1. Map the consumption surface
Enumerate every attacker-controllable cost lever and the cap that should bound it.

| Lever | Attack | Control |
|-------|--------|---------|
| Input length | Paste a 200K-token document | Reject/ truncate above an input-token cap |
| Output length | "Write 50,000 words…" | Enforce `max_tokens` per response |
| Request rate | Rapid-fire requests | Per-principal rate limit |
| Concurrency | Many parallel requests | Per-principal concurrency cap |
| Agent recursion | Self-calling / fan-out loops | Hard depth + total-call budget |
| Total spend | Slow drip under the rate limit | Per-principal token/cost budget window |

### 2. Instrument per-principal token + cost accounting
Log tokens per request and convert to cost. Rate-limiting requests alone misses DoW: 10 requests of 100K tokens each cost far more than 1,000 tiny ones.

```python
PRICE_IN = 0.003 / 1000    # $ per input token (example)
PRICE_OUT = 0.015 / 1000   # $ per output token (example)

def request_cost(prompt_tokens, completion_tokens):
    return prompt_tokens * PRICE_IN + completion_tokens * PRICE_OUT
```

### 3. Enforce hard input and output caps
Reject oversized inputs *before* they reach the model, and always set `max_tokens`. An unset output cap is the single most common DoW hole.

```python
MAX_INPUT_TOKENS = 8000
MAX_OUTPUT_TOKENS = 1024

def guard_request(prompt_tokens, requested_max_tokens):
    if prompt_tokens > MAX_INPUT_TOKENS:
        raise ValueError(f"input {prompt_tokens} exceeds cap {MAX_INPUT_TOKENS}")
    return min(requested_max_tokens or MAX_OUTPUT_TOKENS, MAX_OUTPUT_TOKENS)
```

### 4. Enforce per-principal token budgets + rate/concurrency limits
Track a rolling token budget per principal and reject once exhausted. Combine with a request-rate limit and a concurrency semaphore.

```python
import time, collections

class TokenBudget:
    """Rolling per-principal token budget over a time window."""
    def __init__(self, max_tokens, window_s=3600):
        self.max_tokens, self.window = max_tokens, window_s
        self.usage = collections.defaultdict(list)  # principal -> [(ts, tokens)]

    def allow(self, principal, tokens, now=None):
        now = now if now is not None else time.time()
        hist = [(t, n) for (t, n) in self.usage[principal] if now - t < self.window]
        spent = sum(n for _, n in hist)
        if spent + tokens > self.max_tokens:
            return False
        hist.append((now, tokens))
        self.usage[principal] = hist
        return True
```

### 5. Bound agent recursion and fan-out
For agentic systems, a single user turn must not be able to spawn unbounded model calls. Enforce both a recursion depth and a total per-turn call budget.

```python
MAX_DEPTH = 5
MAX_CALLS_PER_TURN = 25

def check_agent_budget(depth, calls_this_turn):
    if depth > MAX_DEPTH:
        raise RuntimeError("agent recursion depth exceeded")
    if calls_this_turn > MAX_CALLS_PER_TURN:
        raise RuntimeError("agent per-turn call budget exceeded")
```

### 6. Detect cost anomalies
Baseline each principal's normal hourly token spend and flag deviations (e.g., > N× median or > a static ceiling). Wire alerts to your SIEM so DoW is caught in minutes, not on the monthly invoice. The included `scripts/agent.py` does this from a usage log.

### 7. Validate with a self-authorized load test
Confirm that input caps reject oversized prompts, `max_tokens` truncates output, the budget trips, and the anomaly detector fires — *before* an attacker finds the gaps.

## Tools and Resources

| Resource | Link |
|----------|------|
| OWASP LLM10:2025 Unbounded Consumption | https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/ |
| OWASP Top 10 for LLM Applications | https://genai.owasp.org/llm-top-10/ |
| MITRE ATLAS AML.T0034 Cost Harvesting | https://atlas.mitre.org/techniques/AML.T0034 |
| MITRE ATLAS AML.T0029 Denial of ML Service | https://atlas.mitre.org/techniques/AML.T0029 |
| NIST AI Risk Management Framework | https://www.nist.gov/itl/ai-risk-management-framework |

## Control Reference

| Control | Bounds | Stops |
|---------|--------|-------|
| Input-token cap | Prompt size | Oversized-context DoW |
| `max_tokens` output cap | Response size | Verbose-output DoW |
| Per-principal rate limit | Requests / window | Request floods |
| Concurrency semaphore | Parallel in-flight | GPU exhaustion DoS |
| Token/cost budget window | Total spend / window | Slow-drip DoW |
| Agent depth + call budget | Model calls / turn | Recursive-loop amplification |
| Cost-anomaly alert | Detection | Catching DoW before the invoice |

## Validation Criteria

- [ ] Input-token cap rejects oversized prompts before they reach the model.
- [ ] Every model call sets an explicit `max_tokens`.
- [ ] Per-principal token/cost budget enforced over a rolling window (not just request rate).
- [ ] Request-rate and concurrency limits enforced per principal.
- [ ] Agent recursion depth and per-turn call budget are hard-bounded.
- [ ] Cost-anomaly detector baselines per-principal spend and alerts to SIEM.
- [ ] Controls validated by a self-authorized load test.
