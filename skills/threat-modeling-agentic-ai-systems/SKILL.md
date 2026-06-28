---
name: threat-modeling-agentic-ai-systems
description: Threat model autonomous and multi-agent AI systems (planners, tool-callers, MCP clients, agent-to-agent networks) using the MAESTRO layered methodology and the OWASP Agentic Threats taxonomy to enumerate goal manipulation, tool misuse, memory poisoning, and excessive-agency risks, then drive controls and tests from the findings.
domain: cybersecurity
subdomain: ai-security
tags:
- ai-security
- agentic-ai
- threat-modeling
- maestro
- owasp-agentic
- llm-agents
- mcp
- excessive-agency
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- MAP-1.1
- GOVERN-1.3
mitre_attack:
- AML.T0051
- AML.T0053
- AML.T0054
---
# Threat Modeling Agentic AI Systems

> **Scope:** This skill is a defensive design activity. It enumerates how an autonomous agent could be abused so you can build controls *before* deployment. It does not require attacking a live system; where it suggests adversarial probing, do that only against agents you own or are authorized to test.

## Overview

An *agentic* AI system is one where an LLM does more than answer a prompt: it **plans**, **calls tools/APIs**, **reads and writes memory**, and often **coordinates with other agents** — frequently over the Model Context Protocol (MCP) or an agent-to-agent (A2A) bus. Each of those capabilities is also an attack surface. A classic prompt-injection string that is harmless in a chatbot becomes a privilege-escalation primitive when the model on the other end can call `delete_file`, transfer funds, or spawn sub-agents.

Traditional threat modeling (STRIDE on a static data-flow diagram) under-models these systems because the *trust boundary moves at runtime*: untrusted content retrieved by the agent can become instructions, and the agent's autonomy means a single bad decision cascades through many tool calls. This skill uses two AI-native frameworks together:

- **MAESTRO** (Multi-Agent Environment, Security, Threat, Risk, and Outcome) — a 7-layer reference model from the Cloud Security Alliance for reasoning about agentic risk layer by layer (Foundation Model → Data Operations → Agent Frameworks → Deployment Infra → Evaluation/Observability → Security/Compliance → Agent Ecosystem).
- **OWASP Agentic AI – Threats and Mitigations** — a concrete taxonomy of agentic threats (T1 Memory Poisoning, T2 Tool Misuse, T3 Privilege Compromise, T6 Intent Breaking & Goal Manipulation, T9 Identity Spoofing, etc.) that maps to real controls.

The output is a prioritized threat register that feeds directly into the matching MITRE ATLAS techniques — **AML.T0051 (LLM Prompt Injection)**, **AML.T0053 (LLM Plugin Compromise)**, and **AML.T0054 (LLM Jailbreak)** — and into the NIST AI RMF MAP function (MAP-1.1, establishing context and risk) and GOVERN-1.3 (risk management processes).

## When to Use

- Before deploying any LLM agent that can call tools, browse, execute code, or move money.
- When adding MCP servers / plugins to an existing agent and you need to assess the new tool surface.
- When designing a multi-agent (orchestrator + workers, or A2A) topology and need to reason about cross-agent trust.
- During architecture review or a security gate for an AI feature.
- When an incident in an agent occurred and you need a structured model to find what else is exposed.

## Prerequisites

- An architecture description of the agent: which model, what tools/MCP servers, what memory store, what data sources it retrieves, what other agents it talks to, and what it is allowed to do without a human.
- Python 3.9+ for the included register/scoring helper (pure stdlib).
- Familiarity with the agent's identity model (whose credentials does the agent act under for each tool?).

## Objectives

- Draw the agentic data-flow: identify every place untrusted data can enter and every place the agent can take a consequential action.
- Walk the 7 MAESTRO layers and enumerate threats per layer.
- Map each threat to an OWASP Agentic threat ID and a MITRE ATLAS technique.
- Score threats (likelihood × impact, weighted by the agent's autonomy) and rank them.
- Emit a control list: human-in-the-loop gates, tool allow-lists, least-privilege per-tool identity, memory provenance, and output mediation.

## MITRE ATT&CK Mapping

| ID (MITRE ATLAS) | Name | Tactic | Where it shows up |
|----|------|--------|-------------------|
| AML.T0051 | LLM Prompt Injection | Initial Access / Execution | Untrusted retrieved content or tool output becomes instructions |
| AML.T0053 | LLM Plugin Compromise | Execution / Privilege Escalation | A tool/plugin/MCP server is abused or itself malicious (T2 Tool Misuse) |
| AML.T0054 | LLM Jailbreak | Defense Evasion | Goal manipulation / guardrail bypass (T6 Intent Breaking) |

## Workflow

### 1. Inventory the agentic surface
List, concretely, the components an attacker can reach or influence. This is the agentic equivalent of a data-flow diagram.

| Element | Capture |
|---------|---------|
| Model | Provider/version, system prompt, tool schema exposed |
| Tools / MCP servers | Each tool name, what it does, what identity it runs as, reversibility |
| Memory | Short-term (context) and long-term (vector store / DB); who can write to it |
| Untrusted inputs | User input, retrieved documents, web pages, tool outputs, other agents |
| Autonomy | Which actions execute with NO human approval |

### 2. Walk the MAESTRO layers
For each of the 7 layers, ask "how could this be subverted?" The included script ships a starter catalog; extend it per system.

```python
MAESTRO_LAYERS = {
    "L1 Foundation Model":      ["jailbreak / unsafe completion (AML.T0054)",
                                 "hallucinated tool args"],
    "L2 Data Operations":       ["memory poisoning (OWASP T1)",
                                 "RAG indirect injection (AML.T0051)"],
    "L3 Agent Frameworks":      ["tool misuse / unsafe tool chaining (OWASP T2, AML.T0053)",
                                 "goal manipulation (OWASP T6)"],
    "L4 Deployment Infra":      ["over-permissioned tool credentials (OWASP T3)",
                                 "secret exposure to the model"],
    "L5 Evaluation/Observability": ["no audit trail of tool calls",
                                    "prompt/response not logged"],
    "L6 Security & Compliance": ["no human-in-the-loop on high-impact actions",
                                 "policy not enforced at tool boundary"],
    "L7 Agent Ecosystem":       ["agent identity spoofing (OWASP T9)",
                                 "rogue / compromised peer agent (A2A)"],
}
```

### 3. Map threats to taxonomy and frameworks
Each enumerated threat gets an OWASP Agentic ID, a MITRE ATLAS technique, and a one-line attack path. The mapping is what makes the model actionable — it ties an abstract risk to a known technique and a known control family.

### 4. Score and rank
Score each threat with likelihood (1–5) × impact (1–5), then multiply by an **autonomy factor** (1.0 if a human approves the action, up to 2.0 if the agent acts fully autonomously and irreversibly). Irreversible + autonomous + high impact rises to the top.

```python
def risk_score(likelihood, impact, autonomy_factor):
    # autonomy_factor in [1.0, 2.0]: higher when the agent acts with no human gate
    return round(likelihood * impact * autonomy_factor, 1)
```

### 5. Derive controls
Map the top threats to concrete, testable controls:

| Threat class | Primary control |
|--------------|-----------------|
| Prompt/indirect injection (AML.T0051) | Treat all retrieved/tool content as untrusted data, never instructions; spotlighting/delimiting; output mediation |
| Tool misuse (AML.T0053, OWASP T2) | Per-tool allow-list, typed/validated arguments, dry-run + human approval for destructive tools |
| Excessive agency (OWASP T3) | Least-privilege identity *per tool*, short-lived scoped tokens, spend/rate caps |
| Memory poisoning (OWASP T1) | Provenance + signing on long-term memory writes; quarantine untrusted writes |
| Goal manipulation (AML.T0054, OWASP T6) | Immutable system goals, plan validation, guardrails on the planner |
| Identity spoofing (OWASP T9, A2A) | Mutual auth between agents, signed messages, agent identity registry |

### 6. Produce the register and feed the SDLC
Emit the ranked register as JSON/Markdown, attach it to the design doc, and turn the top items into red-team test cases (see `continuous-llm-red-teaming-with-promptfoo` and `securing-agentic-ai-tool-invocation`) and into runtime guardrails.

## Tools and Resources

| Resource | Link |
|----------|------|
| MITRE ATLAS Matrix | https://atlas.mitre.org/matrices/ATLAS |
| MITRE ATLAS AML.T0051 LLM Prompt Injection | https://atlas.mitre.org/techniques/AML.T0051 |
| OWASP Agentic AI – Threats and Mitigations | https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/ |
| OWASP Top 10 for LLM Applications | https://genai.owasp.org/llm-top-10/ |
| CSA MAESTRO threat modeling framework | https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro |
| NIST AI Risk Management Framework | https://www.nist.gov/itl/ai-risk-management-framework |

## Agentic Threat Reference

| OWASP ID | Threat | MAESTRO layer | ATLAS |
|----------|--------|---------------|-------|
| T1 | Memory Poisoning | L2 Data Operations | AML.T0051 |
| T2 | Tool Misuse | L3 Agent Frameworks | AML.T0053 |
| T3 | Privilege Compromise / Excessive Agency | L4 Deployment Infra | AML.T0053 |
| T6 | Intent Breaking & Goal Manipulation | L3 Agent Frameworks | AML.T0054 |
| T9 | Identity Spoofing & Impersonation | L7 Agent Ecosystem | AML.T0051 |

## Validation Criteria

- [ ] Every tool/MCP server the agent can call is inventoried with its runtime identity and reversibility.
- [ ] All 7 MAESTRO layers walked; at least one threat enumerated or explicitly ruled out per layer.
- [ ] Each threat mapped to an OWASP Agentic ID and a MITRE ATLAS technique.
- [ ] Threats scored with an autonomy factor; the register is ranked.
- [ ] Every high-impact autonomous action has a human-in-the-loop or hard guardrail.
- [ ] Tool credentials are least-privilege and per-tool, not a single shared god-token.
- [ ] Top threats converted into red-team test cases and runtime controls.
