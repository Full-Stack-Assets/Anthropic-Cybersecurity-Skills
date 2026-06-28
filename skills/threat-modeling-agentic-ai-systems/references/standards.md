# Standards and References — Threat Modeling Agentic AI Systems

## MITRE ATLAS Techniques

| ID | Name | Tactic | Rationale |
|----|------|--------|-----------|
| AML.T0051 | LLM Prompt Injection | Initial Access / Execution | Untrusted retrieved content, tool output, or memory becomes instructions to the agent. |
| AML.T0053 | LLM Plugin Compromise | Execution / Privilege Escalation | A tool / plugin / MCP server is abused or is itself malicious — the core of agentic tool misuse. |
| AML.T0054 | LLM Jailbreak | Defense Evasion | Goal manipulation and guardrail bypass that redirect the agent's plan. |

## NIST AI RMF

| ID | Function | Rationale |
|----|----------|-----------|
| MAP-1.1 | Context is established and understood | Inventorying the agentic surface and establishing trust boundaries is the MAP context activity. |
| GOVERN-1.3 | Risk management processes are in place | A ranked agentic threat register operationalizes governance over AI risk. |

## OWASP Agentic AI — Threats and Mitigations

| ID | Threat |
|----|--------|
| T1 | Memory Poisoning |
| T2 | Tool Misuse |
| T3 | Privilege Compromise (Excessive Agency) |
| T4 | Resource Overload |
| T5 | Cascading Hallucination |
| T6 | Intent Breaking & Goal Manipulation |
| T7 | Misaligned & Deceptive Behaviors |
| T8 | Repudiation & Untraceability |
| T9 | Identity Spoofing & Impersonation |
| T10 | Overwhelming Human-in-the-Loop |

## MAESTRO Layers (CSA)

1. Foundation Model
2. Data Operations
3. Agent Frameworks
4. Deployment Infrastructure
5. Evaluation & Observability
6. Security & Compliance
7. Agent Ecosystem

## Official Resources

- MITRE ATLAS Matrix: https://atlas.mitre.org/matrices/ATLAS
- OWASP Agentic AI Threats and Mitigations: https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/
- OWASP Top 10 for LLM Applications: https://genai.owasp.org/llm-top-10/
- CSA MAESTRO framework: https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro
- NIST AI Risk Management Framework: https://www.nist.gov/itl/ai-risk-management-framework

## Related Skills

- `securing-agentic-ai-tool-invocation` — runtime controls for the tool-call boundary
- `auditing-mcp-servers-for-tool-poisoning` — assessing individual MCP servers
- `continuous-llm-red-teaming-with-promptfoo` — turning threats into automated tests
