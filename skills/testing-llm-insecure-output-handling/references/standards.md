# Standards and References — Testing LLM Insecure Output Handling

## MITRE ATLAS Techniques

| ID | Name | Tactic | Rationale |
|----|------|--------|-----------|
| AML.T0051 | LLM Prompt Injection | Initial Access / Execution | Attacker plants (often via RAG/tool content) the payload the model later emits into a sink. |
| AML.T0053 | LLM Plugin Compromise | Execution / Privilege Escalation | A plugin/tool/downstream handler executes the model's unsanitized output. |

## NIST AI RMF

| ID | Function | Rationale |
|----|----------|-----------|
| MEASURE-2.7 | AI system security and resilience are evaluated | Probing each sink measures whether model output is safely handled. |
| MANAGE-2.1 | Resources are allocated to manage AI risks | Output encoding / parameterization / allow-listing are the managed controls. |

## OWASP Top 10 for LLM Applications (2025)

| ID | Risk | Relevance |
|----|------|-----------|
| LLM05:2025 | Improper Output Handling | Primary mapping: unsanitized model output reaching downstream sinks. |
| LLM01:2025 | Prompt Injection | The upstream channel that plants the malicious output. |

## Sink → Classic Vulnerability Map

| Sink | CWE / vuln |
|------|------------|
| HTML/DOM render | CWE-79 Cross-Site Scripting |
| SQL query | CWE-89 SQL Injection |
| Shell command | CWE-78 OS Command Injection |
| HTTP client URL | CWE-918 Server-Side Request Forgery |
| File path | CWE-22 Path Traversal |
| Template engine | CWE-1336 Server-Side Template Injection |

## Official Resources

- OWASP LLM05:2025 Improper Output Handling: https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/
- OWASP Top 10 for LLM Applications: https://genai.owasp.org/llm-top-10/
- OWASP XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- MITRE ATLAS: https://atlas.mitre.org/matrices/ATLAS
- NIST AI Risk Management Framework: https://www.nist.gov/itl/ai-risk-management-framework

## Related Skills

- `detecting-indirect-prompt-injection` — the upstream channel for RAG-borne payloads
- `testing-prompt-injection-in-rag-pipelines` — injection testing for RAG specifically
- `testing-for-broken-access-control` / web-app skills — downstream sink exploitation references
