---
name: testing-llm-insecure-output-handling
description: Test LLM-integrated applications for improper output handling (OWASP LLM05:2025) where unsanitized model output flows into downstream sinks and causes XSS, SSRF, SQL injection, path traversal, or command execution. Probe each sink with marker payloads, confirm where LLM text is trusted as code/markup, and apply context-aware output encoding and allow-listing.
domain: cybersecurity
subdomain: ai-security
tags:
- ai-security
- llm-security
- insecure-output-handling
- owasp-llm05
- xss
- ssrf
- output-encoding
- injection
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- MEASURE-2.7
- MANAGE-2.1
mitre_attack:
- AML.T0051
- AML.T0053
---
# Testing LLM Applications for Insecure Output Handling

> **Authorized Use Only:** Probe only applications you own or are authorized to test. The marker payloads here are designed to *prove* a sink is unsafe without causing damage — keep it that way; do not pivot a confirmed flaw into real exploitation outside an authorized engagement.

## Overview

**OWASP LLM05:2025 — Improper Output Handling** is the mirror image of prompt injection. Prompt injection is about what goes *into* the model; insecure output handling is about blindly trusting what comes *out*. An LLM's response is **untrusted, attacker-influenceable content** — yet applications routinely pipe it straight into a browser, a shell, a database query, an HTTP client, or the filesystem. When they do, classic web/OS vulnerabilities reappear *through* the model:

- LLM output rendered as HTML without encoding → **stored/reflected XSS**.
- LLM output used to build a URL the server fetches → **SSRF**.
- LLM output concatenated into SQL → **SQL injection**.
- LLM output used as a file path → **path traversal**.
- LLM output passed to `eval`/`exec`/a shell → **code/command execution**.

This is especially dangerous in **agentic** systems and RAG: an attacker plants a payload in a document or tool result (prompt injection, **AML.T0051**), the model echoes or transforms it, and the application's downstream handler — or a plugin/tool (**AML.T0053**) — executes it. The model becomes a confused deputy that smuggles an exploit past the app's input defenses, because developers treat model output as trusted.

The fix is the same principle as for any untrusted data: **context-aware output encoding, parameterization, and allow-listing at every sink** — treat LLM output exactly as you would treat raw user input. This skill systematically finds the sinks, proves which ones trust model output, and validates the encoding/validation that closes them. It maps to NIST AI RMF MEASURE-2.7 (security/resilience evaluation) and MANAGE-2.1 (managing the risk).

## When to Use

- When an LLM feature's output is rendered in a web UI, used in queries/commands, or drives server-side requests.
- When building or reviewing a RAG or agentic app where retrieved/tool content can reach the model and then a sink.
- During a security assessment or pre-launch gate for any LLM-integrated application.
- After fixing a prompt-injection issue — output handling is the second half of the same problem.
- When threat-modeling identified "LLM output reaches an interpreter/renderer."

## Prerequisites

- Python 3.9+ for the marker-payload harness (uses `requests` for live HTTP tests; the payload generator is stdlib).
- A map of the application's **output sinks**: where does model text end up? (DOM/HTML, SQL, shell, HTTP client, file path, template engine, `eval`.)
- A way to make the model emit attacker-chosen strings — directly (you control the prompt) or indirectly (via a document/tool the model summarizes).
- Authorization to test the target application.

## Objectives

- Enumerate every downstream sink that consumes LLM output.
- For each sink, induce the model to emit a context-specific marker payload and observe whether it is executed/interpreted or safely encoded.
- Classify confirmed flaws by sink type (XSS, SSRF, SQLi, path traversal, command exec).
- Apply and re-test context-aware encoding, parameterization, and allow-listing.

## MITRE ATT&CK Mapping

| ID (MITRE ATLAS) | Name | Tactic | Where it shows up |
|----|------|--------|-------------------|
| AML.T0051 | LLM Prompt Injection | Initial Access / Execution | Attacker plants the payload the model later emits |
| AML.T0053 | LLM Plugin Compromise | Execution / Privilege Escalation | A plugin/tool executes the model's unsanitized output |

## Workflow

### 1. Map the output sinks
Trace where model output flows. Each distinct sink is a separate test with its own payload context.

| Sink | Vulnerability if unsanitized | Marker payload (benign) |
|------|------------------------------|-------------------------|
| HTML/DOM render | XSS | `<x-marker-7f3a onmouseover=...>` / `<img src=x onerror=...>` |
| SQL query | SQL injection | `' || marker-7f3a || '` / `'-- marker` |
| Shell command | Command execution | `; echo marker-7f3a` / `$(echo marker)` |
| HTTP client (URL) | SSRF | `http://marker-7f3a.localhost/` / internal IP |
| File path | Path traversal | `../../marker-7f3a` |
| Template engine | SSTI | `{{7*7}}` / `${marker}` |

### 2. Generate context-specific marker payloads
Use a unique, traceable marker per test so you can confirm exactly which sink reflected it. The `scripts/agent.py` payload generator emits these for each context.

```python
import secrets

def marker():
    return "m" + secrets.token_hex(4)          # unique, greppable

def xss_payload(m):    return f'<img src=x onerror="console.log(\'{m}\')">'
def sqli_payload(m):   return f"' /* {m} */ --"
def ssrf_payload(m):   return f"http://{m}.test.invalid/"
def cmd_payload(m):    return f"; echo {m}"
def path_payload(m):   return f"../../{m}"
```

### 3. Drive the model to emit the payload
Make the model output the marker string. Two channels:

- **Direct:** prompt the feature so the response contains the payload (e.g., "echo this verbatim: …").
- **Indirect (more realistic):** place the payload in a source the model ingests — a RAG document, a web page, a tool result — so it surfaces through normal operation. This is the agentic/RAG attack path (AML.T0051).

### 4. Observe the sink
Check whether the marker was **executed/interpreted** (flaw) or **encoded/escaped** (safe):

- XSS: did the marker run in the DOM, or is it shown as inert text (`&lt;img…`)?
- SSRF: did the server make a request to the marker host? (watch your collaborator/log.)
- SQLi: did the query error, return extra rows, or reflect the comment marker?
- Command exec: did the marker echo into output/logs?

```python
import requests

def test_reflected_xss(url, payload, marker):
    r = requests.post(url, json={"prompt": f"Repeat verbatim: {payload}"}, timeout=15)
    body = r.text
    raw = payload in body                       # unencoded → likely XSS
    encoded = ("&lt;" in body or "&gt;" in body) and marker in body
    return {"sink": "html", "reflected_raw": raw,
            "reflected_encoded": encoded, "marker_present": marker in body}
```

### 5. Classify and prioritize
Rank confirmed flaws by sink severity and exploitability (server-side execution/SSRF/SQLi above reflected XSS; stored above reflected). Note the channel (direct vs. indirect) — indirect, RAG-borne flaws are higher risk because an external attacker triggers them without app access.

### 6. Remediate at the sink and re-test
Treat LLM output as untrusted input at every sink:

| Sink | Control |
|------|---------|
| HTML/DOM | Context-aware output encoding; CSP; never `innerHTML` raw model text |
| SQL | Parameterized queries / prepared statements — never string-concat model output |
| Shell | Avoid shell; use arg arrays + strict allow-list; no `shell=True` |
| HTTP client | URL allow-list, block internal ranges, no redirects to private IPs |
| File path | Canonicalize + confine to a base dir; reject `..` |
| Template | Disable code execution in templates; sandbox; escape by default |

Re-run steps 3–4 after each fix to confirm the marker is now encoded/blocked.

## Tools and Resources

| Resource | Link |
|----------|------|
| OWASP LLM05:2025 Improper Output Handling | https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/ |
| OWASP Top 10 for LLM Applications | https://genai.owasp.org/llm-top-10/ |
| MITRE ATLAS AML.T0051 LLM Prompt Injection | https://atlas.mitre.org/techniques/AML.T0051 |
| OWASP XSS Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html |
| OWASP SSRF Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html |
| NIST AI Risk Management Framework | https://www.nist.gov/itl/ai-risk-management-framework |

## Sink Test Reference

| Sink | Confirms | Safe behavior |
|------|----------|---------------|
| HTML render | XSS | Output HTML-encoded; payload inert |
| SQL | SQL injection | Parameterized; marker treated as literal |
| Shell | Command execution | No shell / allow-listed args; marker not executed |
| HTTP client | SSRF | URL rejected by allow-list; no internal fetch |
| File path | Path traversal | Path confined to base dir; `..` rejected |
| Template | SSTI | Expression not evaluated |

## Validation Criteria

- [ ] Every sink consuming LLM output is enumerated.
- [ ] Each sink probed with a unique, traceable marker payload in its correct context.
- [ ] Both direct and indirect (RAG/tool) emission channels tested.
- [ ] Confirmed flaws classified by sink type and prioritized (server-side > client-side, stored > reflected).
- [ ] Context-aware encoding / parameterization / allow-listing applied at each affected sink.
- [ ] Re-test confirms markers are now encoded or blocked at every fixed sink.
