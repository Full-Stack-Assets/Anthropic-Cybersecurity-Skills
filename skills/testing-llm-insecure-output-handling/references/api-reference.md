# LLM Insecure Output Handling — Harness / API Reference

The companion `scripts/agent.py` generates per-sink marker payloads and (optionally)
drives a live endpoint to check whether model output is executed or safely encoded.
The payload generator is pure stdlib; live HTTP tests use `requests`.

## CLI

| Command | Purpose |
|---------|---------|
| `agent.py payloads` | Print a marker payload for every sink context |
| `agent.py payloads --json` | Emit payloads as JSON (marker + payload per sink) |
| `agent.py test --url <endpoint>` | POST each payload to an endpoint and report reflection |
| `agent.py test --url <endpoint> --field prompt` | Set the JSON field name carrying the prompt |

## Sink contexts

| Context key | Sink | Vulnerability |
|-------------|------|---------------|
| `html` | DOM/HTML render | XSS (CWE-79) |
| `sql` | SQL query | SQL injection (CWE-89) |
| `shell` | Shell command | Command injection (CWE-78) |
| `ssrf` | HTTP client URL | SSRF (CWE-918) |
| `path` | File path | Path traversal (CWE-22) |
| `template` | Template engine | SSTI (CWE-1336) |

## Marker scheme

Each payload embeds a unique marker `m<8-hex>` (from `secrets.token_hex`) so the
exact reflected sink is identifiable in responses, logs, or an out-of-band
collaborator. Markers are benign (no destructive action) — they only prove the
sink trusts model output.

## Live-test result fields

| Field | Meaning |
|-------|---------|
| `marker_present` | The marker appeared in the response at all |
| `reflected_raw` | Payload reflected **unencoded** (likely vulnerable) |
| `reflected_encoded` | Payload reflected **HTML-encoded** (safe handling) |

`reflected_raw == True` is the signal to investigate; `reflected_encoded == True`
with `reflected_raw == False` indicates correct output encoding.

## Out-of-band sinks (SSRF / blind)

SSRF and blind command execution often produce **no** in-response reflection.
Point the payload host at a collaborator/canary you control and watch its logs;
the script flags these sinks as "verify out-of-band" rather than asserting safety.

## External References

- OWASP LLM05:2025: https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/
- OWASP Cheat Sheets (XSS, SSRF, SQLi): https://cheatsheetseries.owasp.org/
