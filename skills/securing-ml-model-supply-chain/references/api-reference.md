# ML Model Supply Chain — Tool / API Reference

## Libraries & Tools

| Tool | Install | Purpose |
|------|---------|---------|
| modelscan | `pip install modelscan` | Scan model files for unsafe operators / embedded code |
| safetensors | `pip install safetensors` | Code-free tensor serialization (preferred format) |
| model-signing | `pip install model-signing` | Sigstore-based model signing & verification |
| torch | `pip install torch` | `weights_only=True` safe(r) loading |

## modelscan CLI

| Command | Purpose |
|---------|---------|
| `modelscan -p <file_or_dir>` | Scan a model file or directory |
| `modelscan -p <path> --reporting-format json -o report.json` | Machine-readable report |
| Exit code `0` | No issues; non-zero indicates findings (gate the pipeline on it) |

## Severity gate (recommended)

| Severity | Action |
|----------|--------|
| CRITICAL / HIGH | Block — do not load or promote |
| MEDIUM | Review; sandbox-detonate before promotion |
| LOW / none | Allow with provenance recorded |

## safetensors (`safetensors.torch`)

| Function | Purpose |
|----------|---------|
| `save_file(state_dict, path)` | Serialize tensors to safetensors |
| `load_file(path)` | Load tensors (no code execution) |

## Provenance helpers (companion `scripts/agent.py`)

| Command | Purpose |
|---------|---------|
| `agent.py scan --path <model>` | Run modelscan if present; else stdlib pickle-opcode heuristic |
| `agent.py scan --path <model> --fail-on high` | Exit non-zero on >= severity |
| `agent.py hash --path <model>` | Print SHA-256 |
| `agent.py hash --path <model> --expected <sha256>` | Verify integrity against a known hash |

## Heuristic fallback

When `modelscan` is unavailable, the script disassembles pickle opcodes and flags
`GLOBAL` / `REDUCE` / `STACK_GLOBAL` referencing dangerous modules
(`os`, `subprocess`, `posix`, `builtins.eval/exec`, `socket`) — a coarse but
dependency-free indicator of an executable payload.

## External References

- modelscan: https://github.com/protectai/modelscan
- safetensors: https://github.com/huggingface/safetensors
- Sigstore model transparency: https://github.com/sigstore/model-transparency
