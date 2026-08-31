# Ollama Provider Guide

Run OpenAnt entirely on local models via [Ollama](https://ollama.com). No API
key, no per-token cost — with the default `base_url`, source code never
leaves the machine. (The endpoint is overridable for LAN/remote
Ollama-compatible gateways — see "Remote / LAN Ollama" below: what leaves
the machine, and to where, is then exactly your configuration.)

## Setup

1. Install Ollama and start the server:

   ```bash
   ollama serve   # often already running as a service
   ```

2. Pull at least one tools-capable model. The wizard defaults below are a
   good starting point for a SAST pipeline:

   ```bash
   ollama pull qwen3.8:27b          # default tier (18GB, 256K ctx — needs ~20GB+ VRAM/RAM)
   ollama pull qwen3.5:9b           # modest-hardware alternative (6.6GB)
   ```

3. Configure OpenAnt:

   ```bash
   openant setup llm
   ```

   Pick `ollama` as the provider type. **Leave the API key blank** — Ollama
   doesn't authenticate local requests; the adapter sends a placeholder
   automatically. Leave the base URL blank to use `http://localhost:11434/v1`.

Or skip the wizard with a hand-authored config:

```json
{
  "$schema_version": 2,
  "default_llm": "local",
  "llm_providers": {
    "ollama": {"type": "ollama"}
  },
  "llm_configs": {
    "local": {
      "app_context": {"provider": "ollama", "model": "qwen3.5:9b"},
      "llm_reach": {"provider": "ollama", "model": "qwen3.8:27b"},
      "enhance": {"provider": "ollama", "model": "qwen3.5:9b"},
      "analyze": {"provider": "ollama", "model": "qwen3.8:27b"},
      "verify": {"provider": "ollama", "model": "qwen3.8:27b"},
      "dynamic_test": {"provider": "ollama", "model": "qwen3.5:9b"},
      "report": {"provider": "ollama", "model": "qwen3.5:9b"}
    }
  }
}
```

## Model choice

The `enhance` and `verify` phases use an agentic tool-calling loop — pick a
model that handles tool calls reliably (the Qwen2.5-Coder family works well;
very small models often don't). If a model can't do tool calls, those phases
fail loud rather than silently producing empty results.

Model IDs are exactly what `ollama list` shows (`qwen3.8:27b`,
`llama3.3:70b`, ...). An unpulled model is caught by the wizard probe /
init-time validation with an `ollama pull <model>` hint.

## Remote / LAN Ollama

Set `base_url` in the provider entry to the remote host, e.g.
`http://192.168.1.50:11434/v1`. If you front Ollama with a key-checking
gateway, set `api_key` on the provider entry — it is forwarded verbatim.

## Cost accounting

Local inference is free. The three shipped Ollama models carry explicit
`{"input": 0, "output": 0}` records in the shared registry
(`config/models.json`, the `_LOCAL_PROVIDERS` exemption in
`core/model_registry.py`): their cost reporting is DEFINED — $0 with
`cost_complete`, never the unknown-model warning. Nothing to keep current
(no vendor rates to track — free is a fact, not a quote) and no silent
cross-provider price guessing (issue #65). A local model ABSENT from the
registry (any custom tag) deliberately still takes the unknown-model warn
path: an arbitrary tag is genuinely unknown, and the loud marker is honest
about it.

## Model quality — an honest note (the round-2 adjudication)

A scanner is only as strong as the model behind it. Local models trade
capability for privacy: a small or base (non-instruct) model can produce
false-clean scans — a report that says "safe" is the MODEL'S verdict, and
a 9B local model's verdict is weaker evidence than a frontier model's.
Use the biggest tool-capable model your hardware fits for the
tool-calling phases (`enhance`, `verify`), pick chat/instruct models over
base ones, and treat a clean result from a small local model as "not
obviously vulnerable" rather than "audited". The confidence fields on
findings reflect the model's own self-assessment, calibrated for frontier
models.

## Troubleshooting

- **Connection refused / could not reach** → the daemon isn't running.
  Start it with `ollama serve`, or check `OLLAMA_HOST`/port and set
  `base_url` accordingly.
- **model not found, try pulling it first** → run `ollama pull <model>`.
- **Slow scans** → full-repo scans make many LLM calls; local hardware is
  the bottleneck. Use incremental modes (`openant scan --staged`,
  `--diff-base`, `--pr`) to scan only changed code, and consider a smaller
  model for the light phases.
