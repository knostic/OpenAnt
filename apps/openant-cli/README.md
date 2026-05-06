# openant CLI

Go-based command-line wrapper for OpenAnt. Delegates parsing and analysis to the Python core in `libs/openant-core/`.

See the [repo README](../../README.md) for setup, installation, and usage.

## Build

```bash
cd apps/openant-cli && make build
```

This compiles the Go source to `apps/openant-cli/bin/openant`.

## Environment variables

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Anthropic API key used for Stage 1/Stage 2 LLM calls. Overridden by the `--api-key` flag and the value stored via `openant set-api-key`. Required unless `OPENANT_LOCAL_CLAUDE=true`. |
| `OPENANT_PYTHON` | Pin a specific Python interpreter for the CLI to use (e.g. `OPENANT_PYTHON=python3.11` or an absolute path). Takes precedence over the managed venv at `~/.openant/venv/` and any Python on `PATH`. Useful for debugging, CI, container images, and **Windows users relying on the managed venv** (the venv layout differs from Linux/macOS, so an explicit override is the simplest fix). If the override is set but unusable, the CLI prints a warning and falls back to its normal search order. |
| `OPENANT_LOCAL_CLAUDE` | Set to `true` to run analyses through a local Claude Code CLI session (`claude -p`) instead of the Anthropic API. No API key required in this mode. See [LOCAL_CLAUDE.md](../../LOCAL_CLAUDE.md) for the full setup. |
| `CLAUDE_CONFIG_DIR` | Optional, only meaningful with `OPENANT_LOCAL_CLAUDE=true`. Tells the `claude` CLI which config/session directory to use. |
