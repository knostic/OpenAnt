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
| `OPENANT_INVOKE_TIMEOUT` | Maximum time the CLI OR the web-UI server waits on a Python subprocess (one invocation spans the whole command — a CLI `scan` runs its phases under this single budget; a web-UI scan runs under the same budget, read from the `serve` process's environment; the standalone verbs are `parse`/`enhance`/`analyze`/`verify`/`dynamic-test`/`generate-context`/`build-output`/`report`). Accepts a Go duration (e.g. `2h`, `90m`) or a bare integer of seconds (e.g. `7200`). Defaults to `30m`. Raise it for large repos whose LLM phases legitimately run longer than 30 minutes. When the deadline fires, the error names the deadline and this override; a COMPLETE result envelope already written to stdout is still returned (recovered, with a note on stderr), and only a run with no complete result is lost — in which case, for the checkpointing subcommands (`scan`/`enhance`/`analyze`/`verify`/`dynamic-test`), the units that completed before the kill are checkpointed under the run's output dir — a re-run resumes from them only with the same `--output` or project (an ad-hoc run's checkpoints land in a fresh temp dir a re-run will not see). An unset, empty, or invalid value falls back to the default (a warning is printed for a non-empty invalid value). |
| `OPENANT_LOCAL_CLAUDE` | Set to `true` to run analyses through a local Claude Code CLI session (`claude -p`) instead of the Anthropic API. No API key required in this mode. See [LOCAL_CLAUDE.md](../../LOCAL_CLAUDE.md) for the full setup. |
| `CLAUDE_CONFIG_DIR` | Optional, only meaningful with `OPENANT_LOCAL_CLAUDE=true`. Tells the `claude` CLI which config/session directory to use. |
