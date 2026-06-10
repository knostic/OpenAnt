<p align="center">
  <img src="assets/open-ant-black.png" alt="OpenAnt" width="180" />
</p>

# OpenAnt

[OpenAnt](https://knostic.ai/openant) from [Knostic](https://knostic.ai) is an open source LLM-based vulnerability discovery product that helps defenders proactively find verified security flaws while minimizing both false positives and false negatives. Stage 1 detects. Stage 2 attacks. What survives is real.

We're pretty proud of this product and are in the vulnerability disclosure process for its findings, but do keep in mind that this started as a research project, and some of its features are still in beta. We welcome contributions to make it better.

## Why open source?

Considering the explosion of AI-discovered vulnerabilities, we hope OpenAnt will be the tool helping open source maintainers stay ahead of attackers, where they can use it themselves or submit their repo for scanning at no cost.

Then, since Knostic's focus is on protecting agents and coding assistants and not vulnerability research or application security, and we like open source, we decided to release OpenAnt under the Apache 2 license.
Besides, you may have heard about Aardvark from OpenAI (now Codex Security) and Claude Code Security from Anthropic, and we have zero intention of competing with them.

## Technical details and free scanning for open source projects

For technical details, limitations, and token costs, check out this blog post:
[https://knostic.ai/blog/openant](https://knostic.ai/blog/openant)

To submit your repo for scanning:
[https://knostic.ai/blog/oss-scan](https://knostic.ai/blog/oss-scan)

## Supported languages

- Go
- Python
- JavaScript/TypeScript (beta)
- C/C++ (beta)
- PHP (beta)
- Ruby (beta)

## Credits

Research and ideation: [Nahum Korda](https://github.com/NahumKorda/).

Productization: [Alex Raihelgaus](https://github.com/ar7casper/), [Daniel Geyshis](https://github.com/dgeyshis).

With thanks to: [Michal Kamensky](https://github.com/kamenskymic/), [Imri Goldberg](https://github.com/lorg), [Gadi Evron](https://github.com/gadievron/), Daniel Cuthbert. Josh Grossman, and Avi Douglen.

## Check out Knostic

**If you like our work**, check out what we do at [Knostic](https://knostic.ai) to defend your agents and coding assistants, prevent them from deleting your hard drive and code, and control associated supply chain risks such as MCP servers, extensions, and skills.

## Local setup

Build the CLI binary (requires Go 1.25+):

```bash
cd apps/openant-cli && make build
```

This compiles the Go source and outputs the binary to `apps/openant-cli/bin/openant`.

Symlink it onto your PATH so you can run `openant` from anywhere:

```bash
ln -sf "$(pwd)/apps/openant-cli/bin/openant" /usr/local/bin/openant
```

_Note: run this from the repo root so `$(pwd)` resolves to the correct absolute path._

### Setting up an LLM

OpenAnt routes each pipeline phase through a configurable (provider, model) pair. The fastest path is the interactive wizard:

```bash
openant setup llm
```

You name the config (e.g. `my-llm`), pick a provider per pipeline phase (`anthropic`, `openai`, or `google`), enter an API key once per provider, and the wizard probes each unique provider+model pair with a 1-token request before writing `~/.config/openant/config.json`. Run a scan against it with `--llm-config`:

```bash
openant scan /path/to/repo --llm-config my-llm
```

Wizard defaults reflect the project's per-phase recommendations (stronger reasoning models for detection / verification / reachability review; lighter models for context, report, and test generation) — override any answer to taste.

#### Shipped adapters

| Provider type | API key from | Notes |
|---|---|---|
| `anthropic` | [console.anthropic.com](https://console.anthropic.com/settings/keys) | Reference adapter. NOT included in Claude Pro / Max subscriptions — separate billing. |
| `openai` | [platform.openai.com](https://platform.openai.com/api-keys) | NOT included in ChatGPT / Codex subscriptions — separate billing. |
| `google` | [aistudio.google.com](https://aistudio.google.com/apikey) | NOT included in Gemini Advanced — separate billing. |

All three support tool calling, so any of them can drive the `enhance` and `verify` phases that use the agentic tool-use loop.

#### Quick path for Anthropic-only setups

If you want today's per-phase Claude defaults and nothing else, skip the wizard:

```bash
openant set-api-key sk-ant-...
openant scan /path/to/repo
```

This uses the built-in `openant-default` config (compiled into the binary, no `config.json` needed) — Claude Opus 4.6 for detection phases, Sonnet 4 for the rest.

#### Hand-authored config

The wizard writes `~/.config/openant/config.json` for you, but you can edit it directly too. Every llm-config must list all seven pipeline phases:

```json
{
  "$schema_version": 2,
  "default_llm": "my-llm",
  "llm_providers": {
    "anthropic": {"type": "anthropic", "api_key": "sk-ant-..."},
    "openai":    {"type": "openai",    "api_key": "sk-proj-..."},
    "google":    {"type": "google",    "api_key": "AIza..."}
  },
  "llm_configs": {
    "my-llm": {
      "app_context":  {"provider": "openai",    "model": "gpt-4o-mini"},
      "llm_reach":    {"provider": "anthropic", "model": "claude-opus-4-6"},
      "enhance":      {"provider": "openai",    "model": "gpt-4o-mini"},
      "analyze":      {"provider": "anthropic", "model": "claude-opus-4-6"},
      "verify":       {"provider": "anthropic", "model": "claude-opus-4-6"},
      "dynamic_test": {"provider": "google",    "model": "gemini-2.0-flash"},
      "report":       {"provider": "google",    "model": "gemini-2.0-flash"}
    }
  }
}
```

Providers accept a custom `base_url` for OpenAI-compatible / Anthropic-compatible proxies (OpenRouter, vLLM, Bedrock, internal gateways). The `openant-default` config (Claude across all phases) is built in and always available regardless of file contents.

#### Adding a new provider adapter

OpenAnt's adapter layer is a small Python recipe — one Python file implementing the `LLMAdapter` Protocol, one factory for the contract-test harness, plus a registry entry — and that alone is enough to run the adapter from a hand-authored config. To also have it offered by the `openant setup llm` wizard and pass its pre-save probe, add a few Go touch-points in `apps/openant-cli/cmd/setup.go` (the supported-provider list, a probe `case`, the per-phase default-model maps) plus a Go probe function. The 12 contract tests run automatically against your adapter once it's wired in. See [`docs/features/llm-providers/HOW_TO_ADD_AN_ADAPTER.md`](docs/features/llm-providers/HOW_TO_ADD_AN_ADAPTER.md) for the full recipe.

### Python runtime

OpenAnt's parsing, enhancement, analysis, and reporting code is Python 3.11+. The Go CLI picks an interpreter in this order:

1. `OPENANT_PYTHON` env var (set this to pin a specific interpreter — e.g. `OPENANT_PYTHON=python3.11`).
2. Managed venv at `~/.openant/venv/` (auto-created on first use). The CLI uses `bin/python` on Linux/macOS and `Scripts\python.exe` on Windows.
3. `python3` / `python` on `PATH`.

If none yield Python 3.11+, the command exits with an error pointing at [python.org](https://www.python.org/downloads/). To rebuild a stale managed venv (e.g. after upgrading Python), delete `~/.openant/venv/` and rerun any `openant` command.

## Data directories

OpenAnt creates two directories:

- **`~/.config/openant/`** — CLI configuration (`config.json`). Stores your API key, active project, and preferences. File permissions are restricted to `0600`.
- **`~/.openant/`** — Project data. Each initialized project gets a workspace under `~/.openant/projects/<org>/<repo>/` containing `project.json` and a `scans/` directory with per-commit outputs.

## Analyzing a project

### 1. Initialize

Point OpenAnt at a repository. The `-l` flag (language) is required — use `go` or `python`.

```bash
# Remote — clones the repo
openant init <repo-url> -l go

# Remote — pin to a specific commit
openant init <repo-url> -l go --commit <sha>

# Local — references the directory in-place
openant init <path-to-repo> -l go --name <org/repo>
```

This creates a project workspace and sets it as the active project. All subsequent commands operate on the active project automatically — no path arguments needed.

### 2. Run the pipeline

Each step picks up the output of the previous one from the project's scan directory:

```bash
openant parse
openant enhance
openant analyze
openant verify
openant build-output
openant report -f summary
```

Or run the full pipeline in one command:

```bash
openant scan --verify
```

### Working with multiple projects

The pipeline operates on one project at a time. Running `openant init` sets the newly initialized project as the active one, so all subsequent commands target it by default.

If you're working with several projects, you have two options:

```bash
# Option 1: switch the active project
openant project switch org/repo
openant parse

# Option 2: target a project directly with -p
openant parse -p org/repo
```

### Project management

```bash
openant project list              # shows all projects, marks active
openant project show              # details of active project
openant project switch <org/repo> # switch active project
```

## Roadmap

Things on the list, in no particular order:

- **More provider adapters.** Ollama (local models), vLLM, Cohere, Mistral, Groq, Amazon Bedrock, Azure OpenAI — each is a small Python adapter recipe (plus a few Go wizard/probe touch-points if you want it offered by `openant setup llm`) per the contributor guide. Lower the barrier to local / on-prem inference.
- **Subscription-based auth.** ChatGPT / Codex, Claude Pro / Max, and Gemini Advanced subscriptions don't currently grant API quota — users have to maintain a separate API-tier key per provider. OAuth-based adapters that ride the consumer subscription would close that gap.
- **Cross-provider tool-call quirks.** All three shipped adapters support tool calling, but the long tail (parallel tool calls, strict-mode schema enforcement, retry semantics on partial JSON) behaves differently per provider. Real-world scans surface these — PRs welcome.
- **More languages.** The supported-languages list above is current coverage. Rust, Java, C#, and Swift come up frequently.
- **Hosted scan service.** Knostic offers free scans for OSS projects today via the form linked above; a self-serve API for trusted partners is a future possibility.

PRs welcome on any of these — open an issue first if the scope is non-trivial so we can align before you build.

## LICENSE

This project is licensed under Apache 2. See the LICENSE file for details.

## Disclaimer and legal notice

This project is intended for defensive and research purposes only. OpenAnt is still in the research phase, use it carefully and at your own risk. Knostic, OpenAnt, and associated developers, researchers, and maintainers assume no responsibility whatsoever for any misuse, damage, or consequences arising from the use of this tool.

Only scan code you own or have explicit permission to test. If you discover a vulnerability in someone else's project through legitimate means, please follow coordinated vulnerability disclosure practices and report it to the maintainers before making it public.
