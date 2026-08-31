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
- Zig (beta)
- Swift (beta)
- Rust (beta)

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

You name the config (e.g. `my-llm`), pick a provider per pipeline phase (any of the shipped adapters below), enter its API key once per provider (Bedrock uses the AWS credential chain instead — leave the key blank), and the wizard probes each unique provider+model pair with a 1-token request before writing `~/.config/openant/config.json`. Run a scan against it with `--llm-config`:

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
| `bedrock` | — (AWS credential chain) | Claude on AWS Bedrock. No `api_key`: credentials come from `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` env vars or a `~/.aws` profile, region from `AWS_REGION`. Model IDs are inference profiles (`us.anthropic.claude-sonnet-4-6`, `global.anthropic.claude-haiku-4-5-20251001-v1:0`, ...) — enable them under "Model access" in the Bedrock console and list them with `aws bedrock list-inference-profiles`. Offered by `openant setup llm` (leave the API key blank — AWS credential chain, probe skipped) — full guide: [`utilities/llm/providers/BEDROCK.md`](libs/openant-core/utilities/llm/providers/BEDROCK.md). |
| `openrouter` | [openrouter.ai](https://openrouter.ai/settings/keys) | Gateway to many providers with one key and one prepaid balance (also reads `OPENROUTER_API_KEY`). Model IDs are `vendor/model` slugs (`anthropic/claude-sonnet-4.6`, `openai/gpt-4o-mini`, ...) — browse them at [openrouter.ai/models](https://openrouter.ai/models). Offered by `openant setup llm` (leave the base URL blank for the OpenRouter default) — full guide: [`utilities/llm/providers/OPENROUTER.md`](libs/openant-core/utilities/llm/providers/OPENROUTER.md). |

All four support tool calling, so any of them can drive the `enhance` and `verify` phases that use the agentic tool-use loop.

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

Providers accept a custom `base_url` for OpenAI-compatible / Anthropic-compatible proxies (vLLM, Bedrock, internal gateways); OpenRouter has its own first-class `openrouter` provider type. The `openant-default` config (Claude across all phases) is built in and always available regardless of file contents.

#### Adding a new provider adapter

OpenAnt's adapter layer is a small Python recipe — one Python file implementing the `LLMAdapter` Protocol, one factory for the contract-test harness, plus a registry entry — and that alone is enough to run the adapter from a hand-authored config. To also have it offered by the `openant setup llm` wizard and pass its pre-save probe, add a few Go touch-points in `apps/openant-cli/cmd/setup.go` (the supported-provider list, a probe `case`, the per-phase default-model maps) plus a Go probe function. The 12 contract tests run automatically against your adapter once it's wired in.

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

### 3. Remediate a finding

Generate a candidate patch and an independent Trust Report for a specific finding — see [Auto Patcher](#auto-patcher) below.

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

## Auto Patcher

Auto Patcher exists to answer one question: **does this AI-generated patch deserve to be trusted?** Generating a candidate patch is only the first step. Auto Patcher focuses on producing the evidence humans need to decide whether that patch should be trusted and deployed.

Given a known CVE or a specific finding from an OpenAnt scan, it runs the candidate patch through a multi-stage pipeline — repository grounding and remediation planning, patch generation, adversarial challenge, calibration, review, confidence scoring, deterministic impact/test analysis — and produces a Trust Report that states whether the patch is fit to deploy, backed by the evidence behind that call. It does not autofix your repository: the patch and its Trust Report are written to disk for a human to review, and the target repository is never modified.

**Learn more:**
- [Auto Patcher architecture](docs/auto-patcher/auto-patcher-architecture.md) — the full pipeline: every stage, execution order, how production and replay share code, and how execution artifacts/provenance work.
- [Recommendation policy](docs/auto-patcher/recommendation-policy.md) — exactly how the Trust Report's evidence and final recommendation are decided.
- [Tracing & debugging guide](libs/openant-core/utilities/autopatcher/tools/TRACING_AND_DEBUGGING.md) — running a traced evaluation, inspecting execution manifests, and replaying individual pipeline stages during development.

### Why AI-generated patches can't be trusted at face value

A patch produced by an LLM can look correct — it compiles, it touches the right function, it reads like a competent fix — without actually closing the vulnerability. It may narrow the attack surface without eliminating it, fix the described case while missing an adjacent one, or apply cleanly against one version of a file and silently fail against another. Fluent output is not verified output, and asking the same model that wrote a patch whether the patch is good doesn't close that gap — it just repeats the same blind spot.

### What Auto Patcher does differently

Rather than returning a single "here's the fix," every candidate patch goes through a trust-building process:

```
Generate a candidate patch
        │
        ▼
Challenge it from an adversarial perspective
        │
        ▼
Collect deterministic evidence — does it apply cleanly? does it introduce obvious defects?
        │
        ▼
Produce a recommendation, backed by the evidence collected above
```

The adversarial pass is a distinct reasoning step whose only job is to argue the patch doesn't hold up — not to confirm that it does. The deterministic checks (applying the patch against the real repository, scanning the diff for hygiene issues) never rely on an LLM's opinion of its own work. The final recommendation is computed from all of this evidence by a fixed decision policy, not read off an LLM's self-reported confidence.

### Philosophy

- **Never communicate more certainty than the evidence supports.** A check that didn't run is reported as unverified, never as a quiet pass.
- **Recommendations come from deterministic policy, not from an LLM's self-assessment.** Each of the four possible recommendations is computed from evidence gates a human can audit — not a model grading its own patch.
- **Every recommendation ships with the evidence behind it.** The Trust Report separates what was mechanically verified from what is heuristic, adversarial-review judgment, so a reviewer never has to guess which is which.
- **The deployment decision stays with a human.** Auto Patcher never applies a patch to the target repository — it produces a recommendation for someone accountable to act on.

### Quick start

Check out the repository revision you want patched, then point `patch` at it with a CVE:

```bash
git clone <repository-url> /tmp/the-repo-to-patch
cd /tmp/the-repo-to-patch
git checkout <version-or-tag-to-patch>

openant patch \
  --cve <CVE-ID> \
  --repo-root /tmp/the-repo-to-patch \
  --output /tmp/patch-report
```

Auto Patcher's LLM provider and model come from OpenAnt's own configuration, not a separate system: run `openant setup llm` once, and every `openant patch` run inherits that config's `analyze` phase provider/model automatically — including the built-in default if you've never run the wizard (e.g. after `openant set-api-key`). There's no provider or model picker specific to Auto Patcher; if the configuration is missing or unusable, the run fails clearly and points you at `openant setup llm` rather than opening a menu. `LLM_PROVIDER=mock` remains available as an explicit way to run without a real provider, for testing/research.

### Example

```bash
git clone https://github.com/urllib3/urllib3.git /tmp/urllib3-eval
cd /tmp/urllib3-eval
git checkout 2.0.5

openant patch \
  --cve CVE-2023-43804 \
  --repo-root /tmp/urllib3-eval \
  --output /tmp/urllib3-report
```

### Context budget

Several pipeline stages (final-target slicing, pre-patch and post-patch source acquisition) share a fixed character budget for how much repository source they can pull in — this is a cap on repository text gathered from disk, not the LLM's context-window size or a token/dollar budget, and it's entirely optional. By default each stage starts with one 10,000-character window. `--context-budget-policy` controls whether a stage can be granted additional windows once it runs out:

- `ask` — prompt before granting another window (the default for an interactive run).
- `always` — grant windows automatically up to the cap, with no prompting (useful for CI / batch runs).
- `never` — never extend; the original fixed-budget behavior (the default for a non-interactive run).

Each granted window adds the same fixed size as the first (10K → 20K → 30K → …, never exponential), up to `--max-context-budget-windows` (default `10`, i.e. up to 100,000 characters per stage). Extending the budget only grants more source text to work from — it never bypasses applicability, source verification, or the Recommendation Policy.

```bash
openant patch \
  --cve CVE-2023-43804 \
  --repo-root /tmp/urllib3-eval \
  --output /tmp/urllib3-report \
  --context-budget-policy always \
  --max-context-budget-windows 10
```

### Remediating a finding instead

Auto Patcher can also remediate a finding already produced by an OpenAnt scan (`openant scan` / `openant build-output`), instead of a CVE. Pick a finding whose verdict is patch-eligible — `confirmed`, `agreed`, `vulnerable`, or `bypassable` — from the `findings` array in your project's `pipeline_output.json` (the snippet below requires [`jq`](https://jqlang.org/)):

```bash
jq -r '.findings[] | "\(.id)\t\(.stage2_verdict // .stage1_verdict)"' pipeline_output.json
```

```bash
openant patch --finding-id VULN-001
```

### The Trust Report

Each run writes two files under `patch/` in the project's scan directory, named after the input (a CVE id or a finding id):

- `{id}-vulnerability.md` — the input as rendered into what Auto Patcher worked from.
- `{id}-trust-report.md` — the Trust Report.

If no final candidate patch could be produced, the report leads with **NO PATCH PRODUCED** — an execution outcome, not a recommendation. Otherwise, it leads with a single recommendation — **Deploy After Validation**, **Deploy With Caution**, **Manual Review Required**, or **Do Not Apply** — computed by a fixed decision policy, never an LLM's self-assessment. A Trust Signals table below it shows the evidence behind that call: whether the patch applies cleanly, whether its edited content was actually verified against the repository, whether adversarial review found it addresses the vulnerability, whether tests already cover the affected code, and what deployment risk it carries. Each signal is marked as either a deterministic check or a heuristic judgment, and a check that didn't run is reported as unverified, never as a quiet pass.

A clean apply and passing hygiene checks mean the patch is well-formed — not that the vulnerability is fixed. Post-Patch Investigation re-checks the vulnerability's original code locations against the patched repository for evidence closer to that claim. When the input is a CVE, the report also flags that the advisory's own claims are unverified against the repository, and that the recommendation is based on evidence gathered against it — not the advisory's severity score.

### Known limitations

- Auto Patcher is an early-stage capability — its own reports are labeled MVP output today.
- Some evidence signals (impact analysis, existing-test discovery) currently run meaningfully only on Python codebases; on other languages they report as not applicable rather than being silently skipped.
- The Trust Report's "Do relevant tests already exist?" signal is a **discovery** check (does a matching test file exist on disk), not an execution check — it doesn't tell you whether those tests pass. Auto Patcher can optionally also *execute* the repository's existing test suite, in Docker, once before and once after the patch, and report any newly-introduced failures (Existing Test Comparison) — but this is opt-in, not yet exposed as an `openant patch` flag, and its result is informational only: it does not affect the recommendation. See [Existing Test Comparison](docs/auto-patcher/recommendation-policy.md#current-limitations) for the exact distinction.
- This is a decision aid for a human reviewer, not a replacement for manual security review.

## Roadmap

Things on the list, in no particular order:

- **More provider adapters.** Ollama (local models), vLLM, Cohere, Mistral, Groq, Azure OpenAI — each is a small Python adapter recipe (plus a few Go wizard/probe touch-points if you want it offered by `openant setup llm`) per the contributor guide. Lower the barrier to local / on-prem inference.
- **Subscription-based auth.** ChatGPT / Codex, Claude Pro / Max, and Gemini Advanced subscriptions don't currently grant API quota — users have to maintain a separate API-tier key per provider. OAuth-based adapters that ride the consumer subscription would close that gap.
- **Cross-provider tool-call quirks.** All three shipped adapters support tool calling, but the long tail (parallel tool calls, strict-mode schema enforcement, retry semantics on partial JSON) behaves differently per provider. Real-world scans surface these — PRs welcome.
- **More languages.** The supported-languages list above is current coverage. Java and C# come up frequently.
- **Hosted scan service.** Knostic offers free scans for OSS projects today via the form linked above; a self-serve API for trusted partners is a future possibility.

PRs welcome on any of these — open an issue first if the scope is non-trivial so we can align before you build.

## LICENSE

This project is licensed under Apache 2. See the LICENSE file for details.

## Disclaimer and legal notice

This project is intended for defensive and research purposes only. OpenAnt is still in the research phase, use it carefully and at your own risk. Knostic, OpenAnt, and associated developers, researchers, and maintainers assume no responsibility whatsoever for any misuse, damage, or consequences arising from the use of this tool.

Only scan code you own or have explicit permission to test. If you discover a vulnerability in someone else's project through legitimate means, please follow coordinated vulnerability disclosure practices and report it to the maintainers before making it public.
