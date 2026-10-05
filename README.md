<p align="center">
  <img src="assets/open-ant-black.png" alt="OpenAnt" width="180" />
</p>

# OpenAnt

[OpenAnt](https://knostic.ai/openant) from [Knostic](https://knostic.ai) is the first open source LLM-based vulnerability discovery product (now called a harness) that helps defenders proactively find verified security flaws while minimizing both false positives and false negatives. Stage 1 detects. Stage 2 attacks. What survives is real.

Do keep in mind that this started as a research project, and as we develop new capabilities, we often release them as beta. We welcome contributions.

## Paper

You can find our research paper on building OpenAnt on arXiv: [OpenAnt: LLM-Powered Vulnerability Discovery Through Code Decomposition, Adversarial Verification, and Dynamic Testing](https://arxiv.org/abs/2606.19149), by Nahum Korda and Gadi Evron.

## Why open source?

This was a relevant question in the readme when we first released OpenAnt, since, many other harnesses have been released. We still hope that with the explosion of AI-discovered vulnerabilities, OpenAnt will help open source maintainers stay ahead of attackers, where they can use it themselves. Or submit their repo for scanning at no cost.

There is also the fact that Knostic's focus is on protecting agents and coding assistants and not vulnerability research or application security, and we like open source, so we decided to release OpenAnt under the Apache 2 license.
Besides, you may have heard about Aardvark from OpenAI (now Codex Security) and Claude Code Security from Anthropic, and we have zero intention of competing with them.

## Technical details and free scanning for open source projects

For technical details, limitations, and token costs, check out this blog post:
[https://knostic.ai/blog/openant](https://knostic.ai/blog/openant)

To submit your repo for scanning:
[https://knostic.ai/blog/oss-scan](https://knostic.ai/blog/oss-scan)

## Supported languages

- Go
- Python
- C/C++
- JavaScript/TypeScript (beta)
- PHP (beta)
- Ruby (beta)
- Zig (beta)
- Swift (beta)
- Rust (beta)

## Credits

Maintainer and research: [Gadi Evron](https://github.com/gadievron/)

Original research, ideation, and original prototype: [Nahum Korda](https://github.com/NahumKorda/).
Original productization: [Alex Raihelgaus](https://github.com/ar7casper/), [Daniel Geyshis](https://github.com/dgeyshis).

With thanks to: [Michal Kamensky](https://github.com/kamenskymic/), [Imri Goldberg](https://github.com/lorg), Daniel Cuthbert. Josh Grossman, and Avi Douglen.

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
| `ollama` | — (local server) | Local models via [Ollama](https://ollama.com). No `api_key`: leave it blank (a placeholder is sent automatically); base URL defaults to `http://localhost:11434/v1`. Models must be pulled first (`ollama pull <model>`); model IDs are exactly what `ollama list` shows. Local inference is free — $0 cost reporting. Offered by `openant setup llm` — full guide: [`utilities/llm/providers/OLLAMA.md`](libs/openant-core/utilities/llm/providers/OLLAMA.md). |

All of them support tool calling, so any of them can drive the `enhance` and `verify` phases that use the agentic tool-use loop. For Ollama, pick a tools-capable model for those phases — very small local models may not handle tool calls reliably.

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
    "google":    {"type": "google",    "api_key": "AIza...", "request_timeout": 600}
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

`llm_providers[name].request_timeout` (seconds, positive integer or null) sets the adapter's per-request HTTP timeout — consumed by the google provider type (the only one whose SDK default is unbounded); other types warn loudly at startup if it is set.

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

#### Exit codes (important for CI)

`openant scan` — and each step verb (`analyze`, `verify`, …) when run step-by-step —
exits **1 when it finds vulnerabilities** — that is the tool working, not failing. The
contract:

| Exit code | Meaning |
|---|---|
| 0 | Clean scan — no vulnerabilities found |
| 1 | **Vulnerabilities found** (a successful run) |
| 2 | Error — the scan itself failed (check `errors` in the JSON envelope on stdout) |

Generic CI steps and process supervisors treat any non-zero exit as a failure, which
misclassifies a healthy findings run. Gate on the contract instead of parsing stdout:

```bash
rc=0
openant scan --verify /path/to/repo || rc=$?   # || captures: set -e safe
if [ "$rc" -gt 1 ]; then
  echo "scan FAILED (exit $rc)" >&2; exit "$rc"
fi
# rc 0 = clean, rc 1 = findings found — both are successful runs
```

The `|| rc=$?` form matters: CI defaults to `set -e` (GitHub Actions `run:`, Jenkins `sh`),
where a bare `openant scan` exiting 1 would terminate the script before the capture line —
reproducing exactly the misclassification this section exists to prevent.

### Web UI

`openant serve` starts a local web UI over the same scan pipeline: submit a
repository URL or local path, watch the scan logs stream live, and read the HTML
report, markdown summary, and disclosures — all from the browser.

```bash
openant serve                       # http://127.0.0.1:8080, opens your browser
openant serve --addr 127.0.0.1:9000 # choose a port
```

The server binds to loopback only (it refuses any non-loopback `--addr`) and is
intended for local single-user use. Scan outputs persist under
`~/.openant/webui/` across restarts. Analysis still sends source code to your
configured LLM provider, the same as the CLI.

### Incremental and diff-based scans

For repositories where a full scan is too slow or expensive, OpenAnt can
restrict the pipeline to units whose bodies overlap a git diff hunk:

```bash
openant scan --diff-base origin/main          # diff vs a ref
openant scan --pr 123                         # diff vs the base of a GitHub PR
openant scan --staged                         # diff vs HEAD using the staged index
openant scan --incremental                    # diff vs the last successful scan
```

`--staged` reads `git diff --cached` and is intended for pre-commit hooks or
local "scan what I'm about to commit" runs. The base is HEAD; the head is the
index, so files staged with `git add` are scanned and worktree-only edits are
not.

The shorter `openant diff` form takes the same flags, e.g.:

```bash
openant diff --staged --skip-dynamic-test
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

PRs welcome — open an issue first if the scope is non-trivial so we can align before you build.

## Auto Patcher

Auto Patcher exists to answer one question: **does this AI-generated patch deserve to be trusted?** Generating a candidate patch is only the first step. Auto Patcher focuses on producing the evidence a human needs to decide whether to trust and deploy that patch.

Given a known CVE or a finding from an OpenAnt scan, Auto Patcher does the following:

1. Grounds the vulnerability in the target repository.
2. Plans a remediation from verified repository evidence.
3. Generates a candidate patch.
4. Checks the patch deterministically.
5. Challenges the patch adversarially.
6. Writes a Trust Report whose recommendation is computed by a fixed policy from the evidence collected.

Auto Patcher does not autofix your repository. The patch and its Trust Report are written to disk for a human to review. Patches are only ever applied to temporary copies of the repository, never to the repository itself.

**Learn more:**
- [Auto Patcher architecture](docs/auto-patcher/auto-patcher-architecture.md): components, stages, information and evidence flow, fail-closed boundaries, recording and replay.
- [Recommendation policy](docs/auto-patcher/recommendation-policy.md): exactly how the Trust Report's evidence and recommendation are decided, and what they do not prove.
- [Tracing & debugging guide](libs/openant-core/utilities/autopatcher/tools/TRACING_AND_DEBUGGING.md): traced runs, execution manifests, single-stage replay.
- [Real-CVE batch runner](libs/openant-core/utilities/autopatcher/tools/RUN_CVE_BATCH.md): parallel, resumable evaluation over YAML manifests of historical CVEs (evaluation tooling, not needed for normal use).

### Why AI-generated patches can't be trusted at face value

A patch produced by an LLM can look correct — it compiles, it touches the right function, it reads like a competent fix — without actually closing the vulnerability. It may narrow the attack surface without eliminating it, fix the described case while missing an adjacent one, or apply cleanly against one version of a file and silently fail against another. Fluent output is not verified output.

### How it works

A run moves through five phases, shown in the terminal as it goes:

1. **Analyze.** Auto Patcher locates and parses the code the vulnerability concerns, then builds a deterministic picture of the repository around it. An LLM planner proposes a remediation. If the planner explicitly asks for more evidence, that evidence is acquired deterministically, within a fixed number of attempts. Specific planner claims are then checked by a separate verification call.
2. **Prepare.** A final strategy is derived from verified evidence only. Auto Patcher then builds the exact source of the target code. If any intended edit still lacks verified, patch-ready source, generation stops rather than guessing.
3. **Generate.** The LLM generates one candidate diff, and deterministic code then checks it:
   - wrong hunk headers are repaired;
   - the patch must touch only the approved target files;
   - the diff is checked for hygiene problems and with `git apply --check`.

   Each kind of failure gets at most one bounded retry. The patch is then applied to an isolated copy of the repository and the original vulnerable locations are re-analyzed.
4. **Validate.** An adversarial Challenger call reports concerns as specific facts backed by verbatim quotes. Code checks those quotes against the evidence the Challenger was actually shown, and derives the verdict from the checked facts. The model's own stated verdict never decides it. Free-text findings are then calibrated, at most one repair attempt can run, and the patch is reviewed.
5. **Decide.** Deterministic Trust Signals and a fixed decision policy produce the recommendation.

LLM judgment is used for planning, strategy, patch generation, adversarial review, finding calibration, and narrative review. Everything that decides whether a patch is applicable, conformant, or recommended is deterministic code operating on that output. Code checks the structure of LLM output and the provenance of its citations, but not the soundness of its reasoning. The same configured model performs every LLM step, including the adversarial one, so the Challenger narrows but does not remove the risk of a shared blind spot.

### Philosophy

- **Never communicate more certainty than the evidence supports.** A check that didn't run is reported as unverified, never as a quiet pass.
- **A fixed, auditable policy makes the call.** No self-reported confidence score influences the recommendation.
- **Fail closed.** When a gate cannot establish the evidence it needs, Auto Patcher stops before generation or lands on Manual Review Required rather than guessing upward. One known exception is described under [Outcomes and exit codes](#outcomes-and-exit-codes).
- **Every recommendation ships with the evidence behind it.** The Trust Report separates deterministic checks from heuristic, adversarial-review judgment.
- **The deployment decision stays with a human.** Auto Patcher never applies a patch to the target repository.

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

The CVE record is fetched from NVD. Setting `NVD_API_KEY` raises NVD's rate limits but is optional.

Auto Patcher's LLM provider and model come from OpenAnt's own configuration, not a separate system. Run `openant setup llm` once, and every `openant patch` run inherits that config's `analyze` phase provider and model. If you have never run the wizard (for example after `openant set-api-key`), it uses the built-in default. There is no Auto Patcher-specific provider or model picker. Setting `LLM_PROVIDER`/`LLM_MODEL` to select a real provider is an error. If the configuration is missing or unusable, the run fails before any repository work and points you at `openant setup llm`. `LLM_PROVIDER=mock` is available only as an explicit way to run without a real provider, for testing and research.

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

### Remediating a finding instead

Auto Patcher can also remediate a finding that an OpenAnt scan already produced (`openant scan` / `openant build-output`), instead of a CVE. Pick a finding whose verdict is patch-eligible from the `findings` array in your project's `pipeline_output.json`. The eligible verdicts are `confirmed`, `agreed`, `vulnerable`, and `bypassable`; any other verdict is rejected. This snippet lists findings and verdicts (it requires [`jq`](https://jqlang.org/)):

```bash
jq -r '.findings[] | "\(.id)\t\(.stage2_verdict // .stage1_verdict)"' pipeline_output.json
```

```bash
openant patch --finding-id VULN-001
```

With no path argument, the active project's `pipeline_output.json` is used, and `--repo-root` and `--output` default to the active project's repository and scan directory.

### Options

| Flag | Meaning |
|---|---|
| `--cve <CVE-ID>` | Remediate a public CVE (requires `--repo-root`, or an active project to default to). Mutually exclusive with `--finding-id`. |
| `--finding-id <id>` | Remediate a finding from `pipeline_output.json`. |
| `--repo-root <path>` | The target repository checkout. Defaults to the active project's repository. |
| `--output`, `-o <dir>` | Output directory. Defaults to the active project's scan directory, or a new temporary directory when there is no active project. |
| `--verbose` | Show detailed per-stage diagnostics and full error detail. |
| `--quiet`, `--json` | Global flags: suppress progress output, or print the raw JSON result envelope. |

`--context-budget-policy` and `--max-context-budget-windows` are deprecated. They are still accepted so existing scripts keep working, but they only print a one-time notice and have no effect (see [Context budget](#context-budget)). Existing Test Comparison (`--compare-existing-tests`) is available on the Python CLI and the tracing tool, not on `openant patch`; see [Known limitations](#known-limitations).

The Go CLI stops a Python subprocess after 30 minutes by default. Set `OPENANT_INVOKE_TIMEOUT` (for example `OPENANT_INVOKE_TIMEOUT=2h`) for unusually long runs.

### Outcomes and exit codes

The Trust Report leads with one outcome:

- **Deploy After Validation**, **Deploy With Caution**, **Manual Review Required**, or **Do Not Apply**: a final candidate patch exists, and the fixed policy evaluated it.
- **NO PATCH PRODUCED**: the run completed, but a fail-closed gate stopped it before a final candidate patch existed. For example, the evidence could not justify a target, the target source could not be verified, or the generated patch edited the wrong files. This is an outcome of the run, not a recommendation, and there is nothing to review or deploy.

Deploy With Caution belongs to the policy's vocabulary, but the current evidence model does not produce it. On non-Python repositories, deployment risk cannot be verified, so the best possible recommendation is Manual Review Required.

**No recommendation proves that the vulnerability is fixed.** Deploy After Validation means the patch applies cleanly, its diff has no hygiene problems, adversarial review left no blocking or unresolved concern, and the change has a low or moderate impact surface. It does not mean an exploit was attempted, that every attack path was closed, or that the patch matches the upstream maintainers' fix.

`openant patch` exits with:

| Exit code | Meaning |
|---|---|
| 0 | A Trust Report was written, whatever its outcome (including NO PATCH PRODUCED). |
| 2 | The run failed and no Trust Report was written. Examples: invalid LLM configuration, an LLM API failure in a non-best-effort stage, an ineligible or unknown finding, a missing `--repo-root`, or an NVD fetch error. |
| 130 | Interrupted. |

Some stages are best-effort, such as planning, evidence acquisition, and calibration. If one of them fails, the run prints a warning and continues with less evidence. That usually makes the outcome more cautious, and can mean NO PATCH PRODUCED. There is one exception: if planning or the final strategy produces no result at all, for example because of an LLM error, the patch is generated without the target-readiness and target-conformance gates. The adversarial review and the policy still apply to it. Treat a run that printed such warnings with extra care.

### The Trust Report

Each run writes to `<output>/patch/`, with files named after the input (a CVE id or a finding id):

- `{id}-vulnerability.md`: the input, as rendered into the text Auto Patcher worked from.
- `{id}-trust-report.md`: the Trust Report. It is written only when the run completes, and a stale report from an earlier failed run is removed first.
- `{id}-investigation/`: parser artifacts from repository analysis.

`openant patch` also writes `<output>/patch.report.json`, OpenAnt's step report for the run. It records the run's inputs, outputs, status, duration, and token and cost usage, including on failure.

Below the outcome, a Trust Signals table shows the evidence behind it:

- whether the patch applies;
- whether its edited content was found in the repository;
- whether adversarial review found that it addresses the vulnerability;
- whether there are unresolved concerns;
- whether relevant tests already exist;
- what deployment risk the change carries;
- whether existing tests newly fail (when that check was requested).

Each row is marked as a deterministic check or a heuristic judgment, and a check that didn't run is reported as unverified. The report also includes the structured Challenger concerns, a Post-Patch Investigation of the patched copy, Validation Actions to run before deploying, and Run Metadata (repository commit, OpenAnt commit, provider and model).

A clean apply and passing hygiene checks mean the patch is well-formed, not that the vulnerability is fixed. When the input is a CVE, the report states that the advisory's claims are not verified against the repository, and that the recommendation is based on evidence gathered from the repository, not on the advisory's severity score.

### Context budget

Repository evidence placed in an LLM call is limited by a per-call technical capacity. There is no cost or spend limit, and no "budget window" setting. The limit is computed per call as:

> (model context window − output-token reserve − 2,000-token safety margin) × 3 characters per token − the exact size of the rest of the prompt

The output-token reserve is `LLM_MAX_TOKENS`, which defaults to 4,096.

**Current behavior:** OpenAnt's model registry (`config/models.json`) does not yet record a context window for any model. Every run therefore uses the documented conservative fallback of **60,000 tokens**, whatever the configured model's real window is. With the default output reserve, that leaves about 160,000 characters of prompt per call, before the system prompt and other mandatory content.

Evidence that is resolved but does not fit is omitted whole, never truncated mid-block, and recorded with the reason `technical_capacity`. If the target source that patch generation requires does not fit, the run stops with NO PATCH PRODUCED instead of sending an incomplete request.

Separately, fixed structural limits bound how much exploration happens. These include up to 5 planning attempts, 2 deterministic and 2 guided acquisition rounds with 5,000 characters of new source per round, one post-patch recovery round, and a whole-function rendering limit of about 3,300 characters per unanchored target. See [the architecture document](docs/auto-patcher/auto-patcher-architecture.md#context-capacity) for details.

### Known limitations

- Auto Patcher is an early-stage capability; its reports are labeled MVP output.
- Impact analysis and existing-test discovery currently run only on Python repositories. Elsewhere they report "not applicable" rather than being silently skipped, which also caps non-Python runs at Manual Review Required.
- "Do relevant tests already exist?" is a **discovery** check (does a matching test file exist?), not a test run. Existing Test Comparison does run the repository's existing tests, in Docker, against unpatched and patched copies, and reports newly failing tests. However, it is opt-in, it is not exposed as an `openant patch` flag (run the Python entry point the CLI uses, for example `~/.openant/venv/bin/python -m openant patch --cve <CVE-ID> --repo-root <path> --compare-existing-tests`), it requires Docker, and it does not affect the recommendation. See the [recommendation policy](docs/auto-patcher/recommendation-policy.md#current-limitations).
- Adversarial review, calibration, and narrative review are LLM calls. Two runs on the same input can reach different outcomes.
- This is a decision aid for a human reviewer, not a replacement for manual security review.

## LICENSE

This project is licensed under Apache 2. See the LICENSE file for details.

## Disclaimer and legal notice

This project is intended for defensive and research purposes only. OpenAnt is still in the research phase, use it carefully and at your own risk. Knostic, OpenAnt, and associated developers, researchers, and maintainers assume no responsibility whatsoever for any misuse, damage, or consequences arising from the use of this tool.

Only scan code you own or have explicit permission to test. If you discover a vulnerability in someone else's project through legitimate means, please follow coordinated vulnerability disclosure practices and report it to the maintainers before making it public.
