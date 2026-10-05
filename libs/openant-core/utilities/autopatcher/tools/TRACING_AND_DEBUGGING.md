# Auto Patcher — Tracing & Debugging Guide

Audience: developers (human or AI) picking up an Auto Patcher debugging
session cold. This document captures the current, source-verified workflow
for building the CLI, running Auto Patcher, tracing every LLM call it makes,
and reasoning backward from a suspicious Trust Report to its root cause.

It lives next to the trace/replay tooling it describes
(`libs/openant-core/utilities/autopatcher/tools/run_traced.py` and
`run_stage.py`, same directory) — a normal, tracked, importable location
next to the Auto Patcher subsystem, not a gitignored scratch directory —
because a debugging session usually starts by opening these files side by
side.

This document describes the current tooling only. If a statement below
disagrees with the source, the source is authoritative.

For the pipeline's overall architecture — every canonical stage, execution
recording, and how replay shares implementation with production — see
[docs/auto-patcher/auto-patcher-architecture.md](../../../../../docs/auto-patcher/auto-patcher-architecture.md).
This document is the operational/debugging companion to that one: it
assumes the architecture document's vocabulary (canonical stage,
`StageExecution`, lineage, effective dependency resolution) and focuses on
*how to run and inspect the system*, not on explaining that vocabulary
from scratch.

`<OPENANT_REPO_ROOT>` stands for your OpenAnt checkout. Commands use
`python3` for any Python ≥ 3.11 that has OpenAnt's dependencies installed
(for example the managed venv, `~/.openant/venv/bin/python`).

---

## Section 1 — Repository / Tooling Map

| Area | Role |
|---|---|
| `apps/openant-cli` | Go CLI (`openant`). Thin transport layer: parses flags, resolves the active project, and shells out to the Python engine via `python.Invoke`. Does **no** LLM resolution, patch logic, or trace capture of its own. |
| `libs/openant-core` | The Python engine. Contains `openant/cli.py` (the actual `patch` subcommand argparse + entry point), `core/patch.py` (`run_patch`/`run_patch_cve`, artifact writing), and `utilities/autopatcher/` (the pipeline itself). |
| `libs/openant-core/utilities/autopatcher/tools/run_traced.py` | In-process tracing wrapper, tracked normally as part of the Auto Patcher subsystem. Calls the same `core.patch.run_patch`/`run_patch_cve` functions the CLI calls, but intercepts every LLM call to record prompt/response to disk, and wires an `ExecutionRecorder` (see below) into `pipeline.run()`. The **canonical producer of replay-capable source traces** (see §19-§22) — every trace it writes carries a schema-v3 `run_manifest.json` with real, structured `StageExecution` records, not just prose. |
| `libs/openant-core/utilities/autopatcher/tools/run_cve_batch.py` | The standard real-CVE regression/evaluation batch runner (see §26 and `RUN_CVE_BATCH.md`, same directory). Runs every case of one or more YAML manifests through `run_traced.py` with bounded parallelism (default `--jobs 2`), an isolated checkout/output/CWD per case attempt, canonical evaluation flags, aggregate summaries, a results ZIP and `--resume`. `run_patcheval_python_37.py` is a thin wrapper around it. |
| `libs/openant-core/utilities/autopatcher/tools/run_stage.py` | Single-stage debug replay tool (see §19), same directory. A thin CLI wrapper around `replay_engine.replay_stage()` — consumes a source run/replay directory and reruns exactly ONE canonical pipeline stage's CURRENT implementation against upstream state resolved from that source's lineage. Accepts any of the 13 canonical stage names; **12 of the 13 currently have a working replay implementation** (every stage except `trust_signals_and_recommendation`, which has no independent execution to replay — see the architecture document's [Terminal reporting architecture](../../../../../docs/auto-patcher/auto-patcher-architecture.md#terminal-reporting-architecture)). |
| `libs/openant-core/utilities/autopatcher/replay_engine.py` | The current, stage-registry-driven replay engine `run_stage.py` calls. Owns dependency resolution, capability-aware preflight, stage invocation, and manifest persistence for every replayable stage. Each stage's replay handler calls the *same* production stage-implementation function `pipeline.run()` calls — see the architecture document's [Shared production/replay architecture](../../../../../docs/auto-patcher/auto-patcher-architecture.md#shared-productionreplay-architecture). |
| `libs/openant-core/utilities/autopatcher/stage_replay.py` | Helpers that `replay_engine.py` imports: `SourceProvenance`, `resolve_source_provenance`, `validate_target_repository`, and output-directory safety checks. |
| `libs/openant-core/utilities/autopatcher/tools/replay_challenger_reparse.py` | Zero-LLM reparse of an archived `challenger` execution's raw response through the *current* `patch_challenger.py` parser and verdict derivation (`--source-run`, `--output`; writes `challenger_reparse.json`). Useful after a parser change. |
| `tools/concern_tree_harness.py`, `simple_concern_harness.py`, `concrete_trace_harness.py` | Research harnesses for experimental Challenger designs (`concern_tree.py`, `simple_concern_resolver.py`, `concrete_trace.py`). Not used by `openant patch` or the production pipeline. |
| `libs/openant-core/utilities/autopatcher/stage_registry.py` | The static, side-effect-free catalog of all 13 canonical stages: names, approved dependency graph, capability flags (repo access / Docker / LLM provider), and which `stage=` LLM tags each canonical stage owns. Answers "what IS this stage," never "is it replayable today" (that's `replay_engine.REPLAY_HANDLERS`). |
| `libs/openant-core/utilities/autopatcher/execution_recorder.py` | `ExecutionRecorder` — passive recording of real `StageExecution` entries during a production run. Strictly opt-in: `pipeline.run()`'s `execution_recorder` parameter defaults to `None`, and only `run_traced.py` constructs one. A plain `openant patch` run records nothing. |
| `libs/openant-core/utilities/autopatcher/lineage.py` | The manifest schema (v3, `executions: [...]`) and the lineage/dependency-resolution logic (`resolve_effective`, `build_chain`) both production recording and replay share. |
| `libs/openant-core/utilities/autopatcher/llm_call_tracing.py` | The shared LLM-call-capture mechanism (`LLMCallCapture`) both `run_traced.py`'s `LLMCallTracer` and `stage_replay.py`/`replay_engine.py` build on — monkeypatch `call_llm`, record each call in order, restore on exit. |
| Auto Patcher pipeline (`libs/openant-core/utilities/autopatcher/pipeline.py` + sibling modules) | Orchestrates the 13 canonical stages (see the architecture document for the full list). Mix of LLM calls and deterministic Python logic. |
| Trace output (`<output>/trace/`) | Written only when running via `run_traced.py`. Per-call prompt/response text files, `checkpoints.jsonl`, `run_manifest.json`, and an `executions/` directory of per-`StageExecution` JSON artifacts. |
| Replay output (`<output>/` from `run_stage.py`) | Written only when running via `run_stage.py`. One new `StageExecution`, its own `run_manifest.json` (`kind: "replay"`, `parent` pointing at the source run), and that stage's own artifact file(s). |
| Debug artifacts (`./reports/debug/*.json`) | Written by the *production* pipeline itself whenever `AUTOPATCHER_DEBUG=1` is set (by hand, or automatically by `run_traced.py`). Observability-only — never fed back into pipeline decisions. |
| Trust Report (`<output>/patch/<label>-trust-report.md`) | The final, user-facing artifact, produced by every completed run (traced or not). It is downstream of everything else, so treat it as a claim to verify, not a starting fact. |

Scope of this document: **build → run → trace → debug → regression
validation** for Auto Patcher specifically. It does not attempt to document
the rest of OpenAnt (the SAST scan pipeline, project/config management,
other CLI commands) except where Auto Patcher depends on them (LLM config,
Python runtime resolution).

---

## Section 2 — Building the CLI

### 2.1 What the project actually wants you to do

`libs/openant-core/CLAUDE.md` states the intended local dev setup explicitly:

> The system uses a symlink: `/usr/local/bin/openant` → `apps/openant-cli/bin/openant`
> **NEVER run `make install`** in `apps/openant-cli/` — it overwrites the symlink with a copy.

This matters because there are two different install paths documented in
this repo, and they are **not equivalent**:

- `<OPENANT_REPO_ROOT>/README.md` recommends a **symlink**, set up once.
- `apps/openant-cli/Makefile`'s `install` target does a plain **`cp`**, which
  replaces that symlink with a static copy that goes stale on the next build.

If `/usr/local/bin/openant` is already the symlink, you only need to rebuild
the binary — the symlink resolves to the new file automatically, with no
copy step:

```bash
cd <OPENANT_REPO_ROOT>/apps/openant-cli
go build -o bin/openant .
```

### 2.2 One-time symlink setup (if you don't already have one)

Run once, from the repo root:

```bash
ln -sf "<OPENANT_REPO_ROOT>/apps/openant-cli/bin/openant" /usr/local/bin/openant
```

After this, every `go build -o bin/openant .` is picked up immediately with
no further steps.

### 2.3 If you use `sudo cp` instead

`sudo cp bin/openant /usr/local/bin/openant` still *works*. If
`/usr/local/bin/openant` is the symlink from §2.2, however, `cp` follows the
symlink and writes through it to the same file (`bin/openant`) that is
already the source. That is why you may see:

```
cp: bin/openant and /usr/local/bin/openant are identical (not copied).
```

This is harmless — the binary was already current via the symlink — but it
is also a **sign you don't need the `cp` step at all**. If `/usr/local/bin/openant`
is instead a real file (not a symlink) — e.g. because someone previously ran
`make install` — `cp` overwrites it for real, and that's the (also fine, but
one-shot, must-repeat-every-build) alternative workflow.

Either way, always finish with:

```bash
hash -r
```

### 2.4 Verify which binary your shell will actually run

```bash
which openant
type -a openant
```

Both matter because **more than one `openant` executable can be on PATH**.
For example, a Python environment that has `libs/openant-core` installed
also has an `openant` console script, alongside the Go CLI binary this
document is about.

`which openant` shows only the first match your shell will actually invoke.
`type -a openant` (zsh/bash) lists **every** match on PATH in resolution
order — use it whenever a rebuilt binary doesn't seem to take effect, or
when `openant version`/`openant patch --help` output looks unexpected. `hash
-r` clears your shell's cached command-path lookup, which is why it's run
right after any change to what's installed where.

### 2.5 Confirm the binary is live

```bash
openant version
openant patch --help
```

`openant version` prints the Go build version, the Go runtime version, and
(if detectable) the resolved Python interpreter version. It is a quick way
to notice that you are running a stale or wrong binary. `openant patch
--help` should show `--finding-id`, `--cve`, `--repo-root`, `--output`/`-o`,
`--verbose` and the two deprecated context-budget flags, plus the global
`--json`, `--quiet`/`-q`, `--api-key` and `--project`/`-p` flags. The Go CLI
has no `--compare-existing-tests` flag; that flag exists only on the Python
`patch` command and on `run_traced.py`.

### 2.6 When a Go rebuild is (and isn't) actually necessary

`apps/openant-cli` is pure transport (§1) — it parses flags and shells out
to the Python engine unmodified. Concretely:

- **A rebuild IS required** when you change anything under
  `apps/openant-cli/` itself: a flag definition, help text, project/config
  resolution logic, or how the Go layer invokes the Python subprocess.
- **A rebuild is NOT required** for a change confined to the Python Auto
  Patcher core — anything under `libs/openant-core/utilities/autopatcher/`,
  `libs/openant-core/core/patch.py`, or the tracing/replay tooling in
  `libs/openant-core/utilities/autopatcher/tools/`. The next `openant
  patch` invocation picks up a Python-only change immediately, because the
  Go binary re-invokes the Python interpreter fresh on every run — there is
  nothing Go-side to recompile.
- **`run_traced.py` and `run_stage.py` never touch the Go binary at all** —
  both are pure Python entry points, invoked directly with `python3` (§7,
  §19), so a Python-only change is visible on your very next invocation of
  either, with no build step of any kind.

If you're not sure which category a change falls in, check whether the
diff touches anything under `apps/openant-cli/` — if not, skip the rebuild.

---

## Section 3 — LLM Configuration (current behavior)

### 3.1 Where provider/model selection comes from

`openant patch --help`'s own `Long` description states it plainly
(`apps/openant-cli/cmd/patch.go:31-36`):

> Requires a resolvable LLM provider so a run never silently falls back to a
> mock LLM: configure one via `openant setup llm` — Auto Patcher inherits
> the active config's `analyze` phase binding, exactly like every other
> OpenAnt command. Set `LLM_PROVIDER=mock` only if you intentionally want a
> mock run; `LLM_PROVIDER`/`LLM_MODEL` are not a supported way to select a
> real provider or model.

Concretely, the resolution path is:

```
openant patch  (Go — no LLM logic, pure transport)
  → python subprocess (core.patch.run_patch / run_patch_cve)
    → utilities.autopatcher.llm_client.ensure_provider_configured()
      → _resolve_canonical_binding()
        → utilities.llm.registry.load_config_file() / resolve_llm_config()
          → default_llm → llm_configs[default_llm].phases["analyze"] → {provider, model}
```

`llm_client.py`'s `_resolve_canonical_binding()` docstring:

> Resolve `(provider, model)` from OpenAnt's canonical LLM configuration —
> `default_llm` → `llm_configs[default_llm].analyze` → `{provider, model}`,
> falling back to the built-in `openant-default` exactly like every other
> OpenAnt command.

If the resolved `analyze` phase has no usable provider/model, this raises a
`RuntimeError` telling you to run `openant setup llm` — it does **not**
degrade into a mock run.

### 3.2 What `unset LLM_PROVIDER` / `unset LLM_MODEL` accomplishes

```bash
unset LLM_PROVIDER
unset LLM_MODEL
```

`LLM_PROVIDER` and `LLM_MODEL` **are not a way to select a real provider or
model** (`utilities/autopatcher/llm_client.py`; the batch runner also refuses
to start when they are set). A non-mock `LLM_PROVIDER` fails in the preflight,
before any repository work. A set `LLM_MODEL` fails at the first live LLM
call:

```python
# llm_client.py — _resolve_active_provider()
if env_provider:
    raise RuntimeError(
        f"LLM_PROVIDER={env_provider!r} is no longer used to select a "
        "real provider for Auto Patcher. Configure a provider and model "
        "via `openant setup llm`. Set LLM_PROVIDER=mock to use Auto "
        "Patcher's test/research mock mode."
    )
```

```python
# llm_client.py — _resolve_model()
if env_model:
    raise RuntimeError(
        f"LLM_MODEL={env_model!r} is no longer used to select a model "
        "for Auto Patcher. Configure a model via `openant setup llm`."
    )
```

So `unset`-ing both before a real/regression run isn't superstition — it
removes the only way an accidentally-still-exported value from an earlier
experiment could turn a normal run into an immediate crash. If they're
already unset in your shell, the `unset` calls are no-ops.

### 3.3 The one supported exception: explicit mock mode

```bash
export LLM_PROVIDER=mock
```

is the **only** live effect either variable has. It routes every stage
through canned, stage-specific responses (`_MOCK_PATCH`, `_MOCK_REVIEW`,
`_MOCK_SCORE`, `_MOCK_CHALLENGE`, `_mock_calibration_response` in
`llm_client.py`) and deliberately bypasses the shared `utilities.llm`
adapter layer entirely. `LLM_MODEL` has no effect in mock mode either.

### 3.4 No silent fallback to mock

The module docstring is explicit:

> `LLM_PROVIDER=mock` is the one narrow, intentional exception: an explicit
> Auto-Patcher-specific test/research escape hatch... It is never an
> implicit fallback — there is no "unset → mock" default.

No failure mode degrades into mock: missing config, missing credentials,
an auth error, a rate limit, a malformed response, a model the provider
does not know. All of them raise a real error. A configured model the
provider rejects raises `ModelUnavailableError`; there is never a fallback
to another model.

### 3.5 How a run tells you which provider/model actually ran

There is no `run_manifest.json` for the production pipeline itself (that
file only exists when you use `run_traced.py` — see §7/§9). Two other
places report the real answer:

1. **The Trust Report's "Run Metadata" table** (`run_metadata.py`,
   `render_metadata_section`), appended to the bottom of every
   `<label>-trust-report.md`:

   ```
   | LLM provider | anthropic |
   | LLM model    | claude-... |
   | LLM mode     | LIVE |
   ```

   with a `⚠️ **MOCK MODE**` banner when `llm_mode == "MOCK"`.

2. **The run header on stderr** (`core/patch.py`), printed once before the
   pipeline starts:

   ```
   OpenAnt Auto Patcher
   ────────────────────────────────────────────────────────────
   CVE         CVE-2023-43804
   Repository  /tmp/urllib3-eval
   Model       Anthropic · claude-...
   ```

   In mock mode the model line reads `Mock`. `--quiet`/`--json` suppress the
   header. A caller that bypasses `core/patch.py` gets a single `Model  …`
   line on its first live call instead.

The CLI's own stdout summary (`PrintPatchSummary`) does **not** print the
provider or model, only the finding/CVE id and the Trust Report path. Check
the Trust Report's metadata table or the stderr log; never assume.

Other environment variables that affect a run: `LLM_MAX_TOKENS` (output
tokens per call, default 4096; this also reduces the source-evidence capacity,
see §5), `NVD_API_KEY` (optional; raises NVD rate limits for `--cve`), and
`AUTOPATCHER_DEBUG` (debug artifacts, §10).

---

## Section 4 — Clean Real-CVE Reproduction

Every real-CVE validation starts from a clean repository, at the exact
vulnerable commit, verified by SHA — not by tag name alone (tags can be
re-pointed; a green result on the wrong revision is not a valid result).

**Worked example is urllib3/CVE-2023-43804 — treat every value below as
case-specific**, not a template constant.

```
Repo:              https://github.com/urllib3/urllib3.git
Vulnerable version: 2.0.5
CVE:               CVE-2023-43804
Expected SHA:      d9f85a749488188c286cd50606d159874db94d5f
```

```bash
rm -rf /tmp/urllib3-eval
rm -rf /tmp/urllib3-trace
git clone https://github.com/urllib3/urllib3.git /tmp/urllib3-eval
cd /tmp/urllib3-eval
git checkout 2.0.5
```

```bash
echo "=== ACTUAL SHA ==="
git rev-parse HEAD
echo "=== EXPECTED SHA ==="
echo "d9f85a749488188c286cd50606d159874db94d5f"
echo "=== STATUS ==="
git status --short
```

Why each step matters:

- **Delete the previous eval repo** — a stale checkout can carry local
  edits, an out-of-date fetch, or a previous patch attempt applied on disk.
  Any of those silently changes what the pipeline sees as "the repository."
- **Delete previous trace/report output** — old `trace/*.prompt.txt` or a
  stale Trust Report can be mistaken for the current run's evidence,
  especially if `--output`/`--trace-dir` are reused across experiments.
- **Clone fresh** — guarantees no accumulated local state from a prior
  investigation.
- **Checkout the exact tag** — the CVE's vulnerable version is a claim about
  a specific commit's behavior, not "whatever HEAD currently is."
- **Verify the SHA** — tags are just refs; confirm the checkout actually
  landed on the commit the CVE record describes, byte-for-byte.
- **`git status --short`** — must be empty. Any local modification means the
  pipeline is analyzing a repository state that doesn't match the CVE
  advisory or any real released version.

---

## Section 5 — Context-Budget Flags (deprecated) and Technical Capacity

`--context-budget-policy` and `--max-context-budget-windows` are **deprecated
no-ops**. `openant patch`, the Python `patch` command, and `run_traced.py`
still accept them, with the same validation, so existing scripts keep
working. When either flag is passed, a deprecation warning is printed
straight to stderr, bypassing the progress layer, so Python-side
`--quiet`/`--json` do not hide it. (The Go CLI's own `--quiet` drops the
Python stderr stream entirely.) Neither flag changes anything else. `run_traced.py` records the raw values (or `null`)
in `run_manifest.json`.

Repository evidence in every LLM call is bounded instead by a per-call
technical capacity (`technical_capacity.compute_source_capacity`):

```
source_capacity_chars = (context_window_tokens − LLM_MAX_TOKENS − 2,000) × 3 − known_overhead_chars
```

`context_window_tokens` comes from `config/models.json` when the active model
has a `context_window_tokens` entry. **No model has one today**, so every run
uses the documented fallback of 60,000 tokens (`capacity_source:
"conservative_fallback"`). Fixed structural limits (attempts, rounds,
requests per round, 5,000 new characters per acquisition round) apply on top;
see the architecture document's
[Context capacity](../../../../../docs/auto-patcher/auto-patcher-architecture.md#context-capacity)
section.

`ContextBudgetController.to_trace_dict()` is embedded as `budget_trace` in
`edit_readiness_*.json` and `post_patch_recovery_*.json` (§10). It has the
shape `{provider, model, stages: {<stage>: {source_capacity_chars,
capacity_source, context_window_tokens, reserved_output_tokens,
safety_margin_tokens, chars_per_token_ratio, known_overhead_chars,
capacity_is_approximate, used_chars}}}`. The controller is built without a
provider or model, so `provider`/`model` are `null` there.

Omit both flags in new commands. The batch runner (§26) still passes them,
only so that its command line stays identical across batches.

---

## Section 6 — Normal Auto Patcher Run

```bash
openant patch --cve CVE-2023-43804 --repo-root /tmp/urllib3-eval -o /tmp/urllib3-report
```

or, for a Finding produced by a prior OpenAnt scan (instead of a CVE):

```bash
openant patch --finding-id <finding-id>
```

`--output` defaults to the active project's scan directory, or to a new
temporary directory when no project is active; pass `-o <dir>` to redirect
it. `--repo-root` defaults to the active project's repository path, and is
**required** for `--cve` mode unless a project is active. `--verbose` adds
per-stage diagnostics (hunk repair, relocation, retries, evidence-acquisition
rounds) and full tracebacks; Go's `--quiet`/`--json` also quiet the Python
side. A normal run writes `<output>/patch/` plus `<output>/patch.report.json`
(OpenAnt's step report). It exits 0 when a Trust Report was written, and 2
on failure.

### Normal run vs. traced run — when to use which

| | `openant patch` | `utilities/autopatcher/tools/run_traced.py` |
|---|---|---|
| Purpose | Product/regression behavior — "does this CVE end up Deploy After Validation / Do Not Apply as expected?" | Deep investigation — "why did each stage decide what it decided?" |
| Invocation | Go CLI → Python subprocess | In-process Python, no subprocess |
| LLM call visibility | None beyond stderr logging and the final Trust Report | Every prompt + raw response saved to disk, per call |
| Extra artifacts | None beyond `patch/` and `patch.report.json` | `trace/` directory: prompts, responses, `checkpoints.jsonl`, `run_manifest.json`, `executions/` |
| Use when | Confirming end-to-end product behavior, running the regression suite | Root-causing a specific failure, comparing two runs stage-by-stage |

Use `openant patch` first to confirm *whether* something is wrong; reach for
`run_traced.py` to find out *why*.

---

## Section 7 — Traced Run

```bash
cd <OPENANT_REPO_ROOT>/libs/openant-core
python3 utilities/autopatcher/tools/run_traced.py \
  --cve CVE-2023-43804 \
  --repo-root /tmp/urllib3-eval \
  --output /tmp/urllib3-trace
```

`run_traced.py` requires Python 3.11+ (`libs/openant-core/pyproject.toml`
pins `requires-python = ">=3.11"`) with the project's dependencies
installed. Run it from `libs/openant-core`, as shown. The script adds that
directory to `sys.path` itself, but the debug-artifact writers it triggers
(§10) resolve `./reports/debug/` against the process's working directory,
not `--output`.

| Flag | Meaning |
|---|---|
| `--cve ID --repo-root PATH` | CVE mode (NVD fetch). `--repo-root` is required. |
| `<pipeline_output.json> --finding-id ID [--repo-root PATH]` | Finding mode. |
| `--output`, `-o DIR` | Output root (default: a new `openant_patch_traced_*` temp dir). |
| `--trace-dir DIR` | Where `trace/` content goes, including `run_manifest.json` and `executions/` (default `<output>/trace`). |
| `--compare-existing-tests` | Opt-in Existing Test Comparison (Docker required; the run aborts first if Docker is not ready). |
| `--blind-evaluation`, `--blind-strip-same-repo-github-references`, `--blind-filter-policy {v1,v2}` | Evaluation-only blind mode (§25). |
| `--verbose`, `--quiet`, `--json` | Verbosity. `--quiet` beats `--verbose`. `--json` implies quiet and prints a JSON summary: paths, trace manifest, LLM call count, usage. |
| `--context-budget-policy`, `--max-context-budget-windows` | Deprecated no-ops (§5). |

At the end, `run_traced.py` prints a "Trace Summary" block to stderr with the
paths, LLM-call count, tokens and cost. It exits 0 on success. It exits 2 for
argument errors, `TestComparisonEnvironmentError`, and `BlindEvaluationError`.
Any other exception writes a failure manifest and is re-raised, so the
process ends with a traceback and exit 1.

### What `run_traced.py` does differently from `openant patch`

Per its own module docstring, it is a "thin tracing ADAPTER" — it does not
reimplement or duplicate any Auto Patcher logic:

1. Builds one `ContextBudgetController`, exactly as `openant patch` does,
   and an `ExecutionRecorder`.
2. Calls `core.patch.run_patch()` / `run_patch_cve()` **in-process** (not via
   subprocess). These are the same functions the CLI calls, so it can
   observe every LLM call made during that call.
3. Replaces `utilities.autopatcher.llm_client.call_llm`, the single choke
   point every stage's `LLMClient.complete()` goes through, with a wrapper
   (`llm_call_tracing.LLMCallCapture`). The wrapper records each call's
   prompt and raw response **after the real call returns**, so a call that
   raises leaves no prompt file, response file or checkpoint. The wrapper
   changes nothing about provider resolution, retries, or content.
4. Sets `AUTOPATCHER_DEBUG=1` for the run's duration (restoring whatever was
   there before), so the pipeline's debug-artifact writers fire exactly as
   they would for any other `AUTOPATCHER_DEBUG=1` run.

### What it captures vs. does not

| Captured? | Item |
|---|---|
| Captured? | Item |
|---|---|
| ✅ | Every rendered prompt sent to an LLM (`NNN_<llm_tag>.prompt.txt`) |
| ✅ | Every raw LLM response (`NNN_<llm_tag>.response.txt`) |
| ✅ | Per-call metadata: sequence, tag, timestamps, char counts, filenames (`checkpoints.jsonl`) |
| ✅ | Run-level metadata and one `StageExecution` record per recorded stage (`run_manifest.json`, `executions/`) |
| ✅ (as absolute-path pointers, not copies) | `reports/debug/` files with the prefixes `context_selection_`, `edit_readiness_`, `relocation_telemetry_`, `post_patch_recovery_` that appeared during the run |
| ✅ | The same `patch/<label>-vulnerability.md`, `<label>-trust-report.md` and `<label>-investigation/` a normal run produces |
| ❌ | It does **not** copy `reports/debug/*` into the trace directory. They stay at `./reports/debug/` relative to the working directory |
| ❌ | It does **not** list `patch_generation_context_*.json` or `prompt_*.txt` debug files in the manifest (§10) |
| ❌ | It does **not** capture a call that raised (see step 3 above) |
| ❌ | It does **not** reformat, re-derive, or reinterpret anything it captures |

---

## Section 8 — Trace Directory Structure

An illustrative run produces the following. Which LLM calls appear depends
on which conditional paths fired.

```
/tmp/urllib3-trace/
  patch/
    CVE-2023-43804-vulnerability.md
    CVE-2023-43804-trust-report.md
    CVE-2023-43804-investigation/     # pre-patch repository parse only
      analyzer_output.json
      call_graph.json
      dataset.json
      functions.json
      scan_result.json

  trace/
    001_remediation_planning.prompt.txt
    001_remediation_planning.response.txt
    002_remediation_strategy.prompt.txt
    002_remediation_strategy.response.txt
    003_patch_generation.prompt.txt
    003_patch_generation.response.txt
    004_challenger.prompt.txt
    004_challenger.response.txt
    005_patch_review.prompt.txt
    005_patch_review.response.txt
    006_confidence_scorer.prompt.txt
    006_confidence_scorer.response.txt
    checkpoints.jsonl
    run_manifest.json
    executions/
      001_repository_analysis_and_remediation_planning.json
      002_remediation_strategy.json
      003_guided_context_acquisition.json
      004_patch_generation_and_post_patch_investigation.json
      005_challenger.json
      006_patch_repair_and_calibration.json
      007_patch_review.json
      008_confidence_scoring.json
      009_impact_and_behavior_analysis.json
    blind_evaluation/                 # only with --blind-evaluation (§25)
```

The post-patch repository parse runs inside a temporary repository copy and
is deleted with it. `reports/debug/*`, if `AUTOPATCHER_DEBUG=1` fired any
writers, lands in `./reports/debug/` under the working directory (§10) and is
only *referenced* from `run_manifest.json`.

### Call numbering is NOT semantically fixed

The prefix number (`NNN`) is just `seq`, a 1-based counter over *however
many LLM calls this particular run happened to make*. The file names are
generated by `LLMCallTracer._write_call` in `run_traced.py`:

```python
prompt_path = self.trace_dir / f"{seq:03d}_{stage}.prompt.txt"
response_path = self.trace_dir / f"{seq:03d}_{stage}.response.txt"
```

The `stage=` tags, in execution order (optional calls in brackets):

1. `remediation_planning`, then
   [`remediation_planning_reattempt` …] when the Planner asks for more
   evidence (up to 5 attempts in total).
2. [`remediation_plan_verification`, `remediation_plan_revision`,
   `remediation_plan_reverification`]: the Planner Claim Verifier.
3. `remediation_strategy`, then [a second `remediation_strategy`] for the
   evidence-gap fallback.
4. [`guided_context_request` ×≤2].
5. `patch_generation`, then [`patch_generation_contract_retry`], then
   [`patch_generation` again, for Post-Patch Recovery or the applicability
   retry].
6. `challenger`.
7. [`finding_calibration` …, `patch_repair_regeneration`, a second
   `challenger`]: Finding Calibration and the repair loop.
8. With `--compare-existing-tests`: [`test_plan_discovery`,
   `test_plan_discovery_contract_retry`, `test_failure_distillation`,
   `existing_test_amendment`].
9. `patch_review`.
10. `confidence_scorer`.

See the
[architecture document's stage table](../../../../../docs/auto-patcher/auto-patcher-architecture.md#pipeline-stages)
for which canonical stage owns each tag.

A run that triggers a regeneration (Post-Patch Recovery or the
applicability-aware retry, §14 Example A) inserts a **second**
`patch_generation` call, shifting every later position by one:

```
without retry:              with retry:
003_patch_generation         003_patch_generation
004_challenger                004_patch_generation   ← retry
                               005_challenger
```

**Rule: never infer stage identity from numeric position alone.** Always
read the stage name embedded in the filename, and cross-check it against
`checkpoints.jsonl`'s `stage` field and `run_manifest.json`. Two traces with
a differently-numbered `challenger` call are not necessarily different runs
of different logic — they may just differ in whether a retry fired earlier.

### Discovery command

```bash
find /tmp/urllib3-trace -maxdepth 4 -type f | sort
```

---

## Section 9 — What Each Artifact Tells You

### `*.prompt.txt`

The exact rendered prompt handed to an LLM for that call — this is
literally the string argument passed to `call_llm()`. Use it to answer:
**"What evidence did the model actually receive?"** Never assume that
because the repository-investigation step *knew* something (e.g. it's in
`analyzer_output.json`), a downstream LLM stage's prompt actually included
it — check the prompt file directly.

### `*.response.txt`

The raw, unparsed LLM output for that call — before any downstream JSON
parsing, regex classification (e.g. `_classify_finding` for Challenger
output), or calibration rewording. Use it to separate:

- **Model reasoning failure** — the response itself is wrong given what the
  prompt showed it.
- **Missing/bad input evidence** — the response is a *reasonable* inference
  from an incomplete or misleading prompt (check the paired `.prompt.txt`).
- **Downstream interpretation failure** — the response is fine, but a later
  deterministic step (classification, calibration, Trust Signal
  computation) mishandled it.

### `checkpoints.jsonl`

One JSON object per LLM call, in call order (written by `run_traced.py`'s
`write_manifest`):

```json
{"seq": 3, "stage": "patch_generation", "started_at": "...", "finished_at": "...",
 "prompt_chars": 4821, "response_chars": 1390,
 "prompt_file": "003_patch_generation.prompt.txt", "response_file": "003_patch_generation.response.txt"}
```

Use it to reconstruct the full call sequence and timing without opening every
file individually — `stage` here is the authoritative name to use instead of
relying on filename position (§8).

### `run_manifest.json`

Run-level summary, written once at the end. Two layers of content live in
the same file:

**Flat run-level fields:**
- Always: `llm_call_count`, `checkpoints_file`, `autopatcher_debug_artifacts`
  (absolute paths of the listed `reports/debug/` files that appeared during
  this run; pointers only, not copies), `compare_existing_tests`, and the raw
  values of the two deprecated budget flags (`context_budget_policy`,
  `max_context_budget_windows`, `null` when not passed).
- On success: `status: "success"`, `input_type`, `input_id`, `repo_root`,
  `output_dir`, `vulnerability_path`, `trust_report_path`.
- On failure: `status: "failed"`, `error_type`, `error_message`, plus every
  execution recorded before the failure.
- In blind mode: `blind_evaluation` (§25).

Note: **no provider/model field lives in the flat layer** — that's carried
in the structured `llm` block below instead (or read from the Trust
Report's Run Metadata table, §3.5, or `stderr` captured during the run).

**The structured, schema-versioned execution-graph layer** — every trace
`run_traced.py` writes today is schema version 3:

```jsonc
{
  "schema_version": 3,
  "kind": "full_run",
  "parent": null,
  "target_repository": {"repo_root": "/tmp/minimist-eval", "repo_commit": "<full 40-char SHA>"},
  "openant": {"patcher_commit": "<full 40-char SHA of the OpenAnt checkout that produced this trace>"},
  "llm": {"provider": "anthropic", "model": "claude-..."},
  "executions": [
    {
      "execution_id": "001_repository_analysis_and_remediation_planning",
      "canonical_stage": "repository_analysis_and_remediation_planning",
      "sequence": 1,
      "invocation_kind": "initial",
      "consumed": {},
      "outcome": "generated",
      "replay_of": null,
      "invoked_by": null,
      "artifact_path": "<output>/trace/executions/001_repository_analysis_and_remediation_planning.json",
      "llm_calls": [{"seq": 1, "stage": "remediation_planning", "started_at": "...", "finished_at": "...",
                     "prompt_chars": 4821, "response_chars": 1390, "prompt_file": "...", "response_file": "..."}],
      "external_calls": [],
      "timing": null
    }
    // ... one entry per recorded execution
  ]
}
```

A full run records **S1–S9 on every completed run**. S10 and S11 are
recorded only with `--compare-existing-tests`, a repository root, and a
non-empty patch that applies. S12/S13 are never separately recorded, because
they run together inside `_build_report` (see the architecture document's
[Canonical order vs. runtime order](../../../../../docs/auto-patcher/auto-patcher-architecture.md#canonical-order-vs-runtime-order)).
Executions are numbered in the order they *finish*. When S10/S11 run, they
are `007`/`008`, and S7–S9 become `009`–`011`.

Other fields: full-run `timing` is always `null` (replays set it).
`invocation_kind` is `"initial"` in full runs and `"replay"` in replays.
`invoked_by` is never set, and `external_calls` is always `[]`. Some records
carry extra keys, for example `canonical_contract_scope: "full"` on S4. See
the architecture document's
[Recording, provenance, and replay](../../../../../docs/auto-patcher/auto-patcher-architecture.md#recording-provenance-and-replay)
section. **Do not read `sequence` or the `NNN` prefix of `execution_id` as
the stage's canonical position.**

A trace with no `schema_version` key at all is a legacy trace, produced
before execution recording existed. `run_stage.py` still accepts it via a
bounded compatibility fallback (§19.8), but a legacy trace has no
structured `executions` list to resolve dependencies from — only the
Trust Report's prose Run Metadata table (§3.5) has any provenance for a
legacy run. `checkpoints.jsonl` is unaffected by any of this — it remains
exactly what §9's own description above says: a per-LLM-call index/
history, never a source of reconstructable stage state.

Each finished execution's own artifact (e.g.
`trace/executions/004_patch_generation_and_post_patch_investigation.json`)
holds that stage's actual output, serialized losslessly
(`execution_recorder.to_jsonable`) — this is what a replay handler reads
back and reconstructs into a typed Python object when that stage becomes a
dependency of something being replayed.

### `vulnerability.md`

The pipeline's *input* framing of the vulnerability — for CVE mode, this is
built from the fetched NVD advisory (`cve_fetcher.py`/`cve_converter.py`),
explicitly not repository-verified. This is the document every downstream
stage's prompt is ultimately grounded against; if the Trust Report says
something surprising about "the vulnerability," check whether it's actually
present here.

### `trust-report.md`

The final, user-facing artifact — Recommendation + Trust Signals + Run
Metadata. **Do not start debugging by trusting its prose.** It's downstream
output built from every earlier stage's results
(`core/patch.py`: "The Trust Report is treated as an opaque artifact: this
module never parses its Recommendation or Trust Signals, only the path it
was written to."). When a claim in the report looks wrong, trace it
backward:

```
report claim
  → the calibrated finding it came from (finding_calibration.response.txt)
  → the Challenger/Reviewer response that originated it (NNN_challenger.response.txt)
  → the prompt evidence that response was based on (NNN_challenger.prompt.txt)
  → repository ground truth (the actual source file)
```

### Investigation artifacts (`<label>-investigation/*.json`)

Produced by OpenAnt's repository parser (`core.parser_adapter.parse_repository`;
the file names below are the Python parser's), which Auto Patcher reuses for
candidate enrichment (`candidate_enrichment.build_investigation_context`).
`<label>-investigation/` holds the **pre-patch** parse only, and only when a
repository root was given. Post-Patch Investigation re-parses an isolated,
patched copy in a temporary directory that is deleted afterwards.

| File | Useful for asking |
|---|---|
| `scan_result.json` | Which files were even seen by the scanner? File inventory + size stats. |
| `functions.json` | Were the relevant functions/classes/methods actually extracted? |
| `call_graph.json` | Is the vulnerable function reachable from an entry point? Who calls it / does it call? |
| `analyzer_output.json` | Combined `functions` + `callGraph` + `reverseCallGraph` — the exact index `RepositoryIndex` builds candidate enrichment from. |
| `dataset.json` | Self-contained analysis units with resolved dependencies — useful for reproducing analysis outside the full pipeline. |

If a candidate/target-selection failure is suspected, this is where to look
first — before assuming an LLM stage reasoned incorrectly.

---

## Section 10 — Debug Artifacts Outside Trace Output

These exist only when `AUTOPATCHER_DEBUG=1` is set (automatically, by
`run_traced.py`; or manually, for a plain `openant patch` run). They are
written under `./reports/debug/` **relative to the process's current
working directory**, not `--output` and not the trace directory.
`run_traced.py` never copies them. It records the absolute paths of the
first four kinds below, if they appeared during the run, in
`run_manifest.json`'s `autopatcher_debug_artifacts` list.

| File | Writer | What it contains | Listed in the manifest? |
|---|---|---|---|
| `context_selection_{ts}.json` | `repo_locator.py` | Which candidate source-context selection happened and why | Yes |
| `edit_readiness_{ts}.json` | `pipeline.py` (S3) | Edit Readiness Gate decision, acquisition attempts, embedded `budget_trace` | Yes |
| `relocation_telemetry_{ts}.json` | `pipeline.py` (S4) | Content-relocation decisions made while repairing hunk headers (§14 Example A) | Yes |
| `post_patch_recovery_{ts}.json` | `pipeline.py` (S4) | Patch Target Conformance and Post-Patch Recovery details, embedded `budget_trace` | Yes |
| `patch_generation_context_{ts}.json` | `pipeline.py` (before S4) | Patch Generation context fit: `max_chars`, included sections, omissions and their reasons, `required_missing` | No |
| `prompt_{ts}.txt` | `patch_generator.py` | The full Patch Generation user message | No |

None of these can influence the patch: they are observability only.

**Explicitly: none of these is the mechanism that mutated the patch.** They
are logs *of* what the deterministic repair code (`diff_hunk_repair.py`,
`patch_applicability.py`) already decided — never read back by any
decision logic. If a run's relocation telemetry shows an unusual line-number
correction, that tells you the repair *happened*; it doesn't itself prove
whether the repair was correct — go read the actual before/after diff in the
`patch_generation` trace files and the real target file to confirm that.

---

## Section 11 — How to Debug a Run

**Core principle: do not start by guessing why the final recommendation is
wrong. Walk backward through evidence, one stage at a time, until you find
where correct information first went missing, distorted, or
misclassified.**

1. Confirm repository/version/SHA (§4) — is this even the right source?
2. Confirm the final recommendation (Trust Report's headline verdict).
3. Read the full Trust Report, including Trust Signals and Run Metadata.
4. Identify the *exact* suspicious claim or signal — quote it precisely.
5. Find which stage/finding originated that claim (Challenger?
   Calibration? a Trust Signal computation?).
6. Read that stage's raw `.response.txt`.
7. Read that stage's paired `.prompt.txt`.
8. Ask: **was the evidence the claim depends on actually present in the
   prompt?**
9. Compare that evidence against the real repository source.
10. If the failure concerns target selection, source ranges, diff
    mechanics, applicability, relocation, or recovery — inspect the
    relevant deterministic artifact (`checkpoints.jsonl`,
    `reports/debug/*.json`, the investigation JSON files) instead of
    guessing from the prose.
11. Find the *first* stage, in call order, where correct information became
    missing, distorted, incorrectly inferred, or incorrectly classified.
12. Fix that earliest systemic cause — not the downstream wording that
    merely reported its consequence.

---

## Section 12 — Failure Taxonomy

| Symptom | Likely layer | Artifacts to inspect first | What to prove before changing code |
|---|---|---|---|
| Wrong starting file | Candidate/target selection | `analyzer_output.json`, `call_graph.json`, `001_remediation_planning.*` | The correct file/symbol was reachable from the investigation index, not just "should have been obvious" |
| Correct target, missing relevant code | Evidence acquisition / context selection | `context_selection_*.json`, `edit_readiness_*.json`, the `remediation_planning`/`remediation_strategy` prompt | The missing code was actually excluded by budget/selection logic, not merely unread by you |
| Correct evidence, wrong remediation plan | Remediation reasoning | `001_remediation_planning.*`, `002_remediation_strategy.*` | The prompt contained the evidence the plan should have used |
| Correct semantic fix, malformed diff | Patch mechanics / deterministic repair | `NNN_patch_generation.response.txt`, `relocation_telemetry_*.json` | Whether `repair_hunk_headers`/`reconstruct_hunk_context` ran and what they changed (see §14 Example A) |
| Patch fails `git apply` | Applicability / diff reconstruction / retry | `checkpoints.jsonl` (look for a second `patch_generation`), `relocation_telemetry_*.json` | Whether deterministic repair alone was tried and failed before any retry |
| Unexpected second `patch_generation` call | Post-Patch Recovery regeneration or applicability-aware retry (the Challenger-driven repair uses `patch_repair_regeneration`) | `checkpoints.jsonl` stage sequence, both `patch_generation.response.txt` files, `post_patch_recovery_*.json` | Which mechanism fired and why |
| NO PATCH PRODUCED | A fail-closed gate in S1–S4 | Terminal output (`--verbose` gives the reason); `executions/001`–`004` outcomes (`planning_ungrounded`, `skipped_target_authority_unresolved`, `no_candidate_patch`, …); `edit_readiness_*.json`, `patch_generation_context_*.json`, `post_patch_recovery_*.json` | Which gate fired, and whether its input evidence was genuinely missing or merely not acquired |
| Correct patch, Challenger verdict not `VERIFIED_FIXED` | Challenger facts, citations, evidence completeness | `NNN_challenger.prompt.txt`/`.response.txt`; the S5 artifact (`classified_challenger.concerns[*]`: consequence, malformed reason) | Whether a concern is BLOCKING on its cited facts, UNRESOLVED because a quote was not in the repository-derived evidence the Challenger was shown, or fail-closed for structure (not exactly one primary concern, or prose in the legacy sections). `replay_challenger_reparse.py` re-derives this with zero LLM calls |
| Unsupported inference becomes "Observed" | Finding Calibration | `NNN_finding_calibration.*`, the paired `NNN_challenger.*`, S6 artifact (`finding_calibration`, `finding_calibration_evidence_acquisition`) | Which findings calibration received (it depends on whether the repair path ran), and whether a rerun with acquired evidence happened |
| Correct findings but wrong final color | Trust Signals / Recommendation Policy | Trust Report's Trust Signals table, `pipeline.py`'s `_compute_trust_signals`/`_build_recommendation_v1` | Which signal drove the decision, and whether `_reconcile_verification_status_with_calibration` narrowed `VERIFIED_FIXED` or calibration changed the defect count (see the [recommendation policy](../../../../../docs/auto-patcher/recommendation-policy.md)) |
| Different result on identical case | Non-determinism / first-divergence analysis | Two full trace directories, compared stage by stage | See §13 — find the *first* differing stage, not just the final report |
| Report contains a factual statement contradicted by source | Trace backward | Report → calibrated finding → Challenger/Reviewer response → prompt evidence → repository ground truth | Every hop in that chain, in order — don't skip straight from report to source |

---

## Section 13 — First-Divergence Analysis

There is no trace-comparison tool; this is a manual method.

We have observed the same real-CVE input produce different recommendations
across runs (non-determinism inherent to LLM calls). The correct approach is
**not** to diff only the two final Trust Reports — that only tells you *that*
they differ, not *why*.

Instead:

1. Produce two full trace directories, e.g. `/tmp/urllib3-trace-A` and
   `/tmp/urllib3-trace-B`, from the same repo state (same verified SHA).
2. Walk both `checkpoints.jsonl` files in parallel, matching by `stage`
   name (not numeric position — see §8) and sequence within that stage.
3. For each matched stage, diff the `.prompt.txt` pair first. If prompts
   differ, that's expected only if upstream evidence genuinely differs
   (e.g. a different evidence-acquisition result, a different earlier LLM
   output feeding this prompt) — anything else is a bug.
4. If prompts are identical, diff the `.response.txt` pair — this isolates
   pure LLM non-determinism at that stage.
5. Stop at the **first** stage where prompt or response meaningfully
   differs. Everything after that point is downstream consequence, not
   independent evidence — a later stage's differences are usually just
   propagation of the first divergence, and chasing them individually wastes
   time.
6. Manual path normalization is required if the two runs used different
   `--repo-root`/`--output` paths — prompts embed absolute paths, so a
   pure `diff` will show spurious differences on every prompt unless you
   normalize (e.g. `sed` both files' repo-root prefix to a placeholder)
   before comparing.

---

## Section 14 — Real Examples of Trace Reasoning

### Example A — malformed diff, mechanically starved

Shape: the LLM's `patch_generation` response contains a semantically correct
edit, but the unified-diff hunk header/context is wrong (drifted line
numbers, insufficient context, or hunks for one file split across multiple
header blocks). `check_applicability()` fails.

Debugging path: check `relocation_telemetry_*.json` and the raw
`patch_generation.response.txt`. Two deterministic repair passes run before
any LLM retry is even considered — `repair_hunk_headers` (arithmetic +
content-based header correction) and, only if that's still not applicable,
`reconstruct_hunk_context` (adds up to 3 lines of real, verbatim
repository context around each failing hunk, verified never to change the
semantic `+`/`-` delta before being adopted). Only if *both* fail does the
applicability-aware LLM retry fire (a second `patch_generation` call fed the
real content of the failed file plus a hint built from the `git apply`
error).

**Lesson: semantic correctness and mechanical diff applicability are
separate questions.** A "wrong patch" complaint might be a perfectly correct
edit that just needs deterministic repair — check whether repair ran and
succeeded before assuming the LLM's reasoning was at fault.

### Example B — missing transformation evidence

Shape: a producer writes some value, a consumer reads a related value, and
the Challenger/Calibration stage infers a data-flow relationship between
them — but an intermediate transformation exists in the real source that
the prompt never showed either stage. Calibration may then mark an inferred
behavior as "Observed" when it was never actually shown running end-to-end.

Debugging path: read the Challenger's prompt (`NNN_challenger.prompt.txt`)
and check whether the transformation step's source is actually included, not
just the producer and consumer. If it's absent, the inference is
unsupported by what the model actually saw, regardless of whether it happens
to be true in the real repository.

**Lesson: repository knowledge is not the same thing as evidence shown to
the LLM.** A producer and a consumer alone are not sufficient evidence for a
data-flow claim if an unseen transformation sits between them — always
verify by reading the prompt, not by reasoning about what "should" have been
included.

---

## Section 15 — How to Read LLM Call Counts

**Call count alone does not prove which code path ran.** A run changing
from, say, 8 calls to 7 could mean:

- deterministic repair (`repair_hunk_headers`/`reconstruct_hunk_context`)
  succeeded and eliminated the need for a retry that used to fire, **or**
- the initial `patch_generation` call simply happened to produce an
  applicable patch this time (LLM non-determinism), with no repair
  mechanism exercised at all, **or**
- an evidence-acquisition call did or didn't fire, independent of any
  repair/retry logic: a Planner reattempt, a Planner Claim Verifier call, the
  evidence-gap Strategy rerun, a `guided_context_request`, or a calibration
  rerun.

Before claiming a specific mechanism ran (or was newly avoided), always
cross-check:

1. The `patch_generation.response.txt` content itself (was the first patch
   already applicable, or is a repaired/retried version present?).
2. `checkpoints.jsonl`'s stage sequence (is there one `patch_generation` or
   two? one `challenger` or two — the defect-driven repair loop also adds a
   call).
3. `reports/debug/relocation_telemetry_*.json` / `edit_readiness_*.json` (did
   deterministic repair actually fire and what did it change?).

Only once all three agree should you conclude which mechanism actually
exercised. This is a regression-testing rule, not just a debugging one — "the
call count changed" is never sufficient evidence on its own in a PR
description or a bug report.

---

## Section 16 — Validation After a Code Change

1. Run the directly affected deterministic unit/integration tests, e.g.:
   ```bash
   cd <OPENANT_REPO_ROOT>/libs/openant-core
   python3 -m pytest tests/patch/test_diff_parsing.py tests/patch/test_pipeline_retry.py tests/patch/test_context_reconstruction.py -v
   ```
2. Run the relevant broader test suite (e.g. all of `tests/patch/`).
3. Pick the real CVE that originally exposed the problem being fixed.
4. Always start that CVE from a fresh clone, exact vulnerable version,
   verified SHA, and clean output directories (§4) — never re-run against a
   dirty checkout from a previous experiment.
5. Inspect actual behavior via the trace, not just the final Trust Report
   color.
6. For trace-related fixes, prove the intended *internal* behavior changed —
   e.g. if the goal is removing an unnecessary `patch_generation` retry,
   don't stop at "the report is green now." Prove: what the first generated
   patch looked like, whether deterministic recovery ran, and whether a
   second `patch_generation` call happened at all (§15).
7. Run the remaining real-CVE regression cases (§26) to check for
   regressions elsewhere.
8. Only after the above should the change be considered ready for commit.
   Committing remains a deliberate, human-controlled step; automated agents
   must not commit as part of this workflow.

---

## Section 17 — Copy-Paste Runbook

### A. Build CLI

```bash
cd <OPENANT_REPO_ROOT>/apps/openant-cli
go build -o bin/openant .
```

### B. Verify binary

```bash
hash -r
which openant
type -a openant
openant version
openant patch --help
```

### C. Clean + clone urllib3 example

```bash
rm -rf /tmp/urllib3-eval
rm -rf /tmp/urllib3-trace
git clone https://github.com/urllib3/urllib3.git /tmp/urllib3-eval
```

### D. Verify vulnerable SHA

```bash
cd /tmp/urllib3-eval
git checkout 2.0.5
git rev-parse HEAD
git status --short
```

Expected SHA for this worked example: `d9f85a749488188c286cd50606d159874db94d5f`.

### E. Run traced CVE

```bash
cd <OPENANT_REPO_ROOT>/libs/openant-core
unset LLM_PROVIDER
unset LLM_MODEL
python3 utilities/autopatcher/tools/run_traced.py --cve CVE-2023-43804 --repo-root /tmp/urllib3-eval --output /tmp/urllib3-trace
```

### F. List trace artifacts

```bash
find /tmp/urllib3-trace -maxdepth 4 -type f | sort
```

### G. Useful first files to inspect

```bash
cat /tmp/urllib3-trace/trace/run_manifest.json
cat /tmp/urllib3-trace/trace/checkpoints.jsonl
cat /tmp/urllib3-trace/patch/CVE-2023-43804-trust-report.md
```

---

## Section 18 — Starting a New Debugging Session

Supply this context at the start of any new session (human or AI) picking
up an investigation:

```
Repository:        <OPENANT_REPO_ROOT>
Branch:
Case (CVE/finding):
Version:
SHA:
Trace directory:
Result (Trust Report recommendation):
Observed problem:
Relevant artifacts:
Current hypothesis:
Uncommitted changes: (paste `git status --short`)
```

**"Current hypothesis" is not evidence.** Whatever hypothesis carries over
from a prior session must be re-verified against the actual trace artifacts
and repository source in the new session (§11) — don't accept it as
established just because it was written down before. Always check `git
status --short` too: an in-progress fix to `diff_hunk_repair.py` or
`pipeline.py` changes what "current behavior" even means for a trace
captured before that edit.

---

## Section 19 — Stage Replay

This is a second, distinct workflow from everything above. Sections 1–18
describe **one full traced run**; this section describes **rerunning
exactly one canonical pipeline stage's CURRENT code**, against upstream
state resolved from a prior run's lineage, without paying for (or waiting
on) the rest of the pipeline. §20–§23 build on this for chained replay,
failed-stage debugging, prompt inspection, and comparing full vs. replay
executions.

### 19.1 The two workflows

```
FULL TRACED RUN                         STAGE REPLAY

run_traced.py                           run_stage.py
  -> runs the full pipeline                -> consumes a source run/replay
  -> creates a replay-capable                 directory
     SOURCE RUN (schema-v3               -> resolves each dependency's
     run_manifest.json)                     EFFECTIVE execution via
                                             that source's lineage
                                          -> reruns ONLY the selected
                                             stage's CURRENT implementation
                                          -> creates an isolated new
                                             REPLAY RUN, itself a valid
                                             --source-run for a further
                                             replay (see §20)
```

Use `run_traced.py` first, exactly as in §7, to get a source run. Use
`run_stage.py` afterward, as many times as you like, each time you change
a stage's code/prompt and want to see the new result — without rerunning
every earlier stage.

### 19.2 When to use it

You already ran a full traced evaluation (§7), found that one stage
behaved incorrectly, and want to test a code/prompt fix to JUST that stage
against the SAME upstream state the original run used — without spending
tokens on, or waiting on, every other stage.

### 19.3 Currently replayable stages

`run_stage.py --stage` accepts any of the 13 canonical stage names
(`repository_analysis_and_remediation_planning`, `remediation_strategy`,
`guided_context_acquisition`,
`patch_generation_and_post_patch_investigation`, `challenger`,
`patch_repair_and_calibration`, `patch_review`, `confidence_scoring`,
`impact_and_behavior_analysis`, `test_analysis_and_plan`,
`existing_test_comparison`, `trust_signals_and_recommendation`,
`report_generation`). **12 of the 13 have a working replay implementation
today — every stage except `trust_signals_and_recommendation`.** That
stage's logic has no independent execution to replay in production either
— it is only ever computed as part of `report_generation`'s combined
Trust-Signals-and-report rendering; see the architecture document's
[Terminal reporting architecture](../../../../../docs/auto-patcher/auto-patcher-architecture.md#terminal-reporting-architecture)
for exactly why. Requesting it (or any genuinely unknown stage name) fails
immediately, before any file I/O or LLM call:

```
$ python3 utilities/autopatcher/tools/run_stage.py \
    --source-run /tmp/minimist-trace --stage trust_signals_and_recommendation --output /tmp/out
Stage 'trust_signals_and_recommendation' is registered but not replayable yet.
Currently replayable: repository_analysis_and_remediation_planning, remediation_strategy,
guided_context_acquisition, patch_generation_and_post_patch_investigation, challenger,
patch_repair_and_calibration, patch_review, confidence_scoring, impact_and_behavior_analysis,
test_analysis_and_plan, existing_test_comparison, report_generation.
```

To replay "the report," pass `--stage report_generation`. Its handler
rebuilds a `PipelineResult` from the persisted S1, S2, S4, S6, S7, S8 and S9
artifacts (plus S11 when present) and calls the real `_build_report()`,
which computes Trust Signals, the Recommendation and the report Markdown in
one call. It also writes `report.md`. Some fields have no persisted source,
for example relocation telemetry, source verification, and edit
readiness/acquisition. These are left empty, so a replayed report always
shows Source Verification as "Not Verified". The manifest's
`replay_limitations` field lists such gaps. Replay never falls back to
running the full pipeline.

Two handlers declare fewer dependencies than the stage's approved contract.

- `test_analysis_and_plan` is **transitional**. It declares no
  dependencies, calls `test_plan_discovery.discover_test_plan` directly, and
  produces only the `TestExecutionPlan`. Its manifest entry is tagged
  `"transitional": true`.
- `report_generation` declares 7 of its 12 approved dependencies.

Other prerequisites:

- `existing_test_comparison` needs a resolvable S10 execution. That exists
  only if the source ran with `--compare-existing-tests`, or if S10 was
  replayed first.
- Stages with `requires_repo_access` need the recorded checkout (§19.5). This
  includes `report_generation`.

See the architecture document's
[Recording, provenance, and replay](../../../../../docs/auto-patcher/auto-patcher-architecture.md#recording-provenance-and-replay)
section.

### 19.4 Usage

```bash
cd <OPENANT_REPO_ROOT>/libs/openant-core
python3 utilities/autopatcher/tools/run_stage.py \
  --source-run /tmp/minimist-trace \
  --stage patch_review \
  --output /tmp/minimist-patch-review-debug
```

Current arguments (`run_stage.py`'s `argparse` setup):

- **`--source-run`** (required): the path to a `run_traced.py` output
  directory, or to a prior replay's `--output` directory. Resolution is
  exact-name only, never a recursive or fuzzy search. This tool never
  modifies the source run. **Spell the path exactly as it was given to
  `run_traced.py --output`** (or to the earlier replay's `--output`). Each
  recorded `consumed` edge stores that path string, and dependency
  resolution compares identities as exact strings. A different spelling of
  the same directory may therefore resolve dependencies as `STALE`.
  **`--source-trace` is still accepted as a deprecated alias** (same
  destination) — use `--source-run` in new commands; `--source-trace` is
  kept only for backward compatibility with older invocations/scripts.
- **`--stage`** (required) — the canonical stage to replay (§19.3). Known
  but not-yet-replayable stages fail with a distinct message from
  genuinely unknown ones — both before any I/O.
- **`--output`** (required) — an isolated output directory for this
  replay's artifacts. Must not be the same as, nested inside, or contain
  `--source-run`.
- **`--repo-root`** (optional) — overrides the target repository path
  instead of the one recorded in the source run/replay (e.g. a second
  checkout on this machine) — still subject to the identical commit-SHA
  and clean-worktree checks described in §19.5, against the SHA the
  source recorded.

On success, `run_stage.py` prints a small JSON summary (`stage`,
`execution_id`, `outcome`, `output_dir`, `run_manifest`) and exits 0. Exits
are as follows:

- **Exit 2** with the reason on stderr: an engine or stage-replay error, such
  as an unknown or not-yet-replayable stage, an unsafe output directory, an
  unresolved or stale dependency, or a failed target-repository gate.
- **Traceback, exit 1**: other failures. These include a missing, invalid,
  or unsupported-schema manifest at `--source-run` (`LineageError`) and an
  unusable LLM configuration.

LLM-owning stages use the **current** OpenAnt LLM configuration (or
`LLM_PROVIDER=mock`), not the source run's provider.

### 19.5 The target-repository safety gate

This is the most important safety boundary, checked BEFORE any LLM call,
for every replayable stage that touches the repository:

1. The target repository (from the source run, or `--repo-root`) must
   exist and be a git repository.
2. Its current `HEAD` must **exactly match** the full SHA the source
   recorded. A legacy trace that recorded only a short SHA is matched by
   prefix.
3. Its working tree must be **clean** (`git status --porcelain` empty).

Any failure stops replay immediately, before any LLM call, with a
specific message, e.g.:

```
Cannot replay <stage>: target repository HEAD does not match source trace.
Expected: d9f85a749488188c286cd50606d159874db94d5f
Actual:   3a1c9e2...
```

```
Cannot replay <stage>: target repository contains uncommitted changes.
```

A stage that declares `requires_repo_access=False` in `stage_registry.py`
(e.g. `challenger`, `patch_review`, `confidence_scoring`,
`trust_signals_and_recommendation`) skips this check entirely — this is
the **capability-aware preflight** the architecture document describes:
a stage never pays for, or is blocked by, a check its own contract never
needed. `run_stage.py` never runs `git checkout`/`reset`/`clean` on the
target repository under any circumstances — it is purely observational.

**This gate applies ONLY to the target repository being analyzed — never
to the OpenAnt development checkout you're running `run_stage.py` from.**
The OpenAnt checkout may (and, mid-debugging, usually will) be dirty —
that's the point: you're testing an uncommitted change to a stage's code
or prompt. The manifest records which OpenAnt commit produced the source
and which one is replaying it, but never requires them to match, and
never blocks on the OpenAnt checkout being dirty.

### 19.6 Provenance: source vs. replay, recorded but never compared

Several identities are recorded on both sides of every replay, and are
**never required to match** — by design, since the whole point is testing
a current code change against historical target-repo state:

| | Must match? |
|---|---|
| Target repository commit SHA | **Yes, strictly** (§19.5) |
| Target repository clean working tree | **Yes** (§19.5) |
| OpenAnt implementation commit (`patcher_commit`) | **No** — recorded on both sides only |
| LLM provider/model | **No** — recorded on both sides only |

A successful replay makes LLM calls **only** with a `stage=` tag that the
replayed canonical stage owns (`stage_registry.STAGE_OWNED_LLM_TAGS`). Any
other captured tag aborts the replay as an "LLM ownership violation", so a
replay cannot silently call into another stage's logic. The prompt and
response files may already be on disk when this happens, but the stage
artifact and `run_manifest.json` are not written.

The replay manifest records both sides. Its `openant` block holds
`source_patcher_commit`, `replay_patcher_commit` and `replay_openant_dirty`.
Its `llm` block holds `source_provider`, `source_model`, `replay_provider`
and `replay_model`.

### 19.7 Output

```
/tmp/minimist-patch-review-debug/
  run_manifest.json                 # kind: "replay", parent: <source_run>
  001_patch_review.prompt.txt       # named NNN_<llm tag>, only if the stage made LLM calls
  001_patch_review.response.txt
  patch_review.json                 # <canonical_stage>.json; test_analysis_and_plan writes
                                    # test_execution_plan.json or rejection_reason.json;
                                    # report_generation also writes report.md
```

Prompt and response files are named after the LLM tag, not the canonical
stage. For example, a `challenger` replay writes `001_challenger.*`, and a
contract retry writes `002_patch_generation_contract_retry.*`. Replay output
is not write-once: reuse an empty `--output` directory per replay.

A directory always contains exactly one new execution
(`execution_id` sequence is always `1` within a replay directory — see
the architecture document's [Execution recording](../../../../../docs/auto-patcher/auto-patcher-architecture.md#execution-recording)).
A rejected/negative outcome (e.g. `test_analysis_and_plan` rejecting a
plan) is still a **valid, completed replay** (exit code 0) — the current
implementation ran, produced a result, and that result happened to be
negative for a specific, recorded reason. This is exactly what you inspect
to tell whether a prompt/code change fixed the problem. The preflight gates
(§19.3, §19.5, unresolved dependencies) fail before anything is written to
`--output`. A failure inside the stage itself can leave partial files behind.

The replay `run_manifest.json` uses the same v3 schema as a full run, with
`kind: "replay"` and exactly one execution. That execution has `sequence` 1,
`invocation_kind: "replay"`, and `timing` set (`started_at`, `finished_at`,
`duration_seconds`). It may also carry `transitional`, `replay_limitations`
and `canonical_contract_scope`.

### 19.8 Legacy traces

A legacy trace (no `schema_version` key in its `run_manifest.json`) is
still usable:
`run_stage.py` falls back to a **bounded** read of that Trust Report's own
`## Run Metadata` table (§9's `trust-report.md` section) — ONLY the `Repo
commit`, `Auto-patcher`, `LLM provider`, and `LLM model` table rows, via
fixed-shape row patterns, never a general prose scan. If that table is
missing, ambiguous (e.g. two `Repo commit` rows), or its `Repo commit`
value is `unknown`, replay fails closed with a specific reason rather than
guessing. Priority is always: structured manifest fields first, this
bounded fallback second, fail closed third — **never** silently. A trace
with a structured manifest never reads the Trust Report at all, for
anything.

### 19.9 Source run immutability

`run_stage.py` never modifies `--source-run` in any way — not
`run_manifest.json`, not `checkpoints.jsonl`, not any prompt/response
file, not the Trust Report, not any earlier `StageExecution` artifact. All
replay output goes only to `--output`, which must not be the same path
as, nested inside, or contain `--source-run` (checked before any other
work). This is what makes chained replay (§20) safe to build on: every
directory in a lineage stays byte-for-byte exactly what it was when it was
written.

---

## Section 20 — Chained Replay

**Chained replay means: use one replay's own output directory as the
`--source-run` for a further replay.** Nothing special has to be enabled
for this — it falls directly out of how `--source-run`/`--output` are
wired: every replay's manifest records its `parent` as the exact
`--source-run` it was invoked with, and the resolver walks `parent`
pointers transitively.

### 20.1 The workflow

```
full run                                     (produces S4, S5, S6, S7, ...)
  → replay S4  --source-run <full run>       --output replay-s4/
    → replay S5  --source-run replay-s4/     --output replay-s5/
      → replay S6  --source-run replay-s5/   --output replay-s6/
        → replay S7  --source-run replay-s6/ --output replay-s7/
```

```bash
cd <OPENANT_REPO_ROOT>/libs/openant-core

python3 utilities/autopatcher/tools/run_stage.py \
  --source-run /tmp/minimist-trace \
  --stage patch_generation_and_post_patch_investigation \
  --output /tmp/replay-s4

python3 utilities/autopatcher/tools/run_stage.py \
  --source-run /tmp/replay-s4 \
  --stage challenger \
  --output /tmp/replay-s5

python3 utilities/autopatcher/tools/run_stage.py \
  --source-run /tmp/replay-s5 \
  --stage patch_repair_and_calibration \
  --output /tmp/replay-s6

python3 utilities/autopatcher/tools/run_stage.py \
  --source-run /tmp/replay-s6 \
  --stage patch_review \
  --output /tmp/replay-s7
```

### 20.2 The resolver obtains dependencies through lineage — the immediate source does not need every dependency itself

This is the important part: **`--source-run` for a replay only needs to
contain (directly, or reachably through its own `parent` chain) the
dependency the replayed stage actually needs — it does not need to be, or
contain, every upstream stage itself.** When replaying S7 with
`--source-run /tmp/replay-s6`, the resolver:

1. Builds the full lineage chain: `[replay-s6, replay-s5, replay-s4, full run]`.
2. For S7's one declared dependency (`patch_repair_and_calibration`),
   finds the closest directory containing a matching execution —
   `replay-s6` itself — and consumes **that** (the replayed S6), not the
   original full-run S6.
3. If S7 needed a dependency that was never replayed anywhere in this
   chain (in this example, it doesn't — S7 only depends on S6), the
   resolver would keep walking up the chain and find it in the original
   `full run`, several hops back — still correctly resolved, with no
   special handling required at the call site.

Inspect `/tmp/replay-s7/run_manifest.json`'s one execution's `consumed`
field to see exactly which directory each dependency actually resolved
from — see §22 for what to look for.

### 20.3 Why this matters

If the resolver instead always used the *original* full run's S6 (ignoring
the replayed one), chaining a fix through S4→S5→S6→S7 would be pointless
— S7 would evaluate against the stale, pre-fix S6 every time. The
closest-ancestor-wins resolution with an exactness check (documented fully
in the architecture document's
[Effective dependency resolution](../../../../../docs/auto-patcher/auto-patcher-architecture.md#effective-dependency-resolution))
is what makes a chained replay actually exercise your change at every
downstream hop, while still correctly falling back to an original,
never-replayed upstream execution when there's nothing newer to prefer.

---

## Section 21 — Debugging a Failed Stage

A practical, end-to-end workflow combining everything above:

1. **Run a full trace.**
   ```bash
   cd <OPENANT_REPO_ROOT>/libs/openant-core
   python3 utilities/autopatcher/tools/run_traced.py \
     --cve CVE-2023-43804 --repo-root /tmp/urllib3-eval --output /tmp/urllib3-trace
   ```
2. **Inspect the failing execution/artifacts.** Open
   `/tmp/urllib3-trace/trace/run_manifest.json`, find the suspect stage's
   entry in `executions` (by `canonical_stage`, never by list position —
   see §9), and read its `artifact_path` (the stage's own settled output)
   and its `llm_calls` entries' `prompt_file`/`response_file` (§9's
   `*.prompt.txt`/`*.response.txt` guidance, §11's general debugging
   walk).
3. **Make a local code change** to the suspect stage's implementation or
   prompt (e.g. `patch_reviewer.py`).
4. **Replay only that stage**, from the original full run:
   ```bash
   python3 utilities/autopatcher/tools/run_stage.py \
     --source-run /tmp/urllib3-trace \
     --stage patch_review \
     --output /tmp/urllib3-replay-review-v2
   ```
5. **Inspect the new artifact/model interaction** — the new
   `run_manifest.json`, the new `.prompt.txt`/`.response.txt` pair, and
   the stage's own artifact file — exactly as you would for a full run's
   equivalent files (§9), asking the same questions (§11): was the
   evidence actually present in the prompt? did the response change in the
   way you intended?
6. **Optionally replay downstream stages from that new run**, chaining
   forward through whatever stages consume the one you just fixed (§20) —
   e.g. `--source-run /tmp/urllib3-replay-review-v2 --stage confidence_scoring`
   — to see the full downstream effect of your change without rerunning
   remediation planning, patch generation, or the Challenger again.

This is cheaper than re-running the full pipeline for every iteration of a
code or prompt fix. Replay calls the same stage implementation production
does. Some handlers, however, cannot reconstruct every production input:

- S1–S4 run without the parsed investigation context;
- S2 skips the evidence-gap fallback;
- S7/S8 run without the calibration summary;
- S8 also runs without the Challenger context.

Most of these gaps are recorded in the replay manifest's
`replay_limitations`; the S7/S8 calibration summary gap is not. Treat a
replay as production behavior given the reconstructed inputs, and confirm
important conclusions with a full traced run.

---

## Section 22 — Model Prompt/Response Inspection (replay)

The same rules from §9's `*.prompt.txt`/`*.response.txt` subsections apply
identically to a replay's own prompt/response files — they are written by
the same underlying capture mechanism (`llm_call_tracing.LLMCallCapture`,
§1). A replay's prompt/response pair is numbered starting from `001`
within its own output directory, regardless of what stage or how many
calls the source run made — never assume the numbering carries over from
the source.

To relate a replay's LLM call back to its execution record, read the
replay's one `executions` entry's `llm_calls` list. Replay entries carry
`seq`, `stage`, `prompt_file` and `response_file`. Full-run entries also
carry timestamps and character counts. The prompt and response text itself
is in the `.prompt.txt`/`.response.txt` files next to the manifest.

---

## Section 23 — Comparing Full vs. Replay Executions

When comparing a full run's execution of a stage against a later replay of
that same stage, these `run_manifest.json` fields are the ones that
matter:

| Field | What it tells you |
|---|---|
| `kind` | `"full_run"` vs `"replay"` — which directory produced this manifest. |
| `invocation_kind` | `"initial"` (a full run's execution) or `"replay"`. (`"retry"` is defined in the schema but no code path produces it today.) |
| `replay_of` | For a replay execution: the closest prior execution of the same canonical stage found anywhere in the source lineage — a provenance pointer, not a data dependency (never used by dependency resolution itself). |
| `consumed` | The exact `{run, execution_id}` this execution actually read for each dependency — compare this between the full run's execution and the replay's execution to see whether the replay picked up a newer (replayed) upstream input or inherited the same original one (§20.2). |
| `parent` (manifest-level, not per-execution) | Which directory this replay was invoked against — walk it manually, or via `lineage.build_chain`, to reconstruct the full lineage a given replay sits in. |
| `artifact_path` | Points at each execution's own settled-output JSON — diff the full run's artifact against the replay's artifact directly to see exactly what changed in the stage's output. |
| `llm_calls` (and the paired `.prompt.txt`/`.response.txt` files) | Diff the full run's prompt/response for this stage against the replay's — isolates whether a difference in behavior came from a prompt change, a code change downstream of the LLM call, or model non-determinism (same technique as §13's first-divergence analysis, applied to exactly two executions instead of two full traces). |

In short: don't just compare Trust Reports or final patches — compare the
specific execution records and artifacts, which is the whole reason the
execution-graph/replay infrastructure records what it consumed and where
its output landed.

---

## Section 24 — What This Is Not (Yet)

Stage replay reruns exactly one canonical stage per `run_stage.py`
invocation, using dependency state resolved from the source lineage. It
does **not** implement (and this document should not be read as
documenting) a single command that replays a whole *range* of stages in
one invocation (`--from-stage`/`--stop-after`), or evaluating an
externally-supplied candidate patch as if it were a stage's own output.
Chaining multiple stages (§20) today means invoking `run_stage.py` once
per stage, each time pointing `--source-run` at the previous hop's
`--output` — that is a real, fully-supported workflow, just not a single
multi-stage command yet. Don't assume a flag or behavior described here
extends beyond what's shown above.

---

## Section 25 — Blind Evaluation (historical regressions only)

`run_traced.py --cve <id> --repo-root <checkout> --blind-evaluation` runs a
historical CVE regression without handing the system under test the known
remediation. It is evaluation-only and off by default. `openant patch` and
`run_traced.py` without the flag behave exactly as before, and their
manifests never gain a `blind_evaluation` key. Implementation:
`blind_evaluation.py` (this directory).

**Where it acts.** On the output of `cve_converter.cve_to_vuln_text`, i.e.
*after* normal rendering (the converter's first-five-references selection is
never refilled), and only on lines inside the rendered `## References`
section. The raw NVD record, the converter, the fetcher and `core.patch` are
not modified; the interception is scoped to one `run_patch_cve()` call and
both wrapped functions are restored on exit.

**Filter contract `blind-evaluation-filter/v1`.**

| Reference form | Action |
|---|---|
| exactly `https://github.com/<owner>/<repo>/commit/<7-40 lowercase hex>` | removed (whole line) |
| exactly `https://github.com/<owner>/<repo>/compare/<ref>...<ref>` | removed (whole line) |
| any other `github.com` / `www.github.com` URL whose repository-relative route (after `/<owner>/<repo>/`) is `commit`, `commits`, `compare`, `pull` or `pulls` — e.g. query/fragment/trailing slash/`.patch`/`.diff` suffix, uppercase hex or route, two-dot or malformed range, `http://`, `www.`, port, userinfo, malformed owner/repo — or whose repository path ends in `.patch`/`.diff` | **abort before the pipeline**, reported, never removed |
| non-GitHub hosts: a path segment `commit`, `commits`, `compare`, `pull`, `pulls`, `pull-requests`, `merge_requests`, `merge-requests`, `changeset(s)`, `diff`; a `.patch`/`.diff` path; a gitweb commit/commitdiff/patch query (GitLab, Bitbucket, Gitea/Codeberg, cgit `/commit/`, Trac) | **abort before the pipeline**, reported, never removed |
| issues, advisory pages, mailing lists, NVD, project pages | kept |

"Exactly" means the whole URL is `https://github.com` + the path: no query,
fragment, trailing slash, suffix, port, userinfo, or host/scheme variant.
`<owner>` is alphanumerics with single inner hyphens; `<repo>` is
`[A-Za-z0-9._-]+` (not `.`/`..`); each compare `<ref>` is non-empty, does not
start or end with `.`, contains no `..`, and does not end in `.diff`/`.patch`.
GitHub owner and repository *names* are never inspected — an owner or repo
called `diff`, `pull`, `compare` or `commit` does not trigger an abort.

Nothing is rewritten and nothing is inserted. A removable or unsupported
code-change URL in prose (outside References) aborts the run as well.
Zero removable references is a valid blind run (identical hashes).

**Known V1 limitation.** V1 is not a universal forge detector. Code-change
links on other platforms — Gerrit / googlesource gitiles (`…/+/<rev>`,
`/c/<project>/+/<n>`), Mercurial (`/rev/<hex>`), cgit `/patch/` — are **not
recognized** and are kept as ordinary references; so are scheme-less links
and bare revision hashes in prose. V1 was scoped to the GitHub-hosted release
regression suite. Before using blind mode on a CVE whose references include
another forge, review its rendered References manually, or extend the policy
in a separately reviewed rule version.

**Verification.** `pipeline.run` is guarded for the duration of the run: it
proceeds only if the converter was intercepted exactly once and the incoming
`vulnerability_text` hashes to the blinded SHA256. After the run, the
`-vulnerability.md` artifact is checked against the same hash. Any deviation
is a `BlindEvaluationError` → failure manifest, exit code 2.

**Audit trail.** `run_manifest.json` → `blind_evaluation` (rule id, status,
original/blinded SHA256, removed lines/URLs, per-reference classification,
unsupported references, converter interception count, pipeline entry count,
pipeline-input hash and verification result). `trace/blind_evaluation/`
holds `original_vulnerability.md`, `blinded_vulnerability.md`,
`removed_reference_lines.txt` and `blind_evaluation.json`; it is written only
after the pipeline has finished, and `--output`/`--trace-dir` must be outside
`--repo-root` so the original text is never reachable by the run. Containment
is checked after resolving symlinks and `..`, and by filesystem identity of
existing ancestors (`os.path.samestat`), so case-variant spellings on a
case-insensitive filesystem and macOS `/System/Volumes/Data` aliases of the
repository are rejected too.

**Opt-in extension: `--blind-strip-same-repo-github-references`
(`blind-evaluation-same-repo-github/v1`).** Valid only together with
`--blind-evaluation`; supplied alone, `run_traced.py` exits 2 before doing
anything. Without it, blind evaluation is exactly the V1 contract above.

- **Target identity.** Read from `--repo-root`'s local `origin` remote
  (`git remote get-url origin` — configuration only, never contacted). Accepted
  forms: `https://github.com/<owner>/<repo>[.git]`, `http://`, `www.`,
  userinfo, `ssh://git@github.com[:port]/<owner>/<repo>[.git]`, and
  `git@github.com:<owner>/<repo>[.git]`; trailing slashes and one `.git` are
  dropped. Anything else (no origin, another forge, a deeper path, `git://`,
  `file://`) → exit 2 before the pipeline. `--repo-root` must itself be the
  repository's top level (`git rev-parse --show-toplevel` is the same
  directory, compared by filesystem identity); a subdirectory, or a plain
  directory nested inside another repository, → exit 2 (identity is never
  inherited from an enclosing repository). The remote is exposed — manifest,
  sidecar, diagnostics — only with URL userinfo removed
  (`https://user:secret@github.com/o/r.git` → `https://github.com/o/r.git`,
  `git@github.com:o/r.git` → `github.com:o/r.git`).
- **Rule.** Additionally remove a References line whose URL is an `http(s)`
  `github.com`/`www.github.com` URL whose first two path segments are exactly
  that `<owner>/<repo>` (case-insensitive, as on GitHub) — any route
  (`pull`, `issues`, `commit`, `compare`, `releases`, `discussions`, …) or the
  repository page itself. Matching is by repository identity and whole path
  segments, never by route list or substring: `<owner>/<repo>-other` and
  other owners are different repositories.
- **Interaction with V1.** V1 runs first, unchanged. A line V1 removes is
  attributed to V1 only (never double-counted). An unsupported same-repository
  code-change line (e.g. a `pull` URL) is removed by this policy instead of
  aborting. Unsupported references to any other repository or host, and every
  code-change URL outside the References section (same repository included),
  keep the V1 behavior (abort). Same-repository URLs in prose are never removed.
- **Audit.** The `blind_evaluation` manifest block (and sidecar
  `blind_evaluation.json`) gains, only in this mode: `removed_by_v1`,
  `removed_same_repo_github`, and `same_repo_github_policy` (`policy_id`,
  `target_repository`, `target_source`, `target_remote_url`). Existing fields
  keep their meaning: `removed_references` / `removed_reference_lines` /
  `removed_count` list every removed line in document order;
  `original_sha256` / `blinded_sha256` hash the exact original and final text;
  `rule_id` stays `blind-evaluation-filter/v1`. Default-mode manifests are
  unchanged.

**Opt-in contract `blind-evaluation-filter/v2` (`--blind-filter-policy v2`).**
Valid only with `--blind-evaluation` (alone, `run_traced.py` exits 2 before
doing anything); the default stays `v1`, whose behavior and manifests are
unchanged. `blind_evaluation.rule_id` records the contract actually applied.
The full contract is in `blind_evaluation.py`'s module docstring (V2 section);
in short:

- **Classification is separate from transformation.** `classify_url_v2` says
  what a URL is (`code_change`, `revision_pinned_content`,
  `malformed_code_change_url`, `ordinary`); what may be done to the text is
  decided by structural context only.
- **Two passes.** Pass 1 collects hex revisions named by code-change URLs in
  the rendered text and in the advisory record's raw reference URLs (including
  those past the five-reference rendering cap) -- never fetched, no git
  history. Pass 2 treats a `blob`/`tree`/`blame`/`raw` (or
  `raw.githubusercontent.com`) link as leakage only when its revision
  prefix-matches a pass-1 revision; other pinned links are kept.
- **Contexts.** Code-change References entries and standalone link-only lines
  are deleted; a line of exactly
  `[bullet] Resolved|Fixed|Patched|Fix|Patch [in|by|via][:] <links>[.]` is
  deleted (the only phrase-level rule); elsewhere only the unsafe span is
  replaced (`[link removed]`, a Markdown link's own text, or -- for a pinned
  link under the target repository whose normalized path exists in the
  checkout -- the repository-relative path, with revision, query and line
  anchor dropped). A deleted paragraph also takes the blank line before it.
- **Bare remediation revisions.** A standalone 7-40 hex token in prose that
  prefix-matches (either direction, case-insensitive) a pass-1 revision is
  replaced -- token only -- by `[revision removed]` (action
  `redact_revision`); inside inline code only when the code span is exactly
  that token (backticks kept). Tokens inside URLs, identifiers, larger code
  spans or fenced code are never rewritten.
- **Fail closed** on malformed code-change URLs, eligible URLs in fenced or
  inline code, URLs truncated in the summary heading, ambiguous Markdown, and
  any known remediation revision the token rule may not redact.
- **Invariants.** The complete blinded text is rescanned (no code-change,
  malformed or remediation-pinned URL; no remediation revision), and the
  recorded transformations must replay to it exactly; otherwise abort.
- **Audit.** V2-only keys: `removed_by_v2` (References lines removed by the
  filter itself; `removed_by_v1` never appears under v2), `transformations`
  (action, context, line, original line/span, URL, replacement, category,
  reason, matched revision, path retention), `transformation_count`,
  `remediation_revisions`, `raw_reference_url_count`, `path_retention`,
  `post_transform_checks`; sidecar `transformations.json`. Path retention uses
  the same-repo target when `--blind-strip-same-repo-github-references` is
  given, otherwise `--repo-root`'s GitHub `origin` if there is one; with no
  identity, pinned links are removed rather than path-reduced.

---

## Section 26 — Batch Real-CVE Evaluation (`run_cve_batch.py`)

Real-CVE regression suites are run with `run_cve_batch.py` (this directory);
the complete guide — options, manifest rules, output layout, statistics
semantics, ZIP contents, resume and exit codes — is
[`RUN_CVE_BATCH.md`](RUN_CVE_BATCH.md).

```bash
cd <OPENANT_REPO_ROOT>/libs/openant-core
python3 utilities/autopatcher/tools/run_cve_batch.py \
    --manifest utilities/autopatcher/tools/cfp_evaluation_cases.yaml --jobs 2
python3 utilities/autopatcher/tools/run_cve_batch.py --resume /tmp/openant-cve-batches/<batch-id>
```

Each case attempt gets a fresh clone at the exact manifest SHA (verified
HEAD, origin and clean tree), its own `--output`, and its own working
directory — mandatory, because the `AUTOPATCHER_DEBUG` writers of §10
resolve `./reports/debug/` against the process CWD. `run_traced.py` is
invoked unchanged with the canonical flags (`--context-budget-policy always
--max-context-budget-windows 10 --blind-evaluation
--blind-strip-same-repo-github-references`). The two budget flags are
deprecated no-ops (§5), kept so batch command lines stay identical.

The case outcome is read from the Trust Report's decision card (its first
`##` heading). It counts only when the run manifest proves success, identity
and verified blind evaluation. A valid `NO PATCH PRODUCED` result is counted
as Gray, a legitimate outcome, never as a failure. Default concurrency is
`--jobs 2`; above 4 the runner warns. See `RUN_CVE_BATCH.md` §6 for the
outcome and failure vocabulary.
