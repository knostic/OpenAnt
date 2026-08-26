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

Everything below was verified against the current working tree of this repo
(`/Users/goddess/dev/OpenAnt`) on 2026-08-13, branch `auto-patcher`, including
the uncommitted changes to `diff_hunk_repair.py`, `diff_parsing.py`,
`pipeline.py` and the `tests/patch/` files shown by `git status`, plus the
subsequent relocation of this tooling out of the (still gitignored)
`scripts/local/` into `utilities/autopatcher/tools/` as a tracked Auto
Patcher development capability. Where behavior recently changed (see the
LLM-configuration refactor in §3), this document describes **only** the
current state — not the superseded one.

Generic placeholder: `<OPENANT_REPO_ROOT>` stands in for
`/Users/goddess/dev/OpenAnt` wherever a path is otherwise specific to this
machine.

---

## Section 1 — Repository / Tooling Map

| Area | Role |
|---|---|
| `apps/openant-cli` | Go CLI (`openant`). Thin transport layer: parses flags, resolves the active project, and shells out to the Python engine via `python.Invoke`. Does **no** LLM resolution, patch logic, or trace capture of its own. |
| `libs/openant-core` | The Python engine. Contains `openant/cli.py` (the actual `patch` subcommand argparse + entry point), `core/patch.py` (`run_patch`/`run_patch_cve`, artifact writing), and `utilities/autopatcher/` (the pipeline itself). |
| `libs/openant-core/utilities/autopatcher/tools/run_traced.py` | In-process tracing wrapper, tracked normally as part of the Auto Patcher subsystem. Calls the same `core.patch.run_patch`/`run_patch_cve` functions the CLI calls, but intercepts every LLM call to record prompt/response to disk. Also the **canonical producer of replay-capable source traces** (see §19) — every trace it writes now carries structured, versioned provenance in `run_manifest.json`, not just prose. |
| `libs/openant-core/utilities/autopatcher/tools/run_stage.py` | Single-stage debug replay tool (see §19), same directory. Consumes a `run_traced.py` source trace and reruns exactly ONE pipeline stage's CURRENT implementation against that trace's recorded upstream state — never the full pipeline. Phase 1 supports exactly one stage: `test_plan_discovery`. |
| `libs/openant-core/utilities/autopatcher/stage_replay.py` | The reusable, importable single-stage replay logic `run_stage.py` is a thin CLI wrapper around — trace-loading, provenance/schema resolution, target-repo identity checks, and the `test_plan_discovery` replay lifecycle itself. |
| `libs/openant-core/utilities/autopatcher/llm_call_tracing.py` | The shared LLM-call-capture mechanism (`LLMCallCapture`) both `run_traced.py`'s `LLMCallTracer` and `stage_replay.py` build on — monkeypatch `call_llm`, record each call in order, restore on exit. |
| Auto Patcher pipeline (`libs/openant-core/utilities/autopatcher/pipeline.py` + sibling modules) | Orchestrates remediation planning → patch generation → challenger → calibration → review → confidence scoring → Trust Signals → Recommendation. Mix of LLM calls and deterministic Python logic. |
| Trace output (`<output>/trace/`) | Written only when running via `run_traced.py`. Per-call prompt/response text files, `checkpoints.jsonl`, `run_manifest.json`. |
| Debug artifacts (`./reports/debug/*.json`) | Written by the *production* pipeline itself whenever `AUTOPATCHER_DEBUG=1` is set (by hand, or automatically by `run_traced.py`). Observability-only — never fed back into pipeline decisions. |
| Trust Report (`<patch_dir>/<label>-trust-report.md`) | The final, user-facing artifact. Produced by every run (traced or not). Downstream of everything else — treat it as a claim to verify, not a starting fact. |

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
cd /Users/goddess/dev/OpenAnt/apps/openant-cli
go build -o bin/openant .
```

### 2.2 One-time symlink setup (if you don't already have one)

Run once, from the repo root:

```bash
ln -sf "/Users/goddess/dev/OpenAnt/apps/openant-cli/bin/openant" /usr/local/bin/openant
```

After this, every `go build -o bin/openant .` is picked up immediately with
no further steps.

### 2.3 If you use `sudo cp` instead

The task that produced this document was framed around `sudo cp
bin/openant /usr/local/bin/openant`. That command still *works* — but if
`/usr/local/bin/openant` is the symlink from §2.2, `cp` follows the symlink
and writes through it to the same underlying file (`bin/openant`) that is
already the source. That's exactly why you may see:

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
This has been observed concretely on this machine:

- `/usr/local/bin/openant` — the Go CLI binary this document is about.
- `/Library/Frameworks/Python.framework/Versions/3.12/bin/openant` — an
  unrelated Python package's console-script entry point that happens to
  share the name `openant`.

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
(if detectable) the resolved Python interpreter version — a quick way to
notice if you're accidentally running a stale or wrong binary. `openant
patch --help` should show, at minimum, `--finding-id`, `--cve`,
`--repo-root`, `--output`/`-o`, `--context-budget-policy`, and
`--max-context-budget-windows`, plus the global `--json`, `--quiet`/`-q`,
`--api-key`, and `--project`/`-p` flags.

---

## Section 3 — LLM Configuration (current behavior)

**This section describes only the current, post-refactor behavior** (commit
`7b59b1a`, "refactor(auto-patcher): align LLM configuration with OpenAnt",
which deleted the previous Auto-Patcher-specific `patch_llm.go` and
`llm_config.py`). Earlier commits on this branch (`d214bae`, `6753e22`)
represent a superseded intermediate design — do not treat them as current.

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

`LLM_PROVIDER` and `LLM_MODEL` are read in exactly one module
(`utilities/autopatcher/llm_client.py`) and **are no longer a way to select a
real provider/model**. If either is set to anything other than the one
exception below, Auto Patcher raises immediately:

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

No failure mode (missing config, missing credentials, auth error, rate
limit, malformed response, model-not-found) degrades into mock. All of
those re-raise a real error. There is one vestigial, display-only code path
(`LLMClient.__init__`/`is_mock` falling back to `not bool(OPENAI_API_KEY)`
when nothing else has set `_cached_provider` yet) — per its own test suite's
comment, "it never selects anything itself." Don't rely on it; it's legacy
plumbing kept only for a label, not a selection mechanism.

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

2. **Live stderr during the run**, from `llm_client.call_llm()`:

   ```
   Using Anthropic (model: claude-...)
   ```
   or, in mock mode:
   ```
   Using mock LLM
   ```

The CLI's own stdout summary (`PrintPatchSummary`) does **not** print
provider/model — only the finding/CVE id and the Trust Report path. Always
check the Trust Report's metadata table or the stderr log, never assume.

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

## Section 5 — Baseline Run Flags

```
--context-budget-policy always
--max-context-budget-windows 10
```

Both flags are defined identically in the Go CLI (`patch.go`) and in
`run_traced.py`, and are validated **only** in Python
(`openant/cli.py:1652-1675` / `utilities/autopatcher/context_budget.py`) —
Go is pure transport (`appendContextBudgetArgs` forwards a flag only if the
user explicitly set it, never inferring a value).

What they actually govern, verified against `context_budget.py` and its
call sites in `remediation_planner.py`:

- **`--context-budget-policy`** controls whether the pipeline is allowed to
  request *additional fixed-size windows* of repository source text once a
  stage's character budget for gathering context is exhausted. This is a
  **capacity** ceiling, not a safety or verification gate.
  - `never` — always refuses (fail-closed on exhaustion).
  - `always` — auto-approves extensions up to the hard cap below.
  - `ask` — interactive Y/N prompt (default No) if stdin is a TTY, otherwise
    silently degrades to `never`.
- **`--max-context-budget-windows`** — a hard ceiling on total windows
  (initial + every approved extension) per acquisition stage, enforced
  regardless of policy. Once reached, further extension requests fail
  closed even under `always`.

Using `always` + `10` for baseline/regression runs means: don't let an
artificially small context window be the reason a run under-performs, but
still cap total growth so a run can't spiral unboundedly. Every extension
decision (policy, decision source, per-stage window counts) is recorded in
`ContextBudgetController.to_trace_dict()`, which is embedded verbatim as a
`"budget_trace"` field inside the `edit_readiness_*.json` and
`post_patch_recovery_*.json` debug artifacts (see §10) — useful when a run's
behavior seems context-starved.

Use these two flags in every standard real-CVE regression command, unless
the experiment is specifically about context-budget behavior itself.

---

## Section 6 — Normal Auto Patcher Run

```bash
openant patch --cve CVE-2023-43804 \
  --repo-root /tmp/urllib3-eval \
  --context-budget-policy always \
  --max-context-budget-windows 10
```

or, for a Finding produced by a prior OpenAnt scan (instead of a CVE):

```bash
openant patch --finding-id <finding-id> \
  --context-budget-policy always \
  --max-context-budget-windows 10
```

`--output` defaults to the active project's scan directory; pass `-o
<dir>` to redirect it. `--repo-root` defaults to the active project's repo
path for `--finding-id` mode, but is **required** for `--cve` mode unless a
project is active.

### Normal run vs. traced run — when to use which

| | `openant patch` | `utilities/autopatcher/tools/run_traced.py` |
|---|---|---|
| Purpose | Product/regression behavior — "does this CVE end up Deploy After Validation / Do Not Apply as expected?" | Deep investigation — "why did each stage decide what it decided?" |
| Invocation | Go CLI → Python subprocess | In-process Python, no subprocess |
| LLM call visibility | None beyond stderr logging and the final Trust Report | Every prompt + raw response saved to disk, per call |
| Extra artifacts | None beyond the standard `patch/` output | `trace/` directory: prompts, responses, `checkpoints.jsonl`, `run_manifest.json` |
| Use when | Confirming end-to-end product behavior, running the regression suite | Root-causing a specific failure, comparing two runs stage-by-stage |

Use `openant patch` first to confirm *whether* something is wrong; reach for
`run_traced.py` to find out *why*.

---

## Section 7 — Traced Run

```bash
cd /Users/goddess/dev/OpenAnt/libs/openant-core
python3.12 utilities/autopatcher/tools/run_traced.py \
  --cve CVE-2023-43804 \
  --repo-root /tmp/urllib3-eval \
  --output /tmp/urllib3-trace \
  --context-budget-policy always \
  --max-context-budget-windows 10
```

`run_traced.py` requires Python 3.11+ (`libs/openant-core/pyproject.toml`
pins `requires-python = ">=3.11"`); any interpreter satisfying that with the
project's dependencies installed works — `python3.12` above is this
machine's convention, not a hard requirement. Run it with the working
directory at `libs/openant-core` (as shown): the script inserts that
directory onto `sys.path` itself for imports, but the debug-artifact writers
it triggers (§10) resolve `./reports/debug/` relative to the process's
current working directory, not `--output`.

### What `run_traced.py` does differently from `openant patch`

Per its own module docstring, it is a "thin tracing ADAPTER" — it does not
reimplement or duplicate any Auto Patcher logic:

1. Parses the *same* `--context-budget-policy`/`--max-context-budget-windows`
   flags, reusing `openant/cli.py`'s own validator and
   `utilities.autopatcher.context_budget` constants.
2. Builds one real `ContextBudgetController`, exactly as `openant patch`
   does.
3. Calls `core.patch.run_patch()` / `run_patch_cve()` **in-process** (not via
   subprocess) — the same functions the CLI calls — so it can observe every
   LLM call made during that call.
4. Monkeypatches `utilities.autopatcher.llm_client.call_llm` — the single
   choke point every stage's `LLMClient.complete()` goes through — purely
   to record each call's prompt and raw response before/after delegating to
   the real, unmodified `call_llm()`. This changes nothing about provider
   resolution, mock fallback, retries, or content.
5. Sets `AUTOPATCHER_DEBUG=1` for the run's duration (restoring whatever was
   there before), so the pipeline's own existing debug-artifact writers fire
   exactly as they would for any other `AUTOPATCHER_DEBUG=1` run.

### What it captures vs. does not

| Captured? | Item |
|---|---|
| ✅ | Every rendered prompt sent to an LLM stage (`NNN_<stage>.prompt.txt`) |
| ✅ | Every raw LLM response (`NNN_<stage>.response.txt`) |
| ✅ | Per-call metadata: sequence, stage, timestamps, char counts, filenames (`checkpoints.jsonl`) |
| ✅ | Run-level metadata: status, input type/id, repo root, output dir, budget policy/windows, artifact paths, LLM call count (`run_manifest.json`) |
| ✅ (as pointers, not copies) | Filenames of any `reports/debug/*.json` artifacts that appeared during the run |
| ✅ | The same production `patch/<label>-vulnerability.md` and `<label>-trust-report.md` that a normal run also produces |
| ✅ | The same production investigation artifacts (`<label>-investigation/*.json`) that a normal run also produces |
| ❌ | It does **not** copy `reports/debug/*.json` into the trace directory — those stay at `./reports/debug/` relative to CWD |
| ❌ | It does **not** implement its own budget-policy decisions, TTY handling, or window-cap enforcement — all of that is the real `ContextBudgetController` |
| ❌ | It does **not** reformat, re-derive, or reinterpret anything it captures |

---

## Section 8 — Trace Directory Structure

A representative run produces:

```
/tmp/urllib3-trace/
  patch/
    CVE-2023-43804-vulnerability.md
    CVE-2023-43804-trust-report.md
    CVE-2023-43804-investigation/
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
    005_finding_calibration.prompt.txt
    005_finding_calibration.response.txt
    006_patch_review.prompt.txt
    006_patch_review.response.txt
    007_confidence_scorer.prompt.txt
    007_confidence_scorer.response.txt
    checkpoints.jsonl
    run_manifest.json
```

(`reports/debug/*.json`, if `AUTOPATCHER_DEBUG=1` fired any writers, land
separately at `libs/openant-core/reports/debug/` — see §10 — and are only
*referenced* from `run_manifest.json`, not present under `/tmp/urllib3-trace/`.)

### Call numbering is NOT semantically fixed

The prefix number (`NNN`) is just `seq`, a 1-based counter over *however
many LLM calls this particular run happened to make*, generated at
`run_traced.py`'s `_traced_call_llm`:

```python
prompt_path = self.trace_dir / f"{seq:03d}_{stage}.prompt.txt"
response_path = self.trace_dir / f"{seq:03d}_{stage}.response.txt"
```

Real pipeline stage names, in normal execution order (from
`remediation_planner.py`, `patch_generator.py`, `patch_reviewer.py`,
`patch_challenger.py`, `confidence_scorer.py`, `finding_calibration.py`):
`remediation_planning`, `remediation_strategy`, optionally
`guided_context_request`, `patch_generation`, `patch_review`, `challenger`,
`confidence_scorer`, `finding_calibration`.

A run that triggers the applicability-aware retry (§9's `patch_generation`
discussion, §12) inserts a **second** `patch_generation` call, shifting
every later position by one:

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

One JSON object per LLM call, in call order. Exact schema (from
`LLMCallTracer._traced_call_llm`):

```json
{"seq": 3, "stage": "patch_generation", "started_at": "...", "finished_at": "...",
 "prompt_chars": 4821, "response_chars": 1390,
 "prompt_file": "003_patch_generation.prompt.txt", "response_file": "003_patch_generation.response.txt"}
```

Use it to reconstruct the full call sequence and timing without opening every
file individually — `stage` here is the authoritative name to use instead of
relying on filename position (§8).

### `run_manifest.json`

Run-level summary, written once at the end. Fields actually present:

- Always: `llm_call_count`, `checkpoints_file`, `autopatcher_debug_artifacts`
  (absolute paths to any `reports/debug/*.json` files that appeared during
  this run — pointers only, not copies).
- On success: `status: "success"`, `input_type`, `input_id`, `repo_root`,
  `output_dir`, `context_budget_policy`, `max_context_budget_windows`,
  `vulnerability_path`, `trust_report_path`.
- On failure: `status: "failed"`, `error_type`, `error_message`,
  `context_budget_policy`, `max_context_budget_windows`.

Note: **no provider/model field is in `run_manifest.json`** — for that,
read the Trust Report's Run Metadata table (§3.5), or `stderr` captured
during the run.

Use `run_manifest.json` to verify: run identity (`input_type`/`input_id`),
where the final artifacts landed, whether the run succeeded, and the total
call count (see §15 for why call count alone isn't diagnostic).

**As of this feature, that "no provider/model field" note above is only
true of the pre-existing flat fields.** Every NEW trace additionally
carries structured, versioned replay provenance in the same file:

```json
{
  "schema_version": 1,
  "target_repository": {"repo_root": "/tmp/minimist-eval", "repo_commit": "<full 40-char SHA>"},
  "openant": {"patcher_commit": "<full 40-char SHA of the OpenAnt checkout that produced this trace>"},
  "llm": {"provider": "anthropic", "model": "claude-..."}
}
```

merged into the exact same `run_manifest.json`, alongside (never replacing)
every pre-existing flat field above. This is what makes a trace produced by
this script **replay-capable by design** — see §19. A trace with no
`schema_version` key at all is a legacy trace (produced before this
feature existed); `run_stage.py` still accepts it via a bounded
compatibility fallback (§19.3), but a legacy trace has no structured
`target_repository`/`openant`/`llm` block — only the Trust Report's prose
Run Metadata table (§3.5) has that provenance for a legacy run.
`checkpoints.jsonl` is unaffected by any of this — it remains exactly what
§9's own description above says: a per-LLM-call index/history, never a
source of reconstructable stage state.

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

Produced by OpenAnt's general repo-parsing pipeline
(`parsers/python/parse_repository.py`), reused by Auto Patcher for its own
candidate enrichment (`candidate_enrichment.py:build_investigation_context`).
Written **twice** per run: once pre-patch, once post-patch against an
isolated patched copy of the repo.

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
working directory** — not `--output`, and not the trace directory.
`run_traced.py` never copies them; it only records their filenames as
pointers inside `run_manifest.json`'s `autopatcher_debug_artifacts` list.

| File | Writer | What it contains | Can it influence the patch? |
|---|---|---|---|
| `context_selection_{ts}.json` | `repo_locator.py:_write_debug_artifact` | Which candidate source-context selection happened and why | **No** — observability only |
| `edit_readiness_{ts}.json` | `pipeline.py` (inline, after Slices 1–3) | Edit-readiness gate decision + embedded `budget_trace` | **No** — observability only |
| `relocation_telemetry_{ts}.json` | `pipeline.py` (inline) | Content-relocation decisions made while repairing hunk headers (§12 Example A) | **No** — observability only |
| `post_patch_recovery_{ts}.json` | `pipeline.py` (inline, after Slice 4) | Post-patch recovery attempt details + embedded `budget_trace` | **No** — observability only |

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
| Unexpected second `patch_generation` call | Applicability-aware retry (or Challenger-driven repair loop) | `checkpoints.jsonl` stage sequence, both `patch_generation.response.txt` files | Which of the two distinct retry mechanisms fired (`pipeline.py`'s applicability retry vs. its defect-driven Challenger repair loop) and why |
| Correct patch, Challenger says still vulnerable | Challenger prompt + evidence completeness | `NNN_challenger.prompt.txt`, `NNN_challenger.response.txt` | Whether the Challenger's prompt actually contained the patched code, or stale/partial evidence |
| Unsupported inference becomes "Confirmed" | Finding Calibration | `NNN_finding_calibration.*`, the paired `NNN_challenger.*` it was calibrating | Whether Calibration only reclassifies `plausible_risk`/`generic` findings (by design it never touches `confirmed_defect`/`validation_gap`) |
| Correct findings but wrong final color | Trust Signals / Recommendation Policy | Trust Report's Trust Signals table, `pipeline.py`'s `_compute_trust_signals`/`_build_recommendation_v1` | Which of the six signals (patch_integrity, security_improvement, remediation_alignment, coverage_confidence, test_availability, deployment_safety) drove the mapping |
| Different result on identical case | Non-determinism / first-divergence analysis | Two full trace directories, compared stage by stage | See §13 — find the *first* differing stage, not just the final report |
| Report contains a factual statement contradicted by source | Trace backward | Report → calibrated finding → Challenger/Reviewer response → prompt evidence → repository ground truth | Every hop in that chain, in order — don't skip straight from report to source |

---

## Section 13 — First-Divergence Analysis

**`compare_traces.py` does not currently exist anywhere in this repository**
(verified by both filename and full-text search across the whole repo).
Don't invent a command for it — the correct current approach is a manual
methodology, described here, until such a script is committed.

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
   (e.g. a different budget-extension decision, a different earlier LLM
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

If you build tooling to automate this, name it and document it here — but do
not claim `compare_traces.py` exists until it's actually committed.

---

## Section 14 — Real Examples of Trace Reasoning

These are generalized methodology lessons, not a historical diary — don't
extend this list into a running log of every bug ever found.

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
- a context-budget extension request (`guided_context_request`) did or
  didn't fire, independent of any repair/retry logic.

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
   cd /Users/goddess/dev/OpenAnt/libs/openant-core
   python3.12 -m pytest tests/patch/test_diff_parsing.py tests/patch/test_pipeline_retry.py tests/patch/test_context_reconstruction.py -v
   ```
2. Run the relevant broader test suite (e.g. all of `tests/patch/`).
3. Pick the real CVE that originally exposed the problem being fixed.
4. Always start that CVE from a fresh clone, exact vulnerable version,
   verified SHA, and clean output directories (§4) — never re-run against a
   dirty checkout from a previous experiment.
5. Use the standard `--context-budget-policy always
   --max-context-budget-windows 10` flags, unless the change specifically
   concerns context-budget behavior.
6. Inspect actual behavior via the trace, not just the final Trust Report
   color.
7. For trace-related fixes, prove the intended *internal* behavior changed —
   e.g. if the goal is removing an unnecessary `patch_generation` retry,
   don't stop at "the report is green now." Prove: what the first generated
   patch looked like, whether deterministic recovery ran, and whether a
   second `patch_generation` call happened at all (§15).
8. Run the remaining real-CVE regression cases you have available to check
   for regressions elsewhere.
9. **Experiment Registry:** a repo-wide search (code, docs, `CLAUDE.md`
   files) for "Experiment Registry" found no matches — this concept does
   not currently exist as a named, documented location in this project.
   (There is an unrelated `experiment.py` benchmarking script for the SAST
   scan pipeline, referenced in `libs/openant-core/CLAUDE.md` — it is not an
   "Experiment Registry" and is unrelated to Auto Patcher.) If a future
   version of this project introduces one, update this section with its
   real name and location rather than assuming this description still
   applies.
10. Only after the above should the change be considered ready for commit.

**AI coding agents must NOT commit automatically as part of this workflow.**
Commit remains a deliberate, human-controlled step — regardless of how
confident validation looks.

---

## Section 17 — Copy-Paste Runbook

### A. Build CLI

```bash
cd /Users/goddess/dev/OpenAnt/apps/openant-cli
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
cd /Users/goddess/dev/OpenAnt/libs/openant-core
unset LLM_PROVIDER
unset LLM_MODEL
python3.12 utilities/autopatcher/tools/run_traced.py --cve CVE-2023-43804 --repo-root /tmp/urllib3-eval --output /tmp/urllib3-trace --context-budget-policy always --max-context-budget-windows 10
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
Repository:        /Users/goddess/dev/OpenAnt
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

## Section 19 — Single-Stage Debug Replay

This is a second, distinct workflow from everything above. Sections 1–18
describe **one full traced run**; this section describes **rerunning
exactly one stage of a run you already have a trace for**, using your
CURRENT code, without paying for (or waiting on) the rest of the pipeline.

### 19.1 The two workflows

```
FULL TRACED RUN                         SINGLE-STAGE DEBUG REPLAY

run_traced.py                           run_stage.py
  -> runs the full pipeline                -> consumes a source trace
  -> creates a replay-capable                 (from run_traced.py)
     SOURCE TRACE                         -> reruns ONLY the selected
                                              stage's CURRENT code
                                          -> creates an isolated
                                             REPLAY TRACE
```

Use `run_traced.py` first, exactly as in §7, to get a source trace. Use
`run_stage.py` afterward, as many times as you like, each time you change
a stage's code/prompt and want to see the new result — without rerunning
remediation planning, patch generation, Challenger, Finding Calibration,
Patch Review, Confidence Scoring, or Existing Test Comparison again.

### 19.2 When to use it

You already ran a full traced evaluation (§7), found that one stage
behaved incorrectly (this release: **`test_plan_discovery`** only — see
§19.5 for why), and want to test a code/prompt fix to JUST that stage
against the SAME upstream repository state the original run used —
without spending tokens on, or waiting on, every other stage.

### 19.3 Currently supported stage

**`test_plan_discovery` is the only stage `run_stage.py` supports in this
release.** Requesting any other `--stage` fails immediately, before any
file I/O or LLM call:

```
$ python3.12 utilities/autopatcher/tools/run_stage.py --source-trace /tmp/minimist-trace --stage challenger --output /tmp/out
Stage 'challenger' is not replayable yet. Currently supported: test_plan_discovery.
```

It never silently falls back to running the full pipeline instead.

### 19.4 Usage

```bash
cd /Users/goddess/dev/OpenAnt/libs/openant-core
python3.12 utilities/autopatcher/tools/run_stage.py \
  --source-trace /tmp/minimist-trace \
  --stage test_plan_discovery \
  --output /tmp/minimist-test-plan-debug
```

`--source-trace` accepts either the run root (`run_traced.py`'s
`--output`, e.g. `/tmp/minimist-trace`) or that run's `trace/`
subdirectory directly — both resolve to the same `run_manifest.json`.
Resolution is exact-name only, never a recursive/fuzzy search of the
directory tree.

`--repo-root` optionally overrides the target repository path instead of
the one recorded in the source trace (e.g. a second checkout on this
machine) — still subject to the identical commit-SHA and clean-worktree
checks described in §19.6, against the SHA the source trace recorded.

### 19.5 Why `test_plan_discovery` is the first (and only) supported stage

`discover_test_plan(repo_root, llm)` (`test_plan_discovery.py`) is the one
Auto Patcher stage whose entire input is a filesystem path plus an LLM
client — no remediation plan, candidate patch, Challenger result, or
Finding Calibration output is needed. Its repository evidence
(`gather_test_plan_evidence`) is gathered fresh, deterministically, from
`repo_root` itself every time — there is nothing upstream to reconstruct.
That means replaying it needs **zero earlier LLM stages to run**, which is
the hard requirement for this feature (§19.7). Every other stage
(`remediation_planning`, `remediation_strategy`, `patch_generation`,
`challenger`, `finding_calibration`, `patch_review`) depends on a prior
stage's LLM output in a way this release does not yet reconstruct — see
the "Known Phase-1 limitations" note this feature's implementation report
recorded, and don't assume support for them exists just because the CLI
shape looks generic.

### 19.6 The target-repository safety gate

This is the most important safety boundary, checked BEFORE any LLM call:

1. The target repository (from the source trace, or `--repo-root`) must
   exist and be a git repository.
2. Its current `HEAD` (full SHA) must **exactly match** the full SHA the
   source trace recorded.
3. Its working tree must be **clean** (`git status --porcelain` empty).

Any failure stops replay immediately, before any LLM call, with a
specific message, e.g.:

```
Cannot replay test_plan_discovery: target repository HEAD does not match source trace.
Expected: d9f85a749488188c286cd50606d159874db94d5f
Actual:   3a1c9e2...
```

```
Cannot replay test_plan_discovery: target repository contains uncommitted changes.
```

`run_stage.py` never runs `git checkout`/`reset`/`clean` — it is purely
observational and never mutates the target repository.

**This gate applies ONLY to the target repository being analyzed — never
to the OpenAnt development checkout you're running `run_stage.py` from.**
The OpenAnt checkout may (and, mid-debugging, usually will) be dirty —
that's the point: you're testing an uncommitted change to
`test_plan_discovery.py` or its prompt. `run_stage.py` records which
OpenAnt commit produced the trace and which one is replaying it
(`replay_manifest.json`'s `openant` block, §19.8) but never requires them
to match, and never blocks on the OpenAnt checkout being dirty.

### 19.7 Provenance: source vs. replay, recorded but never compared

Two identities are recorded on both sides of every replay, and are
**never required to match** — by design, since the whole point is testing
a current code change against historical target-repo state:

| | Must match? |
|---|---|
| Target repository commit SHA | **Yes, strictly** (§19.6) |
| Target repository clean working tree | **Yes** (§19.6) |
| OpenAnt implementation commit (`patcher_commit`) | **No** — recorded on both sides only |
| LLM provider/model | **No** — recorded on both sides only |

A successful replay makes **exactly one LLM call**, tagged
`stage=test_plan_discovery` — enforced by tests
(`tests/patch/test_stage_replay.py`), and structurally guaranteed by
`stage_replay.py` never importing `pipeline.py` or any other stage module
(`remediation_planner`, `patch_generator`, `patch_challenger`,
`finding_calibration`, `patch_reviewer`, `confidence_scorer`) — a replay
cannot call a function it never imported. The one documented exception:
`discover_test_plan` itself makes **zero** LLM calls (not an error) when
the target repository has no test-related evidence at all
(`gather_test_plan_evidence` found nothing) — that's a legitimate,
current-implementation rejection, still recorded as a completed replay.

### 19.8 Output

```
/tmp/minimist-test-plan-debug/
  replay_manifest.json
  001_test_plan_discovery.prompt.txt
  001_test_plan_discovery.response.txt
  parsed_result.json          # if the plan was accepted
  # or, instead:
  rejection_reason.json       # if the plan was rejected
```

A rejected plan is a **valid, completed replay** (exit code 0) — the
current implementation ran, produced a result, and that result was "no
plan" for a specific, recorded reason (malformed JSON, missing
execution-critical field, deterministic validation failure, low
self-reported confidence, ...). This is exactly what you inspect to tell
whether a prompt/code change fixed the problem. Only an infrastructure
failure (§19.6's gate, an unsupported `--stage`, an unresolvable LLM
config, a malformed/incompatible source trace) exits non-zero, and does so
**before** writing anything to `--output` at all.

`replay_manifest.json` shape:

```json
{
  "schema_version": 1,
  "stage": "test_plan_discovery",
  "outcome": "accepted",
  "source_trace": "/tmp/minimist-trace/trace",
  "source_provenance_origin": "structured_manifest",
  "source_run": {"input_type": "cve", "input_id": "CVE-2021-44906"},
  "target_repository": {"repo_root": "/tmp/minimist-eval", "repo_commit": "<full SHA>"},
  "openant": {
    "source_patcher_commit": "<SHA that produced the source trace>",
    "replay_patcher_commit": "<SHA currently running this replay>",
    "replay_openant_dirty": true
  },
  "llm": {
    "source_provider": "anthropic", "source_model": "claude-...",
    "replay_provider": "anthropic", "replay_model": "claude-..."
  },
  "llm_call_count": 1,
  "started_at": "...", "finished_at": "...", "duration_seconds": 4.2
}
```

### 19.9 Legacy traces

A trace produced before this feature existed (no `schema_version` key in
its `run_manifest.json`) is still usable: `run_stage.py` falls back to a
**bounded** read of that Trust Report's own `## Run Metadata` table
(§9's `trust-report.md` section) — ONLY the `Repo commit`, `Auto-patcher`,
`LLM provider`, and `LLM model` table rows, via fixed-shape row patterns,
never a general prose scan. If that table is missing, ambiguous (e.g. two
`Repo commit` rows), or its `Repo commit` value is `unknown`, replay fails
closed with a specific reason rather than guessing. Priority is always:
structured `run_manifest.json` fields first, this bounded fallback second,
fail closed third — **never** silently. A NEW trace's replay never reads
the Trust Report at all, for anything (proven by
`tests/patch/test_stage_replay.py`'s
`test_structured_manifest_never_touches_trust_report`).

### 19.10 Source trace immutability

`run_stage.py` never modifies `--source-trace` in any way — not
`run_manifest.json`, not `checkpoints.jsonl`, not any prompt/response
file, not the Trust Report. All replay output goes only to `--output`,
which must not be the same path as, nested inside, or contain
`--source-trace` (checked before any other work). This is enforced by a
byte-for-byte-unchanged test in `tests/patch/test_stage_replay.py`.

### 19.11 What this is not (yet)

This release replays exactly one stage, once, using the trace's recorded
upstream state. It does NOT implement (and this document should not be
read as documenting) `--from-stage`, `--stop-after`, rerunning downstream
stages after a replay, or evaluating an externally-supplied candidate
patch. Those are plausible future directions the current design leaves
room for, but none of them exist yet — don't assume a flag or behavior
described here extends to them.
