# Real-CVE batch runner — `run_cve_batch.py`

The standard way to run Auto Patcher real-CVE regression/evaluation suites.
One command takes one or more YAML evaluation manifests, runs every case
through `run_traced.py` with bounded parallelism and full isolation, keeps
going when individual cases fail, and leaves one self-contained batch
directory with summaries, per-case artifacts and a results ZIP. Interrupted
batches resume without rerunning finished cases.

It is evaluation tooling only. Normal use of Auto Patcher (`openant patch`)
never needs it. It never changes Auto Patcher behavior, and it reads nothing
but `run_traced.py`'s own artifacts.

All commands below are run from `libs/openant-core` in the OpenAnt checkout:

```bash
cd libs/openant-core
```

**Requirements:** POSIX, `git` on `PATH`, and Python ≥ 3.11 with PyYAML and
OpenAnt's Python dependencies installed. Network access to GitHub, NVD and
the LLM provider is needed. A real LLM provider must be configured with
`openant setup llm` (Auto Patcher's normal configuration). `NVD_API_KEY` is
optional, but it raises NVD's rate limits, which matters at higher
concurrency: NVD 429 responses fail a case as `advisory_fetch_failed`. Each
case inherits the runner's environment.

Shipped manifests: `cfp_evaluation_cases.yaml` (43 cases) and
`smoke_cases.yaml` (7 cases).

---

## 1. Quick start

```bash
# Validate manifests and print the plan (no checkout, no LLM calls, no batch dir)
python3 utilities/autopatcher/tools/run_cve_batch.py \
    --manifest utilities/autopatcher/tools/cfp_evaluation_cases.yaml \
    --validate-only

# Run one manifest (default --jobs 2)
python3 utilities/autopatcher/tools/run_cve_batch.py \
    --manifest utilities/autopatcher/tools/cfp_evaluation_cases.yaml

# Run several manifests as one batch, explicit concurrency and a label
python3 utilities/autopatcher/tools/run_cve_batch.py \
    --manifest utilities/autopatcher/tools/cfp_evaluation_cases.yaml \
    --manifest /path/to/release_cases.yaml \
    --jobs 2 --label release-rc1

# Run only some cases (manifest order is kept)
python3 utilities/autopatcher/tools/run_cve_batch.py \
    --manifest utilities/autopatcher/tools/cfp_evaluation_cases.yaml \
    --case starlette-cve-2023-29159 --case planet-client-python-cve-2023-32303

# Resume an interrupted batch (finished cases are not rerun)
python3 utilities/autopatcher/tools/run_cve_batch.py \
    --resume /tmp/openant-cve-batches/<batch-id>

# Show what a resume would do, without running anything
python3 utilities/autopatcher/tools/run_cve_batch.py \
    --resume /tmp/openant-cve-batches/<batch-id> --validate-only

# Also rerun cases whose latest attempt FAILED
python3 utilities/autopatcher/tools/run_cve_batch.py \
    --resume /tmp/openant-cve-batches/<batch-id> --rerun-failed

# Regenerate summaries + ZIP only (never runs a case)
python3 utilities/autopatcher/tools/run_cve_batch.py \
    --summarize /tmp/openant-cve-batches/<batch-id>

# Long batch that survives closing the terminal
nohup python3 utilities/autopatcher/tools/run_cve_batch.py \
    --manifest utilities/autopatcher/tools/cfp_evaluation_cases.yaml \
    > /tmp/cve-batch.out 2>&1 &
```

New batches go to `/tmp/openant-cve-batches/<batch-id>/` (`--batch-root`
changes the parent; `--batch-id` sets the id). The id is
`<UTC timestamp>[-<label>]-<random>`, e.g. `20261005T101500Z-release-rc1-3f9a2c`.

Before anything runs, the runner checks its preconditions and exits 2 if
one fails:

- `LLM_PROVIDER` and `LLM_MODEL` must be **unset**. Auto Patcher rejects every
  value except `LLM_PROVIDER=mock`, which needs `--allow-mock-llm`;
  `LLM_MODEL` is then allowed.
- The `--python` interpreter must be Python ≥ 3.11.
- `<python> run_traced.py --help` must succeed, and so must importing what
  `run_traced.py` loads only after argument parsing (`core.patch` and the Auto
  Patcher pipeline). A missing dependency or a broken pipeline module
  therefore stops the batch before the first clone.
- The OpenAnt git state must be readable (and clean, with
  `--require-clean-openant`).
- The batch directory must not sit inside the OpenAnt work tree at a path git
  does not ignore, because its clones and outputs would look like OpenAnt code
  changes.

Make sure the OpenAnt work tree is in the state you want recorded.
`--require-clean-openant` enforces a clean tree, and is recommended for the
final regression run.

---

## 2. Options

| Option | Meaning |
|---|---|
| `--manifest YAML` | Evaluation manifest; repeatable. Cases run in the order given (manifest by manifest). |
| `--resume DIR` | Continue an existing batch (see §8). |
| `--summarize DIR` | Regenerate `batch_summary.*`, `batch_results.csv` and the ZIP from the current state. Runs nothing. |
| `--case ID` | Restrict to these case ids (repeatable). New batch: the batch contains only these. Resume: only these may run. |
| `--jobs N` | Concurrent cases (default **2**, must be ≥ 1, no upper bound). Values above the runner's `VALIDATED_MAX_JOBS` (4) still run, but the runner prints a warning and records `jobs_validated: false` for the session. See §11. |
| `--validate-only` | Check the preconditions, validate the input, and print the plan (or the resume plan). Never clones or runs a case, but can still exit 2 on a failed precondition. For a new batch it does not check whether `--batch-id` already exists. With `--resume` it still takes the batch lock. Ignored with `--summarize`. |
| `--batch-root DIR` | Parent directory for new batches (default `/tmp/openant-cve-batches`). Must be outside the OpenAnt work tree unless git ignores the location. |
| `--batch-id ID` | Explicit id for a new batch: starts with a letter or digit, then `[A-Za-z0-9._-]`, at most 100 characters. The default is `<UTC timestamp>[-<label>]-<random>`. An existing batch directory is never reused. |
| `--case-timeout-minutes M` | Stop a case's `run_traced.py` (whole process group: SIGTERM, then SIGKILL after 20 s) after M minutes. Default 120 for a new batch; on resume, the batch's stored initial value. `0` = none. May differ per session (recorded per session). |
| `--heartbeat-seconds S` | Print the running cases after S quiet seconds (default 300, `0` = off). |
| `--blind-filter-policy {v1,v2}` | Forward `run_traced.py --blind-filter-policy`. Default: not passed (run_traced's default, v1 — the canonical setup). Frozen per batch. |
| `--allow-duplicate-cve` | Allow one CVE in several cases with different repository/SHA. Identical CVE+repo+SHA is always an error. |
| `--label TEXT` | Free text recorded in the batch and folded into the id. |
| `--python PATH` | Interpreter for `run_traced.py` (default: the one running the runner; must be ≥ 3.11). Frozen per batch. |
| `--require-clean-openant` | Refuse to start (or resume) if the OpenAnt work tree has uncommitted changes. |
| `--rerun-failed` | With `--resume`: rerun cases whose latest attempt FAILED. |
| `--allow-openant-change` | With `--resume`: allow resuming after the OpenAnt code changed (see §8). |
| `--allow-mock-llm` | Allow `LLM_PROVIDER=mock` (smoke tests only; results are flagged as not real). |
| `--no-zip` | Skip the results ZIP. |
| `--zip-include-investigation` | Also package `output/patch/*-investigation/` (large; see §7). |

---

## 3. Manifest format

The existing manifest schema (`cfp_evaluation_cases.yaml`) is reused:

```yaml
group: CFP            # optional: default group for every case in this file
cases:
  - id: starlette-cve-2023-29159          # required, unique, [A-Za-z0-9._-], starts alnum
    repo: https://github.com/encode/starlette.git   # required, https GitHub URL
    cve: CVE-2023-29159                   # required, CVE-YYYY-NNNN
    sha: 24c1fac62a80bb153c6548145334fc643991e35a   # required, full 40-char lowercase SHA
    display_name: Starlette               # optional (shown as "Project")
    language: Python                      # optional
    group: release-gate                   # optional, overrides the file-level group
    selection_reason: >                   # optional; any other keys are preserved as metadata
      ...
```

Validation happens before any checkout and reports every problem at once
(exit 2, nothing created):

- YAML must parse; **duplicate keys are rejected** (a second `sha:` never wins silently).
- Top-level keys: `cases` (required, non-empty list), `group`, `name`, `description` — anything else (e.g. a `case:` typo) is an error.
- `repo` must be `https://github.com/<owner>/<repo>[.git]` without credentials,
  query or fragment. GitHub is required because same-repository GitHub
  reference stripping is part of the canonical blind setup.
- `sha` must be a full 40-character lowercase hex SHA; tags and short SHAs are rejected.
- `advisory_file` (file-mode) cases are rejected: the runner always uses `--cve`.
- Duplicates across all manifests: the same id (case-insensitively — macOS
  paths are case-insensitive), the same CVE+repository+SHA under two ids, or
  the same CVE twice (unless `--allow-duplicate-cve`), or the same file passed twice.

Each case records its provenance: manifest path, manifest SHA-256, position,
and the copy of the manifest stored inside the batch (`inputs/`).

---

## 4. What a case attempt does

For every case, in its own attempt directory `cases/<id>/attempt-NN/`:

1. `git clone --no-checkout <repo> repo/` (fresh; `GIT_TERMINAL_PROMPT=0`).
2. Check out the exact manifest SHA (fetching it by SHA if it is not on a branch).
3. Verify `HEAD == sha`, `remote.origin.url == repo`, and an empty
   `git status --porcelain --untracked-files=all`.
4. Run, with working directory `cwd/`, stdout → `stdout.log`, stderr → `stderr.log`:

   ```
   <python> run_traced.py --cve <CVE> --repo-root <attempt>/repo --output <attempt>/output \
       --context-budget-policy always --max-context-budget-windows 10 \
       --blind-evaluation --blind-strip-same-repo-github-references
   ```

   `--context-budget-policy`/`--max-context-budget-windows` are deprecated
   no-ops in Auto Patcher. Repository evidence is always bounded by technical
   capacity (see the README's "Context budget"). `run_traced.py` prints a
   deprecation notice for them on every case. The runner still passes both,
   and resume enforces them, so every batch's command line stays identical to
   earlier batches.

   The exact argv, CWD, timeout and the non-secret environment variables that
   matter (`LLM_*`, `OPENANT_*_CONFIG`, …) are written to `command.json`. The
   full environment is never recorded.
5. Classify the attempt from `output/trace/run_manifest.json` and the Trust
   Report (§6), record post-run checkout state, write `result.json`.

**Isolation contract.** Every attempt has its own checkout, output directory
and CWD. The CWD matters: `run_traced.py` sets `AUTOPATCHER_DEBUG=1` and the
pipeline writes `./reports/debug/*` relative to the process CWD, so a shared
CWD would overwrite or cross-attribute debug artifacts. Each result is
cross-checked against this contract: a run manifest whose CVE, commit,
checkout path, output path or Trust Report path does not belong to the
attempt is a `run_manifest_mismatch` failure; debug artifacts outside the
attempt's CWD and a modified checkout are reported as anomalies.

---

## 5. Live output

```
OpenAnt Auto Patcher — real-CVE batch (run_cve_batch.py 1.0.0)
  Batch      20261005T101500Z-3f9a2c
  Directory  /private/tmp/openant-cve-batches/20261005T101500Z-3f9a2c
  Session    1 (initial)
  Cases      43 scheduled of 43 in batch
  Jobs       2
  OpenAnt    <40-character OpenAnt HEAD> (clean)
  ...
[10:15:02] START   starlette-cve-2023-29159  CVE-2023-29159  attempt 1   · running 1 · done 0/43
[10:15:02] START   planet-client-python-cve-2023-32303  CVE-2023-32303  attempt 1   · running 2 · done 0/43
[10:15:20] DONE    planet-client-python-cve-2023-32303  ⚫ GRAY No Patch Produced  18s (checkout 3s)  llm 1   · done 1/43
[10:15:21] FAILED  waitress-cve-2019-16789  blind_evaluation_aborted: exit 2; BlindEvaluationError: …  4s   · done 2/43  → cases/waitress-cve-2019-16789/attempt-01/stderr.log
[10:17:00] DONE    starlette-cve-2023-29159  🟠 ORANGE Manual Review Required  1m58s (checkout 2s)  llm 7   · done 3/43
[10:22:00] …       running: ansible-cve-2020-10691 (5m01s), django-cve-2015-8213 (1m12s)   · done 20/43
```

Raw case output never reaches the terminal; it is in each attempt's
`stdout.log` / `stderr.log`. Every line is also appended (with a UTC
timestamp) to `logs/batch.log`. The run ends with a summary table (both
denominators), failures by kind, the summary/ZIP paths and ZIP size, and the
exact resume command when something is left to do.

---

## 6. Outcomes and statistics

**Outcome source.** A case's outcome is the Trust Report's decision card —
its first `##` heading, which `pipeline.py` renders and documents as the
anchor for tests/tooling — cross-checked against the `## Recommendation`
section. It only counts when `run_traced.py` exited 0, the run manifest says
`success`, the manifest identity matches the attempt, and blind evaluation is
proven (`status: verified`, expected `rule_id`, pipeline input and
vulnerability artifact verified, same-repo stripping enabled).

| Category | Trust Report decision card | Counts as |
|---|---|---|
| 🟢 GREEN | `DEPLOY AFTER VALIDATION` | completed, patch-producing |
| 🟡 YELLOW | `DEPLOY WITH CAUTION` | completed, patch-producing (rare, but part of the production vocabulary — never folded into another category) |
| 🟠 ORANGE | `MANUAL REVIEW REQUIRED` | completed, patch-producing |
| 🔴 RED | `DO NOT APPLY` | completed, patch-producing (a patch exists; it must not be applied) |
| ⚫ GRAY | `NO PATCH PRODUCED` | completed — **a legitimate Auto Patcher outcome, not a failure** |
| ✖ FAILED | — | no valid Auto Patcher outcome exists (see failure kinds) |
| … INCOMPLETE | — | not run yet, interrupted, or a recorded completion that no longer validates |

**Denominators** (both always shown, so failures cannot silently distort recommendation rates):

- **A — all requested cases:** GREEN+YELLOW+ORANGE+RED+GRAY+FAILED+INCOMPLETE.
- **B — completed Auto Patcher executions:** GREEN+YELLOW+ORANGE+RED+GRAY only.

Percentages are rounded to 2 decimals in JSON (1 in Markdown). When a
denominator is 0 they are `null` in JSON and `n/a` in Markdown.

**Failure kinds** (`failure_kind` in `result.json`, CSV and summaries):

| Kind | Meaning |
|---|---|
| `clone_failed` | `git clone` failed |
| `revision_not_found` | SHA not in the clone and not fetchable |
| `checkout_failed` / `sha_mismatch` / `origin_mismatch` / `dirty_checkout` | checkout could not be verified |
| `timeout` | exceeded `--case-timeout-minutes`; process group killed |
| `killed_by_signal` | `run_traced.py` died from a signal |
| `blind_evaluation_aborted` | `BlindEvaluationError` — the advisory cannot be blinded under the policy; deterministic, a rerun fails the same way |
| `advisory_fetch_failed` | `CVEFetchError` / `CVENotFoundError` — the NVD fetch failed (an NVD HTTP 429 lands here, not under the LLM provider) |
| `provider_rate_limit` | LLM rate limit / overload: an adapter `LLMRateLimitError`, or llm_client's `RuntimeError("<Provider> API call failed: …")` carrying 429/529/`rate_limit_error`/`overloaded_error` — usually worth `--rerun-failed` later |
| `provider_error` | other LLM provider or LLM configuration failures (typed `LLM*Error`/`ConfigError`/`ModelUnavailableError`, or llm_client's `API call failed` / `No usable credential` / `LLM_PROVIDER=` / `LLM_MODEL=` RuntimeErrors) |
| `environment_error` | `TestComparisonEnvironmentError` |
| `run_traced_exception` | `run_traced.py` raised (failure run manifest written) |
| `run_traced_crashed` | non-zero exit without a usable failure manifest |
| `run_traced_usage_error` | exit 2 without a manifest (argument/prerequisite error) |
| `run_manifest_missing` / `run_manifest_corrupt` / `run_manifest_not_success` | exit 0 but the manifest is absent, invalid, or not `success` |
| `run_manifest_mismatch` | manifest identity does not match the attempt (contamination guard) |
| `blind_evaluation_unverified` | blind evaluation not proven by the manifest |
| `trust_report_missing` | Trust Report named by the manifest does not exist |
| `recommendation_unparseable` / `recommendation_inconsistent` | decision card unknown, or card and Recommendation section disagree |
| `runner_exception` | bug in the batch runner (traceback in `runner_error.txt`) |

**Anomalies** are warnings that do not change the outcome but are always
listed. Most are checked only for completed attempts:

- the LLM-call count differs from the `checkpoints.jsonl` records, or
  `checkpoints.jsonl` is missing or unreadable;
- debug artifacts appear outside the attempt CWD;
- the run used a different OpenAnt commit than the session recorded;
- **the OpenAnt work tree changed while the batch was running** (see §8), or
  its state could not be read;
- the provider was `mock`;
- the context-budget settings differ;
- the target checkout was modified, or its HEAD moved, during the run;
- the Trace Summary disagrees with the manifest.

**Other figures:**

- *LLM calls* — `run_manifest.json` `llm_call_count` (final attempts; also
  summed over all attempts, since failed attempts cost calls too).
- *Retry-like LLM calls* — from `checkpoints.jsonl` stage tags ending in
  `_retry`, `_reattempt`, `_revision`, `_reverification`, `_regeneration`,
  plus repeats of an earlier tag. Planning re-attempts are designed
  evidence-acquisition rounds, not errors.
- *Tokens / cost* — not in `run_manifest.json`; taken from `run_traced.py`'s
  Trace Summary on stderr (OpenAnt's TokenTracker), only for successful runs
  whose printed LLM-call count equals the manifest's. Cost is rounded to
  cents per case by `run_traced.py`. Failed runs report none.
- *Durations* — case duration = the final attempt's total time (checkout,
  `run_traced.py`, and classification);
  wall clock = sum of the batch sessions' elapsed time; speedup = case time /
  wall clock.
- *No-patch reason* — the Trust Report's `Patch Applicability` skip reason
  (e.g. `planning_ungrounded: ungrounded_unresolvable`), else the first
  unusual execution outcome in the run manifest.

---

## 7. Batch directory and summary files

```
<batch-root>/<batch-id>/
    .batch.lock                one-runner-per-batch lock (flock)
    batch_manifest.json        exact provenance: inputs, resolved cases, run config, every session
    batch_summary.md           human-readable report
    batch_summary.json         complete machine-readable aggregate (every case row included)
    batch_results.csv          one row per case
    <batch-id>-results.zip     packaged results (§7.1)
    inputs/01-<manifest>.yaml  byte-exact copies of the input manifests (SHA-256 in batch_manifest.json)
    logs/batch.log             every live-output line, all sessions, UTC timestamps
    provenance/                openant_worktree-session-NN[-end].diff (tracked OpenAnt changes at session start,
                               and at session end if the tree changed during the session; only when non-empty)
    cases/<case-id>/
        case.json              frozen case spec + manifest provenance
        attempt-01/
            command.json       exact argv, CWD, timeout, recorded env (absent if the checkout failed)
            stdout.log         run_traced.py stdout
            stderr.log         run_traced.py stderr (progress narration, Trace Summary, tracebacks)
            result.json        status, outcome, failure kind/detail, checkout verification,
                               extracted run-manifest facts, usage, anomalies, timings
            runner_error.txt   only if the runner itself raised
            repo/              the fresh checkout (not packaged)
            cwd/reports/debug/ AUTOPATCHER_DEBUG artifacts of this attempt
            output/            run_traced.py --output: trace/ (run_manifest.json, checkpoints.jsonl,
                               NNN_<stage>.prompt/response.txt, executions/, blind_evaluation/)
                               and patch/ (vulnerability, trust report, *-investigation/)
        attempt-02/            only if the case was rerun; earlier attempts are never modified
```

`batch_manifest.json` records, per session: start/end, argv, jobs, timeout,
OpenAnt HEAD + dirty status + porcelain + work-tree fingerprint at the start
and at the end (`openant_end.changed_during_session`), runner Python,
platform, host, recorded environment, scheduled cases, result, exit code,
ZIP info. `run_config` freezes the `run_traced.py` path, the interpreter
(path + version), the exact flags and the expected blind `rule_id` (plus the
initial timeout). Every attempt's `result.json` also records the OpenAnt
fingerprint just before and just after its `run_traced.py` ran. Runner name
and version, and schema versions, are recorded in `batch_manifest.json` and
`batch_summary.json`; `result.json` carries a `schema_version`. (The copy of
`batch_manifest.json` inside the ZIP predates the ZIP itself, so it lacks
that session's `zip` entry.)

`batch_summary.md` contains batch metadata, overall statistics,
distribution tables A and B, failures by kind, a breakdown by manifest
(when there is more than one) and by group (when any case has one), the full
case table (case, CVE, project,
repository, exact SHA, outcome, duration, LLM calls, reason, artifact
path), failure details, anomalies, retry-like calls and definitions.
Summaries are regenerated after every finished case, so they are useful
while a batch is still running; until the session ends their status is
`RUNNING` (final statuses: `COMPLETE`, `COMPLETE_WITH_FAILURES`,
`INCOMPLETE`, `INTERRUPTED`).

`batch_results.csv` has one row per case with these columns: `order,
case_id, cve, display_name, group, language, manifest, repo, sha, category,
decision, status, failure_kind, reason, exit_code, attempts, started_at,
finished_at, duration_seconds, llm_calls, retry_like_llm_calls,
skipped_stages, tokens, cost_usd, provider, model, patcher_commit,
blind_rule_id, blind_status, anomalies, attempt_dir, trust_report,
run_manifest, stderr_log`. List fields are joined with `; `. `status` is one
of `pending`, `incomplete`, `invalid`, `completed`, `failed` or
`interrupted`.

### 7.1 ZIP

`<batch-id>-results.zip` lives inside the batch directory, holds everything
under one `<batch-id>/` folder, and is created at the end of every
non-interrupted session (and by `--summarize`). Creating it never alters
existing artifacts; afterwards `batch_manifest.json` records the ZIP's path
and size. The ZIP includes:

- summaries, manifests, and input copies;
- logs and the `provenance/` diffs;
- per-attempt `command.json`, `result.json`, and logs;
- the complete `output/` trace and patch artifacts;
- the `cwd/` debug artifacts;
- `zip_contents.json`, which describes what was included and excluded.

Excluded:

- target checkouts (`attempt-*/repo/`) — reconstruct from `repo` + `sha` in `case.json`;
- `output/patch/*-investigation/` by default. This is derived parser output
  that can reach gigabytes for large repositories. Their paths and sizes are
  listed in `zip_contents.json`, and `--zip-include-investigation` packages
  them;
- `.git/`, `__pycache__/`, `*.pyc`, caches, `.DS_Store`, symlinks, temp files, the lock file;
- credential-like file names (`.env*`, `*.pem`, `*.key`, `id_rsa*`, `.netrc`, `.git-credentials`, …);
- any file containing the exact value (12 or more characters) of a
  credential-named environment variable (`*API_KEY*`, `*TOKEN*`, `*SECRET*`,
  …) or of an `api_key`/`token`/`secret`/`password` value in OpenAnt's
  `config.json`. Such files are excluded and reported as a warning; the value
  itself is never printed.

---

## 8. Resume

`--resume <batch-dir>` validates each case from its artifacts, never from
directory existence:

| Latest attempt state | Action |
|---|---|
| completed, and the run manifest + Trust Report on disk still prove the recorded outcome | **skipped** (a completed case is final within its batch) |
| no attempt yet / `running` (runner was killed) / `interrupted` / unreadable `result.json` | **rerun** automatically |
| recorded as completed but artifacts missing, changed or inconsistent (`invalid`) | **rerun** automatically |
| failed | kept as FAILED; rerun only with `--rerun-failed` (failures can be deterministic, e.g. `blind_evaluation_aborted`, and reruns cost LLM calls) |

Reruns get a new `attempt-NN`; earlier attempts are never modified or
deleted. Summaries and the ZIP are regenerated from the complete current
state. `--case` restricts which eligible cases run.

Evaluation semantics are frozen per batch: the interpreter, `run_traced.py`
and the blind filter policy cannot change on resume, and the stored
`run_config` must still describe the canonical flags — an edited
`batch_manifest.json` (e.g. a dropped `--blind-strip-same-repo-github-references`)
is refused. `--allow-mock-llm` carries over from the original run.

The runner fingerprints the OpenAnt work tree (HEAD, tracked diff, untracked
file hashes). It **refuses to resume against code that differs from the
first session** unless `--allow-openant-change` is passed. Because HEAD is
part of the fingerprint, committing the same changes also counts as a
change. Within a session, the runner re-checks the fingerprint before and
after every case and at the session end, using read-only git commands. Any
change is recorded, flagged as an anomaly on the affected cases, and
reported in the summary and the terminal ("OpenAnt code changed during the
batch").

`--jobs` (default 2 each session) and `--case-timeout-minutes` (default: the
batch's stored initial value) may change per session. A session that was
still marked in progress when its runner died is recorded as `abandoned`.
Flags that do not apply to the current mode, such as `--label` or
`--batch-id` on resume, are ignored.

A batch must stay at its original path: run manifests record absolute
paths, so a moved batch cannot be resumed or re-validated (the runner
refuses with a clear message). One runner per batch is enforced with a lock
file (`.batch.lock`, `flock`); a second runner on the same batch exits 2.

### Interruption

- **Ctrl-C / SIGTERM / SIGHUP:** running cases are sent SIGINT (whole
  process group), given 20 s, then SIGKILLed; not-yet-started cases are
  cancelled; summaries are written with status INTERRUPTED; no ZIP; exit
  130. A second Ctrl-C kills running cases immediately.
- Signals the parent ignores stay ignored, so `nohup` protects a batch from
  terminal hangup.
- `kill -9` of the runner cannot be handled: in-flight cases keep running as
  orphans (they are in their own process groups) and their attempts stay
  `running`; resume reruns them. Kill orphans with `pkill -f run_traced.py`
  if needed.

---

## 9. Exit codes

| Code | Meaning |
|---|---|
| 0 | every requested case reached a valid Auto Patcher outcome (GREEN/YELLOW/ORANGE/RED/GRAY) |
| 1 | the batch finished but at least one case FAILED; summaries and ZIP were still produced |
| 2 | invalid input or failed precondition (malformed/duplicate manifests, unknown `--case`, existing batch dir, batch dir inside the OpenAnt work tree, batch locked, `LLM_PROVIDER`/`LLM_MODEL` set, `run_traced.py`/pipeline import pre-flight failed, OpenAnt changed or `run_config` edited on resume, …); nothing ran |
| 3 | some requested cases have not been run (e.g. `--summarize` on a partial batch) |
| 4 | cases were summarized but the results ZIP could not be created (retry with `--summarize`) |
| 130 | interrupted; resume with `--resume` |

---

## 10. Compatibility wrapper

`run_patcheval_python_37.py` is now a thin wrapper: it selects the 37
PatchEval-Verified Python expansion cases (`opendiamond-cve-2022-31506`
onward in `cfp_evaluation_cases.yaml`) and delegates to `run_cve_batch.py`
with `--label patcheval-python-37`. For a new batch, `--case` narrows the
selection and must name one of the 37: anything else exits 2, and it never
adds cases. With `--resume`/`--summarize`, `--case` is forwarded unchecked.
`--results-root` is accepted as an alias of `--batch-root`. Every other
option passes through (`--jobs`, `--validate-only`, `--resume`, …). The old
`--repos-root` option is rejected, because each attempt now clones into its
own directory.

```bash
python3 utilities/autopatcher/tools/run_patcheval_python_37.py --validate-only
python3 utilities/autopatcher/tools/run_patcheval_python_37.py --jobs 2
```

---

## 11. Limitations

- POSIX only (process groups, `flock`).
- Concurrency: the runner warns above `VALIDATED_MAX_JOBS` (4). Provider rate
  limits, NVD rate limits, and machine load are the practical limits; per-case
  isolation does not depend on `--jobs`.
- Each attempt makes a full clone; large repositories (ansible, django,
  airflow, mlflow) cost disk and time, and checkouts are kept in the batch
  directory (delete `cases/*/attempt-*/repo/` after packaging if space is
  needed — they are reconstructible from URL + SHA). As a rough estimate
  from earlier runs, budget about 15 GB for the 43-case
  `cfp_evaluation_cases.yaml` batch.
- Token/cost totals depend on `run_traced.py`'s human Trace Summary and are
  rounded to cents per case.
- Outcome parsing depends on the Trust Report decision card format; any
  change there surfaces as `recommendation_unparseable`, never as a silent
  misclassification.

---

## 12. Tests

```bash
python3 -m pytest tests/patch/test_run_cve_batch.py -q
```

Hermetic: local bare repositories served for `https://github.com/...` URLs
through a test-only `GIT_CONFIG_GLOBAL` `insteadOf` rule, and a fake
`run_traced.py` (via the hidden `--run-traced` option) that writes
`run_traced.py`'s artifact shapes. No network, no LLM calls.
