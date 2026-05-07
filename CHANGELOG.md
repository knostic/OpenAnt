# Changelog

All notable changes to OpenAnt are documented in this file.

## [2026-05-07] — Incremental scans + scan pipeline rewire

### Changed

- **`openant scan` rewired end-to-end.** The full pipeline is now
  explicit and visible in `--help`:
  `init → parse → app-context → enhance → analyze → verify →
  build-output → dynamic-test → report`. A single run-mode decision
  (full vs incremental) is resolved once — at `init` or at `scan` —
  and recorded in a per-run `meta.json` whose status field
  transitions `running → success | failed | interrupted`. Step verbs
  (`parse`, `enhance`, …) read that file and inherit the mode, so a
  standalone step after `init --incremental` filters correctly
  without re-passing flags. Docker is preflighted before any work
  begins, so a missing daemon is reported up front instead of after
  a full pipeline run.
- **Dynamic testing is on by default.** The opt-in `--dynamic-test`
  flag has been replaced by an opt-out `--skip-dynamic-test`. `scan`
  now produces dynamic verification of findings out of the box;
  callers without Docker should pass `--skip-dynamic-test`.

### Added

- **Incremental scans.** New `openant diff` subcommand and
  `--diff-base`, `--pr`, and `--diff-scope` flags on `scan` and
  `parse` scope the pipeline to changed files only. Go computes a
  `diff_manifest.json` from the working tree (or a fetched PR head)
  and threads it through every stage — parse → enhance → analyze →
  report — so each phase only processes what changed. The diff range
  surfaces in the CSV export, `_summary.json`, the standalone HTML
  report, the report header, and the live scan banner.
- **Explicit run-mode flags on `init`, `scan`, and `parse`** —
  `--full`, `--incremental`, `--diff-base <ref>`, `--pr <n>`, and
  `--diff-scope`. With a baseline present, an interactive TTY shows
  a recap prompt (default Enter = full, the safer choice); non-TTY
  callers without a flag get a loud error so CI scripts fail fast
  instead of silently picking a mode.

### Fixed

- **Python call graph no longer drops `self.X()` calls.** The call-
  graph builder fed function bodies straight into `ast.parse`, but
  method bodies are stored with their original class indentation —
  so `ast.parse` raised `IndentationError`, the regex fallback ran
  without `self.X()` resolution, and every method-to-method call in
  every Python codebase silently disappeared from the graph. On
  dbt-core that meant 2,243 of 3,116 functions (72%) marked isolated
  and a real scan returning zero findings. The fix dedents a
  temporary copy before parsing and leaves the stored source byte-
  correct so the disclosure renderer's offsets stay valid.
- **Disclosure code is byte-faithful to source.** The disclosure
  renderer pulls the actual file slice from the repo instead of
  rerunning an LLM rewrite, so every finding's `Vulnerable Code`
  block matches the real source.
- **No more silent 401s.** `openant set-api-key` validates the key
  on save and fails loudly on bad input. `openant scan` prints a
  blocking warning and exits non-zero when zero API calls succeed,
  so an all-401 run can no longer masquerade as a clean repo.
- **CWE tagging is systematic.** `pipeline_output.json` carries
  non-null `cwe`, `cwe_id`, and `vulnerability_type` for every
  finding. The Stage 1 prompt asks for them directly rather than
  relying on the renderer LLM to infer them from prose.
- **Repo metadata reaches every report envelope.** Repo name,
  commit SHA, and file count are threaded into `parse.report.json`
  and `scan.report.json` instead of being lost between stages,
  eliminating the `[NOT PROVIDED]` placeholders.
- **`Verified` column reflects the highest evidence tier.**
  `dynamic` > `verified` > `static`, so dynamically reproduced
  findings show as `dynamic` and the disclosure footer reads
  "Confirmed via dynamic test" where applicable.
- **Call-graph-aware deduplication.** When two findings share a
  sink/vector and the call graph records an edge between them,
  they collapse into a single finding.
- **Dedup matches on CWE** instead of `attack_vector` text, so
  small wording differences no longer split what's logically the
  same finding.
- **Dynamic test Docker context is complete on the first try.**
  `openant dynamic-test` pre-stages the vulnerable source file
  into the Docker build context end-to-end through the dynamic-
  test chain — first-try builds no longer fail because the source
  isn't in context.
- **Concurrency-safe Docker resources.** Docker image and network
  names get a UUID prefix so parallel dynamic-test workers can't
  collide.
- **Agreement filter checks the final verdict** instead of the
  intermediate `agree` flag, so high-confidence dynamic results
  aren't dropped by a stale agreement signal.
- **Report prompts respect non-interactive runs.** Prompt output
  goes to stderr (keeping stdout clean for piped JSON) and the
  prompt is skipped entirely when there's no TTY, so CI/scripted
  invocations no longer hang.

## [2026-04-29] — Python parser dedent fix

### Fixed

- **Disclosure code is now byte-faithful to source.** The disclosure
  renderer pulls the actual file slice from the repo instead of rerunning
  an LLM rewrite, so every finding's `Vulnerable Code` block matches the
  real source.
- **No more silent 401s.** `openant set-api-key` validates the key on save
  and fails loudly on bad input. `openant scan` prints a blocking warning
  and exits non-zero when zero API calls succeed, so an all-401 run can no
  longer masquerade as a clean repo.
- **CWE tagging is now systematic.** `pipeline_output.json` carries
  non-null `cwe`, `cwe_id`, and `vulnerability_type` for every finding.
  Stage 1 prompt asks for them directly rather than relying on the
  renderer LLM to infer them from prose.
- **`[NOT PROVIDED]` placeholders eliminated.** Repo name, commit SHA, and
  file count are threaded into every phase report envelope
  (`parse.report.json`, `scan.report.json`) instead of being lost between
  stages.
- **`Verified` column reflects the highest evidence tier.** `dynamic` >
  `verified` > `static`, so dynamically reproduced findings show as
  `dynamic` and the disclosure footer reads "Confirmed via dynamic test"
  where applicable.
- **Call-graph-aware deduplication.** When two findings share a
  sink/vector and the call graph records an edge between them, they
  collapse into a single finding.
- **Dynamic test scaffolding fixed.** `openant dynamic-test` pre-stages
  the vulnerable source file into the Docker build context end-to-end
  through the dynamic-test chain — first-try Docker builds no longer fail
  because the source isn't in context.
- **Concurrency-safe Docker resources.** Docker image and network names
  get a UUID prefix so parallel dynamic-test workers can't collide.
- **Agreement filter checks the final verdict** instead of the
  intermediate `agree` flag, so high-confidence dynamic results aren't
  dropped by a stale agreement signal.
- **Dedup matches on CWE** instead of `attack_vector` text, so small
  wording differences no longer split what's logically the same finding.

## [2026-04-14] — Initial public release

This release synced a large body of work from internal development. Highlights:

### Added

- **Parallelization** across all pipeline stages:
  - Stage 1 analysis (Detect), Stage 2 verification, Enhance, and Dynamic Test now run units concurrently via worker pools.
  - Thread-safe `TokenTracker` and `ProgressReporter` for correct aggregate metrics under parallel execution.
  - Shared HTTP client and a token-bucket `RateLimiter` (`libs/openant-core/utilities/rate_limiter.py`) to stay within Anthropic API rate limits.
- **Checkpoint / resume system** (`libs/openant-core/core/checkpoint.py`): every phase persists per-unit progress so interrupted scans can resume without re-running completed work.
- **Zig parser** (`libs/openant-core/parsers/zig/`): repository scanner, unit generator, and test pipeline.
- **HTML report improvements** (`apps/openant-cli/internal/report/`):
  - Two themes: dark (`overview.gohtml`) and Knostic-branded light (`report-reskin.gohtml`).
  - Report header shows repo name, commit SHA, language, total scan duration (formatted `Xd Xh Xm Xs`), and cost.
  - Findings are numbered (`#N`), have anchor IDs, and are grouped into collapsible sections by verdict (vulnerable / bypassable open by default; inconclusive / protected / safe closed).
  - Within each verdict group, findings are sub-sorted by dynamic test outcome (CONFIRMED first, NOT_REPRODUCED last).
  - File paths link directly to the repo at the exact commit.
  - Pipeline Costs & Timing section with per-step breakdown and a Totals row.
  - Executive Summary links to findings via `#N` references; priority labels (Critical / High / Medium) replace fabricated timeframes.
- **Dynamic testing** hardening: structured result classification (CONFIRMED / NOT_REPRODUCED / BLOCKED / INCONCLUSIVE / ERROR), Docker template updates, retry logic, and checkpoint-aware resume.
- `openant build-output` and `openant dynamic-test` subcommands with prompt-before-skip UX.

### Changed

- Finding verifier (`utilities/finding_verifier.py`) hardened with better error handling and agentic tool integration.
- Context enhancer (`utilities/context_enhancer.py`) overhauled for parallel, agentic enhancement.
- Report data pipeline rewritten: Python computes a `ReportData` JSON blob; Go renders the HTML template.
- Cost tracking reworked to report per-unit costs in progress output and aggregate correctly across parallel workers.

### Fixed

- Cost tracking no longer shows negative or incorrect totals under parallel execution.
- `merge_dynamic_results` no longer contaminates stdout, unblocking clean JSON output.
- HTML report entities (`>`, `<`) render correctly (previously double-escaped).
- "Max iterations reached" verifier timeouts now mark findings as `inconclusive` rather than leaving a stale verdict.
- Checkpoint resume behavior unified across phases.
- Stdin race during interactive signal forwarding.
