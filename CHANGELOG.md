# Changelog

All notable changes to OpenAnt are documented in this file.

## [2026-05-12] — Parser depth, dependency UX, and LLM reachability (opt-in)

### Fixed

- **`openant parse` now defaults `--level` to `reachable`.** The Go CLI's
  `parse` command previously defaulted to `--level all`, contradicting
  `scan` and the Python CLI which both default to `reachable`. The
  documentation has always said the default is `reachable`. Anyone running
  `openant parse <repo>` without `-l` now gets the same dataset as
  `openant scan <repo> --steps parse` — the documented behavior. Set
  `--level all` explicitly to restore the previous output. (#35)

- **JS parser dependencies are now auto-installed on first use.**
  `openant parse` on a JavaScript/TypeScript repository previously failed
  out of the box with `Cannot find module 'ts-morph'` because nothing in
  the install flow ran `npm install` for `parsers/javascript/`. The Python
  parser adapter now runs `npm install` once on first JS parse using
  `node_modules/.package-lock.json` as the completion sentinel (catches
  Ctrl+C-interrupted installs). Python/Go-only users still never need
  `npm`. Includes a cross-platform file lock to prevent concurrent install
  corruption. Closes #6. (#37)

- **TypeScript parser now resolves dependency-injected service calls.**
  NestJS-style `this.userService.findById()` calls were previously
  unresolved in the call graph because the parser didn't extract
  constructor parameter types. Adds DI-aware resolution covering
  constructor injection (`constructor(private svc: SvcType)`),
  field-decorator injection (`@Inject` / `@InjectRepository` / etc.), and
  Angular's functional `inject()` API. Resolution priority: exact type →
  nominal (`implements`/`extends`) → unambiguous prefix (e.g.
  `CallService` → `CallServiceV1`). All steps return `null` on ambiguity
  to preserve the resolver's no-false-positive guarantee. Class-level
  metadata is keyed by `relativePath:className` so multi-module monorepos
  with same-named classes work. (#39)

- **Express anonymous route handler callbacks are now extracted as units.**
  `router.post('/orders', authenticateToken, async (req, res) => {...})` —
  the anonymous handler callback was previously invisible to the analyzer
  because the call-expression argument list wasn't walked. Synth units
  now carry `route_handler` (last callback) or `route_middleware` (earlier
  callbacks) with HTTP method/path metadata. Both unit types are now in
  `ENTRY_POINT_TYPES` so the reachability filter doesn't drop them. The
  receiver filter (`app` / `router` / `routes` / `server` / `web` / `api`
  / `endpoints` / `controller`) prevents false positives on
  `myCache.get(...)` style calls. Named middleware identifiers become
  call-graph edges so `authenticateToken` shows up as an upstream
  dependency of the handler. Closes #21. (#49)

### Added

- **Auto-reinstall when `pyproject.toml` changes.** The Go CLI now hashes
  `libs/openant-core/pyproject.toml` (SHA-256) and stores the hash at
  `~/.openant/venv/.deps-hash`. Every `EnsureRuntime` call compares the
  stored hash against the current file and re-runs `pip install -e <core>`
  automatically when they differ. Eliminates the "user did `git pull`,
  dependencies changed, but venv is stale" silent failure mode that
  previously required manual reinstall. Best-effort: hash read/write
  failures degrade gracefully with stderr warnings rather than crashing
  the CLI. (#36)

- **`openant init` no longer requires a git repository for local paths.**
  Init on a non-git directory (tarball download, generated code, locally
  modified tree) now succeeds with `commit_sha` set to the `"nogit"`
  placeholder. `--commit` on a non-git directory warns and is ignored
  rather than hard-failing. Adds a shared `config/languages.json`
  consumed by both the Go CLI and the Python parser adapter — single
  source of truth for file-extension mappings and skip directories,
  eliminating Go↔Python drift. Language auto-detection is exposed as
  opt-in via `-l auto` (experimental dominance heuristic — see #61 for
  the validation work needed before it becomes the default). (#40)

- **`--llm-reachability` opt-in stage on `openant scan`.** A new optional
  review pass that uses Opus (default) to surface reachability signals
  the structural analysis misses — likely entry points (framework
  handlers, plugin/CLI registrations, message queues), external content
  ingestion sites (HTTP request bodies, file/network reads, env/argv,
  IPC), and async/cross-process data flows. Promote-only semantics:
  signals can mark units as entry points but never demote a unit the
  structural pass kept. When enabled, parse runs with `processing_level
  = "all"` so the LLM sees the full unfiltered codebase, then the
  structural reachability filter re-runs with LLM-promoted entry points
  added as additional BFS seeds. Output: `llm_reachability.json` plus
  per-unit `llm_reachability_signals` field on `dataset.json`.
  Cost-conscious: opt-in only, batched (default 25 units per Opus call),
  scales with total repo size rather than the filtered unit count. Off
  by default. (#50)

- **All parsers now write `call_graph.json`.** Previously only the Python
  and Zig parsers persisted this file; JS, Go, C, Ruby, and PHP did
  reachability filtering internally and didn't expose the graph. Required
  for the new `--llm-reachability` re-filter to work across all
  languages. Defensive WARNING in `scanner.py` fires with a cost-impact
  message if the file is ever missing for a language that should support
  it. (#50)

## [2026-05-10] — Windows compatibility & CI hardening

### Fixed

- **JavaScript parser no longer returns zero functions on Windows.**
  `path.relative()` and `path.resolve()` produce backslash-separated
  paths there, and ts-morph treats `\` as an escape character when
  matching paths it has already added — the analyzer silently emitted
  an empty result. The TypeScript analyzer now normalises every path
  it hands to ts-morph (and every value stored as a `functionId`
  component) to forward slashes via a `toPosixPath()` helper. A
  static-scanner test in `libs/openant-core/tests/test_windows_path_handling.py`
  enforces the contract on every commit.
- **`--files-from` no longer drops every path on Windows.** File lists
  written with CRLF line endings used to leave a trailing `\r` on each
  entry, which `addSourceFileAtPath` then failed to resolve. The
  TypeScript analyzer now splits on `/\r?\n/` and trims each line.
- **Pipeline status output no longer crashes on cp1252 consoles.**
  `parsers/{javascript,go}/test_pipeline.py` previously printed
  `✓ ✗ →` directly, which raised `UnicodeEncodeError` on the Windows
  default code page. Both pipelines now probe `sys.stdout.encoding` at
  import time and fall back to ASCII (`OK` / `FAIL` / `->`) only when
  the terminal can't encode the Unicode glyphs — UTF-8 terminals keep
  the prettier output.
- **`'charmap' codec can't decode byte ...` errors on Windows.** Bare
  `open()` calls and `subprocess.run(..., text=True)` invocations
  across `libs/openant-core/` defaulted to the system locale encoding
  (cp1252 on Windows), crashing on any source code containing non-ASCII
  characters (curly quotes U+2019, accented characters, CJK). All ~190
  call sites now go through new helpers in
  `libs/openant-core/utilities/file_io.py` (`open_utf8`, `read_json`,
  `write_json`, `run_utf8`) that pin UTF-8 explicitly. Four regression
  scanners in `tests/test_file_io.py` prevent reintroduction by failing
  CI on any new bare `open(`, `.read_text(`/`.write_text(`, `.open(`,
  or `subprocess.run(..., text=True)` call without an explicit
  `encoding=`.
- **Token tracker NameError on resume.** `core/analyzer.py` called
  `tracker.add_prior_usage(...)` without `tracker` being defined in the
  surrounding `run_analysis()` function. The path was reached only when
  resuming a scan with non-zero prior token usage — a dormant bug
  uncovered by the new lint step. Now uses `get_global_tracker()` to
  match the existing pattern in the same function.
- **Managed venv path is wrong on Windows.** `venvPython()` in
  `apps/openant-cli/internal/python/runtime.go` hard-coded
  `bin/python`, which doesn't exist in a Windows venv (the layout there
  is `Scripts\python.exe`). The CLI now branches on `runtime.GOOS` and
  returns the OS-correct path, so `~/.openant/venv/` is usable on
  Windows without setting `OPENANT_PYTHON`. New `runtime_test.go`
  covers both layouts.
- **Python parser test pipelines fail when invoked as subprocesses.**
  `parsers/{javascript,go}/test_pipeline.py` import from `utilities.*`
  but, when the Go CLI runs them as subprocesses with a different
  working directory, `openant-core/` was not on `sys.path`. Both files
  now prepend the openant-core root to `sys.path` before the
  `utilities` import.
- **Anthropic SDK auth-error test broken by SDK update.**
  `tests/test_silent_401.py` constructed `AuthenticationError("...")`
  with a positional message; the current SDK requires
  `AuthenticationError(message=, response=, body=)`. The test now
  builds a mock `httpx.Response` and uses the keyword form, and
  temporarily restores the real `anthropic` module so the real
  exception class is used.
- **`run_utf8` explicit-encoding test crashed on Windows.**
  `test_run_utf8_does_not_override_explicit_encoding` used
  `print('café')` from a `-c` snippet, which itself fails to encode
  on a cp1252 console before `run_utf8` even runs. The test now writes
  raw `latin-1` bytes via `sys.stdout.buffer.write(...)` so the
  encoding-override path is the thing under test on every platform.
- **`withTempHome` test helper didn't work on Windows.** Both copies
  (`apps/openant-cli/cmd/mode_test.go` and
  `apps/openant-cli/internal/config/scan_meta_test.go`) only set
  `HOME`, but `os.UserHomeDir()` on Windows reads `USERPROFILE`. The
  helpers now branch on `runtime.GOOS` and set the correct env var.

### Added

- **CI now lints for missing imports and undefined names.** A
  `ruff check .` step runs in the `python-tests` job before `pytest`,
  with `select = ["F821", "F811"]` (undefined name, redefined unused
  name). Both rules are zero-false-positive runtime-bug catchers, so
  contributors get fast static feedback on the kind of mistake Python
  won't surface until the affected code path executes. Scoped narrowly
  on purpose — widening to additional pyflakes rules can come later.
- **CI now runs Go unit tests on every platform.** A new
  `go test ./... -v` step runs in the `go-tests` job before the build,
  on Ubuntu, macOS, and Windows. Catches regressions like the venv
  path bug above before the binary is built. The Python step also
  switched from a hand-curated test list to `pytest tests/`, picking
  up ten previously-CI-invisible test files (UTF-8 file I/O, Windows
  path handling, dedup, cwe-tagging, evidence-tier, and others).

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
