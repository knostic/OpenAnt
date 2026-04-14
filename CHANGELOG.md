# Changelog

All notable changes to OpenAnt are documented in this file.

## [Unreleased]

This release syncs a large body of work from internal development. Highlights:

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
