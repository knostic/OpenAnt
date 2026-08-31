# Auto Patcher Architecture

This is the primary technical architecture document for Auto Patcher. It
describes the system as implemented today: the pipeline's canonical stages,
how a production run executes them, how execution is recorded, and how the
replay/debugging infrastructure reuses that same production code.

It does **not** cover the recommendation/trust-decision logic in depth —
see [recommendation-policy.md](recommendation-policy.md) for that — and it
does not cover day-to-day debugging workflows — see
[TRACING_AND_DEBUGGING.md](../../libs/openant-core/utilities/autopatcher/tools/TRACING_AND_DEBUGGING.md)
for that. This document is the map that ties the two together.

Everything below is grounded in the current implementation under
`libs/openant-core/utilities/autopatcher/`, principally `pipeline.py`,
`stage_registry.py`, `execution_recorder.py`, `lineage.py`, and
`replay_engine.py`. Function and file names are cited so this document can
be re-verified against source at any time; treat a mismatch you find as
this document being stale, not the code.

## Contents

- [System overview](#system-overview)
- [Pipeline architecture](#pipeline-architecture)
- [Terminal reporting architecture](#terminal-reporting-architecture)
- [Shared production/replay architecture](#shared-productionreplay-architecture)
- [Execution recording](#execution-recording)
- [Provenance and lineage](#provenance-and-lineage)
- [Effective dependency resolution](#effective-dependency-resolution)
- [Replay architecture](#replay-architecture)
- [Full run, traced run, and replay compared](#full-run-traced-run-and-replay-compared)
- [Artifacts and directory structure](#artifacts-and-directory-structure)
- [Architectural invariants](#architectural-invariants)

## System overview

```
openant patch (Go CLI)                    tools/run_traced.py (Python, in-process)
        │                                            │
        ▼                                            ▼
 python subprocess                          core.patch.run_patch /
        │                                    run_patch_cve (same functions)
        ▼                                            │
 core.patch.run_patch / run_patch_cve                │
        │                                            │
        └───────────────────┬────────────────────────┘
                             ▼
                  utilities.autopatcher.pipeline.run()
             (the canonical 13-stage pipeline, S1-S13)
                             │
                             ▼
                _build_report()  ──►  Trust Report (Markdown)
```

- **`apps/openant-cli`** (Go) — thin transport. Parses flags, resolves the
  active project, shells out to the Python engine. No LLM resolution, no
  patch logic, no trace capture of its own.
- **`libs/openant-core/core/patch.py`** — `run_patch()` / `run_patch_cve()`.
  Turns a Finding or a fetched CVE advisory into the `(vulnerability_text,
  repo_root)` pair `pipeline.run()` accepts, then writes the two on-disk
  artifacts (`{label}-vulnerability.md`, `{label}-trust-report.md}`) under
  `{output_dir}/patch/`. Both accept an optional `execution_recorder`
  parameter that is `None` for every normal caller.
- **`libs/openant-core/utilities/autopatcher/pipeline.py`** — the engine.
  `run()` orchestrates the 13 canonical stages; `_build_report()` renders
  the Trust Report from the resulting `PipelineResult`.
- **`stage_registry.py`** — the single, static source of truth for what the
  13 canonical stages are, their approved dependency graph, and their
  capability/LLM-ownership metadata. Never mutated at runtime.
- **`execution_recorder.py`** / **`lineage.py`** — the passive recording and
  manifest/provenance model. A production run only produces recorded
  `StageExecution`s when a caller passes an `ExecutionRecorder` in (today:
  only `tools/run_traced.py`). A plain `openant patch` run records nothing.
- **`replay_engine.py`** (plus the reused `stage_replay.py` helpers) — the
  stage-registry-driven replay engine. Reruns one canonical stage's
  *current* production implementation against upstream state resolved from
  a prior run's lineage.
- **`tools/run_traced.py`** / **`tools/run_stage.py`** — the two developer
  entry points: a full traced run, and a single-stage replay. See
  TRACING_AND_DEBUGGING.md for usage.

## Pipeline architecture

### The 13 canonical stages

`stage_registry.CANONICAL_STAGE_ORDER`
(`utilities/autopatcher/stage_registry.py:71-85`) is the single source of
truth for stage identity and order:

| # | Canonical name | Deterministic or model call? |
|---|---|---|
| S1 | `repository_analysis_and_remediation_planning` | Model call (`remediation_planning`) |
| S2 | `remediation_strategy` | Model call (`remediation_strategy`), conditional |
| S3 | `guided_context_acquisition` | Model call (`guided_context_request`), best-effort/optional |
| S4 | `patch_generation_and_post_patch_investigation` | Model call (`patch_generation`, `patch_generation_contract_retry`) + deterministic repair/investigation |
| S5 | `challenger` | Model call (`challenger`) |
| S6 | `patch_repair_and_calibration` | Model calls (`finding_calibration`, `challenger`, `patch_repair_regeneration`), conditional |
| S7 | `patch_review` | Model call (`patch_review`) |
| S8 | `confidence_scoring` | Model call (`confidence_scorer`) + deterministic discount |
| S9 | `impact_and_behavior_analysis` | Deterministic only — owns zero LLM tags |
| S10 | `test_analysis_and_plan` | Model call (`test_plan_discovery`), opt-in |
| S11 | `existing_test_comparison` | Deterministic only (Docker execution + comparison), opt-in |
| S12 | `trust_signals_and_recommendation` | Deterministic only |
| S13 | `report_generation` | Deterministic only (may read the repository, e.g. `tests_for_file`) |

"Model call" above means the stage's canonical implementation is capable of
making an LLM call under some conditions — several are conditional
(S2, S6) or genuinely best-effort/optional (S3, S10, S11). The exact
`stage=` tags each canonical stage is authorized to emit are declared in
`stage_registry.STAGE_OWNED_LLM_TAGS` and enforced by the execution
recorder (see [Execution recording](#execution-recording)). One tag,
`"challenger"`, is legitimately owned by both `CHALLENGER` and
`PATCH_REPAIR_AND_CALIBRATION` today — tracked explicitly as
`KNOWN_AMBIGUOUS_LLM_TAGS`, not silently hidden
(`stage_registry.py:234-244`).

### Per-stage detail

**S1 — `repository_analysis_and_remediation_planning`**
- *Purpose:* repository grounding, deterministic Repository Understanding
  (candidate selection + enrichment + fusion), and the Planner's first LLM
  call proposing an unverified remediation plan.
- *Inputs:* `vulnerability_text`, `repo_root`, `investigation_output_dir`.
- *Outputs:* rendered plan text, `RepositoryGroundingResult`,
  `RepositoryUnderstanding`, pre-patch Anchors, `RemediationPlanResult`.
- *Dependencies:* none — the pipeline's genesis stage
  (`STAGE_DEPENDENCIES[S1] == ()`).
- *Model call:* `remediation_planning`, via
  `remediation_planner.generate_remediation_plan` — skipped only when a
  hand-authored plan is already supplied.
- *Entry point:* `pipeline._run_repository_analysis_and_remediation_planning`
  (`pipeline.py:4815`) — a reusable executor shared verbatim with
  `replay_engine.py`.
- *Notes:* best-effort throughout except a deliberate `ModelUnavailableError`
  re-raise. `repo_locator.py`, `candidate_selection.py`, and
  `candidate_enrichment.py` (all deterministic, no LLM calls) supply the
  grounding/investigation evidence this stage assembles.

**S2 — `remediation_strategy`**
- *Purpose:* a second, distinct Planner call that reasons over S1's
  *deterministically verified* evidence (`build_planner_evidence`, no LLM)
  to produce a Final Remediation Strategy — target files/symbols, warnings,
  and a one-sentence `security_invariant`.
- *Inputs:* S1's verified planner evidence (`planner_evidence_ctx`).
- *Outputs:* `RemediationStrategyResult` (`target_files`, `target_symbols`,
  `security_invariant`, warnings).
- *Dependencies:* S1.
- *Model call:* `remediation_strategy`, via
  `remediation_planner.generate_remediation_strategy` — **skipped entirely**
  (no call made) when S1 produced no verified evidence to reason over; this
  is "not a blind retry" of S1's call.
- *Entry point:* inline in `pipeline.run()` (`pipeline.py:5491-5556`).

**S3 — `guided_context_acquisition`**
- *Purpose:* builds the Final-Target Remediation Slice, runs the
  **Edit Readiness Gate**, and — only if readiness is still incomplete —
  bounded deterministic (Slice 2) and then bounded LLM-guided (Slice 3,
  at most `MAX_GUIDED_ACQUISITION_ROUNDS` calls) source acquisition, plus a
  bounded full-file fallback.
- *Inputs:* S2's `RemediationStrategyResult`, S1's `RemediationPlanResult`
  and investigation context, an optional `ContextBudgetController`.
- *Outputs:* `EditReadinessResult`, `AcquisitionResult`,
  `GuidedAcquisitionResult`, `FinalTargetSliceResult`, and the
  `_skip_patch_generation` flag that gates S4.
- *Dependencies:* S1, S2.
- *Model call:* `guided_context_request`, via
  `remediation_planner.generate_guided_context_requests` — genuinely
  best-effort; fires only when deterministic acquisition still leaves
  readiness incomplete, and most non-`ModelUnavailableError` failures leave
  the slice exactly as already computed rather than failing the stage.
- *Entry point:* `pipeline._run_guided_context_acquisition`
  (`pipeline.py:4957`) — reusable executor shared with `replay_engine.py`.
- *Notes:* this is where the **Edit Readiness Gate**
  (`remediation_planner.check_edit_readiness`) lives — the deterministic
  decision that, if unresolved, sets `_skip_patch_generation = True` and
  causes the pipeline's [no-patch early stop](#no-patch-early-stop).

**S4 — `patch_generation_and_post_patch_investigation`**
- *Purpose:* the single largest canonical stage. Generates the candidate
  patch (with a bounded contract-check retry), runs deterministic
  hunk-header repair, the Slice-4 Patch Target Conformance Gate and
  Post-Patch Recovery, patch hygiene and applicability checks (with their
  own deterministic repair and a bounded applicability-aware retry), and
  finally Post-Patch Vulnerability Investigation — re-evaluating pre-patch
  Anchors against an isolated, patched copy of the repository.
- *Inputs:* assembled `code_context`, S3's `EditReadinessResult` and
  `FinalTargetSliceResult`, pre-patch Anchors.
- *Outputs:* `patch`, hygiene findings, applicability result, relocation
  telemetry, `post_patch_observations`, `post_patch_coverage`.
- *Dependencies:* S1, S2, S3.
- *Model call:* `patch_generation` / `patch_generation_contract_retry`.
  Both `generate_patch`/`generate_patch_raw` default their own `stage`
  parameter to `"patch_generation"` when a caller doesn't override it, so
  every generation call this stage makes carries one of these two tags —
  there is no untagged LLM call anywhere in S4. The initial generation
  (via `_generate_patch_with_contract_check`) can itself make up to two
  calls, `patch_generation` then, only on a contract-violation response,
  `patch_generation_contract_retry`. Two further, conditional generation
  attempts **reuse these same two tags** rather than introducing new ones:
  Post-Patch Recovery's regeneration (`pipeline.py:4079-4082`) calls
  `generate_patch()` with no `stage` override, so it is tagged
  `patch_generation`; the applicability-aware retry
  (`pipeline.py:4392-4396`) calls `_generate_patch_with_contract_check`
  again, so it can itself produce a `patch_generation` and/or
  `patch_generation_contract_retry` call. Practical consequence: a single
  S4 execution's `llm_calls` can contain more than one entry tagged
  `patch_generation` — distinguishing which attempt is which requires
  reading call order/count or the prompt content itself, not the tag
  alone (see TRACING_AND_DEBUGGING.md's guidance on call numbering).
- *Entry point:* `pipeline._run_patch_generation_and_investigation`
  (`pipeline.py:3903`) — reusable executor shared with `replay_engine.py`.
- *Notes:* an invalid Patch Generator response fails closed
  (`_patch_validation_skip_reason`) *before* hunk repair/hygiene/
  applicability run, rather than flowing through as an ordinary empty
  patch. See [Recommendation Policy's Evidence section](recommendation-policy.md#evidence)
  for how the deterministic repair chain feeds `patch_integrity` and
  `source_verification`.

**S5 — `challenger`**
- *Purpose:* the adversarial pass — argues the patch does *not* hold, never
  that it does.
- *Inputs:* `patch`, `challenger_context` (code context + Post-Patch
  Investigation findings, when current).
- *Outputs:* raw Challenger result (`still_vulnerable`, free-text findings).
- *Dependencies:* S4.
- *Model call:* `challenger`, via `patch_challenger.challenge_patch` —
  skipped (`challenger = {}`) when there is no candidate patch.
- *Entry point:* inline in `pipeline.run()` (`pipeline.py:5764-5799`).
- *Notes:* see
  [recommendation-policy.md's Challenger section](recommendation-policy.md#heuristic-evidence-the-adversarial-challenger)
  for the deterministic classification (`_classify_finding`/
  `_classify_challenger`) applied to this stage's output.

**S6 — `patch_repair_and_calibration`**
- *Purpose:* classifies S5's Challenger output (`_classify_challenger`);
  runs Finding Calibration to produce the run's final, reported
  `finding_calibration`; and, only when that classification found at least
  one raw `confirmed_defect`, deterministically gates (`should_auto_repair`)
  a single-shot Challenger-driven repair loop (regenerate → re-check
  hygiene/applicability → re-challenge → `accept_repair`).
- *Finding Calibration is called via one of two distinct paths, not one
  fixed rule* (`_run_patch_repair_and_calibration`,
  `pipeline.py:4521-4752`):
  - **No raw `confirmed_defect` finding exists** (`_orig_defect_count == 0`
    — the common, all-clear case): the repair block above is skipped
    entirely, and a single fallback `calibrate_findings` call runs once,
    against only `plausible_risk`/`generic` findings from the (unmodified)
    Challenger result — `confirmed_defect` and `validation_gap` findings
    are never included in this call's input.
  - **At least one raw `confirmed_defect` finding exists**
    (`_orig_defect_count > 0`): a first `calibrate_findings` call ("v1")
    runs against `confirmed_defect` **+** `plausible_risk` **+**
    `generic` findings (`validation_gap` is still excluded) — deliberately
    widened so the deterministic repair gate (`should_auto_repair`) reads
    calibration-aware state rather than the raw classifier alone. If a
    repair is attempted and the regenerated patch applies, it is
    re-challenged and a second `calibrate_findings` call ("v2") runs
    against the SAME widened category set from that re-challenge; if
    `accept_repair` accepts the repaired patch, v2's calibration replaces
    v1's as the run's final, reported `finding_calibration`.
  In both paths, `calibrate_findings` is passed only finding *text* (its
  original classifier category is not preserved in the call) and
  independently sorts each finding into `observed`/`hypothesis`/
  `hardening` on its own judgment — see
  [recommendation-policy.md's Finding Calibration section](recommendation-policy.md#finding-calibration)
  for what that regrouping means for the report. Every `calibrate_findings`
  call — v1, v2, or the fallback — is tagged `stage="finding_calibration"`
  regardless of which of these call sites made it.
- *Inputs:* S4's `patch`, S5's `challenger` result.
- *Outputs:* the (possibly repaired) `patch`/`challenger`/`applicability_result`/
  `hygiene_findings`, `finding_calibration`, repair bookkeeping fields.
- *Dependencies:* S4, S5.
- *Model call:* `finding_calibration`, `challenger` (ambiguous with S5 —
  see above), `patch_repair_regeneration`.
- *Entry point:* `pipeline._run_patch_repair_and_calibration`
  (`pipeline.py:4521`) — reusable executor shared with `replay_engine.py`.
- *Notes:* the repair loop's internal regeneration/re-challenge are
  **deliberately not** recorded as new S4/S5 executions — the repair path
  is proven not equivalent to S4's full canonical contract (no contract
  retry, no conformance/recovery, no applicability-aware retry, no
  Post-Patch Investigation), so treating it as a second S4/S5 would
  misrepresent two different contracts as one
  (`pipeline.py:5807-5812`). Repair fires **at most once** per run — but
  Finding Calibration itself can be called up to twice within that one S6
  execution (v1 then v2) when the repair path is exercised.

**S7 — `patch_review`**
- *Purpose:* an independent narrative review of the final candidate patch.
- *Inputs:* vulnerability text, S6's authoritative candidate patch
  (original or accepted-repair, whichever S6 selected) — **no**
  `code_context`, **no** Challenger or Calibration output.
- *Outputs:* Explanation / Affected areas / Reviewer Notes text.
- *Dependencies:* S6.
- *Model call:* `patch_review`, via `patch_reviewer.review_patch` — skipped
  when there is no candidate patch.
- *Entry point:* inline in `pipeline.run()` (`pipeline.py:6120-6166`).
- *Notes:* see
  [recommendation-policy.md's Patch Reviewer section](recommendation-policy.md#patch-reviewer)
  for the important provenance caveat — this stage's claims about
  repository/upstream state reflect model prior knowledge, not verified
  evidence.

**S8 — `confidence_scoring`**
- *Purpose:* a numeric confidence score, deterministically discounted by
  the Challenger's own verdict.
- *Inputs:* S6's patch/challenger, S7's review output, the same
  `code_context` the Challenger saw.
- *Outputs:* `score_text`, `orig_score`, `adjusted_score`.
- *Dependencies:* S6, S7.
- *Model call:* `confidence_scorer`, via `confidence_scorer.score_confidence`.
- *Entry point:* inline in `pipeline.run()` (`pipeline.py:6145-6186`), using
  the shared deterministic adjustment `_adjust_confidence_score_for_challenger`.
- *Notes:* this score is computed and then **discarded** — never read by
  Trust Signals or the Recommendation Policy, never rendered in the Trust
  Report. See
  [recommendation-policy.md](recommendation-policy.md#what-does-not-affect-the-recommendation).

**S9 — `impact_and_behavior_analysis`**
- *Purpose:* deterministic AST-based Python-only impact/blast-radius
  analysis (`impact_surface.LightweightImpactAnalyzer`) plus a
  language-agnostic, diff-only behavior summary
  (`behavior_summary.BehaviorAnalyzer`).
- *Inputs:* `patch`, `challenger`, `repo_root`.
- *Outputs:* `impact_dict`, `behavior`, detected language.
- *Dependencies:* S6.
- *Model call:* **none** — `STAGE_OWNED_LLM_TAGS[S9] == ()`. Both analyzers
  are best-effort (`try/except: pass`), so this stage always settles.
- *Entry point:* `pipeline._run_impact_and_behavior_analysis`
  (`pipeline.py:5277`) — reusable executor shared with `replay_engine.py`.
- *Notes:* Impact Surface reports `"not_applicable"` (never a fabricated
  "low impact") on non-Python repositories. Unlike S5/S7/S8, this stage is
  **not** gated on `patch` being non-empty — it always runs, even on a
  no-patch run (`BehaviorAnalyzer` runs against an empty diff; Impact
  Surface is gated only on `repo_root`).

**S10 — `test_analysis_and_plan`**
- *Purpose:* the one bounded LLM call proposing how the repository's
  existing tests should be prepared and run, deterministically validated
  before use.
- *Inputs:* `repo_root`, `patch`, deterministically gathered evidence
  (config files, CI snippets, README excerpt, directory listing —
  `test_evidence_acquisition.gather_test_plan_evidence`).
- *Outputs:* a validated `TestExecutionPlan`, or `None` with a recorded
  rejection reason.
- *Dependencies (declared):* S6, S9. *(See [runtime-order note](#canonical-order-vs-runtime-order) — S9 does not actually execute before this stage in current code order; production `consumed` stays strictly `[S6]`.)*
- *Model call:* `test_plan_discovery`, via
  `test_plan_discovery.discover_test_plan` (invoked through
  `existing_test_regression.discover_test_plan_for_comparison`) — opt-in,
  only runs when `compare_existing_tests=True`.
- *Entry point:* `existing_test_regression.discover_test_plan_for_comparison`
  (`existing_test_regression.py:461`), called from `pipeline.run()`
  (`pipeline.py:6016-6048`).
- *Notes:* this canonical stage **absorbs** the old standalone
  `test_plan_discovery` name as an internal sub-operation — that name is
  explicitly retired (`stage_registry._RETIRED_LEGACY_STAGE_NAMES`), though
  the LLM call itself keeps the legacy tag `stage="test_plan_discovery"`
  (`STAGE_OWNED_LLM_TAGS[TEST_ANALYSIS_AND_PLAN] == ("test_plan_discovery",)`).
  `test_plan_validation.py` is the deterministic gate `discover_test_plan`
  relies on before returning a plan; it never itself calls an LLM.
  `discover_test_plan_for_comparison` runs a Docker preflight check
  *before* its LLM call, fail-fast — but `stage_registry._DOCKER` marks
  only `EXISTING_TEST_COMPARISON` as `True`, leaving this stage's own
  `requires_docker` flag at the default `False`; a known, minor mismatch
  between declared capability metadata and actual runtime behavior.

**S11 — `existing_test_comparison`**
- *Purpose:* runs S10's plan once against an isolated, unpatched copy of
  the repository and once against an isolated, patched copy (Docker-only —
  never falls back to host execution), and deterministically compares
  results for newly-introduced failures.
- *Inputs:* `repo_root`, `patch`, S10's `TestExecutionPlan`.
- *Outputs:* `ExistingTestComparisonResult` (status, per-test delta).
- *Dependencies:* S6, S10.
- *Model call:* **none** — fully deterministic (Docker execution +
  JUnit/TAP comparison via `result_parsers`).
- *Entry point:*
  `existing_test_regression.evaluate_existing_test_comparison_with_plan`
  (`existing_test_regression.py:525`), called from `pipeline.run()`
  (`pipeline.py:6055-6099`).
- *Notes:* a factual delta only — "a newly failing test may be an
  unintended regression, an expected behavior change, or a stale test";
  this module deliberately never decides which, and its result is never
  read by the Recommendation Policy or fed back into the Challenger/repair
  loop. Requires Docker (`stage_registry._DOCKER[S11] == True`) — the only
  canonical stage that does.

**S12 — `trust_signals_and_recommendation`**
- *Purpose:* computes the Trust Signals and the four-label Recommendation
  (`_build_recommendation_v1`) from the evidence assembled by every prior
  stage. `_compute_trust_signals` itself computes **six** signals
  (`patch_integrity`, `security_improvement`, `remediation_alignment`,
  `deployment_safety`, `test_availability`, `coverage_confidence`);
  `_build_report` then merges in two more as separate dict keys —
  `source_verification` and `existing_test_comparison` — neither of which
  is part of `_compute_trust_signals`'s own six-signal computation or its
  I1–I6 invariants. That yields **eight** signal keys in the final signals
  dict passed to `_build_recommendation_v1` and the report renderer.
  **Seven** of those eight are rendered as their own row in the Trust
  Signals table; `security_improvement` is computed and used by the
  Recommendation Policy but not separately displayed. See
  [recommendation-policy.md's Trust Signals section](recommendation-policy.md#trust-signals)
  for the full signal-by-signal breakdown.
- *Dependencies:* S6, S9, S10, S11.
- *Model call:* none — fully deterministic given its inputs.
- *Entry point:* `pipeline._compute_trust_signals` /
  `pipeline._build_recommendation_v1`, both called from inside
  `_build_report()` (`pipeline.py:2629`).
- *Notes:* see
  [Terminal reporting architecture](#terminal-reporting-architecture) below
  — **S12 has no independent execution record or replay path in the
  current implementation.** It is not a separately callable function in
  `run()`; it only ever executes as part of `_build_report()`. Full policy
  detail lives in [recommendation-policy.md](recommendation-policy.md).

**S13 — `report_generation`**
- *Purpose:* renders the final Markdown Trust Report — Recommendation,
  Trust Signals table, Review Results, Post-Patch Investigation, Suggested
  Tests, Appendices, Run Metadata.
- *Dependencies:* every other canonical stage (all 12).
- *Model call:* none — pure deterministic rendering, though it may read the
  repository (e.g. `tests_for_file()` for the Suggested Tests section)
  whenever `repo_root` is available.
- *Entry point:* `pipeline._build_report` (`pipeline.py:2629`) — the last
  call in `run()` (`pipeline.py:6274`).

### Canonical order vs. runtime order

**The canonical stage list (S1-S13) is a dependency/identity ordering, not
a literal runtime execution trace.** `stage_registry.CANONICAL_STAGE_ORDER`
gives every stage a stable position for naming, dependency declarations,
and manifest bookkeeping — but `pipeline.run()`'s actual call order does
not always match it, and the code says so explicitly in more than one
place:

- **S10/S11 run before S7/S8/S9 in code**, not after S9 as the numbering
  implies. Actual order: S1 → S2 → S3 → S4 → S5 → S6 → (S10 → S11, only if
  `compare_existing_tests=True`) → deterministic constraint/remediation
  signals → S7 → S8 → S9 → `PipelineResult` → `_build_report` (S12+S13).
- **S10's declared dependency on S9 is not real in production.**
  `stage_registry.STAGE_DEPENDENCIES[TEST_ANALYSIS_AND_PLAN]` names both S6
  and S9, but S9 has not executed yet by the time S10 runs — the code
  comments on this directly:

  > "S9 does not even execute until AFTER this block in current code order,
  > so no S9 execution exists yet to truthfully reference here. This is a
  > genuine, pre-existing mismatch between the registry's declared graph
  > and actual production dataflow/ordering... `consumed` stays strictly
  > truthful (S6 only) rather than fabricating a forward reference."
  > — `pipeline.py:6006-6015`

- **S6's internal repair loop is not a re-execution of S4/S5.** The
  Challenger-driven repair loop inside S6 regenerates a patch and
  re-challenges it, but this stays wholly inside one S6 `StageExecution` —
  it is never recorded as a second canonical execution of S4 or S5 (see
  the S6 entry above).
- **S12 and S13 are never separately invoked or recorded in production.**
  They exist as canonical stages in `stage_registry.py`, but
  `pipeline.run()` never calls a `_run_trust_signals_and_recommendation`
  or `_run_report_generation` function — both only happen inside
  `_build_report()`, called once, at the very end of `run()`.

The practical rule: **when you need "what actually happened, in what
order," read `pipeline.run()` and its `execution_recorder` call sites (or
a real `run_manifest.json`'s `executions` list, ordered by `sequence`) —
never assume `CANONICAL_STAGE_ORDER` describes the runtime trace.**

### No-patch early stop

If, after S3's Edit Readiness Gate and both acquisition slices run,
`EditReadinessResult.edit_source_ready` is still `False`, S3 sets
`_skip_patch_generation = True` (`pipeline.py:5264-5271`). This flag flows
into S4, which sets `patch = ""` and a
`_patch_validation_skip_reason` instead of generating a patch
(`pipeline.py:3926-3929`). Not every later stage reacts the same way to an
empty `patch` — this is stage-specific gating, not a single blanket rule:

- **S5 (`challenger`) is skipped outright** — `challenger = {}`, no LLM
  call (`pipeline.py:5775-5783`).
- **S6 (`patch_repair_and_calibration`) still runs as a function call**,
  but is a computational no-op: classifying the empty `challenger` dict
  yields zero findings of every category, so the repair gate never
  triggers and the fallback Finding Calibration pass has no findings to
  calibrate, so it makes no LLM call either (`pipeline.py:4736-4752`).
- **S7 (`patch_review`) and S8 (`confidence_scoring`) are both
  skipped** — `review = ""` / `score_text = ""`, no LLM calls
  (`pipeline.py:6134-6169`).
- **S9 (`impact_and_behavior_analysis`) still executes normally** — it is
  never gated on `patch` truthiness at all (Behavior Summary runs against
  an empty diff; Impact Surface is gated only on `repo_root`).
- **S10/S11 (`test_analysis_and_plan`/`existing_test_comparison`), when
  `compare_existing_tests=True`, explicitly short-circuit** to a
  `NOT_VERIFIED` result with the reason `"no candidate patch was
  produced"` — neither attempts test discovery or execution
  (`pipeline.py:5992-5994`).
- **S12/S13 still compute a full result** over this empty/default
  evidence (see
  [recommendation-policy.md](recommendation-policy.md#no-patch-produced)),
  but `_build_report` discards the computed recommendation and renders a
  dedicated `## ⚫ NO PATCH PRODUCED` card instead.

## Terminal reporting architecture

S12 (`trust_signals_and_recommendation`) and S13 (`report_generation`) are
two distinct entries in `stage_registry.CANONICAL_STAGE_ORDER`, with
distinct approved dependency sets — but **in both production and replay,
they are implemented as one fused unit**, not as two independently callable
stages.

In production, neither has its own `_run_*` executor function and neither
gets its own `execution_recorder.start()`/`.finish()` bracket. Both are
computed inside a single function, `_build_report()`
(`pipeline.py:2629`), called once at the very end of `run()`
(`pipeline.py:6274`):

```
PipelineResult(...)
        │
        ▼
   _build_report(result)
        │
        ├── _compute_trust_signals(result)       (S12: Trust Signals)
        ├── _build_recommendation_v1(signals)     (S12: Recommendation)
        └── every render_* helper                 (S13: report Markdown)
        │
        ▼
   Trust Report (Markdown string)
```

This is why replay treats them as **one combined replay unit**, registered
under the `report_generation` name only (see
[Replay architecture](#replay-architecture)): there is no real, separate
execution of "just the Trust Signals half" to replay, because production
itself never executes or records one. `report_generation`'s replay handler
reconstructs a real `PipelineResult` from every upstream stage's own
persisted artifact and calls the same, unmodified `_build_report()`
directly — no recommendation-policy or report-rendering logic is
duplicated in the replay path.

**Do not read this as "S12 is independently replayable."** It is not:
`replay_engine.REPLAY_HANDLERS` has no entry for
`trust_signals_and_recommendation`, and attempting to replay it directly
fails with a "registered but not replayable yet" error, before any I/O.
Lineage resolution can still resolve a *persisted* S12 execution from a
manifest (if one exists) as a dependency of something else — "persisted"
and "replayable" are independent concepts (see
[Execution recording](#execution-recording)) — but there is no code path
that produces or replays an S12 execution on its own.

## Shared production/replay architecture

The single most important invariant in this codebase: **replay is not a
second implementation of pipeline stages.** Production `pipeline.run()`
and the replay engine call the *same* Python functions.

```
                     ┌─────────────────────────────┐
                     │   Stage implementation        │
                     │  (pipeline._run_*, or a       │
                     │   directly-callable, already   │
                     │   pure stage function)         │
                     └───────────────┬────────────────┘
                                     │  called by both
              ┌──────────────────────┴──────────────────────┐
              ▼                                              ▼
   Production orchestration                        Replay orchestration
   (pipeline.run())                                 (replay_engine.replay_stage())
   - builds real inputs from                        - builds the SAME shape of
     live pipeline state                              inputs by reconstructing
   - calls the stage function                          them from persisted
   - records a StageExecution                          execution artifacts
     if an ExecutionRecorder                          (from_jsonable)
     was passed                                      - calls the SAME stage
                                                        function
                                                      - records a StageExecution
                                                        into a NEW replay manifest
```

Four layers are worth distinguishing explicitly, because the codebase's own
comments treat this distinction as load-bearing:

1. **Production orchestration** (`pipeline.run()`) — decides *when* each
   stage runs, threads live Python objects between them, and is the only
   place workflow decisions (e.g. "should the repair loop fire?") are made.
2. **Stage implementation** — the reusable, side-effect-scoped logic each
   stage actually runs: either a standalone `_run_*` executor extracted
   verbatim from what used to be inline in `run()` (S1, S3, S4, S6, S9 —
   `pipeline.py:3903`, `4521`, `4815`, `4957`, `5277`), or an
   already-stateless, already-reusable function that needed no extraction
   at all (S2's `generate_remediation_strategy`, S5's `challenge_patch`,
   S7's `review_patch`, S8's `score_confidence`, S10/S11's
   `existing_test_regression` functions, S13's `_build_report`). Either
   way, this layer contains **zero replay-specific logic** — it is a plain
   function of its real inputs, unaware that it might be running inside a
   replay.
3. **Replay orchestration** (`replay_engine.replay_stage()`) — resolves
   which upstream execution to use for each declared dependency (via
   `lineage.resolve_effective`), reconstructs that execution's persisted
   artifact into the real Python object the stage implementation expects,
   invokes the stage implementation exactly once, and writes a new replay
   manifest. It never contains stage business logic itself.
4. **Persisted execution artifacts + dependency reconstruction** — every
   finished `StageExecution` writes its own JSON artifact
   (`execution_recorder.to_jsonable`). A replay handler reads that JSON
   back and rebuilds it into the *typed* object (dataclass/NamedTuple) the
   stage implementation's signature expects, via
   `execution_recorder.from_jsonable`, not a raw dict. This is what makes
   "production and replay call the same function" literally true rather
   than aspirational — the function signatures don't change between
   callers.

This is enforced structurally, not just by convention: a dedicated test
(`tests/patch/test_replay_engine_s4_s8.py`,
`TestSharedImplementation.test_replay_handlers_call_the_same_pipeline_executors`)
asserts **object identity** between a replay handler's called function and
`pipeline.py`'s own executor — e.g.
`replay_engine._run_replay_patch_generation_and_investigation` literally
calls `pipeline._run_patch_generation_and_investigation`, the same function
object `pipeline.run()` calls.

## Execution recording

`execution_recorder.ExecutionRecorder` (`utilities/autopatcher/execution_recorder.py`)
gives production `pipeline.run()` a way to record real `StageExecution`
entries. It is **purely observational and strictly opt-in**: every
recording call site in `pipeline.run()` is guarded by
`if execution_recorder is not None:`, the parameter defaults to `None`,
and only `tools/run_traced.py` constructs one today. A plain `openant
patch` run passes nothing and produces no `StageExecution` records at all
— confirmed by test (`test_pipeline_execution_recording.py`,
`TestRecorderNoneIsBehaviorPreserving`): the rendered Trust Report is
byte-identical with or without a recorder, and no `executions/` directory
is created without one.

### StageExecution shape (manifest schema v3)

A manifest (`run_manifest.json`) is a plain JSON dict:

```jsonc
{
  "schema_version": 3,
  "kind": "full_run" | "replay",
  "parent": "<path to source run/replay>" | null,
  "target_repository": {"repo_root": "...", "repo_commit": "..."},
  "openant": {"patcher_commit": "..."},
  "llm": {"provider": "...", "model": "..."},
  "executions": [
    {
      "execution_id": "<NNN>_<canonical_stage>",
      "canonical_stage": "<canonical stage name>",
      "sequence": 3,
      "invocation_kind": "initial" | "retry" | "replay",
      "consumed": {"<dep canonical_stage>": {"run": "<dir>", "execution_id": "<id>"}},
      "outcome": "settled" | "skipped_no_candidate_patch" | "..." | null,
      "replay_of": {"run": "<dir>", "execution_id": "<id>"} | null,
      "invoked_by": {"run": "<dir>", "execution_id": "<id>"} | null,
      "artifact_path": "<path>" | null,
      "llm_calls": [{"seq": 3, "stage": "patch_generation", "prompt_file": "...", "response_file": "..."}],
      "external_calls": [],
      "timing": {"started_at": "...", "finished_at": "..."} | null
    }
  ]
}
```

Field-by-field:

- **`execution_id`** — `"<NNN>_<canonical_stage>"`, e.g.
  `"003_patch_generation_and_post_patch_investigation"`. `NNN` is the
  execution's `sequence` within this directory only, zero-padded
  (`lineage.make_execution_id`). Every artifact filename is named after
  the full `execution_id`, never a bare canonical stage name — so a future
  directory recording more than one execution of the same canonical stage
  cannot collide.
- **`canonical_stage`** — one of the 13 names in `CANONICAL_STAGE_ORDER`.
- **`sequence`** — a **directory-local** monotonic counter, not a global
  run-lineage counter. A replay directory always has exactly one execution,
  so its `sequence` is always `1`.
- **`invocation_kind`** — `"initial" | "retry" | "replay"`. Answers *why
  this execution exists*, as universal provenance metadata — it is
  deliberately **not** the same concept as a stage's own workflow decision
  (e.g. S6 deciding to trigger its internal repair loop); that belongs
  inside the execution's own `artifact`, not this field.
- **`consumed`** — one entry per canonical-stage dependency this execution
  *actually* read, each a `{"run": ..., "execution_id": ...}` identity
  pointer. This is strict data provenance: it reflects only what was
  genuinely read, and is recorded per-execution rather than reread from
  `STAGE_DEPENDENCIES`, so a resolver judges history by what was actually
  consumed at the time, not by the current (possibly since-changed)
  declared graph.
- **`outcome`** — a short, stage-defined string (`"settled"`,
  `"skipped_no_candidate_patch"`, `"accepted"`, `"rejected"`, ...) — never
  parsed by lineage resolution, purely descriptive.
- **`artifact_path`** — path to this execution's own `<execution_id>.json`
  artifact file, written once (`ExecutionRecorder.finish()` refuses to
  overwrite an existing artifact file — immutability is enforced at the
  storage boundary, not just by convention).
- **`replay_of`** — set only on a replay execution: the closest prior
  execution of the same canonical stage found anywhere in the source
  lineage. Purely a provenance pointer — it is never used in staleness or
  dependency-resolution logic (see [Effective dependency resolution](#effective-dependency-resolution)).
- **`invoked_by`** — a separate, causal-only pointer: which *other*
  execution's workflow decision caused this one to exist. Distinct from
  `consumed` (data provenance) by design; not populated by any stage yet.
- **`llm_calls`** — the slice of the run's ordered LLM call log that fell
  inside this execution's start/finish bracket, with the full prompt/
  response text stripped (that text already lives in the trace directory's
  own `.prompt.txt`/`.response.txt` files) — only pointers
  (`prompt_file`/`response_file`) plus metadata remain.

### Why sequence must not be read as canonical stage number

`sequence` is a **directory-local execution counter**, assigned in the
order executions happened to finish *in this one directory* — it has
nothing to do with a stage's position in `CANONICAL_STAGE_ORDER`. A replay
directory's one execution always has `sequence == 1`, regardless of which
canonical stage (S1 or S11) it replays. A full run's `executions` list is
ordered by when each stage's recording bracket *finished* in
`pipeline.run()`'s actual call order — which, as documented above, does not
match `CANONICAL_STAGE_ORDER` (S9 finishes after S10/S11 in a full run with
`compare_existing_tests=True`). Always resolve "which canonical stage is
this" from the `canonical_stage` field, never from position in the list or
from the `NNN` prefix alone.

### LLM ownership enforcement

`ExecutionRecorder.finish()` cross-checks every LLM call captured inside a
bracket against `stage_registry.STAGE_OWNED_LLM_TAGS[canonical_stage]`
before accepting it (`execution_recorder.py:230-253`). A mismatch — an LLM
call tagged with a `stage=` value the canonical stage doesn't own — raises
`ExecutionRecorderError` immediately, before any file is written. This
never *reassigns* a call to the "right" stage; it proves the bracket
boundaries and the registry's declared ownership agree, and fails loudly
if they don't.

## Provenance and lineage

`lineage.py` models exactly two concepts: a **manifest** (a JSON dict on
disk) and a **lineage** (a chain of manifests linked by a `parent`
pointer). Nothing more — no database, no branch-management object.

- **Full runs** (`kind: "full_run"`) have `parent: null` — they are the
  root of every lineage. Produced by `tools/run_traced.py`.
- **Replay runs** (`kind: "replay"`) have `parent` set to the exact
  `source_run` directory the replay was invoked against
  (`lineage.new_replay_manifest`, called from `replay_engine.replay_stage()`).
- **Parent runs** — a replay's `parent` may itself be another replay, not
  only an original full run. `lineage.build_chain(tip_dir)` walks `parent`
  pointers from `tip_dir` up to the root full run, returning a flat,
  tip-first list of directories. It raises on a cycle (defensive only — a
  well-formed lineage cannot contain one, since a replay's parent must
  already exist on disk before the replay is written).
- **Exact consumed references** — every execution's `consumed` dict stores
  the *exact* `{run, execution_id}` identity of what it read for each
  dependency, not just "the dependency's canonical stage." This is what
  lets staleness detection be precise rather than directory-scoped.
- **Chained replay** — because a replay's `parent` is the *immediate*
  `source_run` it was invoked against, and `build_chain` follows `parent`
  transitively, replaying stage Y with `source_run` set to a prior replay
  of stage X's own output directory produces a chain
  `[Y's new dir, X's replay dir, ..., original full run]`. Nothing special
  has to be done to "enable" this — it falls directly out of `parent`
  wiring and `build_chain`'s walk.
- **Consuming artifacts from multiple runs in the lineage** — a single
  execution's `consumed` dict can (and typically does, in a chained
  replay) point at different directories for different dependencies: one
  dependency resolved from a nearby replay, another inherited from the
  original full run several hops up the chain, because that particular
  dependency was never replayed. This is normal, expected behavior, not an
  edge case — see the worked example below.

## Effective dependency resolution

When a stage is replayed, the engine must decide, for each declared
dependency, *which* execution in the lineage is the effective one to
consume. `lineage.resolve_effective(chain, stage_name, cache)`
(`lineage.py:702`) implements this as a **closest-ancestor-wins** walk with
an exactness check at every candidate:

1. Walk `chain` tip-first (closest directory to furthest).
2. In each directory, take that directory's own latest execution of
   `stage_name` (highest `sequence` there).
3. The **first** directory with any matching execution is a candidate —
   but it only wins if *every* dependency that execution itself recorded
   as `consumed` still resolves, recursively, to the exact same
   `{run, execution_id}` identity in the current lineage. If any of its
   own inputs have since been superseded (replayed into a different
   directory, or a later sibling execution now exists), that candidate is
   `STALE`, not a match — the walk continues to the next-closest directory
   only for genuinely unresolved cases; a `STALE` result is returned as
   the resolution for that stage, it does not silently fall through to an
   older execution.
4. Three possible outcomes: **`RESOLVED`** (identity found, exactness
   check passed all the way down), **`STALE`** (a historical execution
   exists but its own recorded inputs are no longer current — the
   execution itself is not invalid, just incompatible with the current
   branch), or **`UNRESOLVED`** (never produced anywhere in this lineage).

### Worked example

```
full run                                   (produces S4, S5, S6, S7)
  → replay S4                              (replay-s4/, parent = full run)
    → replay S5   (source_run=replay-s4)   (replay-s5/, parent = replay-s4)
      → replay S6 (source_run=replay-s5)   (replay-s6/, parent = replay-s5)
        → replay S7 (source_run=replay-s6) (replay-s7/, parent = replay-s6)
```

When S7 is replayed from `replay-s6`, its chain is
`[replay-s7, replay-s6, replay-s5, replay-s4, full run]`. Resolving S7's
declared dependency on S6: the closest directory containing an S6
execution is `replay-s6` itself — so S7 consumes the *replayed* S6, not
the original full-run S6, even though the original is also present further
up the chain. This matters because the replayed S6 is what actually
reflects whatever code/prompt change motivated replaying S4→S5→S6 in the
first place; silently falling back to the stale original S6 would defeat
the entire point of the chain. This exact scenario is proven by test
(`tests/patch/test_replay_engine_s4_s8.py`,
`TestChainedReplay.test_full_chain_consumes_newest_at_each_hop`), including
a companion negative test
(`test_resolver_does_not_fall_back_to_stale_full_run_execution`) proving
the opposite case: replaying S6 *directly* from the original full run
(with S5 never replayed) correctly consumes the full run's own S5, not any
replay — resolution is content-driven, never "just pick the nearest
directory regardless of what it actually contains."

A dependency S7 does **not** declare (e.g. S4, several hops up) is
correctly inherited from the original full run even in this same chain —
confirming that one execution's `consumed` dict can legitimately reference
several different directories in the same lineage simultaneously, each the
correct closest-resolved source for that specific dependency.

## Replay architecture

```
        stage_registry.py                    lineage.py
     (WHAT each canonical stage is:      (manifest model + closest-
      dependencies, capabilities,         ancestor-wins dependency
      owned LLM tags — static)            resolution — reused by both
              │                            production recording reads
              │ read by                    and replay)
              ▼                                  │
        replay_engine.py  ◄───────────────────────┘
     (WHICH stages are replayable TODAY,
      and how — REPLAY_HANDLERS dict)
              │
              │ reuses helpers from
              ▼
        stage_replay.py
     (Phase-1 predecessor module — SourceProvenance,
      resolve_source_provenance, validate_target_repository,
      output-dir safety check; its own top-level
      replay_test_plan_discovery() is superseded and no
      longer called by run_stage.py)
```

- **Generic replay engine.** `replay_engine.replay_stage(*, source_run,
  stage_name, output_dir, repo_root_override=None)` is the single entry
  point. It: (1) checks `stage_name` is a known canonical stage, (2) checks
  it has a `REPLAY_HANDLERS` entry, (3) validates `output_dir` is not
  nested in/around `source_run`, (4) builds the lineage chain and resolves
  every declared dependency via `lineage.resolve_effective`, failing
  closed if any is unresolved, (5) resolves source provenance and runs
  capability-aware preflight (repo identity/clean-state if
  `requires_repo_access`, Docker readiness if `requires_docker`, LLM
  config if `requires_llm_provider` — each gated on the stage's own
  declared flags, never run unconditionally), (6) invokes the registered
  `run_fn` — the only step allowed to make an LLM/external call, (7)
  cross-checks any captured LLM calls against `STAGE_OWNED_LLM_TAGS` (an
  ownership violation aborts before any manifest is written), and (8)
  builds and writes a new replay manifest.
- **Replay handlers.** `REPLAY_HANDLERS` (`replay_engine.py`) is a plain
  dict literal, `{canonical_stage: ReplayHandler(run_fn, dependencies)}`.
  A handler's `dependencies` must be a subset of that stage's approved
  `stage_registry.STAGE_DEPENDENCIES` — validated at import time,
  never a superset. Each `run_fn` is a thin adapter: reconstruct upstream
  artifacts into typed objects (`from_jsonable`), call the *same*
  production stage implementation, write the stage's own artifact. A
  `run_fn` never touches manifests or lineage itself — that stays the
  engine's job.
- **Stage registry.** `stage_registry.py` never changes based on what's
  replayable — it answers "what is stage X" once, permanently.
  Importing `replay_engine` has zero effect on `stage_registry.STAGE_SPECS`.
- **Dependencies.** Declared twice, deliberately: `stage_registry.py`'s
  graph is the stage's full, final, approved contract; a `ReplayHandler`'s
  `dependencies` may be a narrower, honestly-declared subset if that
  stage's replay implementation is transitional (today: only
  `test_analysis_and_plan`, whose handler declares no dependencies even
  though its final contract needs S6 and S9 — because neither is
  reconstructable as a replay input yet).
- **Shared run functions.** See
  [Shared production/replay architecture](#shared-productionreplay-architecture)
  above — this is the core mechanism, not a detail.
- **Source run / output replay run.** `source_run` is any prior full run or
  replay's output directory. `output_dir` is a fresh, isolated directory
  for the new replay's own artifacts — validated to not overlap
  `source_run`, and always ends up containing exactly one new execution
  (`sequence == 1`).
- **`replay_of`.** Set to the closest prior execution of the same
  canonical stage found anywhere in the source lineage
  (`lineage.find_latest_execution_identity`) — a heuristic "what am I
  probably redoing" pointer, honest and never fabricated, but explicitly
  **not** a data dependency: it plays no role in `resolve_effective`'s
  staleness logic.
- **Chained replay.** See [Provenance and lineage](#provenance-and-lineage)
  above.

### Which stages are replayable today

`replay_engine.REPLAY_HANDLERS` currently registers **12 of the 13
canonical stages** — every one except `trust_signals_and_recommendation`:

```
repository_analysis_and_remediation_planning   (S1)
remediation_strategy                            (S2)
guided_context_acquisition                      (S3)
patch_generation_and_post_patch_investigation   (S4)
challenger                                      (S5)
patch_repair_and_calibration                    (S6)
patch_review                                    (S7)
confidence_scoring                              (S8)
impact_and_behavior_analysis                    (S9)
test_analysis_and_plan                          (S10)
existing_test_comparison                        (S11)
report_generation                               (S13 — also covers S12's logic, see below)
```

`trust_signals_and_recommendation` (S12) has no entry and cannot be
replayed on its own — attempting it fails with a "registered but not
replayable yet" `ReplayEngineError`, before any I/O. Its logic is only
ever exercised as part of replaying `report_generation`, which
reconstructs a full `PipelineResult` from every other stage's persisted
artifact and calls the real, unmodified `_build_report()` — see
[Terminal reporting architecture](#terminal-reporting-architecture).

`test_analysis_and_plan`'s handler is explicitly transitional: it declares
no dependencies (narrower than its approved `(S6, S9)` contract) and
computes only the `TestExecutionPlan` sub-artifact, tagged
`"transitional": true` in its manifest entry. This is a statement about
*this one handler*, not about S6/S9's own replayability — S6
(`patch_repair_and_calibration`) and S9 (`impact_and_behavior_analysis`)
each have their own working replay handler (see
[Which stages are replayable today](#which-stages-are-replayable-today)).
`test_analysis_and_plan`'s handler was simply never wired to reconstruct
either of their persisted artifacts as its own inputs — its `run_fn` calls
`discover_test_plan(repo_root, llm)` directly and reads nothing from S6 or
S9 at all, which is why it can declare a dependency set narrower than its
approved final contract without misrepresenting anything it consumed.

## Full run, traced run, and replay compared

Four distinct ways to execute some or all of the pipeline exist today.
They are not variations on a theme with subtly different behavior — each
is a different orchestration layer around the *same* stage
implementations (see
[Shared production/replay architecture](#shared-productionreplay-architecture)),
producing different artifacts:

| Mode | How it's invoked | What it executes | Execution recording? | Artifacts produced |
|---|---|---|---|---|
| **Full production run** | `openant patch` (Go CLI → Python subprocess → `core.patch.run_patch`/`run_patch_cve` → `pipeline.run()`) | The pipeline's full 13-canonical-stage *architecture*, in production's real runtime order (see [Canonical order vs. runtime order](#canonical-order-vs-runtime-order)) — not necessarily 13 independent executions: S2/S3/S6's repair path are conditional, S10/S11 execute only when `compare_existing_tests=True`, and S12/S13 are computed together inside `_build_report()`, never as two separately invoked stages | **No** — `execution_recorder` is never passed; no `StageExecution` records exist | `patch/{label}-vulnerability.md`, `patch/{label}-trust-report.md`, investigation JSON (pre- and post-patch) |
| **Full traced run** | `tools/run_traced.py` (in-process, calls the same `core.patch` functions) | The same run as above, with an `ExecutionRecorder` and `LLMCallCapture` wired in | **Yes** — one v3 `run_manifest.json`, `kind: "full_run"`, `parent: null`, with one `executions` entry per canonical stage that actually ran **and** is currently instrumented (today: a subset of S1-S11, depending on which conditional paths fired — S12/S13 are never separately recorded, in production or when traced, since they aren't separately executed; see [Terminal reporting architecture](#terminal-reporting-architecture)) | Everything the production run produces, **plus** `trace/`: per-call prompt/response files, `checkpoints.jsonl`, `run_manifest.json`, `executions/*.json` |
| **Single-stage replay** | `tools/run_stage.py --source-run <dir> --stage <name> --output <dir>` | Exactly ONE canonical stage's *current* implementation, with every declared dependency resolved from `<dir>`'s lineage (see [Effective dependency resolution](#effective-dependency-resolution)) | **Yes** — one v3 `run_manifest.json`, `kind: "replay"`, `parent: <source_run>`, exactly one `executions` entry | An isolated `--output` directory only: that stage's own `run_manifest.json`, its own prompt/response files (if the stage makes LLM calls), and its own artifact file |
| **Chained replay** | Multiple `run_stage.py` invocations, each `--source-run` pointing at the *previous* invocation's `--output` | Same as single-stage replay, repeated — each hop's dependency resolution walks the *entire* lineage back to the original full run, not just its immediate source | **Yes**, once per hop | One isolated output directory per hop, each `parent`-linked to the one before it, forming a chain `build_chain()` can walk back to the root full run |

A full production run and a full traced run execute identically from the
pipeline's own point of view — tracing adds an observer (the LLM call
capture and the execution recorder), it never changes what the pipeline
does. Neither one guarantees exactly 13 independent stage executions: the
**canonical stage count (13) describes the architecture**, not a promise
about how many distinct executions a given run actually produces — see
[Canonical order vs. runtime order](#canonical-order-vs-runtime-order) and
[Execution recording](#execution-recording) for the fuller explanation. A
replay — single-stage or chained — never re-executes the whole pipeline;
it always targets exactly one canonical stage per invocation.

## Artifacts and directory structure

### A normal traced run (`tools/run_traced.py`)

```
<output>/
  patch/
    <label>-vulnerability.md
    <label>-trust-report.md
    <label>-investigation/            # pre-patch and post-patch, written twice
      analyzer_output.json
      call_graph.json
      functions.json
      scan_result.json
      dataset.json
  trace/
    001_remediation_planning.prompt.txt
    001_remediation_planning.response.txt
    002_remediation_strategy.prompt.txt
    ...
    checkpoints.jsonl               # one JSON line per LLM call, call order
    run_manifest.json               # schema_version 3 — see Execution recording
    executions/
      001_repository_analysis_and_remediation_planning.json
      002_remediation_strategy.json
      ...                          # one file per recorded StageExecution
```

`reports/debug/*.json` (edit readiness, relocation telemetry, post-patch
recovery, context selection) land separately, relative to the process's
working directory — never inside `<output>/` — and are only referenced by
filename from `run_manifest.json`'s `autopatcher_debug_artifacts` list,
never copied.

### A replay run (`tools/run_stage.py`)

```
<output>/
  run_manifest.json          # kind: "replay", parent: "<source_run>"
  001_<canonical_stage>.prompt.txt      # only if the stage made an LLM call
  001_<canonical_stage>.response.txt
  <canonical_stage-specific artifact>.json   # e.g. test_execution_plan.json,
                                              # repository_analysis_and_remediation_planning.json,
                                              # report_generation.json
```

A replay directory always contains exactly one execution. Its `parent`
field points at whatever `--source-run` was passed — which may itself be a
prior replay directory, enabling chained replay (see
[Provenance and lineage](#provenance-and-lineage)).

See TRACING_AND_DEBUGGING.md for the exact current commands that produce
these directories and how to inspect them.

## Architectural invariants

Rules future changes must preserve:

1. **Production and replay must share stage implementations.** A replay
   handler's `run_fn` calls the same function `pipeline.run()` calls —
   never a parallel reimplementation. Enforced today by a test asserting
   function-object identity
   (`test_replay_engine_s4_s8.py::TestSharedImplementation`).
2. **Replay orchestration must not duplicate stage business logic.**
   `replay_engine.py` owns lineage/dependency/preflight/manifest concerns
   only. If a stage's logic needs to change, change the shared
   implementation (`pipeline._run_*` or the underlying module function) —
   never patch equivalent logic into a `run_fn`.
3. **Consumed execution provenance must be explicit.** Every execution's
   `consumed` dict must name the exact `{run, execution_id}` it read for
   each dependency — never left implicit, never inferred from
   `STAGE_DEPENDENCIES` after the fact. If a stage's production dataflow
   doesn't actually match its declared dependency graph (as with S10/S9
   today), `consumed` must record the truthful, narrower reality, not a
   fabricated forward reference.
4. **Dependency resolution must prefer the newest effective execution in
   the lineage** — closest-ancestor-wins, with an exact identity check
   against what that candidate itself consumed, never "just pick whatever
   is closest regardless of staleness," and never silently fall back to an
   older execution when a closer one exists but is stale.
5. **Persisted artifacts must be reconstructable into the types stage
   implementations expect.** `to_jsonable`/`from_jsonable` must round-trip
   every real stage-output shape (dataclasses, NamedTuples, arbitrarily
   nested) losslessly — a replay handler reconstructs a *typed* object, not
   a raw dict, so the shared implementation function's signature is
   satisfied exactly as production satisfies it. `to_jsonable` fails closed
   (raises) on any unsupported type rather than silently degrading via
   `str()`/`repr()`.
6. **Adding or reordering stages must not assume canonical stage number
   equals runtime sequence.** `CANONICAL_STAGE_ORDER` position is a stable
   identity/display ordering; a manifest execution's `sequence` is
   directory-local call-completion order. These are different axes today
   (see [Canonical order vs. runtime order](#canonical-order-vs-runtime-order))
   and must not be conflated when adding a new stage or changing when an
   existing one runs.
7. **A source run or replay directory is an immutable input to any
   subsequent replay.** Replaying a stage must never modify
   `--source-run` in any way — not its manifest, not any prompt/response
   file, not any prior execution's artifact. This is what makes a lineage
   chain safe to build on: every directory in it stays exactly what it was
   when it was written, no matter how many further replays are chained off
   it.
8. **Replay output must be isolated from its source.** A replay's
   `--output` directory must never be the same as, nested inside, or
   contain its `--source-run` — checked before any other replay work
   begins, so a misconfigured invocation fails closed rather than risking
   cross-contamination between a source and its own replay.
9. **Repository-access (and other capability) requirements stay
   capability-aware, never universally imposed.** Each canonical stage
   declares its own `requires_repo_access`/`requires_docker`/
   `requires_llm_provider` flags in `stage_registry.py`; replay preflight
   checks only what a given stage's own declared contract actually needs.
   A stage that never touches the repository or Docker must never be
   blocked by (or charged for) a check its contract doesn't require —
   this is why replaying `report_generation` never demands Docker, and
   why a stage like `challenger` or `patch_review` never demands a
   repository at all.
