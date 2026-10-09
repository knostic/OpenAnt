# Auto Patcher Architecture

This document describes how Auto Patcher works today, for a technical reader:
its components, pipeline stages, information flow, how evidence becomes a
recommendation, where LLM judgment is used and where deterministic checks
decide, the fail-closed boundaries, and the recording and replay tooling built
around the pipeline.

Related documents:

- [recommendation-policy.md](recommendation-policy.md): the Trust Signals and
  the recommendation decision in detail, and what they do and do not prove.
- [TRACING_AND_DEBUGGING.md](../../libs/openant-core/utilities/autopatcher/tools/TRACING_AND_DEBUGGING.md):
  commands for traced runs, manifests, and single-stage replay.
- [RUN_CVE_BATCH.md](../../libs/openant-core/utilities/autopatcher/tools/RUN_CVE_BATCH.md):
  the parallel real-CVE evaluation runner.

Code lives under `libs/openant-core/utilities/autopatcher/` unless stated
otherwise. Function names are cited so each statement can be checked; if this
document and the code disagree, the code is authoritative.

## Contents

- [System overview](#system-overview)
- [Components](#components)
- [Pipeline stages](#pipeline-stages)
- [Stage details](#stage-details)
- [Canonical order vs. runtime order](#canonical-order-vs-runtime-order)
- [Trust and evidence flow](#trust-and-evidence-flow)
- [LLM judgment vs. deterministic checks](#llm-judgment-vs-deterministic-checks)
- [Fail-closed boundaries](#fail-closed-boundaries)
- [Context capacity](#context-capacity)
- [Recording, provenance, and replay](#recording-provenance-and-replay)
- [Evaluation-only tooling](#evaluation-only-tooling)
- [Architectural invariants](#architectural-invariants)

## System overview

```
openant patch  (Go CLI: apps/openant-cli/cmd/patch.go)
      │  flag validation, active-project defaults; no LLM or patch logic
      ▼
python -m openant patch  (libs/openant-core/openant/cli.py: cmd_patch)
      │  verbosity, deprecated-flag notice, JSON result envelope
      ▼
core/patch.py: run_patch()  /  run_patch_cve()
      │  Finding eligibility or NVD fetch → vulnerability text
      │  LLM-config preflight, run header, writes <output>/patch/ artifacts
      ▼
utilities/autopatcher/pipeline.py: run()
      │  13 canonical stages (S1–S13), see below
      ▼
pipeline._build_report()  →  Trust Report Markdown  (+ Run Metadata from core/patch.py)

tools/run_traced.py  ── calls the same core/patch.py functions in-process, with an
                        ExecutionRecorder and LLM-call capture attached
tools/run_stage.py   ── replays one canonical stage from a recorded run
tools/run_cve_batch.py ── runs run_traced.py for many historical CVEs in parallel
```

A normal `openant patch` run writes only `<output>/patch/` (two Markdown
files and the repository-parse artifacts) and `<output>/patch.report.json`
(OpenAnt's step report). Tracing adds observers; it does not change what the
pipeline does.

## Components

| Component | Responsibility |
|---|---|
| `apps/openant-cli/cmd/patch.go` | Go transport. Validates `--finding-id`/`--cve` (exactly one; CVE id format), resolves defaults from the active project, forwards flags to Python, prints the result or errors, and exits with the Python exit code. |
| `openant/cli.py` (`cmd_patch`) | Python CLI. Configures progress verbosity, prints the deprecation notice for the context-budget flags, builds a `ContextBudgetController`, calls `core.patch`, and emits the JSON envelope (exit 0 on success, 2 on failure). |
| `core/patch.py` | Turns a Finding (after the `PATCH_ELIGIBLE` verdict check) or an NVD CVE record into `(vulnerability_text, repo_root)`. Checks LLM configuration (and Docker, when test comparison is requested) before any repository work. Writes `{id}-vulnerability.md`, runs the pipeline, and writes `{id}-trust-report.md` with a Run Metadata section appended. |
| `pipeline.py` | Orchestrates the stages (`run()`), applies the deterministic gates, and renders the report (`_build_report`, `_compute_trust_signals`, `_build_recommendation_v1`). |
| `repo_locator.py`, `candidate_selection.py`, `candidate_enrichment.py`, `evidence_fusion.py`, `vulnerability_patterns.py` | Deterministic repository grounding and Repository Understanding: locate candidate code, parse the repository with OpenAnt's parsers, compute call-graph/reachability facts, and render them. |
| `remediation_planner.py` | Planner and Strategy prompts, deterministic evidence acquisition and verification, the Final-Target Remediation Slice, the Edit Readiness Gate, guided acquisition, Patch Target Conformance, and Post-Patch Recovery. |
| `remediation_verifier.py` | The Planner Claim Verifier (one bounded LLM check of the Planner's narrower-alternative claim). |
| `patch_generator.py` | Patch Generation prompt, response-contract classification, and context fitting for Patch Generation's capacity. |
| `generated_patch_processing.py`, `diff_hunk_repair.py`, `patch_hygiene.py`, `patch_applicability.py` | Shared deterministic handling of every generated diff: hunk-header repair and relocation, context reconstruction, hygiene, `git apply --check`. |
| `post_patch_investigation.py`, `post_patch_evaluation.py`, `patch_workspace.py` | Anchors derived before patching, re-evaluated against a temporary patched copy of the repository. |
| `patch_challenger.py` | The adversarial Challenger call, structured-concern parsing, citation validation, and deterministic verdict derivation. |
| `finding_calibration.py` | Calibration of free-text Challenger findings (Observed / Hypothesis / Hardening, remediation impact). |
| `patch_reviewer.py`, `confidence_scorer.py` | Narrative review (rendered) and a confidence score (computed, not used). |
| `impact_surface.py`, `behavior_summary.py`, `testing_support.py`, `source_verification.py`, `language_support.py` | Deterministic evidence: blast radius (Python only), diff-only behavior summary, test discovery (Python only), hunk source verification, language detection. |
| `existing_test_regression.py`, `test_plan_discovery.py`, `test_plan_validation.py`, `test_executors.py`, `existing_test_amendment.py` | Opt-in Existing Test Comparison in Docker, plus the bounded test-amendment step. |
| `technical_capacity.py`, `context_budget.py` | Per-call source-evidence capacity (see [Context capacity](#context-capacity)). |
| `llm_client.py` | Provider/model resolution from OpenAnt's `analyze` phase binding (or `LLM_PROVIDER=mock`), shared adapters, usage tracking, per-stage call metadata. |
| `progress.py` | Terminal output for the five user-facing phases (default / verbose / quiet). |
| `run_metadata.py` | The Run Metadata report section and CVE-input disclosure. |
| `stage_registry.py`, `execution_recorder.py`, `lineage.py`, `replay_engine.py`, `stage_replay.py`, `llm_call_tracing.py` | Canonical stage identities, opt-in execution recording, manifests and lineage, and single-stage replay. |

## Pipeline stages

`stage_registry.CANONICAL_STAGE_ORDER` defines 13 canonical stages. It is the
single source of truth for stage names, declared dependencies, capability
flags, and which LLM `stage=` tags each stage may emit
(`STAGE_OWNED_LLM_TAGS`). The terminal shows five phases
(`progress.stage(n, 5, …)`).

| # | Canonical stage | Phase | LLM tags it may emit | When it does work |
|---|---|---|---|---|
| S1 | `repository_analysis_and_remediation_planning` | Analyze | `remediation_planning`, `remediation_planning_reattempt`, `remediation_plan_verification`, `remediation_plan_revision`, `remediation_plan_reverification` | always |
| S2 | `remediation_strategy` | Analyze | `remediation_strategy` | when S1 produced verified planner evidence |
| S3 | `guided_context_acquisition` | Prepare | `guided_context_request` | when Strategy produced a result (LLM call only if deterministic acquisition left edits unready) |
| S4 | `patch_generation_and_post_patch_investigation` | Generate | `patch_generation`, `patch_generation_contract_retry` | always (generation is skipped when a gate fired) |
| S5 | `challenger` | Validate | `challenger` | when a candidate patch exists |
| S6 | `patch_repair_and_calibration` | Validate | `finding_calibration`, `challenger`, `patch_repair_regeneration` | always (LLM calls only when there are findings) |
| S7 | `patch_review` | Validate | `patch_review` | when a candidate patch exists |
| S8 | `confidence_scoring` | Validate | `confidence_scorer` | when a candidate patch exists |
| S9 | `impact_and_behavior_analysis` | Validate | none | always |
| S10 | `test_analysis_and_plan` | Validate | `test_plan_discovery`, `test_plan_discovery_contract_retry` | only with `compare_existing_tests` |
| S11 | `existing_test_comparison` | Validate | `test_failure_distillation`, `existing_test_amendment` | only with `compare_existing_tests` |
| S12 | `trust_signals_and_recommendation` | Decide | none | always (inside `_build_report`) |
| S13 | `report_generation` | Decide | none | always (inside `_build_report`) |

The `challenger` tag is owned by both S5 and S6, because the S6 repair loop
re-challenges a regenerated patch. This is listed in `KNOWN_AMBIGUOUS_LLM_TAGS`.
Every Auto Patcher LLM call uses the same provider and model.

## Stage details

### S1 — `repository_analysis_and_remediation_planning`

Executor: `pipeline._run_repository_analysis_and_remediation_planning`.

1. **Repository grounding** (`repo_locator.ground_repository`, deterministic):
   finds code relevant to the vulnerability text, sized to the Planner call's
   technical capacity. With no repository root, or nothing found, the run
   continues on a best-effort basis with a warning.
2. **Repository Understanding** (deterministic): candidate selection; one
   parse of the repository with OpenAnt's parsers
   (`candidate_enrichment.build_investigation_context`, artifacts in
   `<output>/patch/{id}-investigation/`); per-candidate call-graph and
   reachability enrichment; fusion and rendering (`evidence_fusion`). Pre-patch
   anchors are derived for Post-Patch Investigation
   (`post_patch_investigation.derive_pre_patch_anchors`). If parsing fails,
   enrichment degrades to file/test/sink facts.
3. **Planning** (`remediation_planner.run_planning_evidence_acquisition`): the
   Planner proposes a remediation. If it explicitly reports that it needs more
   evidence, its requests (at most 3 per round) are resolved deterministically
   against the repository and it is called again with the added evidence, up
   to 5 attempts in total. A plan that never reaches a grounded state stops
   generation later (`_planning_forced_skip`). The plan's own target files and
   symbols are verified against the repository
   (`build_planner_evidence_with_budget`). That verified evidence, not the
   Planner's prose, is what later stages trust.
4. **Planner Claim Verifier** (`_run_planner_claim_verification` →
   `remediation_verifier.verify_planner_claim`): this runs only when the
   Planner reports a narrower alternative it rejected or selected. One
   verification call checks the rejection reason (mode `REJECTED`) or the
   coherence of the selected alternative (mode `SELECTED`) against the verified
   evidence. A `CONTRADICTED` result allows exactly one Planner revision and
   one re-verification. A contradiction that is not cleared stops generation
   (`_verifier_forced_skip`). An infrastructure failure degrades to
   `UNRESOLVED` and never consumes the revision. When an independently
   verified `SELECTED` decision applies (and the plan is not a post-revision
   "v2"), the verified Planner semantics replace Strategy's mechanism prose in
   the Patch Generation context. Target authority always stays with Strategy.

Planning failures other than `ModelUnavailableError` are best-effort: the run
continues without a plan, with a warning. A hand-authored-plan hook
(`_load_experiment_plan`, reading `utilities/evaluation/phase_e/<GHSA>.md`) is
a research leftover. That directory is not shipped, so the hook has no effect.

### S2 — `remediation_strategy`

`remediation_planner.generate_remediation_strategy` makes a second, distinct
call over S1's verified evidence. Before the call, that evidence is re-rendered
narrower if the combined prompt would exceed the call's capacity. The call
produces the Final Remediation Strategy: verified `target_files` and
`target_symbols`, a `security_invariant`, required edits, and two structured
self-reports, `insufficient_evidence` and `target_authority_unresolved`.
Targets the model names that cannot be verified in the repository are dropped
and reported as warnings. The call is skipped (no LLM call) when S1 produced no
verified evidence.

**Evidence-gap fallback** (`_run_evidence_gap_strategy_fallback`, at most once).
This runs when Strategy either named no target while reporting insufficient
evidence, or named a target while reporting `target_authority_unresolved`.
Evidence is re-acquired deterministically around the relevant seed: the
Planner's candidates in the first case, Strategy's own target in the second.
Strategy then runs once more, and that second result becomes authoritative.
There is no third attempt. If the merged evidence would exceed capacity, the
fallback stops without a second call.

### S3 — `guided_context_acquisition`

Executor: `pipeline._run_guided_context_acquisition`. How it proceeds depends
on what Strategy produced:

- **A target with resolved authority:** steps 1–3 below run.
- **A target with `target_authority_unresolved`, or no verified target:**
  `_skip_patch_generation` is set (NO PATCH PRODUCED).
- **No Strategy result at all** (S1 had no verified evidence to give it, or
  the call failed): this stage does nothing. Unless S1 itself withheld
  generation, Patch Generation then runs on the remaining context, without the
  Final-Target Slice, the Edit Readiness Gate, or the Patch Target
  Conformance Gate. This can happen, for example, after a planning LLM failure,
  which is best-effort.

1. **Final-Target Remediation Slice** (`build_final_target_slice`): the exact
   repository source of Strategy's verified targets, built deterministically.
2. **Edit Readiness Gate** (`check_edit_readiness`): checks that every intended
   edit has verified, patch-ready source.
3. If it is not ready:
   - bounded **deterministic acquisition** (`run_deterministic_acquisition`):
     2 rounds, 2 edits per round, 5,000 new characters per round;
   - then bounded **guided acquisition** (`run_guided_acquisition`): at most 2
     `guided_context_request` LLM calls asking which source to fetch, with the
     answers resolved deterministically and limited to 5,000 characters per
     round;
   - then a target-file fallback.

If readiness is still incomplete, `_skip_patch_generation` is set.

Afterwards, `run()` assembles the Patch Generation context from labeled
sections: grounding, vulnerability patterns, Repository Understanding, the
Planner's plan and verified evidence, verified semantics, Strategy, the
Final-Target Slice, and a coverage warning. It fits them to Patch Generation's
capacity, whole sections only, with the Final-Target Slice reserved first
(`patch_generator.fit_patch_generation_context`). If that required slice does
not fit, generation is skipped with reason `technical_capacity`.

### S4 — `patch_generation_and_post_patch_investigation`

Executor: `pipeline._run_patch_generation_and_investigation`.

1. **Generation** (`_generate_patch_with_contract_check`): one call. A response
   that violates the output contract (several diffs, or surrounding prose)
   gets one retry with a contract reminder. A retry that is still invalid
   yields an empty patch.
2. **Patch Target Conformance Gate** (`check_patch_target_conformance`, only
   when S3 produced an Edit Readiness result): the diff must edit only, and
   match, the approved target files. On failure,
   **Post-Patch Recovery** (`recover_post_patch_source`) acquires source for
   the files involved and allows one regeneration. If recovery is insufficient,
   or the regenerated patch still does not conform, the patch is withdrawn
   (empty patch).
3. **Diff processing** (`generated_patch_processing.process_generated_patch`):
   hunk-header repair and content relocation, context reconstruction, hygiene,
   and `git apply --check`. Every `+`/`-` line is preserved.
4. **Applicability-aware retry**: if the patch does not apply and the failing
   file is known, one regeneration with the `git apply` error as a hint. The
   retry is rejected if it modifies a file other than the failing target.
5. **Post-Patch Investigation**: anchors from Repository Understanding and from
   the diff itself (`derive_patch_touched_anchors`) are re-evaluated
   (`evaluate_anchors`) on a temporary patched copy (`patch_workspace`). The
   results, and the post-change source of the changed functions, are appended
   to the Challenger's context as far as they fit.

The repository itself is never written. `git apply --check` is read-only, and
patching happens only inside temporary copies.

### S5 — `challenger`

`patch_challenger.challenge_patch` makes the adversarial call. It sees the
vulnerability report, the patch, the Patch Generation context (or the recovery
context if a regeneration was accepted), and the Post-Patch Investigation
output. Its citations are validated only against the
**repository-derived** sections it was actually shown
(`_challenger_provenance_context`): grounding, Repository Understanding,
verified planner evidence, the Final-Target Slice, recovered source, and
Post-Patch Investigation. Planner and Strategy narrative is excluded. With the
current structured `Concerns:` output, the verdict (`VERIFIED_FIXED`,
`RESIDUAL_VULNERABILITY` or `INSUFFICIENT_EVIDENCE`) is derived
deterministically from the citation-checked facts. See
[recommendation-policy.md](recommendation-policy.md#the-challenger-adversarial-review).
This stage is skipped when there is no candidate patch.

### S6 — `patch_repair_and_calibration`

Executor: `pipeline._run_patch_repair_and_calibration`.

- **Classification:** `_classify_challenger` sorts free-text findings into five
  lexical categories and counts them.
- **Repair path:** this applies only when a `confirmed_defect` or
  `behavioral_defect` finding exists.
  - Calibration v1 runs over every free-text finding.
  - `should_auto_repair` authorizes one repair only if the patch applies and at
    least one such finding is calibrated `observed`.
  - The repair regenerates with a hint (`patch_repair_regeneration`), re-runs
    diff processing (without context reconstruction), re-challenges, and
    re-calibrates.
  - `accept_repair` accepts the repaired patch only if it applies, it does not
    turn a not-vulnerable verdict into a vulnerable one, and every remaining
    repair-eligible finding is calibrated outside `observed`.

  The repair path is a narrower contract than S4: there is no contract retry,
  conformance gate, applicability retry or Post-Patch Investigation. If the
  repair is accepted, the report shows "Not shown" for Post-Patch
  Investigation, because that evidence described the replaced patch.
- **Fallback calibration:** when the repair path did not run, calibration runs
  once over the non-`confirmed_defect` findings, if there are any. With today's
  structured Challenger output there are usually no free-text findings, so this
  makes no call.
- **Calibration evidence acquisition:** every calibration call site can make
  one bounded rerun with deterministically resolved evidence that calibration
  marked `proof_required` and actionable
  (`_calibrate_findings_with_evidence_acquisition`).

After S6, the source-verification signal is computed from the final patch's
hunk relocation records (`source_verification.classify_source_verification`).

### S10/S11 — Existing Test Comparison (opt-in)

These stages run only when `compare_existing_tests=True`
(`--compare-existing-tests` on the Python CLI or `tools/run_traced.py`; the Go
CLI does not expose it). The whole run aborts first if Docker is not ready.

- **S10** (`existing_test_regression.discover_test_plan_for_comparison`): runs
  a Docker preflight, gathers deterministic test evidence (configuration
  files, CI snippets, README, directory listing), then makes one
  `test_plan_discovery` call, with one contract retry, to propose how to run
  the existing tests. `test_plan_validation` checks the proposal
  deterministically. Python, Node and Go runtimes are supported.
- **S11** (`existing_test_amendment.evaluate_existing_test_comparison_with_amendment`):
  runs the plan in Docker against an unpatched copy and a patched copy. It
  never falls back to running tests on the host. The result is PASS,
  NEW_FAILURES_DETECTED, PRE_EXISTING_FAILURES_ONLY, TEST_EXECUTION_ERROR, or
  NOT_VERIFIED. Two LLM calls are possible:
  - `test_failure_distillation`: when new failures exist but no per-test
    identity could be extracted deterministically.
  - `existing_test_amendment`: when newly failing tests resolve to real
    test files and Strategy produced a `security_invariant`. One call may
    propose a diff touching only those test files, and only to resolve a
    direct contradiction with the patch's stated intent. The proposal is
    scope-checked before and after diff processing and composed with the
    unchanged production patch. The combined patch must pass
    `git apply --check`, and then the comparison reruns. If accepted, the
    combined patch becomes the reported patch, and S7–S9 see it. The hygiene
    and applicability results shown for the patch are still those of the
    production-only patch.

Its Trust Signal is display-only. It never feeds back into the Challenger or
the repair loop.

### S7 — `patch_review` and S8 — `confidence_scoring`

`patch_reviewer.review_patch` receives the vulnerability report, the final
patch, and a summary of Finding Calibration. It receives no repository
evidence. Its Explanation, Affected areas and Reviewer Notes are rendered and
labeled as model analysis.

`confidence_scorer.score_confidence` additionally receives the review and the
Challenger's context. Its score is discounted by the Challenger result
(`_adjust_confidence_score_for_challenger`) and then never used by the policy
or the report.

Both stages are skipped when there is no candidate patch. A failed LLM call in
either one fails the run.

### S9 — `impact_and_behavior_analysis`

Executor: `pipeline._run_impact_and_behavior_analysis`. Deterministic, no LLM.

- `impact_surface.LightweightImpactAnalyzer` produces an AST-based usage and
  blast-radius level. It covers Python only; other languages get
  `not_applicable`.
- `behavior_summary.BehaviorAnalyzer` produces a diff-only behavior summary,
  which feeds the Validation Actions.

Both are best-effort. This stage always runs, even with no patch.

### S12/S13 — trust signals, recommendation, report

These run together in `_build_report`, which is called once at the end of
`run()`:

1. reclassify the final Challenger result;
2. reconcile it with calibration (`_reconcile_verification_status_with_calibration`);
3. compute the calibration-aware defect count (`_build_known_findings`);
4. compute the Trust Signals (`_compute_trust_signals`, plus
   `source_verification` and `existing_test_comparison`);
5. decide (`_build_recommendation_v1`);
6. add caveats and render the report.

When the final patch is empty, the computed decision is discarded and the
report shows NO PATCH PRODUCED. `core/patch.py` appends Run Metadata. See
[recommendation-policy.md](recommendation-policy.md).

## Canonical order vs. runtime order

The canonical numbering is an identity and dependency ordering, not the
runtime trace. `pipeline.run()` actually executes:

```
S1 → S2 (+ evidence-gap fallback) → S3 → context assembly/capacity fit → S4 → S5 → S6
   → source verification → [S10 → S11 (+ amendment), only with compare_existing_tests]
   → S7 → S8 → S9 → PipelineResult → _build_report (S12 + S13)
```

- S10/S11 run before S7–S9. S10 declares a dependency on S9 in
  `STAGE_DEPENDENCIES`, but S9 has not run yet at that point, so a recorded S10
  execution's `consumed` lists only S6. This is a known registry/runtime
  mismatch.
- An accepted test amendment makes S11 the source of the patch that S7–S9 read.
  Their recorded `consumed` lists then include S11, although
  `STAGE_DEPENDENCIES` deliberately does not, to avoid a cycle.
- The S6 repair loop's regeneration and re-challenge are not separate S4/S5
  executions.
- S12 and S13 are never separately invoked or recorded.

To learn what actually happened in a run, read a traced run's
`run_manifest.json` (`executions`, ordered by `sequence`), never
`CANONICAL_STAGE_ORDER`.

## Trust and evidence flow

```
repository ──► grounding / Repository Understanding (deterministic) ──┐
                                                                       ▼
vulnerability text ──► Planner (LLM) ──► verified planner evidence (deterministic)
                           │                    │
                 Claim Verifier (LLM)            ▼
                                       Strategy (LLM) ──► verified targets (deterministic)
                                                                │
                              Final-Target Slice + Edit Readiness (deterministic)
                                                                │
                                                 Patch Generation (LLM)
                                                                │
       conformance gate, hunk repair, hygiene, git apply --check, Post-Patch Investigation
                                          (deterministic)       │
                                                                ▼
                     Challenger (LLM facts) ──► citation check + verdict (deterministic)
                                                                │
                     Finding Calibration (LLM) ──► repair gate / reconciliation (deterministic)
                                                                │
                                   Trust Signals + Recommendation Policy (deterministic)
```

The evidence rules:

- **Verified evidence over prose.** Planner and Strategy targets count only
  after they have been resolved against the repository. A model's claim that a
  file or symbol exists grants nothing by itself.
- **Citation authority is repository-derived.** The Challenger's facts count
  only when quoted from content it was shown that came from the repository, the
  diff, or (for scope) the vulnerability report.
- **Model verdicts are not authoritative.** The Challenger's own "Verification
  status" line, the confidence score, and the reviewer's narrative never decide
  the outcome.
- **Calibration can only add caution to the verdict.** It can narrow
  `VERIFIED_FIXED`, discount a lexical `confirmed_defect`, or block a repair.
  It never clears a blocking or unresolved verdict.

## LLM judgment vs. deterministic checks

| LLM judgment | Deterministic checks and decisions |
|---|---|
| Planning, including which evidence to request | Repository grounding, parsing, reachability, evidence resolution |
| Planner Claim Verifier | Verified-evidence rendering; the plan-authority split |
| Strategy (targets, mechanism, security invariant) | Target verification; Edit Readiness; capacity fitting |
| Guided context requests (which source to fetch) | Resolution and size bounds of fetched source |
| Patch Generation, contract retry, recovery and repair regeneration | Contract classification, conformance, hunk repair, hygiene, `git apply --check`, retry acceptance |
| Challenger concern facts | Citation validation, per-concern consequence, run-level verdict, lexical classification |
| Finding Calibration (group, remediation impact, evidence requests) | Repair authorization and acceptance, defect count, verdict reconciliation |
| Patch Review and Confidence Score (not used by the policy) | Impact Surface, test discovery, source verification, Post-Patch Investigation |
| Test plan discovery, failure distillation, test amendment (opt-in) | Test-plan validation, Docker execution, before/after comparison, amendment scope checks |
| — | Trust Signals, the Recommendation Policy, report rendering |

Deterministic code verifies the structure of LLM output and the provenance of
its citations. It does not verify that the model's reasoning is sound.

## Fail-closed boundaries

**The run fails** (exit 2, no Trust Report) when:

- the LLM configuration cannot be resolved, or `LLM_PROVIDER`/`LLM_MODEL` names
  a real provider or model (`llm_client.ensure_provider_configured`, checked
  before any repository work);
- a configured model is rejected by the provider (`ModelUnavailableError`;
  there is never a fallback to another model);
- the finding's verdict is not in `PATCH_ELIGIBLE`, or the finding id is
  unknown;
- `--repo-root` does not exist (CVE mode), or the NVD fetch fails;
- `--compare-existing-tests` was requested and Docker is not ready;
- an LLM call fails in a stage that is not best-effort: Patch Generation,
  Challenger, Patch Review, or Confidence Scoring.

Any stale trust report for the same id is deleted before the run starts, so a
failed run never leaves an earlier report looking current.

**Generation is withheld** (the run completes with NO PATCH PRODUCED) when:

- Planning never reached a grounded state;
- a Planner Claim Verifier contradiction survived the one revision;
- Strategy named no verified target, or reported `target_authority_unresolved`
  after the fallback;
- the Edit Readiness Gate still has unready edits after all acquisition;
- the required Final-Target Slice does not fit Patch Generation's capacity;
- the generator's output is still invalid after the contract retry;
- the patch does not conform to the approved targets and recovery or
  regeneration could not fix it.

**The verdict is withheld** (Manual Review Required) when:

- the structured Challenger response does not have exactly one primary
  concern, or it also contains free-form prose;
- a cited fact cannot be found in the repository-derived context;
- a fact is missing or invalid;
- calibration leaves a proof-blocking dependency unresolved.

**Repair is withheld** unless a repair-eligible finding is calibrated
`observed`. A repaired patch is rejected if it does not apply, if it raises
the vulnerability verdict, or if any remaining repair-eligible finding is
calibrated `observed` or uncalibrated.

**Best-effort stages** print a warning and continue with less evidence:
grounding, Repository Understanding, planning, verification, strategy,
guided acquisition, conformance (if it raises), the applicability retry,
Post-Patch Investigation, calibration, repair, impact and behavior analysis,
and test comparison. Usually the later gates turn missing evidence into NO
PATCH PRODUCED or Manual Review Required. There is one exception. If planning
or Strategy produces no result at all, the Edit Readiness and target
conformance gates have nothing to check against, so generation proceeds on the
remaining repository context (see [S3](#s3--guided_context_acquisition)). The
Challenger, the deterministic patch checks and the Recommendation Policy
still apply to that patch.

## Context capacity

Every stage that embeds repository source in an LLM call bounds that source
with `technical_capacity.compute_source_capacity`:

```
source_capacity_chars = (context_window_tokens − reserved_output_tokens − 2,000) × 3 − known_overhead_chars
```

- `context_window_tokens` comes from `core.model_registry.context_window_tokens`
  when `config/models.json` records it for the active model. **No model records
  it today**, so every run uses `CONSERVATIVE_FALLBACK_CONTEXT_WINDOW_TOKENS =
  60,000`. The result records which source was used (`capacity_source`).
- `reserved_output_tokens` is `LLM_MAX_TOKENS`, which defaults to 4,096.
- `known_overhead_chars` is the exact length of the call's other prompt
  content: system prompt, vulnerability text, and already-rendered sections.

Stages that use it: grounding, planner evidence, Strategy, the Final-Target
Slice, Post-Patch Recovery, Patch Generation (including its retries), the
Post-Patch Investigation context, and calibration evidence.

Evidence is included or omitted as whole blocks, never truncated, and every
omission is recorded as `technical_capacity`.

`ContextBudgetController`, which `openant patch` and `run_traced.py` always
construct, caches one ceiling per stage per run and records usage for traces.
It is constructed without a provider or model, so the stages that read through
it (planner evidence, the Final-Target Slice, Post-Patch Recovery) always use
the fallback window. Today that gives the same number as the direct
`compute_source_capacity(*resolve_active_model(), …)` call sites, because the
registry is empty. `request_extension()` always returns `False`; there are no
budget windows. The CLI flags `--context-budget-policy` and
`--max-context-budget-windows` are accepted and ignored.

Independent fixed limits on exploration also apply:

| Constant | Value |
|---|---|
| `MAX_PLANNING_ATTEMPTS` | 5 |
| `MAX_EVIDENCE_REQUESTS_PER_ROUND` | 3 |
| `MAX_ACQUISITION_ROUNDS` | 2 |
| `MAX_UNREADY_EDITS_PER_ROUND` | 2 |
| `MAX_NEW_SOURCE_CHARS_PER_ROUND` | 5,000 |
| `MAX_GUIDED_ACQUISITION_ROUNDS` | 2 |
| `MAX_CONTEXT_REQUESTS_PER_ROUND` | 2 |
| `MAX_GUIDED_SOURCE_CHARS_PER_ROUND` | 5,000 |
| `MAX_POST_PATCH_RECOVERY_ROUNDS` | 1 |
| `MAX_RECOVERY_TARGETS` | 3 |
| `MAX_ADDITIONAL_PATCH_GENERATOR_CALLS` (recovery) | 1 |
| `MAX_CALIBRATION_ACQUISITION_ATTEMPTS` | 2 |
| `MAX_CALIBRATION_EVIDENCE_REQUESTS` | 3 |

These constants live in `remediation_planner.py` and `pipeline.py`. One more
fixed limit applies: a function target with no anchor inside it is rendered
whole only if it fits `_PER_TARGET_FULL_FUNCTION_CAP`, which is 3,333
characters (`FINAL_TARGET_SLICE_MAX_CHARS // 3`).

## Recording, provenance, and replay

Commands and walkthroughs are in
[TRACING_AND_DEBUGGING.md](../../libs/openant-core/utilities/autopatcher/tools/TRACING_AND_DEBUGGING.md).
This section describes the model behind them.

| Mode | Invocation | Records `StageExecution`s? | Output |
|---|---|---|---|
| Production run | `openant patch` → `core.patch` → `pipeline.run()` | No (`execution_recorder=None`) | `<output>/patch/…`, `<output>/patch.report.json` |
| Traced run | `tools/run_traced.py` → the same `core.patch` functions in-process | Yes: one v3 `run_manifest.json`, `kind: "full_run"` | `<output>/patch/…` plus `<output>/trace/` (or `--trace-dir`) |
| Single-stage replay | `tools/run_stage.py --source-run <dir> --stage <name> --output <dir>` | Yes: `kind: "replay"`, exactly one execution | an isolated output directory |
| Chained replay | Repeated `run_stage.py`, each `--source-run` pointing at the previous `--output` | Yes, once per hop | one directory per hop, `parent`-linked |

Tracing only adds observers. With a recorder or without one, the Trust
Report is byte-identical (`tests/patch/test_pipeline_execution_recording.py::TestRecorderNoneIsBehaviorPreserving`).

### Execution recording

`execution_recorder.ExecutionRecorder` is opt-in. Every call site in
`pipeline.run()` is guarded by `if execution_recorder is not None`, and only
`run_traced.py` constructs one.

**Which executions are recorded:**

- **S1–S9** are recorded on every completed traced run.
- **S10** and **S11** are recorded only when `compare_existing_tests` is on,
  a repository root exists, and the final patch is non-empty and applies.
- **S12/S13** are never recorded.
- The S6 repair loop's regeneration and re-challenge are not separate
  S4/S5 executions. They appear only inside S6's artifact
  (`repair_regeneration`, `repair_rechallenge`, `repair_outcome`,
  `authoritative_candidate`).

Executions are numbered in finish order, `NNN_<canonical_stage>`. S1–S6 are
`001`–`006`. If S10/S11 run, they are `007`/`008` and S7–S9 are
`009`–`011`; otherwise S7–S9 are `007`–`009`.

**Full-run manifest.** `run_traced.py` writes the manifest itself. It
contains:

- `schema_version: 3`, `kind`, `parent: null`;
- `target_repository {repo_root, repo_commit}`, `openant {patcher_commit}`,
  `llm {provider, model}`, `executions`;
- flat run fields: `status`, input and output paths, `compare_existing_tests`,
  the raw values of the deprecated budget flags, `llm_call_count`,
  `checkpoints_file`, `autopatcher_debug_artifacts`, and `blind_evaluation`
  in blind mode.

On failure, `status: "failed"`, `error_type` and `error_message` are written
together with the executions recorded so far. Readers accept schema v1/none,
v2 and v3 (`lineage.py`).

**`StageExecution` fields** (`lineage.new_execution_record`):

- `execution_id`, `canonical_stage`, `sequence`;
- `invocation_kind`: `initial` in full runs, `replay` in replays;
- `consumed`: `{dep: {run, execution_id}}` for every dependency actually
  read;
- `outcome`: a short, stage-defined string, never parsed by resolution;
- `replay_of`, and `invoked_by` (never set today);
- `artifact_path`, the execution's own JSON written by `to_jsonable`;
- `llm_calls`, the call log slice with pointers to the prompt and response
  files;
- `external_calls`, always `[]`;
- `timing`: `null` in full runs, set in replays;
- stage-specific extra keys, for example `canonical_contract_scope`,
  `transitional` and `replay_limitations`.

Full-run artifacts are written once, as
`trace/executions/<execution_id>.json`; `finish()` refuses to overwrite.
`to_jsonable` fails closed on unsupported types, and `from_jsonable`
rebuilds the dataclasses and NamedTuples that replay needs.

**LLM-ownership enforcement.** `ExecutionRecorder.finish()` checks every LLM
call captured inside a bracket against `STAGE_OWNED_LLM_TAGS` before writing
anything for that execution, and raises `ExecutionRecorderError` on a
mismatch. A call is never reassigned to another stage. The trace's
prompt and response files already exist at that point, because they are
written as each call happens.

**`consumed` is the actual dataflow.** It may differ from
`STAGE_DEPENDENCIES`:

- S10 lists only S6, because S9 has not run yet.
- S7, S8 and S9 add S11 when a test amendment was accepted.

### Provenance and lineage

`lineage.py` models a **manifest**, and a **lineage**: a chain of manifests
linked by `parent`.

- A full run has `parent: null`. A replay's `parent` is the exact
  `--source-run` string it was invoked with, which may itself be a replay.
- `lineage.build_chain(tip)` walks `parent` pointers to the root, tip first,
  and raises on a cycle.
- `consumed` stores exact `{run, execution_id}` identities, so one execution
  can consume dependencies from several directories in the same lineage.

### Effective dependency resolution

`lineage.resolve_effective(chain, stage, cache)` is closest-ancestor-wins,
with an exactness check:

1. Walk the chain tip first, and take each directory's latest execution of
   the stage.
2. The first directory that has one is the candidate. It is **RESOLVED** only
   if every dependency it recorded in `consumed` still resolves, recursively,
   to the same `{run, execution_id}`.
3. If not, the result is **STALE**. Resolution never falls back to an older
   execution. A stage that never ran anywhere in the lineage is
   **UNRESOLVED**.

Identities are compared as exact strings. A different spelling of the same
`--source-run` path can therefore make dependencies resolve STALE; use the
path exactly as it was recorded.

The resolution behavior is covered by tests:

- `TestChainedReplay.test_full_chain_consumes_newest_at_each_hop`
  (`tests/patch/test_replay_engine_s4_s8.py`): a chain from the full run
  through S5 → S6 → S7 → S8 consumes the newest replay at each hop, while S6's
  S4 dependency still resolves to the full run.
- `test_resolver_does_not_fall_back_to_stale_full_run_execution` (same file):
  resolution never falls back to a stale full-run execution.

### Shared production/replay architecture

Replay is not a second implementation of the stages. `replay_engine.py`'s
handlers call the same executors that `pipeline.run()` calls:

- `_run_repository_analysis_and_remediation_planning`,
  `_run_guided_context_acquisition`,
  `_run_patch_generation_and_investigation`,
  `_run_patch_repair_and_calibration` and `_run_impact_and_behavior_analysis`;
- the module functions `generate_remediation_strategy`, `challenge_patch`,
  `review_patch` and `score_confidence`;
- `existing_test_amendment.evaluate_existing_test_comparison_with_amendment`
  for S11, and `_build_report`.

The `TestSharedImplementation` tests in `test_replay_engine_s4_s8.py` and
`test_replay_engine_s1_s3_s9_s11_s12.py` assert that these are the same
function objects.

The functions are shared, but replay cannot reconstruct every production
input:

- S1–S4 replay without the parsed investigation context.
- S2 replays a single Strategy call, with no capacity re-render and no
  evidence-gap fallback.
- S7 replays without the calibration summary.
- S8 replays without the calibration summary and with an empty Challenger
  context.
- `report_generation` leaves source verification, relocation telemetry, edit
  readiness/acquisition, conformance and recovery empty. A replayed report
  therefore shows Source Verification as "Not Verified".

Most of these gaps are declared in the replay execution's
`replay_limitations`. Some outcome strings also differ slightly between
production and replay (for example S6's no-patch outcome).

### Replay architecture

`replay_engine.replay_stage(*, source_run, stage_name, output_dir,
repo_root_override=None)` runs these steps in order:

1. Check that the stage is canonical and has a `REPLAY_HANDLERS` entry.
2. Check that `output_dir` neither overlaps nor nests `source_run`.
3. Build the chain, and resolve every declared handler dependency. Fail
   closed on anything not RESOLVED.
4. Run the capability-aware preflight from the stage's `StageSpec`:
   - repository SHA and clean-tree check when `requires_repo_access`;
   - LLM configuration when `requires_llm_provider`. Replays use the
     *current* configuration;
   - a Docker probe when `requires_docker`. Its result is not acted on, so a
     replay is never blocked by Docker; Existing Test Comparison reports its
     own result.
5. Create `output_dir` and call the handler's `run_fn`. A `run_fn`
   reconstructs typed inputs, calls the shared implementation, writes its
   prompt and response files (`NNN_<llm_tag>.*`), checks LLM ownership, and
   writes its artifact (`<canonical_stage>.json`). Some `run_fn`s also
   resolve optional extras from the chain, such as S11 for S7, S8, S9 and S13,
   and return them as extra `consumed` entries.
6. Write `run_manifest.json`: `kind: "replay"`, one execution with
   `sequence: 1`, and source and replay commits and models
   (`openant.source_patcher_commit`/`replay_patcher_commit`/`replay_openant_dirty`,
   `llm.source_*`/`replay_*`).

`REPLAY_HANDLERS` covers **12 of the 13 stages**: every stage except
`trust_signals_and_recommendation`. Asking for that one fails with "registered
but not replayable yet" before any I/O, because S12 only ever runs inside
`report_generation`.

A handler's declared dependencies must be a subset of the approved graph.
Two handlers declare a narrower set:

- `test_analysis_and_plan` is transitional. It declares no dependencies, calls
  `test_plan_discovery.discover_test_plan` directly, and writes
  `test_execution_plan.json` or `rejection_reason.json`.
- `report_generation` declares S1, S2, S4, S6, S7, S8 and S9, and also writes
  `report.md`.

A replay's output directory is not write-once. Use a fresh directory per
replay. The preflight failures in steps 1–4 happen before anything is
written; a failure inside a `run_fn` can leave partial files.

### Terminal reporting architecture

S12 and S13 are separate canonical stages with separate declared
dependencies, but both are implemented by a single call to `_build_report()`
at the end of `run()`. Neither has its own executor or recording bracket.
Replay therefore treats them as one unit, `report_generation`, which calls
the same `_build_report()`. Persisted S12 executions do not exist, so "S12
is replayable" is not a meaningful statement today.

## Evaluation-only tooling

None of the following is used by `openant patch`.

| Tool | Purpose |
|---|---|
| `tools/run_traced.py` | A full run with LLM-call capture and execution recording. Optional `--blind-evaluation`. |
| `tools/run_stage.py` | Single-stage replay. |
| `tools/run_cve_batch.py` (+ `run_patcheval_python_37.py`, `cfp_evaluation_cases.yaml`, `smoke_cases.yaml`) | Parallel, resumable real-CVE batches over YAML manifests: a fresh clone and an isolated output directory and CWD per case, summaries (Markdown, JSON, CSV), a results ZIP, and provenance. GRAY (NO PATCH PRODUCED) is counted as a valid outcome, distinct from FAILED. See [RUN_CVE_BATCH.md](../../libs/openant-core/utilities/autopatcher/tools/RUN_CVE_BATCH.md). |
| `tools/blind_evaluation.py` | **Blind evaluation** for historical regressions. It removes references to the known upstream fix (filter `blind-evaluation-filter/v1`, or `/v2`, and an optional same-repository GitHub policy) from the rendered CVE text before the pipeline sees it. It verifies by hash that the pipeline received the blinded text, and fails closed on references it cannot classify. In production those references are legitimate evidence and are left alone. |
| `tools/replay_challenger_reparse.py` | Re-derives an archived Challenger result through the current parser, with no LLM call. |
| `tools/concern_tree_harness.py`, `simple_concern_harness.py`, `concrete_trace_harness.py` | Research harnesses for the experimental `concern_tree.py`, `simple_concern_resolver.py` and `concrete_trace.py`. These modules are not wired into the production pipeline, and their LLM tags are not in `STAGE_OWNED_LLM_TAGS`. |

Debug artifacts: when `AUTOPATCHER_DEBUG` is set (`run_traced.py` sets it),
the pipeline writes `reports/debug/*.json` and `prompt_*.txt` relative to the
**current working directory**. That is why the batch runner gives every case
its own CWD.

## Architectural invariants

Changes must preserve these rules:

1. **Production and replay share stage implementations.** A `run_fn` calls
   the same function `pipeline.run()` calls. Identity tests enforce this.
2. **Replay orchestration holds no stage business logic.** To change a
   stage, change the shared implementation.
3. **Consumed provenance is explicit and truthful.** `consumed` names the
   exact `{run, execution_id}` actually read. It is never inferred from
   `STAGE_DEPENDENCIES`, and it never contains a forward reference to a stage
   that has not run. (Known gap: the `report_generation` replay reads S11
   whenever it resolves, but records S11 in `consumed` only when an amendment
   was accepted.)
4. **Resolution prefers the newest effective execution, with an exactness
   check.** It never falls back to a stale or older one.
5. **Persisted artifacts round-trip to the types the implementations
   expect.** `to_jsonable` fails closed.
6. **Canonical stage number is not runtime sequence.** Do not conflate the
   two when adding or reordering stages.
7. **Source runs are immutable inputs.** A replay never modifies
   `--source-run`.
8. **Replay output is isolated from its source.** This is checked before any
   other replay work.
9. **Capability checks are stage-specific.** A stage is never blocked by a
   check its contract does not need.
10. **Fail closed toward caution.** Missing or invalid evidence and LLM output
    lead to a skipped generation, an `UNRESOLVED`/`INSUFFICIENT_EVIDENCE`
    verdict, or Manual Review Required. (Known gap: a planning or Strategy
    stage that produces no result at all does not withhold generation; see
    [Fail-closed boundaries](#fail-closed-boundaries).)
11. **The target repository is never written.** Patching and test execution
    happen only in temporary copies.
