# The Trust Report and Recommendation Policy

This document explains what an Auto Patcher Trust Report contains and exactly
how its recommendation is decided. It is written for security engineers who
need to know what a recommendation is and is not based on before acting on it.

For what Auto Patcher is and how to run it, see the
[Auto Patcher section of the README](../../README.md#auto-patcher). For the
pipeline as a whole (stages, information flow, fail-closed boundaries,
recording and replay), see
[auto-patcher-architecture.md](auto-patcher-architecture.md). In that
document's terms, everything below happens in the last two canonical stages,
`trust_signals_and_recommendation` and `report_generation`, which are computed
together by `_build_report` in `utilities/autopatcher/pipeline.py`.

Function names are cited so each statement can be checked against the code in
`libs/openant-core/utilities/autopatcher/`. If this document and the code
disagree, the code is authoritative.

## Contents

- [What a recommendation is, and is not](#what-a-recommendation-is-and-is-not)
- [Outcomes](#outcomes)
- [Evidence](#evidence)
- [Trust Signals](#trust-signals)
- [Recommendation Policy](#recommendation-policy)
- [Which outcomes are reachable today](#which-outcomes-are-reachable-today)
- [How to read each outcome](#how-to-read-each-outcome)
- [Evidence caveats and the Manual Review scope note](#evidence-caveats-and-the-manual-review-scope-note)
- [What does not affect the recommendation](#what-does-not-affect-the-recommendation)
- [The Trust Report layout](#the-trust-report-layout)
- [Current limitations](#current-limitations)

## What a recommendation is, and is not

A Trust Report does not tell you a patch is correct. It reports what was
checked, what those checks found, and what a fixed, auditable policy
recommends given exactly that evidence. In particular:

- **No recommendation proves the vulnerability is fixed.** Even the strongest
  label, Deploy After Validation, means the deterministic checks passed and the
  adversarial review left no blocking or unresolved concern. It does not
  mean an exploit was attempted, that every path to the vulnerability was
  closed, or that the patch matches what an upstream maintainer shipped. Auto
  Patcher has no upstream-patch comparison feature.
- **The policy is deterministic; some of its inputs are not.** The decision
  tree (`_build_recommendation_v1`) and the signal derivation
  (`_compute_trust_signals`) are plain code. But two of their inputs come from
  LLM calls: the Challenger's reported facts and Finding Calibration's
  grouping. Code validates and classifies those outputs, but their semantic
  correctness is model judgment. Two runs on the same input can therefore
  produce different recommendations.
- **The recommendation is a starting point for review, not a substitute for
  it.** Auto Patcher never applies a patch to the target repository; patches
  are applied only to temporary copies.

The policy is built around invariants written in code directly above
`_compute_trust_signals` (I1–I6). In short:

- **No positive inference from missing evidence.** A check that did not run,
  timed out, or raised reads as "Not Verified" / "Unknown", never as a pass.
- **Whitelists, not blacklists.** Every positive gate is "value is in this set
  of known-good values", never "value is not the known-bad value".
- **Heuristic evidence alone never reaches the strongest rejection.** Do Not
  Apply requires a deterministic failure; adversarial-review findings cap out at
  Manual Review Required.
- **Inconclusive evidence defaults to Manual Review Required.**

## Outcomes

A run ends in one of three ways. They must not be confused.

| Outcome | What it means | Trust Report written? |
|---|---|---|
| A **recommendation** (one of four labels below) | A final candidate patch exists and the policy evaluated it. | Yes |
| ⚫ **NO PATCH PRODUCED** | The run completed, but it ended without a final candidate patch, usually because a fail-closed gate stopped generation (see [the architecture document](auto-patcher-architecture.md#fail-closed-boundaries)). There is nothing to review or deploy. | Yes |
| **Run failure** | The run itself failed (for example an LLM API error in a stage that is not best-effort, an invalid LLM configuration, an ineligible finding, a missing `--repo-root`, or an NVD fetch failure). | No. `openant patch` prints the error and exits with code 2. |

The four recommendation labels (`_build_recommendation_v1`):

| Recommendation | Meaning |
|---|---|
| 🟢 **Deploy After Validation** | Every mandatory gate has positive evidence. Run the listed validation actions before deploying. |
| 🟡 **Deploy With Caution** | Limited or uncertain security improvement, but nothing blocking. (Part of the policy vocabulary, but not reachable with today's signals. See [reachability](#which-outcomes-are-reachable-today).) |
| 🟠 **Manual Review Required** | The evidence is inconclusive, heuristic-only, partly contradictory, or shows high deployment risk. |
| 🔴 **Do Not Apply** | A deterministic check failed: the patch does not apply to the repository, or it has a critical hygiene defect. |

NO PATCH PRODUCED is not a fifth recommendation. It is not the same as Do Not
Apply or Manual Review Required, because both of those assume a candidate patch
exists. `_build_report` still computes the signals and policy on the empty
evidence, but it discards the result. Instead it renders a
`## ⚫ NO PATCH PRODUCED` card (`_render_no_patch_card`) and omits the Trust
Signals, Recommendation, Validation Actions, Challenger concerns and Review
Results sections. The terminal banner shows `⚫ NO PATCH PRODUCED` as well.

## Evidence

```
final candidate patch
        │
        ├── deterministic checks ───────────────┐  hygiene, git apply --check, source
        │                                       │  verification, test discovery, impact surface
        │                                       │
        ├── Challenger (LLM) ──► deterministic ─┤  verification status + per-finding categories
        │                        classification │
        │                                       │
        └── Finding Calibration (LLM) ──────────┤  calibration-aware defect count; may narrow
                                                │  a VERIFIED_FIXED verdict
                                                ▼
                                         Trust Signals (8)
                                                ▼
                              Recommendation Policy (fixed decision tree)
                                                ▼
                                          Recommendation
```

### Deterministic checks

Produced by code with no LLM in the loop:

| Check | What it establishes | Module |
|---|---|---|
| Patch Hygiene | Diff-shape defects: empty hunks (HIGH), duplicate assignments (MEDIUM), unused imports (MEDIUM). | `patch_hygiene.check_patch` |
| Patch Applicability | Whether the diff applies to the target repository (`git apply --check`, read-only). | `patch_applicability.check_applicability` |
| Source verification | Whether each hunk's old-side content was found in the repository at a unique position. | `source_verification.classify_source_verification` |
| Test Support | Whether test files that cover the changed file exist on disk. This is a discovery check, not a test run. **Python only.** | `testing_support` |
| Impact Surface | AST-based usage analysis of changed symbols (blast radius). **Python only.** Other languages report "not applicable". | `impact_surface.LightweightImpactAnalyzer` |
| Post-Patch Investigation | Re-evaluates deterministic "anchors" (resolved functions, call edges, reachability, constant values) against an isolated, patched copy of the repository. | `post_patch_investigation`, `post_patch_evaluation` |
| Existing Test Comparison (opt-in) | Runs the repository's existing tests in Docker against unpatched and patched copies, and reports newly failing tests. | `existing_test_regression` |

Hygiene and applicability always evaluate the diff after deterministic repair
(`generated_patch_processing.process_generated_patch`):
`diff_hunk_repair.repair_hunk_headers` recomputes wrong `@@` counts and moves a
hunk to the line where its content uniquely matches the real file, and, on the
initial generation path, `reconstruct_hunk_context` can add context lines that
`git apply` requires. These repairs keep every `+`/`-` line unchanged and never
invent a change. The repair's per-hunk relocation records are the only input
to the source-verification signal.

Post-Patch Investigation records observations, not verdicts. It is never read
by the policy directly. Its findings are added to the context the Challenger
sees, and they are rendered in their own report section.

### The Challenger (adversarial review)

The Challenger (`patch_challenger.challenge_patch`) is a separate LLM call with
an adversarial role: it is asked to find reasons the patch does not hold. It
uses the same configured model as every other Auto Patcher call. It receives
the vulnerability report, the patch, and the repository evidence that Patch
Generation used. When Post-Patch Investigation completed, it also receives
those findings and the post-change source of the changed functions, as far as
they fit the call's technical capacity.

**Structured response (the current prompt).** The Challenger reports one
`primary` concern (does the described vulnerability still occur?) and any
number of `additional` concerns. Each concern states a fixed set of facts
(whether the operation is present in the evidence, whether a guard precedes it,
the guard's default state and effect, whether re-entry preserves state,
whether a non-default action is required, and whether the advisory's scope
covers that action). Each positive fact must carry a short verbatim quote.
Absence answers are not quote-checked: `false` (no non-default action
required), `not_applicable` re-entry, and the `silent` and `absent` markers,
which take a whole-document or whole-function marker instead. `false` only
matters after a fully cited `blocked` chain. Code then does the following:

1. **Checks citations.** A quote counts only if it appears in the
   repository-derived context the Challenger was actually shown, in the
   post-change side of the diff (context and added lines, never removed lines
   or diff headers), or (for scope facts) in the vulnerability report. Context
   lines that the patch removes are excluded too, so a removed guard can never
   be cited as present. A quote must contain an identifier character, be at
   least 3 non-whitespace characters, and match on token boundaries (not
   inside a longer identifier). Planner and Strategy prose is not citation
   authority. A fact with an ungrounded citation is treated as `unresolved`.
   The check proves a quote is real and comes from the patched code, not that
   it supports the fact; that remains the model's judgment.
2. **Assigns each concern a consequence**: `BLOCKING`, `UNRESOLVED`, or
   `NON_BLOCKING` (`_concern_consequence`). A missing, invalid or ungrounded
   fact can never lead to `NON_BLOCKING`; a malformed concern is
   `UNRESOLVED`.
3. **Derives the run-level verification status** (`_derive_status_from_concerns`):
   - any `BLOCKING` concern → `RESIDUAL_VULNERABILITY`;
   - otherwise any `UNRESOLVED` concern → `INSUFFICIENT_EVIDENCE`;
   - all `NON_BLOCKING` → `VERIFIED_FIXED`;
   - fails closed to `INSUFFICIENT_EVIDENCE` if there is not exactly one primary
     concern, or if the response also puts free-form content in its
     `Edge cases`, `Potential issues` or `Summary` sections;
   - fails a `VERIFIED_FIXED` result closed to `INSUFFICIENT_EVIDENCE` if the
     response contradicts itself: its own `Verification status:` line says
     `RESIDUAL_VULNERABILITY` or `INSUFFICIENT_EVIDENCE` (or a legacy
     `Still vulnerable:` line says yes), or the primary concern's
     `Description` or `Hypothesized outcome` states that the vulnerability
     remains exploitable (a declarative sentence such as "remains
     exploitable", "is still vulnerable" or "can still be bypassed";
     questions, conditionals and negated forms do not count). The report
     names the contradiction. Additional concerns' text is not read: it
     often describes non-default or out-of-scope paths that the override
     and scope rules classify as non-blocking by design.

Otherwise the model's own `Verification status:` line is not used for the
decision once a `Concerns:` section is present: it can only fail a
`VERIFIED_FIXED` result closed, never raise a result. `BLOCKING` means the reported facts met the blocking rule;
it does not mean a defect was independently verified. `VERIFIED_FIXED` means
no concern met the blocking or unresolved rules; it does not mean the fix was
proven.

**Legacy free-form response.** A response without a `Concerns:` section is
still supported. Its `Verification status:` header (or an older
`Still vulnerable:` header) is parsed directly, and an unrecognized value fails
closed. Its free-text findings are sorted by a deterministic lexical classifier
(`_classify_finding`) into `confirmed_defect`, `behavioral_defect`,
`plausible_risk`, `validation_gap` or `generic`. A legacy
`RESIDUAL_VULNERABILITY` claim with no `confirmed_defect` or
`behavioral_defect` finding behind it is downgraded to `INSUFFICIENT_EVIDENCE`
(`_classify_challenger`).

`still_vulnerable` is true for every status except `VERIFIED_FIXED`, including
an unknown or unparseable one.

### Finding Calibration

Finding Calibration (`finding_calibration.calibrate_findings`) is a second LLM
pass over the Challenger's free-text findings. It does not process structured
concerns, so with today's structured Challenger output it usually has nothing
to calibrate and makes no call. For each finding it returns:

- a group: `observed` (backed by evidence shown to it), `hypothesis` (a
  plausible inference) or `hardening` (outside the advisory's scope), plus a
  reworded version whose certainty matches the group. A finding cannot stay
  `observed` if the model's own output lists one of its required dependencies
  as unresolved;
- a remediation impact for unresolved dependencies: `proof_required`,
  `validation_only` or `unclear`. A missing or invalid value is `unclear`.

If calibration asks for specific repository evidence that is needed to resolve
a finding, it gets one bounded follow-up
(`_calibrate_findings_with_evidence_acquisition`). The requested files or
symbols are resolved deterministically (at most 3 requests). If new evidence
fits, calibration runs once more and that second result is final.

Calibration affects the policy in exactly two ways, both computed in
`_build_report`:

1. **Calibration-aware defect count.** A raw `confirmed_defect` finding counts
   toward the policy's defect count only if calibration grouped it `observed`
   or did not calibrate it at all. A missing calibration counts as a defect.
   A `confirmed_defect` calibrated `hypothesis` or `hardening` does not count
   (`_build_known_findings`, `potential_remaining_risks`).
2. **Narrowing a `VERIFIED_FIXED` verdict.**
   `_reconcile_verification_status_with_calibration` changes `VERIFIED_FIXED`
   to `INSUFFICIENT_EVIDENCE` (and `still_vulnerable` to true) when any
   `plausible_risk`/`validation_gap`/`generic` finding still blocks remediation
   proof:
   - an uncalibrated `validation_gap` finding blocks;
   - a calibrated finding with unresolved dependencies blocks unless its impact
     is `validation_only`;
   - nothing else blocks.

   This reconciliation only ever narrows a verdict. It never clears
   `RESIDUAL_VULNERABILITY` or `INSUFFICIENT_EVIDENCE`.

Calibration can therefore move a recommendation toward caution, for example
from Deploy After Validation to Manual Review Required. It can also remove a
raw `confirmed_defect` from the count that would otherwise force Manual Review
Required through the Misaligned branch. Calibration also decides how free-text
findings are grouped in the report and whether the Challenger-driven repair
loop may run (see the
[architecture document](auto-patcher-architecture.md#s6--patch_repair_and_calibration)).

## Trust Signals

`_compute_trust_signals` computes six signals. `_build_report` then adds two
more as separate keys: `source_verification` and `existing_test_comparison`.
Seven of the eight have a row in the report's Trust Signals table.
`security_improvement` is used by the policy but not shown as its own row.

| Signal | Values | Computed from | Report row | Read by the decision? |
|---|---|---|---|---|
| `patch_integrity` | Clean · Minor Issues · Not Verified · Does Not Apply · Critical Issues | Hygiene + applicability | "Does the patch apply?" | **Yes** |
| `security_improvement` | None · Unknown · Low · Medium · High | Applicability, hygiene, calibration-aware defect count, `still_vulnerable`, raw plausible-risk count | (not shown) | **Yes** |
| `remediation_alignment` | Aligned · Likely Aligned · Partial · Misaligned | Calibration-aware defect count, `still_vulnerable`, raw plausible-risk count | "Does it address the vulnerability?" | **Yes** |
| `deployment_safety` | Low Risk · Medium Risk · High Risk · Not Verified | Impact Surface level (High Risk also when a HIGH hygiene defect exists) | "Is deployment risk low?" | **Yes** |
| `coverage_confidence` | High · Medium · Low | Defect count; structured concern consequences; raw plausible-risk and validation-gap counts | "Are there unresolved concerns?" | No (display only) |
| `test_availability` | Tests Available · No Tests Found · Not Verified | Test Support | "Do relevant tests already exist?" | Only by the [evidence caveat](#evidence-caveats-and-the-manual-review-scope-note) |
| `source_verification` | Confirmed · Position Unconfirmed · Unverified · Not Verified | Hunk relocation records | "Was the edited content verified against the repository?" | No (display only) |
| `existing_test_comparison` | PASS · NEW_FAILURES_DETECTED · PRE_EXISTING_FAILURES_ONLY · TEST_EXECUTION_ERROR · NOT_VERIFIED | Existing Test Comparison (opt-in; NOT_VERIFIED when not requested) | "Were there new test failures after the patch?" | No (display only) |

The decision itself also reads `still_vulnerable`, the calibration-aware
defect count, and (for wording only) the verification status.

Each signal carries a short `notes` string that names the specific evidence
behind its value. The report labels Patch Integrity, Test Availability and
Deployment Risk as deterministic checks, and Remediation Alignment and Coverage
Confidence as derived from heuristic adversarial review.

## Recommendation Policy

`_build_recommendation_v1` evaluates these checks in order. The first match
wins:

```
if patch_integrity in {"Does Not Apply", "Critical Issues"}:
    return "Do Not Apply"                                    # I4: deterministic only

if remediation_alignment == "Misaligned":                    # calibration-aware defect count > 0
    return "Manual Review Required"

if still_vulnerable and defect_count == 0:                   # verdict is not VERIFIED_FIXED
    return "Manual Review Required"

if (patch_integrity == "Clean"
        and security_improvement in {"High", "Medium"}
        and deployment_safety in {"Low Risk", "Medium Risk"}):
    return "Deploy After Validation"                         # I3: explicit whitelist

if security_improvement == "Low" and deployment_safety == "Low Risk":
    return "Deploy With Caution"

if deployment_safety == "High Risk":
    return "Manual Review Required"

return "Manual Review Required"                              # I5: catch-all
```

There is no numeric score anywhere in this function.

Each decision has a fixed lead sentence as its `reason`. Every decision except
Deploy After Validation may add one sentence that names the signal behind it,
quoting that signal's `notes`. For example: "Remediation alignment: …", or
"Deployment risk could not be verified because impact analysis is not
supported for this language yet." Manual Review Required decisions also carry a
short "why" phrase for the report's "Why manual review" line. For the
`still_vulnerable` branch, the wording depends on the verification status:

- `RESIDUAL_VULNERABILITY` (structured): a concern met the deterministic
  blocking rule, based on citation-checked, model-reported facts. The issue was
  not independently verified.
- `RESIDUAL_VULNERABILITY` (legacy): adversarial review reported affirmative
  evidence that the vulnerability may remain.
- `INSUFFICIENT_EVIDENCE`: the available evidence was not enough to verify the
  fix.
- Unknown or unclassified: stronger confidence is not justified.

This wording never changes the decision.

## Which outcomes are reachable today

The policy can express more states than today's signals produce. With the
current signal derivation:

- **Do Not Apply** is reached only when `git apply --check` rejects the repaired
  diff, or when the diff has an empty hunk (the only HIGH hygiene check).
- **Deploy After Validation** requires every one of the following:
  - the patch applies with no hygiene findings;
  - the verification status is `VERIFIED_FIXED` after calibration
    reconciliation;
  - the calibration-aware defect count is zero;
  - Impact Surface reports low or medium impact.

  `security_improvement` "Medium" and the second way "High" is produced both
  require `still_vulnerable`, so the earlier branch always intercepts them.
  **Impact Surface supports only Python. On any other repository,
  `deployment_safety` is "Not Verified", so Deploy After Validation cannot be
  reached.** The best outcome there is Manual Review Required.
- **Deploy With Caution** is not reachable. Every state that yields
  `security_improvement == "Low"` also triggers an earlier branch: a HIGH
  hygiene defect means Critical Issues and therefore Do Not Apply, and a nonzero
  defect count means Misaligned and therefore Manual Review Required. The label
  stays in the policy vocabulary for a future evidence model that can tell a
  "positive but weaker" state apart from those cases.
- **Manual Review Required** covers everything else: a Misaligned alignment,
  any verification status other than `VERIFIED_FIXED`, high deployment risk,
  Minor Issues integrity, applicability that could not be checked, impact
  analysis that is unavailable or not applicable, or any unrecognized value.

## How to read each outcome

### 🟢 Deploy After Validation

- **What the system knows:** the repaired diff applies cleanly and has no
  hygiene findings. Adversarial review produced no concern that met the
  blocking or unresolved rule, and calibration did not narrow that verdict.
  Python impact analysis found a localized or moderate blast radius.
- **What it does not know:** whether the vulnerability is actually closed
  under real execution, whether other variants or paths remain, and whether
  the patch is equivalent to the upstream fix. Coverage confidence, test
  availability and source verification are not gated here. Check the Trust
  Signals table and any "Evidence check" caveat.
- **What to do next:** run the report's Validation Actions (the top action
  targets the strategy's security invariant when one was produced), then
  decide.

### 🟡 Deploy With Caution

Not produced by the current signal derivation (see above). If it ever appears,
it means low security improvement with low deployment risk, and the report's
reason asks for manual security review.

### 🟠 Manual Review Required

This label covers several distinct situations. The report's "Why manual
review" line names which one applies:

1. **Misaligned:** at least one Challenger finding that calibration did not
   discount reads as a confirmed alternate exploit path. This is unresolved
   heuristic evidence, not a verified exploit.
2. **Not verified fixed:** the Challenger verdict is `RESIDUAL_VULNERABILITY`
   or `INSUFFICIENT_EVIDENCE` (including verdicts narrowed by calibration, and
   every fail-closed structured response).
3. **High deployment risk:** Impact Surface found a high-impact change.
4. **Inconclusive:** anything else, such as Not Verified deployment safety
   (no repository root, non-Python repository, impact analysis unavailable),
   Minor Issues integrity, or applicability that could not be checked.

Manual Review Required does not mean "the patch is bad". In cases 2–4 nothing
deterministic points to a defect. The label reflects evidence that is missing
or inconclusive.

### 🔴 Do Not Apply

The only trigger is `patch_integrity` being "Does Not Apply" (`git apply
--check` rejected the repaired diff) or "Critical Issues" (an empty hunk).
Heuristic findings can never produce this label.

### ⚫ NO PATCH PRODUCED

The pipeline ended without a final candidate patch. Common causes:

- Planning could not reach a grounded plan.
- A Planner claim stayed contradicted after one revision.
- The final strategy named no target, or left its target's authority
  unresolved.
- Not every intended edit had verified source.
- The required target source did not fit Patch Generation's technical
  capacity.
- The generator's response stayed invalid after its contract retry.
- The generated patch edited the wrong files and post-patch recovery could not
  fix that.

Each of these is a deliberate fail-closed stop, not a crash. The cause is shown
in the terminal output; `--verbose` adds detail. For most causes the report's
Patch Applicability section also shows the skip reason.

## Evidence caveats and the Manual Review scope note

Two presentation helpers add context without changing the decision:

- **Evidence check caveat** (`_check_recommendation_consistency`). This runs
  only for Deploy After Validation and Deploy With Caution. It adds a caveat
  sentence when `test_availability` is "No Tests Found", or when Review Results
  contains decision-relevant findings.
- **Manual Review scope note** (`_render_manual_review_scope_note`). For Manual
  Review Required, it lists the open Review Results findings by category.

Both describe findings with `_describe_decision_relevant_findings`. It counts
Potential Remaining Risks, Validation Gaps, Observed Facts and Validation
Questions, but not Future Improvements, and it renders a per-category
breakdown, for example "3 items to weigh: 1 flagged risk · 1 validation gap ·
1 observed fact". It deliberately avoids "open" or "remaining" wording,
because an Observed Fact is an evidence-status label: it can be reassuring as
well as concerning.

## What does not affect the recommendation

The report contains more evidence than the policy uses. None of the following
change the decision:

- **Confidence score.** The Confidence Scorer runs, and its score is discounted
  by the Challenger's result (×0.4 if still vulnerable, ×0.7 if any finding was
  raised), but the score is never read by the policy and never rendered.
- **Patch Reviewer output.** This is rendered as Explanation, Affected areas,
  and Reviewer Notes (in Appendices). The reviewer receives the vulnerability
  report, the final patch and the calibration summary, but no repository
  evidence. Any statement about repository state, an upstream fix, or "matching"
  a release reflects the model's prior knowledge, and the report says so.
- **Post-Patch Investigation observations and Anchor Coverage.** These shape
  what the Challenger sees, but the policy does not read them.
- **`coverage_confidence`, `source_verification`, `existing_test_comparison`.**
  These are displayed only. `test_availability` feeds only the evidence caveat.
- **Behavior Summary and Repository Context.** These are explanatory
  sections, or inputs to the Validation Actions list.
- **Deterministic static signals.** The section is never rendered. The
  `scripts.constraint_signals` / `scripts.remediation_signals` modules it
  depended on never shipped, and importing them could only resolve to a
  `scripts/` directory in the current directory (possibly the analyzed
  repository), so the import was removed.
- **The advisory itself.** For a CVE input, the report states that advisory
  claims (description, CWE, severity) are not repository-verified and that the
  recommendation does not depend on the advisory's CVSS score.

## The Trust Report layout

`_build_report` renders, in order:

1. Header and decision card (or the NO PATCH PRODUCED card).
2. Vulnerability summary and primary references.
3. Proposed patch.
4. Patch Hygiene and Patch Applicability, plus notices when an applicability
   retry or a Challenger-driven repair happened.
5. Trust Signals.
6. Recommendation, with its reason, the "why manual review" line, the top
   validation action, and any evidence caveats.
7. Explanation (reviewer output, labeled as model analysis).
8. Validation Actions.
9. Challenger concerns (structured responses) and Review Results (free-text
   findings, grouped as Potential Remaining Risks, Validation Gaps, Observed
   Facts, Validation Questions and Future Improvements).
10. Repository Context.
11. Post-Patch Investigation.
12. Existing Test Comparison (shown as "not requested" unless it was enabled).
13. Impact Surface.
14. Appendices: deterministic static signals (only when available, see
    above), language coverage gaps, test support and suggested tests, behavior
    summary, affected areas, reviewer notes.

`core/patch.py` then appends a Run Metadata section: timestamp, input source,
repository root and commit, OpenAnt commit, provider and model, LLM mode,
configured max tokens, and per-stage stop reasons. For CVE input it also adds
an input-source disclosure.

## Current limitations

- **Python-only signals.** Impact Surface and Test Support work only on Python
  repositories; elsewhere they report "not applicable". As a result, other
  languages cannot reach Deploy After Validation.
- **Test Support versus Existing Test Comparison.** `test_availability` checks
  that matching test files exist. It does not run them. Existing Test
  Comparison does run the repository's existing tests (Docker only; Python,
  Node or Go runtimes), but only when explicitly requested. It is available as
  `--compare-existing-tests` on the Python CLI and `tools/run_traced.py`, not
  on the Go `openant patch` command. Its signal is displayed only. When enabled,
  it can also make one bounded LLM call to amend an existing test that
  contradicts the patch's stated security intent. If that amended patch is
  accepted, it becomes the reported patch (see the
  [architecture document](auto-patcher-architecture.md#s10s11--existing-test-comparison-opt-in)).
- **Patch Reviewer has no repository evidence.** Treat its Explanation and
  Reviewer Notes as model analysis, not verified fact.
- **Nondeterminism.** The Challenger and calibration are LLM calls. Code
  validates their output structure and citations, but not their reasoning.
- **Legacy code.** `pipeline.py` still contains an older three-label
  `build_recommendation()` and `_decision_relevant_finding_count()`. Neither is
  used to build the report. Their only callers are their own unit tests.
