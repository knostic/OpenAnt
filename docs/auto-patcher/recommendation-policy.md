# The Trust Report and Recommendation Policy

This document explains how Auto Patcher's Trust Report is produced, and — more
importantly — how its final recommendation is decided. It is written for
security engineers who need to know exactly what a recommendation is and is
not based on before acting on it.

For what Auto Patcher is and how to run it, see the
[Auto Patcher section of the README](../../README.md#auto-patcher). This document
goes one level deeper: it describes the evidence-to-decision machinery behind
the report that command produces.

Everything below is grounded in the current implementation of
`utilities/autopatcher/pipeline.py` in `libs/openant-core`, plus the stage
modules it calls directly and cites by name throughout: `patch_challenger.py`,
`finding_calibration.py`, `patch_reviewer.py`, `confidence_scorer.py`,
`source_verification.py`, `diff_hunk_repair.py`, `post_patch_investigation.py`,
and `post_patch_evaluation.py`. Function names are cited so this document can
be re-verified against source at any time; treat any mismatch you find as this
document being stale, not the code.

## Purpose

A Trust Report does not tell you a patch is correct. It tells you what was
checked, what that checking found, and — given exactly that evidence and
nothing else — what a fixed, auditable policy recommends. The recommendation
is a starting point for review, not a substitute for it. Nothing in this
system applies a patch to a repository; every run writes its output to disk
for a human to read.

## Philosophy

The recommendation policy (`_compute_trust_signals`, `_build_recommendation_v1`
in `pipeline.py`) is built around a small set of invariants, documented
in-code directly above `_compute_trust_signals`. Restated here:

- **No positive inference from missing evidence.** If a check didn't run —
  timed out, was skipped, raised an exception — that reads as "not verified"
  or "unknown," never as a passing result. A check that never ran must never
  look identical to a check that ran and passed.
- **Whitelists, not blacklists.** Every gate in the recommendation policy is
  phrased as "value is in this specific set of known-good values," never as
  "value is not the one known-bad value." A blacklist silently admits any
  future or unrecognized value as if it were good; a whitelist doesn't.
- **Heuristic evidence is never treated as proof.** Output from the
  adversarial LLM challenger is classified and counted, but it never on its
  own reaches the strongest recommendation or the strongest rejection —
  see [Recommendation Policy](#recommendation-policy).
- **The report never communicates more certainty than the evidence supports.**
  This governs both the policy's gates and the report's own wording — e.g. a
  "Minor Issues" patch-integrity result is deliberately excluded from the
  "positive" whitelist even though it doesn't hard-block, because it is real
  observed evidence of a defect, not an absence of evidence.

## Two kinds of outcome

Auto Patcher's report leads with exactly one top-level outcome, but that
outcome comes from one of two different axes, and they must not be confused:

**A. Execution outcome — did a final candidate patch exist at all?**

- ⚫ **NO PATCH PRODUCED** — the pipeline never produced a final candidate
  patch to evaluate. There is nothing to deploy, review, or validate.

**B. Recommendation Policy outcome — given a candidate patch, what does the
evidence support?**

- 🟢 Deploy After Validation
- 🟡 Deploy With Caution
- 🟠 Manual Review Required
- 🔴 Do Not Apply

`NO PATCH PRODUCED` is **not** a fifth recommendation, not a
Recommendation-Policy branch, and not equivalent to `Do Not Apply` or `Manual
Review Required` — both of those presuppose a real candidate patch exists for
the policy to judge. `NO PATCH PRODUCED` means there was no candidate to
judge in the first place. See [NO PATCH PRODUCED](#no-patch-produced) below
for the exact trigger and rendering behavior.

Auto Patcher's evidence-to-decision flow, in full:

```
Pipeline execution
       │
       ▼
 final candidate patch exists?   (result.patch non-empty — see _build_report)
       │
   ┌───┴────────────┐
   NO               YES
   │                 │
   ▼                 ▼
⚫ NO PATCH      Evidence
  PRODUCED       │   (deterministic checks + an adversarial LLM Challenger
                 │    call, grounded in repository evidence and, when still
                 │    current, Post-Patch Investigation findings — the
                 │    Challenger's free-text findings then classified by a
                 │    deterministic rule)
                 ▼
             Trust Signals
                 │   (seven named values; six shown as their own report row)
                 ▼
          Recommendation Policy
                 │   (a fixed decision tree over four of those signals)
                 ▼
            Recommendation
                  (one of four labels, with a fixed reason string and, for
                   the top two labels, an evidence-check caveat where
                   warranted)
```

Before this flow starts, several more LLM stages — remediation planning,
remediation strategy, and (best-effort, inside guided repository-context
acquisition) a narrow `guided_context_request` call — help assemble the
repository evidence (`code_context`) that Patch Generation, the Challenger,
Finding Calibration, and the Confidence Scorer all read. After the
Challenger runs, two more LLM stages — Finding Calibration and Patch Review
— plus the Confidence Scorer produce additional report content. **None of
these stages write to Trust Signals or the Recommendation Policy.** See
[Evidence](#evidence) for what each one actually does, and
[What does NOT affect the recommendation](#what-does-not-affect-the-recommendation)
for the ones whose output is discarded or report-only.

One implementation detail worth knowing: Trust Signals and the Recommendation
Policy are computed **unconditionally**, even on a no-patch run (on
whatever empty/default hygiene, applicability, and challenger data exist) —
and so do Finding Calibration, Patch Review, and the Confidence Scorer, which
run against whatever patch text exists with no early return gating them on a
non-empty patch. That computed recommendation is deliberately never shown or
acted on — `_build_report` reads the `no_patch` flag and renders the
`NO PATCH PRODUCED` card in its place instead. Nothing about this bypasses
the policy; the policy result is simply discarded for presentation once there
is no patch to attach it to.

Each stage is described in its own section below. A stage further down the
pipeline can only see what a prior stage already computed — nothing is
recomputed or re-inferred at the Recommendation stage.

## Evidence

Exactly two categories of evidence feed the Trust Signals: deterministic
checks, and the adversarial Challenger's classified output. Everything else
in this section — Finding Calibration, Patch Reviewer, the Confidence Scorer,
and Post-Patch Investigation — either shapes what the Challenger itself sees,
or is computed and rendered without ever reaching `_compute_trust_signals` or
`_build_recommendation_v1`. It matters which is which.

### Deterministic evidence

Produced by code with no LLM in the loop:

| Source | What it checks | Module |
|---|---|---|
| Patch Hygiene | Diff-shape defects: empty hunks, duplicate constants, unused imports | `patch_hygiene.check_patch` |
| Patch Applicability | Whether the diff applies to the target repository (`git apply --check`, read-only) | `patch_applicability.check_applicability` |
| Test Support | Whether existing repository tests already cover the changed file/module — a discovery check, not a test *run* (see [Current limitations](#current-limitations)) | `testing_support.discover_tests` / `tests_for_file` / `score_test_support` |
| Impact Surface | AST-based usage analysis of changed symbols — **Python-only**; reports "not applicable" for other languages | `impact_surface.LightweightImpactAnalyzer` |

Patch Applicability and Patch Hygiene — and, through `patch_integrity`, the
Trust Signal built from them — always evaluate the diff *after* a chain of
deterministic repair steps has already run against it, not the LLM's raw
output. `diff_hunk_repair.repair_hunk_headers` recomputes arithmetically
wrong `@@` hunk-header counts and, when `repo_root` is known, relocates a
hunk's claimed old-side line number to wherever its content uniquely matches
the real file. If the repaired diff still fails `git apply --check`,
`diff_hunk_repair.reconstruct_hunk_context` gets one more deterministic
attempt: it expands context lines for a hunk that is already positionally
correct but too context-thin for `git apply` to accept. Both preserve every
semantic `+`/`-` line; neither invents a change. `check_patch` and
`check_applicability` always run on whichever diff text these repairs
produced — every call site in `pipeline.py` runs header repair immediately
before hygiene/applicability, for the original patch, the applicability
retry, and the Challenger-driven repair loop alike. The same repair pass's
per-hunk relocation records (`unique_match` / `ambiguous` / `no_match` /
`skipped`) are the entire input to the `source_verification` signal — see
[Trust Signals](#trust-signals).

### Heuristic evidence: the adversarial Challenger

One LLM output feeds the Trust Signals: the **Challenger**
(`patch_challenger.challenge_patch`). It is a separate reasoning pass whose
only instruction is to argue that the patch does *not* hold — not to confirm
that it does. Its prompt always includes the vulnerability report and the
proposed patch, and — when available — a `code_context` block: the same
repository evidence (assembled from Repository Grounding, remediation
planning/strategy, and Repository Understanding) that Patch Generation used
to write the patch, plus, when Post-Patch Investigation has already run and
still describes the current candidate patch, that investigation's rendered
findings too (see [Post-Patch Investigation](#post-patch-investigation)
below). This grounding is what lets the Challenger — and, downstream,
Finding Calibration — distinguish a claim that is actually backed by
repository content shown to it from one that is not.

It returns:

- `still_vulnerable` — a boolean the LLM asserts directly, parsed from its
  response. This is a raw model judgment, not a derived value.
- `edge_cases` / `potential_issues` — free-text findings.

Those free-text findings are then run through a **deterministic** classifier,
`_classify_finding` (pattern-matched against explicit-exploit phrasing,
version/scope qualifiers, validation-gap language, and generic-observation
language), sorting each into one of four categories:

- `confirmed_defect` — an unambiguous claim the fix doesn't hold, with no
  scope/version qualifier attached.
- `plausible_risk` — a claim that reads as a scope or version limitation
  rather than a primary fix failure.
- `validation_gap` — the challenger states something wasn't tested/verified,
  not that it's broken.
- `generic` — a stylistic or non-security observation.

`_classify_challenger` then aggregates these into counts
(`confirmed_defect_count`, `plausible_risk_count`, `validation_gap_count`).
**These counts, plus the raw `still_vulnerable` boolean, are the only pieces
of Challenger output the Trust Signals or the Recommendation Policy read.**
The challenger's prose itself is presentational (rendered in Review Results),
not a policy input.

A single-shot, Challenger-driven repair loop (`run`'s Phase C) can fire once,
right after this first Challenger call: if the patch applies cleanly but
carries one or more `confirmed_defect` findings, the pipeline regenerates the
patch (against the plain `code_context`, without the Post-Patch Investigation
addition) and re-challenges the result. If the regenerated patch applies and
its re-challenge finds zero confirmed defects, it replaces `patch`,
`challenger`, `hygiene_findings`, and `applicability_result` for every stage
downstream — including all of the ones described in this document. This loop
is not itself a new evidence source the Trust Signals read; it can only
change *which* patch, and *which* classified-Challenger result, they see.

### Finding Calibration

After the Challenger's final result is classified, a second LLM pass,
**Finding Calibration** (`finding_calibration.calibrate_findings`), reclassifies
and rewords the subset of findings classified as `plausible_risk` or
`generic` — `confirmed_defect` and `validation_gap` findings are never sent
to it; those already carry unambiguous framing. It reasons over the same
evidence the Challenger saw (vulnerability text, patch, and the same
`code_context`, including Post-Patch Investigation findings when still
current) and sorts each input finding into exactly one of three epistemic
groups, rewording it to match that group's certainty:

- `observed` — directly backed by the repository evidence or diff actually
  shown to it. Rendered under **Observed Facts**, with a subtitle stating
  this is an evidence-status label, not a severity one — an Observed Fact
  can be reassuring, neutral, or concerning; it means "backed by evidence,"
  not "this is a problem."
- `hypothesis` — a plausible inference, not directly observed in that
  evidence. Rendered under **Validation Questions**. This is also the
  fallback group for any `plausible_risk` finding calibration didn't classify
  (calibration wasn't run, failed, or omitted that finding).
- `hardening` — out of scope for the current advisory; a suggestion, not a
  concern. Rendered under **Future Improvements**. This is the fallback
  group for any uncalibrated `generic` finding.

Combined with the `confirmed_defect` → **Potential Remaining Risks** and
`validation_gap` → **Validation Gaps** groups (untouched by calibration),
this produces the five subsections `_build_known_findings` populates in the
report's Review Results section.

**Calibration never changes the `confirmed_defect_count` /
`plausible_risk_count` / `validation_gap_count` counts, or the raw
`still_vulnerable` boolean, that the Trust Signals and Recommendation Policy
read** — those are all computed by `_classify_challenger` from the
Challenger's original four categories, before calibration ever runs.
`finding_calibration.py`'s own module docstring states this is deliberate: it
is additive presentation, not reclassification of the signals' inputs.

It does have one indirect effect worth knowing, however: the secondary
consistency check described under
[Recommendation consistency vs. the decision itself](#recommendation-consistency-vs-the-decision-itself)
counts findings that land in **Observed Facts** and **Validation
Questions** (but not **Future Improvements**) toward its evidence-caveat
summary. Because calibration decides which of those three groups a given
`plausible_risk`/`generic` finding lands in, it can change what that summary
says — even though it never changes `decision` itself, and never changes
what the Trust Signals table shows.

### Patch Reviewer

**Patch Reviewer** (`patch_reviewer.review_patch`) runs once per run, after
Finding Calibration. Its prompt receives only the vulnerability report and
the final candidate patch — **no `code_context`, no Challenger output, and no
Finding Calibration output.** Its raw response is split (`_split_review`)
into three sections rendered directly into the report: **Explanation** (why
the original code was vulnerable and how the patch fixes it — the report
also extracts one sentence from this as a presentational "Security gain"
lead-in, `_extract_security_gain`), **Affected areas**, and **Reviewer
Notes** (rendered in Appendices, from the response's `validation_notes`
section).

**Provenance matters here.** The report itself already carries this warning:
the Explanation section states that this text "reflects the reviewer LLM's
analysis of the advisory, diff, and any injected code context — not
independent execution or testing against the target repository," and adds
explicitly that "any statement that a fix 'matches' or 'aligns with' an
upstream release reflects the model's own prior knowledge, not a fetched or
independently verified upstream comparison." Reviewer Notes carries the same
point: "Reviewer-LLM guidance, not independently verified evidence... any
reference to an upstream fix, release, or version number reflects the
model's own prior knowledge, not evidence this pipeline fetched or
verified." Take both literally. Because Patch Reviewer's prompt carries no
repository evidence at all, any specific claim it makes about repository
state, an upstream fix, or a named CVE/advisory detail comes from the
model's own prior knowledge, not from anything Auto Patcher checked against
this repository or against an actual upstream patch — Auto Patcher has no
upstream-diff-comparison feature today. Model prior knowledge, a verified
upstream comparison, and repository-backed evidence (the kind
[Post-Patch Investigation](#post-patch-investigation) or the deterministic
checks above produce) are three different things; only the latter two are
"evidence" in the sense the rest of this document uses that word.

Patch Reviewer's output is not read by `_compute_trust_signals` or
`_build_recommendation_v1` — `_compute_trust_signals` takes no `review`
parameter at all. Its only downstream consumer is the Confidence Scorer,
next.

### Confidence Scorer

**Confidence Scorer** (`confidence_scorer.score_confidence`) runs last. Its
prompt receives the vulnerability report, the final patch, Patch Reviewer's
full output, and the same `code_context` the Challenger saw (including
Post-Patch Investigation findings, when still current). Its numeric score is
then deterministically discounted by the Challenger's own result (0.4× if
`still_vulnerable`, 0.7× if any edge case/potential issue was found,
unchanged otherwise) before being stored on the pipeline result. None of
this — not the raw score, not the discounted score, not the reasoning text —
is read by `_compute_trust_signals` or `_build_recommendation_v1`, or
rendered anywhere in the Trust Report; see
[What does NOT affect the recommendation](#what-does-not-affect-the-recommendation).

### Post-Patch Investigation

After a candidate patch exists and the applicability-retry loop has settled,
Post-Patch Investigation re-checks a set of deterministic "Anchors" — derived
both from the vulnerability's original code
(`post_patch_investigation.derive_pre_patch_anchors`, computed before
Candidate Selection ever ran) and from the final patch's own diff
(`post_patch_evaluation.derive_patch_touched_anchors`, which catches an
element the patch touches even when no selected candidate ever surfaced it)
— against a freshly built `InvestigationContext` for the *patched* repository
copy (`post_patch_evaluation.evaluate_anchors`). Anchor kinds covered:
resolved functions, call edges, reachability, constant values, and
vulnerability-pattern sink matches (a `sink_match` anchor is never
re-evaluated and reports as `unresolved`, honestly, rather than guessed).
Each resulting `AnchorObservation` records what changed — never a verdict on
whether that change is a successful fix; `evaluate_anchors`'s own docstring
is explicit that judging the observation is a downstream consumer's job.

This runs exactly once, immediately before the first Challenger call —
specifically so its rendered findings (`render_post_patch_investigation`) can
be appended to the `code_context` that the Challenger, Finding Calibration,
and the Confidence Scorer all read, not merely placed in the report. A
staleness guard compares the investigated patch against whatever patch
ultimately gets reported: if the Challenger-driven repair loop replaces
`patch` afterward, this evidence is dropped from Finding Calibration's and
the Confidence Scorer's `code_context` (they fall back to the plain
`code_context` without it), and the report's own Post-Patch Investigation
section renders "Not shown" instead of stale findings. The repair loop's own
internal re-challenge call never receives this evidence either way, by
design — extending it there is treated as a separate, later decision.

**This evidence is not read by `_compute_trust_signals` or
`_build_recommendation_v1` directly.** It shapes what the Challenger reasons
about, which can change `still_vulnerable` and the classified finding counts
— both of which *are* read by `_compute_trust_signals`/`_build_recommendation_v1`
— and, transitively, what Finding Calibration and the Confidence Scorer see.
Finding Calibration's own Observed/Hypothesis/Hardening groupings are a
separate matter: they are never read by `_compute_trust_signals` or
`_build_recommendation_v1` either, only by the secondary consistency-caveat
count described under
[Recommendation consistency vs. the decision itself](#recommendation-consistency-vs-the-decision-itself).
The anchor observations and Anchor Coverage themselves are never consulted
directly by `_compute_trust_signals` or the Recommendation Policy; the
distinction — "grounds a heuristic LLM stage" vs. "is read by the
deterministic policy" — matters and should not be collapsed.
They are rendered as their own `## Post-Patch Investigation` report section —
including an "Anchor Coverage" subsection showing how much of the diff's
changed lines were actually tracked by at least one anchor — for a human to
read directly. It is the piece of evidence closest to "did this change
actually touch the vulnerable behavior," as distinct from "the diff applied
cleanly" (`patch_integrity`) — but it remains a deterministic *observation*,
not independent proof the vulnerability is fixed, and it does not itself move
the Trust Signals or the recommendation.

The section can instead read "Not evaluated" (no repository root, no
anchors to re-evaluate, or the investigation itself did not complete) or "Not
shown" (the patch was revised after this evidence was computed, so it no
longer describes the reported patch) — see `render_post_patch_investigation`
and `_build_report`'s `§9c` block.

## Trust Signals

`_compute_trust_signals` computes six named signals from the evidence above.
A seventh, `source_verification`, is merged into the same signals dict
separately (`source_verification.py`'s Evidence Sufficiency Gate) and is
**not** part of `_compute_trust_signals`'s own six-signal computation or its
I1–I6 invariants. Of these seven, six are rendered as their own row in the
report's Trust Signals table; one — `security_improvement` — is computed but
not separately displayed (dropped from *display* only, per the code's own
history: an earlier report design found it a "peer-displayed duplicate" of
two other rows; the policy still depends on it).

| Signal | Possible values | Computed from | Shown as its own row? | Used by the primary decision? |
|---|---|---|---|---|
| `patch_integrity` | Clean · Minor Issues · Not Verified · Does Not Apply · Critical Issues | Hygiene findings + Applicability result (both evaluated on the deterministically repaired diff — see [Evidence](#deterministic-evidence)) | Yes — "Does the patch apply?" | **Yes** |
| `security_improvement` | None · Unknown · Low · Medium · High | Applicability + Hygiene + classified Challenger counts | No | **Yes** |
| `remediation_alignment` | Aligned · Likely Aligned · Partial · Misaligned | Classified Challenger counts + `still_vulnerable` | Yes — "Does it address the vulnerability?" | **Yes** |
| `deployment_safety` | Low Risk · Medium Risk · High Risk · Not Verified | Impact Surface result | Yes — "Is deployment risk low?" | **Yes** |
| `test_availability` | Tests Available · No Tests Found · Not Verified | Test Support rating | Yes — "Do relevant tests already exist?" | No — secondary caveat only (see below) |
| `coverage_confidence` | High · Medium · Low | Classified Challenger counts | Yes — "Are there unresolved concerns?" | No — displayed only |
| `source_verification` | Confirmed · Position Unconfirmed · Unverified · Not Verified | `diff_hunk_repair.repair_hunk_headers`'s hunk-vs-repository relocation records | Yes — "Was the edited content verified against the repository?" | No — displayed only |

Each signal also carries a short human-readable `notes` string explaining the
specific evidence behind its value (e.g. which hygiene check fired, how many
review findings remain open).

**Why this distinction matters architecturally:** four signals
(`patch_integrity`, `security_improvement`, `remediation_alignment`,
`deployment_safety`) are the *only* inputs `_build_recommendation_v1` reads —
these are the primary recommendation inputs. `test_availability` feeds only
the secondary consistency caveat (below), never the primary decision.
`coverage_confidence` and `source_verification` are computed and displayed
for the reader's benefit but are not consulted by either the primary
decision or the consistency caveat — `source_verification` explicitly by
product decision recorded in its own module docstring ("do not yet decide
how, or whether, it should affect the final recommendation... deferred to a
later phase"), pending more real-run evidence on how often it fires and
whether it correlates with bad patches.

## Recommendation Policy

`_build_recommendation_v1` turns evidence into exactly one of four labels.
There is no fifth value and no numeric score anywhere in this function. It
runs on every candidate-patch-bearing evaluation; whether its result is
actually shown depends on the execution-outcome check described above.

**The four recommendations:**

| Recommendation | Meaning |
|---|---|
| 🟢 **Deploy After Validation** | All mandatory gates passed; run the listed validation actions, then deploy. |
| 🟡 **Deploy With Caution** | Limited or uncertain security improvement, but no blocking evidence. |
| 🟠 **Manual Review Required** | Evidence is inconclusive, heuristic-only, or partially contradictory. |
| 🔴 **Do Not Apply** | A deterministic check failed: the patch has critical hygiene issues or does not apply to the repository. |

> **Policy expressiveness vs. current signal expressiveness.** The four
> labels above are the intended, full vocabulary of `_build_recommendation_v1`
> — not merely what today's evidence happens to produce. The policy
> deliberately leaves room for recommendation states that the current Trust
> Signal derivation (`_compute_trust_signals`) cannot yet safely distinguish.
> See the reachability notes under "Deploy With Caution" and "Deploy After
> Validation" below for exactly where the literal policy and the live,
> pipeline-reachable subset of it currently diverge.

**Decision order** (each check is evaluated in sequence; the first match
wins):

1. `patch_integrity` is a hard blocker (Critical Issues / Does Not Apply) →
   **Do Not Apply**. This is the only path to this label, and it is reached
   only through deterministic evidence — heuristic Challenger findings alone
   can never produce it.
2. `remediation_alignment` is `Misaligned` (i.e. `confirmed_defect_count > 0`)
   → **Manual Review Required**.
3. `still_vulnerable` is true but `confirmed_defect_count == 0` (an unresolved
   heuristic claim with no confirmed defect behind it) → **Manual Review
   Required**.
4. Only if `patch_integrity == Clean` **and** `security_improvement` is
   `High`/`Medium` **and** `deployment_safety` is `Low Risk`/`Medium Risk` (an
   explicit three-way whitelist, not "didn't hit a worse case") →
   **Deploy After Validation**.
5. `security_improvement == Low` and `deployment_safety == Low Risk` →
   **Deploy With Caution**.
6. `deployment_safety == High Risk` → **Manual Review Required**.
7. Anything else — including `Unknown`/`Not Verified` on any axis — →
   **Manual Review Required** (the catch-all; nothing falls through to a
   stronger label by default).

Expressed as pseudocode (derived from `_build_recommendation_v1`, current as
of this writing):

```
if patch_integrity in {"Does Not Apply", "Critical Issues"}:
    return "Do Not Apply"

if remediation_alignment == "Misaligned":
    return "Manual Review Required"

if still_vulnerable and confirmed_defect_count == 0:
    return "Manual Review Required"

if (patch_integrity == "Clean"
        and security_improvement in {"High", "Medium"}
        and deployment_safety in {"Low Risk", "Medium Risk"}):
    return "Deploy After Validation"

if security_improvement == "Low" and deployment_safety == "Low Risk":
    return "Deploy With Caution"

if deployment_safety == "High Risk":
    return "Manual Review Required"

return "Manual Review Required"   # catch-all: Unknown/Not Verified/anything
                                   # not explicitly matched above
```

A secondary, non-decision-changing step, `_check_recommendation_consistency`,
runs only when the decision is Deploy After Validation or Deploy With
Caution. It checks `test_availability` and a category-labeled breakdown of
Review Results findings, and — if either is unfavorable — appends an
"Evidence check" caveat sentence to the report. It never changes which of
the four labels is shown; it only makes sure a confident-sounding label
doesn't sit next to undisclosed weak evidence. See
[Recommendation consistency vs. the decision itself](#recommendation-consistency-vs-the-decision-itself)
below.

The `reason` strings quoted in this document are each decision's fixed lead
sentence. `Deploy After Validation`'s `reason` is exactly that sentence,
never extended further. Every other decision's `reason` may append one more
sentence naming the specific Trust Signal(s) that drove that branch, quoting
that signal's own already-rendered `notes` (e.g. "Remediation alignment: …"
for the Misaligned/still-vulnerable branches, or "Patch integrity: …" for
Do Not Apply, or "Deployment risk could not be verified because …" for a
branch reached after the Deploy After Validation whitelist fails). This is
presentation only — it never changes which of the four labels is picked —
but it means the exact `reason` text a report shows can be longer than the
lead sentence quoted throughout this document.

> Note: an older function, `build_recommendation`, also exists in
> `pipeline.py` with a different, three-label vocabulary (Safe to deploy /
> Deploy with caution / Do not deploy yet) that reads a numeric confidence
> score. It is exercised only by its own unit tests (`tests/patch/test_pipeline.py`)
> and is not called by the report-building path (`_build_report` calls
> `_build_recommendation_v1` exclusively). It should not be treated as
> describing current behavior — see [Current limitations](#current-limitations).

## How to interpret each recommendation

### 🟢 Deploy After Validation

- **What the system knows:** `patch_integrity == Clean` (applies with zero
  hygiene defects), `security_improvement` is High or Medium (adversarial
  review found either no remaining exploit path, or only validation-gap-style
  unresolved risk with zero high-confidence findings), and `deployment_safety`
  is Low or Medium Risk (Impact Surface found a localized-to-moderate blast
  radius). All three must hold simultaneously — an explicit whitelist, never
  "didn't hit a worse case."
- **What uncertainty may still remain:** `coverage_confidence`,
  `test_availability`, and `source_verification` are *not* gated on here. A
  Deploy After Validation report can still show "Are there unresolved
  concerns? Medium," "No Tests Found," or an unverified `source_verification`
  row. When `test_availability == "No Tests Found"` or decision-relevant
  Review Results findings remain open, the report attaches an "Evidence
  check" caveat sentence (`_check_recommendation_consistency`) — read it; the
  label alone does not tell the whole story.
- **Why this is not "safe to deploy immediately":** the deterministic part of
  this label (`patch_integrity`) only proves the diff is well-formed;
  `security_improvement`/`remediation_alignment` behind it are heuristic —
  classified adversarial-review output, not independently verified proof the
  vulnerability is fixed.
- **What "After Validation" means operationally:** run the report's listed
  Validation Actions (targeted tests, manual checks) before deploying — this
  is the literal wording of the recommendation's `reason` string.
- **What a reviewer should do next:** read Validation Actions, check for an
  Evidence check caveat, and only then decide.

> **Current reachability note.** The whitelist above literally accepts
> `security_improvement` of `"High"` *or* `"Medium"`. Under the current
> `_compute_trust_signals` derivation, `"Medium"` only occurs when
> `still_vulnerable == True` — and that state is intercepted by the earlier
> `still_vulnerable`/`confirmed_defect_count` gate (Decision order, step 3)
> before this branch is ever reached. The same earlier gate also intercepts
> one of the two ways `"High"` is produced (`still_vulnerable == True` with
> zero plausible-risk findings). In practice, the only state that reaches
> this branch today is `security_improvement == "High"` via
> `still_vulnerable == False` — the challenger found no remaining exploit
> path at all. Do not read a `"Medium"` `security_improvement` value as
> evidence of an observed live Deploy After Validation path; it describes
> what the literal whitelist permits, not what the pipeline currently
> exercises.

### 🟡 Deploy With Caution

- **How it differs from Deploy After Validation:** reached only when the
  Deploy After Validation whitelist test fails, **and**
  `security_improvement == "Low"`, **and** `deployment_safety == "Low Risk"`.
- **Which evidence is weaker:** `security_improvement == "Low"` means either a
  HIGH-severity hygiene defect exists (the patch may be a no-op) or the
  Challenger found one or more `confirmed_defect_count` findings — either
  way, a real signal of concern, just not strong enough on its own to
  escalate further given deployment risk is low.
- **Why not Manual Review Required:** deployment risk is low and
  `remediation_alignment` hasn't hit `Misaligned` or the
  still-vulnerable-with-zero-confirmed-defects gate — the policy treats "weak
  fix, low blast radius" as caution-level, not stop-and-review-level.
- **What's expected before deployment:** the recommendation's own `reason`
  string says "Manual security review recommended" — the same Evidence check
  caveat mechanism as Deploy After Validation still applies here too.

> **Current reachability note.** `Deploy With Caution` remains part of the
> intended Recommendation Policy vocabulary, but no state the pipeline's
> current Trust Signal derivation actually produces reaches it. Every input
> combination that yields `security_improvement == "Low"` today also forces
> a *stronger*, earlier gate first: `high_hygiene` simultaneously forces
> `patch_integrity == "Critical Issues"` (→ Do Not Apply), and
> `confirmed_defect_count > 0` simultaneously forces `remediation_alignment
> == "Misaligned"` (→ Manual Review Required) — see
> `_compute_trust_signals`. This is a property of the *current*
> evidence/signal derivation, not proof that the yellow policy state is
> conceptually unnecessary. The branch is intentionally retained for a
> genuinely positive-but-weaker evidence state that today's evidence model
> cannot yet safely distinguish from those stronger gates — richer
> deterministic validation, remediation assessment, deployment-risk
> analysis, and other evidence may eventually make such a state safely
> distinguishable. Improving deployment-risk assessment alone would not be
> sufficient: the shadowing happens entirely on the
> `patch_integrity`/`remediation_alignment` side, not on
> `deployment_safety`. No specific future gate is proposed here.

### 🟠 Manual Review Required

This single label covers four distinct code paths, each reached for a
different reason:

1. **Heuristic concern (remediation misalignment).**
   `remediation_alignment == "Misaligned"` — the Challenger found one or more
   `confirmed_defect_count` findings: a high-confidence claim of an alternate
   exploit path. Unresolved heuristic evidence, not a verified exploit.
2. **Unresolved heuristic claim.** `still_vulnerable` is true but
   `confirmed_defect_count == 0` — the Challenger flagged something it
   couldn't fully substantiate as a confirmed defect.
3. **High deployment risk.** `deployment_safety == "High Risk"` — deterministic
   Impact Surface evidence of a wide blast radius, independent of whether the
   fix itself looks correct.
4. **Catch-all / inconclusive evidence.** Nothing above matched — covers
   `Unknown`/`Not Verified` on any axis (e.g. no repository root, impact
   analysis unavailable), `Minor Issues` integrity, or any other state the
   policy doesn't explicitly recognize as positive.

The report also renders a short scope note for this label specifically
(`_render_manual_review_scope_note`) — a category-labeled breakdown of open
Review Results findings, followed by "— see Review Results below for
details" — so a reader doesn't have to hunt for why review is needed. It
shares its counting/describing logic with the Evidence check caveat; see
[Recommendation consistency vs. the decision itself](#recommendation-consistency-vs-the-decision-itself)
for exactly what it counts and how it's worded.

**This is not equivalent to "the patch is bad."** In paths 2–4, nothing
deterministic points to an actual defect; the label reflects insufficient or
inconclusive evidence, not a confirmed problem. Per the I5 invariant,
inconclusive evidence must never resolve to a stronger label by default —
only an explicit positive whitelist membership earns Deploy After Validation
or Deploy With Caution, so anything short of that lands here rather than
being guessed upward.

### 🔴 Do Not Apply

- **Exact trigger:** `patch_integrity` is exactly `"Does Not Apply"` or
  `"Critical Issues"` — i.e. either `git apply --check` rejected the
  (deterministically repaired) diff outright, or a HIGH-severity hygiene
  defect was found. Nothing else.
- **Remains deterministic-only.** This is the *only* path to this label
  (I4 invariant) — heuristic Challenger findings, including a `Misaligned`
  `remediation_alignment` (`confirmed_defect_count > 0`), can never produce
  it on their own; that evidence caps out at Manual Review Required.
- **Why this is stronger than Manual Review Required:** it reflects a
  verified, mechanical failure — the diff doesn't apply, or contains a defect
  the hygiene checker can point at with certainty — rather than absent or
  ambiguous evidence.

## Comparison at a glance

| Outcome | Candidate patch exists? | How it's reached | Blocking deterministic failure? | Dominant evidence type | Reviewer action |
|---|---|---|---|---|---|
| ⚫ NO PATCH PRODUCED | No | `result.patch` is empty | N/A — no patch to check | N/A | Nothing to review; investigate why generation didn't complete |
| 🔴 Do Not Apply | Yes | `patch_integrity` blocked (git-apply rejection or HIGH hygiene defect) | Yes | Deterministic only | Do not deploy; fix the target mismatch/generation issue |
| 🟠 Manual Review Required | Yes | Misaligned / unresolved `still_vulnerable` / High deployment risk / catch-all | No | Mixed — often heuristic, sometimes deterministic-but-inconclusive | Read Review Results and Impact Surface; decide manually |
| 🟡 Deploy With Caution | Yes | Low security improvement + Low deployment risk | No | Heuristic-leaning | Manual security review, then deploy if satisfied |
| 🟢 Deploy After Validation | Yes | Clean integrity + High/Medium improvement + Low/Medium Risk safety | No | Mixed — deterministic gate + heuristic improvement signal | Run listed Validation Actions, check the Evidence caveat, then deploy |

## Recommendation consistency vs. the decision itself

`_check_recommendation_consistency` (see [Recommendation
Policy](#recommendation-policy) above) is easy to conflate with the decision
itself; it is not the same mechanism:

- **The recommendation decision** (`_build_recommendation_v1`) picks one of
  the four labels. It runs once, is deterministic given the signals, and
  never changes once computed.
- **The evidence caveat** (`_check_recommendation_consistency`) runs *after*
  the decision, only for the two top-tier labels, and only appends a sentence
  to the rendered report — reusing `notes` text already shown elsewhere in
  the Trust Signals table for the test-coverage caveat, and a finding count
  drawn from the same Review Results categories rendered elsewhere for the
  second caveat, never inventing new evidence. It cannot change `decision`;
  its entire job is making sure a confident-sounding label never sits beside
  undisclosed weak evidence (no test coverage, or open decision-relevant
  Review Results findings) without saying so.

Both this caveat's second sentence and the Manual Review Required scope note
(`_render_manual_review_scope_note`) share one describing function,
`_describe_decision_relevant_findings`. It sums the same four categories —
**Potential Remaining Risks** + **Validation Gaps** + **Observed Facts** +
**Validation Questions** — deliberately excluding **Future Improvements**,
since those are explicitly out of the current advisory's scope, and renders
a per-category breakdown (e.g. "3 items to weigh: 1 flagged risk · 1
validation gap · 1 observed fact") rather than a single undifferentiated
count. It deliberately never uses "open" or "remain" language, specifically
so that an **Observed Fact** — Finding Calibration's own label for a claim
directly backed by the repository evidence shown to it, which may be
reassuring, neutral, or concerning — is not described the same way a
**Validation Gap** or **Validation Question** (both genuinely unresolved
concerns) is. This is a deliberate correction to earlier report wording that
described this same aggregate as "N decision-relevant finding(s) remain
open," which did not make that distinction; if you see that phrase in an
older report, or in cached documentation, it predates this fix.

An older function, `_decision_relevant_finding_count`, still exists in
`pipeline.py` and still computes the same four-category sum as a bare
integer — but it is no longer called by `_check_recommendation_consistency`
or `_render_manual_review_scope_note`; today it is exercised only by its own
unit tests, the same unused-but-present status as the legacy
`build_recommendation` function described under
[Recommendation Policy](#recommendation-policy) above.

## What does NOT affect the recommendation

The report contains more evidence than the recommendation policy uses. This
section exists so that evidence you see in a Trust Report is not mistaken for
evidence that shaped its recommendation.

- **Confidence score.** The Confidence Scorer stage still runs — fed the
  vulnerability text, final patch, Patch Reviewer's output, and the same
  repository/Post-Patch-Investigation evidence context the Challenger saw —
  and its output is still deterministically discounted (0.4× if the
  Challenger found the patch still vulnerable, 0.7× if it found edge
  cases/issues, otherwise unchanged). But this number is never read by
  `_compute_trust_signals` or `_build_recommendation_v1`, and it is not
  rendered anywhere in the Trust Report. It is computed and then discarded.
  See [Confidence Scorer](#confidence-scorer) above.
- **Patch Reviewer output.** Rendered verbatim as Explanation / Affected
  areas / Reviewer Notes. See [Patch Reviewer](#patch-reviewer) above for its
  (narrow) inputs and, importantly, the provenance distinction between model
  prior knowledge and verified evidence. Not read by `_compute_trust_signals`
  or `_build_recommendation_v1`; its only downstream consumer is the
  (also-discarded) Confidence Scorer.
- **Finding calibration.** See [Finding Calibration](#finding-calibration)
  above for the full behavior. In short: it rewords and regroups
  `plausible_risk`/`generic` Challenger findings into Observed Facts /
  Validation Questions / Future Improvements for Review Results, and never
  changes the confirmed/plausible/gap/generic classification or counts the
  Trust Signals and Recommendation Policy read — but it does influence what
  the consistency caveat and Manual Review scope note report (see
  [Recommendation consistency vs. the decision itself](#recommendation-consistency-vs-the-decision-itself)).
- **Deterministic static signals** (constraint/remediation-signal scripts,
  when available for the target repository). Rendered as their own
  "Deterministic Signals" table in the report's Appendices. Not read by
  `_compute_trust_signals` or the recommendation policy.
- **Behavior Summary.** A diff-only, language-agnostic summary of what the
  patch appears to do. Feeds the report's Validation Actions suggestions, not
  the Trust Signals.
- **Repository Context (grounding).** Explains which repository locations
  were used to inform patch generation and review. Purely explanatory; not an
  input to any signal.
- **Post-Patch Investigation's anchor observations and Anchor Coverage.**
  Deterministic, but not read directly by `_compute_trust_signals` or the
  Recommendation Policy — see
  [Post-Patch Investigation](#post-patch-investigation) above. Its rendered
  findings do feed the Challenger's (and, when still current, Finding
  Calibration's and the Confidence Scorer's) prompt evidence, which is a
  different thing from feeding the policy directly; that section explains
  the distinction.
- **`coverage_confidence`.** Computed and rendered as its own row, but not
  read by `_build_recommendation_v1` or `_check_recommendation_consistency` —
  it is derived from the same Challenger counts that `remediation_alignment`
  already uses, presented as a separate lens ("how much did we look").
- **`source_verification`.** Computed and rendered as its own row, but not
  read by `_build_recommendation_v1` or `_check_recommendation_consistency`
  either — an explicit, documented product decision to defer wiring it into
  the policy until more real runs show how it behaves.
- **`test_availability`.** Rendered as its own row and does feed the
  secondary consistency-caveat check, but is not one of the four signals the
  primary decision (`_build_recommendation_v1`) gates on.

## NO PATCH PRODUCED

- **Exact trigger:** `not (result.patch and result.patch.strip())` — the
  pipeline's final candidate patch is empty or whitespace-only when
  `_build_report` runs (`_build_report`'s `no_patch` flag).
- **One deterministic upstream cause, among others:** the Edit Readiness Gate
  (`remediation_planner.check_edit_readiness`) can decide that no intended
  edit has verified, patch-ready repository source and skip Patch Generation
  entirely, leaving `patch = ""`. This is one path to the trigger condition
  above, not a separate execution outcome — the same check and the same card
  render either way, regardless of why `patch` ended up empty.
- **What still runs:** Trust Signals and the Recommendation Policy still
  compute a result (on whatever default/empty evidence exists), and
  Validation Actions are explicitly cleared to an empty list (there is
  nothing to validate). None of this computed recommendation reaches the
  reader.
- **What the report shows instead:** a dedicated `## ⚫ NO PATCH PRODUCED`
  card (`_render_no_patch_card`) stating the pipeline did not produce a final
  candidate patch and that no patch is available for deployment or review,
  plus a files-changed count. The normal Recommendation block is omitted
  entirely (rendered as an empty string), not replaced with a
  Manual-Review-shaped message.
- **Terminal output:** the same run prints `[pipeline] Recommendation:` followed
  by `⚫ NO PATCH PRODUCED` to stderr — never one of the four decision emoji —
  so a human watching the run gets the same signal live.
- **Why it must not be read as Do Not Apply:** `Do Not Apply` means a real
  candidate patch exists and the policy found deterministic blocking
  evidence against it (a failed `git apply --check`, or a HIGH hygiene
  defect). `NO PATCH PRODUCED` means there is no candidate to hold that
  evidence in the first place — a categorically different, and strictly
  earlier, failure mode.

## LLM configuration note

The evidence and policy described above are entirely deterministic-or-
classified computation, apart from the two LLM calls this document depends
on directly: the Challenger, and — informationally only — the Confidence
Scorer, whose output is discarded (see above). Auto Patcher's pipeline runs
several further LLM-backed stages — remediation planning, remediation
strategy, a narrow best-effort `guided_context_request` call inside guided
repository-context acquisition, Patch Generation, Finding Calibration, and
Patch Review — that assemble evidence or produce report-only text but do not
themselves feed Trust Signals or the Recommendation Policy; see
[Evidence](#evidence) for the ones central to this document's evidence
model.

Every one of these calls shares the same configuration story. Auto Patcher does not maintain
an independent LLM provider/model configuration system for these calls; the
provider and model come from OpenAnt's canonical `default_llm` → `analyze`
phase binding (the same configuration `openant setup llm` writes), resolved
through OpenAnt's shared provider/adapter infrastructure. `LLM_PROVIDER` /
`LLM_MODEL` environment variables are **not** a supported way to select a
real provider or model for any of these calls — setting either for that
purpose is a hard, documented failure, never a silent no-op (see
`llm_client.py`'s module docstring). `LLM_PROVIDER=mock` is a distinct,
narrow, intentional test/research escape hatch, not part of real-provider
configuration; a real-provider run normally has both variables unset. See the
[README's Auto Patcher section](../../README.md#auto-patcher) for how to
configure it; nothing about that configuration changes how the evidence
above is interpreted.

## Current limitations

- Impact Surface and Test Support — the two deterministic signals behind
  `deployment_safety` and `test_availability` — currently run meaningfully
  only on Python codebases. On other languages they resolve to "not
  applicable," which the policy treats as "not verified," never as a clean
  result — so fewer of the seven signals carry real signal on non-Python
  repositories today.
- Test Support is a **discovery** check (does a matching test file exist),
  never an execution check — Auto Patcher does not build the target
  repository or run its test suite as part of the pipeline. "Tests
  Available" means relevant tests were found on disk, not that they were run
  or passed.
- Patch Reviewer receives no repository evidence in its prompt — only the
  vulnerability report and the final patch — so any specific claim it makes
  about repository state, or about a prior/upstream fix, reflects the
  model's own training-time knowledge, not something Auto Patcher verified
  against this repository or an actual upstream patch. See
  [Patch Reviewer](#patch-reviewer) for the exact provenance distinction; do
  not read Reviewer Notes or Explanation text as repository-confirmed
  evidence.
- The Confidence Scorer stage still consumes an LLM call — fed the Patch
  Reviewer's output and the same repository evidence the Challenger saw, in
  addition to the vulnerability text and patch — and produces output that,
  per [What does NOT affect the recommendation](#what-does-not-affect-the-recommendation),
  is discarded before reaching the report or the policy. This is current
  behavior, not a documentation gap — flagged here because it is easy to
  assume otherwise from the pipeline's stage log output.
- The Evidence check caveat and the Manual Review Required scope note
  describe their finding aggregate with a category breakdown
  (`_describe_decision_relevant_findings`), not a single "N remain open"
  number — precisely so Observed Facts (evidence-backed) are not worded the
  same as Validation Gaps/Questions (genuinely unresolved). See
  [Recommendation consistency vs. the decision itself](#recommendation-consistency-vs-the-decision-itself)
  for the exact mechanism. The Trust Report presentation/wording work is
  ongoing and may still change exact phrasing further (section names,
  captions, etc.); this document describes the policy code's current
  counting/describing behavior, not that work's final output.
- This document describes the recommendation policy as implemented in
  `_build_recommendation_v1` today. The file also contains an unused,
  differently-worded legacy function (`build_recommendation`, three labels,
  numeric-score-driven); it still exists, is still exercised only by its own
  unit tests, and is still not called by the report-building path. If it is
  ever wired back in, this document must be updated accordingly.
