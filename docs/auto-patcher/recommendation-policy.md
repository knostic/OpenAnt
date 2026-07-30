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
`utilities/autopatcher/pipeline.py` in `libs/openant-core`. Function names are
cited so this document can be re-verified against source at any time; treat
any mismatch you find as this document being stale, not the code.

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

## The trust pipeline

Auto Patcher's evidence-to-decision flow has four stages:

```
Evidence
   │   (deterministic checks + an adversarial LLM challenge,
   │    the challenge classified by a deterministic rule)
   ▼
Trust Signals
   │   (six named values, computed by fixed rules from the evidence above)
   ▼
Recommendation Policy
   │   (a fixed decision tree over four of those signals)
   ▼
Recommendation
    (one of four labels, with a fixed reason string and, for the
     top two labels, an evidence-check caveat where warranted)
```

Each stage is described in its own section below. The next section describes
what feeds Trust Signals; note that a stage further down the pipeline can only
see what a prior stage already computed — nothing is recomputed or
re-inferred at the Recommendation stage.

## Evidence

Two categories of evidence feed the Trust Signals. It matters which is which,
because the policy treats them differently (see Philosophy, above).

### Deterministic evidence

Produced by code with no LLM in the loop:

| Source | What it checks | Module |
|---|---|---|
| Patch Hygiene | Diff-shape defects: empty hunks, duplicate constants, unused imports | `patch_hygiene.check_patch` |
| Patch Applicability | Whether the diff applies to the target repository (`git apply --check`, read-only) | `patch_applicability.check_applicability` |
| Test Support | Whether existing repository tests already cover the changed file/module | `testing_support.discover_tests` / `tests_for_file` / `score_test_support` |
| Impact Surface | AST-based usage analysis of changed symbols — **Python-only**; reports "not applicable" for other languages | `impact_surface.LightweightImpactAnalyzer` |

### Heuristic evidence: the adversarial Challenger

One LLM output feeds the Trust Signals: the **Challenger**
(`patch_challenger.challenge_patch`). It is a separate reasoning pass whose
only instruction is to argue that the patch does *not* hold — not to confirm
that it does. It returns:

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

## Trust Signals

`_compute_trust_signals` computes six named signals from the evidence above.
Five are rendered as their own row in the report's Trust Signals table; one
is computed but not separately displayed (its rationale, from the code's own
history, is that an earlier report design showed it and found it a
"peer-displayed duplicate" of two other rows — it was dropped from *display*,
not from *computation*, because the policy still depends on it).

| Signal | Possible values | Computed from | Shown as its own row? |
|---|---|---|---|
| `patch_integrity` | Clean · Minor Issues · Not Verified · Does Not Apply · Critical Issues | Hygiene findings + Applicability result | Yes — "Does the patch apply?" |
| `security_improvement` | None · Unknown · Low · Medium · High | Applicability + Hygiene + classified Challenger counts | **No** |
| `remediation_alignment` | Aligned · Likely Aligned · Partial · Misaligned | Classified Challenger counts + `still_vulnerable` | Yes — "Does it address the vulnerability?" |
| `coverage_confidence` | High · Medium · Low | Classified Challenger counts | Yes — "Are there unresolved concerns?" |
| `test_availability` | Tests Available · No Tests Found · Not Verified | Test Support rating | Yes — "Do relevant tests already exist?" |
| `deployment_safety` | Low Risk · Medium Risk · High Risk · Not Verified | Impact Surface result | Yes — "Is deployment risk low?" |

Each signal also carries a short human-readable `notes` string explaining the
specific evidence behind its value (e.g. which hygiene check fired, how many
review findings remain open).

## Recommendation Policy

`_build_recommendation_v1` turns evidence into exactly one of four labels.
There is no fifth value and no numeric score anywhere in this function.

**The four recommendations:**

| Recommendation | Meaning |
|---|---|
| 🟢 **Deploy After Validation** | All mandatory gates passed; run the listed validation actions, then deploy. |
| 🟡 **Deploy With Caution** | Limited or uncertain security improvement, but no blocking evidence. |
| 🟠 **Manual Review Required** | Evidence is inconclusive, heuristic-only, or partially contradictory. |
| 🔴 **Do Not Apply** | A deterministic check failed: the patch has critical hygiene issues or does not apply to the repository. |

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

A secondary, non-decision-changing step, `_check_recommendation_consistency`,
runs only when the decision is Deploy After Validation or Deploy With
Caution. It checks `test_availability` and the count of open Review Results
findings, and — if either is unfavorable — appends an "Evidence check"
caveat sentence to the report. It never changes which of the four labels is
shown; it only makes sure a confident-sounding label doesn't sit next to
undisclosed weak evidence.

> Note: an older function, `build_recommendation`, also exists in
> `pipeline.py` with a different, three-label vocabulary (Safe to deploy /
> Deploy with caution / Do not deploy yet) that reads a numeric confidence
> score. It is exercised only by its own unit test and is not called by the
> report-building path (`_build_report` calls `_build_recommendation_v1`
> exclusively). It should not be treated as describing current behavior.

## What does NOT affect the recommendation

The report contains more evidence than the recommendation policy uses. This
section exists so that evidence you see in a Trust Report is not mistaken for
evidence that shaped its recommendation.

- **Confidence score.** The confidence-scorer stage still runs, and its
  output is still deterministically discounted (0.4× if the Challenger found
  the patch still vulnerable, 0.7× if it found edge cases/issues, otherwise
  unchanged). But this number is never read by `_compute_trust_signals` or
  `_build_recommendation_v1`, and it is not rendered anywhere in the Trust
  Report. It is computed and then discarded.
- **Finding calibration.** The calibration pass rewords and regroups
  `plausible_risk`/`generic` Challenger findings for presentation in Review
  Results (e.g. splitting them into "Confirmed Observations" vs. "Future
  Improvements"). By its own design, it changes wording and grouping only —
  it does not change the confirmed/plausible/gap/generic classification or
  counts that the Trust Signals and Recommendation Policy read.
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
- **`coverage_confidence`.** Computed and rendered as its own row, but not
  read by `_build_recommendation_v1` at all — it is derived from the same
  Challenger counts that `remediation_alignment` already uses, presented as a
  separate lens ("how much did we look"), not consulted as a separate gate.
- **`test_availability`.** Rendered as its own row and does feed the
  secondary consistency-caveat check, but is not one of the four signals the
  primary decision (`_build_recommendation_v1`) gates on.

## Current limitations

- `security_improvement` is a required input to the strongest recommendation
  (Deploy After Validation) but is not shown as its own row in the Trust
  Signals table — a reader relying on the visible table alone cannot see one
  of the gates behind that label without this document.
- Impact Surface and Test Support are the two deterministic signals most
  central to `deployment_safety` and `test_availability`; both currently run
  meaningfully only on Python codebases. On other languages they resolve to
  "not applicable," which the policy treats as "not verified," never as a
  clean result — but it does mean fewer of the six signals carry real signal
  on non-Python repositories today.
- The confidence-scorer stage consumes an LLM call and produces output that,
  per the above, is discarded before reaching the report or the policy. This
  is current behavior, not a documentation gap — flagged here because it is
  easy to assume otherwise from the pipeline's stage log output.
- This document describes the recommendation policy as implemented in
  `_build_recommendation_v1` today. The file also contains an unused,
  differently-worded legacy function (`build_recommendation`); if it is ever
  wired back in, this document must be updated accordingly.
