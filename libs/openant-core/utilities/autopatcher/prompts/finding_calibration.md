# Finding Calibration Prompt

You are calibrating the certainty and scope of a security reviewer's adversarial
findings before they are shown to a human reviewer. You are given the
vulnerability advisory, the proposed patch, any repository evidence that was
shown to earlier reviewers, and a numbered list of findings from an
adversarial challenger.

For each finding, do five things:

1. **Expose the finding's factual dependencies.** List every factual claim
   the finding's final conclusion requires, and mark any of them the
   supplied evidence above does not independently establish as unresolved.
   Do this before deciding the group below — the group must follow from
   this list, not the other way around.

   Before finalizing which dependencies are unresolved, compare each
   candidate dependency against the Claims you just listed for this SAME
   finding. If a Claim above already establishes the answer to that
   dependency directly from the supplied evidence, do not list it as
   unresolved — Unresolved must contain only dependencies that remain
   genuinely unanswered after considering both the supplied evidence and
   your own Claims. Do not resolve a dependency merely because related
   evidence exists nearby, or because the answer seems likely — only
   because a Claim above already establishes the specific answer from
   what the evidence actually shows.

2. **Rate the remediation impact of any unresolved dependency**, independently
   of the group you will assign in step 3. This is a narrower question than
   group: given what the supplied Security Invariant (or, if none was
   supplied, the vulnerability description) establishes as the scenario this
   remediation must cover, does resolving THIS dependency matter to
   establishing that the claimed mechanism satisfies it? Answer exactly one
   of:
   - `proof_required` — resolving the unresolved dependency is NECESSARY to
     establish that the claimed remediation mechanism satisfies the supplied
     Security Invariant (or vulnerability description, if no invariant was
     given) for the scenario the evidence establishes as in scope. Without
     it, you cannot confirm the mechanism works as claimed for that scenario.
   - `validation_only` — resolving the unresolved dependency is not necessary
     to establish that the mechanism satisfies the supplied Security
     Invariant for the in-scope scenario. This covers two different
     situations: the mechanism already stands on the evidence shown, or the
     dependency instead concerns a scenario that the supplied evidence does
     not establish as part of the required remediation behavior.
     `validation_only` never means the concern is false, that the underlying
     behavior is safe, that the dependency is resolved, or that the concern
     is unimportant — only that resolving it is not required to establish
     the claimed remediation against the supplied Security Invariant.
   - `unclear` — you cannot confidently determine which of the above applies
     from anything else available to you.
   Decide which scenario the remediation must cover only from what the
   supplied Security Invariant, vulnerability description, and other
   evidence above actually establish — never from a keyword in the finding's
   own wording (such as "override", "non-default", "explicit", or
   "advanced"), and never from whether upstream did or did not address the
   scenario; upstream's own choices are not evidence of what this advisory's
   remediation requires. If that evidence does not clearly establish whether
   the dependency's scenario is part of the required remediation behavior,
   answer `proof_required`, not `validation_only` — scope ambiguity is
   resolved in the blocking direction, the same way any other unresolved
   dependency is.

   Two specific scope patterns recur often enough to name explicitly. Both
   have the same shape: a normally-blocking uncertainty that the supplied
   Security Invariant or vulnerability description itself narrows to
   non-blocking — unless the evidence says otherwise, in which case it
   blocks like any other in-scope dependency.

   - **Existing predicate, helper, policy, or abstraction the patch does
     not modify.** When the supplied Security Invariant explicitly defines
     the in-scope boundary or condition in terms of an existing predicate,
     helper, policy, contract, or abstraction — and the patch does not
     modify that predicate/helper/policy — evaluate the remediation's
     completeness relative to the boundary as the Security Invariant
     actually states it. Do not recursively expand the proof obligation
     into whether that unmodified predicate/helper/policy might itself
     implement some broader alternative semantic definition you can
     imagine; on its own, that is `validation_only`, not `proof_required`
     — the mechanism already stands on the boundary the invariant names.
     This stays `proof_required` only when the supplied vulnerability
     description, Security Invariant, or verified evidence itself makes a
     property of that predicate/helper/policy part of the required
     remediation, or when the evidence itself demonstrates that the
     predicate/helper/policy contradicts the stated invariant — a
     concrete, evidence-backed contradiction always overrides this rule.
     Decide this only from what the supplied Security Invariant and
     evidence actually say about that predicate/helper/policy's role —
     never from a general assumption that unmodified code is automatically
     correct, and never merely because the predicate/helper/policy exists
     unexamined in the codebase.
   - **Explicit non-default caller configuration.** A concern that exists
     only when a caller deliberately selects an explicit non-default
     configuration, override, lower-level entry point, disabled guard,
     custom policy, or replacement value does not, by itself, make the
     default remediation incomplete. When the remediation contract is
     specifically about the default/normal path, classify such a concern
     `validation_only` unless the supplied vulnerability description,
     Security Invariant, or verified evidence itself extends the required
     remediation to that alternate configuration, override, or entry point
     — in which case it remains `proof_required`, exactly like any other
     in-scope dependency. This is a scope decision made only from what the
     supplied evidence and Security Invariant actually establish; it is
     never a blanket rule that a custom configuration or non-default path
     can never matter, and it is never decided from a keyword describing
     the configuration (such as "override", "custom", "explicit",
     "disabled", or "non-default") in the finding's own wording.

   This axis never determines Group, and Group never determines this axis: a
   `Hypothesis` finding may be `proof_required` or `validation_only`, and a
   `Hardening` finding may also carry either value depending on whether its
   own unresolved dependency matters to the supplied Security Invariant —
   `Hardening` is not automatically non-blocking, and `Hypothesis` is not
   automatically blocking.
   If the Unresolved list for this finding is empty (every dependency is
   established), write `validation_only` here — there is nothing left
   unresolved for this axis to grade. Never leave this field blank, and
   never write anything other than one of these three exact words.

3. **Classify** it into exactly one of three groups:
   - `Observed` — the evidence shown above directly demonstrates the specific
     state or behavior the finding claims (not merely a related file,
     function, or constant). This includes any intermediate transformation,
     assignment, or normalization step the conclusion depends on: if reaching
     the claimed conclusion requires such a step, that step itself must be
     visible in the evidence above. A finding may be classified `Observed`
     only if the dependency list above contains no unresolved item.

     Seeing the comparison, membership check, mutation, or use site itself
     is not sufficient on its own. If the value(s) it reads, compares, or
     uses only reach their final runtime form through an assignment,
     conversion, normalization, mutation, configuration, default
     application, or other intermediate transformation, the effect of that
     step on those exact value(s) must independently be visible in the
     supplied evidence. If that step is not visible, the conclusion must
     not be classified as `Observed` — even when the conclusion appears
     likely, when multiple findings agree with it, when no finding
     contradicts it, or when the comparison/use site itself is directly
     shown.

     This standard applies to the finding's entire final conclusion, not
     merely to individual supporting facts. A finding may contain several
     directly observed component facts and still fail to qualify as
     `Observed` if the specific outcome it claims depends on another
     value, state, operand, transformation, assignment, configuration,
     propagation step, or intermediate behavior that is not independently
     established by the supplied evidence. For comparisons or composed
     outcomes, evidence for one side or one contributing transformation
     does not establish the other side. Every factual dependency required
     for the final conclusion must independently satisfy the same
     `Observed` standard; otherwise the finding must remain `Hypothesis`,
     and its reworded text must not state a stronger factual conclusion
     than the evidence supports.
   - `Hypothesis` — a plausible behavior inferred from code analysis where any
     part of the reasoning chain (e.g. an intermediate transformation,
     assignment, or normalization step the conclusion depends on, or the
     file/function/library itself) is NOT directly shown in the evidence
     above, and would need validation to confirm.
   - `Hardening` — a security idea unrelated to the specific vulnerability
     described in the advisory (defense-in-depth, other headers, other
     mechanisms not implicated by this advisory).

4. **Check the full batch for contradictions** before finalizing any
   `Observed` classification. If two findings reach mutually incompatible
   conclusions about the same underlying mechanism, value, transformation,
   or comparison, evaluate them together rather than in isolation. If the
   evidence shown above does not unambiguously establish which of the two
   conclusions is correct, neither one may be classified `Observed` —
   reclassify both as `Hypothesis`. This check applies in addition to, not
   instead of, the `Observed` requirement above: a finding can still fail to
   qualify as `Observed` on its own even when no other finding contradicts
   it.

5. **Reword** it so the certainty of the sentence matches its group:
   - `Observed` findings may state what the evidence shows directly.
   - `Hypothesis` findings must use conditional/hedged language ("may",
     "could", "if X does not do Y, then Z may happen") rather than asserting
     an outcome as if it were observed. Do not state a hypothesis as a fact.
     A finding reclassified under the contradiction check above must also
     make clear that a related finding reaches the opposite conclusion and
     that the available evidence does not establish which one is correct.
   - `Hardening` findings must make explicit that they are unrelated to the
     current advisory's scope, and must not be worded as if they weaken
     confidence in the proposed patch (no "however", "but", "still fails to"
     framing — these are suggestions, not shortcomings).

Do not invent new findings. Do not drop any finding. Every input finding must
appear exactly once in your output, in the same order given.

Return your answer as a numbered list, one block per input finding, in this
exact format (repeat for every finding, in order):

1. Claims:
   - <one factual dependency the conclusion requires, one per line>
   - <another factual dependency, if any>
   Unresolved: none
   Remediation impact: <proof_required|validation_only|unclear>
   Group: <Observed|Hypothesis|Hardening>
   Reworded: <the reworded finding, one paragraph, no line breaks>

2. Claims:
   - <one factual dependency the conclusion requires, one per line>
   Unresolved: <the unresolved dependency, or several separated by semicolons>
   Remediation impact: <proof_required|validation_only|unclear>
   Group: <Observed|Hypothesis|Hardening>
   Reworded: <the reworded finding, one paragraph, no line breaks>

Write exactly `Unresolved: none` when every listed dependency is established
by the supplied evidence — including a dependency your own Claims above
already establish, per the consistency check in step 1. Otherwise, after
`Unresolved:`, list the dependency or dependencies that are not
established, separated by semicolons, on a single line. `Remediation
impact:` always comes immediately after `Unresolved:`, on its own line,
before `Group:`. Whenever `Unresolved: none` applies, `Remediation impact:`
must be `validation_only` — an empty Unresolved list leaves nothing on
this axis to block on. Do not include any other content, headers, or
commentary outside this list.

Example input findings:

1. Users relying on Cookie persistence across redirects will experience breakage.
2. Redirects within the same origin still strip Cookie.
3. The Proxy-Authorization header is not included in the default strip list.
4. The mechanism's cross-origin comparison scope (does it consider scheme and
   port, or host only) is not shown in the supplied evidence.

Example output:

1. Claims:
   - Cookie persistence across redirects is not addressed by this patch.
   - An application relies on that persistence.
   Unresolved: whether any application in this codebase relies on Cookie persistence across redirects
   Remediation impact: validation_only
   Group: Hypothesis
   Reworded: Applications relying on Cookie persistence across redirects may require validation.

2. Claims:
   - Redirect stripping treats same-origin and cross-origin redirects identically.
   Unresolved: whether redirect stripping distinguishes same-origin from cross-origin redirects
   Remediation impact: proof_required
   Group: Hypothesis
   Reworded: If redirect stripping does not distinguish same-origin from cross-origin redirects, same-origin redirects may also strip Cookie.

3. Claims:
   - The Proxy-Authorization header is not in the default strip list.
   Unresolved: none
   Remediation impact: validation_only
   Group: Hardening
   Reworded: The Proxy-Authorization header is not covered by this advisory; adding it to the default strip list would be a separate, unrelated hardening improvement.

4. Claims:
   - The claimed remediation mechanism strips the header only on a
     cross-origin redirect, determined by the comparison scope.
   Unresolved: whether the comparison scope considers scheme and port or host only
   Remediation impact: proof_required
   Group: Hypothesis
   Reworded: If the comparison scope only considers host and not scheme/port, a same-host but cross-scheme or cross-port redirect may not be treated as cross-origin, and the header may not be stripped when it should be.

Findings 2 and 4 above illustrate why `Remediation impact` is independent of
whatever wording a finding happens to use: both name an unresolved
comparison-scope dependency the claimed mechanism's correctness rests on,
so both are `proof_required` — regardless of whether the finding is phrased
as a plain observation, a "cannot verify" statement, or a "depends on ...
not shown" statement.

Contrastive example — evidence sufficiency (same dependency, different
evidence):

Example input findings:

1. The caller's correctness depends on whether helper function `is_valid(x)`
   returns True only for well-formed input; only the caller is shown,
   `is_valid` itself is not.
2. The caller's correctness depends on whether helper function `is_valid(x)`
   returns True only for well-formed input; the full implementation of
   `is_valid` is shown and returns True only when `x` passes an explicit
   format check.

Example output:

1. Claims:
   - The caller relies on `is_valid(x)` returning True only for well-formed input.
   Unresolved: whether `is_valid` actually returns True only for well-formed input
   Remediation impact: proof_required
   Group: Hypothesis
   Reworded: The caller relies on `is_valid` to reject malformed input; `is_valid`'s own implementation was not shown, so whether it actually does so is unconfirmed.

2. Claims:
   - `is_valid`'s own implementation is shown and returns True only when `x` passes an explicit format check.
   Unresolved: none
   Remediation impact: validation_only
   Group: Hypothesis
   Reworded: The shown implementation of `is_valid` returns True only when `x` passes an explicit format check, so the caller's reliance on that behavior is no longer an open dependency.

These two findings name the SAME dependency on `is_valid`'s behavior; the
only difference is whether `is_valid`'s own implementation was actually
shown. Finding 1 correctly stays `proof_required` because the
implementation is absent — there is nothing to check the claim against.
Finding 2 correctly resolves to `Unresolved: none` / `validation_only`
only because the shown implementation itself establishes the answer —
never because the caller looked reasonable, because the dependency seemed
minor, or because nothing else contradicted it. `Group` is deliberately
`Hypothesis` in both findings above: resolving this one dependency changes
only whether it blocks remediation proof, never, by itself, whether the
finding's own broader claim counts as directly demonstrated.

Contrastive example — remediation scope (same unresolved dependency, two
different supplied Security Invariants):

Example input (Case A) — supplied Security Invariant: "All input reaching
`handle(x)`, including input routed through the `mode="compat"` code path,
must be sanitized by `sanitize(x)` before use."

1. The caller's correctness depends on whether `sanitize(x)` is applied when
   `handle(x)` is called with `mode="compat"`; only the `mode="default"` code
   path's call to `sanitize(x)` is shown in the supplied evidence.

Example output:

1. Claims:
   - `handle(x)` calls `sanitize(x)` on the `mode="default"` code path.
   - The supplied Security Invariant requires sanitization for input routed through `mode="compat"` as well.
   Unresolved: whether `handle(x)` applies `sanitize(x)` when called with `mode="compat"`
   Remediation impact: proof_required
   Group: Hypothesis
   Reworded: `handle(x)`'s `mode="compat"` code path was not shown, so whether it applies `sanitize(x)` before use is unconfirmed; the supplied Security Invariant requires sanitization on this path, so this remains an open remediation question.

Example input (Case B) — same unresolved dependency, a different supplied
Security Invariant: "Input reaching `handle(x)` through its `mode="default"`
code path must be sanitized by `sanitize(x)` before use." (The supplied
evidence says nothing about `mode="compat"`.)

1. The caller's correctness depends on whether `sanitize(x)` is applied when
   `handle(x)` is called with `mode="compat"`; only the `mode="default"` code
   path's call to `sanitize(x)` is shown in the supplied evidence.

Example output:

1. Claims:
   - `handle(x)` calls `sanitize(x)` on the `mode="default"` code path.
   - The supplied Security Invariant is stated only in terms of the `mode="default"` path; it says nothing about `mode="compat"`.
   Unresolved: whether `handle(x)` applies `sanitize(x)` when called with `mode="compat"`
   Remediation impact: validation_only
   Group: Hypothesis
   Reworded: `handle(x)`'s `mode="compat"` code path was not shown, so whether it applies `sanitize(x)` before use is unconfirmed; the supplied Security Invariant does not establish this path as part of the required remediation, so resolving this does not affect whether the claimed remediation is established — it may still be worth validating separately.

These two findings name the SAME unresolved dependency — whether
`mode="compat"` applies `sanitize(x)` — worded identically. The only
difference is what the supplied Security Invariant establishes as in scope:
Case A's invariant explicitly names the `mode="compat"` path as required, so
the same open question blocks; Case B's invariant is stated only for
`mode="default"` and never mentions `mode="compat"`, so the same open
question does not block — it is flagged for the reviewer instead. Never
decide this from the word "compat" itself, from whether `mode="compat"`
sounds like an unusual or advanced option, or from any general assumption
that a non-default code path is out of scope — the decision comes only from
what the supplied Security Invariant actually states. `validation_only`
here does not mean the `mode="compat"` behavior is safe, false, resolved, or
unimportant — only that resolving it is not required to establish the
claimed remediation against Case B's supplied Security Invariant.

If the supplied Security Invariant is silent or ambiguous about whether a
scenario like `mode="compat"` is required — rather than clearly excluding
it, as in Case B — the same dependency stays `proof_required`: scope
ambiguity is never resolved by downgrading to `validation_only`.

Contrastive example — existing predicate the patch does not modify (same
unresolved dependency and the same supplied evidence, two different supplied
Security Invariants):

Example input (Case A) — supplied Security Invariant: "A request must not
be dispatched to a destination outside the allowed set, as determined by
`is_allowed_destination(dest)`." The patch changes how the allowed set is
constructed; it does not modify `is_allowed_destination` itself.

1. The claimed remediation's correctness depends on `is_allowed_destination`
   rejecting a destination that merely shares a suffix with an allowed
   entry; `is_allowed_destination`'s own comparison logic (exact match vs.
   suffix match) is not shown in the supplied evidence.

Example output:

1. Claims:
   - The claimed remediation strips access via `is_allowed_destination(dest)`.
   - The Security Invariant defines the allowed boundary as whatever `is_allowed_destination` determines, without independently specifying exact-match vs. suffix-match semantics.
   Unresolved: whether `is_allowed_destination` performs exact-match or suffix-match comparison
   Remediation impact: validation_only
   Group: Hypothesis
   Reworded: `is_allowed_destination`'s own comparison logic was not shown, so whether it uses exact-match or suffix-match is unconfirmed; the Security Invariant defines the allowed boundary in terms of this existing, unmodified predicate rather than independently requiring a specific comparison mode, so this does not affect whether the claimed remediation is established — it may still be worth validating separately.

Example input (Case B) — same unresolved dependency and the same supplied
evidence as Case A (`is_allowed_destination`'s own implementation is still
not shown), but a different supplied Security Invariant: "the allowed-set
check must reject any destination sharing a suffix with a blocked entry."

1. The claimed remediation's correctness depends on `is_allowed_destination`
   rejecting a destination that merely shares a suffix with an allowed
   entry; `is_allowed_destination`'s own comparison logic (exact match vs.
   suffix match) is not shown in the supplied evidence.

Example output:

1. Claims:
   - The claimed remediation strips access via `is_allowed_destination(dest)`.
   - The Security Invariant explicitly requires the allowed-set check to reject suffix-sharing destinations, making `is_allowed_destination`'s own comparison mode part of the required remediation.
   Unresolved: whether `is_allowed_destination` performs exact-match or suffix-match comparison
   Remediation impact: proof_required
   Group: Hypothesis
   Reworded: The Security Invariant explicitly requires the allowed-set check to reject destinations sharing a suffix with a blocked entry, making `is_allowed_destination`'s own comparison mode part of the required remediation; its implementation was not shown, so this remains an open remediation question.

These two findings name the SAME unresolved dependency about an existing,
unmodified predicate's own comparison semantics. Case A's Security Invariant
merely defines the allowed boundary BY REFERENCE to `is_allowed_destination`
— it does not itself require a specific comparison mode, so the predicate's
own broader semantics are not part of the remediation proof; the finding is
`validation_only`. Case B's Security Invariant explicitly names the
predicate's own comparison mode as a required property, so the identical
unresolved dependency becomes `proof_required`. Never decide this from
whether `is_allowed_destination` "sounds like" it should be trusted, and
never assume an unmodified predicate is automatically correct merely
because the patch does not touch it — the decision comes only from what the
supplied Security Invariant and evidence actually establish about that
predicate's role. A concrete, evidence-backed contradiction (e.g. verified
evidence showing the predicate does the opposite of what an in-scope
invariant requires) is `proof_required` regardless of which case applies.

If the supplied Security Invariant, vulnerability description, or verified
evidence does not clearly establish whether `is_allowed_destination`'s own
broader comparison semantics are outside the required remediation, the
uncertainty remains `proof_required` — never `validation_only` merely
because the predicate already existed, because the patch does not modify
it, or because the invariant merely mentions it by name. `validation_only`
applies only when the supplied contract clearly defines the relevant
boundary by reference to that existing predicate and does not independently
require the broader property being questioned; genuine scope ambiguity is
never resolved by downgrading to `validation_only`, exactly as in the
`mode="compat"` contrastive example above.

Contrastive example — explicit non-default caller configuration (same
unresolved dependency, two different supplied Security Invariants):

Example input (Case A) — supplied Security Invariant: "By default,
`fetch(url)` must call `validate(url)` before dispatching the request."

1. A caller can invoke `fetch(url, skip_validation=True)`, an explicit,
   non-default parameter that bypasses the call to `validate(url)`; whether
   this is acceptable is not addressed by the supplied evidence.

Example output:

1. Claims:
   - `fetch(url, skip_validation=True)` bypasses the call to `validate(url)`.
   - `skip_validation=True` is an explicit, non-default argument a caller must deliberately supply.
   - The Security Invariant is stated only for the default path (no `skip_validation` argument).
   Unresolved: whether the required validation still applies when a caller passes `skip_validation=True`
   Remediation impact: validation_only
   Group: Hypothesis
   Reworded: A caller can bypass `validate(url)` by explicitly passing `skip_validation=True`; the supplied Security Invariant is stated only for the default path and does not address this explicit, non-default configuration, so resolving this does not affect whether the claimed remediation is established — it may still be worth validating separately.

Example input (Case B) — same unresolved dependency, a different supplied
Security Invariant: "`fetch(url)` must call `validate(url)` before
dispatching the request, including when called with `skip_validation=True`
for cached or pre-trusted callers."

1. A caller can invoke `fetch(url, skip_validation=True)`, an explicit,
   non-default parameter that bypasses the call to `validate(url)`; whether
   this is acceptable is not addressed by the supplied evidence.

Example output:

1. Claims:
   - `fetch(url, skip_validation=True)` bypasses the call to `validate(url)`.
   - The Security Invariant explicitly requires validation to still apply when `skip_validation=True` is passed.
   Unresolved: whether the required validation still applies when a caller passes `skip_validation=True`
   Remediation impact: proof_required
   Group: Hypothesis
   Reworded: A caller can bypass `validate(url)` by explicitly passing `skip_validation=True`; the supplied Security Invariant explicitly extends the required validation to this configuration, so whether it still applies here remains an open remediation question.

These two findings name the SAME unresolved dependency about an explicit,
non-default caller configuration. Case A's Security Invariant covers only
the default path and says nothing about `skip_validation`, so the bypass
sits outside the required remediation and is `validation_only`; Case B's
Security Invariant explicitly extends the requirement to that same
configuration, so the identical dependency becomes `proof_required`. Never
decide this from the word "skip_validation" itself, from whether the
parameter name sounds like a shortcut, or from any general assumption that
a non-default configuration is automatically out of scope, or automatically
in scope — the decision comes only from what the supplied Security
Invariant and evidence actually establish. If the Security Invariant were
silent or ambiguous about `skip_validation` rather than clearly excluding
it, the same dependency would stay `proof_required`, exactly as in the
`mode="compat"` contrastive example above.
