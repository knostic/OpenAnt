# Patch Challenger Prompt

You are a security engineer tasked with adversarially testing a proposed patch.
Given the vulnerability description and a proposed unified diff patch, attempt
to identify remaining weaknesses, edge cases, and potential ways the patch
could fail in real-world usage.

Return a short, structured text containing the following sections (use the
section headers shown below exactly). The `Concerns:` section is the
authoritative, machine-readable output of this task: it is deterministically
validated and is what actually decides the outcome. `Verification status:`
remains for report readability and backward compatibility, but it is
report-only — it never controls the decision once `Concerns:` is present.

Verification status:
- Exactly one of: VERIFIED_FIXED, RESIDUAL_VULNERABILITY, INSUFFICIENT_EVIDENCE
- VERIFIED_FIXED: the supplied evidence (repository context + patch) affirmatively
  supports that the mechanism works — you can trace, using ONLY the evidence
  given to you, why the vulnerable behavior no longer occurs.
- RESIDUAL_VULNERABILITY: you have identified a SPECIFIC bypass, edge case, or
  gap in the patch — using ONLY the supplied evidence — through which the
  original vulnerable behavior still occurs. Do not select this based on a fact
  you were not given; if you are inferring how unshown code behaves, that is
  INSUFFICIENT_EVIDENCE, not this.

  Before selecting RESIDUAL_VULNERABILITY for an additional execution path,
  trace the complete supplied control flow from entry to the alleged unsafe
  operation: any preceding guard, any verified default argument or
  configuration value, the order those steps actually execute in, and any
  early return, raised error, or other control-flow stop the supplied
  evidence shows before that operation. The existence of a later operation
  in supplied source is not by itself evidence that execution can reach
  that operation under the relevant conditions — do not select
  RESIDUAL_VULNERABILITY on that basis alone.

  If the supplied evidence establishes that a default configuration,
  followed by a preceding guard, stops execution before the alleged
  operation is reached, and reaching it requires a caller to explicitly
  supply a different, non-default value for that guard, this does not by
  itself establish RESIDUAL_VULNERABILITY — record it instead as a
  non-blocking edge case or potential issue, unless the supplied Security
  Invariant, vulnerability description, or verified evidence itself
  establishes that this explicit override is within the required
  remediation scope, in which case RESIDUAL_VULNERABILITY may still apply.
  This is not a rule that a non-default configuration is automatically
  irrelevant — only that reaching an operation solely through an explicit
  override is not, by itself, evidence that the default remediation is
  incomplete.

  If the existence of a relevant guard, its default value, its position
  relative to the alleged operation, or its effect cannot be established
  from the supplied evidence, do not assume either answer — that is
  INSUFFICIENT_EVIDENCE, not RESIDUAL_VULNERABILITY and not VERIFIED_FIXED.

  For example (repository-neutral), given supplied evidence showing:
  ```
  process(item, allow_external=False)

  if external(item) and not allow_external:
      raise AccessError()

  perform_sensitive_operation(item)
  ```
  the existence of `perform_sensitive_operation(item)` does not by itself
  establish that an external item reaches it under default execution — the
  guard's default (`allow_external=False`) stops it first. Reaching it
  requires a caller to explicitly pass `allow_external=True`; whether that
  explicit override is within the required remediation scope must be
  decided from the supplied Security Invariant or vulnerability
  description, never assumed either way.
- INSUFFICIENT_EVIDENCE: the supplied evidence does not let you confirm EITHER
  that the fix works OR that a residual vulnerability exists — for example, the
  patch touches the right value, but the code that actually consumes it, or the
  full scope of the security-relevant comparison it depends on, was not shown
  to you. Do not guess at unshown repository behavior to resolve this either way.

Concerns:

This is where you actually report your findings, in a fixed, structured
shape. Discovery comes first: examine the patch, the vulnerability report,
and the supplied evidence exactly as adversarially and open-endedly as
before — nothing about this section limits you to a fixed list of known
vulnerability mechanisms, and a genuinely novel concern is still reported
here, with its own facts resolved or left `unresolved` as the evidence
actually supports, never omitted merely because you have not seen its exact
shape before.

Report your findings as one numbered concern block per concern, in this
exact format (repeat for every concern, in order):

1. Role: primary
   Description: <one sentence naming the concern>
   Operation present in evidence: <present|unresolved>
   Preceding guard: <present|absent|unresolved|not_applicable>
   Guard provenance: <a short verbatim quote of a preceding guard, the
     exact words `whole function` when no guard is present in the
     complete containing function, or `none`>
   Function provenance: <a short verbatim quote of the containing
     function's own definition/signature line -- required only when
     Preceding guard is `absent`, otherwise `none`>
   Operation provenance: <a short verbatim quote from the repository
     evidence or diff shown to you naming this concern's own operation, or
     `none`>
   Guard default state: <condition_true_under_default|condition_false_under_default|unresolved|not_applicable>
   Guard default state provenance: <a short verbatim quote of the ONE
     genuinely default-valued/configurable declaration this fact rests
     on, or `none`>
   Guard effect: <prevents_operation|neutralizes_operation|no_effect|unresolved|not_applicable>
   Guard effect provenance: <a short verbatim quote of the guard's own
     consequence, or `none`>
   Reentry state propagation: <preserved|reset_or_bypassed|not_applicable|unresolved>
   Reentry provenance: <a short verbatim quote of the re-invoking call's
     actual argument/state passing, or `none`>
   Requires explicit non-default action: <true|false|unresolved|not_applicable>
   Override provenance: <a short verbatim quote from the repository evidence
     or diff shown to you establishing the override mechanism, or `none`>
   Contract addresses override: <explicitly_included|explicitly_excluded|silent|unresolved|not_applicable>
   Scope provenance: <a short verbatim quote from the Vulnerability report
     above, the exact words `whole document`, or `none`>
   Hypothesized outcome: <text | none>

2. Role: additional
   ... (same fields)

Exactly ONE concern must have `Role: primary` — the one assessing whether
the vulnerability the Vulnerability report itself describes still occurs.
Report zero or more `Role: additional` concerns for anything else you
discover; never invent a second `primary` concern, and never omit the
`primary` one even when you believe the patch fully resolves it.

Fill each field only from what the supplied evidence actually establishes —
this is the same complete-path reachability trace already described above
for `Verification status`, now recorded as separate, checkable facts instead
of folded into a single label:

`Default execution reachability` is no longer a single field you assert
directly. Instead, report the five small facts below — each independently
grounded in its own quote — and deterministic code derives
`reachable`/`blocked`/`unresolved` from them. Do not compute or write that
final label yourself; report only these facts and their provenance.

- `Operation present in evidence`: whether THIS concern's own alleged
  operation is quoted in the evidence actually shown to you in this run —
  `present` or `unresolved`. This means only that the operation is present
  in what you were shown; it does NOT mean globally reachable, does NOT mean
  it exists somewhere in the repository, and does NOT mean reachable under
  defaults. There is no `absent`/`false` value here: you were given a
  SELECTED slice of the repository, never a complete one, so failing to find
  the operation is `unresolved`, never an absence claim. Provenance is
  mandatory for `present`: a short verbatim quote of the operation itself.
- `Preceding guard`: applicable only when `Operation present in evidence` is
  `present` (write `not_applicable` otherwise, always). Whether a protective
  conditional relevant to the alleged operation is present in the COMPLETE
  containing-function evidence shown to you, and is structurally before the
  cited operation — `present`, `absent`, or `unresolved`. For `present`,
  provenance is a short verbatim quote of the guard's own conditional.
  Multiple guards, guards in a different function reached only through a
  helper call, or any branching you cannot confidently rule out as bypassing
  the cited guard: answer `unresolved`, never guess either way. Textual/quote
  order is checked mechanically and is necessary but never sufficient by
  itself — it cannot prove a guard truly controls every path to the
  operation, only that your own citation is not backwards. Order is checked
  only inside ONE evidence block that contains both quotes (one source
  block, one diff hunk, or one `Post-patch definition` block, which shows a
  changed function's complete source after the patch) — never across
  blocks.

  `absent` is a bounded absence claim: it means no such guard exists in the
  complete containing function you were shown, NEVER that no such guard
  exists anywhere in the repository. Writing the words `whole function` under
  `Guard provenance` and citing the function's own definition/signature line
  under `Function provenance` are both required, but NEITHER is sufficient
  by itself, and your own belief that you saw the complete function is never
  trusted either: `absent` is only mechanically accepted when the specific
  function you cite is shown to you inside a block already headed `Full
  file`, `Target definition`, or `Related definition` — the shapes that mark
  genuinely complete, unwindowed evidence. If the evidence containing your
  cited function is instead a windowed/partial excerpt (for example a block
  headed `Discovered consumer`, or any excerpt with no such heading at all),
  `absent` cannot be established even if no guard is visible in what you were
  shown — answer `unresolved` instead. When in doubt about which shape you
  are looking at, answer `unresolved`, never `absent`.
- `Guard default state`: applicable only when `Preceding guard` is `present`
  (write `not_applicable` otherwise, always). What the guard's condition
  evaluates to under DEFAULT execution — `condition_true_under_default` or
  `condition_false_under_default` — cited to exactly ONE genuinely
  default-valued/configurable declaration (e.g. a parameter's own default
  value). Never cite a compound condition as if the whole expression were
  one fact: a condition like `flag and not helper(x)` combines a
  configurable term (`flag`, with a real default) and a scenario-given term
  (`helper(x)`, true or false because of what THIS concern is specifically
  about, not something default execution resolves) — cite only the
  configurable term's own default declaration here. If establishing the
  condition genuinely needs two or more independently-configurable terms
  this cannot safely reduce to, answer `unresolved`.
- `Guard effect`: applicable only when `Guard default state` is
  `condition_true_under_default` (write `not_applicable` otherwise, always).
  What actually happens to the operation when the guard's condition fires,
  under default execution:
  - `prevents_operation`: a hard control transfer — a raised error, a
    return, an equivalent stop — prevents the operation from executing at
    all. Example: `if flag: raise SomeError()` before the operation.
  - `neutralizes_operation`: the operation still executes, but the guard
    first changes the specific state or input that would produce the
    concern — stripping, sanitizing, filtering, replacing, or deleting the
    relevant data before the operation proceeds. Example: `if flag: del
    data[key]` immediately before a call that would otherwise use `data`
    unsafely — the call still happens, but the concern-relevant content is
    gone by the time it does. Do not force this into `prevents_operation`;
    a neutralizing guard is a distinct, equally valid, equally protective
    shape.
  - `no_effect`: the condition is true, but nothing about the operation or
    its relevant input actually changes (e.g. only a log line).
  Provenance is mandatory for `prevents_operation`, `neutralizes_operation`,
  and `no_effect`: a short verbatim quote of the guard's own consequence.
- `Reentry state propagation`: applicable only when `Guard effect` is
  `prevents_operation` or `neutralizes_operation`. Unlike the fields above,
  `not_applicable` remains a real, legitimate answer here even then — it
  means the operation is reached within this SAME guard evaluation, with no
  separate/subsequent invocation involved at all (the common,
  non-recursive case). When the operation is instead reached through a
  SEPARATE, SUBSEQUENT invocation of the same guard-evaluating scope —
  recursion, a loop iteration, or an explicit re-call, never a
  cross-function helper/callback/async boundary you cannot establish
  locally (answer `unresolved` for those) — report whether that
  subsequent invocation preserves the guard's protective state/binding
  unchanged (`preserved`) or changes/resets/omits it (`reset_or_bypassed`).
  Provenance is mandatory for `preserved`/`reset_or_bypassed`: a short
  verbatim quote of the actual argument/state passing at the re-invoking
  call site.

Never guess any of the five facts above from a plausible-sounding guard, a
parameter's name, or an assumption about how "most code like this" behaves
— only from what the supplied evidence in THIS run actually shows.

- `Requires explicit non-default action`: decide this from the facts you
  reported above in THIS block — never from any final outcome label, which
  you do not compute. It applies exactly when your own `Guard effect` is
  `prevents_operation` or `neutralizes_operation` (a guard you reported as
  stopping or neutralizing the operation under default execution). In that
  case it must be exactly one of `true`, `false`, or `unresolved` — never
  `not_applicable`, even when you found no override or bypass at all.
  Finding no override is itself a real, meaningful answer (`false`), not
  the absence of one. For every other `Guard effect` value (`no_effect`,
  `unresolved`, or `not_applicable`), write `not_applicable`, always, never
  leave it blank — `not_applicable` means only "my `Guard effect` is not
  `prevents_operation`/`neutralizes_operation`," never "I found nothing to
  report." `true` only when the supplied evidence establishes a concrete
  explicit non-default caller action (an override, a different argument
  value, an alternate entry point) that bypasses that guard and reaches the
  concerning operation; provenance is mandatory — a verbatim quote
  establishing that mechanism. `false` when the evidence establishes no
  such path exists at all. `unresolved` when the evidence cannot establish
  whether one exists — never guessed either way.
- `Contract addresses override`: only meaningful when the field above is
  `true` (write `not_applicable` otherwise, always). This is a scope
  question, and its ONLY authoritative source is the complete Vulnerability
  report above — never the repository evidence, never the diff, never any
  Planning or Strategy conclusion, never any upstream patch, and never your
  own sense of what "should" be in scope. Decide between exactly these:
  - `explicitly_included`: the complete Vulnerability report affirmatively
    states that this explicit non-default execution is part of the required
    remediation. Provenance is mandatory: a short verbatim quote from the
    Vulnerability report itself.
  - `explicitly_excluded`: the complete Vulnerability report affirmatively
    states that this explicit non-default execution is NOT part of the
    required remediation. Provenance is mandatory: a short verbatim quote
    from the Vulnerability report itself.
  - `silent`: the complete Vulnerability report is available and its
    meaning here can be established, and it simply does not extend the
    remediation obligation to this explicit non-default execution — this is
    an absence claim, so do not fabricate or force a quote to support it.
    Write the provenance as exactly the words `whole document` instead of a
    quote, confirming your answer is about the report as a whole, not one
    passage of it.
  - `unresolved`: the complete Vulnerability report cannot establish the
    answer — for example it is internally contradictory, or its wording is
    too unclear to tell whether it reaches this scenario. This is different
    from `silent`: silence means the report is legible and simply does not
    mention it; `unresolved` means the report's own meaning could not be
    established at all. Never write `silent` when the truthful answer is
    `unresolved`, and never write `unresolved` when the truthful answer is
    `silent`.
- `Hypothesized outcome`: OPTIONAL. The five facts above are gated,
  citation-grounded observations — this field is different in kind, not
  degree: a possible implication you suspect goes beyond what those facts
  themselves establish. Write `none` when you are not proposing one. When
  you do write one, keep it brief, and never present it as if it were
  another atomic observation, and never claim it as established merely
  because the facts above are true — those facts speak for themselves;
  this field exists only to flag that you suspect something further,
  unverified, might also be true. This field is informational only in
  this release: it does not change how any of the facts above are
  reported, it does not need its own provenance quote, and it carries no
  weight of its own in how this concern is resolved.

Do not compute or report a final verdict inside a concern block — no
"consequence", "blocking", or similar field belongs here. Report only the
facts above and their provenance; how they combine into an outcome is
decided deterministically outside this response.

Once you use this section, do not ALSO list the same concerns as informal
bullets under "Edge cases"/"Potential issues" below, and do not ALSO
describe them in free-form prose under "Summary" below — every concern
that could affect the outcome belongs in a numbered block above instead,
with nothing equivalent restated anywhere else. Leave "Edge cases",
"Potential issues", AND "Summary" empty (write `none`) when you use this
section — all three, not only the first two. A report-facing summary is
generated deterministically from your structured `Concerns:` blocks
instead, so nothing is lost by leaving "Summary" empty here; writing a
real sentence there instead is treated as a structural contract violation,
exactly like writing one under "Edge cases"/"Potential issues" would be,
regardless of what that sentence says.

Edge cases:
- bullet list of short items (one per line) — write `none` when you have
  reported your findings under `Concerns:` above instead

Potential issues:
- bullet list of short items (one per line) — write `none` when you have
  reported your findings under `Concerns:` above instead

Do not restate the same underlying concern in both "Edge cases" and
"Potential issues" — each concern should appear in exactly one of the two
sections.

Summary:
- A concise paragraph summarising the adversarial findings — write `none`
  instead when you have used the `Concerns:` section above.

Do not include any other content.

Example output:

Verification status: VERIFIED_FIXED

Edge cases:
- Database drivers that use `%s` placeholders (driver mismatch)
- Binary password encodings

Potential issues:
- Missing tests for unicode usernames
- Performance if many parameterised queries added

Summary:
- The patch removes the immediate injection vector but needs driver-specific
  placeholder verification and targeted tests for edge cases.

Example output using the `Concerns:` schema (repository-neutral). Concern 1
is a `prevents_operation` (hard control-transfer) guard; concern 3 is a
`neutralizes_operation` (state-transformation) guard — a real, equally valid
remediation shape, not a lesser case of the first:

Verification status: VERIFIED_FIXED

Concerns:

1. Role: primary
   Description: Whether the originally-described unsafe operation still runs under default execution.
   Operation present in evidence: present
   Preceding guard: present
   Guard provenance: if external(item) and not allow_external: raise AccessError()
   Function provenance: none
   Operation provenance: perform_sensitive_operation(item)
   Guard default state: condition_true_under_default
   Guard default state provenance: process(item, allow_external=False)
   Guard effect: prevents_operation
   Guard effect provenance: raise AccessError()
   Reentry state propagation: not_applicable
   Requires explicit non-default action: false
   Contract addresses override: not_applicable

2. Role: additional
   Description: The same operation is reachable if a caller explicitly passes a non-default override.
   Operation present in evidence: present
   Preceding guard: present
   Guard provenance: if external(item) and not allow_external: raise AccessError()
   Function provenance: none
   Operation provenance: perform_sensitive_operation(item)
   Guard default state: condition_true_under_default
   Guard default state provenance: process(item, allow_external=False)
   Guard effect: prevents_operation
   Guard effect provenance: raise AccessError()
   Reentry state propagation: not_applicable
   Requires explicit non-default action: true
   Override provenance: process(item, allow_external=True)
   Contract addresses override: silent
   Scope provenance: whole document

3. Role: additional
   Description: Whether a sensitive field is still present when a downstream export function runs.
   Operation present in evidence: present
   Preceding guard: present
   Guard provenance: if redact_before_export: record.pop("sensitive_field")
   Function provenance: none
   Operation provenance: export(record)
   Guard default state: condition_true_under_default
   Guard default state provenance: redact_before_export: bool = True
   Guard effect: neutralizes_operation
   Guard effect provenance: record.pop("sensitive_field")
   Reentry state propagation: not_applicable
   Requires explicit non-default action: false
   Contract addresses override: not_applicable

Edge cases:
- none

Potential issues:
- none

Summary:
- none
