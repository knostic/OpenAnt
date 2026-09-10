"""
Planner Claim Verifier.

Provides `verify_planner_claim(...)`: one bounded LLM call that answers
exactly one of two mutually-exclusive, explicitly-dispatched questions
about the Planner's own `narrower_alternative_considered` claim, chosen by
the caller's `mode` argument -- never inferred from the claim's own prose:

  mode="REJECTED" (Mode A -- counterexample validity, the original
  responsibility this module started with): is the Planner's stated reason
  for REJECTING a narrower remediation alternative causally consistent
  with the verified source evidence the Planner itself was given, once
  that narrower alternative is hypothetically applied?

  mode="SELECTED" (Mode B -- decision coherence): when the Planner instead
  SELECTED a narrower alternative, do the authoritative
  `remediation_mechanism`/`required_edits` actually describe that same
  selected alternative, rather than a different (typically broader)
  mechanism left over from before the decision was made? This is strictly
  a same-scope coherence check -- never a judgment about whether the
  mechanism is globally correct, optimal, or better than some third
  option (see prompts/remediation_verifier.md's own "must not" list for
  both modes).

There is no mode for `narrower_alternative_decision == "NONE_IDENTIFIED"`:
the caller (pipeline.py) never invokes this module at all in that case --
there is no rejection claim to validate and no selected alternative to
check for coherence, so there is nothing for either mode to ask about.

This module owns exactly these two questions -- see
prompts/remediation_verifier.md's own "must not" list. It does not
generate a patch, does not design a new remediation, does not redo
Repository Understanding or the Planner, and does not act as a general
Challenger (patch_challenger.py is a deliberately different, later,
diff-centric mechanism this module does not reuse or modify -- there is no
patch yet at this point in the pipeline).

Orchestration -- the bounded verify -> one revision -> re-verify cycle,
which mode applies to each of those two calls, and what happens to
Strategy/`_skip_patch_generation` when a contradiction survives that one
revision -- lives entirely in pipeline.py, not here. This module stays a
pure, single-purpose check, the same "keep the verifier itself pure; a
caller one layer up decides what to do with disagreement" split
`existing_test_amendment.py` already uses for its own comparator.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import NamedTuple

from .llm_client import ModelUnavailableError

_PROMPT_PATH = Path(__file__).parent / "prompts" / "remediation_verifier.md"

_FENCE_RE = re.compile(r"^```(?:json)?\s*\n?(.*?)\n?```$", re.DOTALL)

_VALID_STATUSES = {"SUPPORTED", "CONTRADICTED", "UNRESOLVED"}

_VALID_MODES = {"REJECTED", "SELECTED"}
"""The only two modes this module accepts, chosen by the caller (never
inferred from the Planner's prose) from `RemediationPlanResult.
narrower_alternative_decision` -- see module docstring. Reuses that same
enum vocabulary directly (rather than a second "mode_a"/"mode_b" naming
scheme) so the mapping from Planner decision to verifier question is the
identity function, not a translation the caller could get wrong."""

_DEFAULT_STAGE = "remediation_plan_verification"


class VerifierResult(NamedTuple):
    """One Planner Claim Verifier call's outcome.

    `status`: one of `_VALID_STATUSES`. `CONTRADICTED` is reserved for a
    concrete, externally-checkable contradiction between the Planner's
    counterexample and the verified source -- never mere preference,
    uncertainty, or incomplete evidence (see prompts/remediation_verifier.md).

    `reason`: the model's own concise justification for `status`. Always a
    plain string (never None), so callers/observability never need a
    None-guard.

    `contradiction`: the first concrete contradiction the model cited --
    set only when `status == "CONTRADICTED"`, None otherwise. A response
    that claims CONTRADICTED but supplies no checkable contradiction is
    treated as malformed (see `_parse_response`), never as a real
    CONTRADICTED result -- CONTRADICTED without evidence is exactly the
    "unsupported assertion" this whole mechanism exists to reject.

    `failure_kind`: None for a genuinely evaluated response (whether
    SUPPORTED, CONTRADICTED, or a real semantic UNRESOLVED); "infrastructure"
    when this result exists ONLY because the LLM call or its response
    failed structurally (network/timeout/malformed JSON/missing required
    field). Never inferred from `status` alone -- both currently resolve to
    the SAME pipeline behavior (see pipeline.py's orchestration), so this
    field exists purely for observability, not to create a fourth
    pipeline-visible outcome.

    `evaluated`: True only for a genuinely parsed LLM response -- mirrors
    `RemediationStrategyResult.evaluated` exactly, including why it exists:
    never inferred from `status`/`reason` happening to be non-empty.

    `counterexample_reaches_unsafe_state`: Mode A ("REJECTED") only -- the
    verifier's own structured commitment about whether at least one
    Planner-claimed CONCRETE counterexample, walked through the proposed
    narrower remediation, actually reaches the stated unsafe runtime
    state/effect -- `True`, `False`, or `None` (cannot be determined, or
    there is no genuine concrete counterexample to evaluate at all). This
    exists specifically because a real minimist verifier response walked
    every concrete counterexample the Planner supplied to an explicit
    "neutralized" conclusion in its own prose, then still emitted
    `status="SUPPORTED"` by appealing to unproven "general reasoning"
    about some other, unspecified path -- see `_parse_response`'s Mode A
    SUPPORTED gate, which is the actual enforcement point; this field only
    carries the value that gate reads (and, for CONTRADICTED/UNRESOLVED,
    whatever value survives for observability -- never itself gated for
    those statuses). Always `None` for a Mode B ("SELECTED") result -- a
    Mode B response that populates this field instead of (or in addition
    to) `authoritative_remediation_matches_selected_alternative` answered
    the wrong mode's question and is treated as malformed (see
    `_parse_response`).

    `authoritative_remediation_matches_selected_alternative`: Mode B
    ("SELECTED") only -- the verifier's own structured commitment about
    whether the authoritative `remediation_mechanism`/`required_edits`
    actually describe the same mechanism the Planner's
    `narrower_alternative_considered` says it selected -- `True`, `False`,
    or `None` (cannot be determined). This exists specifically because a
    real minimist Planner response explicitly said it selected a narrower,
    constructor-only guard in `narrower_alternative_considered` while
    `remediation_mechanism`/`required_edits` still described a broader
    constructor-and-prototype mechanism left over from before that
    decision -- an internal inconsistency no amount of free-text
    comparison can safely detect deterministically (two independently-
    phrased descriptions of an equivalent mechanism must not be flagged as
    inconsistent, and two differently-phrased descriptions of a genuinely
    different mechanism must not be waved through); this field is this
    module's own structured, single, LLM-native answer to that exact
    question instead. Gated by `_parse_response`'s Mode B SUPPORTED/
    CONTRADICTED rules exactly as strictly as `counterexample_reaches_
    unsafe_state` gates Mode A. Always `None` for a Mode A ("REJECTED")
    result, for the same reason as above."""

    status: str
    reason: str
    contradiction: "str | None"
    failure_kind: "str | None"
    evaluated: bool
    counterexample_reaches_unsafe_state: "bool | None" = None
    authoritative_remediation_matches_selected_alternative: "bool | None" = None


def _unresolved_infrastructure(reason: str) -> VerifierResult:
    return VerifierResult(
        status="UNRESOLVED", reason=reason, contradiction=None,
        failure_kind="infrastructure", evaluated=False,
    )


def _find_balanced_json_objects(text: str) -> "list[str]":
    """Find every top-level, brace-balanced ``{...}`` substring in `text`,
    respecting JSON string-literal syntax (a ``{``/``}`` inside a quoted
    string value never confuses the depth count) -- but NOT respecting
    intent: a bare, code-formatted ``{}`` sitting in the model's own
    explanatory prose (never inside a JSON string at all) is, syntactically,
    an equally valid top-level balanced object, and this scanner has no way
    to tell it apart from that. Purely syntactic bracket-matching -- no
    JSON parsing, no semantic interpretation, no repair -- so a returned
    substring is only a CANDIDATE; the caller still runs it through
    `json.loads`, and (for this module) a verifier-specific shape check
    (`_has_verifier_shape`), before trusting it.

    Duplicated, byte-for-byte, from test_plan_discovery.py's own
    `_find_balanced_json_objects` -- proven there against a real urllib3
    incident (a model prefacing an otherwise well-formed response with one
    explanatory sentence) and now separately, empirically proven against a
    real minimist Planner Claim Verifier response with the same failure
    shape, PLUS several bare `{}` snippets in its own prose (see this
    module's test fixtures) -- confirming the shape-check step below is
    necessary, not merely defensive.

    Kept as a local duplicate rather than a cross-module import: this is a
    small (~25-line), fully self-contained, dependency-free primitive, and
    this module family already duplicates its other small parsing
    primitives per stage (see `_FENCE_RE`/`_parse_json_response`, already
    duplicated between remediation_planner.py and this module) rather than
    sharing them across otherwise-unrelated canonical stages -- a new
    shared module for one ~25-line function would be more invasive than
    this duplication, not less, and test_plan_discovery.py's own behavior
    stays completely untouched."""
    objects: "list[str]" = []
    depth = 0
    start = None
    in_string = False
    escaped = False
    for i, ch in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth > 0:
            depth -= 1
            if depth == 0 and start is not None:
                objects.append(text[start:i + 1])
                start = None
    return objects


def _has_verifier_shape(parsed) -> bool:
    """The verifier-specific structural discriminator used to disambiguate
    a real candidate from prose-embedded brace noise: a dict with a
    non-empty string `status`. Nothing more -- this is NOT schema
    validation (that is `_parse_response`'s job, unchanged, run afterward
    on whatever this accepts); it exists only to tell "this looks like it
    could be our response at all" apart from a bare `{}` or some other
    object shape a model's own prose happened to contain. A candidate that
    passes this check can still fail `_parse_response`'s own strict checks
    (invalid status, missing reason, CONTRADICTED with no contradiction)
    exactly as before -- this function narrows AMBIGUITY, it does not
    narrow validity."""
    if not isinstance(parsed, dict):
        return False
    status = parsed.get("status")
    return isinstance(status, str) and bool(status.strip())


def _parse_json_response(raw: str) -> "dict | None":
    if not raw or not isinstance(raw, str):
        return None
    text = raw.strip()
    m = _FENCE_RE.match(text)
    if m:
        text = m.group(1).strip()

    # Fast path -- UNCHANGED: the whole (fence-stripped) response parses as
    # JSON on its own. This is the only path taken for a well-formed
    # response, and the only path that existed before this fix.
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        parsed = None
    if isinstance(parsed, dict):
        return parsed

    # Fallback -- only reached when the whole response did NOT parse as
    # JSON on its own (e.g. explanatory prose before the JSON object, the
    # exact shape a real minimist verifier response took). Scan for every
    # top-level, brace-balanced substring and keep only the ones that look
    # like a verifier response at all (_has_verifier_shape) -- this is what
    # tells the real object apart from bare `{}` snippets the model's own
    # prose can otherwise contain. Exactly one surviving candidate is
    # accepted; zero or more than one both fail closed exactly like the
    # pre-fix behavior already did for an unparseable response -- this
    # never selects, merges, or guesses among competing candidates.
    candidates = []
    for substring in _find_balanced_json_objects(text):
        try:
            candidate = json.loads(substring)
        except (json.JSONDecodeError, ValueError):
            continue  # not valid JSON on its own -- e.g. a stray "{" in prose
        if _has_verifier_shape(candidate):
            candidates.append(candidate)

    if len(candidates) == 1:
        return candidates[0]
    return None  # zero or ambiguous (>1) candidates -- fail closed, same as before


def _parse_response(raw: str, mode: str) -> VerifierResult:
    """Strict parse: a well-formed response must be a JSON object with a
    `status` in `_VALID_STATUSES`, a non-empty string `reason`, (only when
    `status == "CONTRADICTED"`) a non-empty string `contradiction`, and a
    mode-specific structured commitment field gated per `mode` -- see the
    per-mode block below. Anything short of that degrades to
    UNRESOLVED/infrastructure. This module never inspects prose downstream
    to recover a policy decision from a response that failed its own
    contract; policy always reads only `.status`/`.failure_kind`, never
    re-parses `.reason`/`.contradiction`.

    `mode` is supplied by the caller (`verify_planner_claim`, itself given
    it by pipeline.py's orchestration, which reads it from the Planner's
    OWN structural `narrower_alternative_decision`) -- never inferred here
    from the response's own prose. Must be one of `_VALID_MODES`; this
    function has no default and no fallback, by design -- a caller passing
    an invalid mode is a programming error in this module family, not a
    verifier-response quality issue, so it is allowed to raise rather than
    silently degrading."""
    if mode not in _VALID_MODES:
        raise ValueError(f"_parse_response called with an invalid mode: {mode!r}")

    plan = _parse_json_response(raw)
    if plan is None:
        return _unresolved_infrastructure("verifier response was not valid JSON")

    status = plan.get("status")
    status = status.strip().upper() if isinstance(status, str) else status
    if status not in _VALID_STATUSES:
        return _unresolved_infrastructure(f"verifier response had an invalid or missing status: {status!r}")

    reason = plan.get("reason")
    reason = reason.strip() if isinstance(reason, str) else ""
    if not reason:
        return _unresolved_infrastructure("verifier response was missing a reason")

    contradiction = plan.get("contradiction")
    contradiction = contradiction.strip() if isinstance(contradiction, str) else None
    if status == "CONTRADICTED" and not contradiction:
        return _unresolved_infrastructure(
            "verifier claimed CONTRADICTED but gave no concrete contradiction"
        )
    if status != "CONTRADICTED":
        contradiction = None

    # Both mode-specific fields -- strict bool-or-None only, for the same
    # reason in both cases. `isinstance(x, bool)` (not truthiness)
    # deliberately excludes every other JSON type INCLUDING 1/0 -- Python's
    # `bool` is a subclass of `int`, but a JSON `1`/`0` deserializes to a
    # plain Python `int`, never a `bool`, so `isinstance(1, bool)` is
    # already False; this is not a workaround, it is simply relying on
    # json.loads' own type mapping. Missing key, explicit `null`, and any
    # wrong type all normalize to the same `None` here -- none of them are
    # a value this module trusts.
    raw_reaches = plan.get("counterexample_reaches_unsafe_state")
    reaches_unsafe_state = raw_reaches if isinstance(raw_reaches, bool) else None
    raw_matches = plan.get("authoritative_remediation_matches_selected_alternative")
    matches_selected = raw_matches if isinstance(raw_matches, bool) else None

    if mode == "REJECTED":
        # Mode A -- counterexample validity. The SELECTED-mode field must
        # be absent: a response that populates it answered Mode B's
        # question while this call asked Mode A's -- that is exactly as
        # untrustworthy as any other malformed response, never silently
        # accepted or silently ignored.
        if matches_selected is not None:
            return _unresolved_infrastructure(
                "verifier response populated the Mode B (selected-alternative) "
                "coherence field while operating in Mode A (rejected-alternative) mode"
            )
        if status == "SUPPORTED" and reaches_unsafe_state is not True:
            # Real minimist evidence: a response can walk every concrete
            # Planner-claimed counterexample to an explicit "neutralized"
            # conclusion in its own prose and still emit status="SUPPORTED"
            # by appealing to unproven "general reasoning" about some
            # other, unspecified path. A SUPPORTED verdict is therefore
            # trustworthy ONLY when the response separately, structurally
            # commits that a concrete counterexample reaches the unsafe
            # state -- missing, null, false, and wrong-type all fail
            # identically (there is exactly one value, the literal boolean
            # `True`, that counts as that commitment). This is NEVER
            # reinterpreted as CONTRADICTED: doing so would fabricate a
            # specific semantic verdict (a real contradiction/
            # counterexample) the response never actually supplied --
            # UNRESOLVED is the only honest outcome for "this response's
            # own claim is unsupported by its own schema."
            return _unresolved_infrastructure(
                "verifier claimed SUPPORTED but did not confirm, via "
                "counterexample_reaches_unsafe_state, that a concrete claimed "
                "counterexample reaches the stated unsafe state"
            )
        # Mode A's CONTRADICTED has no additional requirement on
        # `counterexample_reaches_unsafe_state` -- unchanged, validated
        # semantics: that field is set to `False` for observability when a
        # concrete claimed path was walked and neutralized, but left `null`
        # when the rejection is invalid for some other reason with no
        # concrete path to walk at all (see the prompt's own CONTRADICTED
        # description) -- never itself gated for this status.
        return VerifierResult(
            status=status, reason=reason, contradiction=contradiction,
            counterexample_reaches_unsafe_state=reaches_unsafe_state,
            authoritative_remediation_matches_selected_alternative=None,
            failure_kind=None, evaluated=True,
        )

    # mode == "SELECTED" -- Mode B, decision coherence.
    if reaches_unsafe_state is not None:
        return _unresolved_infrastructure(
            "verifier response populated the Mode A (rejected-alternative) "
            "counterexample field while operating in Mode B (selected-alternative) mode"
        )
    if status == "SUPPORTED" and matches_selected is not True:
        # Mirrors Mode A's SUPPORTED gate exactly, for the same reason: a
        # SUPPORTED coherence verdict is trustworthy ONLY when the response
        # separately, structurally commits that the authoritative fields
        # match the selected alternative -- missing, null, false, and
        # wrong-type all fail identically to UNRESOLVED/infrastructure,
        # never fabricated into a specific semantic verdict this response
        # did not actually supply.
        return _unresolved_infrastructure(
            "verifier claimed SUPPORTED but did not confirm, via "
            "authoritative_remediation_matches_selected_alternative, that the "
            "authoritative remediation matches the selected alternative"
        )
    if status == "CONTRADICTED" and matches_selected is not False:
        # Asymmetric with Mode A's CONTRADICTED deliberately: Mode B's
        # CONTRADICTED IS specifically "the authoritative fields do not
        # match the selected alternative" -- there is no other concrete,
        # externally-checkable contradiction this mode's question could be
        # about (see prompts/remediation_verifier.md). A CONTRADICTED
        # response that does not also commit `matches_selected == False`
        # has not actually supplied the one concrete finding this mode
        # exists to check for, so it degrades exactly like an unsupported
        # SUPPORTED does -- never a fabricated verdict.
        return _unresolved_infrastructure(
            "verifier claimed CONTRADICTED in Mode B (selected-alternative) mode "
            "but did not confirm, via authoritative_remediation_matches_selected_"
            "alternative=false, a concrete mismatch"
        )

    return VerifierResult(
        status=status, reason=reason, contradiction=contradiction,
        counterexample_reaches_unsafe_state=None,
        authoritative_remediation_matches_selected_alternative=matches_selected,
        failure_kind=None, evaluated=True,
    )


def verify_planner_claim(
    vulnerability_text: str,
    security_invariant: "str | None",
    remediation_mechanism: "str | None",
    narrower_alternative_considered: "str | None",
    required_edits: "list[str] | None",
    planner_evidence_ctx: str,
    llm,
    mode: str,
    stage: str = _DEFAULT_STAGE,
) -> VerifierResult:
    """
    One bounded LLM call answering exactly one of two mutually-exclusive
    questions (see module docstring and prompts/remediation_verifier.md),
    selected by the required `mode` argument -- never inferred here from
    `narrower_alternative_considered`'s own prose:

      mode="REJECTED": is the Planner's stated reason for rejecting
      `narrower_alternative_considered` causally consistent with the
      verified source in `planner_evidence_ctx`, once that narrower
      alternative is hypothetically applied?

      mode="SELECTED": do the authoritative `remediation_mechanism`/
      `required_edits` describe the same mechanism `narrower_alternative_
      considered` says the Planner selected?

    Best-effort like every other Planner-family call in this module family
    (`generate_remediation_plan`, `generate_remediation_strategy`): any
    ordinary call or parsing failure degrades to UNRESOLVED with
    `failure_kind="infrastructure"` -- never a fabricated SUPPORTED or
    CONTRADICTED. `ModelUnavailableError` is the one exception NOT treated
    as best-effort, for the same reason it isn't for those two calls: it
    is an explicit execution/configuration decision, not ordinary evidence
    acquisition failure.

    Callers decide the trigger (this function has no opinion on whether it
    should run at all, or in which mode -- see pipeline.py's own
    `narrower_alternative_decision` dispatch) and decide what happens for
    each outcome (bounded revision, Strategy/Patch-Generation skip) --
    this function only ever answers the one question `mode` selects.
    `mode` must be one of `_VALID_MODES`; an invalid value raises
    immediately, BEFORE any LLM call is made -- a caller passing an
    invalid mode is a programming error in this module family, not a
    verifier-response quality issue, so it must never be caught by this
    function's own best-effort `except Exception` below (which exists for
    ordinary call/parsing failures, not for catching this module's own
    misuse).

    `stage`, like every other LLM-call `stage` parameter in this module
    family, is purely an observability tag for the LLM call tracer -- it
    never affects the request or the returned text. Defaults to
    `"remediation_plan_verification"`; the second (post-revision)
    verification call should pass a distinct value so the two verifier
    calls remain individually visible in a trace.
    """
    if mode not in _VALID_MODES:
        raise ValueError(f"verify_planner_claim called with an invalid mode: {mode!r}")

    system_prompt = _PROMPT_PATH.read_text(encoding="utf-8")
    sections = ["## Vulnerability report\n\n" + vulnerability_text]
    sections.append(
        "## Mode\n\n"
        + (
            "REJECTED -- the Planner rejected the narrower alternative. Answer "
            "only the Mode A (counterexample-validity) question."
            if mode == "REJECTED"
            else "SELECTED -- the Planner selected the narrower alternative. Answer "
            "only the Mode B (decision-coherence) question."
        )
    )
    if security_invariant:
        sections.append("## Security invariant\n\n" + security_invariant)
    if remediation_mechanism:
        sections.append("## Authoritative remediation mechanism\n\n" + remediation_mechanism)
    sections.append(
        "## Narrower alternative considered (Planner's own claim)\n\n"
        + (narrower_alternative_considered or "")
    )
    if required_edits:
        sections.append("## Required edits\n\n" + "\n".join(f"- {e}" for e in required_edits))
    if planner_evidence_ctx and planner_evidence_ctx.strip():
        sections.append("## Verified Planner evidence\n\n" + planner_evidence_ctx)
    user_message = "\n\n".join(sections)

    try:
        raw = llm.complete(system_prompt, user_message, stage=stage)
    except ModelUnavailableError:
        raise
    except Exception as exc:
        return _unresolved_infrastructure(f"verifier LLM call failed: {type(exc).__name__}: {exc}")

    try:
        return _parse_response(raw, mode)
    except Exception as exc:
        return _unresolved_infrastructure(f"verifier response could not be parsed: {type(exc).__name__}: {exc}")
