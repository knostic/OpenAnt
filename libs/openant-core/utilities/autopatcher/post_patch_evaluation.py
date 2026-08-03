"""Post-Patch Anchor Evaluation.

Phase 3 of Post-Patch Vulnerability Investigation: re-evaluates the atomic,
deterministic Anchors derived by post_patch_investigation.py's
derive_pre_patch_anchors() against an already-built
candidate_enrichment.InvestigationContext for the patched repository copy.

``evaluate_anchors()`` is a pure function: ``list[Anchor]`` +
``InvestigationContext | None`` in, ``list[AnchorObservation]`` out. It
builds nothing itself -- no parser invocation, no temp-directory
management, no ``repo_root``, no ``PatchApplicationResult`` -- exactly
mirroring how Phase 2's ``derive_pre_patch_anchors()`` consumed an
already-built ``RepositoryUnderstanding`` rather than orchestrating its own
parsing. Whoever orchestrates copying the repo, applying the patch, and
building a fresh ``InvestigationContext`` against the patched copy (a
future, separate pipeline-wiring phase, not this one) is responsible for:
  - deciding whether to call this function at all -- if the patch never
    applied, there is no patched state to evaluate, and that decision is
    orchestration state (``PatchApplicationResult``), not something this
    module re-derives or accepts as input;
  - building the ``InvestigationContext`` via
    ``candidate_enrichment.build_investigation_context(patched_root, output_dir)``,
    exactly as pre-patch enrichment already does.

Like ``Anchor``, ``AnchorObservation`` records an OBSERVATION, not a
verdict: ``status`` is one of a small closed set describing what changed,
never whether the change is good, expected, or a successful fix. That
judgement is entirely a downstream consumer's responsibility (Trust
Signals, Trust Report, Challenger) -- never this module's.

Anchor kinds evaluated now: resolved_function, call_edge, reachability --
all resolvable purely from an InvestigationContext (RepositoryIndex +
call_graph + ReachabilityAnalyzer), with no additional input.

Anchor kind NOT evaluated here: sink_match. Re-checking a sink_match
anchor requires knowing which vulnerability class's pattern to re-scan for
(``vulnerability_patterns.extract_repo_sinks(repo_root, vuln_class)``), and
``vuln_class`` is not captured anywhere on ``SinkMatchKey`` (Phase 2,
already committed) nor accepted as an input here -- widening
``evaluate_anchors()``'s signature to take ``vuln_class`` was deliberately
rejected, to keep this function focused on "Anchors -> deterministic
observations" with no orchestration-adjacent parameters. Every sink_match
anchor therefore evaluates to ``unresolved``, honestly stating why, rather
than guessing a vuln_class or fabricating a comparison. Closing this gap
-- either by capturing vuln_class on the Anchor at derivation time, or by
giving sink_match its own dedicated evaluation path -- is left to a
future, separately-scoped change.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from utilities.autopatcher.candidate_enrichment import InvestigationContext
from utilities.autopatcher.post_patch_investigation import (
    Anchor,
    AnchorKey,
    AnchorKind,
    AnchorValue,
    ReachabilityValue,
    ResolvedFunctionValue,
)

ObservationStatus = Literal["unchanged", "changed", "disappeared", "unresolved", "evaluation_error"]


@dataclass(frozen=True)
class AnchorObservation:
    """One deterministic, post-patch observation for one Anchor.

    Mirrors Anchor's own discipline: `status` describes only what was
    observed (unchanged/changed/disappeared/unresolved/evaluation_error)
    -- never a verdict like "successfully_fixed", "expected_change", or
    "patch_correct". Those belong to downstream consumers, never here.

    `disappeared` is reserved for a presence/absence transition (something
    confidently observable is now confidently gone); a reachability
    anchor's `before_value.reachable` going from `None` (unresolved at
    Phase 2 derivation time) to a definite `True`/`False` is instead
    reported as `changed` -- it's a known/unknown transition, the same
    axis `unresolved` already names elsewhere, not a presence/absence one,
    so it doesn't get its own status value.

    `source` is echoed verbatim from the originating Anchor (pre-patch
    provenance: which existing capability produced `before_value`).
    `evaluated_via` names the capability used to compute `after_value` in
    THIS phase (post-patch provenance). Together with `anchor_kind`/
    `anchor_key`/`candidate_path`, every observation is fully traceable
    back to its originating Anchor without needing to keep the original
    Anchor list around.
    """

    anchor_kind: AnchorKind
    anchor_key: AnchorKey
    candidate_path: str
    status: ObservationStatus
    before_value: AnchorValue
    after_value: "AnchorValue | None"
    details: "str | None"
    source: str
    evaluated_via: str


def _observation(
    anchor: Anchor,
    status: ObservationStatus,
    after_value: "AnchorValue | None",
    details: "str | None",
    evaluated_via: str,
) -> AnchorObservation:
    return AnchorObservation(
        anchor_kind=anchor.kind,
        anchor_key=anchor.key,
        candidate_path=anchor.candidate_path,
        status=status,
        before_value=anchor.before_value,
        after_value=after_value,
        details=details,
        source=anchor.source,
        evaluated_via=evaluated_via,
    )


_RESOLVED_FUNCTION_EVALUATED_VIA = "agentic_enhancer.repository_index.RepositoryIndex.get_function"


def _evaluate_resolved_function(anchor: Anchor, context: InvestigationContext) -> AnchorObservation:
    func_id = anchor.key.func_id
    try:
        func = context.index.get_function(func_id)
    except Exception as exc:  # noqa: BLE001 -- isolate to this anchor, never propagate
        return _observation(
            anchor, "evaluation_error", None,
            f"lookup failed: {type(exc).__name__}: {exc}",
            _RESOLVED_FUNCTION_EVALUATED_VIA,
        )

    if func is None:
        return _observation(
            anchor, "disappeared", None,
            "function id no longer present in the patched copy",
            _RESOLVED_FUNCTION_EVALUATED_VIA,
        )

    after = ResolvedFunctionValue(start_line=func.get("startLine"), end_line=func.get("endLine"))
    status: ObservationStatus = "unchanged" if after == anchor.before_value else "changed"
    return _observation(anchor, status, after, None, _RESOLVED_FUNCTION_EVALUATED_VIA)


_CALL_EDGE_EVALUATED_VIA = "core.parser_adapter.parse_repository (call_graph)"


def _evaluate_call_edge(anchor: Anchor, context: InvestigationContext) -> AnchorObservation:
    caller_id = anchor.key.caller_func_id
    callee_id = anchor.key.callee_func_id
    try:
        caller_func = context.index.get_function(caller_id)
        if caller_func is None:
            return _observation(
                anchor, "unresolved", None,
                "caller function id no longer resolves in the patched copy",
                _CALL_EDGE_EVALUATED_VIA,
            )
        still_present = callee_id in context.call_graph.get(caller_id, [])
    except Exception as exc:  # noqa: BLE001
        return _observation(
            anchor, "evaluation_error", None,
            f"lookup failed: {type(exc).__name__}: {exc}",
            _CALL_EDGE_EVALUATED_VIA,
        )

    if still_present:
        return _observation(anchor, "unchanged", True, None, _CALL_EDGE_EVALUATED_VIA)
    return _observation(anchor, "disappeared", False, None, _CALL_EDGE_EVALUATED_VIA)


_REACHABILITY_EVALUATED_VIA = "agentic_enhancer.reachability_analyzer.ReachabilityAnalyzer"


def _evaluate_reachability(anchor: Anchor, context: InvestigationContext) -> AnchorObservation:
    func_id = anchor.key.func_id
    try:
        func = context.index.get_function(func_id)
        if func is None:
            return _observation(
                anchor, "unresolved", None,
                "function id no longer resolves in the patched copy",
                _REACHABILITY_EVALUATED_VIA,
            )
        reachable = context.reachability.is_reachable_from_entry_point(func_id)
        path = context.reachability.get_entry_point_path(func_id)
        after = ReachabilityValue(reachable=reachable, entry_point_path=tuple(path) if path else None)
    except Exception as exc:  # noqa: BLE001
        return _observation(
            anchor, "evaluation_error", None,
            f"reachability computation failed: {type(exc).__name__}: {exc}",
            _REACHABILITY_EVALUATED_VIA,
        )

    # A None-before-value transitioning to a definite True/False (the rare
    # Phase 2 enrichment-exception case) is a known/unknown transition,
    # not a presence/absence one -- it falls through to the same
    # unchanged/changed comparison as any other value change, since
    # `None != True`/`None != False` already makes that comparison correct
    # without a dedicated status.
    status: ObservationStatus = "unchanged" if after == anchor.before_value else "changed"
    return _observation(anchor, status, after, None, _REACHABILITY_EVALUATED_VIA)


_SINK_MATCH_DEFERRED_NOTE = (
    "sink_match evaluation deferred: vuln_class is not captured on the "
    "Anchor and evaluate_anchors() does not accept it as an input; "
    "closing this gap requires either capturing vuln_class at "
    "anchor-derivation time or a dedicated future evaluation path."
)


def _evaluate_sink_match(anchor: Anchor) -> AnchorObservation:
    return _observation(anchor, "unresolved", None, _SINK_MATCH_DEFERRED_NOTE, "deferred")


def evaluate_anchors(
    anchors: list[Anchor],
    post_patch_context: "InvestigationContext | None",
) -> list[AnchorObservation]:
    """Re-evaluate each Anchor against an already-built InvestigationContext
    for the patched repository copy.

    Pure: no I/O, no parsing, no subprocess, no network, no LLM calls, no
    mutation of `anchors` or `post_patch_context`. `post_patch_context` may
    be `None` (e.g. the patched copy failed to parse) -- every
    context-dependent anchor then evaluates to `evaluation_error`,
    honestly, rather than raising. Returns exactly one AnchorObservation
    per input Anchor, in the same order -- never reordered, never
    deduplicated (Phase 2 already deduplicated the anchors themselves).
    """
    observations: list[AnchorObservation] = []

    for anchor in anchors:
        if anchor.kind == "sink_match":
            observations.append(_evaluate_sink_match(anchor))
            continue

        if post_patch_context is None:
            observations.append(_observation(
                anchor, "evaluation_error", None,
                "no investigation context available for the patched copy",
                "candidate_enrichment.build_investigation_context",
            ))
            continue

        if anchor.kind == "resolved_function":
            observations.append(_evaluate_resolved_function(anchor, post_patch_context))
        elif anchor.kind == "call_edge":
            observations.append(_evaluate_call_edge(anchor, post_patch_context))
        elif anchor.kind == "reachability":
            observations.append(_evaluate_reachability(anchor, post_patch_context))
        else:
            # Defensive only -- AnchorKind is a closed Literal covering
            # every kind post_patch_investigation.py currently derives;
            # this is unreachable given today's Anchor producers.
            observations.append(_observation(
                anchor, "evaluation_error", None,
                f"unknown anchor kind: {anchor.kind!r}",
                "post_patch_evaluation",
            ))

    return observations


# ---------------------------------------------------------------------------
# Deterministic Markdown rendering of list[AnchorObservation].
#
# Mirrors evidence_fusion.py's render_repository_understanding(): a pure
# function from data to a bounded Markdown string, with a "not a verdict"
# preamble and a hard-clamp backstop that guarantees the result never
# exceeds max_chars. Local constants (DEFAULT_MAX_CHARS/_MAX_LIST_ITEMS),
# not imported from evidence_fusion.py -- that module's values are sized
# for its own <=3-candidate assumption, which doesn't hold here (anchor
# count per candidate is unbounded, e.g. multiple call_edge anchors).
#
# Unlike evidence_fusion's per-candidate whole-block-drop-from-budget
# mechanism, Changed/Disappeared observations are never silently dropped
# here -- they're the rarest and most report-worthy groups. Only a
# per-group item count cap applies (mirroring evidence_fusion's own
# _render_list_line "+N more" convention), with _hard_clamp as the sole,
# unconditional final backstop.
# ---------------------------------------------------------------------------

DEFAULT_MAX_CHARS = 4_000
"""Same order of magnitude as evidence_fusion.DEFAULT_MAX_CHARS, sized
independently: anchor count per candidate is unbounded here, unlike that
module's <=3-candidate sizing."""

_MAX_LIST_ITEMS = 5
"""Per-status-group item cap before a "(+N more)" note -- mirrors
evidence_fusion._render_list_line's convention."""

_TRUNCATION_MARKER = "\n\n*(truncated to fit the character budget)*\n"

_HEADING = "## Post-Patch Investigation"

_PREAMBLE = (
    "*Deterministic re-evaluation of pre-patch Anchors against an isolated, "
    "patched copy of the repository. These are structural observations "
    "(unchanged, changed, disappeared, or not statically verifiable) -- not "
    "a verdict that the patch is correct, safe, or a successful fix. Missing "
    "evidence is reported as missing, never as a negative finding.*"
)


def _display_id(obs: AnchorObservation) -> str:
    """Same anchor-kind-specific formatting as Anchor.display_id, applied
    to an evaluated AnchorObservation instead."""
    if obs.anchor_kind == "resolved_function":
        return f"resolved_function:{obs.anchor_key.func_id}"
    if obs.anchor_kind == "call_edge":
        return f"call_edge:{obs.anchor_key.caller_func_id}->{obs.anchor_key.callee_func_id}"
    if obs.anchor_kind == "reachability":
        return f"reachability:{obs.anchor_key.func_id}"
    if obs.anchor_kind == "sink_match":
        method_label = obs.anchor_key.method or "<module>"
        return f"sink_match:{obs.anchor_key.candidate_path}:{method_label}"
    return f"{obs.anchor_kind}:{obs.anchor_key!r}"


def _render_group_items(observations: list, render_one) -> str:
    shown = observations[:_MAX_LIST_ITEMS]
    remainder = len(observations) - len(shown)
    lines = [f"- {render_one(o)}" for o in shown]
    if remainder > 0:
        lines.append(f"- (+{remainder} more)")
    return "\n".join(lines) + "\n"


def _render_changed(obs: AnchorObservation) -> str:
    return f"`{_display_id(obs)}` (`{obs.candidate_path}`): {obs.before_value!r} → {obs.after_value!r}"


def _render_disappeared(obs: AnchorObservation) -> str:
    detail = f" -- {obs.details}" if obs.details else ""
    return f"`{_display_id(obs)}` (`{obs.candidate_path}`): no longer present{detail}"


def _render_unknown(obs: AnchorObservation) -> str:
    detail = f" -- {obs.details}" if obs.details else ""
    return f"`{_display_id(obs)}` (`{obs.candidate_path}`): {obs.status}{detail}"


def _hard_clamp(rendered: str, max_chars: int) -> str:
    """Absolute backstop: truncate at the last full line boundary that
    fits, so the result is never split mid-item, and append an explicit
    marker. Guarantees len(result) <= max_chars."""
    limit = max_chars - len(_TRUNCATION_MARKER)
    if limit <= 0:
        return _TRUNCATION_MARKER[:max_chars]
    cut = rendered.rfind("\n", 0, limit)
    if cut <= 0:
        cut = limit
    return rendered[:cut] + _TRUNCATION_MARKER


def render_post_patch_investigation(
    observations: list[AnchorObservation],
    *,
    max_chars: int = DEFAULT_MAX_CHARS,
) -> str:
    """Render a list[AnchorObservation] into one deterministic Markdown
    block, starting with a top-level ``## Post-Patch Investigation``
    heading.

    Never mutates `observations`. No LLM calls, no I/O, no parsing.
    Observations are grouped by `status`: Changed and Disappeared are
    shown in full (capped per-group at `_MAX_LIST_ITEMS` with a "+N more"
    note, never silently dropped to fit a byte budget); Unchanged is
    compressed to a count/breakdown; Unresolved and evaluation_error are
    merged into a separate "Remaining Unknowns" section, never mixed into
    the determinate-looking groups above. The returned string never
    exceeds `max_chars` -- a final hard-clamp backstop applies only in the
    unlikely case the grouped sections alone exceed it.
    """
    header = _HEADING + "\n\n" + _PREAMBLE + "\n"

    if not observations:
        rendered = header + "\nNo anchors were available to re-evaluate.\n"
        return rendered if len(rendered) <= max_chars else _hard_clamp(rendered, max_chars)

    changed = [o for o in observations if o.status == "changed"]
    disappeared = [o for o in observations if o.status == "disappeared"]
    unchanged = [o for o in observations if o.status == "unchanged"]
    unknown = [o for o in observations if o.status in ("unresolved", "evaluation_error")]

    parts = ["\n### Changed\n\n"]
    parts.append(_render_group_items(changed, _render_changed) if changed else "None observed.\n")

    parts.append("\n### Disappeared\n\n")
    parts.append(_render_group_items(disappeared, _render_disappeared) if disappeared else "None observed.\n")

    parts.append("\n### Unchanged\n\n")
    if unchanged:
        by_kind: dict[str, int] = {}
        for o in unchanged:
            by_kind[o.anchor_kind] = by_kind.get(o.anchor_kind, 0) + 1
        breakdown = ", ".join(f"{kind}: {count}" for kind, count in sorted(by_kind.items()))
        parts.append(f"{len(unchanged)} anchor(s) confirmed unchanged ({breakdown}).\n")
    else:
        parts.append("None observed.\n")

    parts.append("\n### Remaining Unknowns\n\n")
    parts.append(_render_group_items(unknown, _render_unknown) if unknown else "None observed.\n")

    rendered = header + "".join(parts)

    if len(rendered) > max_chars:
        rendered = _hard_clamp(rendered, max_chars)

    return rendered
