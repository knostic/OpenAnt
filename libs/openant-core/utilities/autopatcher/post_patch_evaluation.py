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

Anchor kinds evaluated now: resolved_function, call_edge, reachability,
constant_value -- all resolvable purely from an InvestigationContext
(RepositoryIndex + call_graph + ReachabilityAnalyzer + the constants table
built once by candidate_enrichment.build_investigation_context()), with no
additional input and no I/O performed by this module itself.

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
from pathlib import Path
from typing import Literal

from utilities.autopatcher.candidate_enrichment import InvestigationContext
from utilities.autopatcher.diff_parsing import parse_diff
from utilities.autopatcher.post_patch_investigation import (
    Anchor,
    AnchorKey,
    AnchorKind,
    AnchorOrigin,
    AnchorValue,
    ConstantValueValue,
    ReachabilityValue,
    ResolvedFunctionValue,
    SinkMatchValue,
    const_id,
    constant_value_anchor,
    resolved_function_anchor,
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
    THIS phase (post-patch provenance). `origin` is likewise echoed
    verbatim from the originating Anchor -- whether this fact was
    selected before the patch existed (`"pre_patch"`) or discovered
    because the final patch touched this location
    (`"patch_touched"`, see post_patch_evaluation.derive_patch_touched_anchors).
    It is copied mechanically by `_observation()` below, exactly like
    `source`/`candidate_path` -- evaluate_anchors() never branches on it;
    it is inert provenance metadata carried through, not something the
    evaluation logic reasons about. Together with `anchor_kind`/
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
    origin: AnchorOrigin = "pre_patch"


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
        origin=anchor.origin,
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


_CONSTANT_VALUE_EVALUATED_VIA = "candidate_enrichment.InvestigationContext.constants"


def _evaluate_constant_value(anchor: Anchor, context: InvestigationContext) -> AnchorObservation:
    """Pure dict lookup against ``context.constants`` -- built once, with
    I/O, by ``build_investigation_context()`` (mirroring how
    ``_evaluate_resolved_function`` is a pure lookup against
    ``context.index``). No file read happens here."""
    file_constants = context.constants.get(anchor.candidate_path, {})
    entry = file_constants.get(anchor.key.qualified_name)

    if entry is None:
        return _observation(
            anchor, "disappeared", None,
            "assignment target no longer found in the patched copy",
            _CONSTANT_VALUE_EVALUATED_VIA,
        )

    if entry.get("outcome") != "literal":
        return _observation(
            anchor, "unresolved", None,
            f"target's assigned value is no longer a supported literal shape (outcome={entry.get('outcome')!r})",
            _CONSTANT_VALUE_EVALUATED_VIA,
        )

    after = ConstantValueValue(ast_literal_kind=entry["ast_literal_kind"], value=entry["value"])
    status: ObservationStatus = "unchanged" if after == anchor.before_value else "changed"
    return _observation(anchor, status, after, None, _CONSTANT_VALUE_EVALUATED_VIA)


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
        elif anchor.kind == "constant_value":
            observations.append(_evaluate_constant_value(anchor, post_patch_context))
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
# Coverage Analysis: deterministic accounting of how much of a generated
# patch's diff is tracked by at least one pre-patch Anchor.
#
# This answers a question distinct from (and prior to) AnchorObservation's
# unchanged/changed/disappeared taxonomy: "did our instrumentation even
# reach this part of the diff at all?" A hunk with no covering Anchor was
# never checked below -- it is not evidence of stability, just an
# instrumentation gap. Motivating case: CVE-2023-43804's actual fix (a
# one-line class-constant value change) produced zero changed/disappeared
# anchors purely because no anchor kind existed that could see it -- this
# reports that gap explicitly instead of letting "N unchanged" imply
# completeness it doesn't have.
#
# Deliberately reuses, not reimplements, existing machinery: diff parsing
# (diff_parsing.parse_diff) and content-based hunk relocation
# (impact_surface.LightweightImpactAnalyzer's own relocation primitives,
# which never trust a hunk header's claimed line number) are the same
# primitives impact_surface.py already uses for its own, unrelated
# blast-radius analysis. What's new here is small: resolving a relocated
# hunk to a ref string that is IDENTICAL to what an Anchor's own key
# already carries (a resolved_function/reachability anchor's `func_id`,
# or a constant_value anchor's `const_id`) -- so a covering Anchor is a
# plain set-membership check, never a fuzzy/heuristic match.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CoverageResult:
    """Deterministic coverage accounting for one generated patch's diff.

    ``covered``/``uncovered`` are deduplicated ref strings (func_id or
    const_id -- the same identity strings Anchor keys already use), sorted
    for reproducible rendering. ``unattributed`` counts non-cosmetic hunks
    that could not be confidently relocated, or whose file didn't parse --
    never silently dropped, never guessed into either bucket."""

    total: int
    covered: "tuple[str, ...]"
    uncovered: "tuple[str, ...]"
    unattributed: int


@dataclass(frozen=True)
class _PatchTouchedElement:
    """One patch-diff hunk, resolved (by content, never by trusting the
    hunk header) to the smallest containing function or literal-assignment
    target already known to an InvestigationContext. `ref` is identical to
    what an Anchor's own key already carries for that element (a func_id
    or const_id) -- comparing `ref` against an existing Anchor's key is a
    plain string/set check, never fuzzy. `function`/`constant_entry` carry
    the raw dict needed to actually construct an Anchor for this element
    (see derive_patch_touched_anchors) -- Coverage Analysis only needs
    `ref`/`kind`, but building this once and sharing it is what lets both
    consumers use one resolution pass instead of two."""

    ref: str
    kind: Literal["resolved_function", "constant_value"]
    file: str
    function: "dict | None" = None
    constant_entry: "dict | None" = None


def _anchor_refs(anchors: "list[Anchor]") -> "set[str]":
    """The set of identity strings (func_id/const_id) `anchors` already
    covers -- shared by compute_coverage (what's already tracked) and
    derive_patch_touched_anchors (what to skip re-deriving).

    call_edge is deliberately excluded: its key names a relationship
    between two OTHER locations, not an observable property of either
    location's own content -- crediting it would let a pure topology fact
    manufacture false "covered" status for a hunk whose actual edit (e.g.
    rewritten body) no anchor ever observed. sink_match's `method` is a
    bare, unqualified name from a different convention
    (vulnerability_patterns.py's regex scan) and is not comparable to a
    func_id/const_id."""
    refs: "set[str]" = set()
    for anchor in anchors:
        if anchor.kind in ("resolved_function", "reachability"):
            refs.add(anchor.key.func_id)
        elif anchor.kind == "constant_value":
            refs.add(anchor.key.const_id)
    return refs


def _resolve_patch_touched_elements(
    patch_diff: str,
    repo_root: "Path",
    context: InvestigationContext,
) -> "tuple[list[_PatchTouchedElement], int]":
    """Resolve every non-cosmetic hunk in `patch_diff` to a
    `_PatchTouchedElement` (deduplicated by ref) using content-based
    relocation (never trusting a hunk header's claimed line number) plus
    `context.index`/`context.constants` -- both already built, repo-wide,
    independent of Candidate Selection. Returns `(elements, unattributed)`;
    `unattributed` counts hunks that could not be confidently relocated,
    or whose file didn't parse -- never silently dropped, never guessed
    into an element.

    Shared, unchanged-behavior resolution step for both compute_coverage
    (which only needs to know a ref was touched) and
    derive_patch_touched_anchors (which additionally needs the raw
    function/constant-entry dict to build an Anchor) -- one pass, two
    consumers, instead of duplicating hunk relocation twice.
    """
    from utilities.autopatcher.impact_surface import LightweightImpactAnalyzer

    analyzer = LightweightImpactAnalyzer()
    changed_files, file_hunks = parse_diff(patch_diff)

    elements: "dict[str, _PatchTouchedElement]" = {}
    unattributed = 0

    for file_path in changed_files:
        if not file_path.endswith((".py", ".pyi")):
            continue
        try:
            file_text = (repo_root / file_path).read_text(encoding="utf-8")
        except Exception:
            unattributed += len(file_hunks.get(file_path, []))
            continue

        file_lines = file_text.splitlines()
        try:
            functions = context.index.list_functions_in_file(file_path)
        except Exception:
            functions = []
        constants = context.constants.get(file_path, {})

        for hunk in file_hunks.get(file_path, []):
            if analyzer._is_whitespace_only_hunk(hunk.lines):
                continue
            anchor_text, changed_flags = analyzer._anchor_lines(hunk.lines)
            start_idx = analyzer._locate_hunk(anchor_text, file_lines)
            if start_idx is None:
                unattributed += 1
                continue
            changed_positions = [start_idx + i for i, c in enumerate(changed_flags) if c]
            if not changed_positions:
                changed_positions = list(range(start_idx, start_idx + len(anchor_text)))
            true_start = min(changed_positions) + 1  # 1-indexed
            true_end = max(changed_positions) + 1

            element = (
                _resolve_element_at_line(file_path, functions, constants, true_start)
                or (_resolve_element_at_line(file_path, functions, constants, true_end) if true_end != true_start else None)
            )
            if element is None:
                unattributed += 1
                continue
            elements[element.ref] = element

    return list(elements.values()), unattributed


def _resolve_element_at_line(
    file_path: str, functions: "list[dict]", constants: dict, line: int
) -> "_PatchTouchedElement | None":
    """Resolve one line to the smallest containing function or
    literal-assignment target -- whichever span is smaller. Returns None
    when no containing element is found (a non-Python-parseable line, or
    module-level code with no matching constant and no functions_in_file
    entry at all -- functions_in_file's own whole-file `module_level`
    fallback unit still participates here like any other function span,
    so it only ever wins when nothing finer-grained contains the line)."""
    best: "tuple[int, _PatchTouchedElement] | None" = None
    for f in functions:
        start, end = f.get("startLine"), f.get("endLine")
        if start is None or end is None or not (start <= line <= end):
            continue
        span = end - start
        if best is None or span < best[0]:
            best = (span, _PatchTouchedElement(ref=f["id"], kind="resolved_function", file=file_path, function=f))
    for qualified, entry in constants.items():
        start = entry.get("line")
        end = entry.get("end_line", start)
        if start is None or end is None or not (start <= line <= end):
            continue
        span = end - start
        if best is None or span < best[0]:
            ref = const_id(file_path, qualified)
            best = (span, _PatchTouchedElement(ref=ref, kind="constant_value", file=file_path, constant_entry=entry))
    return best[1] if best else None


def compute_coverage(
    patch_diff: str,
    anchors: "list[Anchor]",
    repo_root: "Path",
    context: "InvestigationContext | None",
) -> "CoverageResult | None":
    """Deterministically account for how much of `patch_diff` is tracked by
    at least one Anchor in `anchors` -- `anchors` is expected to be the
    MERGED pre-patch + patch-touched list (see derive_patch_touched_anchors)
    so that "uncovered" means "genuinely unsupported element type", not
    "Candidate Selection happened not to pick this file." Treats every
    Anchor equally regardless of `origin` -- coverage answers "is this
    location tracked by anything," which doesn't depend on which phase
    produced the tracking.

    Returns None (never raises) when `context` is None -- there is no
    RepositoryIndex/constants table to resolve against. Reads only Python
    files named in the diff, from `repo_root` (the PRE-patch repository --
    the diff's context/removed lines describe that state, not the patched
    one). A per-file read/parse failure counts that file's hunks as
    unattributed rather than aborting the whole computation.
    """
    if context is None:
        return None

    elements, unattributed = _resolve_patch_touched_elements(patch_diff, repo_root, context)
    anchor_refs = _anchor_refs(anchors)

    covered = tuple(sorted(e.ref for e in elements if e.ref in anchor_refs))
    uncovered = tuple(sorted(e.ref for e in elements if e.ref not in anchor_refs))
    return CoverageResult(total=len(elements), covered=covered, uncovered=uncovered, unattributed=unattributed)


def derive_patch_touched_anchors(
    patch_diff: str,
    repo_root: "Path",
    context: "InvestigationContext | None",
    existing_anchors: "list[Anchor]",
) -> "list[Anchor]":
    """Derive NEW Anchors, independent of Candidate Selection entirely, for
    semantic elements the final patch's diff touches but which no existing
    Anchor already tracks.

    Resolves directly against `context` (repo-wide, already built by
    build_investigation_context() before Candidate Selection even runs)
    and `patch_diff` (the final, applicability-adjusted patch) -- never
    against `understanding.candidate_evidence`, so a file Candidate
    Selection never selected is exactly as resolvable as one it did.

    Returns only the net-new anchors, already deduplicated against
    `existing_anchors` and against each other by (kind, key), each marked
    `origin="patch_touched"`. `existing_anchors` itself is never mutated,
    read for identity comparison only -- callers concatenate this
    function's return value onto it.

    Supports exactly the two element kinds compute_coverage's own
    resolution already produces: resolved_function and constant_value.
    Two cases are deliberately never anchored, left to render as
    "uncovered" by Coverage Analysis instead of fabricating a fact:
      - a function-tier match whose `unitType` is `"module_level"` (the
        whole-file catch-all unit) -- its before/after span is the entire
        file, so it carries no meaningful signal, and constructing an
        anchor for it would manufacture false "covered" status for a
        location where nothing was actually captured (the same category
        of bug already fixed once in candidate_enrichment's own
        scope_constants scoping, applied here to a different call site);
      - a constant-tier match whose `outcome` isn't `"literal"` -- there
        is no value to compare, so no constant_value Anchor is buildable
        without guessing one.
    Anything else the diff touches (a control-flow change, a new call, an
    edit inside a function body that doesn't move its boundaries) has no
    corresponding fact type at all yet and is likewise left uncovered.

    Returns [] (never raises) when `context` is None.
    """
    if context is None:
        return []

    existing_refs = _anchor_refs(existing_anchors)
    elements, _unattributed = _resolve_patch_touched_elements(patch_diff, repo_root, context)

    new_anchors: "list[Anchor]" = []
    for element in elements:
        if element.ref in existing_refs:
            continue
        if element.kind == "resolved_function":
            if element.function is None or element.function.get("unitType") == "module_level":
                continue
            new_anchors.append(resolved_function_anchor(
                element.file, element.function, element.ref, origin="patch_touched",
            ))
        elif element.kind == "constant_value":
            if element.constant_entry is None or element.constant_entry.get("outcome") != "literal":
                continue
            new_anchors.append(constant_value_anchor(
                element.file, element.constant_entry, origin="patch_touched",
            ))

    return new_anchors


_COVERAGE_MAX_LIST_ITEMS = 5


def _render_coverage_section(coverage: "CoverageResult | None") -> str:
    if coverage is None:
        return (
            "\n### Anchor Coverage\n\n"
            "*Not computed for this run (no repository index available).*\n"
        )

    total = coverage.total
    covered_n = len(coverage.covered)
    uncovered_n = len(coverage.uncovered)

    if total == 0:
        if coverage.unattributed:
            body = f"No semantic elements could be attributed to this diff ({coverage.unattributed} hunk(s) unattributed).\n"
        else:
            body = "No hunks required attribution (cosmetic-only diff, or no Python files changed).\n"
        return "\n### Anchor Coverage\n\n" + body

    lines = [
        "\n### Anchor Coverage\n\n",
        f"{covered_n} of {total} element(s) changed by the diff are covered by at least one Anchor; "
        f"{uncovered_n} are not -- uncovered elements were never checked below, not confirmed unchanged.",
    ]
    if coverage.unattributed:
        lines.append(f" {coverage.unattributed} hunk(s) could not be attributed to any element at all.")
    lines.append("\n")

    if uncovered_n:
        shown = coverage.uncovered[:_COVERAGE_MAX_LIST_ITEMS]
        remainder = uncovered_n - len(shown)
        lines.append("\nUncovered:\n\n")
        lines.extend(f"- `{ref}`\n" for ref in shown)
        if remainder > 0:
            lines.append(f"- (+{remainder} more)\n")

    return "".join(lines)


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
    "patched copy of the repository. These are structural observations about "
    "specific, pre-selected facts (a function's boundaries, a call edge, a "
    "reachability path, a literal constant value) -- not a verdict that the "
    "patch is correct, safe, or a successful fix, and not a claim that every "
    "change in the diff was checked. Missing evidence is reported as "
    "missing, never as a negative finding. This evidence is gathered from "
    "the final patch diff itself, after the patch was generated -- distinct "
    "from Repository Context, which lists locations selected before the "
    "patch existed.*"
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
    if obs.anchor_kind == "constant_value":
        return f"constant_value:{obs.anchor_key.const_id}"
    return f"{obs.anchor_kind}:{obs.anchor_key!r}"


def _render_group_items(observations: list, render_one) -> str:
    shown = observations[:_MAX_LIST_ITEMS]
    remainder = len(observations) - len(shown)
    lines = [f"- {render_one(o)}" for o in shown]
    if remainder > 0:
        lines.append(f"- (+{remainder} more)")
    return "\n".join(lines) + "\n"


def _origin_tag(obs: AnchorObservation) -> str:
    """Concise marker distinguishing a patch_touched observation -- one
    discovered because the final patch touched this location, independent
    of Candidate Selection -- from a pre_patch one, selected before the
    patch existed. Applied only to Changed/Disappeared (the statuses
    where a reader most needs to know evidence came from outside the
    originally selected candidates); Unchanged's aggregate count stays a
    single breakdown axis (by anchor_kind only), not a second one."""
    return " (discovered from patch diff)" if obs.origin == "patch_touched" else ""


def _format_anchor_value(kind: AnchorKind, value: "AnchorValue | None") -> str:
    """Concise, maintainer-readable rendering of one anchor value for the
    Changed section -- presentation only, never consulted by
    evaluate_anchors() to decide status. Dispatches on `kind` (the
    evaluation layer already guarantees which value type accompanies each
    kind -- see _evaluate_resolved_function/_evaluate_reachability/
    _evaluate_constant_value) rather than isinstance-sniffing alone, so a
    value shape that doesn't match its kind falls through to the safe
    fallback below instead of silently mis-rendering.

    Never raises: an unrecognized kind, or a value whose shape doesn't
    match what that kind expects, falls back to a plain str() -- the same
    "defensive, unreachable given today's AnchorKind" posture
    Anchor.display_id already uses for its own unknown-kind fallback.
    """
    if value is None:
        return "unknown"

    if kind == "resolved_function" and isinstance(value, ResolvedFunctionValue):
        if value.start_line is None or value.end_line is None:
            return "location unknown"
        return f"lines {value.start_line}-{value.end_line}"

    if kind == "reachability" and isinstance(value, ReachabilityValue):
        if value.reachable is None:
            return "reachability unknown"
        if not value.reachable:
            return "not reachable"
        if value.entry_point_path:
            return "reachable (via " + " -> ".join(value.entry_point_path) + ")"
        return "reachable"

    if kind == "constant_value" and isinstance(value, ConstantValueValue):
        # The literal's own value, not the ConstantValueValue wrapper --
        # ast_literal_kind is disambiguation metadata for evaluate_anchors()
        # itself, not something a reader needs repeated back to them.
        return repr(value.value)

    if kind == "call_edge":
        return "present" if value else "absent"

    if kind == "sink_match" and isinstance(value, SinkMatchValue):
        return f"line {value.line}"

    # Defensive fallback only -- unreachable given today's AnchorKind/value
    # pairings; mirrors Anchor.display_id's own unknown-kind fallback.
    return str(value)


def _render_changed(obs: AnchorObservation) -> str:
    before = _format_anchor_value(obs.anchor_kind, obs.before_value)
    after = _format_anchor_value(obs.anchor_kind, obs.after_value)
    return f"`{_display_id(obs)}` (`{obs.candidate_path}`){_origin_tag(obs)}: {before} → {after}"


def _render_disappeared(obs: AnchorObservation) -> str:
    detail = f" -- {obs.details}" if obs.details else ""
    return f"`{_display_id(obs)}` (`{obs.candidate_path}`){_origin_tag(obs)}: no longer present{detail}"


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
    coverage: "CoverageResult | None" = None,
    *,
    max_chars: int = DEFAULT_MAX_CHARS,
) -> str:
    """Render a list[AnchorObservation] into one deterministic Markdown
    block, starting with a top-level ``## Post-Patch Investigation``
    heading.

    Never mutates `observations`. No LLM calls, no I/O, no parsing.
    An optional ``coverage`` (see ``compute_coverage()``) renders as an
    "### Anchor Coverage" section immediately after the preamble --
    before Changed/Disappeared/Unchanged/Remaining Unknowns, and
    deliberately not last, so it survives `_hard_clamp`'s end-of-string
    truncation under budget pressure (the one section whose entire job is
    "here's what we did NOT check" should not be the first thing dropped).
    Omitted entirely when ``coverage`` is ``None`` (caller didn't compute
    it), never rendered as a fabricated zero.

    Observations are grouped by `status`: Changed and Disappeared are
    shown in full (capped per-group at `_MAX_LIST_ITEMS` with a "+N more"
    note, never silently dropped to fit a byte budget); Unchanged is
    compressed to a count/breakdown (with a one-line caveat pointing at
    Anchor Coverage whenever `coverage` shows any uncovered elements, so
    "N unchanged" is never misread as "everything was checked"); Unresolved
    and evaluation_error are merged into a separate "Remaining Unknowns"
    section, never mixed into the determinate-looking groups above. The
    returned string never exceeds `max_chars` -- a final hard-clamp
    backstop applies only in the unlikely case the grouped sections alone
    exceed it.
    """
    header = _HEADING + "\n\n" + _PREAMBLE + "\n"
    coverage_section = _render_coverage_section(coverage) if coverage is not None else ""

    if not observations:
        rendered = header + coverage_section + "\nNo anchors were available to re-evaluate.\n"
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
        caveat = ""
        if coverage is not None and coverage.uncovered:
            caveat = (
                " -- this covers only the fact types anchors track; "
                "see Anchor Coverage above for what else the diff changed"
            )
        parts.append(f"{len(unchanged)} anchor(s) confirmed unchanged ({breakdown}){caveat}.\n")
    else:
        parts.append("None observed.\n")

    parts.append("\n### Remaining Unknowns\n\n")
    parts.append(_render_group_items(unknown, _render_unknown) if unknown else "None observed.\n")

    rendered = header + coverage_section + "".join(parts)

    if len(rendered) > max_chars:
        rendered = _hard_clamp(rendered, max_chars)

    return rendered
