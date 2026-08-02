"""Deterministic candidate enrichment.

Attaches ``CandidateEnrichment`` metadata (see
``repository_grounding_models.py``) to selected ``RepositoryCandidate``
objects, using only existing OpenAnt parser, call-graph, reachability, and
test-discovery capabilities. No LLM calls anywhere in this module, and no
vulnerability judgement is made -- this is deterministic repository fact
gathering only, meant to run *before* any model is asked to reason about
the vulnerability.

``build_investigation_context()`` performs the one repo-wide, real-parse
step (``core.parser_adapter.parse_repository``) and assembles the shared,
read-only artifacts every candidate's enrichment reuses -- the same
read-call_graph.json / EntryPointDetector / ReachabilityAnalyzer sequence
``core.parser_adapter.apply_reachability_filter`` already performs
internally, reused here for enrichment instead of dataset filtering.

``enrich_candidates()`` is pure orchestration over an already-built
``InvestigationContext`` (or ``None``): it never parses anything itself,
which keeps it trivially testable with hand-built fixtures.

Enrichment is intentionally depth-1 only: callers/callees are recorded as
names, never recursively re-enriched into their own ``CandidateEnrichment``
objects. Expanding further is the same "generic full-repository scan"
failure mode this whole design exists to avoid, relocated to the graph
level instead of eliminated.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from core.parser_adapter import parse_repository
from utilities.agentic_enhancer.entry_point_detector import EntryPointDetector
from utilities.agentic_enhancer.reachability_analyzer import ReachabilityAnalyzer
from utilities.agentic_enhancer.repository_index import RepositoryIndex, load_index_from_file
from utilities.autopatcher import testing_support, vulnerability_patterns
from utilities.autopatcher.candidate_selection import CandidateSelection
from utilities.autopatcher.repository_grounding_models import (
    CandidateEnrichment,
    RepositoryCandidate,
)
from utilities.file_io import read_json


@dataclass
class InvestigationContext:
    """Shared, repo-wide artifacts built once per patch run from a single
    ``parse_repository()`` call. Nothing here is candidate-specific --
    every candidate's enrichment reads from this read-only."""

    index: RepositoryIndex
    call_graph: dict
    reverse_call_graph: dict
    reachability: ReachabilityAnalyzer


def build_investigation_context(repo_root: Path, output_dir: Path) -> "InvestigationContext | None":
    """Parse the repository once and assemble the shared artifacts every
    candidate's enrichment reuses.

    Uses ``processing_level="all"`` deliberately: candidate enrichment
    needs the *complete* function/call-graph picture for a candidate's
    file so ``list_functions_in_file`` isn't missing anything a narrower
    processing level would have already filtered out before reachability
    is queried per-candidate, below.

    Returns ``None`` (never raises) if parsing fails or produces no usable
    ``analyzer_output.json``/``call_graph.json`` (e.g. an unsupported
    language). Callers must treat ``None`` as "enrichment degrades to
    file/test/sink-only facts", never as a reason to fail the patch run.

    ``repo_root`` is resolved internally (``Path.resolve()``) before
    parsing. This matters: ``repo_locator.py``'s own ``_rel()`` helper
    silently falls back to a bare filename (instead of a proper
    repo-relative path) when a discovered file's resolved absolute path
    doesn't share a common root with an *unresolved* ``repo_root`` --  a
    real, observed failure mode on macOS, where a raw temp directory
    (``/var/folders/...``) is a symlink to its resolved form
    (``/private/var/folders/...``). Resolving here keeps this module's own
    parse/index/reachability construction internally consistent regardless
    of what the caller passed -- but it cannot retroactively fix a
    ``RepositoryCandidate.path`` that an *earlier*, differently-resolved
    call to ``ground_repository()`` already computed as a bare filename.
    Whatever calls ``ground_repository()`` to build the
    ``RepositoryGroundingResult`` this whole chain starts from must also
    pass an already-``.resolve()``d ``repo_root``, or candidate paths may
    degrade to bare filenames and enrichment will correctly, but
    unhelpfully, fail to resolve a containing function for them.
    """
    repo_root = Path(repo_root).resolve()
    output_dir_str = str(output_dir)

    try:
        parse_result = parse_repository(str(repo_root), output_dir_str, processing_level="all")
    except Exception:
        return None

    if not parse_result.analyzer_output_path or not os.path.exists(parse_result.analyzer_output_path):
        return None

    call_graph_path = os.path.join(output_dir_str, "call_graph.json")
    if not os.path.exists(call_graph_path):
        return None

    try:
        index = load_index_from_file(parse_result.analyzer_output_path, str(repo_root))
        call_graph_data = read_json(call_graph_path)
        functions = call_graph_data.get("functions", {})
        call_graph = call_graph_data.get("call_graph", {})
        reverse_call_graph = call_graph_data.get("reverse_call_graph", {})
        entry_points = EntryPointDetector(functions, call_graph).detect_entry_points()
        reachability = ReachabilityAnalyzer(functions, reverse_call_graph, entry_points)
    except Exception:
        return None

    return InvestigationContext(
        index=index,
        call_graph=call_graph,
        reverse_call_graph=reverse_call_graph,
        reachability=reachability,
    )


def enrich_candidates(
    selection: CandidateSelection,
    repo_root: Path,
    vulnerability_text: str,
    context: "InvestigationContext | None",
) -> list[RepositoryCandidate]:
    """Attach deterministic ``CandidateEnrichment`` metadata to every
    selected candidate, in place.

    Returns the same ``RepositoryCandidate`` objects passed in via
    ``selection.selected`` (same identity, same order) -- never a second
    candidate model. ``path``/``evidence``/``best_tier`` are never
    modified; only ``.enrichment`` is set.

    A failure enriching one candidate is isolated to that candidate's
    ``enrichment.enrichment_errors`` and never prevents enriching the
    others. No LLM calls anywhere in this function or anything it calls.

    ``repo_root`` is resolved internally for the same reason
    ``build_investigation_context()`` resolves it -- see that function's
    docstring. This cannot fix a candidate path already computed as a bare
    filename by an unresolved-root call to ``ground_repository()``.
    """
    repo_root = Path(repo_root).resolve()
    vuln_class = vulnerability_patterns.classify_vuln_class(vulnerability_text)
    for candidate in selection.selected:
        _enrich_one(candidate, repo_root, vuln_class, context)
    return selection.selected


def _enrich_one(
    candidate: RepositoryCandidate,
    repo_root: Path,
    vuln_class: "str | None",
    context: "InvestigationContext | None",
) -> None:
    errors: list[str] = []
    functions_in_file: list[dict] = []
    resolved_function: "dict | None" = None
    resolution_note: "str | None" = None
    callees: list[str] = []
    callers_by_call_graph: list[str] = []
    callers_by_text_search: list[dict] = []
    is_reachable: "bool | None" = None
    entry_point_path: "list[str] | None" = None

    if context is not None:
        try:
            functions_in_file = context.index.list_functions_in_file(candidate.path)
            resolved_function, resolution_note = _resolve_containing_function(
                functions_in_file, candidate
            )
            if resolved_function is not None:
                func_id = resolved_function["id"]
                callees = list(context.call_graph.get(func_id, []))
                callers_by_call_graph = list(context.reverse_call_graph.get(func_id, []))
                name = resolved_function.get("name")
                if name:
                    callers_by_text_search = context.index.search_usages(name)
                is_reachable = context.reachability.is_reachable_from_entry_point(func_id)
                if is_reachable:
                    entry_point_path = context.reachability.get_entry_point_path(func_id)
        except Exception as exc:  # noqa: BLE001 -- isolate to this candidate, never propagate
            errors.append(f"graph enrichment failed: {type(exc).__name__}: {exc}")
    else:
        resolution_note = (
            "no investigation context available "
            "(parse produced no usable analyzer_output.json/call_graph.json)"
        )

    try:
        target_file = repo_root / candidate.path
        related_tests = testing_support.tests_for_file(repo_root, target_file)
        test_support_rating = testing_support.score_test_support(related_tests)
    except Exception as exc:  # noqa: BLE001
        related_tests = []
        test_support_rating = None
        errors.append(f"test discovery failed: {type(exc).__name__}: {exc}")

    sink_matches: "list[dict] | None" = None
    if vuln_class:
        try:
            all_sinks = vulnerability_patterns.extract_repo_sinks(repo_root, vuln_class)
            sink_matches = [s for s in all_sinks if s.get("file") == candidate.path]
        except Exception as exc:  # noqa: BLE001
            errors.append(f"sink extraction failed: {type(exc).__name__}: {exc}")

    candidate.enrichment = CandidateEnrichment(
        functions_in_file=functions_in_file,
        resolved_function=resolved_function,
        resolution_note=resolution_note,
        callees=callees,
        callers_by_call_graph=callers_by_call_graph,
        callers_by_text_search=callers_by_text_search,
        is_reachable_from_entry_point=is_reachable,
        entry_point_path=entry_point_path,
        related_tests=related_tests,
        test_support_rating=test_support_rating,
        sink_matches=sink_matches,
        enrichment_errors=errors,
    )


def _resolve_containing_function(
    functions_in_file: list[dict],
    candidate: RepositoryCandidate,
) -> "tuple[dict | None, str | None]":
    """Resolve which function in ``functions_in_file`` contains -- or is
    nearest to -- the candidate's strongest evidence's ``hit_line``.

    Never fabricates a match: an explicit note accompanies any fallback,
    and ``None`` with a note is returned rather than guessing when nothing
    can be resolved.
    """
    if not functions_in_file:
        return None, "file has no parsed functions (module-level code, or unsupported/unparsed file)"

    evidence_with_tier = [e for e in candidate.evidence if e.tier is not None]
    if not evidence_with_tier:
        return None, "no evidence carries a tier"
    strongest = max(evidence_with_tier, key=lambda e: e.tier)

    hit_line = strongest.hit_line
    if hit_line is None:
        return None, "strongest evidence carries no hit_line"

    containing = [
        f
        for f in functions_in_file
        if f.get("startLine") is not None
        and f.get("endLine") is not None
        and f["startLine"] <= hit_line <= f["endLine"]
    ]
    if containing:
        return containing[0], None

    with_start_line = [f for f in functions_in_file if f.get("startLine") is not None]
    if not with_start_line:
        return None, "no function has line-range metadata to match against"

    nearest = min(with_start_line, key=lambda f: (abs(f["startLine"] - hit_line), f["startLine"]))
    return nearest, f"no function contains hit_line {hit_line}; used nearest function by start line"
