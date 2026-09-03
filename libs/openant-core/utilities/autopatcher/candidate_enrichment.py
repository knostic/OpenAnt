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

import ast
import os
from dataclasses import dataclass, field
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
    # file_path -> {qualified_name -> literal-assignment record}. Populated
    # once here (see _collect_repo_constants below), covering every Python
    # file RepositoryIndex already knows about (i.e. every file containing
    # at least one function/class) -- a file with zero functions/classes is
    # never scanned, an accepted gap for a "smallest extension" (see
    # build_investigation_context's docstring). Default {} keeps existing
    # hand-built test fixtures (which construct this dataclass without the
    # field) working unchanged.
    constants: dict = field(default_factory=dict)


_LITERAL_WRAPPER_CTORS = {"frozenset": frozenset, "set": set, "list": list, "tuple": tuple, "dict": dict}
_BASE_LITERAL_NODE_TYPES = (ast.Set, ast.List, ast.Tuple, ast.Dict, ast.Constant, ast.UnaryOp)


def _canonicalize_literal(value: object) -> object:
    """Recursively convert an ast.literal_eval() result into a hashable
    form, so it can live inside a frozen, hashable Anchor/AnchorValue
    (mutable set/list/dict are not hashable). Shape-preserving: a set-like
    input always canonicalizes to frozenset, list-like to tuple, dict to a
    sorted tuple of (key, value) pairs -- recursively, so nested literal
    containers are handled too.

    Raises TypeError for a bytes/bytearray leaf, at any nesting depth --
    caught by _evaluate_literal_rhs's own callers (the same "except
    Exception: non_literal" idiom already used everywhere else in that
    function), never propagated further. ast.literal_eval happily
    evaluates a bytes literal (e.g. ``b'#!python'``, a real, ordinary
    module-level constant shape -- see distlib's own SHEBANG_PYTHON/
    SHEBANG_PYTHONW, a real urllib3/pip investigation exposed this via
    execution_recorder.to_jsonable(), which has no bytes representation
    and, by design, no str()/repr() fallback -- see that module's own
    docstring). A raw byte string is exactly the kind of value this
    module's "non_literal" classification already exists for -- the same
    treatment already given to attribute access, name references, and any
    other call shape (see _evaluate_literal_rhs's own docstring) --
    extended here to a literal VALUE ast.literal_eval can produce but this
    module has no safe representation for, rather than special-casing
    to_jsonable() or inventing a lossy/irreversible encoding. bytearray is
    included for symmetry even though ast.literal_eval/this module's own
    wrapper constructors never actually produce one today."""
    if isinstance(value, (bytes, bytearray)):
        raise TypeError(f"unsupported literal value type for candidate enrichment: {type(value).__name__}")
    if isinstance(value, dict):
        return tuple(sorted(
            (_canonicalize_literal(k), _canonicalize_literal(v)) for k, v in value.items()
        ))
    if isinstance(value, (set, frozenset)):
        return frozenset(_canonicalize_literal(v) for v in value)
    if isinstance(value, (list, tuple)):
        return tuple(_canonicalize_literal(v) for v in value)
    return value  # str/int/float/bool/None/complex -- already hashable


def _evaluate_literal_rhs(node: "ast.AST") -> "tuple[str, str | None, object]":
    """Evaluate one assignment's RHS deterministically. Returns
    ``(outcome, ast_literal_kind, value)``. ``outcome`` is ``"literal"`` or
    ``"non_literal"`` -- never guessed, never partially evaluated (e.g. a
    dict literal with one non-literal value fails whole, never yields a
    partial dict).

    Supports bare literal expressions (Set/List/Tuple/Dict/Constant, or
    UnaryOp of one -- e.g. ``-1``) directly via ``ast.literal_eval``, plus
    exactly one call-shaped exception: a zero-or-one-argument call to
    ``frozenset``/``set``/``list``/``tuple``/``dict`` wrapping a bare
    literal (e.g. ``frozenset(["Authorization"])``) -- the exact shape
    urllib3's own ``DEFAULT_REMOVE_HEADERS_ON_REDIRECT`` declaration uses.
    Any other call, attribute access, name reference, or expression is
    ``"non_literal"`` -- as is a syntactically-literal value (at any
    nesting depth) containing bytes/bytearray, which ``ast.literal_eval``
    can produce but this module has no safe representation for (see
    ``_canonicalize_literal``'s own docstring).
    """
    ctor_name: "str | None" = None
    literal_node = node

    if isinstance(node, ast.Call):
        func = node.func
        if not (
            isinstance(func, ast.Name)
            and func.id in _LITERAL_WRAPPER_CTORS
            and not node.keywords
            and len(node.args) <= 1
        ):
            return "non_literal", None, None
        ctor_name = func.id
        if not node.args:
            try:
                return "literal", f"{ctor_name}_call", _canonicalize_literal(_LITERAL_WRAPPER_CTORS[ctor_name]())
            except Exception:
                return "non_literal", None, None
        literal_node = node.args[0]

    if not isinstance(literal_node, _BASE_LITERAL_NODE_TYPES):
        return "non_literal", None, None

    try:
        raw = ast.literal_eval(literal_node)
    except Exception:
        return "non_literal", None, None

    if ctor_name is not None:
        try:
            raw = _LITERAL_WRAPPER_CTORS[ctor_name](raw)
        except Exception:
            return "non_literal", None, None
        try:
            return "literal", f"{ctor_name}_call", _canonicalize_literal(raw)
        except Exception:
            return "non_literal", None, None

    try:
        return "literal", type(literal_node).__name__, _canonicalize_literal(raw)
    except Exception:
        return "non_literal", None, None


def _extract_literal_constants(file_text: str) -> "dict[str, dict]":
    """Walk module-level and class-level simple assignments in ``file_text``
    and return ``{qualified_name: record}`` -- ``qualified_name`` is the
    bare name at module scope, ``"ClassName.name"`` at class scope, matching
    ``RepositoryIndex``'s own func_id convention.

    Only ``Assign``/``AnnAssign`` nodes with a single ``ast.Name`` target,
    at module level or directly inside a class body, are considered --
    mirroring ``impact_surface.py``'s own module/class-scope restriction.
    Multi-target (``a = b = {...}``) and destructuring/attribute targets
    are excluded here entirely (not "non_literal" -- they're not a
    single-name assignment at all). Augmented assignment (``X |= {...}``)
    and annotation-only (``x: int``, no RHS) are recorded with their own
    explicit outcome, never a guessed/fabricated value.

    Returns ``{}`` when ``file_text`` does not parse as Python -- callers
    must treat that as "no constants available", never guess.
    """
    try:
        tree = ast.parse(file_text)
    except (SyntaxError, ValueError):
        return {}

    result: "dict[str, dict]" = {}

    def _record(name: str, class_name: "str | None", line: int, end_line: int,
                outcome: str, kind: "str | None", value: object) -> None:
        qualified = f"{class_name}.{name}" if class_name else name
        result[qualified] = {
            "qualified_name": qualified,
            "class_name": class_name,
            "name": name,
            "outcome": outcome,
            "ast_literal_kind": kind,
            "value": value,
            "line": line,
            "end_line": end_line,
        }

    def _handle(node: "ast.Assign | ast.AnnAssign | ast.AugAssign", class_name: "str | None") -> None:
        end_line = getattr(node, "end_lineno", node.lineno) or node.lineno
        if isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name):
                _record(node.target.id, class_name, node.lineno, end_line, "augmented_assign", None, None)
            return
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
            return  # multi-target / destructuring / attribute target -- out of scope, not a guess
        name = targets[0].id
        if isinstance(node, ast.AnnAssign) and node.value is None:
            _record(name, class_name, node.lineno, end_line, "annotation_only", None, None)
            return
        outcome, kind, value = _evaluate_literal_rhs(node.value)
        _record(name, class_name, node.lineno, end_line, outcome, kind, value)

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            _handle(node, None)
        elif isinstance(node, ast.ClassDef):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    _handle(child, node.name)

    return result


def _collect_repo_constants(repo_root: Path, index: RepositoryIndex) -> dict:
    """Build the ``InvestigationContext.constants`` table: for every Python
    file ``index`` already knows about (i.e. every file containing at least
    one function/class -- ``index.by_file``), read and AST-walk it once for
    module/class-level literal assignments. A single file's read/parse
    failure is isolated to that file (skipped, never aborts the whole
    table); there is no dedicated error channel here because this mirrors
    ``list_functions_in_file``'s own best-effort, per-file posture."""
    constants: dict = {}
    for file_path in index.by_file.keys():
        if not file_path.endswith((".py", ".pyi")):
            continue
        try:
            file_text = (repo_root / file_path).read_text(encoding="utf-8")
        except Exception:
            continue
        per_file = _extract_literal_constants(file_text)
        if per_file:
            constants[file_path] = per_file
    return constants


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

    try:
        constants = _collect_repo_constants(repo_root, index)
    except Exception:
        constants = {}

    return InvestigationContext(
        index=index,
        call_graph=call_graph,
        reverse_call_graph=reverse_call_graph,
        reachability=reachability,
        constants=constants,
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

    scope_constants: list[dict] = []
    if context is not None:
        try:
            file_constants = context.constants.get(candidate.path, {})
            # unitType == "module_level" is this parser's one-per-file
            # whole-module catch-all unit (spans the entire file), used by
            # _resolve_containing_function whenever no real function's
            # line range contains the hit_line -- exactly what happens for
            # a class-body constant sitting between methods (observed
            # directly against a real repo: a hit_line on
            # Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT resolved to this
            # catch-all, with className=None, even though the constant
            # itself is class-scoped). That className=None carries no real
            # narrowing signal -- it must be treated the same as
            # resolved_function being None entirely, not as "the real
            # scope is module-only" (which would incorrectly exclude every
            # class-level constant in the file). A genuine top-level
            # function/method resolution (unitType != "module_level")
            # still narrows normally.
            have_narrowing_signal = (
                resolved_function is not None
                and resolved_function.get("unitType") != "module_level"
            )
            resolved_class_name = resolved_function.get("className") if have_narrowing_signal else None
            for entry in file_constants.values():
                entry_class = entry["class_name"]
                # Module-level constants (entry_class is None) are always
                # in scope. Class-level constants are scoped to the
                # resolved function's own class when there is a real
                # narrowing signal; otherwise every class-level constant
                # in the file is included rather than silently missed
                # (mirrors sink_matches' independence from
                # resolved_function, below, applied to the analogous "no
                # signal to narrow by" case here).
                if entry_class is not None and have_narrowing_signal and entry_class != resolved_class_name:
                    continue
                scope_constants.append(entry)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"constant scope resolution failed: {type(exc).__name__}: {exc}")

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
        scope_constants=scope_constants,
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
