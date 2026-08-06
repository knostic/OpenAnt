"""
Remediation planner (experimental).

Planning is split into two bounded, distinctly-labeled LLM calls around one
deterministic bridge:

    initial repository evidence
    -> generate_remediation_plan()        ("target_discovery" role)
    -> build_planner_evidence()           (deterministic verification + enrichment)
    -> generate_remediation_strategy()    ("remediation_strategy" stage)
    -> Patch Generator

`generate_remediation_plan(vulnerability_text, llm, code_context)`: one
bounded LLM call (stage "remediation_planning") that identifies files,
symbols, and open questions worth investigating -- exploratory, not
authoritative. Returns a `RemediationPlanResult` (rendered Markdown plus the
parsed, unverified `target_files`/`target_symbols`) -- never a patch, never
code. On any call/parsing failure this degrades to an all-empty result,
never raises.

`build_planner_evidence(...)`: a deterministic bridge from that (unverified)
Planner proposal to a separately-labeled evidence block, built entirely from
existing OpenAnt analysis (RepositoryIndex, call graph, reachability,
constants, candidate enrichment/fusion/rendering). Every proposed
file/symbol is verified against the real repository before it is allowed
anywhere near enrichment -- an unverifiable proposal is dropped, never
presented as evidence. No new LLM call, no new analysis, no repository-wide
reparsing: this only ever reuses the InvestigationContext already built for
this run.

`generate_remediation_strategy(...)`: a second, distinct LLM call (stage
"remediation_strategy") that runs only once verified Planner evidence
exists, and receives that verified evidence in addition to everything the
first call saw. It selects the smallest evidence-backed remediation
mechanism -- still never a diff, never code. Its `target_files`/
`target_symbols` are deterministically re-verified against the same
repository before anything from it reaches Patch Generation; anything that
doesn't verify is dropped with an explicit warning, never silently promoted.
On any call/parsing failure, or when there is no verified evidence to give
it, this degrades to an all-empty result and the pipeline continues with
whatever evidence already existed -- never raises, never a third LLM call.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import NamedTuple

from .content_relocation import find_unique_occurrence, old_side_anchors
from .context_budget import ContextBudgetController
from .diff_parsing import parse_diff
from .repository_grounding_models import DiscoveryEvidence, RepositoryCandidate

_PROMPT_PATH = Path(__file__).parent / "prompts" / "remediation_planner.md"
_STRATEGY_PROMPT_PATH = Path(__file__).parent / "prompts" / "remediation_strategy.md"

_FENCE_RE = re.compile(r"^```(?:json)?\s*\n?(.*?)\n?```$", re.DOTALL)

_SECTIONS = [
    ("security_invariant", "Security invariant", False),
    ("remediation_mechanism", "Likely remediation mechanism", False),
    ("target_files", "Likely remediation files", True),
    ("target_symbols", "Relevant symbols", True),
    ("required_edits", "Required edits", True),
    ("approaches_to_avoid", "Approaches to avoid", True),
    ("explicit_unknowns", "Explicit unknowns", True),
]


class RemediationPlanResult(NamedTuple):
    """The Planner's output, kept in one minimal shape rather than a model
    hierarchy: the rendered Markdown (unchanged from before), plus the
    parsed-but-UNVERIFIED target_files/target_symbols lists the pipeline
    needs to build the deterministic evidence bridge. Never claims these
    paths/symbols are real -- that's `build_planner_candidates`'s job."""

    rendered: str
    target_files: "list[str]"
    target_symbols: "list[str]"


_EMPTY_PLAN_RESULT = RemediationPlanResult(rendered="", target_files=[], target_symbols=[])


def _parse_json_response(raw: str) -> "dict | None":
    if not raw or not isinstance(raw, str):
        return None
    text = raw.strip()
    m = _FENCE_RE.match(text)
    if m:
        text = m.group(1).strip()
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _render_plan(plan: dict) -> str:
    # "Target Discovery" (not "Remediation Plan") is deliberate: this is the
    # exploratory first call's output. It is never authoritative for Patch
    # Generation once a Final Strategy exists -- that distinction is carried
    # by this label and by context ordering (Final Strategy always renders
    # last), not by removing or hiding any field here.
    lines = ["## Target Discovery Plan (exploratory — not authoritative for Patch Generation)"]

    for key, label, is_list in _SECTIONS:
        value = plan.get(key)
        if is_list:
            if not value:
                continue
            lines.append(f"\n**{label}:**")
            lines.extend(f"- {item}" for item in value)
        else:
            if not value:
                continue
            lines.append(f"\n**{label}:** {value}")

    if len(lines) == 1:
        return ""  # nothing but the heading -- no usable content
    return "\n".join(lines) + "\n"


def _string_list(value) -> "list[str]":
    """Best-effort coercion for a JSON field that is *supposed* to be a list
    of strings: a non-list value degrades to [], and non-string items are
    dropped rather than crashing anything downstream."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def generate_remediation_plan(vulnerability_text: str, llm, code_context: str = "") -> RemediationPlanResult:
    """
    Ask the model to commit to a remediation strategy before Patch
    Generation runs. Never generates code or a diff. Best-effort: any call
    or parsing failure returns an all-empty RemediationPlanResult so the
    pipeline degrades exactly like every other optional context section --
    no rendered plan, and no Planner candidates for the enrichment bridge.
    """
    system_prompt = _PROMPT_PATH.read_text(encoding="utf-8")
    user_message = "## Vulnerability report\n\n" + vulnerability_text
    if code_context:
        user_message += "\n\n## Repository evidence\n\n" + code_context

    try:
        raw = llm.complete(system_prompt, user_message, stage="remediation_planning")
    except Exception:
        return _EMPTY_PLAN_RESULT

    plan = _parse_json_response(raw)
    if plan is None:
        return _EMPTY_PLAN_RESULT

    try:
        rendered = _render_plan(plan)
    except Exception:
        rendered = ""

    return RemediationPlanResult(
        rendered=rendered,
        target_files=_string_list(plan.get("target_files")),
        target_symbols=_string_list(plan.get("target_symbols")),
    )


# ---------------------------------------------------------------------------
# Planner -> deterministic enrichment bridge
#
# Everything below treats the Planner's target_files/target_symbols as
# hypotheses, never as facts. Nothing here adds a new LLM call, a new
# repository parse, a new index, or a new call graph -- it only verifies
# Planner proposals against data structures (RepositoryIndex, constants,
# the call graph) that InvestigationContext already built for this run,
# then reuses the existing enrich_candidates/fuse_evidence/
# render_repository_understanding chain unmodified.
# ---------------------------------------------------------------------------

_PLANNER_HEADING = "## Planner-Proposed Candidate Evidence"
_PLANNER_DISCLAIMER = (
    "*The file and symbol locations below were proposed by the experimental "
    "Remediation Planner -- an LLM hypothesis, not deterministic Repository "
    "Grounding. Every path and symbol shown here was independently verified "
    "to exist in this repository before any enrichment ran. The structural "
    "facts below (call graph, constants, tests, etc.) are deterministic. "
    "None of this confirms that these locations are vulnerable, or that "
    "they are the correct remediation target.*"
)


def _verify_file(raw_path, repo_root: Path) -> "str | None":
    """A Planner-proposed path survives only if it is a non-empty string,
    not absolute, contains no `..` traversal segment, resolves to a real
    regular file *inside* repo_root, and is returned as the canonical
    repo-relative path (never the raw string the model happened to use)."""
    if not isinstance(raw_path, str):
        return None
    raw_path = raw_path.strip()
    if not raw_path:
        return None
    if raw_path.startswith("/") or raw_path.startswith("\\"):
        return None
    if len(raw_path) > 1 and raw_path[1] == ":" and raw_path[0].isalpha():
        return None  # Windows drive-letter absolute path, e.g. "C:\..."
    if ".." in Path(raw_path).parts:
        return None

    try:
        resolved_root = repo_root.resolve()
        candidate = (resolved_root / raw_path).resolve()
        rel = candidate.relative_to(resolved_root)
    except (ValueError, OSError):
        return None

    if not candidate.is_file():
        return None
    return str(rel)


def _split_symbol_entry(raw: str) -> "tuple[str | None, str]":
    """Supports `path/to/file.py:Class.method`, `path/to/file.py:Class`,
    and a bare symbol name with no file hint at all."""
    raw = raw.strip()
    if ":" in raw:
        maybe_file, _, maybe_symbol = raw.rpartition(":")
        if maybe_file.strip() and maybe_symbol.strip():
            return maybe_file.strip(), maybe_symbol.strip()
    return None, raw


def _file_part(func_id: str) -> str:
    colon_idx = func_id.rfind(":")
    return func_id[:colon_idx] if colon_idx > 0 else func_id


class _SymbolMatch(NamedTuple):
    """The richer result of resolving one Planner-proposed symbol string --
    everything the source-excerpt bridge needs (kind/end_line/func_id) in
    addition to the (file, label, line) shape `_resolve_symbol` has always
    returned. Built once per symbol; never re-derived by a second lookup
    implementation."""

    file: str
    label: str
    kind: str  # "function" | "constant"
    line: int
    end_line: "int | None"
    func_id: "str | None"  # set only when kind == "function"


def _resolve_symbol_details(raw: str, repo_root: Path, context) -> "_SymbolMatch | None":
    """Resolve one Planner-proposed symbol string using only existing
    lookups -- RepositoryIndex.search_by_name for functions, the
    already-built constants table for module/class-level constants.
    Returns None (never a fabricated line) if the symbol can't be
    confirmed, or if a stated file hint doesn't itself verify, or if the
    only match found belongs to a different file than the one proposed.

    A qualified proposal (``"ClassName.method"``) additionally requires the
    matched function's own class to equal that qualifier -- bare-name
    search alone is not enough, since a repository can legitimately contain
    the same method name on more than one class (e.g. urllib3's
    ``PoolManager.urlopen`` and ``HTTPConnectionPool.urlopen``). Without
    this check, the first same-named match anywhere in the repo would be
    accepted silently, under the ORIGINALLY PROPOSED label, even when it
    belongs to a different class entirely. A proposal with no class
    qualifier (a bare function name) is unaffected -- bare-name matching
    behaves exactly as before."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    if context is None:
        return None

    file_hint, name = _split_symbol_entry(raw)
    bare_name = name.rsplit(".", 1)[-1]
    class_qualifier = name.rsplit(".", 1)[0] if "." in name else None

    verified_file = None
    if file_hint:
        verified_file = _verify_file(file_hint, repo_root)
        if verified_file is None:
            return None  # a stated file that doesn't verify invalidates the whole pairing

    index = getattr(context, "index", None)
    if index is not None and bare_name:
        for match in index.search_by_name(bare_name, exact=True):
            func_id = match.get("id", "")
            candidate_file = _file_part(func_id)
            if verified_file is not None and candidate_file != verified_file:
                continue
            if class_qualifier is not None and match.get("className") != class_qualifier:
                continue
            line = match.get("startLine")
            if line is not None:
                return _SymbolMatch(
                    file=candidate_file, label=name, kind="function",
                    line=line, end_line=match.get("endLine"), func_id=func_id,
                )

    constants = getattr(context, "constants", None) or {}
    files_to_check = [verified_file] if verified_file else list(constants.keys())
    for f in files_to_check:
        for qualified_name, record in constants.get(f, {}).items():
            if qualified_name == name or qualified_name.rsplit(".", 1)[-1] == bare_name:
                line = record.get("line")
                if line is not None:
                    return _SymbolMatch(
                        file=f, label=name, kind="constant",
                        line=line, end_line=record.get("end_line"), func_id=None,
                    )

    return None


def _resolve_symbol(raw: str, repo_root: Path, context) -> "tuple[str, str, int] | None":
    """Original (file, label, line) shape, kept as-is for existing callers
    and tests. See `_resolve_symbol_details` for the richer shape the
    source-excerpt bridge needs -- this is a thin wrapper over it, not a
    second implementation."""
    match = _resolve_symbol_details(raw, repo_root, context)
    if match is None:
        return None
    return match.file, match.label, match.line


def _resolve_planner_symbols(plan: RemediationPlanResult, repo_root: Path, context) -> "dict[str, _SymbolMatch]":
    """Resolve every Planner-proposed symbol exactly once, keyed by its
    resolved file (first-occurrence wins per file, matching the Planner's
    own target_symbols order). Shared by build_planner_candidates (which
    only reads .label/.line) and build_planner_source_excerpts (which also
    needs .kind/.end_line/.func_id) so this resolution never runs twice."""
    resolved: "dict[str, _SymbolMatch]" = {}
    for raw_symbol in plan.target_symbols:
        match = _resolve_symbol_details(raw_symbol, repo_root, context)
        if match is None:
            continue
        if match.file not in resolved:
            resolved[match.file] = match
    return resolved


def build_planner_candidates(
    plan: RemediationPlanResult,
    repo_root: Path,
    context,
    symbol_locations: "dict[str, _SymbolMatch] | None" = None,
) -> "list[RepositoryCandidate]":
    """
    Verify every Planner-proposed file against the real repository first;
    only verified files ever become candidates. Symbols are then used only
    to pick a hit_line for a file that already verified -- an unresolved
    symbol never suppresses its file's candidate, and a symbol resolving to
    a file the Planner did not also name as a target_file is never used to
    invent a new candidate. Order matches the Planner's own target_files
    order (first-occurrence deduplicated); the result is capped at the same
    small constant candidate_selection.py already uses for ordinary
    grounding, reused here rather than re-derived.

    `symbol_locations`, when given, must be `_resolve_planner_symbols`'s
    own output -- passed in by build_planner_evidence so symbol resolution
    runs exactly once per Planner proposal, shared with the source-excerpt
    bridge, rather than being recomputed here. Computed internally when
    omitted, so existing 3-argument callers are unaffected.
    """
    if not plan.target_files:
        return []

    verified_files: "list[str]" = []
    seen: set = set()
    for raw in plan.target_files:
        vf = _verify_file(raw, repo_root)
        if vf and vf not in seen:
            seen.add(vf)
            verified_files.append(vf)

    if not verified_files:
        return []

    from .candidate_selection import DEFAULT_MAX_CANDIDATES

    if symbol_locations is None:
        symbol_locations = _resolve_planner_symbols(plan, repo_root, context)

    candidates = []
    for path in verified_files[:DEFAULT_MAX_CANDIDATES]:
        match = symbol_locations.get(path) if path in seen else None
        label, line = (match.label, match.line) if match else (None, None)
        evidence = DiscoveryEvidence(
            pass_name="planner_proposed",
            # 0, not None: _resolve_containing_function only reads hit_line
            # from evidence entries that carry SOME tier (its "no evidence
            # carries a tier" guard), so a real int is needed for a verified
            # symbol's hit_line to actually be used. 0 is deliberately below
            # every real repo_locator tier (1-4, see candidate_selection.py's
            # docstring) so it can never be mistaken for one. The CANDIDATE's
            # own best_tier stays None (below) -- that is what render_
            # repository_understanding's "best tier" line actually reads, so
            # the rendered text never claims an ordinary Repository Grounding
            # tier for a Planner-origin candidate.
            tier=0,
            matched_tokens=[label] if label else None,
            total_occurrences=None,
            hit_line=line if line is not None else 0,
            resolution_strategy="planner_symbol_verified" if line is not None else "planner_file_only",
        )
        candidates.append(RepositoryCandidate(path=path, evidence=[evidence], best_tier=None))
    return candidates


_SOURCE_SUBHEADING = "### Verified source from Planner-proposed candidates"
_SOURCE_DISCLAIMER = (
    "*The source below was loaded from the target repository. Each path or "
    "symbol was proposed by the Remediation Planner and then independently "
    "verified to exist before its source was read -- inclusion here does "
    "not prove that it is the correct remediation target.*"
)


_DEFINITION_CONTEXT_LINES = 3
"""Lines of exact repository text to include on each side of a rendered
"Target definition" block in the Final-Target Remediation Slice (see
build_final_target_slice below), so Patch Generation has enough real,
repository-verbatim surrounding lines to construct a unified diff hunk
without inventing them from memory.

3, not an arbitrary guess: it matches the number of context lines a
unified diff conventionally carries on each side of a change (git's own
default context is 3 lines) -- the exact quantity this system's own
output format already assumes, tied to what a patch actually needs rather
than picked freehand.

Applies only where a bounded line-range read already happens (the
constant branch of _read_symbol_source, and the two other line-range
reads inside _build_final_target_slice_inner) -- never to a
whole-function-body read (get_function_code) or a whole-file read,
neither of which needs it: both already contain ample internal context by
construction. This is a structural distinction (bounded line-range read
vs. whole-body/whole-file read), not a policy keyed on "is this a
constant" -- the same widening would apply identically to any other
short, line-range-shaped definition (a class attribute, a type alias, an
enum member, in any language) that this codebase resolves the same way.
"""


def _padded_line_range(line: int, end_line: int, pad: int) -> "tuple[int, int]":
    """Expand a (line, end_line) span by `pad` lines on each side, clamped
    to a minimum start of 1. Pure arithmetic -- no new repository read: the
    upper bound needs no file-length lookup because
    RepositoryIndex.read_file_section already clamps its own end_line to
    min(len(lines), end_line) (repository_index.py), so passing an
    end_line past EOF is always safe. pad <= 0 returns the input unchanged,
    so this is a strict no-op for every caller that doesn't opt in."""
    if pad <= 0:
        return line, end_line
    return max(1, line - pad), end_line + pad


def _rendered_end_line(start: int, source: str) -> int:
    """The end line a rendered block's header must claim, given the text
    actually returned for it starting at `start`.

    Not simply `start + pad`: read_file_section clamps its own end_line to
    min(len(lines), end_line) (repository_index.py) when a padded request
    runs past EOF, silently returning fewer lines than requested -- using
    the unclamped requested end here would make the header claim lines
    that were never actually shown. Derived from `source`'s own line
    count, which is already in hand -- no new repository read."""
    return start + max(0, len(source.splitlines()) - 1)


def _read_symbol_source(match: "_SymbolMatch", context, pad_lines: int = 0) -> "str | None":
    """Real source text for one verified symbol, using only existing
    RepositoryIndex accessors -- get_function_code for a resolved function,
    read_file_section for a resolved constant's exact defining line(s).
    Never reconstructs source by hand; returns None (never fabricated
    text) if the index/context can't produce it.

    `pad_lines` (default 0, so every existing caller is unaffected) widens
    the constant branch's read by that many lines on each side -- see
    _padded_line_range and FINAL_TARGET_SLICE_MAX_CHARS' docstring for why.
    Never applies to the function branch: a rendered whole-function body
    already contains its own internal context by construction, so this
    isn't "constants get padding, functions don't" as a policy choice --
    it only widens the one branch that performs a bounded line-range read
    at all; the function branch uses a different accessor entirely."""
    index = getattr(context, "index", None) if context is not None else None
    if index is None:
        return None
    if match.kind == "function" and match.func_id:
        return index.get_function_code(match.func_id) or None
    if match.kind == "constant" and match.end_line is not None:
        start, end = _padded_line_range(match.line, match.end_line, pad_lines)
        return index.read_file_section(match.file, start, end) or None
    return None


def _render_source_excerpt(path: str, label: "str | None", start: int, end: int, source: str) -> str:
    if label:
        header = f"#### Verified source: `{path}:{label}` (lines {start}–{end})"
    else:
        header = f"#### Verified source: `{path}` (full file, {end} lines)"
    return f"{header}\n\n```python\n{source.rstrip()}\n```\n"


def build_planner_source_excerpts(
    candidates: "list[RepositoryCandidate]",
    symbol_locations: "dict[str, _SymbolMatch]",
    repo_root: Path,
    context,
) -> str:
    """
    Two deterministic passes over the already-verified Planner candidates
    (same order build_planner_candidates produced) -- no scoring, no
    ranking weights, just a strict priority split:

    Pass 1: every candidate with a verified Planner symbol gets its exact
    symbol source considered for the budget FIRST, in candidate order.
    Never the enrichment pipeline's own containing-function guess (for a
    file-only candidate that is the whole-module catch-all, not a real
    symbol) -- only `symbol_locations.get(path)`, which holds nothing
    unless a Planner symbol was independently verified for that path. If
    the symbol's source can't be read, or its excerpt doesn't fit even
    after earlier Pass-1 excerpts, it is omitted explicitly -- never
    truncated, and never silently replaced by that file's full content.

    Pass 2: full-file fallback, and ONLY for candidates whose Planner
    symbol never resolved at all (not for one whose excerpt merely failed
    to fit in Pass 1 -- that stays omitted, per above). Runs strictly
    after every Pass-1 excerpt has already had first claim on the shared
    budget, so a lower-priority fallback can never consume budget a
    higher-priority verified symbol still needed.

    Best-effort throughout: any failure returns "" so the caller falls
    back to structural evidence alone.
    """
    if not candidates:
        return ""

    from .evidence_fusion import DEFAULT_MAX_CHARS as _budget

    blocks: "list[str]" = []
    symbol_omitted: "list[str]" = []
    fallback_omitted: "list[str]" = []
    read_failed: "list[str]" = []
    running = 0
    seen: set = set()
    fallback_eligible: "list[str]" = []

    # Pass 1 -- verified symbol excerpts only.
    for candidate in candidates:
        path = candidate.path
        if path in seen:
            continue  # defensive: build_planner_candidates already dedupes by path
        seen.add(path)

        match = symbol_locations.get(path)
        if match is None:
            fallback_eligible.append(path)
            continue

        label = f"{match.file}:{match.label}"
        source = _read_symbol_source(match, context)
        if source is None:
            read_failed.append(label)
            continue

        block = _render_source_excerpt(match.file, match.label, match.line, match.end_line, source)
        if running + len(block) <= _budget:
            blocks.append(block)
            running += len(block)
        else:
            symbol_omitted.append(label)

    # Pass 2 -- full-file fallback, only for candidates with no resolved
    # symbol at all (never for one whose symbol excerpt was itself omitted
    # above -- that stays omitted, it is not "upgraded" to a full file).
    for path in fallback_eligible:
        try:
            full_text = (repo_root / path).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            read_failed.append(path)
            continue
        n_lines = len(full_text.splitlines())
        block = _render_source_excerpt(path, None, 1, n_lines, full_text)
        if running + len(block) <= _budget:
            blocks.append(block)
            running += len(block)
        else:
            fallback_omitted.append(path)

    if not blocks and not symbol_omitted and not fallback_omitted and not read_failed:
        return ""

    lines = [_SOURCE_SUBHEADING, "", _SOURCE_DISCLAIMER]
    if blocks:
        lines.append("")
        lines.append("\n".join(blocks).rstrip())

    notes = []
    if symbol_omitted:
        notes.append(f"symbol excerpt(s) omitted to stay within the {_budget}-character budget: {', '.join(symbol_omitted)}")
    if fallback_omitted:
        notes.append(f"full-file fallback(s) omitted to stay within the {_budget}-character budget: {', '.join(fallback_omitted)}")
    if read_failed:
        notes.append(f"source could not be read: {', '.join(read_failed)}")
    if notes:
        lines.append("")
        lines.extend(f"*{n}.*" for n in notes)

    return "\n".join(lines) + "\n"


def _render_planner_evidence(understanding) -> str:
    """Thin wrapper around the existing renderer: re-labels its fixed
    heading + preamble with Planner-specific provenance wording, without
    duplicating any of its actual rendering logic. render_repository_
    understanding's header is always exactly `_HEADING + "\\n\\n" +
    _PREAMBLE + "\\n"` with no blank line inside _PREAMBLE itself, so
    splitting on the first two "\\n\\n" occurrences cleanly isolates
    (heading, preamble, everything else) -- "everything else" is the only
    part reused verbatim here."""
    from .evidence_fusion import render_repository_understanding

    rendered = render_repository_understanding(understanding)
    if not rendered:
        return ""
    parts = rendered.split("\n\n", 2)
    rest = parts[2] if len(parts) > 2 else ""
    if not rest.strip():
        return ""
    return f"{_PLANNER_HEADING}\n\n{_PLANNER_DISCLAIMER}\n\n{rest}"


def build_planner_evidence(
    plan: RemediationPlanResult,
    repo_root,
    vulnerability_text: str,
    context,
) -> str:
    """
    Best-effort bridge: verify the Planner's proposals against the target
    repository, run only the ones that verify through the existing
    deterministic enrich_candidates -> fuse_evidence -> render_repository_
    understanding chain (reusing `context`, never rebuilding it), and
    return a separately-labeled Markdown block. Returns "" -- never
    raises -- if there is no repo_root, nothing was proposed, nothing
    verified, or any downstream step fails; the caller's existing context
    is always left untouched either way.
    """
    if not repo_root or not (plan.target_files or plan.target_symbols):
        return ""
    try:
        root = Path(repo_root)
        # Resolved exactly once here, then reused for both candidate
        # construction (hit_line selection) and source-excerpt selection
        # below -- never re-derived by a second lookup pass.
        symbol_locations = _resolve_planner_symbols(plan, root, context)
        candidates = build_planner_candidates(plan, root, context, symbol_locations=symbol_locations)
        if not candidates:
            return ""

        from .candidate_enrichment import enrich_candidates
        from .candidate_selection import CandidateSelection
        from .evidence_fusion import fuse_evidence

        selection = CandidateSelection(
            generated=list(candidates),
            excluded_by_policy=[],
            eligible=list(candidates),
            selected=list(candidates),
            excluded_by_cap=[],
            max_candidates=len(candidates),
        )
        enrich_candidates(selection, root, vulnerability_text, context)
        understanding = fuse_evidence(selection, investigation_context_available=context is not None)
        structural = _render_planner_evidence(understanding)
        if not structural:
            return ""

        try:
            source_block = build_planner_source_excerpts(candidates, symbol_locations, root, context)
        except Exception:
            source_block = ""

        return f"{structural.rstrip()}\n\n{source_block}" if source_block else structural
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Final Strategy -- a second, distinct LLM call over materially new evidence
#
# Runs only after build_planner_evidence() has produced verified evidence.
# Selects the smallest evidence-backed remediation mechanism -- still never
# a diff, never code. Its own target_files/target_symbols are re-verified
# with the SAME _verify_file/_resolve_symbol_details helpers the bridge
# above already uses, before anything from it is rendered: no new
# repository analysis, no broader policy engine.
# ---------------------------------------------------------------------------

_STRATEGY_HEADING = "## Final Evidence-Backed Remediation Strategy"
_STRATEGY_DISCLAIMER = (
    "*This strategy is model reasoning constrained by the verified "
    "Planner-Proposed Candidate Evidence above -- every file and symbol "
    "named here was independently re-verified against the repository; "
    "anything proposed that did not verify was removed rather than "
    "presented as a target (see \"Unverified items removed\" below when "
    "present). This is the last planning section before Patch Generation.*"
)

_STRATEGY_SECTIONS = [
    ("extended_mechanism", "Extended mechanism", False),
    ("target_files", "Verified target files", True),
    ("target_symbols", "Verified target symbols", True),
    ("required_edits", "Required edits", True),
    ("rejected_targets", "Rejected discovery targets", True),
    ("security_invariant", "Security invariant", False),
    ("insufficient_evidence", "Insufficient evidence", True),
]


class RemediationStrategyResult(NamedTuple):
    """The Final Strategy call's output. `target_files`/`target_symbols`
    here are the DETERMINISTICALLY RE-VERIFIED subset of what the model
    proposed -- anything that did not verify is listed in `warnings`
    instead, never silently promoted. `rendered` (when non-empty) already
    reflects this verified subset, not the model's raw, unverified claim.

    `extended_mechanism`/`required_edits` are additive fields: the same
    already-parsed JSON values `_render_strategy` already renders into
    Markdown, ALSO kept here structurally so the Final-Target Remediation
    Slice builder can extract repository-looking identifiers from them
    without re-parsing `rendered` text. No prompt or JSON schema change --
    both fields already existed in the parsed response; this only stops
    discarding them after rendering."""

    rendered: str
    target_files: "list[str]"
    target_symbols: "list[str]"
    warnings: "list[str]"
    extended_mechanism: "str | None"
    required_edits: "list[str]"


_EMPTY_STRATEGY_RESULT = RemediationStrategyResult(
    rendered="", target_files=[], target_symbols=[], warnings=[],
    extended_mechanism=None, required_edits=[],
)


def _verify_strategy_targets(
    raw_files: "list[str]", raw_symbols: "list[str]", repo_root, context
) -> "tuple[list[str], list[str], list[str]]":
    """Re-verify the Final Strategy's own proposed files/symbols using the
    exact same path/symbol verification already used for the first
    Planner's proposals -- no second implementation, no broader policy
    engine. Returns (kept_files, kept_symbols, warnings); an item that
    doesn't verify is dropped and recorded in `warnings`, never silently
    lost and never allowed to abort the call."""
    warnings: "list[str]" = []
    kept_files: "list[str]" = []
    root = Path(repo_root) if repo_root else None

    seen_files: set = set()
    for raw in raw_files:
        vf = _verify_file(raw, root) if root is not None else None
        if vf and vf not in seen_files:
            seen_files.add(vf)
            kept_files.append(vf)
        else:
            warnings.append(f"unverified target_file removed: {raw}")

    kept_symbols: "list[str]" = []
    seen_symbols: set = set()
    for raw in raw_symbols:
        match = _resolve_symbol_details(raw, root, context) if root is not None else None
        if match is not None and raw not in seen_symbols:
            seen_symbols.add(raw)
            kept_symbols.append(raw)
        else:
            warnings.append(f"unverified target_symbol removed: {raw}")

    return kept_files, kept_symbols, warnings


def _render_strategy(
    plan: dict, verified_files: "list[str]", verified_symbols: "list[str]", warnings: "list[str]"
) -> str:
    working = dict(plan)
    working["target_files"] = verified_files
    working["target_symbols"] = verified_symbols

    body: "list[str]" = []
    for key, label, is_list in _STRATEGY_SECTIONS:
        value = working.get(key)
        if is_list:
            if not value:
                continue
            body.append(f"\n**{label}:**")
            body.extend(f"- {item}" for item in value)
        else:
            if not value:
                continue
            body.append(f"\n**{label}:** {value}")

    if warnings:
        body.append("\n**Unverified items removed:**")
        body.extend(f"- {w}" for w in warnings)

    if not body:
        return ""  # nothing usable -- a complete, correct answer, not an error

    return "\n".join([_STRATEGY_HEADING, "", _STRATEGY_DISCLAIMER] + body) + "\n"


def generate_remediation_strategy(
    vulnerability_text: str,
    llm,
    repo_root,
    context,
    repo_grounding_ctx: str = "",
    repository_understanding_ctx: str = "",
    discovery_plan_ctx: str = "",
    planner_evidence_ctx: str = "",
) -> RemediationStrategyResult:
    """
    Second, distinct LLM call (stage "remediation_strategy"). Runs only when
    there is verified Planner evidence to reason over -- with no
    `planner_evidence_ctx` there is nothing materially new for this call
    versus the first, so it is skipped entirely (no LLM call at all, not
    merely an empty result). Never generates code or a diff. Best-effort
    like `generate_remediation_plan`: any call or parsing failure returns an
    all-empty result so the pipeline continues with whatever evidence
    already existed -- never raises.

    `target_files`/`target_symbols` on the result are independently
    re-verified via `_verify_strategy_targets` before rendering -- an
    invented file or symbol never reaches Patch Generation through this
    call; it is dropped and recorded in `warnings` instead.
    """
    if not planner_evidence_ctx or not planner_evidence_ctx.strip():
        return _EMPTY_STRATEGY_RESULT

    system_prompt = _STRATEGY_PROMPT_PATH.read_text(encoding="utf-8")

    sections = ["## Vulnerability report\n\n" + vulnerability_text]
    if repo_grounding_ctx and repo_grounding_ctx.strip():
        sections.append("## Original Repository Grounding context\n\n" + repo_grounding_ctx)
    if repository_understanding_ctx and repository_understanding_ctx.strip():
        sections.append("## Ordinary Repository Understanding\n\n" + repository_understanding_ctx)
    if discovery_plan_ctx and discovery_plan_ctx.strip():
        sections.append("## Initial Target Discovery output\n\n" + discovery_plan_ctx)
    sections.append("## Verified Planner-Proposed Candidate Evidence\n\n" + planner_evidence_ctx)
    user_message = "\n\n".join(sections)

    try:
        raw = llm.complete(system_prompt, user_message, stage="remediation_strategy")
    except Exception:
        return _EMPTY_STRATEGY_RESULT

    plan = _parse_json_response(raw)
    if plan is None:
        return _EMPTY_STRATEGY_RESULT

    raw_files = _string_list(plan.get("target_files"))
    raw_symbols = _string_list(plan.get("target_symbols"))
    verified_files, verified_symbols, warnings = _verify_strategy_targets(
        raw_files, raw_symbols, repo_root, context
    )

    try:
        rendered = _render_strategy(plan, verified_files, verified_symbols, warnings)
    except Exception:
        rendered = ""

    return RemediationStrategyResult(
        rendered=rendered,
        target_files=verified_files,
        target_symbols=verified_symbols,
        warnings=warnings,
        extended_mechanism=plan.get("extended_mechanism") if isinstance(plan.get("extended_mechanism"), str) else None,
        required_edits=_string_list(plan.get("required_edits")),
    )


# ---------------------------------------------------------------------------
# Final-Target Remediation Slice
#
# Built ONLY from generate_remediation_strategy()'s verified result -- never
# the earlier, exploratory Target Discovery candidates -- so source budget
# is never spent on candidates the Final Strategy later rejected. Reuses
# the existing InvestigationContext/RepositoryIndex and the existing
# _resolve_symbol_details/_read_symbol_source helpers; adds no new
# repository parse, no new index, no new LLM call, no AST framework.
#
# One proven gap in the existing capabilities (see module docstring history
# for the empirical urllib3 v2.0.5 check this was measured against):
# RepositoryIndex.search_usages() requires the target name to be followed by
# "(" -- a real constant/policy value referenced as a plain attribute
# (e.g. ``retries.remove_headers_on_redirect``, never called) is invisible
# to it. Everything below that needs to find such a reference uses its own
# plain, word-boundary substring scan over the SAME already-parsed
# ``code`` text RepositoryIndex.search_usages() itself reads -- not a new
# parser, just a less restrictive pattern over existing data.
# ---------------------------------------------------------------------------

FINAL_TARGET_SLICE_MAX_CHARS = 10_000
"""
A budget SEPARATE from evidence_fusion.DEFAULT_MAX_CHARS (never reused
implicitly). Measured, not guessed: against a real urllib3 v2.0.5 checkout,
the exact `Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT` definition alone is 70
characters; padded by _DEFINITION_CONTEXT_LINES on each side (see that
constant) it is 265 characters -- still small. A focused ~30-line consumer
window inside `PoolManager.urlopen` (clamped to its own 409-486 line range)
is 1,234 characters -- roughly 1,500 combined with the padded definition.
10,000 comfortably holds this shape for up to three final targets (a
padded exact definition + one focused consumer each, ~2,000 characters
apiece even generously) plus headings/provenance text (roughly 1,000
characters), while staying meaningfully bounded: it is deliberately NOT
sized to fit a single full 14,188-character `HTTPConnectionPool.urlopen`
or a full 18,374-character `retry.py` -- an oversized full function/file
must never be able to consume this whole budget by itself when a focused
window was available instead.
"""


def _effective_final_target_max(budget_controller: "ContextBudgetController | None") -> int:
    """The shared Final-Target Slice ceiling actually in force right now
    -- FINAL_TARGET_SLICE_MAX_CHARS unless `budget_controller` has
    already had a user-approved extension for the "final_target_slice"
    stage this run (see ContextBudgetController). `budget_controller=None`
    (every existing caller, and any library caller that never builds
    one) returns FINAL_TARGET_SLICE_MAX_CHARS unchanged -- reads it live
    at call time, never cached, so a test that monkeypatches the module
    constant keeps working identically whether or not a controller is
    given. This is the ONE mechanism Slices 2/3/4 (run_deterministic_
    acquisition/run_guided_acquisition/recover_post_patch_source) all
    reuse for the shared total -- never a separate, per-stage-sized
    ceiling for this particular budget."""
    if budget_controller is None:
        return FINAL_TARGET_SLICE_MAX_CHARS
    return budget_controller.effective_budget("final_target_slice", FINAL_TARGET_SLICE_MAX_CHARS)


_USAGE_WINDOW_LINES = 15
"""Lines of context on each side of a discovered usage line, before
clamping to the enclosing function's own start/end line -- the middle of
the 12-20 line range a focused window should default to."""

_PER_TARGET_FULL_FUNCTION_CAP = FINAL_TARGET_SLICE_MAX_CHARS // 3
"""A directly-resolved function target with no discoverable strategy-term
anchor inside it (so no focused window is possible) renders whole only if
it fits this share of the budget -- sized so up to three such targets
could each still get a full rendering without any single one of them
dominating the whole slice. A genuinely oversized function (e.g.
HTTPConnectionPool.urlopen's 14,188 characters) will not fit and is
correctly left uncovered by exact means rather than crowding out every
other target."""

_SLICE_HEADING = "## Final-Target Remediation Slice"
_SLICE_DISCLAIMER = (
    "*Deterministic, bounded repository source built from the Final "
    "Evidence-Backed Remediation Strategy's own verified targets -- not "
    "the earlier, exploratory Target Discovery candidates. Exact "
    "definitions are repository text, verbatim. Consumer windows are "
    "deterministic discovered usage, not a claim of complete coverage.*"
)

# Conservative, deterministic, order-preserving identifier shapes. No
# stopword list is needed: an ordinary English word in prose has no dot,
# no underscore, and no internal capitalization hump, so it is never
# extracted by construction.
_DOTTED_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+\b")
_SNAKE_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+\b")
_CAMEL_RE = re.compile(r"\b[A-Z][a-z0-9]+(?:[A-Z][a-zA-Z0-9]*)+\b")


def _extract_identifiers_from_text(text: "str | None") -> "list[str]":
    """Dotted identifiers first (widest/most specific), then snake_case /
    SCREAMING_SNAKE_CASE, then CamelCase (>=2 humps -- a single-hump
    capitalized word, e.g. a sentence-initial "Extend" or a bare class
    name, is deliberately excluded as too generic on its own; a bare
    class name of interest reaches this extraction some other way, e.g.
    as a verified target symbol's own class qualifier). A shorter token
    that is only a substring of an already-captured longer token (e.g.
    "ALLOWED_VALUES" inside "Policy.ALLOWED_VALUES") is skipped -- it adds
    no new search target. Order-preserving, first-occurrence-deduplicated.
    """
    if not text:
        return []
    found: "list[str]" = []
    seen: set = set()
    for m in _DOTTED_RE.finditer(text):
        tok = m.group(0)
        if tok not in seen:
            seen.add(tok)
            found.append(tok)
    for regex in (_SNAKE_RE, _CAMEL_RE):
        for m in regex.finditer(text):
            tok = m.group(0)
            if tok in seen:
                continue
            if any(tok != longer and tok in longer for longer in found):
                continue
            seen.add(tok)
            found.append(tok)
    return found


def _extract_strategy_identifiers(strategy: RemediationStrategyResult) -> "list[str]":
    """Repository-looking identifiers from the Final Strategy's own text,
    order-preserving and first-occurrence-deduplicated: every verified
    target symbol first (already known-good -- no shape filtering, plus
    its dotted components), then shape-filtered tokens from
    `extended_mechanism`, then from each `required_edits` entry in order.
    No LLM, no free-form NLP."""
    ordered: "list[str]" = []
    seen: set = set()

    def _add(tok: "str | None") -> None:
        if tok and tok not in seen:
            seen.add(tok)
            ordered.append(tok)

    for raw_symbol in strategy.target_symbols:
        _file_hint, name = _split_symbol_entry(raw_symbol)
        _add(name)
        if "." in name:
            _add(name.rsplit(".", 1)[-1])
            _add(name.rsplit(".", 1)[0])

    for tok in _extract_identifiers_from_text(strategy.extended_mechanism):
        _add(tok)
    for edit in strategy.required_edits:
        for tok in _extract_identifiers_from_text(edit):
            _add(tok)

    return ordered


def _merge_line_windows(windows: "list[tuple[int, int]]") -> "list[tuple[int, int]]":
    """Sort by start line, merge overlapping or adjacent (gap <= 1 line)
    ranges. Never drops a range, never reorders unrelated ranges, never
    produces an inverted (start > end) range."""
    if not windows:
        return []
    ordered = sorted(windows)
    merged = [ordered[0]]
    for start, end in ordered[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end + 1:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged


def _find_identifier_line_offsets(code: str, identifier: str) -> "list[int]":
    """Plain, word-boundary substring scan over one function's own
    already-parsed `code` -- deliberately WITHOUT
    RepositoryIndex.search_usages()'s trailing "(" requirement (see module
    comment above for the empirical proof this misses real attribute-style
    usages). Reads only already-parsed data; never a new parse."""
    if not identifier:
        return []
    pattern = re.compile(r"\b" + re.escape(identifier) + r"\b")
    return [i for i, line in enumerate(code.split("\n")) if pattern.search(line)]


class _IdentifierMatch(NamedTuple):
    kind: str  # "constant" | "function"
    file: str
    label: str
    line: int
    end_line: "int | None"
    func_id: "str | None"


def _lookup_identifier_definition(
    identifier: str, preferred_files: "list[str]", context
) -> "_IdentifierMatch | None":
    """Constants first (RepositoryIndex has no concept of a constant at
    all -- only InvestigationContext.constants does), then function/method
    definitions via the existing, real search_definitions() -- restricted
    to `preferred_files` only. Never a whole-repository scan for a
    strategy-derived term: an identifier that verifies nowhere within the
    Final Strategy's own target files or the files already connected via
    Planner evidence is not looked up further, by design (a repository can
    legitimately have more than one function/class sharing a name -- see
    _resolve_symbol_details' own class-qualifier check; this lookup accepts
    the SAME residual ambiguity `search_definitions()` itself has for a
    bare, class-unqualified strategy term, bounded by staying inside
    preferred_files rather than the whole repository)."""
    constants = getattr(context, "constants", None) or {}
    for f in preferred_files:
        for qualified_name, record in constants.get(f, {}).items():
            if qualified_name == identifier or record.get("name") == identifier:
                line = record.get("line")
                if line is not None:
                    return _IdentifierMatch(
                        kind="constant", file=f, label=qualified_name,
                        line=line, end_line=record.get("end_line"), func_id=None,
                    )

    index = getattr(context, "index", None)
    if index is not None:
        for match in index.search_definitions(identifier):
            func_id = match.get("id", "")
            candidate_file = _file_part(func_id)
            if candidate_file not in preferred_files:
                continue
            line = match.get("startLine")
            if line is not None:
                return _IdentifierMatch(
                    kind="function", file=candidate_file, label=match.get("name") or identifier,
                    line=line, end_line=match.get("endLine"), func_id=func_id,
                )
    return None


def _lookup_identifier_usages(
    identifier: str, preferred_files: "list[str]", context
) -> "list[tuple[str, str, int, int, list[int]]]":
    """Every function within `preferred_files` whose own already-parsed
    code contains `identifier` as a plain, word-boundary substring (see
    _find_identifier_line_offsets). Returns
    (file, func_label, fn_start, fn_end, line_offsets) tuples, in
    preferred_files order, then list_functions_in_file's own stable order.
    Never a whole-repository scan."""
    index = getattr(context, "index", None)
    if index is None or not identifier:
        return []
    results = []
    for f in preferred_files:
        for entry in index.list_functions_in_file(f):
            func_id = entry.get("id")
            func = index.get_function(func_id) if func_id else None
            if not func:
                continue
            code = func.get("code", "") or ""
            offsets = _find_identifier_line_offsets(code, identifier)
            if not offsets:
                continue
            start, end = func.get("startLine"), func.get("endLine")
            if start is None or end is None:
                continue
            label = f"{func.get('className')}.{func.get('name')}" if func.get("className") else func.get("name")
            results.append((f, label, start, end, offsets))
    return results


# ---------------------------------------------------------------------------
# One-hop dependency expansion -- given source ALREADY selected for the
# slice (an exact target definition, or a focused consumer window),
# discover an exact repository-referenced CONSTANT it depends on and
# prepend its own exact definition. Deliberately bounded to exactly one
# hop: the functions below are never called again on their own output, so
# there is no recursion, no traversal, no generic data-flow analysis.
# ---------------------------------------------------------------------------

_SOURCE_CONSTANT_REF_RE = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\b")


def _class_of_label(label: "str | None") -> "str | None":
    """The class-qualifier component of a "ClassName.member" label, or
    None for a bare (module-level) label -- same convention _resolve_
    symbol_details/_extract_strategy_identifiers already use."""
    if not label or "." not in label:
        return None
    return label.rsplit(".", 1)[0]


def _contains_any_strategy_identifier(text: str, terms: "list[str]") -> bool:
    """True if `text` contains at least one of `terms` verbatim, OR (for a
    dotted term like "Class.NAME") its own bare suffix after the last
    "." -- a class/module body's own definition site never repeats its
    own qualifier inline (e.g. `ALLOWED_VALUES = ...` inside `class
    Policy:` never literally contains the substring "Policy.ALLOWED_VALUES"),
    so checking only the dotted form would systematically miss the most
    common real case. Same class-qualifier/bare-suffix split
    _class_of_label and _extract_strategy_identifiers already use --
    not a new identifier-shape rule."""
    for term in terms:
        if term in text:
            return True
        if "." in term and term.rsplit(".", 1)[-1] in text:
            return True
    return False


def _extract_source_constant_refs(code: str) -> "list[str]":
    """Conservative, order-preserving, first-occurrence-deduplicated
    SCREAMING_SNAKE_CASE-shaped identifier extraction from already-
    selected Python SOURCE (not strategy-text prose -- see
    _extract_identifiers_from_text for that; this is a separate, narrower
    rule and does not reuse or modify it). Module/class-level constants in
    InvestigationContext.constants are conventionally ALL-CAPS (matching
    _extract_literal_constants' own real-world population), so
    restricting to that shape avoids speculatively looking up every
    lowercase attribute/parameter name in the constants table. Full-line
    comments are skipped outright -- a small, deterministic filter, not a
    parser; string-literal content is not otherwise excluded (an
    accepted, documented MVP limitation)."""
    if not code:
        return []
    found: "list[str]" = []
    seen: set = set()
    for line in code.split("\n"):
        if line.strip().startswith("#"):
            continue
        for m in _SOURCE_CONSTANT_REF_RE.finditer(line):
            tok = m.group(0)
            if tok not in seen:
                seen.add(tok)
                found.append(tok)
    return found


def _extract_fenced_code(rendered_block: "str | None") -> "str | None":
    """Recovers the raw source text from a block this module itself
    rendered via _render_definition_block/_render_usage_window_block --
    both use the exact same ```python fence convention, so this is
    deterministic (fully controlled here), not a general markdown
    parser."""
    if not rendered_block:
        return None
    start = rendered_block.find("```python\n")
    if start == -1:
        return None
    start += len("```python\n")
    end = rendered_block.rfind("```")
    if end == -1 or end <= start:
        return None
    return rendered_block[start:end]


def _find_constant_candidates_by_name(
    bare_name: str, preferred_files: "list[str]", context
) -> "list[tuple[str, str, dict]]":
    """Every InvestigationContext.constants record, across
    `preferred_files` ONLY, whose own `name` field exactly equals
    `bare_name` -- a bare-NAME match, never a qualified_name match (that
    is _lookup_identifier_definition's job, for a different caller), and
    never outside preferred_files. Returns (file, qualified_name, record)
    tuples."""
    constants = getattr(context, "constants", None) or {}
    found: "list[tuple[str, str, dict]]" = []
    for f in preferred_files:
        for qualified_name, record in constants.get(f, {}).items():
            if record.get("name") == bare_name:
                found.append((f, qualified_name, record))
    return found


def _disambiguate_constant_candidates(
    candidates: "list[tuple[str, str, dict]]",
    source_file: str,
    source_class: "str | None",
    symbol_matches: dict,
    strategy_target_files: "list[str]",
) -> "tuple[tuple[str, str, dict] | None, str | None]":
    """Returns (chosen_candidate_or_None, omission_reason_or_None). Never
    guesses: a tie at any priority tier is a skip, not a choice.

    Priority (tried only when more than one candidate exists):
    1. a candidate that is already one of the Final Strategy's own
       verified (constant) target symbols;
    2. same file AND same class as the block containing the reference;
    3. same file as a Final Strategy target file;
    4. same file as the block containing the reference;
    (a single overall candidate is used directly, without needing any of
    the above -- the trivial "unique match" case.)
    """
    if not candidates:
        return None, "no constant record with that name in the preferred files"
    if len(candidates) == 1:
        return candidates[0], None

    def _is_verified_target(c):
        f, _qn, record = c
        line, end_line = record.get("line"), record.get("end_line")
        return any(
            m.kind == "constant" and m.file == f and m.line == line and m.end_line == end_line
            for m in symbol_matches.values()
        )

    def _same_file_and_class(c):
        f, qn, _record = c
        return source_class is not None and f == source_file and _class_of_label(qn) == source_class

    def _same_target_file(c):
        f, _qn, _record = c
        return f in strategy_target_files

    def _same_source_file(c):
        f, _qn, _record = c
        return f == source_file

    for tier_filter in (_is_verified_target, _same_file_and_class, _same_target_file, _same_source_file):
        narrowed = [c for c in candidates if tier_filter(c)]
        if len(narrowed) == 1:
            return narrowed[0], None

    name = candidates[0][2].get("name")
    return None, f"ambiguous: {len(candidates)} equal-priority constant candidates named {name!r}"


def _render_definition_block(path: str, label: str, start: int, end: int, source: str) -> str:
    return (
        f"#### Target definition: `{path}:{label}` (lines {start}–{end})\n\n"
        f"```python\n{source.rstrip()}\n```\n"
    )


def _render_full_file_block(path: str, source: str) -> str:
    n_lines = len(source.splitlines())
    return (
        f"#### Full file (last resort): `{path}` ({n_lines} lines)\n\n"
        f"```python\n{source.rstrip()}\n```\n"
    )


def _render_usage_window_block(path: str, label: str, ranges: "list[tuple[int, int]]", context) -> "str | None":
    """Renders one or more (possibly non-contiguous) merged windows for a
    single consumer function -- reads each window's exact text via the
    existing read_file_section, never hand-reconstructed source. Two
    non-contiguous windows from the same function are separated by an
    explicit omitted-region marker rather than concatenated silently."""
    index = getattr(context, "index", None)
    if index is None:
        return None
    pieces: "list[str]" = []
    prev_end = None
    for start, end in ranges:
        if prev_end is not None:
            gap = start - prev_end - 1
            pieces.append(f"# ... ({gap} line(s) omitted) ...")
        text = index.read_file_section(path, start, end)
        if text is None:
            return None
        pieces.append(text.rstrip("\n"))
        prev_end = end
    body = "\n".join(pieces)
    lo, hi = ranges[0][0], ranges[-1][1]
    return (
        f"#### Discovered consumer: `{path}:{label}` (lines {lo}–{hi}, "
        f"deterministic discovered usage)\n\n"
        f"```python\n{body}\n```\n"
    )


class FinalTargetSliceResult(NamedTuple):
    """`covered_target_files`/`covered_target_symbols` are the exact
    subset of the Final Strategy's own verified targets this slice
    actually produced usable source for -- see build_final_target_slice's
    docstring for the precise per-category coverage rule. `warning_text`
    is a separately-rendered '## Final-target source coverage warning'
    section, non-empty only when coverage is incomplete but not zero (the
    caller decides whether zero coverage should skip Patch Generation
    entirely; this result never makes that decision itself).

    The three fields below exist for check_edit_readiness (Slice 1, Edit
    Readiness Gate) -- additive; no test constructs this NamedTuple
    directly (only build_final_target_slice()'s own two construction
    sites do, both updated alongside these fields), so no defaults are
    needed and every field stays required, matching this module's other
    NamedTuples:
      resolved_target_symbols   : subset of strategy.target_symbols that
                                   resolved to a real repository location
                                   via _resolve_symbol_details, REGARDLESS
                                   of whether it made it into the budget
                                   (i.e. symbol_matches.keys()). Lets the
                                   Gate tell "never resolved" apart from
                                   "resolved but not rendered".
      full_file_fallback_covered: target FILES covered specifically by
                                   the category-5 full-file fallback AND
                                   containing a strategy-derived
                                   identifier -- the only way a file-level
                                   (no target_symbol) intended edit can be
                                   ready; an unrelated block from the same
                                   file is never enough.
      edit_target_budget_exhausted: True when the combined attempted size
                                   of every edit-target candidate (before
                                   any supporting-context block was even
                                   considered) already exceeds
                                   FINAL_TARGET_SLICE_MAX_CHARS.

    Two more fields exist for the bare-symbol fix and Slice 2 (Deterministic
    Pre-Patch Retrieval) -- both additive, both built entirely from data
    this function already computes, no new resolution pass either:
      resolved_symbol_files     : {raw target_symbol -> the real
                                   repository file it resolved to}, for
                                   every symbol in `symbol_matches`
                                   regardless of whether it made it into
                                   the budget. Lets build_intended_edits
                                   learn a bare (file-hint-less) symbol's
                                   real file without re-resolving it, so a
                                   bare symbol and its own file never
                                   produce two separate IntendedEdits for
                                   one logical target.
      identifier_definition_covered: target FILES covered specifically by
                                   an exact category-2 definition of a
                                   strategy-derived identifier (not a mere
                                   usage window, and not full_file_
                                   fallback_covered's whole-file render) --
                                   a second, more precise way a file-level
                                   (no target_symbol) intended edit can be
                                   ready (see check_edit_readiness)."""

    rendered: str
    covered_target_files: "list[str]"
    covered_target_symbols: "list[str]"
    uncovered_target_files: "list[str]"
    uncovered_target_symbols: "list[str]"
    coverage_complete: bool
    has_any_coverage: bool
    warning_text: str
    resolved_target_symbols: "list[str]"
    full_file_fallback_covered: "list[str]"
    edit_target_budget_exhausted: bool
    resolved_symbol_files: "dict[str, str]"
    identifier_definition_covered: "list[str]"


_EMPTY_SLICE_RESULT = FinalTargetSliceResult(
    rendered="", covered_target_files=[], covered_target_symbols=[],
    uncovered_target_files=[], uncovered_target_symbols=[],
    coverage_complete=True, has_any_coverage=False, warning_text="",
    resolved_target_symbols=[], full_file_fallback_covered=[],
    edit_target_budget_exhausted=False,
    resolved_symbol_files={}, identifier_definition_covered=[],
)


def build_final_target_slice(
    strategy: RemediationStrategyResult,
    repo_root,
    context,
    planner_evidence_files: "list[str] | tuple" = (),
    max_chars: "int | None" = None,
) -> FinalTargetSliceResult:
    """
    Build the '## Final-Target Remediation Slice' from
    generate_remediation_strategy()'s VERIFIED result only -- never the
    earlier, exploratory Target Discovery candidates. Reuses the existing
    InvestigationContext/RepositoryIndex and the existing
    _resolve_symbol_details/_read_symbol_source helpers; no new repository
    parse, no new index, no new LLM call, no AST framework.

    Rendering order (never re-scored, never LLM-ranked): (1) exact
    definitions resolved directly from the Final Strategy's own verified
    target symbols; (2) definitions discovered from strategy-derived
    identifiers (constants/functions inside a class-only/file-only
    target's own file, or any other preferred file); (3) focused
    usage/consumer windows; (4) compact full target-symbol functions with
    no discoverable focus point; (5) full-file fallback, last resort only.
    Each category is added to a single running budget
    (FINAL_TARGET_SLICE_MAX_CHARS) strictly in that order, whole-block-or-
    omitted -- so an earlier category's block can never be displaced by a
    later one.

    "Exact definition" (categories 1, 2, and the one-hop dependency
    expansion) means patch-ready repository source, not merely a
    reasoning-ready one: every such block is padded by
    _DEFINITION_CONTEXT_LINES of real, repository-verbatim lines on each
    side of the resolved symbol's own span (via _padded_line_range) --
    without this, a short definition (e.g. a one-line constant) would
    render with zero surrounding context, leaving Patch Generation nothing
    real to anchor a unified diff hunk's leading/trailing context to, and
    it would invent neighboring lines from memory instead (observed
    directly: a real urllib3 run's generated hunk against
    `DEFAULT_REMOVE_HEADERS_ON_REDIRECT` failed content-based relocation
    with relocation_reason="no_match" -- the invented context never
    existed in the file). The padding is purely arithmetic on top of the
    existing read_file_section accessor -- no new repository reader, and
    it never applies to a whole-function-body or whole-file render (both
    already self-contain ample context).

    Coverage: a target FILE is covered if the slice contains an exact
    definition, an exact target symbol, or a focused usage/consumer
    window from that file. A target SYMBOL is covered only by its own
    exact definition or its own full/windowed source (categories 1/3b/4) --
    never merely because some other identifier from the same file was
    included.

    Never raises: any internal failure returns a short, explicit failure
    note (see _EMPTY_SLICE_RESULT's caller, build_final_target_slice's
    except-branch below) -- never silently empty, never silently
    "coverage complete".

    `max_chars=None` (the default) reads the module-level
    FINAL_TARGET_SLICE_MAX_CHARS AT CALL TIME (not bound into the
    function signature), so every existing caller is unaffected AND a
    test that monkeypatches FINAL_TARGET_SLICE_MAX_CHARS still works
    exactly as before. Slice 2 (Deterministic Pre-Patch Retrieval, see
    run_deterministic_acquisition) is the only caller that passes an
    explicit smaller per-round budget, re-invoking this same function on
    a narrowly-scoped strategy naming only the targets still unready,
    rather than a second retrieval implementation.
    """
    if not strategy or not (strategy.target_files or strategy.target_symbols):
        return _EMPTY_SLICE_RESULT

    resolved_max_chars = FINAL_TARGET_SLICE_MAX_CHARS if max_chars is None else max_chars
    try:
        return _build_final_target_slice_inner(strategy, repo_root, context, planner_evidence_files, resolved_max_chars)
    except Exception:
        return FinalTargetSliceResult(
            rendered=(
                f"{_SLICE_HEADING}\n\n*Slice construction failed for this run -- no additional "
                f"exact source could be deterministically extracted. Earlier context sections "
                f"are unaffected.*\n"
            ),
            covered_target_files=[], covered_target_symbols=[],
            uncovered_target_files=list(strategy.target_files),
            uncovered_target_symbols=list(strategy.target_symbols),
            coverage_complete=False, has_any_coverage=False,
            warning_text=(
                "Final-Target Remediation Slice construction failed; "
                "no verified source was added this run."
            ),
            resolved_target_symbols=[], full_file_fallback_covered=[],
            edit_target_budget_exhausted=False,
            resolved_symbol_files={}, identifier_definition_covered=[],
        )


def _render_coverage_warning(
    uncovered_files: "list[str]", uncovered_symbols: "list[str]",
    rendered_nonempty: bool, named_any_target: bool,
) -> str:
    """The '## Final-target source coverage warning' section -- extracted
    so both _build_final_target_slice_inner's own return and Slice 2's
    _merge_slice_results (which recomputes uncovered lists after
    acquisition) render it identically, never a second, divergent
    wording."""
    if rendered_nonempty and (uncovered_files or uncovered_symbols):
        parts = []
        if uncovered_files:
            parts.append("files: " + ", ".join(uncovered_files))
        if uncovered_symbols:
            parts.append("symbols: " + ", ".join(uncovered_symbols))
        return (
            "## Final-target source coverage warning\n\n"
            "*Deterministic verified source could not be produced for every "
            "Final Strategy target. Patch Generation is proceeding with "
            "partial coverage -- treat any edit to an uncovered target as "
            "unverified against real repository text.*\n\n"
            "Uncovered " + "; ".join(parts) + "\n"
        )
    if not rendered_nonempty and named_any_target:
        return (
            "## Final-target source coverage warning\n\n"
            "*No deterministic verified source could be produced for any "
            "Final Strategy target this run.*\n"
        )
    return ""


def _build_final_target_slice_inner(
    strategy: RemediationStrategyResult, repo_root, context, planner_evidence_files,
    max_chars: int = FINAL_TARGET_SLICE_MAX_CHARS,
) -> FinalTargetSliceResult:
    root = Path(repo_root) if repo_root else None
    if root is None:
        return _EMPTY_SLICE_RESULT

    preferred_files: "list[str]" = []
    seen_pf: set = set()
    for f in list(strategy.target_files) + list(planner_evidence_files):
        if f not in seen_pf:
            seen_pf.add(f)
            preferred_files.append(f)

    strategy_terms = _extract_strategy_identifiers(strategy)

    budget = max_chars
    running = 0
    blocks_by_category: "dict[int, list[str]]" = {1: [], 2: [], 3: [], 4: [], 5: []}
    covered_files: set = set()
    covered_symbols: set = set()
    used_definition_keys: set = set()  # (file, line, end_line)
    used_usage_keys: set = set()       # (file, label, tuple(ranges))
    # Files covered specifically by an exact category-2 definition of a
    # strategy-derived identifier -- a second, more precise way a
    # file-level intended edit can satisfy check_edit_readiness (see
    # FinalTargetSliceResult.identifier_definition_covered), distinct from
    # full_file_fallback_covered's whole-file requirement.
    identifier_definition_covered: set = set()

    # Slice 1 -- Edit Readiness Gate bookkeeping (see check_edit_readiness
    # below). `edit_target_attempted_chars` sums every EDIT-TARGET-role
    # candidate's rendered size REGARDLESS of whether it actually fit the
    # shared budget -- purely additive bookkeeping, never consulted by any
    # commit decision above. This is what lets the Gate tell apart "the
    # edit targets themselves already exceed the whole slice budget"
    # (target_budget_exhausted) from "budget had room for edit targets but
    # this specific one still didn't make it in" (a read/resolution
    # failure -- missing_target_source). `full_file_fallback_covered`
    # records which target FILES were covered specifically by the
    # full-file fallback (category 5) and actually contain a
    # strategy-derived identifier -- the only case a file-level (no
    # target_symbol) intended edit can be "ready" (see
    # check_edit_readiness): an unrelated block from the same file must
    # never count.
    edit_target_attempted_chars = 0
    full_file_fallback_covered: set = set()

    def _try_add_to(block_list: list, text: str) -> bool:
        nonlocal running
        if running + len(text) > budget:
            return False
        block_list.append(text)
        running += len(text)
        return True

    # --- Category 1 (EDIT-TARGET role): exact verified target definitions
    # -- constants resolved directly from the Final Strategy's own
    # verified target symbols. Functions resolved here are deferred to
    # categories 3b/4 below. Committed to the budget FIRST, immediately --
    # nothing outranks this tier, and per the Edit Readiness Gate's "actual
    # edit targets first, supporting evidence second" rule, no
    # supporting-context block (one-hop / category 2 / category 3a /
    # category 5) is committed anywhere below until every edit-target
    # candidate in categories 1, 3b, and 4 has already had its turn.
    symbol_matches: "dict[str, object]" = {}
    for raw_symbol in strategy.target_symbols:
        match = _resolve_symbol_details(raw_symbol, root, context)
        if match is None:
            continue
        symbol_matches[raw_symbol] = match
        if match.kind != "constant":
            continue
        key = (match.file, match.line, match.end_line)
        if key in used_definition_keys:
            covered_symbols.add(raw_symbol)
            covered_files.add(match.file)
            continue
        source = _read_symbol_source(match, context, pad_lines=_DEFINITION_CONTEXT_LINES)
        if source is None:
            continue
        render_start, _ = _padded_line_range(match.line, match.end_line, _DEFINITION_CONTEXT_LINES)
        render_end = _rendered_end_line(render_start, source)
        text = _render_definition_block(match.file, match.label, render_start, render_end, source)
        edit_target_attempted_chars += len(text)
        if _try_add_to(blocks_by_category[1], text):
            used_definition_keys.add(key)
            covered_symbols.add(raw_symbol)
            covered_files.add(match.file)

    # --- Category 2 (SUPPORTING-context role): definitions discovered
    # from strategy identifiers, for class-only/file-only targets or any
    # other mechanism-related identifier the strategy named that isn't
    # already a verified target symbol. CANDIDATES ONLY here -- gathering
    # candidates doesn't touch the budget, so this can run in its
    # original position; the actual commit happens far below, after every
    # edit-target candidate (categories 1, 3b, 4) has already been tried.
    category2_candidates: "list[tuple[str, str]]" = []  # (rendered_text, file)
    for term in strategy_terms:
        found = _lookup_identifier_definition(term, preferred_files, context)
        if found is None:
            continue
        key = (found.file, found.line, found.end_line)
        if key in used_definition_keys:
            continue
        if found.kind == "constant":
            index = getattr(context, "index", None)
            read_start, read_end = _padded_line_range(found.line, found.end_line, _DEFINITION_CONTEXT_LINES)
            source = index.read_file_section(found.file, read_start, read_end) if index else None
            render_start = read_start
            render_end = _rendered_end_line(render_start, source) if source else found.end_line
        else:
            source = _read_symbol_source(
                _SymbolMatch(file=found.file, label=found.label, kind="function",
                             line=found.line, end_line=found.end_line, func_id=found.func_id),
                context,
            )
            render_start, render_end = found.line, found.end_line
        if source is None:
            continue
        used_definition_keys.add(key)  # decided now; committed later (key stays unpadded -- see _padded_line_range)
        text = _render_definition_block(found.file, found.label, render_start, render_end, source)
        category2_candidates.append((text, found.file))

    # --- Category 3 candidates (usage/consumer windows) -- CANDIDATES
    # ONLY here too. Committed in two separate passes further below: 3b
    # (a focused window into an ACTUAL verified target symbol's own body
    # -- edit-target role) ahead of every supporting block; 3a (a mere
    # consumer/usage scan, unrelated to any specific verified target --
    # supporting-context role) only with whatever budget remains.
    def _windows_for(fn_start: int, fn_end: int, offsets: "list[int]") -> "list[tuple[int, int]]":
        raw_ranges = [
            (max(fn_start, fn_start + off - _USAGE_WINDOW_LINES),
             min(fn_end, fn_start + off + _USAGE_WINDOW_LINES))
            for off in offsets
        ]
        return _merge_line_windows(raw_ranges)

    category3_candidates: "list[tuple[str, str, str, object]]" = []  # (rendered_text, file, label, raw_symbol_or_None)

    # 3a. Strategy-term usage scan, bounded to preferred_files -- covers
    # class-only/file-only targets' discovered consumers (SUPPORTING
    # role: raw_symbol stays None). Offsets from EVERY matching strategy
    # term are accumulated PER FUNCTION first (never rendered per-term) so
    # two different terms landing in the same function (e.g. both
    # "DEFAULT_REMOVE_HEADERS_ON_REDIRECT" and "remove_headers_on_redirect"
    # inside the same __init__) merge into one window set and render once,
    # in first-encountered function order.
    per_function_hits: "dict[tuple[str, str], dict]" = {}
    function_order: "list[tuple[str, str]]" = []
    for term in strategy_terms:
        for (f, label, fn_start, fn_end, offsets) in _lookup_identifier_usages(term, preferred_files, context):
            fkey = (f, label)
            if fkey not in per_function_hits:
                per_function_hits[fkey] = {"fn_start": fn_start, "fn_end": fn_end, "offsets": set()}
                function_order.append(fkey)
            per_function_hits[fkey]["offsets"].update(offsets)

    for (f, label) in function_order:
        hit = per_function_hits[(f, label)]
        ranges = _windows_for(hit["fn_start"], hit["fn_end"], sorted(hit["offsets"]))
        key = (f, label, tuple(ranges))
        if key in used_usage_keys:
            continue
        text = _render_usage_window_block(f, label, ranges, context)
        if text is None:
            continue
        used_usage_keys.add(key)
        category3_candidates.append((text, f, label, None))

    # 3b. Inside a directly-resolved FUNCTION target itself: a focused
    # window around any strategy term found in its own body, rather than
    # an immediate full-function render. EDIT-TARGET role: raw_symbol is
    # always one of strategy.target_symbols here -- this IS the target's
    # own source, just windowed rather than shown in full.
    for raw_symbol, match in symbol_matches.items():
        if match.kind != "function" or not match.func_id:
            continue
        index = getattr(context, "index", None)
        func = index.get_function(match.func_id) if index else None
        if not func:
            continue
        code = func.get("code", "") or ""
        offsets: "list[int]" = []
        for term in strategy_terms:
            offsets.extend(_find_identifier_line_offsets(code, term))
        if not offsets:
            continue
        ranges = _windows_for(match.line, match.end_line, sorted(set(offsets)))
        key = (match.file, match.label, tuple(ranges))
        if key in used_usage_keys:
            continue
        text = _render_usage_window_block(match.file, match.label, ranges, context)
        if text is None:
            continue
        used_usage_keys.add(key)
        category3_candidates.append((text, match.file, match.label, raw_symbol))

    # --- Commit category 3b's EDIT-TARGET candidates now (still ahead of
    # every supporting-context block below): these are windows into an
    # actual verified target symbol's own body, not a mere consumer, so
    # they must not be displaced by one-hop/category-2/category-3a/
    # category-5 content competing for the same budget.
    function_targets_with_window: set = set()
    for (text, f, _label, raw_symbol) in category3_candidates:
        if raw_symbol is None:
            continue  # 3a (supporting) -- committed later, below
        edit_target_attempted_chars += len(text)
        if _try_add_to(blocks_by_category[3], text):
            covered_files.add(f)
            covered_symbols.add(raw_symbol)
            function_targets_with_window.add(raw_symbol)

    # --- Category 4 (EDIT-TARGET role): compact full target symbols -- a
    # directly-resolved FUNCTION target with no strategy-term anchor
    # inside it (no focused window possible), rendered whole only if it
    # fits the per-target cap, and only if the same function wasn't
    # already rendered via its own 3b window above. Still ahead of every
    # supporting-context block -- this is the last edit-target tier.
    for raw_symbol, match in symbol_matches.items():
        if match.kind != "function" or raw_symbol in function_targets_with_window:
            continue
        key = (match.file, match.line, match.end_line)
        if key in used_definition_keys:
            covered_symbols.add(raw_symbol)
            covered_files.add(match.file)
            continue
        source = _read_symbol_source(match, context)
        if source is None or len(source) > _PER_TARGET_FULL_FUNCTION_CAP:
            continue  # too large for a "compact" full render -- left uncovered by exact means
        text = _render_definition_block(match.file, match.label, match.line, match.end_line, source)
        edit_target_attempted_chars += len(text)
        if _try_add_to(blocks_by_category[4], text):
            used_definition_keys.add(key)
            covered_symbols.add(raw_symbol)
            covered_files.add(match.file)

    # Every edit-target candidate (categories 1, 3b, 4) has now had its
    # turn, with the FULL slice budget available to it -- nothing
    # supporting-context has been committed yet. If their combined
    # attempted size alone already exceeds the budget, at least one edit
    # target could not possibly fit no matter what else is/isn't
    # rendered -- this is the one failure reason distinguishable as
    # "the budget itself is the problem", not a resolution/read failure.
    edit_target_budget_exhausted = edit_target_attempted_chars > budget

    # --- One-hop dependency expansion (SUPPORTING-context role, rendered
    # priority tier 2): scan ONLY the exact target definitions already
    # committed (category 1) and the focused consumer-window CANDIDATES
    # computed above (category 3, regardless of commit status) for exact
    # repository-referenced constants, and prepend their own exact
    # definitions ahead of every OTHER supporting block. Exactly one pass
    # -- newly added definitions below are never themselves scanned for
    # further references (no recursion). Committed here -- AFTER every
    # edit-target candidate above has already had first claim on the
    # budget, per the Edit Readiness Gate's ordering rule.
    one_hop_blocks: "list[str]" = []
    scan_sources: "list[tuple[str, str, str]]" = []  # (source_file, source_class, raw_code)

    for match in symbol_matches.values():
        if match.kind != "constant":
            continue
        if (match.file, match.line, match.end_line) not in used_definition_keys:
            continue  # category 1 did not actually include this one (budget)
        source = _read_symbol_source(match, context)
        if source is not None:
            scan_sources.append((match.file, _class_of_label(match.label), source))

    for (text, f, label, _raw_symbol) in category3_candidates:
        code = _extract_fenced_code(text)
        if code is not None:
            scan_sources.append((f, _class_of_label(label), code))

    seen_refs: set = set()
    for (source_file, source_class, code) in scan_sources:
        for ref in _extract_source_constant_refs(code):
            if ref in seen_refs:
                continue
            seen_refs.add(ref)
            candidates = _find_constant_candidates_by_name(ref, preferred_files, context)
            chosen, _reason = _disambiguate_constant_candidates(
                candidates, source_file, source_class, symbol_matches, list(strategy.target_files)
            )
            if chosen is None:
                continue
            found_file, qualified_name, record = chosen
            line, end_line = record.get("line"), record.get("end_line")
            if line is None or end_line is None:
                continue
            key = (found_file, line, end_line)
            if key in used_definition_keys:
                continue  # already selected elsewhere -- never duplicated
            index = getattr(context, "index", None)
            read_start, read_end = _padded_line_range(line, end_line, _DEFINITION_CONTEXT_LINES)
            source_text = index.read_file_section(found_file, read_start, read_end) if index else None
            if source_text is None:
                continue
            render_end = _rendered_end_line(read_start, source_text)
            text = _render_definition_block(found_file, qualified_name, read_start, render_end, source_text)
            if _try_add_to(one_hop_blocks, text):
                used_definition_keys.add(key)  # key stays unpadded -- see _padded_line_range
                covered_files.add(found_file)

    # --- Commit category 2's candidates now (SUPPORTING-context role,
    # tier 3) -- after every edit-target candidate AND the one-hop step
    # above have already had first claim on the budget.
    for (text, f) in category2_candidates:
        if _try_add_to(blocks_by_category[2], text):
            covered_files.add(f)
            identifier_definition_covered.add(f)

    # --- Commit category 3a's SUPPORTING-context candidates now (tier 4)
    # -- 3b's edit-target candidates were already committed above.
    for (text, f, _label, raw_symbol) in category3_candidates:
        if raw_symbol is not None:
            continue  # 3b (edit-target) -- already committed above
        if _try_add_to(blocks_by_category[3], text):
            covered_files.add(f)

    # --- Category 5: full-file fallback -- only for a target FILE with no
    # coverage at all from categories 1-4. EDIT-TARGET role only when the
    # file has no target_symbol of its own (a file-level intended edit --
    # see check_edit_readiness) AND the fallback text actually contains a
    # strategy-derived identifier ("do not consider a file covered merely
    # because unrelated source from the same file was included" -- a
    # full-file fallback for a file that also has its own, separately
    # uncovered target_symbol is NOT treated as satisfying that symbol).
    symbol_owned_files = {m.file for m in symbol_matches.values()}
    for f in strategy.target_files:
        if f in covered_files:
            continue
        try:
            full_text = (root / f).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        text = _render_full_file_block(f, full_text)
        if _try_add_to(blocks_by_category[5], text):
            covered_files.add(f)
            if f not in symbol_owned_files and (
                not strategy_terms or _contains_any_strategy_identifier(full_text, strategy_terms)
            ):
                full_file_fallback_covered.add(f)

    lines: "list[str]" = [_SLICE_HEADING, "", _SLICE_DISCLAIMER]
    any_block = False
    for group in (
        blocks_by_category[1], one_hop_blocks, blocks_by_category[2],
        blocks_by_category[3], blocks_by_category[4], blocks_by_category[5],
    ):
        for text in group:
            lines.append("")
            lines.append(text.rstrip())
            any_block = True
    rendered = ("\n".join(lines).rstrip() + "\n") if any_block else ""

    uncovered_files = [f for f in strategy.target_files if f not in covered_files]
    uncovered_symbols = [s for s in strategy.target_symbols if s not in covered_symbols]
    coverage_complete = not uncovered_files and not uncovered_symbols
    has_any_coverage = bool(covered_files or covered_symbols)

    warning_text = _render_coverage_warning(
        uncovered_files, uncovered_symbols, rendered_nonempty=bool(rendered),
        named_any_target=bool(strategy.target_files or strategy.target_symbols),
    )

    return FinalTargetSliceResult(
        rendered=rendered,
        covered_target_files=[f for f in strategy.target_files if f in covered_files],
        covered_target_symbols=[s for s in strategy.target_symbols if s in covered_symbols],
        uncovered_target_files=uncovered_files,
        uncovered_target_symbols=uncovered_symbols,
        coverage_complete=coverage_complete,
        has_any_coverage=has_any_coverage,
        warning_text=warning_text,
        resolved_target_symbols=list(symbol_matches.keys()),
        full_file_fallback_covered=sorted(full_file_fallback_covered),
        edit_target_budget_exhausted=edit_target_budget_exhausted,
        resolved_symbol_files={raw: m.file for raw, m in symbol_matches.items()},
        identifier_definition_covered=sorted(identifier_definition_covered),
    )


# ---------------------------------------------------------------------------
# Edit Readiness Gate (Slice 1)
#
# Prevents Patch Generation from running when an intended edit does not yet
# have relevant, verified, patch-ready repository source -- replacing the
# coarse "has_any_coverage == safe to generate" assumption with a decision
# made separately for every intended edit. Reuses ONLY data
# build_final_target_slice() already computes: no new repository read, no
# new resolution pass, no new LLM call, no retrieval loop. Slices 2+
# (bounded re-retrieval, post-patch correction) are explicitly out of scope
# here -- this only detects and fails closed.
# ---------------------------------------------------------------------------


class IntendedEdit(NamedTuple):
    """One deterministic (file, symbol) pair Patch Generation is expected
    to edit -- derived only from RemediationStrategyResult's already
    independently re-verified target_files/target_symbols (see
    _verify_strategy_targets). Never a new LLM schema, never a new
    resolution pass. `symbol` is None only for a file-level intended edit
    (see build_intended_edits)."""

    file: "str | None"
    symbol: "str | None"


def build_intended_edits(
    strategy: RemediationStrategyResult, slice_result: "FinalTargetSliceResult | None" = None,
) -> "list[IntendedEdit]":
    """Derive intended edits from a verified RemediationStrategyResult.

    One IntendedEdit per verified target_symbol (deduplicated, in
    strategy.target_symbols' own order), using _split_symbol_entry -- the
    same existing helper _resolve_symbol_details already uses -- to read
    off a file hint when the symbol string carries one
    ("path/to/file.py:Class.method"). A file-level IntendedEdit
    (symbol=None) is added only for a verified target_file that has no
    target_symbol naming a location inside it, per this slice's explicit
    scope ("Add a file-level intended edit only when a verified target
    file has no corresponding verified target symbol").

    A target_symbol with NO file hint in its own string (e.g. a bare
    "Class.method") is not necessarily unrelated to one of
    strategy.target_files -- it may simply have been proposed without a
    "file.py:" prefix. `slice_result.resolved_symbol_files` (already
    computed by build_final_target_slice -- see FinalTargetSliceResult),
    when given, supplies that symbol's own real, verified file without
    any new resolution pass here. Passing it lets a bare symbol's
    IntendedEdit carry its real file (rather than file=None) and
    correctly suppresses the file-level IntendedEdit that would
    otherwise be added for the same file -- fixing a real duplication:
    without this, a bare target_symbol resolving into a file already
    named in target_files previously produced TWO IntendedEdits for one
    logical target (IntendedEdit(file=None, symbol=...) AND
    IntendedEdit(file=<that file>, symbol=None)), and the second,
    spurious one could fail readiness on its own and falsely block Patch
    Generation even though the real (symbol) edit was fully ready.
    `slice_result=None` (the default) preserves the exact prior
    behavior for any caller that doesn't have one yet.

    Pure and deterministic: no repository access, no new resolution, no
    LLM call -- everything read here (including via `slice_result`) was
    already computed and re-verified before this function is ever
    called.
    """
    resolved_symbol_files = getattr(slice_result, "resolved_symbol_files", None) or {}

    edits: "list[IntendedEdit]" = []
    seen_symbols: set = set()
    symbol_files: set = set()
    for raw_symbol in strategy.target_symbols:
        if raw_symbol in seen_symbols:
            continue
        seen_symbols.add(raw_symbol)
        file_hint, _name = _split_symbol_entry(raw_symbol)
        resolved_file = file_hint or resolved_symbol_files.get(raw_symbol)
        if resolved_file:
            symbol_files.add(resolved_file)
        edits.append(IntendedEdit(file=resolved_file, symbol=raw_symbol))

    seen_files: set = set()
    for f in strategy.target_files:
        if f in symbol_files or f in seen_files:
            continue
        seen_files.add(f)
        edits.append(IntendedEdit(file=f, symbol=None))

    return edits


class ReadyEdit(NamedTuple):
    """One intended edit the Final-Target Remediation Slice already has
    patch-ready source for. `role` is always "edit_target" -- the only
    role check_edit_readiness ever grants readiness through (a consumer,
    dependency, caller, or callee is never treated as equivalent to the
    actual edit target -- see check_edit_readiness)."""

    edit: IntendedEdit
    role: str
    file: str
    symbol: "str | None"


class UnreadyEdit(NamedTuple):
    """One intended edit the Slice does NOT yet have patch-ready source
    for, with the single most evidence-supported reason -- see
    check_edit_readiness's docstring for exactly what each reason means
    and what it deliberately does not claim."""

    edit: IntendedEdit
    reason: str


class EditReadinessResult(NamedTuple):
    """The Edit Readiness Gate's decision -- exposed at enough detail for
    later work (bounded re-retrieval, post-patch correction) without this
    slice implementing either. `failure_reasons` is `unready_edits`' own
    reasons, deduplicated, in first-seen order -- a quick top-level
    summary of why readiness failed, never a claim more precise than what
    each UnreadyEdit itself already states."""

    strategy_ready: bool
    edit_source_ready: bool
    intended_edits: "list[IntendedEdit]"
    ready_edits: "list[ReadyEdit]"
    unready_edits: "list[UnreadyEdit]"
    failure_reasons: "list[str]"


# The full reason vocabulary this Gate's schema supports. NOTE:
# "source_not_patch_ready" is deliberately never produced by
# check_edit_readiness below -- every block build_final_target_slice
# renders today (padded constants via _DEFINITION_CONTEXT_LINES, whole
# functions, focused windows, full files) is already patch-ready by
# construction, so nothing in current data can distinguish "resolved and
# rendered, but not patch-ready" from "ready". Kept in the vocabulary for
# schema completeness/forward compatibility only -- see check_edit_readiness's
# docstring, which is the actual, current, evidence-backed behavior.
EDIT_READINESS_REASONS = (
    "unresolved_symbol",
    "missing_target_source",
    "missing_identifier",
    "source_not_patch_ready",
    "target_budget_exhausted",
)


def check_edit_readiness(
    intended_edits: "list[IntendedEdit]", slice_result: FinalTargetSliceResult
) -> EditReadinessResult:
    """Deterministically decide, per intended edit, whether the Final-
    Target Remediation Slice already gave Patch Generation patch-ready,
    verified repository source for it -- reusing only fields
    build_final_target_slice() already computes. No new repository read,
    no new resolution pass, no new LLM call, no retrieval.

    A symbol-having edit is ready iff its symbol is in
    slice_result.covered_target_symbols -- which already means, by
    build_final_target_slice's own coverage rule (see that function's
    docstring), "this exact symbol's own definition or full/windowed
    source was rendered", never merely "some other identifier from the
    same file was included". When not ready:
      - "unresolved_symbol" if the symbol never resolved to a real
        repository location at all (not in slice_result.resolved_target_symbols);
      - "target_budget_exhausted" if it resolved, but the combined
        attempted size of every edit-target candidate (categories 1, 3b,
        4 -- computed BEFORE any supporting-context block was even
        considered) already exceeded the whole slice budget on its own;
      - "missing_target_source" otherwise (resolved, budget had room, but
        no usable rendered source for it still made it in -- e.g. a read
        failure, or an oversized function exceeding the compact-render
        cap; current data cannot distinguish these further, so this
        function does not claim to).

    A file-only edit (no target_symbol names a location inside it) is
    ready via either of two precise, verified sources -- categories 1/3b/4
    never fire without a resolved symbol, so neither path can ever be
    satisfied by an unrelated same-file block:
      - slice_result.full_file_fallback_covered (category 5): the whole
        file was rendered AND contains a strategy-derived identifier; or
      - slice_result.identifier_definition_covered (category 2): an
        EXACT definition of a strategy-derived identifier -- constant or
        function, not a mere usage window -- was rendered from that
        file. Added for Slice 2 (Deterministic Pre-Patch Retrieval):
        without it, a file whose own exact identifier definition was
        found and rendered could still fail readiness merely because
        category 5's full-file fallback never ran for it (already
        covered, so skipped) -- an evidence-quality gap, not a
        correctness requirement, since a resolved exact definition is
        strictly stronger evidence than an unverified whole file.
    When neither is satisfied:
      - "missing_target_source" if no source at all was rendered for
        that file;
      - "missing_identifier" if source WAS rendered for that file (it's
        in covered_target_files) but not via either of the above -- i.e.
        only unrelated/supporting content (e.g. a usage window, or a
        one-hop dependency) from that file exists, which must never
        count as covering it.

    "source_not_patch_ready" is never produced -- see EDIT_READINESS_REASONS.
    """
    strategy_ready = bool(intended_edits)
    ready: "list[ReadyEdit]" = []
    unready: "list[UnreadyEdit]" = []
    reasons_seen: "list[str]" = []

    def _note(reason: str) -> None:
        if reason not in reasons_seen:
            reasons_seen.append(reason)

    for edit in intended_edits:
        if edit.symbol is not None:
            if edit.symbol in slice_result.covered_target_symbols:
                ready.append(ReadyEdit(edit=edit, role="edit_target", file=edit.file or "", symbol=edit.symbol))
                continue
            if edit.symbol not in slice_result.resolved_target_symbols:
                reason = "unresolved_symbol"
            elif slice_result.edit_target_budget_exhausted:
                reason = "target_budget_exhausted"
            else:
                reason = "missing_target_source"
        else:
            if (
                edit.file in slice_result.full_file_fallback_covered
                or edit.file in slice_result.identifier_definition_covered
            ):
                ready.append(ReadyEdit(edit=edit, role="edit_target", file=edit.file or "", symbol=None))
                continue
            if edit.file not in slice_result.covered_target_files:
                reason = "missing_target_source"
            else:
                reason = "missing_identifier"
        unready.append(UnreadyEdit(edit=edit, reason=reason))
        _note(reason)

    edit_source_ready = strategy_ready and not unready
    return EditReadinessResult(
        strategy_ready=strategy_ready,
        edit_source_ready=edit_source_ready,
        intended_edits=list(intended_edits),
        ready_edits=ready,
        unready_edits=unready,
        failure_reasons=reasons_seen,
    )


# ---------------------------------------------------------------------------
# Slice 2 -- Deterministic Pre-Patch Retrieval
#
# When check_edit_readiness (Slice 1) reports one or more UnreadyEdits,
# attempt to obtain additional verified repository source for exactly
# those targets -- deterministic, bounded, language-agnostic, fully
# traceable, fail-closed, and free of any new LLM call. Not a general
# agent loop: there is no exploration, no LLM-guided request, no retry of
# Patch Generation itself, and no post-patch recovery -- see
# run_deterministic_acquisition's docstring for the exact scope.
#
# Design choice: rather than a second, parallel retrieval implementation,
# this RE-INVOKES build_final_target_slice() itself, per still-unready
# edit, on a narrowly-scoped RemediationStrategyResult naming ONLY that
# edit's own file/symbol -- so every existing category (1-5), the
# existing _DEFINITION_CONTEXT_LINES padding, the existing ambiguity
# rejection (_disambiguate_constant_candidates), and the existing
# coverage rules all apply completely unchanged. check_edit_readiness
# itself (also completely unchanged) is what decides whether each
# retrieval attempt actually satisfied its edit.
# ---------------------------------------------------------------------------

MAX_ACQUISITION_ROUNDS = 2
"""How many acquisition rounds run_deterministic_acquisition will attempt
before giving up and failing closed. Conservative MVP default -- Slice 3
(LLM-guided context requests) is explicitly out of scope, so there is no
mechanism here to ever do better than "the same deterministic lookups,
tried again next round with a fresh per-round budget for whatever is
still unready"."""

MAX_UNREADY_EDITS_PER_ROUND = 2
"""How many still-unready intended edits one round will attempt, in
their existing (deterministic) order. Never all of them at once -- an
unbounded round could spend the whole remaining budget on a single
round's first few targets."""

MAX_NEW_SOURCE_CHARS_PER_ROUND = 5_000
"""Shared character budget for ONE round's acquisition, across every
edit that round processes (not per edit) -- consumed in order as each
edit in the round is attempted. Always further clamped by whatever
remains of FINAL_TARGET_SLICE_MAX_CHARS overall (see
run_deterministic_acquisition) -- this is a per-round ceiling on top of
the existing hard total, never a separate allowance that extends it."""

MAX_NEW_BLOCKS_PER_EDIT_PER_ROUND = 1
"""At most one new EDIT-TARGET block per edit per round. Enforced
STRUCTURALLY, not by truncating a rendered result after the fact: each
round's retrieval call for one edit is built from a RemediationStrategy
naming ONLY that edit's own single file-or-symbol target, so categories
1/3b/4 (the edit-target categories) can resolve at most that one target.
A one-hop supporting definition or full-file fallback may still
accompany it as SUPPORTING content, exactly like every other
build_final_target_slice call -- never a second competing edit-target
block for the same edit."""


class RetrievalAttempt(NamedTuple):
    """One deterministic acquisition attempt for a single UnreadyEdit,
    during one round of run_deterministic_acquisition. Fields are
    exactly what actually happened -- `resolved_file`/`resolved_symbol`/
    `start_line`/`end_line`/`source_kind` are None whenever nothing was
    rendered for this edit this round, never a guess.

    `failure_reason` reuses check_edit_readiness's own
    EDIT_READINESS_REASONS vocabulary verbatim (this function's own
    per-edit recheck IS a check_edit_readiness call) -- no new reason
    string is invented. In particular, an ambiguous candidate
    (_disambiguate_constant_candidates rejecting a tie) is not
    separately labeled "ambiguous" here: it is simply never rendered, so
    it surfaces as "missing_target_source"/"missing_identifier" like any
    other resolved-but-unrendered case, per this module's existing "do
    not claim a more precise reason than the underlying data supports"
    convention (see check_edit_readiness's own docstring for the same
    convention applied to "missing_target_source")."""

    intended_edit: IntendedEdit
    round: int
    retrieval_strategy: str
    resolved_file: "str | None"
    resolved_symbol: "str | None"
    start_line: "int | None"
    end_line: "int | None"
    source_kind: "str | None"
    source_chars: int
    success: bool
    failure_reason: "str | None"


class AcquisitionResult(NamedTuple):
    """run_deterministic_acquisition's own output. `slice_result` is the
    ORIGINAL slice extended additively with whatever this loop acquired
    -- nothing already present is ever removed or reordered. `attempts`
    is every RetrievalAttempt made, in round then edit order (for the
    debug artifact). `rounds_used` is 0 when the initial readiness was
    already complete (no acquisition work performed at all)."""

    slice_result: FinalTargetSliceResult
    attempts: "list[RetrievalAttempt]"
    rounds_used: int


_RENDERED_LINES_RE = re.compile(r"\(lines (\d+)[–-](\d+)\)")


def _sniff_rendered_lines(rendered_text: str) -> "tuple[int | None, int | None]":
    """Recover the (start, end) line numbers from a block's own header --
    a format this module fully controls (_render_definition_block/
    _render_usage_window_block), so this is reading back already-known
    data, never a new computation or a guess."""
    m = _RENDERED_LINES_RE.search(rendered_text)
    if not m:
        return None, None
    return int(m.group(1)), int(m.group(2))


def _sniff_rendered_kind(rendered_text: str) -> "str | None":
    """Classify which of this module's own, fully-controlled block
    headers is present -- for RetrievalAttempt.source_kind only, never
    consulted by any readiness or budget decision."""
    if "#### Target definition:" in rendered_text:
        return "exact_definition"
    if "#### Discovered consumer:" in rendered_text:
        return "usage_window"
    if "#### Full file (last resort):" in rendered_text:
        return "full_file_fallback"
    return None


def _merge_slice_results(
    base: FinalTargetSliceResult,
    addition: FinalTargetSliceResult,
    strategy: RemediationStrategyResult,
) -> FinalTargetSliceResult:
    """Fold one round's single-edit Final-Target Slice into the running
    aggregate -- ADDITIVELY ONLY: every field is a union/append against
    `base`, so nothing already covered or already rendered is ever
    removed, reordered, or displaced. `addition`'s own per-round budget
    was already independently enforced by build_final_target_slice (see
    run_deterministic_acquisition) -- this performs no further size
    check of its own.

    Coverage/uncovered/coverage_complete/has_any_coverage are recomputed
    against the FULL original `strategy` (not `addition`'s narrowly-
    scoped one) so they keep meaning exactly what they meant before
    acquisition ever ran. `warning_text` is re-rendered via the same
    _render_coverage_warning helper build_final_target_slice itself
    uses, so it never goes stale after new coverage is folded in.
    """
    rendered = base.rendered
    if addition.rendered:
        rendered = (rendered.rstrip() + "\n\n" + addition.rendered) if rendered else addition.rendered

    covered_files = set(base.covered_target_files) | set(addition.covered_target_files)
    covered_symbols = set(base.covered_target_symbols) | set(addition.covered_target_symbols)
    resolved_symbols = set(base.resolved_target_symbols) | set(addition.resolved_target_symbols)
    fallback_covered = set(base.full_file_fallback_covered) | set(addition.full_file_fallback_covered)
    identifier_def_covered = set(base.identifier_definition_covered) | set(addition.identifier_definition_covered)
    resolved_symbol_files = dict(base.resolved_symbol_files)
    resolved_symbol_files.update(addition.resolved_symbol_files)

    uncovered_files = [f for f in strategy.target_files if f not in covered_files]
    uncovered_symbols = [s for s in strategy.target_symbols if s not in covered_symbols]
    coverage_complete = not uncovered_files and not uncovered_symbols

    return FinalTargetSliceResult(
        rendered=rendered,
        covered_target_files=[f for f in strategy.target_files if f in covered_files],
        covered_target_symbols=[s for s in strategy.target_symbols if s in covered_symbols],
        uncovered_target_files=uncovered_files,
        uncovered_target_symbols=uncovered_symbols,
        coverage_complete=coverage_complete,
        has_any_coverage=bool(covered_files or covered_symbols),
        warning_text=_render_coverage_warning(
            uncovered_files, uncovered_symbols, rendered_nonempty=bool(rendered),
            named_any_target=bool(strategy.target_files or strategy.target_symbols),
        ),
        resolved_target_symbols=sorted(resolved_symbols),
        full_file_fallback_covered=sorted(fallback_covered),
        edit_target_budget_exhausted=base.edit_target_budget_exhausted or addition.edit_target_budget_exhausted,
        resolved_symbol_files=resolved_symbol_files,
        identifier_definition_covered=sorted(identifier_def_covered),
    )


def _try_commit_acquisition(
    current_slice: FinalTargetSliceResult,
    addition: FinalTargetSliceResult,
    strategy: RemediationStrategyResult,
    edits_to_check: "list[IntendedEdit]",
) -> "tuple[FinalTargetSliceResult, EditReadinessResult, bool]":
    """Transactional commit/rollback for ONE acquisition candidate --
    Slice 2 (run_deterministic_acquisition) and Slice 3
    (run_guided_acquisition) both share this exact mechanism rather than
    each reimplementing it. `addition` is folded into a TEMPORARY working
    slice via the existing, unmodified _merge_slice_results (never a
    second merge implementation), so Edit Readiness for `edits_to_check`
    can be recomputed (check_edit_readiness, also unmodified) against
    what the running slice WOULD look like if this candidate were kept.

    The commit criterion is exactly, and only, "did Edit Readiness
    improve for at least one of `edits_to_check`?" -- deterministic,
    content-blind, and never a heuristic judgement of whether the
    retrieved text looks generically useful:
      - improved (at least one of `edits_to_check` is now in the
        returned readiness's `ready_edits`): the temporary merge IS the
        new running slice -- `addition` is committed, and its size is
        the caller's own signal to actually deduct from whatever budget
        it tracks.
      - not improved: `current_slice` is returned completely unchanged --
        `addition` never entered the Final-Target Slice, so a caller
        that only advances its own state (and consumes its own budget)
        when `committed` is True never lets a rolled-back candidate
        occupy either.

    Returns `(slice_to_use, readiness, committed)`. `readiness` is
    ALWAYS computed against the temporary merged slice, whether or not
    it is committed -- so a rolled-back attempt's own diagnostic
    (`RetrievalAttempt.failure_reason` / `GuidedRetrievalAttempt.
    failure_reason`) still names exactly what THIS attempt found (e.g.
    "target_budget_exhausted", "missing_identifier"), precisely as
    before this mechanism existed. It is `slice_to_use` -- never
    `readiness` -- that enforces "a rolled-back candidate leaves the
    running slice, and therefore every OTHER edit's own readiness,
    completely unchanged": callers must recompute readiness against
    `slice_to_use` (not this returned `readiness`) for anything meant to
    persist past this one attempt (e.g. the next round's starting
    readiness)."""
    merged = _merge_slice_results(current_slice, addition, strategy)
    readiness = check_edit_readiness(edits_to_check, merged)
    committed = bool(readiness.ready_edits)
    return (merged if committed else current_slice), readiness, committed


def _focused_strategy_for_edit(strategy: RemediationStrategyResult, edit: IntendedEdit) -> RemediationStrategyResult:
    """A RemediationStrategyResult naming ONLY `edit`'s own file/symbol --
    `extended_mechanism`/`required_edits` are kept unchanged, so strategy-
    derived identifier extraction (_extract_strategy_identifiers, used by
    categories 2/3a/one-hop) still benefits from the full mechanism text;
    only WHICH targets are attempted is narrowed. This is what makes one
    retrieval attempt see only its own edit target -- never an unrelated
    caller, consumer, or other still-ready target competing for the same
    round budget (see MAX_NEW_BLOCKS_PER_EDIT_PER_ROUND)."""
    target_symbols = [edit.symbol] if edit.symbol is not None else []
    target_files = [edit.file] if edit.file else []
    return strategy._replace(target_files=target_files, target_symbols=target_symbols)


def run_deterministic_acquisition(
    strategy: RemediationStrategyResult,
    repo_root,
    context,
    slice_result: FinalTargetSliceResult,
    readiness: EditReadinessResult,
    budget_controller: "ContextBudgetController | None" = None,
) -> AcquisitionResult:
    """
    Slice 2 -- Deterministic Pre-Patch Retrieval.

    Runs ONLY when `readiness` already reports at least one UnreadyEdit;
    a fully-ready (or empty) initial readiness performs zero acquisition
    work and returns `slice_result` unchanged (rounds_used=0, no
    attempts) -- see PipelineResult.edit_acquisition/pipeline.py wiring
    for where this sits between the Edit Readiness Gate and Patch
    Generation.

    Bounded: at most MAX_ACQUISITION_ROUNDS rounds; each round attempts
    at most MAX_UNREADY_EDITS_PER_ROUND still-unready intended edits (in
    their existing, deterministic order -- never re-ordered by size or
    likelihood of success); each round's newly-acquired source is capped
    at MAX_NEW_SOURCE_CHARS_PER_ROUND characters shared across that
    round's edits, and further clamped so FINAL_TARGET_SLICE_MAX_CHARS
    overall is never exceeded -- this is the SAME hard total the initial
    slice already enforces, never a separate additional allowance.

    Deterministic and language-agnostic: each attempt re-invokes
    build_final_target_slice() itself (unmodified) on a strategy naming
    only that one edit's own target (_focused_strategy_for_edit) -- so
    every existing category (1: exact definitions, 2: strategy-
    identifier definitions, 3: focused usage windows, 4: compact full
    functions, 5: full-file fallback), the existing
    _DEFINITION_CONTEXT_LINES padding, and the existing ambiguity
    rejection (_disambiguate_constant_candidates -- an ambiguous
    candidate is never promoted, exactly as in the initial pass) all
    apply completely unchanged. No fuzzy matching, no trusting an
    LLM-provided line number (nothing here reads one), no retrieval of a
    caller/consumer as a substitute for the edit target -- the focused
    strategy names only the edit target itself, so a supporting-role
    category can only ever surface content FROM that same file/symbol's
    own neighborhood, never an unrelated one.

    Readiness is recalculated (check_edit_readiness, unmodified) after
    every round, and the loop stops immediately once every intended edit
    is ready -- never running a round it doesn't need. If bounds are
    reached with readiness still incomplete, the caller's existing
    fail-closed skip path applies unchanged; this function itself makes
    no Patch Generation decision.

    Never evicts anything already in `slice_result`, and -- via
    _try_commit_acquisition (shared with Slice 3) -- never ADDS anything
    that didn't earn its place either: each attempt's `addition` is
    committed into the running slice, and only then counts against
    `round_budget_remaining`/the overall FINAL_TARGET_SLICE_MAX_CHARS
    total, if it actually made `edit` ready. An attempt that resolves and
    renders fine but never satisfies `edit`'s own readiness is rolled
    back completely -- transactional, so a candidate that never helped
    this edit can never be the reason a LATER, more precise attempt
    (this round, a later round, or Slice 3 afterward) fails with
    "target_budget_exhausted"/"context_request_limit_reached" purely
    because the earlier one silently used up shared budget. Introduces
    zero new LLM calls (build_final_target_slice/check_edit_readiness
    both take no `llm` parameter).

    `budget_controller=None` (the default, and every existing caller)
    preserves this exact fixed-budget, fail-closed behavior unchanged.
    When given, a candidate blocked ONLY by the shared
    FINAL_TARGET_SLICE_MAX_CHARS total (never by an unsafe path,
    ambiguity, or any other non-budget reason) gets exactly one
    immediate, local retry against a raised ceiling if the controller
    approves an additional window (see ContextBudgetController /
    _effective_final_target_max) -- never a second round, never a
    restart of this function, never a rerun of the Planner/Final
    Strategy.
    """
    if readiness.edit_source_ready or not readiness.unready_edits:
        return AcquisitionResult(slice_result=slice_result, attempts=[], rounds_used=0)

    attempts: "list[RetrievalAttempt]" = []
    current_slice = slice_result
    current_readiness = readiness
    rounds_used = 0

    for round_num in range(1, MAX_ACQUISITION_ROUNDS + 1):
        if current_readiness.edit_source_ready or not current_readiness.unready_edits:
            break
        rounds_used = round_num
        batch = current_readiness.unready_edits[:MAX_UNREADY_EDITS_PER_ROUND]
        round_budget_remaining = MAX_NEW_SOURCE_CHARS_PER_ROUND

        for unready in batch:
            edit = unready.edit
            _affected = [f"{edit.file or '?'}:{edit.symbol or '(file-level)'}"]
            total_remaining = _effective_final_target_max(budget_controller) - len(current_slice.rendered)
            available = min(round_budget_remaining, total_remaining)
            if budget_controller is not None:
                budget_controller.record_used("final_target_slice", len(current_slice.rendered))

            if available <= 0 or (edit.symbol is None and not edit.file):
                if available <= 0 and budget_controller is not None and budget_controller.request_extension(
                    "final_target_slice", FINAL_TARGET_SLICE_MAX_CHARS,
                    reason="target_budget_exhausted", affected_targets=_affected,
                ):
                    total_remaining = _effective_final_target_max(budget_controller) - len(current_slice.rendered)
                    available = min(round_budget_remaining, total_remaining)
                if available <= 0 or (edit.symbol is None and not edit.file):
                    attempts.append(RetrievalAttempt(
                        intended_edit=edit, round=round_num, retrieval_strategy="skipped_no_budget",
                        resolved_file=None, resolved_symbol=None, start_line=None, end_line=None,
                        source_kind=None, source_chars=0, success=False,
                        failure_reason="target_budget_exhausted" if available <= 0 else unready.reason,
                    ))
                    continue

            focused_strategy = _focused_strategy_for_edit(strategy, edit)
            addition = build_final_target_slice(
                focused_strategy, repo_root, context, planner_evidence_files=(), max_chars=available,
            )
            current_slice, single, committed = _try_commit_acquisition(current_slice, addition, strategy, [edit])
            if committed:
                round_budget_remaining = max(0, round_budget_remaining - len(addition.rendered))
            elif (
                budget_controller is not None
                and single.unready_edits
                and single.unready_edits[0].reason == "target_budget_exhausted"
                and budget_controller.request_extension(
                    "final_target_slice", FINAL_TARGET_SLICE_MAX_CHARS,
                    reason="target_budget_exhausted", affected_targets=_affected,
                )
            ):
                # Resolved fine but didn't fit `available` -- exactly one
                # local retry against the newly-raised shared ceiling,
                # never a second round and never a Planner/Strategy rerun.
                total_remaining = _effective_final_target_max(budget_controller) - len(current_slice.rendered)
                available = min(round_budget_remaining, total_remaining)
                addition = build_final_target_slice(
                    focused_strategy, repo_root, context, planner_evidence_files=(), max_chars=available,
                )
                current_slice, single, committed = _try_commit_acquisition(current_slice, addition, strategy, [edit])
                if committed:
                    round_budget_remaining = max(0, round_budget_remaining - len(addition.rendered))

            if single.ready_edits:
                r = single.ready_edits[0]
                start, end = _sniff_rendered_lines(addition.rendered)
                attempts.append(RetrievalAttempt(
                    intended_edit=edit, round=round_num, retrieval_strategy="final_target_slice_retry",
                    resolved_file=r.file or None, resolved_symbol=r.symbol,
                    start_line=start, end_line=end,
                    source_kind=_sniff_rendered_kind(addition.rendered),
                    source_chars=len(addition.rendered), success=True, failure_reason=None,
                ))
            else:
                reason = single.unready_edits[0].reason if single.unready_edits else "missing_target_source"
                attempts.append(RetrievalAttempt(
                    intended_edit=edit, round=round_num, retrieval_strategy="final_target_slice_retry",
                    resolved_file=None, resolved_symbol=None, start_line=None, end_line=None,
                    source_kind=None, source_chars=len(addition.rendered), success=False, failure_reason=reason,
                ))

        current_readiness = check_edit_readiness(readiness.intended_edits, current_slice)

    return AcquisitionResult(slice_result=current_slice, attempts=attempts, rounds_used=rounds_used)


# ---------------------------------------------------------------------------
# Slice 3 -- Bounded LLM-guided pre-patch context retrieval
#
# Runs only after Slice 2 (deterministic acquisition) still leaves at least
# one intended edit unready. The LLM may NAME repository identifiers it
# still needs (a symbol, an identifier, a file hint) -- it never provides
# repository code, a diff, or a line number, and nothing it returns is ever
# trusted directly: every request is schema-validated, attributed to a
# specific still-unready IntendedEdit, and deterministically resolved
# through the SAME helpers Slice 2 already uses
# (_resolve_symbol_details/_lookup_identifier_definition/
# build_final_target_slice) before a single character of source is
# retrieved. An unattributable, ambiguous, cross-file, or unverified
# request is rejected outright -- the model only ever improves WHICH
# target the next deterministic retrieval attempt goes after, never what
# that attempt is allowed to trust.
# ---------------------------------------------------------------------------

_GUIDED_PROMPT_PATH = Path(__file__).parent / "prompts" / "guided_context_request.md"

GUIDED_REQUEST_TYPES = (
    "symbol_definition",
    "identifier_definition",
    "enclosing_symbol",
    "identifier_usage",
)

MAX_GUIDED_ACQUISITION_ROUNDS = 2
"""At most this many guided rounds -- and therefore at most this many
guided_context_request LLM calls total (exactly one per round, never
more)."""

MAX_CONTEXT_REQUESTS_PER_ROUND = 2
"""At most this many of one round's own context_requests are even
attempted -- any beyond this are ignored, never queued for a later round."""

MAX_CONTEXT_REQUESTS_PER_EDIT = 2
"""At most this many guided requests may be attributed to the SAME
intended edit across the whole guided acquisition run (all rounds
combined) -- prevents one stubborn edit from consuming every round's
budget on repeated requests that already failed."""

MAX_NEW_SOURCE_BLOCKS_PER_REQUEST = 1
"""At most one new EDIT-TARGET block per verified request. Enforced
STRUCTURALLY, exactly like Slice 2's MAX_NEW_BLOCKS_PER_EDIT_PER_ROUND:
each request's retrieval call is built from a RemediationStrategy naming
only that ONE resolved symbol/identifier."""

MAX_GUIDED_SOURCE_CHARS_PER_ROUND = 5_000
"""Shared character budget for one round's guided retrieval, across every
request that round actually attempts -- always further clamped by
whatever remains of FINAL_TARGET_SLICE_MAX_CHARS overall (the SAME hard
total Slice 1/2 already enforce, never a separate additional allowance)."""

GUIDED_REQUEST_FAILURE_REASONS = (
    "unsupported_request_type",
    "missing_required_field",
    "unsafe_file_path",
    "unverified_file_hint",
    "ambiguous_symbol",
    "ambiguous_identifier",
    "cross_file_mismatch",
    "unresolved_symbol",
    "unresolved_identifier",
    "unrelated_to_unready_edit",
    "context_request_limit_reached",
    "target_budget_exhausted",
    "missing_target_source",
)
"""The full reason vocabulary GuidedRetrievalAttempt.failure_reason draws
from -- every rejection below sets exactly one of these, never a freeform
string, so a caller can rely on the vocabulary being closed.

NOTE: "unverified_file_hint" is deliberately never produced today -- an
identifier_definition/identifier_usage request can only ever be
attributed to an unready edit via an explicit, already-truthy file_hint,
and the same is now true of a symbol_definition/enclosing_symbol request
attributed to a file-ONLY unready edit (see _attribute_guided_request),
so by the time resolution runs that file_hint has always either already
verified (continuing past "unsafe_file_path" instead) or already caused
a "continue" on that same reason. Kept in the vocabulary for schema
completeness/forward compatibility only -- same convention as Slice 1's
own "source_not_patch_ready" (see EDIT_READINESS_REASONS)."""


class GuidedContextRequest(NamedTuple):
    """One LLM-proposed context request, parsed from JSON but NOT YET
    verified or attributed -- `intended_edit` is None until
    run_guided_acquisition successfully attributes it to a specific
    still-unready edit. Only ever built from `request_type`/`file_hint`/
    `symbol`/`identifier`/`reason` -- any other key the model's response
    JSON might contain (a line number, source code, a shell command) is
    never read into this structure at all, so it is structurally
    impossible for such a field to influence anything downstream."""

    intended_edit: "IntendedEdit | None"
    request_type: "str | None"
    file_hint: "str | None"
    symbol: "str | None"
    identifier: "str | None"
    reason: "str | None"


class GuidedRetrievalAttempt(NamedTuple):
    """One deterministic verification+retrieval attempt for a single
    GuidedContextRequest. `schema_valid` is False only for a request whose
    own shape is rejected outright (unsupported request_type, or a
    required field missing for that type) -- attribution/verification
    never even run for those. `verified` is True only once the request
    was attributed to a specific unready edit AND deterministically
    resolved to a real, unambiguous repository location.
    `readiness_improved` is True only when that specific attributed edit
    became ready as a direct result of this attempt -- retrieving a
    consumer/usage or an unrelated symbol's own supporting content never
    sets this, even when source was genuinely added (see
    run_guided_acquisition's docstring)."""

    round: int
    request: GuidedContextRequest
    schema_valid: bool
    verified: bool
    failure_reason: "str | None"
    resolved_file: "str | None"
    resolved_symbol: "str | None"
    start_line: "int | None"
    end_line: "int | None"
    source_kind: "str | None"
    source_chars: int
    readiness_improved: bool


class GuidedAcquisitionResult(NamedTuple):
    """run_guided_acquisition's own output -- mirrors AcquisitionResult's
    shape (Slice 2), plus `readiness` (the recalculated
    EditReadinessResult after guided acquisition, so a caller never has
    to re-derive it from `slice_result` a second time)."""

    slice_result: FinalTargetSliceResult
    readiness: EditReadinessResult
    attempts: "list[GuidedRetrievalAttempt]"
    rounds_used: int


def _render_guided_request_context(
    strategy: RemediationStrategyResult,
    vulnerability_text: str,
    readiness: EditReadinessResult,
    slice_result: FinalTargetSliceResult,
    deterministic_attempts: "list",
) -> str:
    """Compact, summary-only prompt context -- NEVER whole files, NEVER
    the full rendered slice text (which may itself contain a full-file
    fallback). Only what's needed to name missing context: a one-line
    vulnerability summary, the already-rendered Final Strategy (reused
    verbatim, not re-rendered), the current intended edits and WHY each
    unready one is unready, which files/symbols are already covered (so
    the model does not re-request them), a compact summary of what Slice
    2 already tried, and the identifiers already visible in verified
    evidence (_extract_strategy_identifiers, reused unchanged)."""
    first_line = ""
    for line in (vulnerability_text or "").splitlines():
        line = line.strip().lstrip("#").strip()
        if line:
            first_line = line
            break

    lines: "list[str]" = ["## Vulnerability summary", "", first_line or "(no summary available)", ""]

    if strategy.rendered:
        lines += [strategy.rendered.rstrip(), ""]

    lines += ["## Current intended edits", ""]
    for e in readiness.intended_edits:
        lines.append(f"- {e.file or '(unknown file)'}:{e.symbol or '(file-level edit)'}")

    lines += ["", "## Unready edits and their evidence-supported reason", ""]
    for u in readiness.unready_edits:
        lines.append(f"- {u.edit.file or '(unknown file)'}:{u.edit.symbol or '(file-level edit)'} -- {u.reason}")

    lines += ["", "## Already-verified evidence -- do not re-request these", ""]
    lines.append("Covered files: " + (", ".join(slice_result.covered_target_files) or "(none)"))
    lines.append("Covered symbols: " + (", ".join(slice_result.covered_target_symbols) or "(none)"))

    if deterministic_attempts:
        lines += ["", "## Deterministic acquisition already attempted (Slice 2)", ""]
        for a in deterministic_attempts:
            outcome = "succeeded" if a.success else (a.failure_reason or "failed")
            lines.append(f"- {a.intended_edit.file or '?'}:{a.intended_edit.symbol or '(file-level)'} -- {outcome}")

    identifiers = _extract_strategy_identifiers(strategy)
    if identifiers:
        lines += ["", "## Identifiers already visible in verified evidence", ""]
        lines.extend(f"- {i}" for i in identifiers)

    return "\n".join(lines) + "\n"


def _parse_one_guided_request(item) -> "GuidedContextRequest | None":
    """Extract only the five allowed fields from one raw JSON item --
    anything else present (a line number, source code, a shell command)
    is never read. Returns None only when `item` isn't even a dict (no
    request to reason about at all)."""
    if not isinstance(item, dict):
        return None

    def _s(key: str) -> "str | None":
        v = item.get(key)
        return v.strip() if isinstance(v, str) and v.strip() else None

    return GuidedContextRequest(
        intended_edit=None,
        request_type=_s("request_type"),
        file_hint=_s("file_hint"),
        symbol=_s("symbol"),
        identifier=_s("identifier"),
        reason=_s("reason"),
    )


def _validate_guided_request_schema(request: GuidedContextRequest) -> "str | None":
    """Returns a GUIDED_REQUEST_FAILURE_REASONS value if `request`'s own
    shape is rejected outright, else None. Never inspects repository
    state -- purely a shape check."""
    if request.request_type not in GUIDED_REQUEST_TYPES:
        return "unsupported_request_type"
    if request.request_type in ("symbol_definition", "enclosing_symbol") and not request.symbol:
        return "missing_required_field"
    if request.request_type in ("identifier_definition", "identifier_usage") and not request.identifier:
        return "missing_required_field"
    return None


def _guided_symbol_is_evidence_supported(
    name: str,
    strategy: "RemediationStrategyResult | None",
    slice_result: "FinalTargetSliceResult | None",
    deterministic_attempts: "list",
) -> bool:
    """True only when `name` was already visible, BEFORE this guided
    request ever ran, in evidence this run already gathered -- the Final
    Strategy's own rendered text/fields, the verified repository source
    already rendered into the current slice ("existing source capsules" /
    verified repository evidence), a prior deterministic-acquisition
    attempt's own resolved symbol or edit (Slice 2 evidence), or the
    repository-looking identifiers this module's existing shape-filtered
    extraction (_extract_strategy_identifiers) already derives from those
    same artifacts. A whole-word, case-sensitive match against the raw
    text is used (not just the shape-filtered extraction) because a
    single-hump capitalized name like "Retry" never matches
    _SNAKE_RE/_CAMEL_RE, yet can still be named explicitly in prose (e.g.
    a rationale or required_edits entry) -- this is the ONLY thing that
    lets a symbol_definition/enclosing_symbol request be attributed to a
    file-ONLY unready edit; see _attribute_guided_request."""
    if not name:
        return False
    word = re.compile(rf"\b{re.escape(name)}\b")

    if strategy is not None:
        if any(word.search(tok) for tok in _extract_strategy_identifiers(strategy)):
            return True
        if strategy.rendered and word.search(strategy.rendered):
            return True
        if strategy.extended_mechanism and word.search(strategy.extended_mechanism):
            return True
        if any(word.search(item) for item in strategy.required_edits if item):
            return True
        if any(word.search(sym) for sym in strategy.target_symbols if sym):
            return True

    if slice_result is not None and slice_result.rendered and word.search(slice_result.rendered):
        return True

    for attempt in deterministic_attempts or ():
        resolved_symbol = getattr(attempt, "resolved_symbol", None)
        if resolved_symbol and word.search(resolved_symbol):
            return True
        intended = getattr(attempt, "intended_edit", None)
        symbol = getattr(intended, "symbol", None) if intended is not None else None
        if symbol and word.search(symbol):
            return True

    return False


def _attribute_guided_request(
    request: GuidedContextRequest,
    unready_edits: "list[UnreadyEdit]",
    strategy: "RemediationStrategyResult | None" = None,
    slice_result: "FinalTargetSliceResult | None" = None,
    deterministic_attempts: "list" = (),
) -> "IntendedEdit | None":
    """A request must be attributable to a specific still-unready
    IntendedEdit -- never satisfied by "some file appears somewhere",
    always by matching against the CURRENT unready set. A
    symbol_definition/enclosing_symbol request matches an edit whose own
    `symbol` equals it exactly, or whose own bare (file-hint-stripped)
    name matches when a file_hint is either absent or consistent with
    that edit's own file. An identifier_definition/identifier_usage
    request -- which never names a specific existing target_symbol --
    can ONLY be attributed via an EXPLICIT file_hint equal to an unready
    edit's own file; a request naming no file_hint is unattributable by
    construction, and is rejected rather than guessed onto the first
    unready edit.

    A symbol_definition/enclosing_symbol request naming no matching
    target_symbol is ADDITIONALLY attributable to a file-ONLY unready
    edit (edit.symbol is None) -- but only when its own file_hint is an
    EXACT match for that edit's own file (never a partial/suffix match,
    never "absent is fine" the way the symbol-having branch above
    tolerates) AND the requested symbol's name was already named by
    evidence this run gathered before this request even existed
    (_guided_symbol_is_evidence_supported). Without the file_hint being
    both present and exact, a bare name that happens to also exist in
    more than one candidate file-only edit is never guessed onto any of
    them. Without the evidence-support check, any symbol that merely
    happens to live inside the right file would qualify -- exactly the
    unbounded behavior this function must not have. This does NOT itself
    verify the file or resolve the symbol -- exactly like the
    symbol-having branch above, that still happens afterward in
    run_guided_acquisition (_verify_file / _resolve_guided_symbol), so a
    file that fails to verify, or a symbol that resolves
    ambiguously/cross-file/not at all, is rejected there with its own
    precise reason, never masked by a coarser "attributed" here."""
    for unready in unready_edits:
        edit = unready.edit
        if request.request_type in ("symbol_definition", "enclosing_symbol"):
            if not request.symbol:
                continue
            if edit.symbol is not None and edit.symbol == request.symbol:
                return edit
            if edit.symbol is not None:
                _e_hint, e_name = _split_symbol_entry(edit.symbol)
                _r_hint, r_name = _split_symbol_entry(request.symbol)
                if e_name == r_name and (not request.file_hint or edit.file in (None, request.file_hint)):
                    return edit
            elif edit.file is not None and request.file_hint and request.file_hint == edit.file:
                _s_hint, s_name = _split_symbol_entry(request.symbol)
                candidate_names = {s_name, s_name.rsplit(".", 1)[-1]}
                if "." in s_name:
                    candidate_names.add(s_name.rsplit(".", 1)[0])
                if any(
                    _guided_symbol_is_evidence_supported(c, strategy, slice_result, deterministic_attempts)
                    for c in candidate_names
                ):
                    return edit
        else:
            if request.file_hint and edit.file == request.file_hint:
                return edit
    return None


def _resolve_guided_symbol(
    symbol: str, verified_file: "str | None", repo_root, context,
) -> "tuple[_SymbolMatch | None, str | None]":
    """Resolve a guided request's `symbol` field, explicitly REJECTING an
    ambiguous bare-name match rather than silently taking
    _resolve_symbol_details' own first-match behavior (that function
    reuses it for the actual resolution once uniqueness is confirmed, so
    there is still only one resolution mechanism -- this only adds the
    enumeration step _resolve_symbol_details itself doesn't perform).
    Returns (match, None) on success, or (None, reason) using
    GUIDED_REQUEST_FAILURE_REASONS.

    A `symbol` that already carries its own file component
    ("other.py:m") which CONTRADICTS a separately-given, already-verified
    `verified_file` (file_hint) is rejected immediately as
    "cross_file_mismatch" -- never silently resolved using one of the two
    disagreeing files while ignoring the other."""
    own_file_hint, name = _split_symbol_entry(symbol)
    if own_file_hint and verified_file and own_file_hint != verified_file:
        return None, "cross_file_mismatch"
    file_part = own_file_hint or verified_file
    qualified = f"{file_part}:{name}" if file_part else name
    bare_name = name.rsplit(".", 1)[-1]
    class_qualifier = name.rsplit(".", 1)[0] if "." in name else None

    index = getattr(context, "index", None)
    func_candidate_files: set = set()
    if index is not None:
        for m in index.search_by_name(bare_name, exact=True):
            candidate_file = _file_part(m.get("id", ""))
            if file_part is not None and candidate_file != file_part:
                continue
            if class_qualifier is not None and m.get("className") != class_qualifier:
                continue
            func_candidate_files.add(candidate_file)
    if len(func_candidate_files) > 1:
        return None, "ambiguous_symbol"

    if not func_candidate_files:
        constants = getattr(context, "constants", None) or {}
        files_to_check = [file_part] if file_part else list(constants.keys())
        const_candidate_files: set = set()
        for f in files_to_check:
            for qn, _record in constants.get(f, {}).items():
                if qn == name or qn.rsplit(".", 1)[-1] == bare_name:
                    const_candidate_files.add(f)
        if len(const_candidate_files) > 1:
            return None, "ambiguous_identifier"

    match = _resolve_symbol_details(qualified, Path(repo_root) if repo_root else None, context)
    if match is None:
        return None, "unresolved_symbol"
    if file_part is not None and match.file != file_part:
        return None, "cross_file_mismatch"
    return match, None


def _resolve_guided_identifier(
    identifier: str, verified_file: str, strategy_target_files: "list[str]", context,
) -> "tuple[_SymbolMatch | None, str | None]":
    """Resolve a guided identifier_definition/identifier_usage request's
    `identifier` field, restricted to the single verified file the
    request was attributed through (never a broader search). Reuses
    _find_constant_candidates_by_name + _disambiguate_constant_candidates
    (the exact same tie-break-then-reject-ambiguity mechanism Slice 2's
    one-hop step already uses) for constants, and
    RepositoryIndex.search_definitions for functions -- no new lookup
    mechanism, only restricted to one file and explicit about rejecting
    a same-file tie."""
    candidates = _find_constant_candidates_by_name(identifier, [verified_file], context)
    if candidates:
        chosen, _reason = _disambiguate_constant_candidates(
            candidates, source_file=verified_file, source_class=None,
            symbol_matches={}, strategy_target_files=strategy_target_files,
        )
        if chosen is None:
            return None, "ambiguous_identifier"
        f, qn, record = chosen
        line, end_line = record.get("line"), record.get("end_line")
        if line is None:
            return None, "unresolved_identifier"
        return _SymbolMatch(file=f, label=qn, kind="constant", line=line, end_line=end_line, func_id=None), None

    index = getattr(context, "index", None)
    if index is not None:
        hits = [m for m in index.search_definitions(identifier) if _file_part(m.get("id", "")) == verified_file]
        if len(hits) > 1:
            return None, "ambiguous_identifier"
        if len(hits) == 1:
            m = hits[0]
            line = m.get("startLine")
            if line is None:
                return None, "unresolved_identifier"
            return _SymbolMatch(
                file=verified_file, label=m.get("name") or identifier, kind="function",
                line=line, end_line=m.get("endLine"), func_id=m.get("id"),
            ), None

    return None, "unresolved_identifier"


def generate_guided_context_requests(
    strategy: RemediationStrategyResult,
    vulnerability_text: str,
    llm,
    readiness: EditReadinessResult,
    slice_result: FinalTargetSliceResult,
    deterministic_attempts: "list" = (),
) -> "list[GuidedContextRequest]":
    """One narrow LLM call (stage "guided_context_request") asking only
    which repository identifiers are still missing -- never a patch,
    never code, never a line number (see prompts/guided_context_request.md
    for the full contract). Returns schema-shape-parsed requests with
    `intended_edit=None` -- attribution and verification happen in
    run_guided_acquisition, never here. Best-effort: any call or parsing
    failure returns [] (never raises), which run_guided_acquisition
    treats identically to "the model had nothing further to ask" --
    failing closed, not retrying.
    """
    system_prompt = _GUIDED_PROMPT_PATH.read_text(encoding="utf-8")
    user_message = _render_guided_request_context(
        strategy, vulnerability_text, readiness, slice_result, list(deterministic_attempts),
    )
    try:
        raw = llm.complete(system_prompt, user_message, stage="guided_context_request")
    except Exception:
        return []

    parsed = _parse_json_response(raw)
    if parsed is None:
        return []
    raw_requests = parsed.get("context_requests")
    if not isinstance(raw_requests, list):
        return []

    out: "list[GuidedContextRequest]" = []
    for item in raw_requests:
        request = _parse_one_guided_request(item)
        if request is not None:
            out.append(request)
    return out


def run_guided_acquisition(
    strategy: RemediationStrategyResult,
    vulnerability_text: str,
    llm,
    repo_root,
    context,
    slice_result: FinalTargetSliceResult,
    readiness: EditReadinessResult,
    deterministic_attempts: "list" = (),
    budget_controller: "ContextBudgetController | None" = None,
) -> GuidedAcquisitionResult:
    """
    Slice 3 -- Bounded LLM-guided pre-patch context retrieval.

    Runs ONLY when `readiness` still reports at least one UnreadyEdit
    (i.e. after Slice 2's deterministic acquisition already ran and
    still left something incomplete) -- a fully-ready or empty readiness
    performs zero guided work and returns `slice_result`/`readiness`
    unchanged (rounds_used=0, no attempts, no LLM call at all).

    Exactly one narrow LLM call per round (stage "guided_context_request",
    see generate_guided_context_requests), up to MAX_GUIDED_ACQUISITION_
    ROUNDS rounds. Never calls the Patch Generator, never reruns the
    Planner or Final Strategy, never calls the Challenger, and never adds
    a hidden retry beyond that one call per round.

    Every returned context_request is treated as untrusted: schema-
    validated (_validate_guided_request_schema), attributed to a specific
    CURRENTLY-unready IntendedEdit (_attribute_guided_request -- an
    unattributable request is rejected, never guessed onto the first
    unready edit), and deterministically resolved
    (_resolve_guided_symbol/_resolve_guided_identifier -- explicitly
    rejecting ambiguous or cross-file-mismatched candidates, never
    trusting the model's own claimed location). Only once resolution
    succeeds is build_final_target_slice() itself re-invoked (exactly
    Slice 2's own retrieval mechanism, on a strategy naming only the one
    resolved symbol/identifier) to actually retrieve verified repository
    source -- no second source-slice implementation.

    Bounded the same way as Slice 2: at most MAX_CONTEXT_REQUESTS_PER_
    ROUND requests attempted per round, at most MAX_CONTEXT_REQUESTS_
    PER_EDIT requests attributed to the same edit across the whole run,
    each round's newly-retrieved source capped at MAX_GUIDED_SOURCE_
    CHARS_PER_ROUND (shared across that round's requests) and further
    clamped so FINAL_TARGET_SLICE_MAX_CHARS overall is never exceeded --
    the SAME hard total Slice 1/2 already enforce, never a separate
    allowance. Stops immediately once every intended edit is ready.

    check_edit_readiness (itself unmodified) is what actually decides
    whether a retrieved block satisfies its attributed edit -- a
    consumer/usage window or a different symbol's own supporting content
    is folded into the slice additively (so Patch Generation still sees
    it) but never marked as satisfying a DIFFERENT edit's readiness,
    exactly like Slice 2. If the bounds are reached with readiness still
    incomplete, the caller's existing fail-closed skip path applies
    unchanged -- this function makes no Patch Generation decision itself.

    `budget_controller=None` (the default, and every existing caller)
    preserves this exact fixed-budget, fail-closed behavior unchanged.
    When given, resolution (_resolve_guided_symbol/_resolve_guided_
    identifier) always runs BEFORE the budget is even consulted, so an
    ambiguous/cross-file/unresolved candidate is rejected on its own
    non-budget reason and never triggers an extension request -- only a
    request that has ALREADY resolved to a real, unambiguous location,
    and is blocked ONLY by the shared FINAL_TARGET_SLICE_MAX_CHARS
    total, gets one immediate, local retry against a raised ceiling if
    the controller approves an additional window (see
    ContextBudgetController / _effective_final_target_max) -- never a
    second round, never a rerun of the Planner/Final Strategy/
    guided_context_request LLM call.
    """
    if readiness.edit_source_ready or not readiness.unready_edits or repo_root is None:
        return GuidedAcquisitionResult(
            slice_result=slice_result, readiness=readiness, attempts=[], rounds_used=0,
        )

    root = Path(repo_root)
    current_slice = slice_result
    current_readiness = readiness
    attempts: "list[GuidedRetrievalAttempt]" = []
    requests_per_edit: dict = {}
    rounds_used = 0

    def _record(round_num, request, schema_valid, verified, failure_reason, match=None,
                start=None, end=None, kind=None, chars=0, improved=False) -> None:
        attempts.append(GuidedRetrievalAttempt(
            round=round_num, request=request, schema_valid=schema_valid, verified=verified,
            failure_reason=failure_reason,
            resolved_file=match.file if match is not None else None,
            resolved_symbol=match.label if match is not None else None,
            start_line=start, end_line=end, source_kind=kind, source_chars=chars,
            readiness_improved=improved,
        ))

    for round_num in range(1, MAX_GUIDED_ACQUISITION_ROUNDS + 1):
        if current_readiness.edit_source_ready or not current_readiness.unready_edits:
            break
        rounds_used = round_num

        raw_requests = generate_guided_context_requests(
            strategy, vulnerability_text, llm, current_readiness, current_slice, deterministic_attempts,
        )
        round_budget_remaining = MAX_GUIDED_SOURCE_CHARS_PER_ROUND

        for request in raw_requests[:MAX_CONTEXT_REQUESTS_PER_ROUND]:
            schema_reason = _validate_guided_request_schema(request)
            if schema_reason is not None:
                _record(round_num, request, False, False, schema_reason)
                continue

            attributed_edit = _attribute_guided_request(
                request, current_readiness.unready_edits, strategy, current_slice, deterministic_attempts,
            )
            if attributed_edit is None:
                _record(round_num, request, True, False, "unrelated_to_unready_edit")
                continue
            request = request._replace(intended_edit=attributed_edit)

            if requests_per_edit.get(attributed_edit, 0) >= MAX_CONTEXT_REQUESTS_PER_EDIT:
                _record(round_num, request, True, False, "context_request_limit_reached")
                continue
            requests_per_edit[attributed_edit] = requests_per_edit.get(attributed_edit, 0) + 1

            verified_file = None
            if request.file_hint:
                verified_file = _verify_file(request.file_hint, root)
                if verified_file is None:
                    _record(round_num, request, True, False, "unsafe_file_path")
                    continue

            # Resolution ALWAYS runs before the budget is even consulted
            # below -- an ambiguous/cross-file/unresolved candidate is
            # rejected on its own non-budget reason here, and never
            # reaches (or triggers) a budget-extension request.
            if request.request_type in ("symbol_definition", "enclosing_symbol"):
                match, reason = _resolve_guided_symbol(request.symbol, verified_file, root, context)
                if match is None:
                    _record(round_num, request, True, False, reason)
                    continue
                focused = strategy._replace(
                    target_files=[match.file], target_symbols=[f"{match.file}:{match.label}"],
                )
            else:
                if verified_file is None:
                    _record(round_num, request, True, False, "unverified_file_hint")
                    continue
                match, reason = _resolve_guided_identifier(
                    request.identifier, verified_file, list(strategy.target_files), context,
                )
                if match is None:
                    _record(round_num, request, True, False, reason)
                    continue
                focused = strategy._replace(
                    target_files=[match.file], target_symbols=[], extended_mechanism=request.identifier,
                )

            _affected = [f"{attributed_edit.file or verified_file or '?'}:{attributed_edit.symbol or '(file-level)'}"]
            total_remaining = _effective_final_target_max(budget_controller) - len(current_slice.rendered)
            available = min(round_budget_remaining, total_remaining)
            if budget_controller is not None:
                budget_controller.record_used("final_target_slice", len(current_slice.rendered))
            if available <= 0:
                if budget_controller is not None and budget_controller.request_extension(
                    "final_target_slice", FINAL_TARGET_SLICE_MAX_CHARS,
                    reason="target_budget_exhausted", affected_targets=_affected,
                ):
                    total_remaining = _effective_final_target_max(budget_controller) - len(current_slice.rendered)
                    available = min(round_budget_remaining, total_remaining)
                if available <= 0:
                    _record(round_num, request, True, False, "target_budget_exhausted")
                    continue

            addition = build_final_target_slice(
                focused, repo_root, context, planner_evidence_files=(), max_chars=available,
            )
            # Transactional: _try_commit_acquisition merges `addition`
            # into a TEMPORARY working slice first -- current_slice only
            # actually advances to it (and only then does this request's
            # size count against round_budget_remaining) when that merge
            # makes attributed_edit ready. A candidate that resolves and
            # renders fine but never satisfies attributed_edit's own
            # readiness (e.g. a usage window, or a block that lands but
            # isn't the exact definition) is rolled back completely --
            # current_slice reverts to exactly what it was before this
            # request, so it never occupies budget a later, more precise
            # request in this same round or a later Slice 3 round would
            # otherwise still have available. single_readiness still
            # reflects what THIS request found (reused for the
            # diagnostic below via check_edit_readiness's own
            # classification -- never a second one), whether or not it
            # was ultimately committed.
            current_slice, single_readiness, improved = _try_commit_acquisition(
                current_slice, addition, strategy, [attributed_edit],
            )
            if improved:
                round_budget_remaining = max(0, round_budget_remaining - len(addition.rendered))
            elif (
                budget_controller is not None
                and single_readiness.unready_edits
                and single_readiness.unready_edits[0].reason == "target_budget_exhausted"
                and budget_controller.request_extension(
                    "final_target_slice", FINAL_TARGET_SLICE_MAX_CHARS,
                    reason="target_budget_exhausted", affected_targets=_affected,
                )
            ):
                # Resolved fine but didn't fit `available` -- exactly one
                # local retry against the newly-raised shared ceiling.
                total_remaining = _effective_final_target_max(budget_controller) - len(current_slice.rendered)
                available = min(round_budget_remaining, total_remaining)
                addition = build_final_target_slice(
                    focused, repo_root, context, planner_evidence_files=(), max_chars=available,
                )
                current_slice, single_readiness, improved = _try_commit_acquisition(
                    current_slice, addition, strategy, [attributed_edit],
                )
                if improved:
                    round_budget_remaining = max(0, round_budget_remaining - len(addition.rendered))
            start, end = (None, None)
            kind = None
            if addition.rendered:
                start, end = _sniff_rendered_lines(addition.rendered)
                kind = _sniff_rendered_kind(addition.rendered)
            _record(
                round_num, request, True, True,
                None if improved else (single_readiness.unready_edits[0].reason if single_readiness.unready_edits else None),
                match=match, start=start, end=end, kind=kind, chars=len(addition.rendered), improved=improved,
            )

        current_readiness = check_edit_readiness(readiness.intended_edits, current_slice)

    return GuidedAcquisitionResult(
        slice_result=current_slice, readiness=current_readiness, attempts=attempts, rounds_used=rounds_used,
    )


# ---------------------------------------------------------------------------
# Slice 4 -- Post-Patch Target Conformance and Recovery
#
# Slices 1-3 validate and acquire source for the intended edits known
# BEFORE Patch Generation runs. Nothing before this point can catch a
# generated patch that edits a DIFFERENT repository target than the one
# Edit Readiness actually approved -- the Patch Generator is free-text
# generation over a large context, not a constrained tool call, and can
# still write a diff against a file/symbol it merely recalls rather than
# one it was given verified source for.
#
# This section adds one deterministic, bounded post-patch gate:
# check_patch_target_conformance() compares the ACTUAL edited targets of
# the generated diff (via the existing diff_parsing.parse_diff and the
# relocation records repair_hunk_headers() already computes as a side
# effect of its own repair pass -- no second diff parser, no second
# relocation mechanism) against the pre-patch ready IntendedEdits and
# verified source. recover_post_patch_source() then attempts, once and
# boundedly, to retrieve verified source for whatever is uncovered --
# reusing build_final_target_slice()/_merge_slice_results() exactly like
# Slices 2/3 do. The actual regeneration LLM call (generate_patch) is
# orchestrated by pipeline.py itself (matching where the existing
# applicability-aware retry call already lives), never here -- this
# module stays a deterministic mechanism library, same as every earlier
# slice.
# ---------------------------------------------------------------------------

MAX_POST_PATCH_RECOVERY_ROUNDS = 1
"""At most one post-patch recovery round -- if the regenerated patch
still isn't conformant, this fails closed rather than looping."""

MAX_RECOVERY_TARGETS = 3
"""At most this many distinct uncovered/unexpected/no_match files are
ever attempted for recovery in one round -- more than this fails closed
immediately (too many unexpected targets to safely recover from)."""

MAX_RECOVERY_SOURCE_BLOCKS_PER_TARGET = 1
"""At most one new EDIT-TARGET block retrieved per recovery target.
Enforced STRUCTURALLY, exactly like Slice 2/3's own per-target bounds:
each target's retrieval call is built from a RemediationStrategy naming
only that one file."""

MAX_POST_PATCH_SOURCE_CHARS = 6_000
"""Shared character budget for the whole recovery round, across every
target it attempts -- always further clamped by whatever remains of
FINAL_TARGET_SLICE_MAX_CHARS overall (the SAME hard total Slices 1-3
already enforce, never a separate additional allowance)."""

MAX_ADDITIONAL_PATCH_GENERATOR_CALLS = 1
"""Slice 4 itself calls generate_patch() at most this many times (the
one bounded regeneration attempt) -- enforced by construction (the
regeneration call site in pipeline.py runs at most once per pipeline
run), not by a counter, since there is only ever one call site."""

POST_PATCH_WINDOW_CONTEXT_LINES = 10
"""Lines of exact repository text padded on each side of a Slice 4
recovery target when no smaller enclosing unit (a sibling constant
group, or a small-enough function -- see _build_post_patch_window) can
be used whole instead. One symmetric constant, matching the existing
_padded_line_range/_DEFINITION_CONTEXT_LINES convention, deliberately
NOT reused from Slices 1-3: _DEFINITION_CONTEXT_LINES (3) is sized for
reasoning/evidence, matching a unified diff's own conventional context
width -- not for reconstructing a diff against a target an earlier,
untrusted regeneration attempt already got slightly wrong. Wider here
on purpose, and scoped to this module's post-patch recovery alone."""

_POST_PATCH_SMALL_ENCLOSING_UNIT_CHARS = _PER_TARGET_FULL_FUNCTION_CAP
"""Reuses the SAME "small enough to include whole rather than a padded
window" threshold Slice 1-3 already use for a compact full-function
render (category 4) -- no new, separate size policy for what counts as
"small" here."""

POST_PATCH_RECOVERY_FAILURE_REASONS = (
    "too_many_recovery_targets",
    "unsafe_file_path",
    "target_budget_exhausted",
    "partial_recovery_evidence",
    "regeneration_call_failed",
    "malformed_or_empty_regenerated_patch",
    "regenerated_patch_still_uncovered",
    "regenerated_patch_introduces_unexpected_file",
)
"""The closed reason vocabulary PostPatchRecoveryResult.failure_reason
and the pipeline's own post-Slice-4 skip decision draw from."""


class PatchTargetConformanceResult(NamedTuple):
    """One edited hunk's conformance verdict. `target_coverage` answers
    "does this edit belong to an approved target at all" -- never merely
    "same repository file": `_edit_target_source_for_file` reads back
    ONLY this module's own EDIT-TARGET-role block headers ("Target
    definition"/"Full file (last resort)"), explicitly excluding
    "Discovered consumer" (supporting/consumer-role) text, so a mechanism
    consumer's own content can never satisfy conformance for a different
    edit target. `old_side_status` answers "does the old-side content
    this hunk claims to remove/match actually exist in the repository" --
    read back from HunkRelocationRecord, which repair_hunk_headers()
    already computed as a side effect of its own repair pass (no second
    relocation mechanism). `conformant` is the single, strict verdict:
    True only when both are satisfied (or, for a genuine new-file hunk,
    when the file is an approved target -- there is no old side to
    verify)."""

    file: str
    hunk_index: int
    target_coverage: str  # "approved_target" | "unexpected_file" | "uncovered_target"
    old_side_status: str  # "old_side_verified" | "old_side_no_match" | "old_side_ambiguous" | "not_verifiable" | "new_file"
    conformant: bool


class PatchConformanceReport(NamedTuple):
    """The full-patch conformance verdict -- one PatchTargetConformanceResult
    per hunk, plus the per-file groupings a caller needs to decide whether
    (and what) to recover. `all_conformant` is strict (every hunk
    conformant, including ambiguous old-side); recovery is triggered by
    the narrower `unexpected_files`/`uncovered_files`/`no_match_files`
    sets, NOT by `all_conformant` alone -- an ambiguous-but-otherwise-
    approved target must not, by itself, trigger recovery (see
    recover_post_patch_source's docstring)."""

    results: "list[PatchTargetConformanceResult]"
    all_conformant: bool
    edited_files: "list[str]"
    unexpected_files: "list[str]"
    uncovered_files: "list[str]"
    no_match_files: "list[str]"


def _edit_target_source_for_file(rendered: str, file: str) -> str:
    """Concatenated CODE content of every EDIT-TARGET-role block for
    exactly `file` inside an already-rendered Final-Target Slice --
    reads back this module's own, fully-controlled block headers
    (_render_definition_block's "Target definition" and
    _render_full_file_block's "Full file (last resort)") via
    _extract_fenced_code (reused, not re-implemented). Deliberately
    excludes _render_usage_window_block's "Discovered consumer" blocks --
    a consumer's own text must never satisfy conformance for a different
    edit target (see PatchTargetConformanceResult's docstring)."""
    if not rendered or not file:
        return ""
    blocks: "list[str]" = []
    for part in re.split(r"\n(?=#### )", rendered):
        if not part.startswith("#### Target definition:") and not part.startswith("#### Full file (last resort):"):
            continue
        header_line = part.splitlines()[0] if part.splitlines() else ""
        m = re.search(r"`([^`]+)`", header_line)
        if not m:
            continue
        path_part = m.group(1).split(":")[0]
        if path_part != file:
            continue
        code = _extract_fenced_code(part)
        if code:
            blocks.append(code)
    return "\n".join(blocks)


def check_patch_target_conformance(
    patch: str,
    relocations: "list",
    ready_edits: "list",
    slice_result: "FinalTargetSliceResult | None",
) -> PatchConformanceReport:
    """Compare the ACTUAL edited targets of a generated patch against the
    pre-patch Edit Readiness Gate's own ready edits and verified source.

    Reuses diff_parsing.parse_diff (the existing, generic unified-diff
    parser -- no second diff parser) for every edited file/hunk, and
    `relocations` (diff_hunk_repair.RepairResult.relocations, already
    computed by repair_hunk_headers() as a side effect of its OWN repair
    pass over this same `patch` -- no second relocation mechanism, no new
    git call, no new repository read) for old-side verification.

    A hunk is "approved_target" only when its own file is one of
    `ready_edits`' own files AND (for a non-new-file hunk) its old-side
    content is found, via the same content-matching primitive
    diff_hunk_repair.py itself uses (content_relocation.
    find_unique_occurrence), inside the EDIT-TARGET-role source already
    rendered for that file (_edit_target_source_for_file) -- never merely
    "this file happens to be a ready target" (see
    PatchTargetConformanceResult's docstring): an edit to an unrelated
    part of a ready-edit's own file, or to a mechanism consumer, is
    "uncovered_target", not "approved_target".

    A hunk whose declared old_start is 0 (repair_hunk_headers' own
    new-file sentinel) is a genuine new-file creation -- there is no old
    side to verify, so it is never classified "old_side_no_match" merely
    for having none; it is "new_file", and conformant whenever its own
    file is an approved target.

    Never raises: an unparseable/empty patch, or missing relocation data,
    degrades to an empty, non-conformant report rather than crashing.
    """
    try:
        changed_files, file_hunks = parse_diff(patch or "")
    except Exception:
        changed_files, file_hunks = [], {}

    ready_files = {getattr(e, "file", None) for e in (ready_edits or []) if getattr(e, "file", None)}
    rendered = getattr(slice_result, "rendered", "") or ""

    by_file_relocations: "dict[str, list]" = {}
    for r in (relocations or []):
        by_file_relocations.setdefault(getattr(r, "file", None), []).append(r)

    results: "list[PatchTargetConformanceResult]" = []
    for file in changed_files:
        hunks = file_hunks.get(file, [])
        file_relocations = by_file_relocations.get(file, [])
        target_source = _edit_target_source_for_file(rendered, file)

        for idx, hunk in enumerate(hunks):
            record = file_relocations[idx] if idx < len(file_relocations) else None

            if record is None:
                old_side_status = "not_verifiable"
            elif getattr(record, "original_hunk_start", None) == 0:
                old_side_status = "new_file"
            elif record.relocation_reason == "unique_match":
                old_side_status = "old_side_verified"
            elif record.relocation_reason == "ambiguous":
                old_side_status = "old_side_ambiguous"
            elif record.relocation_reason == "no_match":
                old_side_status = "old_side_no_match"
            else:
                old_side_status = "not_verifiable"

            if file not in ready_files:
                target_coverage = "unexpected_file"
            elif old_side_status == "new_file":
                # No old side to cross-check -- a new symbol/file inside
                # an already-approved file scope is covered by construction.
                target_coverage = "approved_target"
            else:
                anchors = old_side_anchors(hunk.lines)
                if anchors and target_source and find_unique_occurrence(anchors, target_source.splitlines()) is not None:
                    target_coverage = "approved_target"
                else:
                    target_coverage = "uncovered_target"

            conformant = (
                target_coverage == "approved_target"
                and old_side_status in ("old_side_verified", "new_file")
            )
            results.append(PatchTargetConformanceResult(
                file=file, hunk_index=idx, target_coverage=target_coverage,
                old_side_status=old_side_status, conformant=conformant,
            ))

    all_conformant = bool(results) and all(r.conformant for r in results)
    return PatchConformanceReport(
        results=results,
        all_conformant=all_conformant,
        edited_files=list(changed_files),
        unexpected_files=sorted({r.file for r in results if r.target_coverage == "unexpected_file"}),
        uncovered_files=sorted({r.file for r in results if r.target_coverage == "uncovered_target"}),
        no_match_files=sorted({r.file for r in results if r.old_side_status == "old_side_no_match"}),
    )


def post_patch_recovery_trigger_reasons(conformance: PatchConformanceReport) -> "list[str]":
    """The narrow set of conditions that trigger recovery -- deliberately
    NOT the same as `not conformance.all_conformant`. An ambiguous-but-
    otherwise-approved target alone must never trigger recovery (only
    when the SAME file is also uncovered/unexpected/no_match does it
    already appear in one of these three sets)."""
    reasons: "list[str]" = []
    if conformance.unexpected_files:
        reasons.append("unexpected_file")
    if conformance.uncovered_files:
        reasons.append("uncovered_target")
    if conformance.no_match_files:
        reasons.append("old_side_no_match")
    return reasons


def _recovery_reason_for_file(file: str, conformance: PatchConformanceReport) -> str:
    if file in conformance.unexpected_files:
        return "unexpected_file"
    if file in conformance.no_match_files:
        return "old_side_no_match"
    if file in conformance.uncovered_files:
        return "uncovered_target"
    return "unknown"


# ---------------------------------------------------------------------------
# Slice 4 patch-ready recovery window -- keeps two concepts that the rest of
# this module deliberately conflates for Slices 1-3 (where it is harmless)
# separate here: a REASONING-ready definition (any exact block that proves a
# symbol exists, however narrowly padded) vs. a PATCH-ready edit window (one
# contiguous, sufficiently-padded, verified repository block that a unified
# diff can actually be constructed against). build_final_target_slice's own
# category 2 (identifier definitions) pads each resolved identifier
# independently by _DEFINITION_CONTEXT_LINES (3) -- adequate evidence, but
# when a hunk's real target sits at the edge of, or between, two such
# independently-padded blocks for DIFFERENT nearby identifiers, Patch
# Generation sees two disjoint fragments rather than one buildable window,
# and the regenerated diff's own context lines fail relocation
# (content_relocation.find_unique_occurrence) against the real file. The
# functions below build ONE such window directly -- reusing the same
# primitives (_lookup_identifier_definition, _read_symbol_source,
# _padded_line_range, _rendered_end_line, RepositoryIndex.read_file_section,
# content_relocation.old_side_anchors/find_unique_occurrence) build_final_
# target_slice and repair_hunk_headers already use, never a new repository
# reader or a second relocation mechanism -- and are used ONLY by
# recover_post_patch_source below; Slices 1-3 never call them and are
# therefore unaffected.
# ---------------------------------------------------------------------------

class _PostPatchWindow(NamedTuple):
    """One resolved, contiguous, patch-ready recovery window --
    everything recover_post_patch_source needs to render it
    (_render_definition_block, reused unchanged) and trace it."""

    file: str
    label: str
    target_start: "int | None"  # the resolved target's OWN (unpadded) span --
    target_end: "int | None"    # None for an old-side-anchor match (no symbol resolved)
    start: int                  # the FINAL window actually rendered
    end: int
    source: str
    enclosing_symbol: "str | None"
    source_kind: str  # "patch_ready_window" | "enclosing_symbol" | "small_full_file"


def _constant_group_bounds(
    file: str, class_name: "str | None", context,
) -> "tuple[int, int, int] | None":
    """The contiguous line span covering EVERY constant
    InvestigationContext.constants already records for `file` under the
    SAME enclosing `class_name` (None for module-level) -- the existing
    "class attribute section"/"constant group" metadata this table
    already carries (the same `class_name` field _disambiguate_constant_
    candidates already reads), never a new AST-derived symbol boundary.
    Returns (start, end, member_count), or None when `file` has no
    constants recorded at all. A member_count of 1 means the target has
    no siblings at this scope -- the caller then treats it as having no
    real "enclosing group" and falls back to a plain padded window
    rather than treating one isolated constant as its own enclosing
    unit."""
    constants = getattr(context, "constants", None) or {}
    records = constants.get(file) or {}
    spans = [
        (record.get("line"), record.get("end_line"))
        for record in records.values()
        if record.get("class_name") == class_name
        and record.get("line") is not None and record.get("end_line") is not None
    ]
    if not spans:
        return None
    return min(s for s, _ in spans), max(e for _, e in spans), len(spans)


def _locate_old_side_in_file(
    file_hunks_for_file: "list", verified_file: str, context,
) -> "tuple[int, int] | None":
    """Source priority 1: does one of this file's failing hunks' own
    OLD-side content (context + removed lines) exist, verbatim and
    UNIQUELY, anywhere in the real (current) repository file right now?
    Reuses content_relocation.old_side_anchors/find_unique_occurrence --
    the SAME primitives repair_hunk_headers/check_patch_target_
    conformance already use for old-side verification, never a second
    matching implementation -- searched against the WHOLE file via the
    existing RepositoryIndex.read_file_section reader (never a new
    reader; a huge end_line is safe, see _padded_line_range's own
    docstring: read_file_section already clamps to EOF). Returns a
    1-indexed (start, end) line span, or None when no hunk's old side
    matches uniquely (expected, by construction, for a hunk whose old
    side was already classified "old_side_no_match" upstream -- the
    exact reason it's known NOT to match)."""
    index = getattr(context, "index", None)
    if index is None:
        return None
    whole_file = index.read_file_section(verified_file, 1, 10**9)
    if not whole_file:
        return None
    file_lines = whole_file.splitlines()
    for hunk in file_hunks_for_file:
        anchors = old_side_anchors(hunk.lines)
        if not anchors:
            continue
        pos = find_unique_occurrence(anchors, file_lines)
        if pos is not None:
            return pos + 1, pos + len(anchors)
    return None


def _build_post_patch_window(
    verified_file: str,
    identifiers: "list[str]",
    file_hunks_for_file: "list",
    context,
    try_old_side_anchor: bool,
) -> "_PostPatchWindow | None":
    """Resolve ONE contiguous, patch-ready recovery window for
    `verified_file`, per the Source priority Slice 4 recovery follows:

    1. (only when `try_old_side_anchor`) the failing hunk's own old-side
       content, located verbatim in the real file (_locate_old_side_in_
       file) -- deliberately gated to the "uncovered_target" trigger
       reason by the caller: for an "unexpected_file"/"old_side_no_match"
       target, a trivially-matching old side (e.g. a one-line file whose
       entire content happens to equal the hunk's own old side) proves
       nothing about whether the edit belongs there at all, and
       "old_side_no_match" makes this priority a guaranteed no-op by
       construction anyway (see _locate_old_side_in_file).
    2/3. the first of `identifiers` (already ordered changed-line-first
       by the caller) that resolves via _lookup_identifier_definition,
       reused unchanged -- never all of them independently, which is
       what previously produced multiple, independently-padded, possibly
       disjoint blocks for one target file.
    4. for that resolved identifier: an enclosing unit small enough to
       include WHOLE (a sibling constant group sharing the same
       class_name -- _constant_group_bounds -- or, for a function, its
       own full body via _read_symbol_source/get_function_code) is
       preferred over a padded window; a window is still built when the
       enclosing unit is too large, clamped to never read past that
       unit's own bounds.
    5. (the caller's own fallback, not built here) a small, bounded
       full-file read via the existing build_final_target_slice.

    Returns None when nothing above resolves -- the caller then falls
    back to tier 5."""
    index = getattr(context, "index", None)
    if index is None:
        return None

    if try_old_side_anchor:
        old_side_span = _locate_old_side_in_file(file_hunks_for_file, verified_file, context)
        if old_side_span is not None:
            start, end = _padded_line_range(
                old_side_span[0], old_side_span[1], POST_PATCH_WINDOW_CONTEXT_LINES,
            )
            source = index.read_file_section(verified_file, start, end)
            if source:
                label = identifiers[0] if identifiers else verified_file
                return _PostPatchWindow(
                    file=verified_file, label=label,
                    target_start=old_side_span[0], target_end=old_side_span[1],
                    start=start, end=_rendered_end_line(start, source), source=source,
                    enclosing_symbol=None, source_kind="patch_ready_window",
                )

    for identifier in identifiers:
        match = _lookup_identifier_definition(identifier, [verified_file], context)
        if match is None:
            continue

        if match.kind == "function" and match.func_id:
            full_source = index.get_function_code(match.func_id)
            if full_source and len(full_source) <= _POST_PATCH_SMALL_ENCLOSING_UNIT_CHARS:
                return _PostPatchWindow(
                    file=verified_file, label=match.label,
                    target_start=match.line, target_end=match.end_line,
                    start=match.line, end=match.end_line, source=full_source,
                    enclosing_symbol=match.label, source_kind="enclosing_symbol",
                )
            # Large enclosing function -- a focused, bounded window
            # anchored at its own definition line, clamped to never
            # read past the function's own end (its enclosing bound).
            start = max(1, match.line - POST_PATCH_WINDOW_CONTEXT_LINES)
            end = min(match.end_line, match.line + POST_PATCH_WINDOW_CONTEXT_LINES) if match.end_line else start
            source = index.read_file_section(verified_file, start, end)
            if source:
                return _PostPatchWindow(
                    file=verified_file, label=match.label,
                    target_start=match.line, target_end=match.end_line,
                    start=start, end=_rendered_end_line(start, source), source=source,
                    enclosing_symbol=match.label, source_kind="patch_ready_window",
                )
            continue

        if match.kind == "constant" and match.end_line is not None:
            constants = getattr(context, "constants", None) or {}
            record = (constants.get(match.file) or {}).get(match.label)
            group_class = record.get("class_name") if record is not None else None
            group = _constant_group_bounds(match.file, group_class, context)

            if group is not None and group[2] > 1:
                g_start, g_end, _count = group
                whole_group_source = index.read_file_section(match.file, g_start, g_end)
                if whole_group_source and len(whole_group_source) <= _POST_PATCH_SMALL_ENCLOSING_UNIT_CHARS:
                    return _PostPatchWindow(
                        file=verified_file, label=match.label,
                        target_start=match.line, target_end=match.end_line,
                        start=g_start, end=_rendered_end_line(g_start, whole_group_source),
                        source=whole_group_source,
                        enclosing_symbol=group_class or verified_file, source_kind="enclosing_symbol",
                    )
                if whole_group_source:
                    # Group too large to include whole -- clamp the
                    # padded window to its own bounds rather than
                    # spilling into a different enclosing unit.
                    start = max(g_start, match.line - POST_PATCH_WINDOW_CONTEXT_LINES)
                    end = min(g_end, match.end_line + POST_PATCH_WINDOW_CONTEXT_LINES)
                    clamped_source = index.read_file_section(match.file, start, end)
                    if clamped_source:
                        return _PostPatchWindow(
                            file=verified_file, label=match.label,
                            target_start=match.line, target_end=match.end_line,
                            start=start, end=_rendered_end_line(start, clamped_source),
                            source=clamped_source,
                            enclosing_symbol=group_class or verified_file, source_kind="patch_ready_window",
                        )

            # No usable enclosing group -- bounded fallback (Required
            # behavior #5: "Use a bounded fallback when no enclosing
            # symbol is known").
            start, end = _padded_line_range(match.line, match.end_line, POST_PATCH_WINDOW_CONTEXT_LINES)
            source = index.read_file_section(match.file, start, end)
            if source:
                return _PostPatchWindow(
                    file=verified_file, label=match.label,
                    target_start=match.line, target_end=match.end_line,
                    start=start, end=_rendered_end_line(start, source), source=source,
                    enclosing_symbol=None, source_kind="patch_ready_window",
                )

    return None


def _window_confirms_target(
    window: _PostPatchWindow, identifiers: "list[str]", file_hunks_for_file: "list",
) -> bool:
    """Observational trace check only -- never a gate on whether
    `window` was already built. True when the window's own source text
    demonstrably contains what recovery was actually trying to recover:
    either the resolved identifier's own bare name, or (for an old-side-
    anchor match, which resolves no symbol) the hunk's own old-side
    anchors, verbatim and contiguous, inside `window.source` itself.
    Reuses old_side_anchors/find_unique_occurrence -- no second matching
    mechanism."""
    source_lines = window.source.splitlines()
    for hunk in file_hunks_for_file:
        anchors = old_side_anchors(hunk.lines)
        if anchors and find_unique_occurrence(anchors, source_lines) is not None:
            return True
    bare = window.label.rsplit(".", 1)[-1] if window.label else ""
    if bare and bare in window.source:
        return True
    return any(identifier and identifier in window.source for identifier in identifiers)


def _wrap_post_patch_window(window: _PostPatchWindow, verified_file: str) -> FinalTargetSliceResult:
    """Wrap one patch-ready recovery window into a minimal, single-block
    FinalTargetSliceResult -- the SAME shape build_final_target_slice
    itself returns, so _merge_slice_results (unmodified) folds it into
    the running slice exactly like any other addition, and
    recover_post_patch_source's own existing success check (`verified_
    file in current_slice.identifier_definition_covered`) recognizes it
    with no change to that check itself. Rendered via
    _render_definition_block -- the SAME header shape check_patch_
    target_conformance's own _edit_target_source_for_file already reads
    back as EDIT-TARGET-role content, so a subsequent regeneration
    re-check recognizes this window's code exactly like any other target
    definition, without needing a new header form."""
    text = _render_definition_block(window.file, window.label, window.start, window.end, window.source)
    return FinalTargetSliceResult(
        rendered=text, covered_target_files=[verified_file], covered_target_symbols=[],
        uncovered_target_files=[], uncovered_target_symbols=[],
        coverage_complete=False, has_any_coverage=True, warning_text="",
        resolved_target_symbols=[], full_file_fallback_covered=[],
        edit_target_budget_exhausted=False, resolved_symbol_files={},
        identifier_definition_covered=[verified_file],
    )


def _post_patch_fallback_source_kind(sniffed_kind: "str | None") -> "str | None":
    """Maps _sniff_rendered_kind's shared vocabulary (also used by
    Slices 2/3, never changed here) onto Slice 4's own, more precise
    trace vocabulary for its tier-5 full-file fallback only --
    "full_file_fallback" becomes "small_full_file" (Required behavior:
    "Use a source_kind that accurately reflects the final source").
    "exact_definition" is defensively relabelled too, though it should
    be unreachable here: this fallback's own `required_edits` names
    only identifiers _build_post_patch_window already tried and could
    not resolve, so its category 2 (which uses the identical lookup)
    cannot resolve them either -- the fallback's only reachable success
    mode is category 5 (full-file)."""
    if sniffed_kind == "full_file_fallback":
        return "small_full_file"
    if sniffed_kind == "exact_definition":
        return "patch_ready_window"
    return sniffed_kind


class RecoveryTargetAttempt(NamedTuple):
    """One deterministic recovery attempt for a single actual patch
    target (a file the generated diff edited but Edit Readiness never
    approved, or approved-file content that doesn't match verified
    source). `identifiers_considered` are extracted from the hunk's OWN
    old/new text (_extract_identifiers_from_text, reused), changed-line
    (+/-) identifiers ordered ahead of context-line (' ') ones -- the
    generated patch is used only as a retrieval HINT here, never as a
    source of trusted line numbers or content.

    `resolved_target`/`target_start_line`/`target_end_line` describe the
    underlying identifier/symbol/old-side match ITSELF (its own natural,
    unpadded span) -- `start_line`/`end_line` describe the FINAL window
    actually rendered, which may be wider (a padded window, a sibling
    constant group, an enclosing function) than the target's own span.
    `patch_ready` is True only when that final window is a single
    contiguous, verbatim, bounded block sufficient to build a unified
    diff against -- see _build_post_patch_window's module comment for
    exactly what that excludes. `identifier_verified_in_window` is a
    purely observational trace flag (_window_confirms_target) -- never a
    gate on `success` itself."""

    file: str
    trigger_reason: str
    identifiers_considered: "list[str]"
    resolved_file: "str | None"
    resolved_target: "str | None"
    target_start_line: "int | None"
    target_end_line: "int | None"
    start_line: "int | None"
    end_line: "int | None"
    enclosing_symbol: "str | None"
    source_kind: "str | None"
    source_chars: int
    patch_ready: bool
    identifier_verified_in_window: bool
    success: bool
    failure_reason: "str | None"


class PostPatchRecoveryResult(NamedTuple):
    """recover_post_patch_source()'s own output -- retrieval only, no LLM
    call. `slice_result` is the ORIGINAL slice extended additively with
    whatever this round retrieved (never evicting anything already
    present, exactly like Slices 2/3's own merge). `ready_for_regeneration`
    is True only when EVERY recovery target obtained genuine EDIT-TARGET-
    role source (never a partial subset) -- pipeline.py must not attempt
    regeneration otherwise (see recover_post_patch_source's docstring)."""

    triggered: bool
    trigger_reasons: "list[str]"
    recovery_targets: "list[str]"
    attempts: "list[RecoveryTargetAttempt]"
    slice_result: "FinalTargetSliceResult | None"
    ready_for_regeneration: bool
    failure_reason: "str | None"


_EMPTY_RECOVERY_RESULT_NOT_TRIGGERED = PostPatchRecoveryResult(
    triggered=False, trigger_reasons=[], recovery_targets=[], attempts=[],
    slice_result=None, ready_for_regeneration=False, failure_reason=None,
)


def recover_post_patch_source(
    strategy: RemediationStrategyResult,
    repo_root,
    context,
    slice_result: "FinalTargetSliceResult | None",
    conformance: PatchConformanceReport,
    patch: str,
    budget_controller: "ContextBudgetController | None" = None,
) -> PostPatchRecoveryResult:
    """
    Slice 4's deterministic, bounded post-patch source recovery. No LLM
    call anywhere in this function -- the actual regeneration call is
    orchestrated by pipeline.py itself, using this function's output only
    to decide whether attempting it is even warranted.

    Triggered only by post_patch_recovery_trigger_reasons(conformance)
    being non-empty (an unexpected file, an uncovered target, or an
    old-side no_match) -- never for unique_match, never for a patch whose
    targets are already covered, and never for ambiguous-old-side alone.
    Returns a not-triggered result (0 targets, `ready_for_regeneration`
    False, no failure) when there is nothing to recover, or when
    `repo_root`/`slice_result` is unavailable.

    Recovery targets are the union of unexpected/uncovered/no_match
    files, capped at MAX_RECOVERY_TARGETS (more than that fails closed
    immediately, before attempting anything -- "too many unexpected
    targets to safely recover from"). For each target file: the file
    itself is re-verified (_verify_file) -- an unsafe/unverifiable path
    fails that target outright; candidate identifiers are extracted from
    every hunk's own old/new text in that file (_extract_identifiers_from_text,
    reused, never a line number), changed-line identifiers ordered ahead
    of context-line ones so the identifier actually being edited is tried
    first.

    A SINGLE contiguous, patch-ready window is then built for the file
    (_build_post_patch_window) -- source priority: (1, only for
    "uncovered_target") the hunk's own old-side content located verbatim
    in the real file; (2/3/4) the first candidate identifier that
    resolves to a real definition, with its own small enclosing unit (a
    sibling constant group, or a small function) preferred whole over a
    padded window. This deliberately REPLACES the previous approach of
    feeding every extracted identifier into build_final_target_slice's
    own category 2 independently: that could -- and, per the real trace
    this fix addresses, did -- render several separately, narrowly
    (_DEFINITION_CONTEXT_LINES=3) padded blocks for nearby identifiers in
    one file, leaving the actual hunk's target sitting at the edge of, or
    between, two disjoint fragments rather than inside one buildable
    window, so the regenerated diff's own context lines failed
    relocation against the real file. Only when nothing resolves at all
    does this fall back to the pre-existing mechanism (build_final_
    target_slice, unmodified, tier 5: a small, bounded full-file read) --
    a target only "succeeds" via that tier when the retrieved block
    actually lands in `identifier_definition_covered`/`full_file_
    fallback_covered` for that file, exactly as before.

    A window that resolves but does not fit this target's remaining
    share of the budget fails closed as "target_budget_exhausted"
    immediately -- it is never silently replaced by a smaller, possibly
    insufficiently-padded block from the old mechanism, which would
    reintroduce exactly the under-context failure mode this function
    exists to prevent.

    `ready_for_regeneration` is True only when EVERY recovery target
    succeeded -- "Do not regenerate a patch from partial recovery
    evidence" is enforced here, not left to the caller.

    `budget_controller=None` (the default, and every existing caller)
    preserves this exact fixed-budget, fail-closed behavior unchanged.
    When given, a target blocked ONLY by this round's own
    MAX_POST_PATCH_SOURCE_CHARS total and/or the shared
    FINAL_TARGET_SLICE_MAX_CHARS ceiling (never by an unsafe path or
    genuine unresolvability) gets one immediate, local retry against
    whichever of the two pools the controller actually extends (see
    ContextBudgetController) -- never a second recovery round, never a
    rerun of the Planner/Final Strategy/Patch Generator.
    """
    reasons = post_patch_recovery_trigger_reasons(conformance)
    if not reasons or repo_root is None or slice_result is None:
        return _EMPTY_RECOVERY_RESULT_NOT_TRIGGERED

    root = Path(repo_root)
    target_files = sorted(
        set(conformance.unexpected_files) | set(conformance.uncovered_files) | set(conformance.no_match_files)
    )

    if len(target_files) > MAX_RECOVERY_TARGETS:
        return PostPatchRecoveryResult(
            triggered=True, trigger_reasons=reasons, recovery_targets=target_files,
            attempts=[], slice_result=slice_result, ready_for_regeneration=False,
            failure_reason="too_many_recovery_targets",
        )

    try:
        _changed_files, file_hunks = parse_diff(patch or "")
    except Exception:
        file_hunks = {}

    current_slice = slice_result
    attempts: "list[RecoveryTargetAttempt]" = []
    budget_remaining = MAX_POST_PATCH_SOURCE_CHARS

    def _extend_post_patch_budget(affected_file: str) -> bool:
        """Try, in order, to extend whichever pool(s) are actually
        binding for the CURRENT target -- this round's own
        "post_patch_recovery" pool first (the narrower one in practice),
        then the shared "final_target_slice" ceiling -- returning True
        if at least one extension was approved (the caller recomputes
        `available` immediately afterward). A no-op, always returning
        False, when `budget_controller` is None."""
        nonlocal budget_remaining
        if budget_controller is None:
            return False
        extended = False
        if budget_remaining <= 0 and budget_controller.request_extension(
            "post_patch_recovery", MAX_POST_PATCH_SOURCE_CHARS,
            reason="target_budget_exhausted", affected_targets=[affected_file],
        ):
            budget_remaining += MAX_POST_PATCH_SOURCE_CHARS
            extended = True
        if (_effective_final_target_max(budget_controller) - len(current_slice.rendered)) <= 0 and (
            budget_controller.request_extension(
                "final_target_slice", FINAL_TARGET_SLICE_MAX_CHARS,
                reason="target_budget_exhausted", affected_targets=[affected_file],
            )
        ):
            extended = True
        return extended

    for file in target_files:
        trigger_reason = _recovery_reason_for_file(file, conformance)
        verified_file = _verify_file(file, root)
        if verified_file is None:
            attempts.append(RecoveryTargetAttempt(
                file=file, trigger_reason=trigger_reason, identifiers_considered=[],
                resolved_file=None, resolved_target=None, target_start_line=None, target_end_line=None,
                start_line=None, end_line=None, enclosing_symbol=None, source_kind=None,
                source_chars=0, patch_ready=False, identifier_verified_in_window=False,
                success=False, failure_reason="unsafe_file_path",
            ))
            continue

        hunks_for_file = file_hunks.get(file, [])
        changed_identifiers: "list[str]" = []
        context_identifiers: "list[str]" = []
        seen_ids: set = set()
        for hunk in hunks_for_file:
            for line in hunk.lines:
                changed = line[:1] in ("+", "-")
                stripped = line[1:] if line[:1] in (" ", "+", "-") else line
                for tok in _extract_identifiers_from_text(stripped):
                    if tok in seen_ids:
                        continue
                    seen_ids.add(tok)
                    (changed_identifiers if changed else context_identifiers).append(tok)
        identifiers = changed_identifiers + context_identifiers

        total_remaining = _effective_final_target_max(budget_controller) - len(current_slice.rendered)
        available = min(budget_remaining, total_remaining)
        if budget_controller is not None:
            budget_controller.record_used("final_target_slice", len(current_slice.rendered))
        if available <= 0:
            if _extend_post_patch_budget(file):
                total_remaining = _effective_final_target_max(budget_controller) - len(current_slice.rendered)
                available = min(budget_remaining, total_remaining)
            if available <= 0:
                attempts.append(RecoveryTargetAttempt(
                    file=file, trigger_reason=trigger_reason, identifiers_considered=identifiers,
                    resolved_file=None, resolved_target=None, target_start_line=None, target_end_line=None,
                    start_line=None, end_line=None, enclosing_symbol=None, source_kind=None,
                    source_chars=0, patch_ready=False, identifier_verified_in_window=False,
                    success=False, failure_reason="target_budget_exhausted",
                ))
                continue

        window = _build_post_patch_window(
            verified_file, identifiers, hunks_for_file, context,
            try_old_side_anchor=(trigger_reason == "uncovered_target"),
        )

        if window is not None:
            rendered_text = _render_definition_block(window.file, window.label, window.start, window.end, window.source)
            if len(rendered_text) > available:
                if _extend_post_patch_budget(file):
                    total_remaining = _effective_final_target_max(budget_controller) - len(current_slice.rendered)
                    available = min(budget_remaining, total_remaining)
                if len(rendered_text) > available:
                    # Fails closed here rather than degrading to the tier-5
                    # fallback below with the SAME tiny budget: a smaller,
                    # less-padded block from that mechanism could "succeed"
                    # by its own (looser) criterion while still not being a
                    # sufficient patch-ready window -- exactly the failure
                    # mode this function exists to prevent.
                    attempts.append(RecoveryTargetAttempt(
                        file=file, trigger_reason=trigger_reason, identifiers_considered=identifiers,
                        resolved_file=None, resolved_target=window.label,
                        target_start_line=window.target_start, target_end_line=window.target_end,
                        start_line=None, end_line=None, enclosing_symbol=window.enclosing_symbol,
                        source_kind=None, source_chars=len(rendered_text),
                        patch_ready=False, identifier_verified_in_window=False,
                        success=False, failure_reason="target_budget_exhausted",
                    ))
                    continue

            addition = _wrap_post_patch_window(window, verified_file)
            current_slice = _merge_slice_results(current_slice, addition, strategy)
            budget_remaining = max(0, budget_remaining - len(rendered_text))
            attempts.append(RecoveryTargetAttempt(
                file=file, trigger_reason=trigger_reason, identifiers_considered=identifiers,
                resolved_file=verified_file, resolved_target=window.label,
                target_start_line=window.target_start, target_end_line=window.target_end,
                start_line=window.start, end_line=window.end, enclosing_symbol=window.enclosing_symbol,
                source_kind=window.source_kind, source_chars=len(rendered_text),
                patch_ready=True,
                identifier_verified_in_window=_window_confirms_target(window, identifiers, hunks_for_file),
                success=True, failure_reason=None,
            ))
            continue

        # Tier 5 (the only tier left): nothing resolved above at all --
        # fall back to the pre-existing mechanism, unmodified, as a small
        # bounded full-file read. Its own category 2 (identical
        # _lookup_identifier_definition lookup) cannot resolve anything
        # _build_post_patch_window did not already try and fail, so the
        # only reachable success here is category 5's full-file
        # fallback.
        focused = strategy._replace(
            target_files=[verified_file], target_symbols=[], required_edits=identifiers[:20],
        )
        addition = build_final_target_slice(
            focused, repo_root, context, planner_evidence_files=(), max_chars=available,
        )
        current_slice = _merge_slice_results(current_slice, addition, strategy)
        budget_remaining = max(0, budget_remaining - len(addition.rendered))

        succeeded = bool(addition.rendered) and (
            verified_file in current_slice.identifier_definition_covered
            or verified_file in current_slice.full_file_fallback_covered
        )

        failure_reason = None
        if not succeeded:
            # category 2/5 (the only categories a target_symbols=[]
            # focused strategy can ever use) don't feed
            # edit_target_budget_exhausted (that flag only tracks
            # categories 1/3b/4) -- so whether the ROUND's own smaller
            # `available` budget (rather than genuine unresolvability)
            # was the blocker is determined here, deterministically, by
            # re-probing the SAME focused strategy at the full effective
            # budget. The probe's own result is discarded either way --
            # never merged, never committed -- only used to pick the
            # honest reason (and, when a controller is given, to decide
            # whether an extension is even worth asking for).
            if available < _effective_final_target_max(budget_controller):
                probe = build_final_target_slice(focused, repo_root, context, planner_evidence_files=())
                probe_would_cover = bool(probe.rendered) and (
                    verified_file in probe.identifier_definition_covered
                    or verified_file in probe.full_file_fallback_covered
                )
                if probe_would_cover and _extend_post_patch_budget(file):
                    # Budget was confirmed to be the sole blocker AND an
                    # extension was approved -- retry the REAL build
                    # (never just the discarded probe) against the
                    # raised ceiling, exactly once.
                    total_remaining = _effective_final_target_max(budget_controller) - len(current_slice.rendered)
                    available = min(budget_remaining, total_remaining)
                    addition = build_final_target_slice(
                        focused, repo_root, context, planner_evidence_files=(), max_chars=available,
                    )
                    current_slice = _merge_slice_results(current_slice, addition, strategy)
                    budget_remaining = max(0, budget_remaining - len(addition.rendered))
                    succeeded = bool(addition.rendered) and (
                        verified_file in current_slice.identifier_definition_covered
                        or verified_file in current_slice.full_file_fallback_covered
                    )
                failure_reason = None if succeeded else ("target_budget_exhausted" if probe_would_cover else "missing_target_source")
            else:
                failure_reason = "missing_target_source"

        start, end, kind = None, None, None
        if addition.rendered:
            start, end = _sniff_rendered_lines(addition.rendered)
            kind = _post_patch_fallback_source_kind(_sniff_rendered_kind(addition.rendered))

        attempts.append(RecoveryTargetAttempt(
            file=file, trigger_reason=trigger_reason, identifiers_considered=identifiers,
            resolved_file=verified_file if succeeded else None, resolved_target=None,
            target_start_line=None, target_end_line=None,
            start_line=start, end_line=end, enclosing_symbol=None,
            source_kind=kind, source_chars=len(addition.rendered),
            patch_ready=succeeded, identifier_verified_in_window=False,
            success=succeeded, failure_reason=failure_reason,
        ))

    all_succeeded = bool(attempts) and all(a.success for a in attempts)
    return PostPatchRecoveryResult(
        triggered=True, trigger_reasons=reasons, recovery_targets=target_files,
        attempts=attempts, slice_result=current_slice,
        ready_for_regeneration=all_succeeded,
        failure_reason=None if all_succeeded else "partial_recovery_evidence",
    )


def build_post_patch_recovery_hint(
    conformance: PatchConformanceReport, recovery: PostPatchRecoveryResult, failed_patch: str,
) -> str:
    """Deterministic retry instruction for the ONE bounded regeneration
    call (generate_patch, called by pipeline.py itself -- this function
    only builds the text). States exactly which file(s) failed and why,
    that the now-available verified source above must be copied
    verbatim, and that the same intended fix must be preserved without
    introducing unrelated edits -- never repository-specific wording, no
    vulnerability-family rules."""
    lines = ["The previous patch edited repository content that could not be verified:"]
    for f in conformance.unexpected_files:
        lines.append(f"- `{f}` was not an approved edit target for this vulnerability.")
    for f in conformance.uncovered_files:
        lines.append(f"- `{f}` was edited, but the specific content changed there did not match verified evidence.")
    for f in conformance.no_match_files:
        lines.append(f"- `{f}`'s removed/context lines could not be found anywhere in the repository (no_match).")
    lines.append("")
    lines.append(
        "Exact, verified repository source for the actual target(s) is now included in the "
        "repository code context above. Regenerate the patch using ONLY that verified source:"
    )
    lines.append("- Every old-side (context and removed) line in the new diff must be copied verbatim from the verified source above.")
    lines.append("- Do not invent a line number or any content that is not shown above.")
    lines.append("- Preserve the same intended security fix -- do not change what the fix does, only anchor it to real repository text.")
    lines.append("- Do not introduce edits to any file or symbol other than what the verified source above covers.")
    lines.append("- Return only the smallest patch necessary.")
    if failed_patch and failed_patch.strip():
        lines.append("")
        lines.append("The previous (unverified) attempt, shown only to identify the intended semantic edit:")
        lines.append(f"```diff\n{failed_patch.strip()}\n```")
    return "\n".join(lines)
