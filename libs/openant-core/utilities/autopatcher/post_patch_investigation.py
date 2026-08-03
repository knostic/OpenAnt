"""Pre-Patch Anchor Derivation.

Phase 2 of Post-Patch Vulnerability Investigation: converts already-computed,
deterministic pre-patch evidence (``RepositoryUnderstanding``, built by
``evidence_fusion.py`` from ``candidate_enrichment.py``'s
``CandidateEnrichment``) into a small set of atomic, typed ``Anchor``
objects -- stable facts that a later phase can re-resolve against an
isolated, patched copy of the repository.

``derive_pre_patch_anchors()`` is a pure function: ``RepositoryUnderstanding``
in, ``list[Anchor]`` out. No patch application, no post-patch comparison, no
repository reads, no parsing, no LLM calls, no mutation of its input, and no
``repo_root`` parameter -- this phase is deliberately independent of any
external repository input, reading only fields ``evidence_fusion.py`` /
``candidate_enrichment.py`` already computed.

Anchors record OBSERVATIONS, not expectations: no anchor claims a
remediation direction, a verdict, or a confidence score. Whether a later
observed change is consistent with a fix is entirely a downstream
consumer's responsibility (a later Post-Patch evaluation phase, Trust
Signals, Trust Report) -- never this module's.

Anchor kinds derived now, one Anchor per atomic fact:
  resolved_function -- identity of the function resolved near a
                        candidate's strongest grounding evidence
  call_edge          -- one structural caller->callee edge (from
                        candidate_enrichment.callees /
                        callers_by_call_graph only -- never
                        callers_by_text_search, and never re-derived from
                        evidence_fusion.relationships, which is already a
                        strict subset of the same raw fields and would
                        only produce duplicate anchors)
  reachability       -- reachability of a resolved function from any
                        entry point, honestly distinguishing True/False/
                        unresolved (None)
  sink_match         -- one existing vulnerability-pattern sink match,
                        never claimed to BE the vulnerability
  constant_value     -- the canonicalized value of one module-level or
                        class-level literal assignment in scope for a
                        candidate (see candidate_enrichment.scope_constants);
                        only entries whose value was actually captured
                        ("literal" outcome) become an anchor -- a
                        non-literal RHS produces no anchor, never a guess

Anchor kinds deliberately NOT derived here:
  related_test -- CandidateEnrichment.related_tests[].path is already an
                  ABSOLUTE, resolved path (testing_support.tests_for_file()
                  calls `str(t.resolve())`), computed using the repo_root
                  the original pipeline run had at enrichment time. A
                  stable, repo-relative key -- one that would still
                  resolve correctly against a *different* workspace root
                  in a later evaluation phase -- cannot be built from
                  RepositoryUnderstanding alone; there is no other field
                  carrying a repo-relative form of the test path. Rather
                  than accept a repo_root parameter here (which would
                  break this phase's "pure RepositoryUnderstanding ->
                  Anchors" contract), this anchor kind is deferred to
                  whichever later phase already has repo_root as a
                  required input (the post-patch evaluation phase, which
                  needs it anyway to build/apply against an isolated
                  copy). The root cause -- tests_for_file() returning
                  absolute rather than repo-relative paths -- belongs to
                  a separate, small future fix in testing_support.py /
                  candidate_enrichment.py, not to this module.
  diff_touches_function, diff_adds_test_path -- both require the
                  generated patch's text, which does not exist yet at
                  Repository Understanding time (Repository Understanding
                  runs strictly before Patch Generation in the pipeline).
                  Deferred to a later, separate post-generation derivation
                  step.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, NamedTuple, Union

from utilities.autopatcher.evidence_fusion import RepositoryUnderstanding
from utilities.autopatcher.repository_grounding_models import CandidateEnrichment

# ---------------------------------------------------------------------------
# Typed key/value shapes, one pair per anchor kind. Flat NamedTuples -- no
# inheritance, no per-kind behavior, just a compact, immutable,
# self-documenting alternative to an untyped dict. call_edge's before_value
# is the bare literal True (see CallEdgeKey usage below): every call_edge
# anchor is, by construction, only ever derived for an edge that currently
# exists, so a value wrapper would carry no information beyond the type
# itself.
# ---------------------------------------------------------------------------


class ResolvedFunctionKey(NamedTuple):
    """Identity of a resolved function. No content/body hash is included:
    CandidateEnrichment.resolved_function carries no source text (only
    RepositoryIndex.search_by_name()/search_usages() results do, and
    enrichment never stores those) -- func_id/name/class_name/unit_type is
    the most stable, line-number-independent identity available without
    adding a file read to this pure-transformation phase."""

    func_id: str
    name: "str | None"
    class_name: "str | None"
    unit_type: "str | None"


class ResolvedFunctionValue(NamedTuple):
    """Supporting positional metadata only -- never part of identity, since
    line ranges shift for reasons unrelated to a function's semantic
    identity (e.g. an earlier function in the same file growing/shrinking)."""

    start_line: "int | None"
    end_line: "int | None"


class CallEdgeKey(NamedTuple):
    caller_func_id: str
    callee_func_id: str


class ReachabilityKey(NamedTuple):
    func_id: str


class ReachabilityValue(NamedTuple):
    """`reachable` is honestly tri-state: True, False, or None (unresolved
    -- e.g. an enrichment exception fired after resolving the function but
    before reachability could be computed). `entry_point_path` is a tuple,
    not a list, so this NamedTuple (and therefore the whole Anchor) stays
    hashable."""

    reachable: "bool | None"
    entry_point_path: "tuple[str, ...] | None"


class SinkMatchKey(NamedTuple):
    candidate_path: str
    method: "str | None"  # None = module-level, matches vulnerability_patterns.py's own convention


class SinkMatchValue(NamedTuple):
    line: int
    snippet: str


class ConstantValueKey(NamedTuple):
    """Identity of one module-level or class-level literal assignment
    target. ``const_id`` follows RepositoryIndex's own func_id convention
    ("file/path.py:name" or "file/path.py:ClassName.name" -- see
    repository_index.py's own comment on that format) so identity is
    self-contained, independent of the sibling Anchor.candidate_path
    field, exactly like every other anchor kind's key."""

    const_id: str
    qualified_name: str  # "name" at module scope, "ClassName.name" at class scope
    class_name: "str | None"


class ConstantValueValue(NamedTuple):
    """The literal's canonicalized, hashable value (see
    candidate_enrichment._canonicalize_literal -- raw set/list/dict are not
    hashable and would break Anchor's frozen/hashable contract).
    ``ast_literal_kind`` disambiguates literal shapes that could
    canonicalize to the same value (e.g. a set literal vs. a list literal
    with identical elements, or a plain ``set(...)`` vs. a ``frozenset``
    literal)."""

    ast_literal_kind: "str | None"
    value: object


AnchorKind = Literal["resolved_function", "call_edge", "reachability", "sink_match", "constant_value"]

AnchorKey = Union[ResolvedFunctionKey, CallEdgeKey, ReachabilityKey, SinkMatchKey, ConstantValueKey]
AnchorValue = Union[ResolvedFunctionValue, bool, ReachabilityValue, SinkMatchValue, ConstantValueValue]

AnchorOrigin = Literal["pre_patch", "patch_touched"]
"""Which phase decided this Anchor was worth tracking -- never part of
semantic identity or deduplication (see Anchor's docstring: identity is
strictly `(kind, key)`). ``"pre_patch"`` (the default): derived by
``derive_pre_patch_anchors()`` from selected-candidate evidence, before the
patch exists. ``"patch_touched"``: derived by
``post_patch_evaluation.derive_patch_touched_anchors()`` from the final
patch's own diff, independent of Candidate Selection -- for a semantic
element the patch touches but no selected candidate ever surfaced."""


@dataclass(frozen=True)
class Anchor:
    """One atomic, deterministic observation -- either selected before the
    patch existed (``origin="pre_patch"``), or discovered because the
    final patch touched this location (``origin="patch_touched"``).

    Contains only: a stable identity (kind + key), the deterministic
    before_value, and provenance (source, origin) -- never a complete
    RepositoryCandidate/CandidateEnrichment/RepositoryUnderstanding, never
    an expected remediation direction, never a verdict or confidence
    score.

    Semantic identity is the pair ``(kind, key)`` -- not `key` alone, and
    NOT including `origin` (two anchors with the same (kind, key) are the
    same fact regardless of which phase found it first; origin is
    provenance metadata, never a dedup axis -- see
    ``derive_pre_patch_anchors``'s and ``derive_patch_touched_anchors``'s
    own dedup, both keyed strictly on `(kind, key)`).
    `NamedTuple` equality/hash ignore the declared subclass (they inherit
    `tuple.__eq__`/`__hash__`, which compare positionally), so two
    different anchor kinds whose key shapes happen to share a field count
    and matching values would silently compare equal as plain tuples
    (verified: ``CallEdgeKey("auth.py", "authenticate") ==
    SinkMatchKey("auth.py", "authenticate")`` is ``True``). Including
    `kind` in the identity is what disambiguates that. There is no stored
    `id` field: it would either duplicate `(kind, key)` (redundant, two
    sources of truth that could drift) or, if built by string
    concatenation, risk its own collision when a field value contains the
    separator. `display_id` below is computed on demand instead.

    All fields are hashable (str/Literal/NamedTuple-of-hashables), so
    Anchor itself is hashable and immutable (frozen).
    """

    kind: AnchorKind
    candidate_path: str
    key: AnchorKey
    before_value: AnchorValue
    source: str
    origin: AnchorOrigin = "pre_patch"

    @property
    def display_id(self) -> str:
        """Human-readable string for rendering, logs, and test assertions
        only -- NOT the semantic identity (see class docstring; use
        `(anchor.kind, anchor.key)` for that). Computed on demand from
        `kind`/`key` so it can never drift out of sync with them."""
        if self.kind == "resolved_function":
            return f"resolved_function:{self.key.func_id}"
        if self.kind == "call_edge":
            return f"call_edge:{self.key.caller_func_id}->{self.key.callee_func_id}"
        if self.kind == "reachability":
            return f"reachability:{self.key.func_id}"
        if self.kind == "sink_match":
            method_label = self.key.method or "<module>"
            return f"sink_match:{self.key.candidate_path}:{method_label}"
        if self.kind == "constant_value":
            return f"constant_value:{self.key.const_id}"
        return f"{self.kind}:{self.key!r}"  # defensive fallback; unreachable given AnchorKind


def _file_part(func_id: str) -> str:
    """Extract the file portion of a func_id (``"file/path.py:funcName"``
    -> ``"file/path.py"``), matching RepositoryIndex._build_index's own
    convention (split on the last colon). Reimplemented locally --
    evidence_fusion._file_part is private to that module."""
    colon_idx = func_id.rfind(":")
    if colon_idx <= 0:
        return func_id
    return func_id[:colon_idx]


def resolved_function_anchor(
    candidate_path: str, resolved: dict, func_id: str, origin: AnchorOrigin = "pre_patch"
) -> Anchor:
    """Build a ``resolved_function`` Anchor from a RepositoryIndex-shaped
    function dict (the exact shape ``list_functions_in_file``/
    ``get_function`` already return: name/startLine/endLine/unitType/
    className). Exported (no leading underscore): shared by
    derive_pre_patch_anchors below and
    post_patch_evaluation.derive_patch_touched_anchors -- the only
    difference between a pre-patch and a patch-touched resolved_function
    Anchor is which `origin` the caller passes."""
    key = ResolvedFunctionKey(
        func_id=func_id,
        name=resolved.get("name"),
        class_name=resolved.get("className"),
        unit_type=resolved.get("unitType"),
    )
    value = ResolvedFunctionValue(
        start_line=resolved.get("startLine"),
        end_line=resolved.get("endLine"),
    )
    return Anchor(
        kind="resolved_function",
        candidate_path=candidate_path,
        key=key,
        before_value=value,
        source="candidate_enrichment.resolved_function",
        origin=origin,
    )


def _call_edge_anchor(caller_func_id: str, callee_func_id: str, source: str) -> Anchor:
    """`candidate_path` is always the CALLER's file -- computed the same
    way regardless of whether this edge was discovered via the calling
    candidate's `callees` or the called candidate's `callers_by_call_graph`,
    so a deduplicated anchor's candidate_path never depends on which
    candidate happened to be processed first."""
    return Anchor(
        kind="call_edge",
        candidate_path=_file_part(caller_func_id),
        key=CallEdgeKey(caller_func_id=caller_func_id, callee_func_id=callee_func_id),
        before_value=True,
        source=source,
    )


def _reachability_anchor(candidate_path: str, func_id: str, enrichment: CandidateEnrichment) -> Anchor:
    path = enrichment.entry_point_path
    value = ReachabilityValue(
        reachable=enrichment.is_reachable_from_entry_point,
        entry_point_path=tuple(path) if path else None,
    )
    return Anchor(
        kind="reachability",
        candidate_path=candidate_path,
        key=ReachabilityKey(func_id=func_id),
        before_value=value,
        source="candidate_enrichment.is_reachable_from_entry_point",
    )


def _sink_match_anchor(candidate_path: str, sink: dict) -> Anchor:
    method = sink.get("method")
    return Anchor(
        kind="sink_match",
        candidate_path=candidate_path,
        key=SinkMatchKey(candidate_path=candidate_path, method=method),
        before_value=SinkMatchValue(line=sink.get("line"), snippet=sink.get("snippet", "")),
        source="candidate_enrichment.sink_matches",
    )


def const_id(candidate_path: str, qualified_name: str) -> str:
    """Build a constant's identity string using the exact same
    "file:qualified_name" convention RepositoryIndex uses for func_id
    (see repository_index.py's own comment on that format), so a
    constant_value anchor's identity is self-contained and directly
    comparable to a func_id string wherever both need to be joined.

    Exported (no leading underscore): shared by derive_pre_patch_anchors
    below and post_patch_evaluation.derive_patch_touched_anchors, so both
    phases build identical, joinable identities without duplicating this
    one-line format."""
    return f"{candidate_path}:{qualified_name}"


def constant_value_anchor(candidate_path: str, entry: dict, origin: AnchorOrigin = "pre_patch") -> Anchor:
    """Build a ``constant_value`` Anchor from one ``scope_constants``-shaped
    entry (see candidate_enrichment._extract_literal_constants for the
    exact dict shape). Exported (no leading underscore): shared by
    derive_pre_patch_anchors below and
    post_patch_evaluation.derive_patch_touched_anchors -- the only
    difference between a pre-patch and a patch-touched constant_value
    Anchor is which `origin` the caller passes; the construction itself
    is identical."""
    cid = const_id(candidate_path, entry["qualified_name"])
    key = ConstantValueKey(
        const_id=cid,
        qualified_name=entry["qualified_name"],
        class_name=entry["class_name"],
    )
    value = ConstantValueValue(ast_literal_kind=entry["ast_literal_kind"], value=entry["value"])
    return Anchor(
        kind="constant_value",
        candidate_path=candidate_path,
        key=key,
        before_value=value,
        source="candidate_enrichment.scope_constants",
        origin=origin,
    )


def derive_pre_patch_anchors(understanding: RepositoryUnderstanding) -> list[Anchor]:
    """Derive atomic, deterministic anchors from already-computed pre-patch
    evidence.

    Pure and deterministic: no I/O, no parsing, no repository reads, no
    patch reads, no LLM calls, no mutation of `understanding` or anything
    it references, no `repo_root` parameter. Candidate order and each
    per-candidate list's existing order are preserved from the input --
    nothing is re-sorted. Duplicate facts (the same call edge surfacing
    from both endpoints' enrichment) collapse to one anchor via a single
    `(kind, key)`-keyed dedup pass -- not `key` alone (see Anchor's
    docstring for why) and not a formatted id string. Membership uses a
    set, but the returned list is only ever built by appending in scan
    order, never by iterating a set or dict, so output order stays
    reproducible across separate process runs (str hashing/set iteration
    order is not guaranteed stable across runs, only within one).
    """
    anchors: list[Anchor] = []
    seen_identities: "set[tuple[AnchorKind, AnchorKey]]" = set()

    def _add(anchor: Anchor) -> None:
        identity = (anchor.kind, anchor.key)
        if identity not in seen_identities:
            seen_identities.add(identity)
            anchors.append(anchor)

    for candidate in understanding.candidate_evidence:
        enrichment = candidate.enrichment
        if enrichment is None:
            continue

        resolved = enrichment.resolved_function
        if resolved is not None:
            func_id = resolved["id"]

            _add(resolved_function_anchor(candidate.path, resolved, func_id))

            for callee_id in enrichment.callees:
                _add(_call_edge_anchor(func_id, callee_id, "candidate_enrichment.callees"))

            for caller_id in enrichment.callers_by_call_graph:
                _add(_call_edge_anchor(caller_id, func_id, "candidate_enrichment.callers_by_call_graph"))

            _add(_reachability_anchor(candidate.path, func_id, enrichment))

        # sink_matches does not depend on resolved_function -- it's computed
        # independently in candidate_enrichment._enrich_one, so it must be
        # derived here regardless of whether a function was resolved.
        if enrichment.sink_matches:
            for sink in enrichment.sink_matches:
                _add(_sink_match_anchor(candidate.path, sink))

        # scope_constants, like sink_matches, does not depend on
        # resolved_function -- candidate_enrichment already scoped it
        # (module-level always; class-level narrowed to resolved_function's
        # own class when one was resolved, else left unnarrowed). Only
        # entries with a captured literal value become anchors -- a
        # "non_literal"/"augmented_assign"/etc. entry has no comparable
        # before_value and is silently excluded here, never guessed.
        for entry in enrichment.scope_constants:
            if entry.get("outcome") != "literal":
                continue
            _add(constant_value_anchor(candidate.path, entry))

    return anchors
