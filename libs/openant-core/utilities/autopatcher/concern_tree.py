"""
Experimental, standalone recursive evidence-backed concern resolver.

STATUS: EXPERIMENTAL. Not wired into production Challenger or the pipeline.
Nothing in `patch_challenger.py` or `pipeline.py` imports from this module,
and this module never imports FROM `pipeline.py` -- only from lower-level,
already-production-validated primitives (`remediation_planner.py`,
`technical_capacity.py`, `llm_client.py`, and `patch_challenger.py`'s own
provenance helpers, reused verbatim, never reimplemented).

Hypothesis under test (see the architecture reviews this module implements):
recursive decomposition + explicit evidence gathering + smaller evidence-
backed semantic decisions + fail-closed uncertainty may produce more stable
Challenger resolutions than one large semantic jump, while remaining generic
across remediation mechanisms. This module contains NO mechanism-specific
vocabulary (no "guard", "transformation", "parser", etc.) -- the exact same
generic evaluator is used at every node, at every depth, for every concern.

This is explicitly NOT a deterministic semantic-proof system. What IS
deterministic here: response-shape validation, provenance/citation
validation (reusing `patch_challenger._point_citation_valid` unchanged),
evidence-request validation and resolution (reusing
`remediation_planner.py`'s existing primitives unchanged), deduplication,
recursion/resource limits, no-progress detection, and fail-closed
termination. What is NOT deterministic: whether a decomposition is
semantically complete, whether a cited passage really establishes what the
model claims, and whether a parent's reconsideration genuinely follows from
its children's results. See the architecture reviews for the full analysis
of why this boundary cannot be moved further without either reintroducing
free-form LLM judgment or a mechanism-specific taxonomy -- both explicitly
out of scope for this experiment.

Authority boundary: node evaluation NEVER receives `vulnerability_text`.
Only repository evidence (`code_context`/`patch`/acquired source) is ever
passed to the evaluator or checked as a citation source. Scope/override
authority (`vulnerability_text`) remains entirely outside this module, to
be applied by an existing, unmodified caller AFTER a root verdict is
produced -- this module never attempts that step itself.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Tuple

from .remediation_planner import (
    PlanningEvidenceRequest,
    _validate_planning_request_schema,
    _resolve_planning_evidence_request,
    _planning_request_key,
    _resolve_guided_symbol,
    _read_symbol_source,
    _render_source_excerpt,
)
from .patch_challenger import _point_citation_valid, _normalize_for_provenance
from .technical_capacity import compute_source_capacity

_PROMPT_PATH = Path(__file__).parent / "prompts" / "concern_tree_evaluator.md"

ACTIONS = ("PROVEN", "REFUTED", "DECOMPOSE", "REQUEST_EVIDENCE", "UNRESOLVED")
"""The only five actions one evaluation call may return -- mutually
exclusive, no mechanism-specific action ever added. `INVALID` (see
`_parse_action`) is a SIXTH, purely internal outcome for a response that
does not cleanly match exactly one of these five -- never surfaced to a
caller as if it were a legitimate sixth action; it always demotes to
UNRESOLVED(invalid_output)."""

TERMINAL_STATUSES = ("PROVEN", "REFUTED", "UNRESOLVED")

REQUEST_TYPES = ("file_source", "symbol_definition")

# ---------------------------------------------------------------------------
# Conservative MVP limits. Every one of these, once exhausted, produces
# UNRESOLVED with an explicit, distinct reason -- never a guess. See module
# docstring: these are the ENTIRE deterministic-guarantee surface this
# module offers beyond citation validation.
# ---------------------------------------------------------------------------
MAX_DEPTH = 3
MAX_CHILDREN_PER_DECOMPOSITION = 4
MAX_TOTAL_NODES_PER_ROOT = 12
MAX_EVIDENCE_REQUESTS_PER_NODE = 2
MAX_ACQUISITION_ROUNDS_PER_NODE = 2
MAX_SEMANTIC_EVALUATIONS_PER_NODE = 3


class Limits(NamedTuple):
    """All MVP bounds in one place, overridable per call (tests use small
    values to exercise limit-exhaustion paths without needing large
    fixtures) -- production/experimental callers use the module-level
    defaults above."""
    max_depth: int = MAX_DEPTH
    max_children_per_decomposition: int = MAX_CHILDREN_PER_DECOMPOSITION
    max_total_nodes_per_root: int = MAX_TOTAL_NODES_PER_ROOT
    max_evidence_requests_per_node: int = MAX_EVIDENCE_REQUESTS_PER_NODE
    max_acquisition_rounds_per_node: int = MAX_ACQUISITION_ROUNDS_PER_NODE
    max_semantic_evaluations_per_node: int = MAX_SEMANTIC_EVALUATIONS_PER_NODE


# ---------------------------------------------------------------------------
# Evaluator action parsing -- deterministic SHAPE validation only. Never a
# semantic check (see module docstring): this parses and validates that a
# response IS one well-formed action of the five, not that its content is
# correct.
# ---------------------------------------------------------------------------

class EvaluatorAction(NamedTuple):
    kind: str  # one of ACTIONS, or "INVALID"
    rationale: str = ""
    citations: "Tuple[str, ...]" = ()
    children: "Tuple[str, ...]" = ()
    request: "Optional[PlanningEvidenceRequest]" = None
    reason: "Optional[str]" = None
    invalid_detail: "Optional[str]" = None
    # PROVEN/REFUTED only -- the generic adversarial terminal-verdict check
    # (see module docstring's terminal-leaf section). Freeform semantic
    # text, deterministically required to be NON-EMPTY (structural gate
    # only, see `parse_action`) -- never inspected for content here or
    # anywhere else in this module. No mechanism-specific field of any
    # kind (no "control_flow_complete", no "guard_check", etc.).
    necessary_conditions: "Tuple[str, ...]" = ()
    evidence_conflict_check: "Tuple[str, ...]" = ()


_ACTION_LINE_RE = re.compile(r"^[ \t]*Action:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_FIELD_RE_TEMPLATE = r"^[ \t]*{label}:\s*(.+?)\s*$"
_BULLET_RE = re.compile(r"^[ \t]*[-*+]\s*(.+?)\s*$")


def _extract_field(text: str, label: str) -> "Optional[str]":
    m = re.search(_FIELD_RE_TEMPLATE.format(label=re.escape(label)), text, re.IGNORECASE | re.MULTILINE)
    return m.group(1).strip() if m else None


def _extract_bulleted_section(text: str, heading: str) -> "List[str]":
    """Lines under a `<heading>:` line, up to the next recognized field/
    heading or end of text -- mirrors `patch_challenger._lines_from_bullets`'s
    own bullet-stripping discipline (reused conceptually, not imported,
    since this module's response shape is a single block, not a numbered
    multi-concern body)."""
    m = re.search(rf"^[ \t]*{re.escape(heading)}:\s*$", text, re.IGNORECASE | re.MULTILINE)
    if not m:
        return []
    rest = text[m.end():]
    lines: "List[str]" = []
    for line in rest.splitlines():
        if not line.strip():
            continue
        bullet_match = _BULLET_RE.match(line)
        if bullet_match:
            lines.append(bullet_match.group(1).strip())
            continue
        # Stop at the next top-level "Label:" line (any recognized or
        # unrecognized field) -- never accidentally consumes a later
        # section's own bulleted content.
        if re.match(r"^[ \t]*[A-Za-z][A-Za-z _]*:\s*", line):
            break
        lines.append(line.strip())
    return lines


def parse_action(raw: str) -> EvaluatorAction:
    """Parse ONE evaluator response into exactly one `EvaluatorAction`.
    Never raises, never silently repairs ambiguous output (see module
    docstring's provenance section): a response with zero or more than one
    `Action:` line, an unrecognized action value, or missing required
    fields for its own declared action, is `kind="INVALID"` -- the
    controller demotes this to UNRESOLVED(invalid_output), exactly like
    every other fail-closed gate in this module."""
    action_lines = _ACTION_LINE_RE.findall(raw or "")
    if len(action_lines) != 1:
        return EvaluatorAction(kind="INVALID", invalid_detail="missing_or_multiple_action_lines")
    kind = action_lines[0].strip().upper()
    if kind not in ACTIONS:
        return EvaluatorAction(kind="INVALID", invalid_detail="unrecognized_action")

    rationale = _extract_field(raw, "Rationale") or ""

    if kind in ("PROVEN", "REFUTED"):
        citations = tuple(_extract_bulleted_section(raw, "Citations"))
        if not rationale or not citations:
            return EvaluatorAction(kind="INVALID", invalid_detail="missing_rationale_or_citations")
        # Generic adversarial terminal-verdict check -- deterministic SHAPE
        # gate only (non-empty), never a semantic judgment of content (see
        # module docstring). A PROVEN/REFUTED response that skips either
        # section is exactly as malformed as one missing Citations, and
        # demotes the same way: INVALID -> UNRESOLVED(invalid_output).
        necessary_conditions = tuple(_extract_bulleted_section(raw, "Necessary conditions"))
        if not necessary_conditions:
            return EvaluatorAction(kind="INVALID", invalid_detail="missing_necessary_conditions")
        evidence_conflict_check = tuple(_extract_bulleted_section(raw, "Evidence conflict check"))
        if not evidence_conflict_check:
            return EvaluatorAction(kind="INVALID", invalid_detail="missing_evidence_conflict_check")
        return EvaluatorAction(
            kind=kind, rationale=rationale, citations=citations,
            necessary_conditions=necessary_conditions, evidence_conflict_check=evidence_conflict_check,
        )

    if kind == "DECOMPOSE":
        children = tuple(_extract_bulleted_section(raw, "Children"))
        if not rationale or not children:
            return EvaluatorAction(kind="INVALID", invalid_detail="missing_rationale_or_children")
        return EvaluatorAction(kind=kind, rationale=rationale, children=children)

    if kind == "REQUEST_EVIDENCE":
        request_type = _extract_field(raw, "Request type")
        file_hint = _extract_field(raw, "File hint")
        symbol = _extract_field(raw, "Symbol")
        if not rationale or request_type not in REQUEST_TYPES:
            return EvaluatorAction(kind="INVALID", invalid_detail="missing_rationale_or_request_type")
        file_hint = None if not file_hint or file_hint.strip().lower() in ("none", "n/a") else file_hint.strip()
        symbol = None if not symbol or symbol.strip().lower() in ("none", "n/a") else symbol.strip()
        request = PlanningEvidenceRequest(
            request_type=request_type, file_hint=file_hint, symbol=symbol, reason=rationale,
        )
        return EvaluatorAction(kind=kind, rationale=rationale, request=request)

    # UNRESOLVED
    reason = _extract_field(raw, "Reason")
    if not reason:
        return EvaluatorAction(kind="INVALID", invalid_detail="missing_reason")
    return EvaluatorAction(kind=kind, rationale=rationale, reason=reason)


# ---------------------------------------------------------------------------
# Evidence pool -- one per root concern, monotonically growing, shared by
# every node in that root's tree. See module docstring: no per-child
# pruning, reused whole-block-or-omit capacity discipline instead of
# semantic evidence selection.
# ---------------------------------------------------------------------------

class EvidencePool:
    """`code_context`/`patch` are the ORIGINAL, fixed Challenger evidence --
    never mutated. `acquired_blocks` grows monotonically as nodes acquire
    new evidence; a label already in `included_labels` is never re-added
    (the SAME dedup discipline `_merge_planner_evidence_results` already
    uses elsewhere), and a block that does not fit the remaining technical
    capacity is never partially included -- omitted whole, exactly like
    every other whole-block-or-omit renderer in this codebase."""

    def __init__(self, code_context: str, patch: str):
        self.code_context = code_context or ""
        self.patch = patch or ""
        self.acquired_blocks: "List[Tuple[str, str]]" = []  # (label, text)
        self.included_labels: "set" = set()

    def sources(self) -> "Tuple[str, ...]":
        """The complete set of citation-eligible sources -- NEVER includes
        `vulnerability_text` (see module docstring's authority-boundary
        section; this class has no parameter for it and never will)."""
        acquired_text = "\n\n".join(text for _label, text in self.acquired_blocks)
        return (self.code_context, self.patch, acquired_text)

    def rendered_for_prompt(self) -> str:
        parts = [p for p in (self.code_context, "\n\n".join(t for _l, t in self.acquired_blocks)) if p.strip()]
        return "\n\n".join(parts)

    def try_merge(self, label: str, text: str, *, provider, model, known_overhead_chars: int) -> "Tuple[bool, str]":
        """Attempt to merge one newly-resolved evidence block. Returns
        `(progressed, outcome)`: `progressed=True` only when this call
        actually grew the pool with genuinely new content -- a label
        already present, or one that does not fit the remaining technical
        capacity, both return `progressed=False` (never partially
        included) with a distinct `outcome` tag for tracing, mirroring
        `technical_capacity`'s existing omission-reason discipline."""
        if label in self.included_labels:
            return False, "already_present"
        capacity = compute_source_capacity(
            provider, model, reserved_output_tokens=1, known_overhead_chars=known_overhead_chars,
        )
        remaining = capacity.source_capacity_chars - sum(len(t) for _l, t in self.acquired_blocks)
        if remaining <= 0 or len(text) > remaining:
            return False, "technical_capacity"
        self.acquired_blocks.append((label, text))
        self.included_labels.add(label)
        return True, "merged"


def _resolve_evidence_source(
    request: PlanningEvidenceRequest, repo_root, investigation_context,
) -> "Tuple[Optional[str], Optional[str], Optional[str]]":
    """(label, rendered_text, failure_reason) for one already schema-valid
    request -- thin adapter over `remediation_planner.py`'s own resolution
    + rendering primitives, reused verbatim (mirrors
    `pipeline._render_calibration_evidence_block` exactly, reimplemented
    here rather than imported so this module never imports from
    `pipeline.py` -- see module docstring). No new resolution or
    rendering logic of any kind."""
    if repo_root is None or investigation_context is None:
        return None, None, "no_repo_root"

    resolved_file, resolved_symbol, failure_reason = _resolve_planning_evidence_request(
        request, repo_root, investigation_context,
    )
    if failure_reason is not None:
        return None, None, failure_reason

    if request.request_type == "file_source":
        try:
            full_text = (Path(repo_root) / resolved_file).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None, None, "source_unavailable"
        n_lines = len(full_text.splitlines())
        return resolved_file, _render_source_excerpt(resolved_file, None, 1, n_lines, full_text), None

    match, reason = _resolve_guided_symbol(request.symbol, request.file_hint, repo_root, investigation_context)
    if match is None:
        return None, None, reason or "unresolved_symbol"
    source = _read_symbol_source(match, investigation_context)
    if source is None:
        return None, None, "source_unavailable"
    label = f"{match.file}:{match.label}"
    return label, _render_source_excerpt(match.file, match.label, match.line, match.end_line, source), None


# ---------------------------------------------------------------------------
# Tree structure.
# ---------------------------------------------------------------------------

class ConcernNode:
    def __init__(self, node_id: str, parent_id: "Optional[str]", depth: int, proposition: str):
        self.node_id = node_id
        self.parent_id = parent_id
        self.depth = depth
        self.proposition = proposition
        self.attempts: "List[dict]" = []
        self.children: "List[str]" = []
        self.status: "Optional[str]" = None
        self.citations: "Tuple[str, ...]" = ()
        self.unresolved_reason: "Optional[str]" = None
        self.evidence_requests: "List[dict]" = []
        self._requested_keys: "set" = set()
        self.evaluation_count = 0
        self.acquisition_rounds = 0

    def record_attempt(self, action: EvaluatorAction, **extra) -> None:
        entry = {
            "action": action.kind,
            "rationale": action.rationale,
            "citations": list(action.citations),
            "children": list(action.children),
            "necessary_conditions": list(action.necessary_conditions),
            "evidence_conflict_check": list(action.evidence_conflict_check),
            "reason": action.reason,
            "invalid_detail": action.invalid_detail,
        }
        entry.update(extra)
        self.attempts.append(entry)

    def finalize(self, status: str, *, citations: "Tuple[str, ...]" = (), unresolved_reason: "Optional[str]" = None) -> None:
        self.status = status
        self.citations = citations
        self.unresolved_reason = unresolved_reason

    def to_jsonable(self) -> dict:
        return {
            "node_id": self.node_id,
            "parent_id": self.parent_id,
            "depth": self.depth,
            "proposition": self.proposition,
            "attempts": self.attempts,
            "children": list(self.children),
            "status": self.status,
            "citations": list(self.citations),
            "unresolved_reason": self.unresolved_reason,
            "evidence_requests": self.evidence_requests,
        }


class ConcernTree:
    """One root concern's complete tree -- owns node identity allocation,
    the shared evidence pool, and the cross-node request-dedup ledger (a
    request already resolved by any node in this tree is never re-resolved
    by another, mirroring Planning's own cross-round dedup, generalized
    here to cross-NODE)."""

    def __init__(self, root_proposition: str, code_context: str, patch: str, limits: Limits):
        self.limits = limits
        self.pool = EvidencePool(code_context, patch)
        self.nodes: "Dict[str, ConcernNode]" = {}
        self._next_id = 0
        self._resolved_request_cache: "Dict[tuple, tuple]" = {}  # key -> (label, text, failure_reason)
        self.root_id = self._new_node(None, 0, root_proposition).node_id

    def _new_node(self, parent_id: "Optional[str]", depth: int, proposition: str) -> ConcernNode:
        node_id = f"n{self._next_id}"
        self._next_id += 1
        node = ConcernNode(node_id, parent_id, depth, proposition)
        self.nodes[node_id] = node
        return node

    def node_count(self) -> int:
        return len(self.nodes)

    def ancestor_propositions(self, node: ConcernNode) -> "List[str]":
        out = []
        current = node
        while current.parent_id is not None:
            current = self.nodes[current.parent_id]
            out.append(current.proposition)
        return out

    def is_duplicate_proposition(self, text: str, node: ConcernNode, sibling_texts: "List[str]") -> bool:
        normalized = _normalize_for_provenance(text).lower()
        if not normalized:
            return True
        candidates = [node.proposition] + self.ancestor_propositions(node) + sibling_texts
        return any(normalized == _normalize_for_provenance(c).lower() for c in candidates)

    def to_jsonable(self) -> dict:
        root = self.nodes[self.root_id]
        evaluations = sum(n.evaluation_count for n in self.nodes.values())
        acquired = sum(1 for _l, _t in self.pool.acquired_blocks)
        requests = sum(len(n.evidence_requests) for n in self.nodes.values())
        invalid_provenance = sum(
            1 for n in self.nodes.values() if n.unresolved_reason == "invalid_provenance"
        )
        unresolved = sum(1 for n in self.nodes.values() if n.status == "UNRESOLVED")
        return {
            "root_id": self.root_id,
            "root_proposition": root.proposition,
            "root_final_status": root.status,
            "nodes": {nid: n.to_jsonable() for nid, n in self.nodes.items()},
            "totals": {
                "total_nodes": self.node_count(),
                "max_depth_reached": max((n.depth for n in self.nodes.values()), default=0),
                "semantic_evaluation_calls": evaluations,
                "evidence_requests": requests,
                "evidence_acquired": acquired,
                "invalid_provenance_count": invalid_provenance,
                "unresolved_count": unresolved,
            },
        }


# ---------------------------------------------------------------------------
# The ONE generic evaluator call -- used, unmodified, at every node, at
# every depth, for the initial evaluation AND for parent reconsideration
# after children resolve. See module docstring: this uniformity is the
# core of the experiment.
# ---------------------------------------------------------------------------

def _render_child_results(child_nodes: "List[ConcernNode]") -> str:
    lines = ["## Sub-question results", ""]
    for child in child_nodes:
        lines.append(f"- Proposition: {child.proposition}")
        lines.append(f"  Result: {child.status}")
        if child.status == "UNRESOLVED":
            lines.append(f"  Reason: {child.unresolved_reason}")
        else:
            lines.append(f"  Citations: {'; '.join(child.citations) if child.citations else 'none'}")
    return "\n".join(lines)


def _evaluate(llm, proposition: str, pool: EvidencePool, child_nodes: "Optional[List[ConcernNode]]" = None) -> EvaluatorAction:
    """One evaluator call. `child_nodes=None` is the initial evaluation of
    a node; a non-empty list is parent reconsideration after decomposition
    -- the SAME function, the SAME prompt, the SAME parser either way.
    Never receives `vulnerability_text` -- this function's own signature
    has no parameter for it (see module docstring's authority-boundary
    section)."""
    system_prompt = _PROMPT_PATH.read_text(encoding="utf-8")
    sections = [
        "## Proposition to evaluate", "", proposition, "",
        "## Repository evidence (patch + supplied/acquired source)", "",
        pool.rendered_for_prompt() or "(none supplied yet)", "",
    ]
    if pool.patch.strip():
        sections += ["## Proposed patch", "", pool.patch, ""]
    if child_nodes:
        sections += [_render_child_results(child_nodes), ""]
    user_message = "\n".join(sections)
    resp = llm.complete(system_prompt, user_message, stage="concern_tree_evaluator")
    return parse_action(resp)


# ---------------------------------------------------------------------------
# Recursive controller.
# ---------------------------------------------------------------------------

def _citations_valid(citations: "Tuple[str, ...]", pool: EvidencePool) -> bool:
    return bool(citations) and all(_point_citation_valid(c, *pool.sources()) for c in citations)


def _validate_decompose(
    action: EvaluatorAction, node: ConcernNode, tree: ConcernTree,
) -> "Optional[str]":
    """Shape/structural validation for a DECOMPOSE action -- returns a
    rejection reason, or None if valid. Never a semantic check (see module
    docstring): this can never verify the decomposition is complete or
    that AND/OR-style sufficiency holds, only that its SHAPE is sane and
    bounded."""
    children = [c for c in action.children if c and c.strip()]
    if not children or len(children) != len(action.children):
        return "empty_child"
    if node.depth + 1 > tree.limits.max_depth:
        return "max_depth"
    if len(children) > tree.limits.max_children_per_decomposition:
        return "too_many_children"
    if tree.node_count() + len(children) > tree.limits.max_total_nodes_per_root:
        return "node_budget_exhausted"
    existing_children_text = [tree.nodes[cid].proposition for cid in node.children]
    seen_norm: "set" = set()
    for child_text in children:
        normalized = _normalize_for_provenance(child_text).lower()
        if normalized in seen_norm:
            return "duplicate_child"
        seen_norm.add(normalized)
        if tree.is_duplicate_proposition(child_text, node, existing_children_text):
            return "child_equals_ancestor_or_self"
    return None


def _handle_request_evidence(
    action: EvaluatorAction, node: ConcernNode, tree: ConcernTree, repo_root, investigation_context,
    provider, model,
) -> "Tuple[bool, str]":
    """Attempt to resolve and merge ONE evidence request for `node`.
    Returns `(progressed, outcome)` -- `progressed=True` only when the
    pool genuinely grew with content this node did not already have
    access to. Never re-resolves a request already resolved anywhere else
    in this tree (cross-node dedup, mirroring Planning's own cross-round
    dedup) and never re-attempts an identical request from the SAME node
    twice."""
    request = action.request
    shape_reason = _validate_planning_request_schema(request)
    if shape_reason is not None:
        node.evidence_requests.append({
            "request": request._asdict(), "resolved": False, "failure_reason": shape_reason, "included": None,
        })
        return False, "malformed_request"

    key = _planning_request_key(request)
    if key in node._requested_keys:
        return False, "duplicate_request"
    node._requested_keys.add(key)

    if key in tree._resolved_request_cache:
        label, text, failure_reason = tree._resolved_request_cache[key]
    else:
        label, text, failure_reason = _resolve_evidence_source(request, repo_root, investigation_context)
        tree._resolved_request_cache[key] = (label, text, failure_reason)

    if failure_reason is not None:
        node.evidence_requests.append({
            "request": request._asdict(), "resolved": False, "failure_reason": failure_reason, "included": None,
        })
        return False, failure_reason

    known_overhead = len(node.proposition) + len(tree.pool.code_context) + len(tree.pool.patch) + 2000
    progressed, outcome = tree.pool.try_merge(
        label, text, provider=provider, model=model, known_overhead_chars=known_overhead,
    )
    node.evidence_requests.append({
        "request": request._asdict(), "resolved": True, "failure_reason": None,
        "resolved_label": label, "included": progressed, "merge_outcome": outcome,
    })
    return progressed, outcome


def resolve_node(
    tree: ConcernTree, node: ConcernNode, llm, repo_root=None, investigation_context=None,
    provider=None, model=None, child_nodes: "Optional[List[ConcernNode]]" = None,
) -> None:
    """Resolve `node` in place -- direct verdict, evidence acquisition +
    retry, or decomposition + recursive child resolution + reconsideration.
    Mutates `node`/`tree` only; never returns a value (the tree itself is
    the result). Every exit path calls `node.finalize(...)` exactly once."""
    if node.status is not None:
        return  # already finalized (defensive; controller never re-enters a finalized node)

    if node.depth > tree.limits.max_depth:
        node.finalize("UNRESOLVED", unresolved_reason="max_depth")
        return
    if tree.node_count() > tree.limits.max_total_nodes_per_root:
        node.finalize("UNRESOLVED", unresolved_reason="node_budget_exhausted")
        return

    while True:
        if node.evaluation_count >= tree.limits.max_semantic_evaluations_per_node:
            node.finalize("UNRESOLVED", unresolved_reason="evaluation_limit_reached")
            return

        action = _evaluate(llm, node.proposition, tree.pool, child_nodes=child_nodes)
        node.evaluation_count += 1
        node.record_attempt(action)

        if action.kind == "INVALID":
            node.finalize("UNRESOLVED", unresolved_reason="invalid_output")
            return

        if action.kind in ("PROVEN", "REFUTED"):
            if _citations_valid(action.citations, tree.pool):
                node.finalize(action.kind, citations=action.citations)
            else:
                node.finalize("UNRESOLVED", unresolved_reason="invalid_provenance")
            return

        if action.kind == "UNRESOLVED":
            node.finalize("UNRESOLVED", unresolved_reason=action.reason or "model_reported_unresolved")
            return

        if action.kind == "REQUEST_EVIDENCE":
            if len(node.evidence_requests) >= tree.limits.max_evidence_requests_per_node:
                node.finalize("UNRESOLVED", unresolved_reason="no_progress")
                return
            if node.acquisition_rounds >= tree.limits.max_acquisition_rounds_per_node:
                node.finalize("UNRESOLVED", unresolved_reason="no_progress")
                return
            node.acquisition_rounds += 1
            progressed, outcome = _handle_request_evidence(
                action, node, tree, repo_root, investigation_context, provider, model,
            )
            if not progressed:
                node.finalize("UNRESOLVED", unresolved_reason="no_progress" if outcome != "malformed_request" else "invalid_output")
                return
            continue  # retry the SAME node with the grown pool

        if action.kind == "DECOMPOSE":
            rejection = _validate_decompose(action, node, tree)
            if rejection is not None:
                node.finalize("UNRESOLVED", unresolved_reason=rejection)
                return
            new_children = []
            for child_text in action.children:
                child = tree._new_node(node.node_id, node.depth + 1, child_text)
                node.children.append(child.node_id)
                new_children.append(child)
            for child in new_children:
                resolve_node(
                    tree, child, llm, repo_root=repo_root, investigation_context=investigation_context,
                    provider=provider, model=model,
                )
            all_children = [tree.nodes[cid] for cid in node.children]
            child_nodes = all_children  # feeds the NEXT loop iteration's reconsideration call
            continue

        # Unreachable given ACTIONS' closed set, but never silently trusted.
        node.finalize("UNRESOLVED", unresolved_reason="invalid_output")
        return


def evaluate_concern_tree(
    proposition: str, code_context: str, patch: str, llm, *,
    repo_root=None, investigation_context=None, limits: "Optional[Limits]" = None,
) -> dict:
    """Top-level entry point. `proposition` must be a clean root concern
    description ONLY -- no `concerns_v2` mechanism fields (see module
    docstring; callers are responsible for this separation, and the
    harness/tests demonstrate it explicitly). `vulnerability_text` has no
    parameter here at all -- structurally impossible to pass in.

    Returns the complete, JSON-serializable trace (see `ConcernTree.
    to_jsonable`) -- the only artifact this function produces; nothing is
    written to disk or fed back into any other Challenger stage."""
    from .llm_client import resolve_active_model

    tree = ConcernTree(proposition, code_context, patch, limits or Limits())
    provider, model = resolve_active_model()
    root = tree.nodes[tree.root_id]
    resolve_node(tree, root, llm, repo_root=repo_root, investigation_context=investigation_context,
                 provider=provider, model=model)
    return tree.to_jsonable()
