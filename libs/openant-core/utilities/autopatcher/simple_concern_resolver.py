"""
Experimental, standalone two-pass concern resolver ("Simple Concern
Resolver").

STATUS: EXPERIMENTAL, ISOLATED. Not wired into production Challenger or the
pipeline. Does NOT depend on `concern_tree.py` -- the recursive Concern
Tree experiment is PAUSED, not removed, and this module is a completely
independent A/B alternative to it, never a Tree variant. Nothing in
`patch_challenger.py`, `pipeline.py`, or `concern_tree.py` imports from
this module, and this module never imports FROM `concern_tree.py` -- only
from the same lower-level, already-tested primitives the Tree also reuses
(`remediation_planner.py`, `technical_capacity.py`, `llm_client.py`,
`patch_challenger.py`'s own provenance helpers).

Hypothesis under test: a fixed, two-call ANALYZE -> CHALLENGE+FINALIZE
sequence -- with the second call genuinely independent (a fresh LLM call,
never a continuation of the first) and explicitly adversarial -- can catch
evidence, assumptions, or contradictions a single semantic pass misses,
without the cost/complexity of recursive decomposition. See the design
review this module implements for the concrete real-run evidence
motivating this experiment.

Complexity ceiling, enforced by the CONTROL FLOW ITSELF in
`resolve_concern` (not by a counter that could simply be raised): at most
3 LLM calls (Pass 1, an optional Pass 1 rerun, Pass 2), at most 1
evidence-acquisition attempt. No loops, no recursion, no child
propositions, no node graph, no parent reconciliation, no third semantic
pass. If a future change needs any of those, it no longer belongs in this
module.

What IS deterministic here: response-shape validation for both passes,
provenance/citation validation (reusing `patch_challenger._point_citation_
valid` unchanged), the exactly-one-acquisition-attempt bound, and fail-
closed termination. What is NOT deterministic: whether Pass 1's reasoning
is correct, whether Pass 2's challenge is semantically relevant, or
whether a conclusion logically follows from its citations.

Authority boundary: this module never receives `vulnerability_text`,
`security_invariant`, upstream remediation knowledge, or any Challenger v2
resolution field -- only a concern proposition string and repository
evidence (`code_context`/`patch`/acquired source). The harness enforces
this at the archived-run boundary (see `tools/simple_concern_harness.py`).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Tuple

from .remediation_planner import (
    PlanningEvidenceRequest,
    _validate_planning_request_schema,
    _resolve_planning_evidence_request,
    _resolve_guided_symbol,
    _read_symbol_source,
    _render_source_excerpt,
)
from .patch_challenger import _point_citation_valid, _normalize_for_provenance, _strip_quote_wrapping
from .technical_capacity import compute_source_capacity

_PASS1_PROMPT_PATH = Path(__file__).parent / "prompts" / "simple_concern_analyze.md"
_PASS2_PROMPT_PATH = Path(__file__).parent / "prompts" / "simple_concern_challenge.md"

VERDICTS = ("PROVEN", "REFUTED", "UNRESOLVED")
"""The only three verdicts either pass may produce -- deliberately smaller
than the Concern Tree's 5-action vocabulary. Evidence acquisition is a
FIELD on a Pass 1 UNRESOLVED, never a fourth verdict or a separate action
type."""

REQUEST_TYPES = ("file_source", "symbol_definition")

MAX_ACQUISITION_ROUNDS = 1
"""Documents the bound `resolve_concern`'s control flow already enforces
structurally -- there is no loop anywhere in this module that could
exceed this."""


# ---------------------------------------------------------------------------
# Response parsing -- deterministic SHAPE validation only (see module
# docstring). Small generic regex helpers reimplemented independently here
# (not imported from `concern_tree.py`) so this module has zero dependency
# on it.
# ---------------------------------------------------------------------------

_FIELD_RE_TEMPLATE = r"^[ \t]*{label}:\s*(.+?)\s*$"
_BULLET_RE = re.compile(r"^[ \t]*[-*+]\s*(.+?)\s*$")


def _extract_field(text: str, label: str) -> "Optional[str]":
    m = re.search(_FIELD_RE_TEMPLATE.format(label=re.escape(label)), text, re.IGNORECASE | re.MULTILINE)
    return m.group(1).strip() if m else None


def _field_position(text: str, label: str) -> "Optional[int]":
    m = re.search(_FIELD_RE_TEMPLATE.format(label=re.escape(label)), text, re.IGNORECASE | re.MULTILINE)
    return m.start() if m else None


def _extract_bulleted_section(text: str, heading: str) -> "List[str]":
    """Lines under a `<heading>:` line, up to the next recognized field/
    heading or end of text. Mirrors `concern_tree._extract_bulleted_
    section`'s own logic exactly, deliberately reimplemented rather than
    imported (see module docstring's isolation requirement)."""
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
        if re.match(r"^[ \t]*[A-Za-z][A-Za-z _]*:\s*", line):
            break
        lines.append(line.strip())
    return lines


class Pass1Result(NamedTuple):
    kind: str  # PROVEN | REFUTED | UNRESOLVED | INVALID
    reasoning: str = ""
    citations: "Tuple[str, ...]" = ()
    missing_evidence: bool = False
    request: "Optional[PlanningEvidenceRequest]" = None
    invalid_detail: "Optional[str]" = None


class Pass2Result(NamedTuple):
    kind: str  # PROVEN | REFUTED | UNRESOLVED | INVALID
    challenge_result: str = ""
    reasoning: str = ""
    citations: "Tuple[str, ...]" = ()
    invalid_detail: "Optional[str]" = None


def parse_pass1(raw: str) -> Pass1Result:
    """Parse one Pass 1 (ANALYZE) response. Never raises, never silently
    repairs ambiguous output -- a malformed response is `kind="INVALID"`,
    demoted by `resolve_concern` to final UNRESOLVED(invalid_output),
    exactly like every other fail-closed gate in this module."""
    raw = raw or ""
    verdict = _extract_field(raw, "Candidate verdict")
    if verdict is None:
        return Pass1Result(kind="INVALID", invalid_detail="missing_candidate_verdict")
    verdict = verdict.strip().upper()
    if verdict not in VERDICTS:
        return Pass1Result(kind="INVALID", invalid_detail="unrecognized_verdict")

    reasoning = _extract_field(raw, "Reasoning") or ""
    if not reasoning:
        return Pass1Result(kind="INVALID", invalid_detail="missing_reasoning")

    citations = tuple(_extract_bulleted_section(raw, "Citations"))

    missing_evidence_raw = _extract_field(raw, "Missing evidence")
    if missing_evidence_raw is None:
        return Pass1Result(kind="INVALID", invalid_detail="missing_missing_evidence_field")
    missing_evidence_raw = missing_evidence_raw.strip().lower()
    if missing_evidence_raw not in ("none", "needed"):
        return Pass1Result(kind="INVALID", invalid_detail="unrecognized_missing_evidence_value")

    if missing_evidence_raw == "needed":
        # Structural rule: "Missing evidence: needed" requires "Candidate
        # verdict: UNRESOLVED" -- deterministic shape validation only,
        # never a semantic check.
        if verdict != "UNRESOLVED":
            return Pass1Result(kind="INVALID", invalid_detail="missing_evidence_requires_unresolved_verdict")
        request_type = _extract_field(raw, "Request type")
        file_hint = _extract_field(raw, "File hint")
        symbol = _extract_field(raw, "Symbol")
        if request_type not in REQUEST_TYPES:
            return Pass1Result(kind="INVALID", invalid_detail="missing_or_invalid_request_type")
        file_hint = None if not file_hint or file_hint.strip().lower() in ("none", "n/a") else file_hint.strip()
        symbol = None if not symbol or symbol.strip().lower() in ("none", "n/a") else symbol.strip()
        request = PlanningEvidenceRequest(request_type=request_type, file_hint=file_hint, symbol=symbol, reason=reasoning)
        shape_reason = _validate_planning_request_schema(request)
        if shape_reason is not None:
            return Pass1Result(kind="INVALID", invalid_detail=f"malformed_evidence_request:{shape_reason}")
        return Pass1Result(
            kind=verdict, reasoning=reasoning, citations=citations, missing_evidence=True, request=request,
        )

    # missing_evidence_raw == "none"
    if verdict in ("PROVEN", "REFUTED") and not citations:
        return Pass1Result(kind="INVALID", invalid_detail="missing_citations_for_verdict")
    return Pass1Result(kind=verdict, reasoning=reasoning, citations=citations, missing_evidence=False)


def parse_pass2(raw: str) -> Pass2Result:
    """Parse one Pass 2 (CHALLENGE + FINALIZE) response. Enforces the
    required output ORDER (`Challenge result` before `Final verdict`) as a
    pure positional/structural check, never a semantic one -- see module
    docstring: this is the autoregressive-commitment discipline the
    design review specified, so the challenge is generated before the
    verdict it might change."""
    raw = raw or ""
    challenge_pos = _field_position(raw, "Challenge result")
    verdict_pos = _field_position(raw, "Final verdict")
    if challenge_pos is None:
        return Pass2Result(kind="INVALID", invalid_detail="missing_challenge_result")
    if verdict_pos is None:
        return Pass2Result(kind="INVALID", invalid_detail="missing_final_verdict")
    if challenge_pos >= verdict_pos:
        return Pass2Result(kind="INVALID", invalid_detail="wrong_order")

    challenge_result = _extract_field(raw, "Challenge result") or ""
    if not challenge_result:
        return Pass2Result(kind="INVALID", invalid_detail="empty_challenge_result")

    verdict = (_extract_field(raw, "Final verdict") or "").strip().upper()
    if verdict not in VERDICTS:
        return Pass2Result(kind="INVALID", invalid_detail="unrecognized_verdict")

    reasoning = _extract_field(raw, "Final reasoning") or ""
    if not reasoning:
        return Pass2Result(kind="INVALID", invalid_detail="missing_final_reasoning")

    citations = tuple(_extract_bulleted_section(raw, "Citations"))
    if verdict in ("PROVEN", "REFUTED") and not citations:
        return Pass2Result(kind="INVALID", invalid_detail="missing_citations_for_verdict")

    return Pass2Result(kind=verdict, challenge_result=challenge_result, reasoning=reasoning, citations=citations)


# ---------------------------------------------------------------------------
# Evidence -- single-slot, since at most ONE acquisition is ever possible
# (see module docstring's complexity ceiling). Deliberately simpler than
# `concern_tree.EvidencePool`: no dedup ledger, no growing list -- there is
# structurally nothing to dedup against.
# ---------------------------------------------------------------------------

class _ResolverEvidence:
    def __init__(self, code_context: str, patch: str):
        self.code_context = code_context or ""
        self.patch = patch or ""
        self.acquired_label: "Optional[str]" = None
        self.acquired_text: str = ""

    def sources(self) -> "Tuple[str, ...]":
        """NEVER includes `vulnerability_text` (see module docstring's
        authority-boundary section; this class has no parameter for it
        and never will)."""
        return (self.code_context, self.patch, self.acquired_text)

    def rendered_for_prompt(self) -> str:
        parts = [p for p in (self.code_context, self.acquired_text) if p.strip()]
        return "\n\n".join(parts)

    def merge(
        self, label: "Optional[str]", text: "Optional[str]", *, provider, model, known_overhead_chars: int,
    ) -> "Tuple[bool, str]":
        if not text:
            return False, "source_unavailable"
        capacity = compute_source_capacity(
            provider, model, reserved_output_tokens=1, known_overhead_chars=known_overhead_chars,
        )
        if capacity.source_capacity_chars <= 0 or len(text) > capacity.source_capacity_chars:
            return False, "technical_capacity"
        self.acquired_label = label
        self.acquired_text = text
        return True, "merged"


def _resolve_evidence_source(
    request: PlanningEvidenceRequest, repo_root, investigation_context,
) -> "Tuple[Optional[str], Optional[str], Optional[str]]":
    """(label, rendered_text, failure_reason) for one already schema-valid
    request. Independently implemented here, not imported from
    `concern_tree.py` (see module docstring's isolation requirement) --
    a thin adapter over `remediation_planner.py`'s own resolution +
    rendering primitives, reused verbatim. No new resolution logic of any
    kind."""
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


def _citations_valid(citations: "Tuple[str, ...]", pool: _ResolverEvidence) -> bool:
    return bool(citations) and all(_point_citation_valid(c, *pool.sources()) for c in citations)


# ---------------------------------------------------------------------------
# The two LLM calls. Each reads its OWN prompt file -- genuinely separate
# system prompts, never a shared/parameterized one (see module docstring's
# independence discussion in the design review).
# ---------------------------------------------------------------------------

def _render_evidence_sections(pool: _ResolverEvidence) -> "List[str]":
    sections = [
        "## Repository evidence (patch + supplied/acquired source)", "",
        pool.rendered_for_prompt() or "(none supplied yet)", "",
    ]
    if pool.patch.strip():
        sections += ["## Proposed patch", "", pool.patch, ""]
    return sections


def _run_pass1(llm, proposition: str, pool: _ResolverEvidence, *, stage: str) -> Pass1Result:
    system_prompt = _PASS1_PROMPT_PATH.read_text(encoding="utf-8")
    sections = ["## Concern to evaluate", "", proposition, ""] + _render_evidence_sections(pool)
    user_message = "\n".join(sections)
    resp = llm.complete(system_prompt, user_message, stage=stage)
    return parse_pass1(resp)


def _render_pass1_result(pass1: Pass1Result) -> str:
    """Retained for observability/offline analysis of a `Pass1Result`
    (e.g. a future report/CLI summary) -- no longer called anywhere in
    the live `resolve_concern` control flow. See `_run_pass2`'s own
    docstring: Pass 2 is now information-isolated from Pass 1 (the Pass 2
    Information Isolation experiment), so nothing in this module renders
    a Pass 1 result into another LLM call's prompt."""
    lines = [
        "## Pass 1 candidate result", "",
        f"Candidate verdict: {pass1.kind}",
        f"Reasoning: {pass1.reasoning}",
        "Citations:",
    ]
    lines += [f"- {c}" for c in pass1.citations] if pass1.citations else ["- (none)"]
    return "\n".join(lines)


def _run_pass2(llm, proposition: str, pool: _ResolverEvidence) -> Pass2Result:
    """Pass 2 Information Isolation experiment: this call receives the
    original proposition and the SAME shared evidence pool Pass 1 saw
    (including anything Pass 1's acquisition round added to it) -- and
    nothing else. It never receives Pass 1's verdict, reasoning, or
    selected citations; `_render_pass1_result` is deliberately not called
    here. Acquired evidence remains shared (it lives in `pool`, not in
    any Pass-1-specific structure); only Pass 1's own INTERPRETATION of
    the evidence is withheld."""
    system_prompt = _PASS2_PROMPT_PATH.read_text(encoding="utf-8")
    sections = ["## Concern to evaluate", "", proposition, ""] + _render_evidence_sections(pool)
    user_message = "\n".join(sections)
    resp = llm.complete(system_prompt, user_message, stage="simple_concern_pass2")
    return parse_pass2(resp)


# ---------------------------------------------------------------------------
# Trace serialization -- flat, linear, never a node/graph shape.
# ---------------------------------------------------------------------------

def _pass1_jsonable(pass1: Pass1Result) -> dict:
    return {
        "kind": pass1.kind,
        "reasoning": pass1.reasoning,
        "citations": list(pass1.citations),
        "missing_evidence": pass1.missing_evidence,
        "request": pass1.request._asdict() if pass1.request is not None else None,
        "invalid_detail": pass1.invalid_detail,
    }


def _pass2_jsonable(pass2: Pass2Result) -> dict:
    return {
        "kind": pass2.kind,
        "challenge_result": pass2.challenge_result,
        "reasoning": pass2.reasoning,
        "citations": list(pass2.citations),
        "invalid_detail": pass2.invalid_detail,
    }


def _finalize(trace: dict, metrics: dict, verdict: str, *, citations: "Tuple[str, ...]" = (), unresolved_reason=None) -> dict:
    return {
        "final_verdict": verdict,
        "unresolved_reason": unresolved_reason,
        "citations": list(citations),
        "pass1": trace["pass1"],
        "acquisition": trace["acquisition"],
        "pass1_rerun": trace["pass1_rerun"],
        "pass2": trace["pass2"],
        "metrics": metrics,
    }


# ---------------------------------------------------------------------------
# Top-level entry point -- the ENTIRE bounded flow.
# ---------------------------------------------------------------------------

def resolve_concern(
    proposition: str, code_context: str, patch: str, llm, *,
    repo_root=None, investigation_context=None,
) -> dict:
    """Pass 1, an optional single acquisition + Pass 1 rerun, then Pass 2,
    which always produces the final verdict. `vulnerability_text` has no
    parameter here at all -- structurally impossible to pass in.

    At most 3 calls to `llm.complete`, ever -- there is no loop in this
    function that could exceed that; the acquisition branch runs at most
    once, unconditionally followed by at most one Pass 1 rerun, and Pass 2
    is called at most once, after acquisition (if any) is fully settled."""
    from .llm_client import resolve_active_model
    provider, model = resolve_active_model()

    pool = _ResolverEvidence(code_context, patch)
    metrics = {"llm_calls": 0, "evidence_requests": 0, "evidence_acquired": 0, "invalid_provenance_count": 0}
    trace: "Dict[str, object]" = {"pass1": None, "acquisition": None, "pass1_rerun": None, "pass2": None}

    pass1 = _run_pass1(llm, proposition, pool, stage="simple_concern_pass1")
    metrics["llm_calls"] += 1
    trace["pass1"] = _pass1_jsonable(pass1)

    if pass1.kind == "INVALID":
        return _finalize(trace, metrics, "UNRESOLVED", unresolved_reason="invalid_output")

    active_pass1 = pass1
    if pass1.missing_evidence:
        metrics["evidence_requests"] += 1
        label, text, failure_reason = _resolve_evidence_source(pass1.request, repo_root, investigation_context)
        if failure_reason is not None:
            trace["acquisition"] = {
                "request": pass1.request._asdict(), "resolved": False,
                "failure_reason": failure_reason, "included": None,
            }
            return _finalize(trace, metrics, "UNRESOLVED", unresolved_reason=failure_reason)

        known_overhead = len(proposition) + len(pool.code_context) + len(pool.patch) + 2000
        progressed, outcome = pool.merge(
            label, text, provider=provider, model=model, known_overhead_chars=known_overhead,
        )
        trace["acquisition"] = {
            "request": pass1.request._asdict(), "resolved": True, "failure_reason": None,
            "resolved_label": label, "included": progressed, "merge_outcome": outcome,
        }
        if not progressed:
            return _finalize(trace, metrics, "UNRESOLVED", unresolved_reason=outcome)
        metrics["evidence_acquired"] += 1

        pass1_rerun = _run_pass1(llm, proposition, pool, stage="simple_concern_pass1_rerun")
        metrics["llm_calls"] += 1
        trace["pass1_rerun"] = _pass1_jsonable(pass1_rerun)

        if pass1_rerun.kind == "INVALID":
            return _finalize(trace, metrics, "UNRESOLVED", unresolved_reason="invalid_output")
        if pass1_rerun.missing_evidence:
            # Exactly one acquisition round permitted -- a second request
            # is never attempted (see module docstring's complexity
            # ceiling and MAX_ACQUISITION_ROUNDS).
            return _finalize(trace, metrics, "UNRESOLVED", unresolved_reason="no_progress")
        active_pass1 = pass1_rerun

    # Pass 1's OWN citation validity never gates control flow -- it is a
    # CANDIDATE, and Pass 2 is the sole finalizer, always invoked once
    # evidence is settled, regardless of whether Pass 1's own citations
    # happen to validate. Still tracked in metrics for comparison.
    if active_pass1.kind in ("PROVEN", "REFUTED") and not _citations_valid(active_pass1.citations, pool):
        metrics["invalid_provenance_count"] += 1

    pass2 = _run_pass2(llm, proposition, pool)
    metrics["llm_calls"] += 1
    trace["pass2"] = _pass2_jsonable(pass2)

    if pass2.kind == "INVALID":
        return _finalize(trace, metrics, "UNRESOLVED", unresolved_reason="invalid_output")

    if pass2.kind in ("PROVEN", "REFUTED"):
        if _citations_valid(pass2.citations, pool):
            return _finalize(trace, metrics, pass2.kind, citations=pass2.citations)
        metrics["invalid_provenance_count"] += 1
        return _finalize(trace, metrics, "UNRESOLVED", unresolved_reason="invalid_provenance")

    return _finalize(trace, metrics, "UNRESOLVED", unresolved_reason="model_reported_unresolved")
