"""Canonical Investigation Engine data model.

Pure data only — no I/O, no LLM calls, no adapters. See
``investigation_adapters.py`` for the functions that build these objects
from today's existing inputs (a GHSA advisory dict, a hand-written
vulnerability_text string).

``InvestigationCase`` is the source of truth; ``ContextProjection`` is a
disposable, regenerable view of it sized for the existing pipeline's
``(vulnerability_text, repo_root)`` contract. See docs/investigation-engine.md
and docs/investigation-roadmap.md for the design this implements.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RawArtifact:
    """The artifact a run started from, before any interpretation."""

    source_type: str  # e.g. "ghsa", "cve", "vulnerability_text", "free_text"
    raw_text: str
    source_url: str | None = None
    structured_payload: dict | None = None


@dataclass
class ProblemClaims:
    """Structured claims about the problem, extracted from a RawArtifact.

    Field-level confidence, not a single collapsed score: a GHSA's package
    list is near-certain, a free-text guess at the same field is not, and
    this model must not flatten that distinction away.
    """

    summary: str = ""
    cwes: list[str] = field(default_factory=list)
    severity: str | None = None
    packages: list[dict] = field(default_factory=list)
    code_hints: dict = field(default_factory=dict)  # file_paths, symbols, keywords
    confidence: float | None = None


@dataclass
class Hypothesis:
    """A concrete, falsifiable claim about where/how the problem manifests.

    Not populated by any adapter yet (Slice 1 is foundational only) — the
    shape is locked in now so Evidence Collection and Hypothesis Formation
    slices don't renegotiate it later.
    """

    id: str
    statement: str
    predicted_location: str | None = None
    predicted_mechanism: str | None = None
    confirming_evidence_needed: list[str] = field(default_factory=list)
    status: str = "open"  # open | confirmed | rejected
    rejection_reason: str | None = None
    confidence: float | None = None


@dataclass
class EvidenceItem:
    """One piece of evidence gathered in support of, or against, a hypothesis.

    Not populated by any adapter yet — see Hypothesis docstring.
    """

    evidence_type: str
    source_module: str
    content: str
    supports: list[str] = field(default_factory=list)  # hypothesis ids
    refutes: list[str] = field(default_factory=list)  # hypothesis ids
    confidence: float | None = None


@dataclass
class ContextProjection:
    """The existing pipeline's input contract, as a view of an InvestigationCase."""

    vulnerability_text: str
    repo_root: Path | None = None


@dataclass
class InvestigationCase:
    """The Investigation Engine's primary artifact and source of truth.

    ``rendered_text`` is the case's current best vulnerability_text
    rendering. In Slice 1 it is always a verbatim passthrough of whatever
    text the case was built from — no rendering logic exists yet, only the
    field to hold its result.
    """

    raw_artifact: RawArtifact
    framing: ProblemClaims
    rendered_text: str
    repo_root: Path | None = None
    hypotheses: list[Hypothesis] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    leading_hypothesis_id: str | None = None
    open_questions: list[str] = field(default_factory=list)

    def to_context_projection(self) -> ContextProjection:
        """Collapse this case to the existing pipeline's input contract.

        Every InvestigationCase must remain reducible to this shape — see
        docs/investigation-roadmap.md's "Source of truth" section.
        """
        return ContextProjection(vulnerability_text=self.rendered_text, repo_root=self.repo_root)
