"""Adapter between a rendered vulnerability description and InvestigationCase.

Ported from the standalone Auto Patcher project's investigation_adapters.py,
trimmed to the file-mode path only: OpenAnt always supplies its own rendered
Finding markdown (core/patch.py), never a bare GHSA/CVE identifier, so the
GHSA/CVE adapters (``case_from_ghsa_advisory``, ``case_from_cve``) and their
converters are excluded entirely, not just their dead call path.

Also drops the original module's record-only evidence-collection machinery
(``_collect_evidence`` and its four collectors): verified dead in the
upstream project -- ``InvestigationCase.evidence`` is attached to the case
but never read by anything downstream (``to_context_projection()`` returns
``rendered_text`` verbatim, unaffected by ``evidence``). Dropping it changes
no observable output.

Guarantee preserved: ``case.to_context_projection().vulnerability_text`` is
byte-identical to the input text, same as upstream.
"""

from __future__ import annotations

from pathlib import Path

from .investigation_models import InvestigationCase, ProblemClaims, RawArtifact


def _first_summary_line(text: str) -> str:
    """Return the first non-empty line of text, with leading '#'/whitespace stripped."""
    for line in text.splitlines():
        line = line.strip().lstrip("#").strip()
        if line:
            return line
    return ""


def case_from_vulnerability_text(
    vulnerability_text: str, repo_root: Path | None = None
) -> InvestigationCase:
    """Wrap an already-rendered vulnerability_text (file mode) as an InvestigationCase.

    The text is carried through verbatim as ``rendered_text`` so
    ``to_context_projection()`` reproduces it exactly.
    """
    artifact = RawArtifact(source_type="vulnerability_text", raw_text=vulnerability_text)
    framing = ProblemClaims(summary=_first_summary_line(vulnerability_text))
    return InvestigationCase(
        raw_artifact=artifact,
        framing=framing,
        rendered_text=vulnerability_text,
        repo_root=repo_root,
        evidence=[],
    )
