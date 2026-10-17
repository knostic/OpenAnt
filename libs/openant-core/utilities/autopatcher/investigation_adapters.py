"""Adapters between today's inputs and InvestigationCase.

Ported from the standalone Auto Patcher project's investigation_adapters.py.
``case_from_vulnerability_text`` covers OpenAnt's own rendered Finding
markdown (core/patch.py); ``case_from_cve`` covers a raw NVD CVE record
(utilities.autopatcher.cve_fetcher.fetch_cve's return shape), added to
support patching directly from a known CVE identifier. The GHSA adapter
(``case_from_ghsa_advisory``) has no current caller in OpenAnt and stays
excluded, along with the original module's record-only evidence-collection
machinery (``_collect_evidence`` and its four collectors): verified dead in
the upstream project -- ``InvestigationCase.evidence`` is attached to the
case but never read by anything downstream (``to_context_projection()``
returns ``rendered_text`` verbatim, unaffected by ``evidence``). Dropping it
changes no observable output.

Guarantee preserved for both adapters: ``case.to_context_projection().vulnerability_text``
is byte-identical to the text each adapter's own renderer produces --
``case_from_vulnerability_text`` carries its input through verbatim,
``case_from_cve`` carries through ``cve_converter.cve_to_vuln_text``'s
output verbatim. Neither adapter reimplements any rendering of its own.
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


def case_from_cve(cve: dict, repo_root: Path | None = None) -> InvestigationCase:
    """Build an InvestigationCase from a raw NVD CVE record dict.

    Renders through ``cve_converter.cve_to_vuln_text`` -- the existing,
    tested formatter -- for ``rendered_text``, so
    ``to_context_projection().vulnerability_text`` is exactly what that
    formatter produces. Nothing here reimplements any part of that
    rendering, and ``framing.summary`` is derived from the same rendered
    text via ``_first_summary_line`` (the same helper
    ``case_from_vulnerability_text`` uses) rather than re-deriving it a
    second, independent way from the raw CVE dict.

    ``framing.packages`` reflects the CVE advisory's own claimed affected
    CPEs (``cve_converter.extract_affected_products``) -- this is advisory
    evidence, not a check against ``repo_root``. Nothing in this adapter or
    downstream verifies that ``repo_root``'s actual dependency versions
    match.

    ``evidence`` stays ``[]`` -- same as ``case_from_vulnerability_text``; no
    consumer of ``InvestigationCase.evidence`` exists yet.
    """
    from .cve_converter import cve_to_vuln_text, extract_affected_products, extract_cvss, extract_cwes

    rendered_text = cve_to_vuln_text(cve)
    cve_id = cve.get("id")
    _, severity = extract_cvss(cve)

    artifact = RawArtifact(
        source_type="cve",
        raw_text=rendered_text,
        source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else None,
        structured_payload=cve,
    )
    framing = ProblemClaims(
        summary=_first_summary_line(rendered_text),
        cwes=extract_cwes(cve),
        severity=severity,
        packages=[{"cpe": p} for p in extract_affected_products(cve)],
    )
    return InvestigationCase(
        raw_artifact=artifact,
        framing=framing,
        rendered_text=rendered_text,
        repo_root=repo_root,
        evidence=[],
    )
