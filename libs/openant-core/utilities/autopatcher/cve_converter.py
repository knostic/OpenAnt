"""Convert a parsed NVD CVE record dict into the vulnerability text format
consumed by the Auto Patcher pipeline. Mirrors the standalone Auto Patcher
project's GHSA path (``advisory_converter.py``), so both sources reach
``pipeline.run()`` through the same rendered-Markdown shape.

Ported from the standalone Auto Patcher project's ``cve_converter.py``.
``extract_description``/``extract_cwes``/``extract_cvss``/
``extract_affected_products``/``first_sentence`` are public (not
leading-underscore) so a future InvestigationCase adapter can reuse them to
populate ``ProblemClaims`` without re-deriving the same fields from the raw
NVD shape a second time -- that adapter is not part of this commit.

Pure formatting only: no network access, no filesystem access, no repository
inspection. The rendered Markdown is unchanged from the reference
implementation's template -- including the "Affected products" section,
which lists only what the advisory itself claims. The closing Note already
states plainly that no source code was inspected; see
extract_affected_products' docstring for why this data must not be treated
as repository-verified.
"""

from __future__ import annotations

import html as _html
import re


def cve_to_vuln_text(cve: dict) -> str:
    """Format an NVD CVE record dict as a Markdown vulnerability description.

    The output structure matches what ``advisory_converter.ghsa_to_vuln_text``
    produces upstream, so both sources reach the pipeline through the same
    shape. When no source code snippet is available (always true for a bare
    CVE record), this is stated explicitly so downstream stages -- and a
    human reviewer -- can adjust their expectations accordingly.
    """
    cve_id = cve.get("id") or "unknown"
    description = _clean(extract_description(cve)) or "No description available"
    summary = _clean(first_sentence(description)) or cve_id

    cwes = extract_cwes(cve)
    cwe_str = ", ".join(cwes) if cwes else "Unknown"

    score_str, severity_str = extract_cvss(cve)

    products = extract_affected_products(cve)
    product_section = "\n".join(f"- {p}" for p in products) if products else "- (not specified)"

    refs = _extract_references(cve)
    ref_section = "\n".join(f"- {r}" for r in refs) if refs else "- (none)"

    return f"""\
# {summary}

## Vulnerability description

**Advisory:** {cve_id}
**Severity:** {severity_str} (CVSS: {score_str})
**Type:** {cwe_str}

{description}

## Affected products

{product_section}

## References

{ref_section}

## Note

No source code snippet is available from this advisory. \
The patch generator will produce a best-effort patch based on the description above. \
Use --repo-root to enable impact analysis and test discovery on the actual codebase.
"""


def extract_description(cve: dict) -> str:
    """Return the English-language description text, or "" if absent."""
    for entry in cve.get("descriptions") or []:
        if entry.get("lang") == "en" and entry.get("value"):
            return entry["value"]
    return ""


def extract_cwes(cve: dict) -> list[str]:
    """Return the deduplicated list of English-language CWE labels (e.g. "CWE-89")."""
    cwes: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        for entry in weakness.get("description") or []:
            value = entry.get("value")
            if entry.get("lang") == "en" and value and value not in cwes:
                cwes.append(value)
    return cwes


_CVSS_METRIC_PREFERENCE = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def extract_cvss(cve: dict) -> tuple[str, str]:
    """Return (score_str, severity_str), preferring the newest CVSS version present.

    Falls back to ("N/A", "UNKNOWN") when no CVSS metric of any known
    version is present.
    """
    metrics = cve.get("metrics") or {}
    for key in _CVSS_METRIC_PREFERENCE:
        entries = metrics.get(key) or []
        if not entries:
            continue
        metric = entries[0]
        cvss_data = metric.get("cvssData") or {}
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or metric.get("baseSeverity")
        score_str = str(score) if score is not None else "N/A"
        severity_str = (severity or "UNKNOWN").upper()
        return score_str, severity_str
    return "N/A", "UNKNOWN"


def extract_affected_products(cve: dict) -> list[str]:
    """Return up to 5 vulnerable CPE criteria strings the advisory itself claims are affected.

    This reflects only what NVD's ``configurations`` block asserts -- it is
    not cross-checked against any repository's actual dependency versions.
    Callers (and any future consumer of this list, e.g. an InvestigationCase
    adapter) must not present this as a verified affected-version match.
    """
    products: list[str] = []
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if match.get("vulnerable") and match.get("criteria"):
                    if match["criteria"] not in products:
                        products.append(match["criteria"])
                if len(products) >= 5:
                    return products
    return products


def _extract_references(cve: dict) -> list[str]:
    """Return up to 5 reference URLs from the advisory."""
    refs: list[str] = []
    for entry in cve.get("references") or []:
        url = entry.get("url")
        if url:
            refs.append(url)
        if len(refs) >= 5:
            break
    return refs


def _truncate_at_word_boundary(text: str, limit: int, *, ellipsis: str = "...") -> str:
    """Cap `text` at `limit` characters without cutting a word in half.

    Returns `text` unchanged if it already fits. When truncation is
    required, backs off to the last whitespace boundary within the budget
    and appends `ellipsis` so the reader can tell the text was shortened.
    Falls back to a hard slice only when there is no word boundary to back
    off to (e.g. one unbroken token longer than the limit).
    """
    if len(text) <= limit:
        return text
    budget = max(limit - len(ellipsis), 0)
    cut = text[:budget]
    if " " in cut:
        cut = cut.rsplit(" ", 1)[0]
    cut = cut.rstrip()
    if not cut:
        cut = text[:budget]
    return cut + ellipsis


def first_sentence(text: str) -> str:
    """Return the first sentence of text, truncated to at most 120 chars.

    Truncation never cuts mid-word: when the sentence (or the whole text,
    if no sentence-ending punctuation is found) exceeds the limit, it is
    cut back to the last word boundary and an ellipsis is appended so the
    reader can tell the summary was shortened. Short summaries are
    returned unchanged.
    """
    if not text:
        return ""
    match = re.search(r"^(.*?[.!?])(\s|$)", text.strip())
    sentence = match.group(1) if match else text.strip()
    return _truncate_at_word_boundary(sentence, 120).rstrip()


def _clean(text: str) -> str:
    """Unescape HTML entities and strip whitespace."""
    return _html.unescape(text).strip()
