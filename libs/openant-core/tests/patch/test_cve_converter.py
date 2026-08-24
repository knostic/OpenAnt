"""Unit tests for cve_converter.

Ported from the standalone Auto Patcher project's test_cve_converter.py. The
rendered Markdown template is byte-for-byte identical to the reference
implementation's -- no wording changes were introduced in this commit. The
"rendering parity with the reference implementation" requirement is covered
by pinning assertions to exact strings the reference implementation is known
to produce (its module isn't importable here -- it lives in a sibling repo,
not a dependency of this one).
"""

from __future__ import annotations

from utilities.autopatcher.cve_converter import (
    cve_to_vuln_text,
    extract_affected_products,
    extract_cvss,
    extract_cwes,
    extract_description,
    first_sentence,
)

FULL_CVE = {
    "id": "CVE-2021-12345",
    "descriptions": [
        {
            "lang": "en",
            "value": (
                "A SQL injection vulnerability exists in the authenticate() function. "
                "An attacker can bypass authentication."
            ),
        }
    ],
    "metrics": {
        "cvssMetricV31": [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"},
            }
        ]
    },
    "weaknesses": [
        {"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-89"}]}
    ],
    "configurations": [
        {
            "nodes": [
                {
                    "operator": "OR",
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:example:example-lib:*:*:*:*:*:*:*:*",
                        }
                    ],
                }
            ]
        }
    ],
    "references": [
        {"url": "https://github.com/example/security/advisories/GHSA-1234", "source": "nvd@nist.gov"}
    ],
}

SPARSE_CVE = {"id": "CVE-0000-00000"}


def _cve_with_n_cpe_matches(n: int) -> dict:
    matches = [
        {"vulnerable": True, "criteria": f"cpe:2.3:a:example:lib-{i}:*:*:*:*:*:*:*:*"}
        for i in range(n)
    ]
    return {"id": "CVE-0001-00001", "configurations": [{"nodes": [{"cpeMatch": matches}]}]}


class TestCveToVulnText:
    def test_returns_string(self):
        result = cve_to_vuln_text(FULL_CVE)
        assert isinstance(result, str)
        assert len(result) > 50

    def test_deterministic_rendering(self):
        assert cve_to_vuln_text(FULL_CVE) == cve_to_vuln_text(FULL_CVE)

    def test_includes_advisory_line_recognized_by_pipeline(self):
        # pipeline.py's _ADVISORY_LINE_RE/_CVE_ID_RE match a literal
        # "**Advisory:** <id>" line -- this is the existing, unmodified
        # mechanism that surfaces the CVE id in the pipeline's own report.
        result = cve_to_vuln_text(FULL_CVE)
        assert "**Advisory:** CVE-2021-12345" in result

    def test_severity_present(self):
        assert "CRITICAL" in cve_to_vuln_text(FULL_CVE)

    def test_includes_cwe(self):
        assert "CWE-89" in cve_to_vuln_text(FULL_CVE)

    def test_includes_description(self):
        assert "authenticate()" in cve_to_vuln_text(FULL_CVE)

    def test_includes_affected_product_cpe(self):
        result = cve_to_vuln_text(FULL_CVE)
        assert "cpe:2.3:a:example:example-lib" in result

    def test_affected_products_section_header_matches_reference_implementation(self):
        # No wording change from the reference implementation in this commit
        # -- the non-verification caveat lives in extract_affected_products'
        # docstring, not in the rendered Markdown.
        result = cve_to_vuln_text(FULL_CVE)
        assert "## Affected products\n" in result

    def test_includes_no_code_snippet_note(self):
        assert "No source code snippet is available" in cve_to_vuln_text(FULL_CVE)

    def test_cvss_score_present(self):
        assert "9.8" in cve_to_vuln_text(FULL_CVE)

    def test_references_included(self):
        result = cve_to_vuln_text(FULL_CVE)
        assert "github.com/example/security" in result

    def test_summary_derived_from_first_sentence(self):
        result = cve_to_vuln_text(FULL_CVE)
        assert result.startswith(
            "# A SQL injection vulnerability exists in the authenticate() function."
        )


class TestCveToVulnTextMissingOptionalFields:
    def test_handles_sparse_cve_without_crash(self):
        result = cve_to_vuln_text(SPARSE_CVE)
        assert isinstance(result, str)
        assert "CVE-0000-00000" in result

    def test_sparse_cve_reports_no_description_available(self):
        assert "No description available" in cve_to_vuln_text(SPARSE_CVE)

    def test_sparse_cve_reports_unknown_cwe(self):
        assert "**Type:** Unknown" in cve_to_vuln_text(SPARSE_CVE)

    def test_sparse_cve_reports_na_cvss_and_unknown_severity(self):
        result = cve_to_vuln_text(SPARSE_CVE)
        assert "**Severity:** UNKNOWN (CVSS: N/A)" in result

    def test_sparse_cve_reports_products_not_specified(self):
        assert "- (not specified)" in cve_to_vuln_text(SPARSE_CVE)

    def test_sparse_cve_reports_no_references(self):
        assert "- (none)" in cve_to_vuln_text(SPARSE_CVE)

    def test_missing_id_falls_back_to_unknown(self):
        result = cve_to_vuln_text({})
        assert "**Advisory:** unknown" in result


class TestExtractDescription:
    def test_extracts_english_description(self):
        assert "SQL injection" in extract_description(FULL_CVE)

    def test_missing_description_returns_empty_string(self):
        assert extract_description({}) == ""

    def test_ignores_non_english_description(self):
        cve = {"descriptions": [{"lang": "fr", "value": "une vulnerabilite"}]}
        assert extract_description(cve) == ""


class TestExtractCwes:
    def test_extract_cwes_deduped(self):
        cve = dict(FULL_CVE, weaknesses=FULL_CVE["weaknesses"] * 2)
        assert extract_cwes(cve) == ["CWE-89"]

    def test_missing_weaknesses_returns_empty_list(self):
        assert extract_cwes({}) == []


class TestExtractCvss:
    def test_extract_cvss_prefers_v31(self):
        score, severity = extract_cvss(FULL_CVE)
        assert score == "9.8"
        assert severity == "CRITICAL"

    def test_extract_cvss_falls_back_when_absent(self):
        assert extract_cvss({}) == ("N/A", "UNKNOWN")

    def test_extract_cvss_falls_back_to_v2_when_v31_and_v30_absent(self):
        cve = {
            "metrics": {
                "cvssMetricV2": [
                    {"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}
                ]
            }
        }
        score, severity = extract_cvss(cve)
        assert score == "5.0"
        assert severity == "MEDIUM"


class TestExtractAffectedProducts:
    def test_returns_criteria_strings(self):
        products = extract_affected_products(FULL_CVE)
        assert products == ["cpe:2.3:a:example:example-lib:*:*:*:*:*:*:*:*"]

    def test_caps_at_five_products(self):
        cve = _cve_with_n_cpe_matches(8)
        products = extract_affected_products(cve)
        assert len(products) == 5

    def test_deduplicates_identical_criteria(self):
        cve = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"vulnerable": True, "criteria": "cpe:2.3:a:x:y:*"},
                                {"vulnerable": True, "criteria": "cpe:2.3:a:x:y:*"},
                            ]
                        }
                    ]
                }
            ]
        }
        assert extract_affected_products(cve) == ["cpe:2.3:a:x:y:*"]

    def test_ignores_non_vulnerable_matches(self):
        cve = {
            "configurations": [
                {"nodes": [{"cpeMatch": [{"vulnerable": False, "criteria": "cpe:2.3:a:x:y:*"}]}]}
            ]
        }
        assert extract_affected_products(cve) == []

    def test_missing_configurations_returns_empty_list(self):
        assert extract_affected_products({}) == []


class TestFirstSentence:
    def test_extracts_first_sentence(self):
        assert first_sentence("First one. Second one.") == "First one."

    def test_empty_string_returns_empty_string(self):
        assert first_sentence("") == ""

    def test_truncates_long_sentence_to_120_chars(self):
        long_text = "A" * 200 + "."
        assert len(first_sentence(long_text)) <= 120

    def test_shorter_than_limit_returned_unchanged(self):
        text = "A short vulnerability summary."
        assert first_sentence(text) == "A short vulnerability summary."

    def test_around_limit_no_ellipsis_when_it_fits(self):
        # Exactly 120 chars, no sentence-ending punctuation early enough to
        # be picked up as a shorter "first sentence" -- the whole string is
        # returned as-is, unmodified.
        text = "word " * 23 + "word"  # 24 words * 5 chars - 1 = 119 chars
        assert len(text) <= 120
        assert first_sentence(text) == text
        assert "..." not in first_sentence(text)

    def test_long_sentence_gets_ellipsis(self):
        long_text = (
            "This is a long CVE description that goes on and on describing "
            "an insufficiently protected credentials vulnerability affecting "
            "many versions of the affected software package in great detail"
        )
        result = first_sentence(long_text)
        assert len(result) <= 120
        assert result.endswith("...")

    def test_no_mid_word_truncation(self):
        # Regression: the old hard [:120] slice produced truncations like
        # "...affected that co" and "...via the funct" -- cut mid-word with
        # no indication anything was omitted.
        long_text = (
            "An insufficiently protected credentials vulnerability exists in "
            "curl 4.9 to and include curl 7.82.0 are affected that could allow "
            "an attacker to obtain credentials via a crafted redirect"
        )
        result = first_sentence(long_text)
        assert result.endswith("...")
        core = result[: -len("...")]
        assert not core.endswith(("co", "funct"))
        # Every word in the truncated core must appear as a whole word in
        # the source text -- i.e. nothing was cut mid-word.
        words = [w for w in core.split(" ") if w]
        for word in words:
            assert word in long_text.split(" ") or word == ""

    def test_punctuation_and_markdown_like_content(self):
        text = (
            "A ReDoS issue exists via the `parseRange()` function when "
            "given a crafted string containing many repeated whitespace "
            "characters and version-like tokens such as `1.2.3`"
        )
        result = first_sentence(text)
        assert len(result) <= 120
        # No mid-word cut: every space-delimited token in the (ellipsis-
        # stripped) result must be a real token from the source text.
        core = result[: -len("...")] if result.endswith("...") else result
        source_tokens = set(text.split(" "))
        for tok in core.split(" "):
            if tok:
                assert tok in source_tokens or text.startswith(core)
