"""Characterization tests for the InvestigationCase adapters.

Ported from the standalone Auto Patcher project's test_investigation_adapters.py.
TestCaseFromVulnerabilityText covers case_from_vulnerability_text (file mode,
i.e. core/patch.py's rendered Finding markdown). TestCaseFromCve covers
case_from_cve, added to support patching directly from a known CVE
identifier. The GHSA adapter and the evidence-collection classes tested
functionality that was excluded during the merge into OpenAnt (see
utilities/autopatcher/investigation_adapters.py's module docstring).

These tests prove the one guarantee that matters here: an InvestigationCase
built from either input projects back to byte-identical text -- for
case_from_vulnerability_text, core/patch.py's render_vulnerability_markdown()
output; for case_from_cve, cve_converter.cve_to_vuln_text()'s output. Neither
must be altered en route to the patch engine.
"""

from __future__ import annotations

from pathlib import Path

EXAMPLE_FILE = Path(__file__).parent / "fixtures" / "examples" / "vulnerability.md"

FIXTURE_CVE = {
    "id": "CVE-2021-12345",
    "descriptions": [
        {"lang": "en", "value": "A SQL injection vulnerability exists in the authenticate() function."}
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
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:example:example-lib:*:*:*:*:*:*:*:*",
                        }
                    ]
                }
            ]
        }
    ],
    "references": [{"url": "https://example.com/advisory", "source": "nvd@nist.gov"}],
}


class TestCaseFromVulnerabilityText:
    def test_round_trips_example_file_byte_identical(self):
        from utilities.autopatcher.investigation_adapters import case_from_vulnerability_text

        original = EXAMPLE_FILE.read_text(encoding="utf-8")
        case = case_from_vulnerability_text(original, repo_root=Path("/tmp/repo"))
        projection = case.to_context_projection()

        assert projection.vulnerability_text == original
        assert projection.repo_root == Path("/tmp/repo")

    def test_repo_root_optional(self):
        from utilities.autopatcher.investigation_adapters import case_from_vulnerability_text

        case = case_from_vulnerability_text("# Some vuln\n\nDetails.")
        assert case.to_context_projection().repo_root is None

    def test_framing_summary_extracted(self):
        from utilities.autopatcher.investigation_adapters import case_from_vulnerability_text

        case = case_from_vulnerability_text("# SQL Injection Vulnerability\n\nDetails.")
        assert case.framing.summary == "SQL Injection Vulnerability"

    def test_raw_artifact_preserves_source_type_and_text(self):
        from utilities.autopatcher.investigation_adapters import case_from_vulnerability_text

        text = "# Vuln\n\nDetails."
        case = case_from_vulnerability_text(text)
        assert case.raw_artifact.source_type == "vulnerability_text"
        assert case.raw_artifact.raw_text == text


class TestCaseFromCve:
    def test_projection_byte_identical_to_cve_to_vuln_text(self):
        from utilities.autopatcher.cve_converter import cve_to_vuln_text
        from utilities.autopatcher.investigation_adapters import case_from_cve

        case = case_from_cve(FIXTURE_CVE, repo_root=Path("/tmp/repo"))
        projection = case.to_context_projection()

        assert projection.vulnerability_text == cve_to_vuln_text(FIXTURE_CVE)
        assert projection.repo_root == Path("/tmp/repo")

    def test_repo_root_optional(self):
        from utilities.autopatcher.investigation_adapters import case_from_cve

        case = case_from_cve(FIXTURE_CVE)
        assert case.to_context_projection().repo_root is None

    def test_raw_artifact_preserves_source_type_url_and_structured_payload(self):
        from utilities.autopatcher.investigation_adapters import case_from_cve

        case = case_from_cve(FIXTURE_CVE)
        assert case.raw_artifact.source_type == "cve"
        assert case.raw_artifact.source_url == "https://nvd.nist.gov/vuln/detail/CVE-2021-12345"
        assert case.raw_artifact.structured_payload == FIXTURE_CVE

    def test_raw_artifact_source_url_none_when_id_missing(self):
        from utilities.autopatcher.investigation_adapters import case_from_cve

        case = case_from_cve({})
        assert case.raw_artifact.source_url is None

    def test_framing_extracted_from_cve(self):
        from utilities.autopatcher.investigation_adapters import case_from_cve

        case = case_from_cve(FIXTURE_CVE)
        assert case.framing.cwes == ["CWE-89"]
        assert case.framing.severity == "CRITICAL"
        assert case.framing.packages == [{"cpe": "cpe:2.3:a:example:example-lib:*:*:*:*:*:*:*:*"}]
        assert "SQL injection" in case.framing.summary or "authenticate" in case.framing.summary

    def test_evidence_stays_empty(self):
        from utilities.autopatcher.investigation_adapters import case_from_cve

        case = case_from_cve(FIXTURE_CVE, repo_root=Path("/tmp/repo"))
        assert case.evidence == []

    def test_handles_sparse_cve_without_crash(self):
        from utilities.autopatcher.investigation_adapters import case_from_cve

        case = case_from_cve({"id": "CVE-0000-00000"})
        projection = case.to_context_projection()
        assert "CVE-0000-00000" in projection.vulnerability_text
        assert case.framing.cwes == []
        assert case.framing.packages == []
