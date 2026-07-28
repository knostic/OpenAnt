"""Characterization tests for the InvestigationCase adapter.

Ported from the standalone Auto Patcher project's test_investigation_adapters.py,
trimmed to TestCaseFromVulnerabilityText -- the only class covering a
function this package still has (case_from_vulnerability_text). The
GHSA/CVE adapter classes and the evidence-collection classes tested
functionality that was excluded during the merge into OpenAnt (see
utilities/autopatcher/investigation_adapters.py's module docstring).

These tests prove the one guarantee that matters here: an InvestigationCase
built from a rendered vulnerability_text projects back to byte-identical
text -- core/patch.py's render_vulnerability_markdown() output must reach
the patch engine unchanged.
"""

from __future__ import annotations

from pathlib import Path

EXAMPLE_FILE = Path(__file__).parent / "fixtures" / "examples" / "vulnerability.md"


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
