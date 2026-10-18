"""Regression tests for F-01: pipeline.run() must not fall back to
Path.cwd() when no repository root is provided.

Repository-dependent evidence (Impact Surface, Test Support) must be
treated as unavailable -- routed through the existing F-23/F-24 trust
policy ("Not Verified"/"unavailable") -- rather than silently analyzing
whatever directory the process happens to run in.

Every end-to-end test here deliberately runs from a temp cwd seeded with
decoy files, so a regression that reintroduces a Path.cwd() fallback would
make these tests fail regardless of the *real* working directory the test
suite happens to run from.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from utilities.autopatcher.pipeline import _compute_trust_signals, run

EXAMPLES_DIR = Path(__file__).parent / "fixtures" / "examples"
_VULN_TEXT = (EXAMPLES_DIR / "vulnerability.md").read_text(encoding="utf-8")

_NOT_EVALUATED_TEXT = "Not evaluated — no repository root was provided."


def _seed_decoy_cwd(tmp_path: Path) -> None:
    """Populate tmp_path with files that would only appear in a report if
    something fell back to scanning the process's cwd -- e.g. a
    Path.cwd() fallback re-added to pipeline.py.

    `authenticate` matches a symbol name from the vulnerability fixture
    (fixtures/examples/vulnerability.md references app/auth.py's
    `authenticate()`), so a cwd-based Impact Surface scan would find and
    quote this file as "usage evidence".
    """
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_decoy_should_never_appear.py").write_text(
        "def test_decoy(): pass\n", encoding="utf-8"
    )
    (tmp_path / "decoy_module_should_never_appear.py").write_text(
        "def authenticate(username, password):\n    return True\n",
        encoding="utf-8",
    )


@pytest.fixture
def decoy_cwd(tmp_path, monkeypatch):
    """A cwd containing files that must never leak into a repo_root=None
    report. Fixture (not a bare tmp_path use) so every test in this file
    runs from a *different* real directory each time -- the fix must hold
    regardless of what the actual process cwd is."""
    _seed_decoy_cwd(tmp_path)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _run_without_repo_root(monkeypatch) -> str:
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    return run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=None)


class TestNoCwdFallback:
    """The core regression: repo_root=None must never scan the process cwd."""

    def test_decoy_files_never_appear_in_report(self, decoy_cwd, monkeypatch):
        report = _run_without_repo_root(monkeypatch)
        assert "test_decoy_should_never_appear.py" not in report
        assert "decoy_module_should_never_appear.py" not in report

    def test_decoy_cwd_path_never_appears_in_report(self, decoy_cwd, monkeypatch):
        report = _run_without_repo_root(monkeypatch)
        assert str(decoy_cwd) not in report

    def test_result_independent_of_cwd_identity(self, tmp_path, monkeypatch):
        """Running from two different decoy cwds must produce the same
        repository-dependent sections -- proving neither run is reading
        cwd content into the report."""
        cwd_a = tmp_path / "a"
        cwd_b = tmp_path / "b"
        cwd_a.mkdir()
        cwd_b.mkdir()
        _seed_decoy_cwd(cwd_a)
        _seed_decoy_cwd(cwd_b)
        (cwd_b / "extra_marker_file.py").write_text("MARKER = 1\n", encoding="utf-8")

        monkeypatch.chdir(cwd_a)
        report_a = _run_without_repo_root(monkeypatch)
        monkeypatch.chdir(cwd_b)
        report_b = _run_without_repo_root(monkeypatch)

        assert "extra_marker_file.py" not in report_b
        for report in (report_a, report_b):
            # Repository Context + Impact Surface + Test Support
            assert report.count(_NOT_EVALUATED_TEXT) == 3


class TestExplicitNotEvaluatedMessaging:
    """F-01 item 4: sections must state the gap explicitly, not omit it."""

    def test_impact_surface_states_not_evaluated(self, decoy_cwd, monkeypatch):
        report = _run_without_repo_root(monkeypatch)
        idx = report.find("## Impact Surface")
        assert idx != -1, "Impact Surface section must still be present"
        section = report[idx: idx + 300]
        assert _NOT_EVALUATED_TEXT in section

    def test_test_support_states_not_evaluated(self, decoy_cwd, monkeypatch):
        report = _run_without_repo_root(monkeypatch)
        idx = report.find("### Test Support")
        assert idx != -1, "Test Support section must still be present"
        section = report[idx: idx + 300]
        assert _NOT_EVALUATED_TEXT in section
        # Must not show the populated-section fields with fabricated values.
        assert "Total test files found:" not in section

    def test_trust_signals_table_marks_both_signals_not_verified(self, decoy_cwd, monkeypatch):
        report = _run_without_repo_root(monkeypatch)
        assert "No repository root was provided" in report

    def test_repository_context_states_not_evaluated_not_zero_selection(self, decoy_cwd, monkeypatch):
        """Repository Context must say grounding was never attempted, not
        reuse _render_repository_context_section's zero-selection sentence
        ("No repository locations were identified...") -- that sentence
        also covers "grounding ran and found nothing", so reusing it here
        would read as if a repository search happened and came up empty."""
        report = _run_without_repo_root(monkeypatch)
        idx = report.find("## Repository Context")
        assert idx != -1, "Repository Context section must still be present"
        section = report[idx: idx + 300]
        assert _NOT_EVALUATED_TEXT in section
        assert "No repository locations were identified" not in section

    def test_recommendation_never_deploy_after_validation(self, decoy_cwd, monkeypatch):
        """Deployment Safety is forced to Not Verified when no repo_root is
        given (impact analysis is skipped, not run against the wrong root),
        which the existing F-37 whitelist gate already excludes from
        Deploy After Validation -- this must hold even though decoy_cwd
        contains files that would otherwise look like real evidence."""
        report = _run_without_repo_root(monkeypatch)
        assert "**Deploy After Validation**" not in report


class TestComputeTrustSignalsNotVerifiedRating:
    """Unit-level coverage for the new testing_rating="Not Verified" branch
    added to _compute_trust_signals (mirrors test_trust_package.py's style)."""

    @staticmethod
    def _applicability_clean():
        return {"applicable": True, "skipped": False, "skipped_reason": None, "error": None, "stderr": ""}

    @staticmethod
    def _classified():
        return {"still_vulnerable": False, "confirmed_defect_count": 0, "plausible_risk_count": 0, "validation_gap_count": 0}

    def test_test_availability_not_verified_for_missing_repo_root(self):
        signals = _compute_trust_signals(
            [], self._applicability_clean(), self._classified(), "Not Verified", "unavailable"
        )
        assert signals["test_availability"]["value"] == "Not Verified"
        assert signals["test_availability"]["notes"] == "No repository root was provided"

    def test_test_availability_not_verified_distinct_from_no_tests_found(self):
        """"Not Verified" (no repo_root -- nothing was searched) must never
        collapse into "No Tests Found" (a search ran and found nothing) --
        those are different claims about different amounts of evidence."""
        not_verified = _compute_trust_signals(
            [], self._applicability_clean(), self._classified(), "Not Verified", "unavailable"
        )
        no_tests_found = _compute_trust_signals(
            [], self._applicability_clean(), self._classified(), "None", "low"
        )
        assert not_verified["test_availability"]["value"] != no_tests_found["test_availability"]["value"]

    def test_deployment_safety_not_verified_when_impact_unavailable(self):
        signals = _compute_trust_signals(
            [], self._applicability_clean(), self._classified(), "Not Verified", "unavailable"
        )
        assert signals["deployment_safety"]["value"] == "Not Verified"
