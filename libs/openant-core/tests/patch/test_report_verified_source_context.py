"""PR #763 review: the Repository Context section must not say "No repository
locations were identified" when the model was in fact given repository source
through the Planner's verified-source route (which has no Repository Grounding
location of its own) -- and must not claim that unless a completed LLM call
actually carried that source.
"""

from __future__ import annotations

from unittest import mock

from utilities.autopatcher import pipeline as pipeline_mod
from utilities.autopatcher.pipeline import _render_repository_context_section, _verified_source_files
from utilities.autopatcher.remediation_planner import (
    PlannerEvidenceResult,
    RemediationPlanResult,
    RemediationStrategyResult,
    _SourceExcerptPlan,
)

_VULN_TEXT = "# Test vulnerability\n\nSome description of a vulnerability for testing.\n"
_NO_LOCATIONS = "No repository locations were identified"
_SWIFT_BLOCK = (
    "#### Verified source: `Sources/Files.swift` (full file, 3 lines)\n\n"
    "```swift\nfunc move() {\n    try fm.moveItem(at: a, to: b)\n}\n```\n"
)


class TestRepositoryContextSection:
    def test_no_evidence_keeps_the_original_sentence(self):
        section = _render_repository_context_section(None)
        assert _NO_LOCATIONS in section

    def test_verified_source_is_reported_instead(self):
        section = _render_repository_context_section(None, verified_source_files=("Sources/Files.swift",))
        assert _NO_LOCATIONS not in section
        assert "identified no locations" in section
        assert "- `Sources/Files.swift`" in section

    def test_files_are_read_from_verified_source_headings_only(self):
        context = _SWIFT_BLOCK + "#### Verified source: `pkg/a.py:handle` (lines 1–3)\n\n```python\nx\n```\n"
        assert _verified_source_files(context, "", context) == ("Sources/Files.swift", "pkg/a.py")
        assert _verified_source_files("#### Target definition: `pkg/b.py:f` (lines 1–2)\n") == ()


def _evidence():
    return PlannerEvidenceResult(
        rendered=_SWIFT_BLOCK,
        excerpt_plan=_SourceExcerptPlan(
            blocks=(_SWIFT_BLOCK,), included_labels=frozenset({"Sources/Files.swift"}),
            symbol_omitted=(), fallback_omitted=(), read_failed=(),
            budget=4_000, omitted_sizes={}, omission_reason={},
        ),
    )


def _plan():
    return RemediationPlanResult(
        rendered="## Target Discovery Plan\n", target_files=["Sources/Files.swift"], target_symbols=[],
        narrower_alternative_decision=None, narrower_alternative_considered=None,
        additional_evidence_required="explicit_false",
    )


def _strategy(evaluated):
    return RemediationStrategyResult(
        rendered="", target_files=[], target_symbols=[], warnings=[], extended_mechanism=None,
        required_edits=[], security_invariant=None, insufficient_evidence=[], evaluated=evaluated,
    )


def _report(tmp_path, strategy):
    with (
        mock.patch("utilities.autopatcher.remediation_planner.generate_remediation_plan", return_value=_plan()),
        mock.patch("utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                   return_value=_evidence()),
        mock.patch("utilities.autopatcher.remediation_planner.generate_remediation_strategy", return_value=strategy),
    ):
        return pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))


class TestPipelineReportsWhatTheModelWasGiven:
    """End to end through pipeline.run() (no repository locations exist in an
    empty repository; the verified source arrives only via Planner evidence)."""

    def test_source_given_to_the_strategy_is_reported(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        report = _report(tmp_path, _strategy(evaluated=True))
        assert _NO_LOCATIONS not in report
        assert "- `Sources/Files.swift`" in report

    def test_source_never_confirmed_received_is_not_claimed(self, tmp_path, monkeypatch):
        """The Strategy call failed (unevaluated): nothing confirms the model
        saw the excerpt, so the report keeps the no-locations sentence."""
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        report = _report(tmp_path, _strategy(evaluated=False))
        assert _NO_LOCATIONS in report
        assert "Sources/Files.swift" not in report.split("## Repository Context", 1)[1].split("\n---", 1)[0]
