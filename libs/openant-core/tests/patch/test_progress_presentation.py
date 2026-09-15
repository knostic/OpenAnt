"""Focused tests for the Auto Patcher terminal-output cleanup.

Deliberately semantic, not golden-snapshot: assertions check for the
presence/absence of structural markers (stage headers, status symbols,
specific decision text) and NEVER assert on the full byte-for-byte
contents of a captured stream -- see the module docstrings in
utilities/autopatcher/progress.py and pipeline.py's Recommendation
banner comment for why (the brief explicitly asks for "semantic
structure", not "giant golden-output snapshots").

Round 2 (presentation-only polish): existing tests that pinned the old
"[pipeline] Recommendation:" prefix and the raw "[pipeline] LLM mode:"
line were updated in test_pipeline.py/test_remediation_planner.py
directly -- that human-output contract intentionally changed. This file
adds the new coverage the round-2 brief asks for.

Covers:
  - progress.py's own verbosity/symbol/announce-once semantics in
    isolation (no pipeline needed).
  - pipeline.py's Decide-stage Recommendation banner for cases A/B/C/D,
    with the legacy "[pipeline] Recommendation:" prefix gone from
    default and present in verbose only.
  - A real, mocked-LLM `pipeline.run()` invocation's default/verbose/
    quiet stderr structure: stage numbering, no raw diagnostic leakage
    into default (no `[pipeline]`/`[Parser]` prefixes, no
    "Auto-detected language:"), provider/model announced exactly once,
    repository analysis announced exactly once even though the parser
    runs a second time internally during Post-Patch Investigation.
  - The repository parser's AUTOPATCHER_PARSER_QUIET gate and the
    suppress_summary_announcement() second-invocation gate, in isolation.
  - step_report.py's fatal-error presentation (case N).
  - run_traced.py's --json mode: exactly one machine-readable stdout
    result, no human progress on stderr.
"""

from __future__ import annotations

import os

import pytest

from utilities.autopatcher import progress


# ---------------------------------------------------------------------------
# progress.py in isolation
# ---------------------------------------------------------------------------

class TestProgressModule:
    def test_default_state_is_not_verbose_not_quiet(self):
        assert progress.is_verbose() is False
        assert progress.is_quiet() is False

    def test_quiet_wins_over_verbose(self):
        progress.configure(verbose=True, quiet=True)
        assert progress.is_quiet() is True
        assert progress.is_verbose() is False

    def test_success_warning_recovery_symbols(self, capsys):
        progress.configure()
        progress.success("ok thing")
        progress.warning("iffy thing")
        progress.recovery("fixed thing")
        progress.failure("broken thing")
        progress.skipped("skipped thing", reason="why")
        progress.info("fyi thing")
        err = capsys.readouterr().err
        assert "✓ ok thing" in err
        assert "⚠ iffy thing" in err
        assert "↻ fixed thing" in err
        assert "✗ broken thing" in err
        assert "– skipped thing: why" in err
        assert "ℹ fyi thing" in err

    def test_verbose_only_prints_in_verbose_mode(self, capsys):
        progress.configure(verbose=False)
        progress.verbose("[pipeline] detail nobody needs by default")
        assert capsys.readouterr().err == ""

        progress.configure(verbose=True)
        progress.verbose("[pipeline] detail nobody needs by default")
        assert "detail nobody needs by default" in capsys.readouterr().err

    def test_quiet_suppresses_stage_success_warning_header_banner(self, capsys):
        progress.configure(quiet=True)
        progress.stage(1, 5, "Analyze")
        progress.success("thing")
        progress.warning("thing")
        progress.header("Title", [("K", "V")])
        progress.banner(["line one", "line two"])
        assert capsys.readouterr().err == ""

    def test_fatal_is_never_suppressed_by_quiet(self, capsys):
        progress.configure(quiet=True)
        progress.fatal("Run failed: boom")
        err = capsys.readouterr().err
        assert "✗ Run failed: boom" in err

    def test_fatal_detail_only_printed_when_caller_passes_it(self, capsys):
        progress.configure()
        progress.fatal("Run failed: boom", detail="Traceback (most recent call last):\n...")
        err = capsys.readouterr().err
        assert "Traceback" in err

    def test_claim_model_announcement_fires_once(self):
        assert progress.claim_model_announcement("Anthropic", "claude-opus-4-8") is True
        assert progress.claim_model_announcement("Anthropic", "claude-opus-4-8") is False
        # A genuinely different (provider, model) is a new claim -- there is
        # no real fallback/switching in llm_client today, but the primitive
        # itself must not treat every pair as "already announced" forever.
        assert progress.claim_model_announcement("Anthropic", "claude-opus-4-9") is True

    def test_format_provider_model(self):
        assert progress.format_provider_model("Anthropic", "claude-opus-4-8") == "Anthropic · claude-opus-4-8"
        assert progress.format_provider_model("mock", "mock") == "Mock"

    def test_header_renders_title_divider_and_fields(self, capsys):
        progress.configure()
        progress.header("OpenAnt Auto Patcher", [("CVE", "CVE-2023-43804"), ("Model", "Anthropic · x")])
        err = capsys.readouterr().err
        assert "OpenAnt Auto Patcher" in err
        assert "CVE" in err and "CVE-2023-43804" in err
        assert "─" in err

    @pytest.fixture(autouse=True)
    def _reset(self):
        yield
        progress.reset_for_tests()


# ---------------------------------------------------------------------------
# Decide-stage Recommendation banner -- cases A/B/C/D
# ---------------------------------------------------------------------------

def _minimal_pipeline_result(tmp_path, *, patch, applicability=None):
    from utilities.autopatcher.pipeline import PipelineResult

    return PipelineResult(
        vulnerability_text="# Some vulnerability\n",
        patch=patch,
        review="ok review" if patch else "",
        score_text="0.8" if patch else "",
        challenger={},
        repo_root=tmp_path,
        applicability=applicability,
    )


class TestRecommendationBannerCases:
    """The legacy "[pipeline] Recommendation:" prefix is intentionally gone
    from the default human banner (round-2 presentation cleanup) -- it now
    shows only in verbose mode, as historical diagnostic context. Decision
    text itself (still exactly `trust_rec['decision']`/"NO PATCH PRODUCED")
    is unchanged; the default banner just uppercases it for display."""

    def test_case_d_no_patch_produced_banner(self, tmp_path, capsys):
        from utilities.autopatcher.pipeline import _build_report

        progress.configure()
        result = _minimal_pipeline_result(tmp_path, patch="")
        _build_report(result)
        err = capsys.readouterr().err

        assert "⚫ NO PATCH PRODUCED" in err
        assert "[pipeline] Recommendation:" not in err
        # Bordered: a divider line appears both above and below the banner.
        assert err.count("─" * 10) >= 2

    def test_case_c_do_not_apply_banner(self, tmp_path, monkeypatch, capsys):
        from utilities.autopatcher import pipeline as pl

        progress.configure()
        monkeypatch.setattr(
            pl, "_build_recommendation_v1",
            lambda *a, **k: {"decision": "Do Not Apply", "reason": "stub"},
        )
        patch = "--- a/f.py\n+++ b/f.py\n@@ -1,1 +1,1 @@\n-old\n+new\n"
        result = _minimal_pipeline_result(
            tmp_path, patch=patch,
            applicability={"applicable": True, "skipped": False, "skipped_reason": None, "error": None, "stderr": ""},
        )
        pl._build_report(result)
        err = capsys.readouterr().err

        assert "DO NOT APPLY" in err
        assert "🔴" in err
        assert "[pipeline] Recommendation:" not in err
        assert err.count("─" * 10) >= 2

    def test_case_a_deploy_after_validation_banner(self, tmp_path, monkeypatch, capsys):
        from utilities.autopatcher import pipeline as pl

        progress.configure()
        monkeypatch.setattr(
            pl, "_build_recommendation_v1",
            lambda *a, **k: {"decision": "Deploy After Validation", "reason": "stub"},
        )
        patch = "--- a/f.py\n+++ b/f.py\n@@ -1,1 +1,1 @@\n-old\n+new\n"
        result = _minimal_pipeline_result(
            tmp_path, patch=patch,
            applicability={"applicable": True, "skipped": False, "skipped_reason": None, "error": None, "stderr": ""},
        )
        pl._build_report(result)
        err = capsys.readouterr().err

        assert "DEPLOY AFTER VALIDATION" in err
        assert "🟢" in err

    def test_case_b_manual_review_required_banner(self, tmp_path, monkeypatch, capsys):
        from utilities.autopatcher import pipeline as pl

        progress.configure()
        monkeypatch.setattr(
            pl, "_build_recommendation_v1",
            lambda *a, **k: {"decision": "Manual Review Required", "reason": "stub"},
        )
        patch = "--- a/f.py\n+++ b/f.py\n@@ -1,1 +1,1 @@\n-old\n+new\n"
        result = _minimal_pipeline_result(
            tmp_path, patch=patch,
            applicability={"applicable": True, "skipped": False, "skipped_reason": None, "error": None, "stderr": ""},
        )
        pl._build_report(result)
        err = capsys.readouterr().err

        assert "MANUAL REVIEW REQUIRED" in err
        assert "🟠" in err

    def test_verbose_still_shows_legacy_recommendation_prefix(self, tmp_path, capsys):
        from utilities.autopatcher.pipeline import _build_report

        progress.configure(verbose=True)
        result = _minimal_pipeline_result(tmp_path, patch="")
        _build_report(result)
        err = capsys.readouterr().err

        assert "[pipeline] Recommendation:" in err
        assert "⚫ NO PATCH PRODUCED" in err

    def test_decide_stage_banner_and_trust_signals_line(self, tmp_path, capsys):
        from utilities.autopatcher.pipeline import _build_report

        progress.configure()
        result = _minimal_pipeline_result(tmp_path, patch="")
        _build_report(result)
        err = capsys.readouterr().err

        assert "[5/5] Decide" in err
        assert "✓ Trust signals evaluated" in err

    @pytest.fixture(autouse=True)
    def _reset(self):
        yield
        progress.reset_for_tests()


# ---------------------------------------------------------------------------
# Full pipeline.run() -- default / verbose / quiet stderr structure
# ---------------------------------------------------------------------------

def _run_mock_pipeline(vulnerability_text="XSS in login form"):
    import utilities.autopatcher.llm_client as llm_client
    from utilities.autopatcher.pipeline import run

    llm_client._cached_provider = None
    return run(vulnerability_text)


class TestFullRunDefaultVerboseQuiet:
    def test_default_shows_stage_numbers_and_no_raw_diagnostics(self, monkeypatch, capsys):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        progress.configure()

        _run_mock_pipeline()
        err = capsys.readouterr().err

        for stage_line in ("[1/5] Analyze", "[2/5] Prepare", "[3/5] Generate", "[4/5] Validate", "[5/5] Decide"):
            assert stage_line in err, f"missing {stage_line!r} in default stderr:\n{err}"

        # A real success/decision line is present -- default output is not
        # merely stage headers with nothing underneath them.
        assert "✓ Patch generated" in err
        assert "MANUAL REVIEW REQUIRED" in err or "DEPLOY" in err or "NO PATCH PRODUCED" in err

        # Raw diagnostic dumps must not leak into default output at all --
        # round 2: no bare "[pipeline] ...", no "[Parser] ...", no
        # "Auto-detected language:", no legacy Recommendation prefix, no
        # raw LLM-mode line.
        assert "failure_kind=None" not in err
        assert "failure_kind=" not in err
        assert "PARSING COMPLETE" not in err
        assert "PYTHON REPOSITORY PARSER" not in err
        assert "[pipeline]" not in err
        assert "[Parser]" not in err
        assert "Auto-detected language:" not in err
        assert "LLM mode:" not in err

        # Provider/model is announced exactly once, not once per LLM call
        # (several stages call the mock LLM in one run of this pipeline).
        assert err.count("Model") == 1

    def test_verbose_adds_detail_without_removing_default_lines(self, monkeypatch, capsys):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        progress.configure(verbose=True)

        _run_mock_pipeline()
        err = capsys.readouterr().err

        # Everything default shows is still present...
        assert "[1/5] Analyze" in err
        assert "✓ Patch generated" in err
        # ...plus verbose-only diagnostics: the raw LLM-mode line and at
        # least one other raw [pipeline]-prefixed diagnostic.
        assert "[pipeline] LLM mode:" in err
        assert "[pipeline]" in err

    def test_quiet_suppresses_all_progress(self, monkeypatch, capsys):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        progress.configure(quiet=True)

        _run_mock_pipeline()
        err = capsys.readouterr().err

        assert err == ""

    @pytest.fixture(autouse=True)
    def _reset(self):
        yield
        progress.reset_for_tests()


# ---------------------------------------------------------------------------
# "Target context ready" shows the resolved target file/symbol -- tiny
# presentation improvement, no new data plumbing (see remediation_planner.
# ReadyEdit.file/.symbol, already computed by check_edit_readiness()).
# ---------------------------------------------------------------------------

class TestTargetContextReadyShowsTargetFile:
    def test_shows_file_and_symbol_alongside_edits_ready_count(self, capsys):
        from unittest import mock
        from utilities.autopatcher import pipeline as pl
        from utilities.autopatcher.remediation_planner import (
            EditReadinessResult, IntendedEdit, ReadyEdit,
        )

        progress.configure()

        intended = IntendedEdit(file="src/urllib3/util/retry.py", symbol="Retry")
        ready = ReadyEdit(
            edit=intended, role="edit_target",
            file="src/urllib3/util/retry.py", symbol="Retry",
        )
        readiness = EditReadinessResult(
            strategy_ready=True, edit_source_ready=True,
            intended_edits=[intended], ready_edits=[ready],
            unready_edits=[], failure_reasons=[],
        )
        slice_result = mock.MagicMock(
            rendered="some content", warning_text="", coverage_complete=True,
            covered_target_files=["src/urllib3/util/retry.py"], covered_target_symbols=["Retry"],
            uncovered_target_files=[], uncovered_target_symbols=[],
        )
        strategy_result = mock.MagicMock(
            target_files=["src/urllib3/util/retry.py"], target_symbols=["Retry"], evaluated=True,
        )

        with (
            mock.patch("utilities.autopatcher.remediation_planner.build_final_target_slice",
                       return_value=slice_result),
            mock.patch("utilities.autopatcher.remediation_planner.build_intended_edits",
                       return_value=[intended]),
            mock.patch("utilities.autopatcher.remediation_planner.check_edit_readiness",
                       return_value=readiness),
        ):
            pl._run_guided_context_acquisition(
                vulnerability_text="x", llm=mock.MagicMock(), repo_root="/tmp/urllib3-eval",
                budget_controller=None, _strategy_result=strategy_result,
                _plan_result=None, _investigation_context=None,
            )

        err = capsys.readouterr().err
        assert "✓ Target context ready" in err
        assert "src/urllib3/util/retry.py · Retry" in err
        assert "Edits ready: 1/1" in err

    def test_falls_back_to_file_only_when_symbol_is_absent(self, capsys):
        from unittest import mock
        from utilities.autopatcher import pipeline as pl
        from utilities.autopatcher.remediation_planner import (
            EditReadinessResult, IntendedEdit, ReadyEdit,
        )

        progress.configure()

        intended = IntendedEdit(file="setup.py", symbol=None)
        ready = ReadyEdit(edit=intended, role="edit_target", file="setup.py", symbol=None)
        readiness = EditReadinessResult(
            strategy_ready=True, edit_source_ready=True,
            intended_edits=[intended], ready_edits=[ready],
            unready_edits=[], failure_reasons=[],
        )
        slice_result = mock.MagicMock(
            rendered="some content", warning_text="", coverage_complete=True,
            covered_target_files=["setup.py"], covered_target_symbols=[],
            uncovered_target_files=[], uncovered_target_symbols=[],
        )
        strategy_result = mock.MagicMock(target_files=["setup.py"], target_symbols=[], evaluated=True)

        with (
            mock.patch("utilities.autopatcher.remediation_planner.build_final_target_slice",
                       return_value=slice_result),
            mock.patch("utilities.autopatcher.remediation_planner.build_intended_edits",
                       return_value=[intended]),
            mock.patch("utilities.autopatcher.remediation_planner.check_edit_readiness",
                       return_value=readiness),
        ):
            pl._run_guided_context_acquisition(
                vulnerability_text="x", llm=mock.MagicMock(), repo_root="/tmp/urllib3-eval",
                budget_controller=None, _strategy_result=strategy_result,
                _plan_result=None, _investigation_context=None,
            )

        err = capsys.readouterr().err
        assert "✓ Target context ready" in err
        assert "setup.py" in err
        assert "setup.py · " not in err

    @pytest.fixture(autouse=True)
    def _reset(self):
        yield
        progress.reset_for_tests()


# ---------------------------------------------------------------------------
# Repository parser verbosity gate (isolated, no pipeline needed)
# ---------------------------------------------------------------------------

class TestParserVerbosityGate:
    def _parse(self, repo_root, output_dir, suppress_summary=False):
        import sys
        parser_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "parsers", "python",
        )
        if parser_dir not in sys.path:
            sys.path.insert(0, parser_dir)
        from parsers.python.parse_repository import parse_repository
        return parse_repository(
            str(repo_root), {"output_dir": str(output_dir), "suppress_summary": suppress_summary},
        )

    def _write_tiny_repo(self, root):
        f = root / "m.py"
        f.write_text("def f():\n    return 1\n", encoding="utf-8")

    def test_default_shows_full_phase_report(self, tmp_path, capsys, monkeypatch):
        monkeypatch.delenv("AUTOPATCHER_PARSER_QUIET", raising=False)
        repo = tmp_path / "repo"
        repo.mkdir()
        self._write_tiny_repo(repo)
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        self._parse(repo, out_dir)
        err = capsys.readouterr().err

        assert "PYTHON REPOSITORY PARSER" in err
        assert "PARSING COMPLETE" in err
        assert "[Phase 1]" in err

    def test_quiet_env_var_shows_compact_summary_instead(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("AUTOPATCHER_PARSER_QUIET", "1")
        repo = tmp_path / "repo"
        repo.mkdir()
        self._write_tiny_repo(repo)
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        self._parse(repo, out_dir)
        err = capsys.readouterr().err

        assert "PYTHON REPOSITORY PARSER" not in err
        assert "PARSING COMPLETE" not in err
        assert "[Phase 1]" not in err
        assert "✓ Repository analyzed" in err
        assert "Python ·" in err
        assert "files ·" in err and "functions ·" in err and "classes" in err

    def test_suppress_summary_hides_even_the_compact_line(self, tmp_path, capsys, monkeypatch):
        """The second (internal, Post-Patch Investigation) parse must
        produce NO summary line at all in default mode -- see
        core.parser_adapter.suppress_summary_announcement()."""
        monkeypatch.setenv("AUTOPATCHER_PARSER_QUIET", "1")
        repo = tmp_path / "repo"
        repo.mkdir()
        self._write_tiny_repo(repo)
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        self._parse(repo, out_dir, suppress_summary=True)
        err = capsys.readouterr().err

        assert err == ""

    def test_suppress_summary_does_not_affect_verbose_output(self, tmp_path, capsys, monkeypatch):
        """Verbose may still expose the complete second parser execution
        -- suppress_summary must be a no-op when AUTOPATCHER_PARSER_QUIET
        is unset."""
        monkeypatch.delenv("AUTOPATCHER_PARSER_QUIET", raising=False)
        repo = tmp_path / "repo"
        repo.mkdir()
        self._write_tiny_repo(repo)
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        self._parse(repo, out_dir, suppress_summary=True)
        err = capsys.readouterr().err

        assert "PYTHON REPOSITORY PARSER" in err
        assert "PARSING COMPLETE" in err


class TestParserAdapterSuppressionContextManager:
    """core.parser_adapter.suppress_summary_announcement() is the
    generic, presentation-only primitive pipeline.py's Post-Patch
    Investigation uses around its second build_investigation_context()
    call -- tested here directly against the real (module-level) shared
    parser_adapter, not re-derived."""

    def test_context_manager_suppresses_then_restores(self, tmp_path, capsys, monkeypatch):
        from core.parser_adapter import parse_repository, suppress_summary_announcement

        monkeypatch.setenv("AUTOPATCHER_PARSER_QUIET", "1")
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "m.py").write_text("def f():\n    return 1\n", encoding="utf-8")

        out_dir_1 = tmp_path / "out1"
        with suppress_summary_announcement():
            parse_repository(str(repo), str(out_dir_1), language="python", processing_level="all")
        suppressed_err = capsys.readouterr().err
        assert suppressed_err == ""

        out_dir_2 = tmp_path / "out2"
        parse_repository(str(repo), str(out_dir_2), language="python", processing_level="all")
        unsuppressed_err = capsys.readouterr().err
        assert "✓ Repository analyzed" in unsuppressed_err

    @pytest.fixture(autouse=True)
    def _reset(self):
        yield
        progress.reset_for_tests()


# ---------------------------------------------------------------------------
# End-to-end: initial repository analysis announced once, post-patch
# analysis (second, internal parser invocation) never re-announces it.
# ---------------------------------------------------------------------------

class TestNoDuplicateRepositoryAnalyzedAcrossPostPatchInvestigation:
    """Forces a real second build_investigation_context() call (Post-Patch
    Investigation) by mocking apply_patch() to report success against a
    real, tiny on-disk git repo -- proving the suppression wired into
    pipeline.py actually reaches the second parser invocation, not just
    the isolated unit tests above."""

    def _write_repo(self, root):
        import subprocess
        auth = root / "app" / "auth.py"
        auth.parent.mkdir(parents=True)
        auth.write_text(
            "def authenticate():\n"
            "    pass\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "init"], cwd=root, capture_output=True)
        subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=root, capture_output=True)
        subprocess.run(["git", "config", "user.name", "T"], cwd=root, capture_output=True)
        subprocess.run(["git", "add", "-A"], cwd=root, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=root, capture_output=True)

    def test_repository_analyzed_appears_once_post_patch_appears_once(self, tmp_path, monkeypatch, capsys):
        from unittest import mock
        from utilities.autopatcher.patch_applicability import PatchApplicationResult

        repo_root = tmp_path / "repo"
        self._write_repo(repo_root)

        diff = (
            "```diff\n--- a/app/auth.py\n+++ b/app/auth.py\n"
            "@@ -1,2 +1,3 @@\n def authenticate():\n+    pass\n     pass\n```"
        )

        monkeypatch.setenv("LLM_PROVIDER", "mock")
        # This test calls pipeline.run() directly (for fine control over
        # apply_patch), bypassing core/patch.py -- which is what normally
        # sets AUTOPATCHER_PARSER_QUIET outside --verbose (see
        # core/patch.py's own comment at that call site). Set it here to
        # simulate that production wiring instead of re-testing it.
        monkeypatch.setenv("AUTOPATCHER_PARSER_QUIET", "1")
        progress.configure()

        import utilities.autopatcher.pipeline as _pipeline_mod
        import tempfile
        investigation_dir = tempfile.mkdtemp(prefix="dup-summary-")

        with (
            mock.patch("utilities.autopatcher.pipeline.LLMClient"),
            mock.patch("utilities.autopatcher.pipeline.generate_patch_raw", return_value=diff),
            mock.patch("utilities.autopatcher.pipeline.generate_patch", return_value=diff),
            mock.patch("utilities.autopatcher.patch_applicability.check_applicability",
                       return_value={"applicable": True, "skipped": False, "stderr": "",
                                     "exit_code": 0, "skipped_reason": None, "error": None}),
            mock.patch("utilities.autopatcher.patch_applicability.apply_patch",
                       return_value=PatchApplicationResult(applied=True, exit_code=0, error=None)),
            mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok review"),
            mock.patch("utilities.autopatcher.pipeline.challenge_patch", return_value={}),
            mock.patch("utilities.autopatcher.pipeline.calibrate_findings", return_value=[]),
            mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="0.8"),
            mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
            mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
        ):
            _pipeline_mod.run(
                "# SQL Injection\n\nSee `app/auth.py`, function `authenticate`.\n",
                api_key="", repo_root=str(repo_root),
                investigation_output_dir=investigation_dir,
            )

        err = capsys.readouterr().err
        assert err.count("✓ Repository analyzed") == 1
        assert err.count("✓ Post-patch analysis completed") <= 1

    @pytest.fixture(autouse=True)
    def _reset(self):
        yield
        progress.reset_for_tests()


# ---------------------------------------------------------------------------
# Fatal error presentation (case N) -- core/step_report.py
# ---------------------------------------------------------------------------

class TestFatalErrorPresentation:
    def test_patch_step_default_is_concise_no_traceback(self, tmp_path, capsys):
        from core.step_report import step_context

        progress.configure()
        with pytest.raises(RuntimeError):
            with step_context("patch", str(tmp_path)) as ctx:
                raise RuntimeError("boom")

        err = capsys.readouterr().err
        assert "✗ Run failed: boom" in err
        assert "Traceback" not in err

    def test_patch_step_verbose_includes_traceback(self, tmp_path, capsys):
        from core.step_report import step_context

        progress.configure(verbose=True)
        with pytest.raises(RuntimeError):
            with step_context("patch", str(tmp_path)) as ctx:
                raise RuntimeError("boom")

        err = capsys.readouterr().err
        assert "✗ Run failed: boom" in err
        assert "Traceback (most recent call last):" in err

    def test_json_envelope_error_content_unchanged(self, tmp_path):
        """The error() envelope core.schemas/openant.cli builds from
        StepReport.errors is untouched by the presentation cleanup --
        this only changes what a human watching the terminal sees."""
        from core.step_report import step_context

        with pytest.raises(RuntimeError):
            with step_context("patch", str(tmp_path)) as ctx:
                raise RuntimeError("boom")

        import json
        report = json.loads((tmp_path / "patch.report.json").read_text())
        assert report["status"] == "error"
        assert report["errors"] == ["boom"]

    def test_other_steps_keep_unconditional_traceback_unchanged(self, tmp_path, capsys):
        """Non-`patch` steps (parse/analyze/scan/...) share step_context
        too -- their behavior must be byte-for-byte unchanged: unconditional
        `[{step}] ERROR: ...` plus a full traceback, regardless of
        progress.py's verbosity state."""
        from core.step_report import step_context

        progress.configure()  # default -- would suppress a `patch` traceback
        with pytest.raises(RuntimeError):
            with step_context("parse", str(tmp_path)) as ctx:
                raise RuntimeError("boom")

        err = capsys.readouterr().err
        assert "[parse] ERROR: boom" in err
        assert "Traceback (most recent call last):" in err

    @pytest.fixture(autouse=True)
    def _reset(self):
        yield
        progress.reset_for_tests()


