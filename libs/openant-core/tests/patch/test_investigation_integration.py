"""Integration tests for the live Repository Understanding wiring.

Covers the orchestration boundary approved for this phase:

    ground_repository() -> select_candidates() -> build_investigation_context()
    -> enrich_candidates() -> fuse_evidence() -> render_repository_understanding()

now running once inside pipeline.run() (reusing the single existing
ground_repository() call) and reaching generate_patch()'s code_context.
core/patch.py-level coverage (repo_root normalization, the run-scoped
investigation directory) lives in test_run_patch_cve.py and
test_patch_wrapper_contract.py instead, alongside each entry point's other
contract tests.

Hermetic: LLM_PROVIDER=mock, no network, real (but tiny) on-disk repos under
tmp_path so ground_repository()/parse_repository() have real, deterministic
work to do.
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import utilities.autopatcher.candidate_enrichment as _ce_mod
import utilities.autopatcher.candidate_selection as _cs_mod
import utilities.autopatcher.evidence_fusion as _ef_mod
import utilities.autopatcher.patch_generator as _pg_mod
from utilities.autopatcher.pipeline import run as pipeline_run

EXAMPLES_DIR = Path(__file__).parent / "fixtures" / "examples"
_VULN_TEXT = (EXAMPLES_DIR / "vulnerability.md").read_text(encoding="utf-8")


def _write_auth_repo(root: Path) -> None:
    """A tiny real repo matching fixtures/examples/vulnerability.md's
    explicit `app/auth.py` / `authenticate()` reference -- gives
    ground_repository() a real, strong-tier (explicit_path) candidate to
    select, and the parser a real function to resolve."""
    auth = root / "app" / "auth.py"
    auth.parent.mkdir(parents=True)
    auth.write_text(
        "import sqlite3\n\n"
        "db = sqlite3.connect(\"users.db\")\n\n"
        "def authenticate(username, password):\n"
        "    query = f\"SELECT * FROM users WHERE username='{username}'\"\n"
        "    return db.execute(query).fetchone() is not None\n",
        encoding="utf-8",
    )


def _capture_generate_patch():
    """Patch pipeline.generate_patch_raw to record (vulnerability_text,
    code_context) while still delegating to the real (mock-LLM)
    implementation, mirroring test_pipeline.py's TestPipelineCodeContext
    convention.

    Release: response-contract enforcement moved the initial generation
    call site (Site 1, what this helper's callers all exercise) from
    generate_patch() to _generate_patch_with_contract_check() ->
    generate_patch_raw() (both defined in pipeline.py) -- generate_patch()
    itself is defined in patch_generator.py and resolves its own internal
    generate_patch_raw() call against THAT module's namespace, so patching
    "pipeline.generate_patch" no longer intercepts Site 1 at all; this now
    patches the actual entry point Site 1 uses.
    """
    captured: list[dict] = []
    original = _pg_mod.generate_patch_raw

    def _capturing(vtext, llm, code_context="", retry_hint="", stage="patch_generation"):
        captured.append({"vulnerability_text": vtext, "code_context": code_context})
        return original(vtext, llm, code_context=code_context, retry_hint=retry_hint, stage=stage)

    return mock.patch("utilities.autopatcher.pipeline.generate_patch_raw", side_effect=_capturing), captured


class TestInvestigationRunsOnce:
    """Each investigation stage must run exactly once per pipeline.run()
    call -- no duplicate grounding, no duplicate parsing, no repeated
    candidate selection."""

    def test_each_stage_called_exactly_once(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        _write_auth_repo(repo_root)
        investigation_dir = tmp_path / "investigation"
        investigation_dir.mkdir()

        calls = {"select": 0, "build_context": 0, "enrich": 0, "fuse": 0, "render": 0}
        original_select = _cs_mod.select_candidates
        original_build = _ce_mod.build_investigation_context
        original_enrich = _ce_mod.enrich_candidates
        original_fuse = _ef_mod.fuse_evidence
        original_render = _ef_mod.render_repository_understanding

        def _select(*a, **kw):
            calls["select"] += 1
            return original_select(*a, **kw)

        def _build(*a, **kw):
            calls["build_context"] += 1
            return original_build(*a, **kw)

        def _enrich(*a, **kw):
            calls["enrich"] += 1
            return original_enrich(*a, **kw)

        def _fuse(*a, **kw):
            calls["fuse"] += 1
            return original_fuse(*a, **kw)

        def _render(*a, **kw):
            calls["render"] += 1
            return original_render(*a, **kw)

        with (
            mock.patch.object(_cs_mod, "select_candidates", side_effect=_select),
            mock.patch.object(_ce_mod, "build_investigation_context", side_effect=_build),
            mock.patch.object(_ce_mod, "enrich_candidates", side_effect=_enrich),
            mock.patch.object(_ef_mod, "fuse_evidence", side_effect=_fuse),
            mock.patch.object(_ef_mod, "render_repository_understanding", side_effect=_render),
        ):
            pipeline_run(
                vulnerability_text=_VULN_TEXT,
                api_key="",
                repo_root=str(repo_root),
                investigation_output_dir=str(investigation_dir),
            )

        assert calls == {"select": 1, "build_context": 1, "enrich": 1, "fuse": 1, "render": 1}

    def test_no_investigation_when_no_repo_root(self, monkeypatch):
        """repo_root=None must never trigger selection/enrichment/fusion --
        matches F-01's no-cwd-fallback guarantee."""
        monkeypatch.setenv("LLM_PROVIDER", "mock")

        with mock.patch.object(_cs_mod, "select_candidates") as m_select:
            pipeline_run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=None)

        m_select.assert_not_called()

    def test_no_new_llm_call_is_introduced(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        _write_auth_repo(repo_root)
        investigation_dir = tmp_path / "investigation"
        investigation_dir.mkdir()

        patcher, captured = _capture_generate_patch()
        with patcher:
            pipeline_run(
                vulnerability_text=_VULN_TEXT,
                api_key="",
                repo_root=str(repo_root),
                investigation_output_dir=str(investigation_dir),
            )

        # Exactly the one, existing patch-generation call -- investigation
        # adds repository facts to its input, not a second model call.
        assert len(captured) == 1


class TestContextComposition:
    def test_repository_understanding_appended_after_existing_context(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        _write_auth_repo(repo_root)
        investigation_dir = tmp_path / "investigation"
        investigation_dir.mkdir()

        patcher, captured = _capture_generate_patch()
        with patcher:
            pipeline_run(
                vulnerability_text=_VULN_TEXT,
                api_key="",
                repo_root=str(repo_root),
                investigation_output_dir=str(investigation_dir),
            )

        assert captured, "generate_patch was never called"
        assert captured[0]["vulnerability_text"] == _VULN_TEXT, (
            "vulnerability_text must reach generate_patch unchanged"
        )

        ctx = captured[0]["code_context"]
        assert "## Repository Understanding" in ctx
        # The real candidate (app/auth.py, found by ground_repository()) must
        # be the one rendered -- proves selection/enrichment/fusion ran
        # against real repo data, not a stub.
        assert "### `app/auth.py`" in ctx
        # Appended, not prepended -- existing repo/pattern context precedes it.
        idx = ctx.index("## Repository Understanding")
        assert idx > 0 and ctx[:idx].strip() != ""

    def test_existing_repo_code_context_still_present(self, tmp_path, monkeypatch):
        """Raw repository code context (ground_repository()'s own rendered
        snippet of app/auth.py) must still reach code_context unchanged --
        Repository Understanding must complement it, not replace it.

        (Vulnerability-class guidance is not asserted here: classify_vuln_class
        only recognizes PATH_TRAVERSAL/COMMAND_INJECTION today, so this
        fixture's CWE-89/SQL-injection text never produces that block,
        independent of this change.)
        """
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        _write_auth_repo(repo_root)
        investigation_dir = tmp_path / "investigation"
        investigation_dir.mkdir()

        patcher, captured = _capture_generate_patch()
        with patcher:
            pipeline_run(
                vulnerability_text=_VULN_TEXT,
                api_key="",
                repo_root=str(repo_root),
                investigation_output_dir=str(investigation_dir),
            )

        ctx = captured[0]["code_context"]
        assert "auth.py" in ctx
        assert 'def authenticate(username, password):' in ctx


class TestFailureDegradesGracefully:
    def test_enrichment_failure_falls_back_to_existing_context(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        _write_auth_repo(repo_root)
        investigation_dir = tmp_path / "investigation"
        investigation_dir.mkdir()

        def _boom(*a, **kw):
            raise RuntimeError("simulated enrichment failure")

        patcher, captured = _capture_generate_patch()
        with patcher, mock.patch.object(_ce_mod, "enrich_candidates", side_effect=_boom):
            report = pipeline_run(
                vulnerability_text=_VULN_TEXT,
                api_key="",
                repo_root=str(repo_root),
                investigation_output_dir=str(investigation_dir),
            )

        assert report  # the run completes; a failure here must not abort it
        assert captured, "generate_patch must still be called"
        ctx = captured[0]["code_context"]
        assert "## Repository Understanding" not in ctx
        # existing repo context must still make it through untouched
        assert "auth.py" in ctx


class TestRetentionForLaterReporting:
    def test_repository_understanding_retained_on_pipeline_result(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        _write_auth_repo(repo_root)
        investigation_dir = tmp_path / "investigation"
        investigation_dir.mkdir()

        import utilities.autopatcher.pipeline as _pipeline_module

        captured = {}
        original_build_report = _pipeline_module._build_report

        def _capturing_build_report(result):
            captured["result"] = result
            return original_build_report(result)

        with mock.patch.object(_pipeline_module, "_build_report", side_effect=_capturing_build_report):
            pipeline_run(
                vulnerability_text=_VULN_TEXT,
                api_key="",
                repo_root=str(repo_root),
                investigation_output_dir=str(investigation_dir),
            )

        result = captured["result"]
        assert result.repository_understanding is not None
        assert result.repository_understanding.candidate_evidence
        assert result.repository_understanding.candidate_evidence[0].path.endswith("auth.py")
        assert len(result.repository_understanding.candidate_evidence) <= 3  # DEFAULT_MAX_CANDIDATES


class TestOnlySelectedCandidatesAreEnriched:
    def test_enrich_candidates_receives_select_candidates_own_selected_list(self, tmp_path, monkeypatch):
        """Orchestration-wiring check: enrich_candidates() must be called
        with select_candidates()'s own bounded `.selected` output, not
        `.generated`/`.eligible` -- the actual bounding (<= 3) is already
        unit-tested in test_candidate_selection.py."""
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        _write_auth_repo(repo_root)
        investigation_dir = tmp_path / "investigation"
        investigation_dir.mkdir()

        captured = {}
        original_select = _cs_mod.select_candidates
        original_enrich = _ce_mod.enrich_candidates

        def _select(*a, **kw):
            selection = original_select(*a, **kw)
            captured["selection"] = selection
            return selection

        def _enrich(selection, *a, **kw):
            captured["enrich_selection_arg"] = selection
            return original_enrich(selection, *a, **kw)

        with (
            mock.patch.object(_cs_mod, "select_candidates", side_effect=_select),
            mock.patch.object(_ce_mod, "enrich_candidates", side_effect=_enrich),
        ):
            pipeline_run(
                vulnerability_text=_VULN_TEXT,
                api_key="",
                repo_root=str(repo_root),
                investigation_output_dir=str(investigation_dir),
            )

        assert captured["enrich_selection_arg"] is captured["selection"]
        assert len(captured["selection"].selected) <= 3


class TestBackwardCompatibility:
    def test_run_without_investigation_output_dir_still_works(self):
        """The pre-existing call signature -- no repo_root, no
        investigation_output_dir -- must remain valid for direct callers
        that predate this phase."""
        report = pipeline_run(vulnerability_text=_VULN_TEXT, api_key="")
        assert isinstance(report, str) and report.strip()

    def test_run_with_repo_root_but_no_investigation_output_dir_degrades(self, tmp_path, monkeypatch):
        """A caller that passes repo_root but not investigation_output_dir
        (every existing test in test_pipeline*.py) must still get a report;
        candidate enrichment runs in degraded (context=None) mode."""
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        _write_auth_repo(repo_root)

        report = pipeline_run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(repo_root))
        assert isinstance(report, str) and report.strip()
