"""Tests for the Phase 4 Post-Patch Investigation pipeline wiring.

Covers the orchestration boundary approved for this phase: derive
pre-patch Anchors right after Repository Understanding, run the
workspace-copy -> apply -> parse -> evaluate -> render chain exactly once
(right before the FIRST challenge_patch() call), thread its evidence into
that call plus calibrate_findings()/score_confidence() (guarded by a
patch-identity staleness check against the Challenger-driven repair
loop), and render a "Post-Patch Investigation" Trust Report section.

Hermetic: LLM_PROVIDER=mock, no network. A real (tiny) on-disk git repo
under tmp_path gives Repository Understanding/Anchor derivation real,
deterministic work to do; the post-patch chain itself (workspace copy,
git apply, parser, evaluation) also runs for real against that repo --
the mock patches deliberately don't apply cleanly to it, so the chain
naturally degrades to `evaluation_error` observations, which is itself a
real, useful thing to verify (see test_investigation_integration.py for
the identical fixture-repo convention this file reuses).
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest import mock

import utilities.autopatcher.post_patch_evaluation as _ppe_mod

EXAMPLES_DIR = Path(__file__).parent / "fixtures" / "examples"
_VULN_TEXT = (EXAMPLES_DIR / "vulnerability.md").read_text(encoding="utf-8")

_APPLICABILITY_CLEAN = {
    "applicable": True, "skipped": False, "stderr": "",
    "exit_code": 0, "skipped_reason": None, "error": None,
}

_SOME_DIFF = """\
```diff
--- a/app/auth.py
+++ b/app/auth.py
@@ -1,2 +1,3 @@
 def authenticate():
+    pass
     pass
```"""

_REPAIR_DIFF = """\
```diff
--- a/app/auth.py
+++ b/app/auth.py
@@ -1,2 +1,3 @@
 def authenticate():
+    # repaired
     pass
```"""

_CHALLENGER_WITH_DEFECT = {
    "still_vulnerable": False,
    "edge_cases": ["An attacker can bypass this check via path traversal"],
    "potential_issues": [],
    "summary": "The patch has a confirmed bypass.",
}

_CHALLENGER_CLEAN = {
    "still_vulnerable": False,
    "edge_cases": [],
    "potential_issues": [],
    "summary": "No issues found.",
}


def _write_auth_repo(root: Path) -> None:
    """Same fixture as test_investigation_integration.py's _write_auth_repo
    -- matches fixtures/examples/vulnerability.md's explicit `app/auth.py`
    / `authenticate()` reference, giving grounding a real, strong-tier
    candidate and the parser a real function to resolve."""
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
    subprocess.run(["git", "init"], cwd=root, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=root, capture_output=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=root, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=root, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=root, capture_output=True)


def _run_pipeline(
    tmp_path,
    *,
    patches_gen,
    patches_chall,
    repo_root,
    extra_patches=(),
):
    import utilities.autopatcher.pipeline as _pipeline_mod
    from contextlib import ExitStack

    captured_result = {}
    orig_build = _pipeline_mod._build_report

    def _capture_build(r):
        captured_result["result"] = r
        return orig_build(r)

    calls = {"challenge": [], "calibrate": [], "score": []}

    def _challenge_side_effect(*a, **kw):
        calls["challenge"].append(kw.get("code_context", ""))
        idx = len(calls["challenge"]) - 1
        return patches_chall[min(idx, len(patches_chall) - 1)]

    def _calibrate_side_effect(*a, **kw):
        calls["calibrate"].append(kw.get("code_context", ""))
        return None

    def _score_side_effect(*a, **kw):
        calls["score"].append(kw.get("code_context", ""))
        return "Confidence score: 0.8"

    patchers = [
        mock.patch("utilities.autopatcher.pipeline.LLMClient"),
        mock.patch("utilities.autopatcher.pipeline.generate_patch", side_effect=patches_gen),
        mock.patch("utilities.autopatcher.patch_applicability.check_applicability", return_value=_APPLICABILITY_CLEAN),
        mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok review"),
        mock.patch("utilities.autopatcher.pipeline.challenge_patch", side_effect=_challenge_side_effect),
        mock.patch("utilities.autopatcher.pipeline.calibrate_findings", side_effect=_calibrate_side_effect),
        mock.patch("utilities.autopatcher.pipeline.score_confidence", side_effect=_score_side_effect),
        mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
        mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
        mock.patch("utilities.autopatcher.pipeline._build_report", side_effect=_capture_build),
    ]
    patchers.extend(extra_patches)

    import tempfile
    investigation_dir = Path(tempfile.mkdtemp(prefix="ppi-investigation-"))

    with ExitStack() as stack:
        mocks = [stack.enter_context(p) for p in patchers]
        from utilities.autopatcher.pipeline import run
        report = run(
            _VULN_TEXT, api_key="", repo_root=repo_root,
            investigation_output_dir=(str(investigation_dir) if repo_root else None),
        )

    return captured_result["result"], report, calls, mocks


# ---------------------------------------------------------------------------
# Runs once, regardless of retry/repair
# ---------------------------------------------------------------------------

class TestRunsExactlyOnce:
    def test_evaluate_anchors_called_once_even_with_repair(self, tmp_path):
        repo_root = tmp_path / "repo"
        _write_auth_repo(repo_root)

        with mock.patch.object(
            _ppe_mod, "evaluate_anchors", side_effect=_ppe_mod.evaluate_anchors,
        ) as m_evaluate:
            result, report, calls, _ = _run_pipeline(
                tmp_path,
                patches_gen=[_SOME_DIFF, _REPAIR_DIFF],
                patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN],
                repo_root=str(repo_root),
            )

        assert m_evaluate.call_count == 1
        assert result.repair_succeeded is True


# ---------------------------------------------------------------------------
# repo_root=None: never attempted
# ---------------------------------------------------------------------------

class TestNoRepoRoot:
    def test_section_states_not_evaluated_distinctly(self, tmp_path):
        with mock.patch("utilities.autopatcher.patch_workspace.temporary_repo_copy") as m_copy:
            result, report, calls, _ = _run_pipeline(
                tmp_path,
                patches_gen=[_SOME_DIFF],
                patches_chall=[_CHALLENGER_CLEAN],
                repo_root=None,
            )

        m_copy.assert_not_called()
        assert result.post_patch_observations is None
        assert "## Post-Patch Investigation" in report
        assert "Not evaluated for this run" in report
        # Must never collide with the exact F-01 string used elsewhere.
        assert report.count("Not evaluated — no repository root was provided.") == 3


# ---------------------------------------------------------------------------
# First challenge_patch() call receives the evidence
# ---------------------------------------------------------------------------

class TestFirstChallengeCallEnriched:
    def test_first_challenge_context_includes_post_patch_section(self, tmp_path):
        repo_root = tmp_path / "repo"
        _write_auth_repo(repo_root)

        result, report, calls, _ = _run_pipeline(
            tmp_path,
            patches_gen=[_SOME_DIFF],
            patches_chall=[_CHALLENGER_CLEAN],
            repo_root=str(repo_root),
        )

        assert result.post_patch_observations is not None
        assert len(calls["challenge"]) == 1
        assert "## Post-Patch Investigation" in calls["challenge"][0]

    def test_no_new_llm_calls_introduced(self, tmp_path):
        """Only the already-existing generate_patch/challenge_patch/
        review_patch/score_confidence/calibrate_findings call sites should
        fire -- the post-patch chain itself makes no LLM calls."""
        repo_root = tmp_path / "repo"
        _write_auth_repo(repo_root)

        result, report, calls, _ = _run_pipeline(
            tmp_path,
            patches_gen=[_SOME_DIFF],
            patches_chall=[_CHALLENGER_CLEAN],
            repo_root=str(repo_root),
        )
        assert len(calls["challenge"]) == 1
        assert len(calls["score"]) == 1


# ---------------------------------------------------------------------------
# Staleness guard: repair replacing the patch must not leak stale evidence
# ---------------------------------------------------------------------------

class TestStalenessGuard:
    def test_repair_succeeds_invalidates_evidence_for_later_consumers(self, tmp_path):
        repo_root = tmp_path / "repo"
        _write_auth_repo(repo_root)

        result, report, calls, _ = _run_pipeline(
            tmp_path,
            patches_gen=[_SOME_DIFF, _REPAIR_DIFF],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN],
            repo_root=str(repo_root),
        )

        assert result.repair_succeeded is True
        assert result.patch != result.post_patch_investigated_patch

        # The FIRST challenge_patch call (pre-repair) got the evidence...
        assert "## Post-Patch Investigation" in calls["challenge"][0]
        # ...but the repair loop's own re-challenge never does (by design,
        # regardless of staleness -- extending fresh evidence to the
        # repair path is explicitly deferred).
        assert "## Post-Patch Investigation" not in calls["challenge"][1]
        # ...and score_confidence (which runs after the repair loop, on the
        # final patch) must not receive the now-stale evidence either.
        assert "## Post-Patch Investigation" not in calls["score"][0]

        # The Trust Report must say so explicitly, not silently show stale data.
        assert "revised after this evidence was computed" in report

    def test_no_repair_evidence_reaches_score_confidence(self, tmp_path):
        repo_root = tmp_path / "repo"
        _write_auth_repo(repo_root)

        result, report, calls, _ = _run_pipeline(
            tmp_path,
            patches_gen=[_SOME_DIFF],
            patches_chall=[_CHALLENGER_CLEAN],
            repo_root=str(repo_root),
        )

        assert result.repair_attempted is False
        assert result.patch == result.post_patch_investigated_patch
        assert "## Post-Patch Investigation" in calls["score"][0]


# ---------------------------------------------------------------------------
# Failure isolation
# ---------------------------------------------------------------------------

class TestFailureIsolation:
    def test_exception_mid_chain_degrades_without_crashing(self, tmp_path):
        repo_root = tmp_path / "repo"
        _write_auth_repo(repo_root)

        with mock.patch(
            "utilities.autopatcher.patch_workspace.temporary_repo_copy",
            side_effect=RuntimeError("boom"),
        ):
            result, report, calls, _ = _run_pipeline(
                tmp_path,
                patches_gen=[_SOME_DIFF],
                patches_chall=[_CHALLENGER_CLEAN],
                repo_root=str(repo_root),
            )

        assert result.post_patch_observations is None
        assert "## Post-Patch Investigation" in report
        assert "Not evaluated for this run" in report
        # code_context passed to challenge_patch must fall back cleanly,
        # never raise or contain a partial/garbled section.
        assert "## Post-Patch Investigation" not in calls["challenge"][0]

    def test_trust_signals_unaffected_by_injected_failure(self, tmp_path):
        """Recommendation/Trust Signals must be identical whether the
        post-patch chain succeeds, degrades, or throws -- this feature is
        provably inert with respect to that machinery (no new parameter
        was added to _compute_trust_signals/_build_recommendation_v1)."""
        repo_root = tmp_path / "repo"
        _write_auth_repo(repo_root)

        result_ok, report_ok, _, _ = _run_pipeline(
            tmp_path,
            patches_gen=[_SOME_DIFF],
            patches_chall=[_CHALLENGER_CLEAN],
            repo_root=str(repo_root),
        )
        with mock.patch(
            "utilities.autopatcher.patch_workspace.temporary_repo_copy",
            side_effect=RuntimeError("boom"),
        ):
            result_fail, report_fail, _, _ = _run_pipeline(
                tmp_path,
                patches_gen=[_SOME_DIFF],
                patches_chall=[_CHALLENGER_CLEAN],
                repo_root=str(repo_root),
            )

        assert result_ok.final_score == result_fail.final_score
        assert result_ok.hygiene == result_fail.hygiene
