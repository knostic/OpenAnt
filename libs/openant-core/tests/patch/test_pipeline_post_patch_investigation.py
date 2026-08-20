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
        # should_auto_repair/accept_repair now require an explicit
        # "observed" calibration entry before a raw confirmed_defect
        # finding can authorize or accept a mutation -- returning "observed"
        # for every finding here reproduces, for this module's fixtures,
        # the same repair-triggering behavior tested before that gate
        # existed (this file is about Post-Patch Investigation evidence
        # wiring, not the calibration gate itself; see
        # TestDeterministicRepairGate in test_pipeline_repair.py for that).
        findings = a[2] if len(a) > 2 else []
        return [{"original": f, "group": "observed", "reworded": f} for f in findings]

    def _score_side_effect(*a, **kw):
        calls["score"].append(kw.get("code_context", ""))
        return "Confidence score: 0.8"

    # Release: response-contract enforcement moved the initial generation
    # call site (Site 1) from generate_patch() to
    # _generate_patch_with_contract_check() -> generate_patch_raw() (both
    # defined in pipeline.py); the Challenger-repair loop (Site 4, exercised
    # by some tests here) still calls generate_patch() directly
    # (patch_generator.py), unchanged. patches_gen[0] is always the Site 1
    # response in every caller of this helper -- mocking generate_patch_raw
    # with it, and generate_patch with the REMAINING items, preserves every
    # existing call's exact meaning.
    patchers = [
        mock.patch("utilities.autopatcher.pipeline.LLMClient"),
        mock.patch("utilities.autopatcher.pipeline.generate_patch_raw", return_value=patches_gen[0]),
        mock.patch("utilities.autopatcher.pipeline.generate_patch", side_effect=patches_gen[1:]),
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


# ---------------------------------------------------------------------------
# Candidate-selection-independent patch-touched Anchors (end-to-end regression)
#
# Reproduces, hermetically, the exact real-repo gap found while validating
# this feature against urllib3/CVE-2023-43804: Candidate Selection runs on
# the vulnerability TEXT before any patch exists, so it can never select a
# file the text doesn't textually resemble -- even when the eventual patch
# touches it. `app/rate_limit_config.py` below is deliberately unrelated,
# in vocabulary, to the SQL-injection vulnerability.md text (no "auth"/
# "password"/"query"/"sql" overlap) precisely so real, unmodified grounding
# genuinely does not select it -- the same way real grounding for the
# urllib3 CVE never selected retry.py. No candidate is manually injected
# anywhere in this test.
# ---------------------------------------------------------------------------

_RATE_LIMIT_CONFIG_DIFF = """\
```diff
--- a/app/rate_limit_config.py
+++ b/app/rate_limit_config.py
@@ -1,5 +1,5 @@
 class RateLimitConfig:
-    DEFAULT_ALLOWED_METHODS = frozenset(["GET"])
+    DEFAULT_ALLOWED_METHODS = frozenset(["GET", "POST"])

     def as_dict(self):
         return {"methods": self.DEFAULT_ALLOWED_METHODS}
```"""


def _write_auth_and_rate_limit_repo(root: Path) -> None:
    """_write_auth_repo's app/auth.py (matches vulnerability.md, so real
    grounding selects it) plus a second, vocabulary-disjoint file holding
    a class-level literal constant that the final patch below touches but
    that no selected candidate ever surfaces.

    The class has a real method (not just the constant) deliberately --
    matching urllib3's actual `Retry` class, which has plenty of real
    methods. A class with zero methods produces no RepositoryIndex entry
    at all for its file (a separate, pre-existing parser limitation,
    unrelated to this feature); this fixture avoids that degenerate shape
    so the test exercises the real gap, not an incidental one.
    """
    _write_auth_repo(root)  # commits app/auth.py + git init
    rate_limit = root / "app" / "rate_limit_config.py"
    rate_limit.write_text(
        "class RateLimitConfig:\n"
        "    DEFAULT_ALLOWED_METHODS = frozenset([\"GET\"])\n"
        "\n"
        "    def as_dict(self):\n"
        "        return {\"methods\": self.DEFAULT_ALLOWED_METHODS}\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "-A"], cwd=root, capture_output=True)
    subprocess.run(["git", "commit", "-m", "add rate_limit_config"], cwd=root, capture_output=True)


class TestPatchTouchedAnchorsIndependentOfCandidateSelection:
    def test_constant_untouched_by_selection_still_detected_as_changed_and_covered(self, tmp_path):
        repo_root = tmp_path / "repo"
        _write_auth_and_rate_limit_repo(repo_root)

        result, report, calls, _ = _run_pipeline(
            tmp_path,
            patches_gen=[_RATE_LIMIT_CONFIG_DIFF],
            patches_chall=[_CHALLENGER_CLEAN],
            repo_root=str(repo_root),
        )

        # 1. The changed file is genuinely not in selection.selected --
        # real, unmodified Candidate Selection, no manual injection.
        assert result.repository_understanding is not None
        selected_paths = {c.path for c in result.repository_understanding.candidate_evidence}
        assert "app/rate_limit_config.py" not in selected_paths

        # 2. No PRE-PATCH Anchor exists for the changed constant (proves
        # the gap is real, not already closed by some other mechanism).
        pre_patch_const_anchors = [
            o for o in result.post_patch_observations
            if o.anchor_kind == "constant_value" and o.origin == "pre_patch"
            and "rate_limit_config.py" in o.candidate_path
        ]
        assert pre_patch_const_anchors == []

        # 3. A patch_touched constant_value Anchor WAS derived from the
        # final diff, and (4) it reports Changed: GET -> {GET, POST}.
        touched = [
            o for o in result.post_patch_observations
            if o.anchor_kind == "constant_value" and o.origin == "patch_touched"
        ]
        assert len(touched) == 1
        obs = touched[0]
        assert obs.status == "changed"
        assert obs.before_value.value == frozenset({"GET"})
        assert obs.after_value.value == frozenset({"GET", "POST"})
        assert "app/rate_limit_config.py" in obs.candidate_path

        # 5. Coverage reports 1 of 1 covered, 0 uncovered for this element.
        assert result.post_patch_coverage is not None
        ref = obs.anchor_key.const_id
        assert ref in result.post_patch_coverage.covered
        assert ref not in result.post_patch_coverage.uncovered

        # Rendered report shows the fact, tagged as patch-discovered, and
        # is reachable by the Challenger (evidence actually flows downstream).
        assert "### Changed" in report
        changed_section = report[report.index("### Changed"):report.index("### Disappeared")]
        assert "discovered from patch diff" in changed_section
        assert "1 of 1 element(s)" in calls["challenge"][0] or "1 of 1 element(s)" in report
