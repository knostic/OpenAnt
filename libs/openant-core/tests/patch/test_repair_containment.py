"""PR #763 HUNT FABLE-R1-1 (off-target repair), Option A containment.

The Challenger-driven repair loop accepted a regenerated patch that changed a
file the original (target-conformant) patch never touched, and the run
reached Deploy After Validation although the vulnerable code was untouched.
A regenerated repair is now considered only when every file it changes is a
file the original patch changes; otherwise it is rejected before any
re-challenge, and the original patch with its own evidence is kept.

Residual (documented): a repair inside the same files can still change
unrelated code there -- this is file containment, not target conformance.

Drives the production Stage-6 executor with a deterministic stubbed model,
exactly like the HUNT reproduction; no network, no paid calls.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import utilities.autopatcher.pipeline as P
from utilities.autopatcher.patch_challenger import challenge_patch

VULN = "# Path traversal in app.handler\n\napp.py handler opens attacker path."
CTX = ("#### Target definition: `app.py:handler` (lines 1-2)\n\n```python\n"
       "def handler(path):\n    return open(path).read()\n```\n")
INITIAL = ("--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,3 @@\n def handler(path):\n"
           "+    check(path)\n     return open(path).read()\n")
SAME_FILE_FIX = ("--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,3 @@\n def handler(path):\n"
                 "+    if not is_safe(path): raise ValueError()\n     return open(path).read()\n")
OFF_TARGET = ("--- a/lib.py\n+++ b/lib.py\n@@ -1,2 +1,3 @@\n def unrelated(x):\n"
              "+    if not is_safe(x): raise ValueError()\n     return x\n")
CALIBRATION = ("1. Claims:\n   - bypass shown\n   Unresolved: none\n   Remediation impact: validation_only\n"
               "   Group: Observed\n   Reworded: An attacker can bypass this check via path traversal.\n")


def _concern(guard, op, default):
    return f"""Verification status: VERIFIED_FIXED

Concerns:

1. Role: primary
   Description: the guard prevents the operation
   Operation present in evidence: present
   Preceding guard: present
   Guard provenance: {guard}
   Function provenance: none
   Operation provenance: {op}
   Guard default state: condition_true_under_default
   Guard default state provenance: {default}
   Guard effect: prevents_operation
   Guard effect provenance: raise ValueError()
   Reentry state propagation: not_applicable
   Reentry provenance: none
   Requires explicit non-default action: false
   Override provenance: none
   Contract addresses override: not_applicable
   Scope provenance: none

Edge cases:
- none

Potential issues:
- none

Summary:
- none
"""


class _Model:
    def __init__(self, repaired: str, challenger_reply: str):
        self.repaired, self.reply, self.stages = repaired, challenger_reply, []

    def complete(self, system, user, stage=None):
        self.stages.append(stage)
        if stage == "finding_calibration":
            return CALIBRATION
        if stage == "patch_repair_regeneration":
            return "```diff\n" + self.repaired + "```"
        if stage == "challenger":
            return self.reply
        raise AssertionError(f"unexpected stage {stage}")


class _FirstChallenger:
    def complete(self, s, u, stage=None):
        return ("Verification status: INSUFFICIENT_EVIDENCE\n\nEdge cases:\n"
                "- An attacker can bypass this check via path traversal\n\nPotential issues:\n- none\n\n"
                "Summary:\n- none\n")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("def handler(path):\n    return open(path).read()\n")
    (root / "lib.py").write_text("def unrelated(x):\n    return x\n")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false",
                    "commit", "-qm", "init"], cwd=root, check=True)
    return root


def _run(repo: Path, repaired: str, reply: str):
    original_challenger = challenge_patch("vuln", INITIAL, _FirstChallenger(), code_context="")
    model = _Model(repaired, reply)
    original_applicability = {"applicable": True}
    s6 = P._run_patch_repair_and_calibration(
        vulnerability_text=VULN, llm=model, repo_root=str(repo), code_context=CTX, challenger_context="",
        patch=INITIAL, challenger=original_challenger, applicability_result=original_applicability,
        hygiene_findings=[], _final_repair_meta=None, _post_patch_observations=None, _investigated_patch=None,
    )
    impact = P._run_impact_and_behavior_analysis(patch=s6["patch"], challenger=s6["challenger"], repo_root=str(repo))
    classified = P._reconcile_verification_status_with_calibration(
        P._classify_challenger(s6["challenger"]), s6["finding_calibration"],
    )
    signals = P._compute_trust_signals(s6["hygiene_findings"], s6["applicability_result"], classified, "Good",
                                       P._resolve_impact_level(impact["impact_dict"]))
    decision = P._build_recommendation_v1(signals, classified["still_vulnerable"], classified["confirmed_defect_count"],
                                          classified.get("verification_status"), structured_challenger=True)["decision"]
    return s6, model, original_challenger, original_applicability, decision


OFF_TARGET_REPLY = _concern("if not is_safe(x):", "return x", "def unrelated(x):")
SAME_FILE_REPLY = _concern("if not is_safe(path):", "return open(path).read()", "def handler(path):")


class TestOffTargetRepairIsRejected:
    def test_hunt_reproduction_no_longer_reaches_deploy(self, repo):
        s6, model, original_challenger, original_applicability, decision = _run(repo, OFF_TARGET, OFF_TARGET_REPLY)
        assert decision != "Deploy After Validation"
        assert s6["repair_succeeded"] is False and s6["repair_off_target"] is True

    def test_original_patch_and_its_evidence_are_kept(self, repo):
        s6, model, original_challenger, original_applicability, _ = _run(repo, OFF_TARGET, OFF_TARGET_REPLY)
        assert s6["patch"] == INITIAL
        assert s6["challenger"] is original_challenger
        assert s6["applicability_result"] is original_applicability
        assert s6["hygiene_findings"] == []
        assert s6["finding_calibration"] == s6["_calibration_v1"]

    def test_rejected_candidate_gets_no_challenger_evidence(self, repo):
        s6, model, *_ = _run(repo, OFF_TARGET, OFF_TARGET_REPLY)
        assert "challenger" not in model.stages
        assert s6["repair_rechallenged"] is False and s6["repair_challenger_result"] is None

    @pytest.mark.parametrize("repaired", [
        SAME_FILE_FIX + OFF_TARGET,  # the fix plus an additional file
        "--- /dev/null\n+++ b/new_guard.py\n@@ -0,0 +1,2 @@\n+def is_safe(p):\n+    return '..' not in p\n",
    ], ids=["additional-file", "new-file"])
    def test_any_file_outside_the_original_set_is_rejected(self, repo, repaired):
        s6, model, _, _, decision = _run(repo, repaired, SAME_FILE_REPLY)
        assert s6["patch"] == INITIAL and s6["repair_succeeded"] is False
        assert "challenger" not in model.stages


class TestSameFileRepairIsStillAccepted:
    def test_a_repair_that_fixes_the_original_vulnerability(self, repo):
        s6, model, _, _, decision = _run(repo, SAME_FILE_FIX, SAME_FILE_REPLY)
        assert s6["repair_succeeded"] is True and s6["repair_off_target"] is False
        assert "is_safe(path)" in s6["patch"] and "lib.py" not in s6["patch"]
        assert decision == "Deploy After Validation"

    def test_same_file_repair_is_still_judged_by_the_challenger(self, repo):
        """Containment only admits the candidate; the re-challenge decides."""
        blocking = SAME_FILE_REPLY.replace("Guard default state: condition_true_under_default",
                                           "Guard default state: condition_false_under_default").replace(
            "   Guard effect: prevents_operation\n   Guard effect provenance: raise ValueError()\n",
            "   Guard effect: not_applicable\n   Guard effect provenance: none\n").replace(
            "Requires explicit non-default action: false", "Requires explicit non-default action: not_applicable")
        s6, model, _, _, decision = _run(repo, SAME_FILE_FIX, blocking)
        assert "challenger" in model.stages and s6["repair_off_target"] is False
        assert s6["repair_challenger_result"]["verification_status"] == "RESIDUAL_VULNERABILITY"
        assert decision != "Deploy After Validation"


class TestFileSet:
    """`_patch_changed_files`: every path a diff changes, normalized, or None
    when that set cannot be established (fail closed)."""

    @pytest.mark.parametrize("diff,expected", [
        (INITIAL, {"app.py"}),
        ("```diff\n" + INITIAL + "```\n", {"app.py"}),
        (SAME_FILE_FIX + OFF_TARGET, {"app.py", "lib.py"}),
        ("--- /dev/null\n+++ b/pkg/new.py\n@@ -0,0 +1 @@\n+x = 1\n", {"pkg/new.py"}),
        ("--- a/app.py\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-def handler(path):\n-    return open(path).read()\n",
         {"app.py"}),
        ("diff --git a/app.py b/app2.py\nsimilarity index 100%\nrename from app.py\nrename to app2.py\n",
         {"app.py", "app2.py"}),
        ("diff --git a/app.py b/app.py\nindex 1..2 100644\n" + INITIAL, {"app.py"}),
        ("diff --git a/src\\\\app.py b/src\\\\app.py\n--- a/src\\app.py\n+++ b/src\\app.py\n@@ -1 +1 @@\n-a\n+b\n",
         {"src/app.py"}),
    ], ids=["modify", "fenced", "two-files", "addition", "deletion", "rename", "git-header", "backslashes"])
    def test_files(self, diff, expected):
        assert P._patch_changed_files(diff) == frozenset(expected)

    @pytest.mark.parametrize("diff", [
        "",
        "no diff here at all",
        "--- app.py\n+++ app.py\n@@ -1 +1 @@\n-a\n+b\n",  # no a/ b/ prefixes (-p0)
        "--- a/./app.py\n+++ b/./app.py\n@@ -1 +1 @@\n-a\n+b\n",  # path alias
        "--- a/x/../app.py\n+++ b/x/../app.py\n@@ -1 +1 @@\n-a\n+b\n",  # traversal alias
        "--- a//app.py\n+++ b//app.py\n@@ -1 +1 @@\n-a\n+b\n",  # absolute after the prefix
        "--- a/pkg//app.py\n+++ b/pkg//app.py\n@@ -1 +1 @@\n-a\n+b\n",  # doubled separator
        '--- "a/app.py"\n+++ "b/app.py"\n@@ -1 +1 @@\n-a\n+b\n',  # quoted git path
        "diff --git a/app.py b/app.py\n@@ -1 +1 @@\n-a\n+b\n",  # header pair missing
    ], ids=["empty", "prose", "no-prefix", "dot-alias", "dotdot-alias", "absolute", "double-slash", "quoted",
            "missing-headers"])
    def test_undeterminable_sets_are_none(self, diff):
        assert P._patch_changed_files(diff) is None

    @pytest.mark.parametrize("repaired,original,ok", [
        (INITIAL, INITIAL, True),
        (SAME_FILE_FIX, INITIAL, True),
        (OFF_TARGET, INITIAL, False),
        (SAME_FILE_FIX + OFF_TARGET, INITIAL, False),
        ("--- a/App.py\n+++ b/App.py\n@@ -1 +1 @@\n-a\n+b\n", INITIAL, False),  # case alias
        ("--- a/./app.py\n+++ b/./app.py\n@@ -1 +1 @@\n-a\n+b\n", INITIAL, False),
        ("diff --git a/app.py b/app2.py\nrename from app.py\nrename to app2.py\n", INITIAL, False),
        (SAME_FILE_FIX, "not a diff", False),  # the original set is unknown
    ], ids=["identical", "same-file", "other-file", "plus-other-file", "case-alias", "dot-alias", "rename",
            "unknown-original"])
    def test_containment(self, repaired, original, ok):
        assert P._repair_within_original_files(original, repaired) is ok
