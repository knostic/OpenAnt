"""PR #763 review: a Challenger citation must evidence the PATCHED code.

Before the fix, citation containment was checked against the raw diff and the
pre-change evidence, so a patch that REMOVES a security guard could cite its
own removed line as "Preceding guard: present", and diff metadata (`+++`,
`---`, `@@ -`) or a mid-identifier fragment (`ete` in `delete`) passed as a
reachability citation -- each reaching VERIFIED_FIXED -> Deploy After
Validation. These tests drive the production report path end to end
(challenge_patch with a stubbed model reply -> PipelineResult ->
_build_report) with every other recommendation axis positive.
"""

import re
from pathlib import Path
from unittest import mock

import pytest

from utilities.autopatcher.patch_challenger import challenge_patch
from utilities.autopatcher.pipeline import PipelineResult, _build_report, _challenger_provenance_context

VULN = "# Missing authorization in delete_user\n\nAny user can delete accounts via delete_user."
GUARD = "if not user.is_admin: raise PermissionError()"
OP = "db.delete(target)"

_HEADER = "diff --git a/app.py b/app.py\nindex 1111111..2222222 100644\n--- a/app.py\n+++ b/app.py\n"
REMOVING = (
    _HEADER + "@@ -1,4 +1,3 @@\n def delete_user(user, target):\n"
    f"-    {GUARD}\n     {OP}\n     return True\n"
)
ADDING = (
    _HEADER + "@@ -1,3 +1,4 @@\n def delete_user(user, target):\n"
    f"+    {GUARD}\n     {OP}\n     return True\n"
)
CONTEXT = (
    _HEADER + "@@ -1,4 +1,4 @@\n def delete_user(user, target):\n"
    f"     {GUARD}\n     {OP}\n-    return True\n+    return None\n"
)
NOOP = (
    _HEADER + "@@ -1,3 +1,3 @@\n def delete_user(user, target):\n"
    f"     {OP}\n-    return True\n+    return None\n"
)
PRE_CTX = (
    "#### Target definition: `app.py:delete_user` (lines 1-4)\n\n```python\n"
    f"def delete_user(user, target):\n    {GUARD}\n    {OP}\n    return True\n```\n"
)
PRE_CTX_UNGUARDED = (
    "#### Target definition: `app.py:delete_user` (lines 1-3)\n\n```python\n"
    f"def delete_user(user, target):\n    {OP}\n    return True\n```\n"
)
POST_CTX_REMOVED = (
    "### Post-patch definitions\n\n"
    "#### Post-patch definition: `app.py:delete_user` (lines 1-3)\n\n```python\n"
    f"def delete_user(user, target):\n    {OP}\n    return True\n```\n"
)


def _v2(op_prov, guard_prov, ds_prov="user.is_admin", eff_prov="raise PermissionError()"):
    return (
        "1. Role: primary\n"
        "   Description: authorization check before delete\n"
        "   Operation present in evidence: present\n"
        f"   Operation provenance: {op_prov}\n"
        "   Preceding guard: present\n"
        f"   Guard provenance: {guard_prov}\n"
        "   Function provenance: none\n"
        "   Guard default state: condition_true_under_default\n"
        f"   Guard default state provenance: {ds_prov}\n"
        "   Guard effect: prevents_operation\n"
        f"   Guard effect provenance: {eff_prov}\n"
        "   Reentry state propagation: not_applicable\n"
        "   Reentry provenance: none\n"
        "   Requires explicit non-default action: false\n"
        "   Override provenance: none\n"
        "   Contract addresses override: not_applicable\n"
        "   Scope provenance: none\n"
        "   Hypothesized outcome: none\n"
    )


def _v1(reach_prov):
    return (
        "1. Role: primary\n"
        "   Description: authorization check before delete\n"
        "   Default execution reachability: blocked\n"
        f"   Reachability provenance: {reach_prov}\n"
        "   Requires explicit non-default action: false\n"
        "   Override provenance: none\n"
        "   Contract addresses override: not_applicable\n"
        "   Scope provenance: none\n"
    )


def _decide(patch, block, code_context="", tmp_path=None):
    reply = (
        f"Verification status: VERIFIED_FIXED\n\nConcerns:\n\n{block}\n"
        "Edge cases:\n- none\n\nPotential issues:\n- none\n\nSummary:\n- none\n"
    )
    llm = mock.MagicMock()
    llm.complete.return_value = reply
    prov = _challenger_provenance_context([code_context], code_context) if code_context else None
    ch = challenge_patch(VULN, patch, llm, code_context=code_context, provenance_context=prov)
    result = PipelineResult(
        vulnerability_text=VULN, patch=patch, review="**Explanation:**\nok\n",
        score_text="**Confidence score:** 0.80\n\n**Reasons:**\n- ok", challenger=ch,
        impact={"impact_level": "low", "changed_files": [], "affected_files": [], "impact_summary": "",
                "recommendations": [], "usage_matches": []},
        hygiene=[], applicability={"applicable": True, "skipped": False, "skipped_reason": None,
                                   "error": None, "stderr": ""},
        repo_root=Path(tmp_path), detected_language="python",
    )
    report = _build_report(result)
    decisions = re.findall(
        r"\*\*(Deploy After Validation|Deploy With Caution|Manual Review Required|Do Not Apply)\*\*", report
    )
    return ch["verification_status"], decisions[0]


class TestRemovedGuardNeverVerifies:
    @pytest.mark.parametrize("code_context", ["", PRE_CTX, PRE_CTX + "\n\n" + POST_CTX_REMOVED],
                             ids=["diff-only", "pre-change-ctx", "pre-and-post-ctx"])
    def test_citing_the_removed_guard(self, tmp_path, code_context):
        status, decision = _decide(REMOVING, _v2(OP, GUARD), code_context, tmp_path)
        assert status != "VERIFIED_FIXED"
        assert decision != "Deploy After Validation"

    def test_citing_the_removed_line_with_its_minus_prefix(self, tmp_path):
        status, decision = _decide(REMOVING, _v2(OP, f"-    {GUARD}"), "", tmp_path)
        assert status != "VERIFIED_FIXED"
        assert decision != "Deploy After Validation"

    @pytest.mark.parametrize("patch,code_context", [
        (ADDING, ""), (ADDING, PRE_CTX_UNGUARDED), (CONTEXT, ""), (CONTEXT, PRE_CTX),
    ], ids=["added", "added-with-ctx", "context-line", "context-line-with-ctx"])
    def test_guard_present_after_the_patch_still_verifies(self, tmp_path, patch, code_context):
        status, decision = _decide(patch, _v2(OP, GUARD), code_context, tmp_path)
        assert status == "VERIFIED_FIXED"
        assert decision == "Deploy After Validation"


class TestDiffMetadataIsNeverACitation:
    @pytest.mark.parametrize("quote", [
        "+++", "---", "@@ -", "+++ b/app.py", "--- a/app.py", "diff --git", "index 1111111", "@@ -1,3 +1,3 @@",
    ])
    def test_v1_reachability_citation(self, tmp_path, quote):
        status, decision = _decide(NOOP, _v1(quote), "", tmp_path)
        assert status != "VERIFIED_FIXED"
        assert decision != "Deploy After Validation"

    def test_v2_supporting_citations(self, tmp_path):
        status, decision = _decide(
            NOOP, _v2(OP, "def delete_user(user, target):", "@@ -1,3", "+++ b/app.py"), "", tmp_path
        )
        assert status != "VERIFIED_FIXED"
        assert decision != "Deploy After Validation"

    def test_v1_real_citation_control(self, tmp_path):
        status, decision = _decide(CONTEXT, _v1(GUARD), "", tmp_path)
        assert status == "VERIFIED_FIXED"
        assert decision == "Deploy After Validation"


class TestMidIdentifierFragmentsAreNotCitations:
    def test_v2_fragments(self, tmp_path):
        status, decision = _decide(NOOP, _v2("ete", "def", "use", "Tru"), "", tmp_path)
        assert status != "VERIFIED_FIXED"
        assert decision != "Deploy After Validation"

    def test_v1_fragment(self, tmp_path):
        status, decision = _decide(NOOP, _v1("ret"), "", tmp_path)
        assert status != "VERIFIED_FIXED"
        assert decision != "Deploy After Validation"
