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


def _v2(op_prov, guard_prov, ds_prov="user.is_admin", eff_prov="raise PermissionError()",
        description="authorization check before delete", hypothesis="none", role="1. Role: primary"):
    return (
        f"{role}\n"
        f"   Description: {description}\n"
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
        f"   Hypothesized outcome: {hypothesis}\n"
    )


def _v1(reach_prov, description="authorization check before delete"):
    return (
        "1. Role: primary\n"
        f"   Description: {description}\n"
        "   Default execution reachability: blocked\n"
        f"   Reachability provenance: {reach_prov}\n"
        "   Requires explicit non-default action: false\n"
        "   Override provenance: none\n"
        "   Contract addresses override: not_applicable\n"
        "   Scope provenance: none\n"
    )


def _decide(patch, block, code_context="", tmp_path=None, header="VERIFIED_FIXED"):
    status_line = f"Verification status: {header}\n\n" if header is not None else ""
    reply = (
        f"{status_line}Concerns:\n\n{block}\n"
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
    _decide.last = (ch, report)
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


ADDING_WITH_RULE = (
    _HEADER + "@@ -1,3 +1,5 @@\n def delete_user(user, target):\n"
    f"+    # ======\n+    {GUARD}\n     {OP}\n     return True\n"
)


class TestCitationMustContainIdentifierCharacter:
    """A quote with no identifier character proves nothing even when it is
    real post-change text: `======` is a genuine added line here."""

    def test_punctuation_only_quote_is_never_a_citation(self, tmp_path):
        status, decision = _decide(ADDING_WITH_RULE, _v1("======"), "", tmp_path)
        assert status != "VERIFIED_FIXED"
        assert decision != "Deploy After Validation"

    def test_real_guard_citation_control(self, tmp_path):
        status, decision = _decide(ADDING_WITH_RULE, _v1(GUARD), "", tmp_path)
        assert status == "VERIFIED_FIXED"
        assert decision == "Deploy After Validation"


_BOTH_SCHEMAS = {
    "v1": lambda **kw: _v1(GUARD, **{k: v for k, v in kw.items() if k == "description"}),
    "v2": lambda **kw: _v2(OP, GUARD, **kw),
}


class TestSelfContradictingResponseFailsClosed:
    """PR #763 review: when the Challenger's own text concludes that the
    vulnerability is not fixed, valid citations that would otherwise compute
    VERIFIED_FIXED must not turn that into Deploy After Validation."""

    def _assert_failed_closed(self, status, decision, needle):
        ch, report = _decide.last
        assert status == "INSUFFICIENT_EVIDENCE"
        assert decision == "Manual Review Required"
        assert needle in ch["verdict_conflict"]
        assert "**Failed closed:**" in report and needle in report

    @pytest.mark.parametrize("schema", ["v1", "v2"])
    @pytest.mark.parametrize("header", ["RESIDUAL_VULNERABILITY", "INSUFFICIENT_EVIDENCE"])
    def test_negative_status_header(self, tmp_path, schema, header):
        status, decision = _decide(ADDING, _BOTH_SCHEMAS[schema](), "", tmp_path, header=header)
        self._assert_failed_closed(status, decision, header)

    def test_legacy_still_vulnerable_yes_header(self, tmp_path):
        status, decision = _decide(
            ADDING, _v2(OP, GUARD), "", tmp_path, header="VERIFIED_FIXED\nStill vulnerable: Yes"
        )
        self._assert_failed_closed(status, decision, "Still vulnerable")

    @pytest.mark.parametrize("schema", ["v1", "v2"])
    def test_primary_description_says_still_exploitable(self, tmp_path, schema):
        block = _BOTH_SCHEMAS[schema](description="The issue remains exploitable via the bulk endpoint.")
        status, decision = _decide(ADDING, block, "", tmp_path)
        self._assert_failed_closed(status, decision, "Description")

    def test_primary_hypothesized_outcome_says_still_bypassable(self, tmp_path):
        block = _v2(OP, GUARD, hypothesis="An attacker can still bypass the check through the bulk endpoint.")
        status, decision = _decide(ADDING, block, "", tmp_path)
        self._assert_failed_closed(status, decision, "Hypothesized outcome")

    # --- controls: consistent responses keep their fact-based verdict ---

    @pytest.mark.parametrize("schema", ["v1", "v2"])
    def test_consistent_verified_response_still_deploys(self, tmp_path, schema):
        status, decision = _decide(ADDING, _BOTH_SCHEMAS[schema](), "", tmp_path)
        assert status == "VERIFIED_FIXED"
        assert decision == "Deploy After Validation"
        assert "verdict_conflict" not in _decide.last[0]

    def test_question_and_negated_text_is_not_a_negative_conclusion(self, tmp_path):
        block = _v2(
            OP, GUARD,
            description="Whether the issue remains exploitable after the patch under default execution.",
            hypothesis="The delete is no longer exploitable because the guard raises before it runs.",
        )
        status, decision = _decide(ADDING, block, "", tmp_path)
        assert status == "VERIFIED_FIXED"
        assert decision == "Deploy After Validation"

    def test_additional_concern_text_is_not_read(self, tmp_path):
        block = _v2(OP, GUARD) + "\n" + _v2(
            OP, GUARD, role="2. Role: additional",
            description="The issue remains exploitable when a caller passes a non-default override.",
        )
        status, decision = _decide(ADDING, block, "", tmp_path)
        assert status == "VERIFIED_FIXED"
        assert decision == "Deploy After Validation"

    def test_missing_header_keeps_the_fact_based_verdict(self, tmp_path):
        status, decision = _decide(ADDING, _v2(OP, GUARD), "", tmp_path, header=None)
        assert status == "VERIFIED_FIXED"
        assert decision == "Deploy After Validation"


class TestStillExploitableDetector:
    @pytest.mark.parametrize("text", [
        "The issue remains exploitable via the bulk endpoint.",
        "The endpoint is still vulnerable to the same payload.",
        "Guards were added; the original request remains fully exploitable.",
        "An attacker can still bypass the check through the bulk endpoint.",
        "The token could still be exploited by a replayed request.",
    ])
    def test_declarative_assertions(self, text):
        from utilities.autopatcher.patch_challenger import _asserts_still_exploitable
        assert _asserts_still_exploitable(text)

    @pytest.mark.parametrize("text", [
        None, "", "none",
        "Whether the issue remains exploitable after the patch.",
        "Is the endpoint still vulnerable?",
        "If a caller passes allow_external=True, the operation remains exploitable.",
        "The endpoint is no longer exploitable.",
        "The operation is not still vulnerable after the guard.",
        "Nothing remains exploitable once the guard raises.",
        # real recorded primary-concern text (release-regression batches)
        "Whether a server-supplied Content-Disposition filename with path separators or `../` can still "
        "make file_path escape temp_dir.",
        "In PoolManager.urlopen, with 'Cookie' now in the default set, the cross-origin strip loop removes "
        "the Cookie header before re-invoking, closing this path.",
        "Whether an attacker-supplied oversized range segment still reaches the backtracking-prone trimming "
        "regexes in parseRange.",
    ])
    def test_non_assertions(self, text):
        from utilities.autopatcher.patch_challenger import _asserts_still_exploitable
        assert not _asserts_still_exploitable(text)
