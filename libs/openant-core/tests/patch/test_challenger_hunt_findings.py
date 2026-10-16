"""PR #763 independent HUNT review, findings N1-N5: Challenger evidence and
verification paths that let a stubbed model reply reach VERIFIED_FIXED ->
Deploy After Validation although the reply (or the evidence) says otherwise.

Every test drives the production report path (challenge_patch with a stubbed
reply -> PipelineResult -> _build_report) with every other recommendation axis
positive, so a wrong VERIFIED_FIXED shows up as a wrong Deploy decision.
"""

import re
from pathlib import Path
from unittest import mock

import pytest

from utilities.autopatcher.patch_challenger import _asserts_still_exploitable, challenge_patch
from utilities.autopatcher.patch_generator import classify_patch_response
from utilities.autopatcher.pipeline import PipelineResult, _build_report, _challenger_provenance_context

VULN = "# Missing authorization in delete_user\n\nAny user can delete accounts via delete_user."
GUARD = "if not user.is_admin: raise PermissionError()"
OP = "db.delete(target)"
DEPLOY = "Deploy After Validation"

_HEADER = "diff --git a/app.py b/app.py\nindex 1111111..2222222 100644\n--- a/app.py\n+++ b/app.py\n"
GUARDED = (
    _HEADER + "@@ -1,3 +1,4 @@\n def delete_user(user, target):\n"
    f"+    {GUARD}\n     {OP}\n     return True\n"
)
PRE_CTX = (
    "#### Target definition: `app.py:delete_user` (lines 1-3)\n\n```python\n"
    f"def delete_user(user, target):\n    {OP}\n    return True\n```\n"
)
_LEGACY_EMPTY = "Edge cases:\n- none\n\nPotential issues:\n- none\n\nSummary:\n- none\n"


def _block(number=1, role="primary", description="authorization check before delete", op=OP, guard=GUARD,
           ds_prov="user.is_admin", effect="prevents_operation", eff_prov="raise PermissionError()",
           hypothesis="none"):
    return (
        f"{number}. Role: {role}\n"
        f"   Description: {description}\n"
        "   Operation present in evidence: present\n"
        f"   Operation provenance: {op}\n"
        "   Preceding guard: present\n"
        f"   Guard provenance: {guard}\n"
        "   Function provenance: none\n"
        "   Guard default state: condition_true_under_default\n"
        f"   Guard default state provenance: {ds_prov}\n"
        f"   Guard effect: {effect}\n"
        f"   Guard effect provenance: {eff_prov}\n"
        "   Reentry state propagation: not_applicable\n"
        "   Reentry provenance: none\n"
        f"   Requires explicit non-default action: {'false' if effect != 'no_effect' else 'not_applicable'}\n"
        "   Override provenance: none\n"
        "   Contract addresses override: not_applicable\n"
        "   Scope provenance: none\n"
        f"   Hypothesized outcome: {hypothesis}\n"
    )


def _reply(blocks=None, status="VERIFIED_FIXED", pre="", between="", legacy=_LEGACY_EMPTY):
    return (
        f"{pre}Verification status: {status}\n\n{between}Concerns:\n\n"
        f"{_block() if blocks is None else blocks}\n{legacy}"
    )


def _decide(reply, patch=GUARDED, code_context=PRE_CTX, tmp_path=".", vuln=VULN):
    llm = mock.MagicMock()
    llm.complete.return_value = reply
    prov = _challenger_provenance_context([code_context], code_context) if code_context else None
    ch = challenge_patch(vuln, patch, llm, code_context=code_context, provenance_context=prov)
    result = PipelineResult(
        vulnerability_text=vuln, patch=patch, review="**Explanation:**\nok\n",
        score_text="**Confidence score:** 0.80\n\n**Reasons:**\n- ok", challenger=ch,
        impact={"impact_level": "low", "changed_files": [], "affected_files": [], "impact_summary": "",
                "recommendations": [], "usage_matches": []},
        hygiene=[], applicability={"applicable": True, "skipped": False, "skipped_reason": None,
                                   "error": None, "stderr": ""},
        repo_root=Path(tmp_path), detected_language="python",
    )
    decisions = re.findall(
        r"\*\*(Deploy After Validation|Deploy With Caution|Manual Review Required|Do Not Apply)\*\*",
        _build_report(result),
    )
    return ch, decisions[0]


def _assert_not_deployed(ch, decision):
    assert ch["verification_status"] != "VERIFIED_FIXED"
    assert decision != DEPLOY


def _assert_deployed(ch, decision):
    assert ch["verification_status"] == "VERIFIED_FIXED", ch.get("summary")
    assert decision == DEPLOY


def test_fixture_verifies(tmp_path):
    """The shared fixture is a genuinely verifiable fix: each test below
    changes exactly one thing about it."""
    _assert_deployed(*_decide(_reply(), tmp_path=tmp_path))


# ---------------------------------------------------------------------------
# N1 -- content outside the parsed sections must not be silently dropped.
# ---------------------------------------------------------------------------

_EXPLOITABLE = "A symlink inside the upload dir means the traversal remains exploitable."
_BLOCKING_2 = _block(2, "additional", "Another entry point deletes without the check.", effect="no_effect")


class TestN1UnaccountedResponseContent:
    @pytest.mark.parametrize("reply", [
        _reply(pre=_EXPLOITABLE + "\n\n"),
        _reply(status="VERIFIED_FIXED\n" + _EXPLOITABLE),
        _reply(blocks=_EXPLOITABLE + "\n" + _block()),
        _reply(legacy="**Edge cases:**\n- none\n\n**Potential issues:**\n- " + _EXPLOITABLE + "\n\n**Summary:**\n- none\n"),
        _reply(legacy="### Potential issues\n- " + _EXPLOITABLE + "\n"),
        _reply(status="VERIFIED_FIXED\n" + _BLOCKING_2),
    ], ids=["preamble", "status-second-line", "prose-before-first-block", "bold-legacy-headers",
            "markdown-heading-legacy", "blocking-block-before-concerns"])
    def test_hunt_reproductions_fail_closed(self, tmp_path, reply):
        _assert_not_deployed(*_decide(reply, tmp_path=tmp_path))

    @pytest.mark.parametrize("reply", [
        # a whole BLOCKING block placed after the legacy sections
        _reply(legacy=_LEGACY_EMPTY + "\n" + _BLOCKING_2),
        # a second Verification status header further down
        _reply(legacy=_LEGACY_EMPTY + "\nVerification status: RESIDUAL_VULNERABILITY\n"),
        # a repeated legacy header (the parser keeps only the last body)
        _reply(legacy="Edge cases:\n- " + _EXPLOITABLE + "\n\nEdge cases:\n- none\n\nPotential issues:\n- none\n\n"
               "Summary:\n- none\n"),
        # an indented (non-column-0) section header
        _reply(legacy="  Potential issues:\n- " + _EXPLOITABLE + "\n\nSummary:\n- none\n"),
        # a separate paragraph inside the last concern block
        _reply(blocks=_block() + "\n   The bulk endpoint still deletes accounts without any check.\n"),
        # prose between the status line and the Concerns header
        _reply(between="I could not confirm the guard runs for the bulk endpoint.\n\n"),
        # a line after a one-line (closed-vocabulary) field
        _reply(_block().replace("Guard effect: prevents_operation\n",
                                "Guard effect: prevents_operation\n   except on the bulk endpoint, which skips it\n")),
        # a line directly after a `none` placeholder (the HUNT verifier's own variant)
        _reply(_block() + "   Negative input remains exploitable.\n"),
    ], ids=["blocking-block-at-end", "second-status-header", "repeated-legacy-header",
            "indented-section-header", "paragraph-inside-block", "prose-before-concerns-header",
            "line-after-one-line-field", "line-after-none-placeholder"])
    def test_adversarial_variations_fail_closed(self, tmp_path, reply):
        _assert_not_deployed(*_decide(reply, tmp_path=tmp_path))

    def test_failure_is_reported_as_structural(self, tmp_path):
        ch, _ = _decide(_reply(pre=_EXPLOITABLE + "\n\n"), tmp_path=tmp_path)
        assert ch["verification_status"] == "INSUFFICIENT_EVIDENCE"
        assert "outside its recognized sections" in ch["summary"]

    @pytest.mark.parametrize("reply", [
        _reply(),
        _reply(status="\nVERIFIED_FIXED"),  # the status value on the line after its header
        _reply(pre="\n\n"),  # blank lines only
        _reply(_block(description="authorization check\n     before delete")),  # a wrapped field value
    ], ids=["canonical", "status-on-next-line", "blank-preamble", "wrapped-description"])
    def test_supported_shapes_still_verify(self, tmp_path, reply):
        _assert_deployed(*_decide(reply, tmp_path=tmp_path))

    def test_multi_line_code_quote_still_verifies(self, tmp_path):
        """Recorded urllib3 runs quote a multi-line call over several lines;
        the whole quote is now read (previously only its first line)."""
        patch = (_HEADER + "@@ -1,4 +1,5 @@\n def delete_user(user, target):\n"
                 f"+    {GUARD}\n     db.delete(\n         target)\n     return True\n")
        ctx = PRE_CTX.replace(f"    {OP}\n", "    db.delete(\n        target)\n").replace("lines 1-3", "lines 1-4")
        reply = _reply(_block(op="db.delete(\n                target)"))
        ch, decision = _decide(reply, patch=patch, code_context=ctx, tmp_path=tmp_path)
        _assert_deployed(ch, decision)

    def test_blocking_block_inside_concerns_still_blocks(self, tmp_path):
        ch, decision = _decide(_reply(blocks=_block() + _BLOCKING_2), tmp_path=tmp_path)
        assert ch["verification_status"] == "RESIDUAL_VULNERABILITY"
        assert decision != DEPLOY


# ---------------------------------------------------------------------------
# N2 -- a guard in a separate (nested, never-called) scope is not the
# operation's guard.
# ---------------------------------------------------------------------------

def _py_patch(added, new_len):
    body = "".join(f"+{line}\n" for line in added)
    return _HEADER + f"@@ -1,3 +1,{new_len} @@\n def delete_user(user, target):\n{body}     {OP}\n     return True\n"


_JS_HEADER = "diff --git a/app.js b/app.js\nindex 1111111..2222222 100644\n--- a/app.js\n+++ b/app.js\n"
JS_GUARD = "if (!user.isAdmin) { throw new Error(\"denied\"); }"


def _js_patch(added):
    body = "".join(f"+{line}\n" for line in added)
    return (_JS_HEADER + f"@@ -1,4 +1,{4 + len(added)} @@\n function deleteUser(user, target) {{\n{body}"
            f"   {OP};\n   return true;\n }}\n")


def _js_block():
    return _block(guard=JS_GUARD, ds_prov="user.isAdmin", eff_prov="throw new Error")


class TestN2NestedScopeGuard:
    def test_nested_never_called_def(self, tmp_path):
        patch = _py_patch(["    def _check():", f"        {GUARD}"], 5)
        _assert_not_deployed(*_decide(_reply(), patch=patch, tmp_path=tmp_path))

    @pytest.mark.parametrize("added", [
        ["    class _Checker:", "        def run(self):", f"            {GUARD}"],
        ["    async def _check():", f"        {GUARD}"],
        ["    @staticmethod", "    def _check():", f"        {GUARD}"],
    ], ids=["nested-class-method", "nested-async-def", "decorated-nested-def"])
    def test_python_nested_scopes(self, tmp_path, added):
        _assert_not_deployed(*_decide(_reply(), patch=_py_patch(added, 3 + len(added)), tmp_path=tmp_path))

    def test_guard_inside_a_lambda(self, tmp_path):
        patch = _py_patch(["    _check = lambda: _deny() if not user.is_admin else None"], 4)
        reply = _reply(_block(guard="if not user.is_admin", eff_prov="else None"))
        _assert_not_deployed(*_decide(reply, patch=patch, tmp_path=tmp_path))

    @pytest.mark.parametrize("added", [
        ["  function check() {", f"    {JS_GUARD}", "  }"],
        ["  const check = () => {", f"    {JS_GUARD}", "  };"],
        ["  items.forEach((item) => {", f"    {JS_GUARD}", "  });"],
    ], ids=["nested-function", "arrow-function", "callback"])
    def test_brace_language_nested_scopes(self, tmp_path, added):
        _assert_not_deployed(*_decide(_reply(_js_block()), patch=_js_patch(added), code_context="",
                                      tmp_path=tmp_path))

    def test_enclosing_scope_not_shown_fails_closed(self, tmp_path):
        """The guard is indented deeper than the operation, and the hunk does
        not show the line that opens the guard's block: nothing establishes
        that block is not a nested function."""
        patch = _HEADER + f"@@ -5,2 +5,3 @@\n+        {GUARD}\n     {OP}\n     return True\n"
        _assert_not_deployed(*_decide(_reply(), patch=patch, code_context="", tmp_path=tmp_path))

    def test_inline_guard_still_verifies(self, tmp_path):
        _assert_deployed(*_decide(_reply(), patch=_py_patch([f"    {GUARD}"], 4), tmp_path=tmp_path))

    @pytest.mark.parametrize("added", [
        ["    if target.protected:", f"        {GUARD}"],
        ["    with audit_lock:", f"        {GUARD}"],
        ["    try:", f"        {GUARD}", "    finally:", "        audit()"],
    ], ids=["conditional-block", "with-block", "try-block"])
    def test_guard_in_a_control_block_is_still_accepted(self, tmp_path, added):
        """Documented: whether a control-flow block runs is the Challenger's
        judgment, not textual scope (recommendation-policy.md)."""
        _assert_deployed(*_decide(_reply(), patch=_py_patch(added, 3 + len(added)), tmp_path=tmp_path))

    def test_guard_under_a_multi_line_if_header_is_still_accepted(self, tmp_path):
        """Shape of the recorded urllib3 redirect guard: a loop inside an
        `if (` header that wraps and closes on its own `):` line. The
        closing line is not the block's opener."""
        added = ["    if target.protected and not user.same_tenant(", "        target", "    ):",
                 "        for _ in range(1):", f"            {GUARD}"]
        _assert_deployed(*_decide(_reply(), patch=_py_patch(added, 3 + len(added)), tmp_path=tmp_path))

    @pytest.mark.parametrize("added", [
        ["    def _check(", "        strict=True,", "    ):", f"        {GUARD}"],
        ["    def _check():", "# a comment at column 0", f"        {GUARD}"],
        ["    def _check():", '        note = """', "text at column 0", '"""', f"        {GUARD}"],
    ], ids=["nested-def-with-multi-line-signature", "dedented-comment-before-guard",
            "dedented-string-before-guard"])
    def test_closers_and_comments_do_not_hide_a_nested_def(self, tmp_path, added):
        _assert_not_deployed(*_decide(_reply(), patch=_py_patch(added, 3 + len(added)), tmp_path=tmp_path))

    def test_brace_language_inline_guard_still_verifies(self, tmp_path):
        _assert_deployed(*_decide(_reply(_js_block()), patch=_js_patch([f"  {JS_GUARD}"]), code_context="",
                                  tmp_path=tmp_path))


# ---------------------------------------------------------------------------
# N3 -- only real post-change diff content is patch citation authority.
# ---------------------------------------------------------------------------

_STRICT_SRC_HEADER = "diff --git a/svc.py b/svc.py\n--- a/svc.py\n+++ b/svc.py\n"
STRICT_GUARD = "if strict and not user.is_admin:"
STRICT_DIFF = (
    _STRICT_SRC_HEADER + "@@ -1,3 +1,5 @@\n def delete_user(user, target, strict=False):\n"
    f"+    {STRICT_GUARD}\n+        raise PermissionError()\n     {OP}\n     return True\n"
)
_PROSE = "The guard is on by default because every production caller passes strict=True.\n"
STRICT_CTX = (
    "#### Target definition: `svc.py:delete_user` (lines 1-3)\n\n```python\n"
    f"def delete_user(user, target, strict=False):\n    {OP}\n    return True\n```\n"
)


def _strict_reply():
    return _reply(_block(guard=STRICT_GUARD, ds_prov="strict=True"))


class TestN3GeneratorProseIsNotEvidence:
    @pytest.mark.parametrize("patch", [
        _PROSE + "\n" + STRICT_DIFF,
        STRICT_DIFF + "\n" + _PROSE,
        STRICT_DIFF.replace("     return True\n", "     return True\n" + _PROSE),
    ], ids=["leading-prose", "trailing-prose", "prose-right-after-hunk"])
    def test_prose_never_grounds_a_citation(self, tmp_path, patch):
        ch, decision = _decide(_strict_reply(), patch=patch, code_context=STRICT_CTX, tmp_path=tmp_path)
        assert ch["concerns"][0]["reachability_facts"]["guard_default_state"] != "condition_true_under_default"
        _assert_not_deployed(ch, decision)

    def test_diff_without_hunk_header_is_not_citable(self, tmp_path):
        patch = "--- a/svc.py\n+++ b/svc.py\n" + _PROSE + f"+    {STRICT_GUARD}\n"
        ch, decision = _decide(_strict_reply(), patch=patch, code_context=STRICT_CTX, tmp_path=tmp_path)
        _assert_not_deployed(ch, decision)

    def test_added_line_is_still_citable(self, tmp_path):
        """Positive control: the same citation, made true by the patch's own
        added line, still verifies."""
        patch = STRICT_DIFF.replace(
            " def delete_user(user, target, strict=False):\n",
            "-def delete_user(user, target, strict=False):\n+def delete_user(user, target, strict=True):\n",
        ).replace("@@ -1,3 +1,5 @@", "@@ -1,3 +1,5 @@")
        _assert_deployed(*_decide(_strict_reply(), patch=patch, code_context=STRICT_CTX, tmp_path=tmp_path))

    @pytest.mark.parametrize("raw", [
        _PROSE + "\n" + STRICT_DIFF,
        STRICT_DIFF + "\nThis blocks every default caller.\n",
        "Here is the fix:\n" + STRICT_DIFF.replace(_STRICT_SRC_HEADER, ""),
    ], ids=["prose-before", "prose-after", "prose-before-bare-hunk"])
    def test_unfenced_diff_with_prose_is_a_contract_violation(self, raw):
        result = classify_patch_response(raw)
        assert result.status == "contract_violation"
        assert result.diff == ""

    @pytest.mark.parametrize("raw,status", [
        (STRICT_DIFF, "no_diff"),  # a clean unfenced diff: unchanged legacy route
        ("No patch is possible: the vulnerable code is not in the supplied evidence.", "no_diff"),
        ("```diff\n" + STRICT_DIFF + "```\n", "valid"),
    ], ids=["clean-unfenced-diff", "honest-non-answer", "fenced"])
    def test_other_responses_are_unchanged(self, raw, status):
        result = classify_patch_response(raw)
        assert result.status == status
        if status == "no_diff":
            assert result.diff == raw.strip()


# ---------------------------------------------------------------------------
# N4 -- removing a line in one place does not erase an identical line
# elsewhere.
# ---------------------------------------------------------------------------

REWRITE = (
    _HEADER + "@@ -1,3 +1,4 @@\n def delete_user(user, target):\n"
    f"+    {GUARD}\n-    {OP}\n+    db.delete(target, audited=True)\n     return True\n"
)


def _located(path, function, first, source):
    last = first + len(source.splitlines()) - 1
    return f"#### Related definition (context only, not an approved edit target): `{path}:{function}` " \
           f"(lines {first}-{last})\n\n```python\n{source}```\n"


OTHER = f"def purge_user(user, target):\n    {OP}\n    return True\n"


class TestN4RemovedTextIsLocationScoped:
    def test_identical_unpatched_call_site_in_another_file(self, tmp_path):
        ctx = PRE_CTX + "\n" + _located("admin.py", "purge_user", 10, OTHER)
        reply = _reply(_block(op="db.delete(target"))
        _assert_not_deployed(*_decide(reply, patch=REWRITE, code_context=ctx, tmp_path=tmp_path))

    def test_identical_unpatched_call_site_in_the_same_file(self, tmp_path):
        ctx = PRE_CTX + "\n" + _located("app.py", "purge_user", 20, OTHER)
        reply = _reply(_block(op="db.delete(target"))
        _assert_not_deployed(*_decide(reply, patch=REWRITE, code_context=ctx, tmp_path=tmp_path))

    def test_identical_call_site_without_a_location_fails_closed(self, tmp_path):
        ctx = PRE_CTX + "\n#### Discovered consumer: somewhere\n\n```python\n" + OTHER + "```\n"
        reply = _reply(_block(op="db.delete(target"))
        _assert_not_deployed(*_decide(reply, patch=REWRITE, code_context=ctx, tmp_path=tmp_path))

    def test_rewritten_call_site_alone_still_verifies(self, tmp_path):
        """Positive control: the pre-change copy of the patched line itself
        is decided by its hunk, exactly as before."""
        reply = _reply(_block(op="db.delete(target"))
        _assert_deployed(*_decide(reply, patch=REWRITE, code_context=PRE_CTX, tmp_path=tmp_path))

    def test_guarded_call_site_elsewhere_still_verifies(self, tmp_path):
        guarded = f"def purge_user(user, target):\n    {GUARD}\n    {OP}\n    return True\n"
        ctx = PRE_CTX + "\n" + _located("admin.py", "purge_user", 10, guarded)
        reply = _reply(_block(op="db.delete(target"))
        _assert_deployed(*_decide(reply, patch=REWRITE, code_context=ctx, tmp_path=tmp_path))

    def test_removed_guard_still_never_verifies(self, tmp_path):
        """The conservative citation rule is kept: a guard the patch removes
        cannot be cited from its pre-change copy anywhere."""
        removing = (_HEADER + "@@ -1,4 +1,3 @@\n def delete_user(user, target):\n"
                    f"-    {GUARD}\n     {OP}\n     return True\n")
        ctx = PRE_CTX.replace(f"    {OP}\n", f"    {GUARD}\n    {OP}\n").replace("lines 1-3", "lines 1-4")
        _assert_not_deployed(*_decide(_reply(), patch=removing, code_context=ctx, tmp_path=tmp_path))


_CFG_HEADER = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n"
_CFG_GUARD = "if strict and not user.is_admin: raise PermissionError()"
_CFG_APP = ("def delete_user(user, target, strict=STRICT_DEFAULT):\n    db.delete(target)\n    return True\n\n\n"
            "DEBUG = (\n    True\n    and False\n)\n")
_CFG_GUARD_HUNK = (f"@@ -1,3 +1,4 @@\n def delete_user(user, target, strict=STRICT_DEFAULT):\n+    {_CFG_GUARD}\n"
                   "     db.delete(target)\n     return True\n")
_CFG_DEBUG_HUNK = "@@ -6,4 +7,4 @@\n DEBUG = (\n     True\n-    and False\n+    and True\n )\n"
_CFG_CTX = _located("app.py", "delete_user", 1, _CFG_APP).replace("Related definition (context only, not an approved "
                                                                    "edit target)", "Target definition")
_CFG_FALSE = _located("config.py", "STRICT_DEFAULT", 1, "STRICT_DEFAULT = (\n    True\n    and False\n)\n")
_CFG_TRUE = _located("config.py", "STRICT_DEFAULT", 1, "STRICT_DEFAULT = (\n    True\n)\n")


def _cfg_reply(ds_prov):
    return _reply(_block(guard=_CFG_GUARD, ds_prov=ds_prov))


class TestN4CitationFilteringIsConservative:
    """The citation corpus still excludes every line whose text the patch
    removes (a removed guard must never read as present). Excluding a line
    must never join the lines around it into a quote that occurs nowhere."""

    def test_quote_skipping_a_line_removed_elsewhere_is_not_evidence(self, tmp_path):
        """`config.py` is unpatched and says `True and False`; the patch
        removes an identical `and False` line from app.py. The quote
        `STRICT_DEFAULT = ( True )` must not validate."""
        patch = _CFG_HEADER + _CFG_GUARD_HUNK + _CFG_DEBUG_HUNK
        _assert_not_deployed(*_decide(_cfg_reply("STRICT_DEFAULT = ( True )"), patch=patch,
                                      code_context=_CFG_CTX + _CFG_FALSE, tmp_path=tmp_path))

    def test_the_same_quote_of_a_true_default_still_verifies(self, tmp_path):
        patch = _CFG_HEADER + _CFG_GUARD_HUNK + _CFG_DEBUG_HUNK
        _assert_deployed(*_decide(_cfg_reply("STRICT_DEFAULT = ( True )"), patch=patch,
                                  code_context=_CFG_CTX + _CFG_TRUE, tmp_path=tmp_path))

    @pytest.mark.parametrize("ctx", [_CFG_CTX + _CFG_FALSE, _CFG_CTX], ids=["other-file", "same-file"])
    def test_identical_surviving_line_is_suppressed_never_promoted(self, tmp_path, ctx):
        """Conservative direction: a surviving copy of removed text cannot be
        cited either (the citation is lost, never gained)."""
        patch = _CFG_HEADER + _CFG_GUARD_HUNK + _CFG_DEBUG_HUNK
        _assert_not_deployed(*_decide(_cfg_reply("    and False"), patch=patch, code_context=ctx, tmp_path=tmp_path))

    def test_removed_line_re_added_inside_a_hunk_is_still_citable(self, tmp_path):
        readd = _CFG_DEBUG_HUNK.replace("+    and True\n", "+    and False\n")
        patch = _CFG_HEADER + _CFG_GUARD_HUNK + readd
        _assert_deployed(*_decide(_cfg_reply("and False"), patch=patch, code_context=_CFG_CTX, tmp_path=tmp_path))

    def test_removed_text_only_in_prose_around_the_diff_is_not_citable(self, tmp_path):
        patch = "Note: STRICT_DEFAULT = ( True )\n\n" + _CFG_HEADER + _CFG_GUARD_HUNK + _CFG_DEBUG_HUNK
        _assert_not_deployed(*_decide(_cfg_reply("STRICT_DEFAULT = ( True )"), patch=patch,
                                      code_context=_CFG_CTX, tmp_path=tmp_path))


# ---------------------------------------------------------------------------
# N5 -- a primary concern that says the issue remains exploitable is never
# read as VERIFIED_FIXED.
# ---------------------------------------------------------------------------

class TestN5SelfContradiction:
    @pytest.mark.parametrize("field,text", [
        ("description", "Review of the authorization check.\n     The bulk endpoint remains exploitable."),
        ("description", "It isn't fixed: the path remains exploitable."),
        ("hypothesis", "The check runs first.\n     However, the bulk endpoint is still vulnerable."),
        ("hypothesis", "The guard does not cover bulk deletes, so the endpoint remains exploitable."),
        ("description", "No admin check is skipped here, but the export path remains exploitable."),
    ], ids=["description-continuation", "negation-of-another-clause", "hypothesis-continuation",
            "negation-before-comma-clause", "negative-quantifier-in-other-clause"])
    def test_contradiction_is_detected(self, tmp_path, field, text):
        ch, decision = _decide(_reply(_block(**{field: text})), tmp_path=tmp_path)
        _assert_not_deployed(ch, decision)
        assert "verdict_conflict" in ch

    @pytest.mark.parametrize("text", [
        "The path is not still exploitable.",
        "Nothing remains exploitable once the guard raises.",
        "The endpoint does not remain exploitable after the check.",
        "The endpoint isn't still vulnerable.",
        "No request path remains exploitable.",
        "Whether the issue remains exploitable after the patch.",
    ])
    def test_negated_and_conditional_forms_are_not_contradictions(self, tmp_path, text):
        ch, decision = _decide(_reply(_block(description=text)), tmp_path=tmp_path)
        assert "verdict_conflict" not in ch
        _assert_deployed(ch, decision)

    @pytest.mark.parametrize("text,expected", [
        ("It isn't fixed: the path remains exploitable.", True),
        ("The fix is incomplete, and the token can still be bypassed.", True),
        ("Not only is it unfixed, the endpoint is still vulnerable.", True),
        ("The patch is not a full fix because the endpoint remains exploitable.", True),
        ("The endpoint is not still vulnerable.", False),
        ("The token cannot still be bypassed.", False),
        ("None of the callers remain exploitable.", False),
    ])
    def test_negation_scope(self, text, expected):
        assert _asserts_still_exploitable(text) is expected
