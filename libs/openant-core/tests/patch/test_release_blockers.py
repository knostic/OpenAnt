"""Release-blocker regressions (final release review, RB-1..RB-4).

RB-1  The model's own stated verdict must never decide the recommendation:
      a Challenger response without trustworthy structured `Concerns:`
      evidence fails closed, whatever verdict it states.
RB-2  A BLOCKING concern must not disappear because its numbering/heading
      differs from the expected format; ambiguous structure fails closed.
RB-3  "Could not attribute the changed code" is not evidence of Low Risk.
RB-4  The sink inventory never reads file content outside the resolved
      repo_root.

Deterministic: mocked LLM text only, real parsing/policy code.
"""
from __future__ import annotations

import os
import textwrap

import pytest

from utilities.autopatcher import patch_challenger as pc
from utilities.autopatcher import pipeline as pl
from utilities.autopatcher.impact_surface import LightweightImpactAnalyzer
from utilities.autopatcher.vulnerability_patterns import (
    build_vulnerability_pattern_context,
    extract_repo_sinks,
)

# ---------------------------------------------------------------------------
# RB-1 / RB-2: Challenger parsing -> recommendation
# ---------------------------------------------------------------------------

PATCH = (
    "--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,4 @@\n"
    " def handler(req):\n+    validate(req)\n     run(req.data)\n     other_sink(req.raw)\n"
)
CTX = "```python\ndef handler(req):\n    validate(req)\n    run(req.data)\n    other_sink(req.raw)\n```"
VULN = "# Injection\n\n## Vulnerability description\n\nrun(req.data) is injectable."
APPLIES = {"applicable": True, "skipped": False, "skipped_reason": None, "error": None, "stderr": ""}

# concerns_v2 (the live schema): a legacy concerns_v1 `blocked` claim never
# verifies, so it cannot serve as the clean-response vehicle here.
PRIMARY_FIELDS = """Role: primary
   Description: original path
   Operation present in evidence: present
   Operation provenance: run(req.data)
   Preceding guard: present
   Guard provenance: validate(req)
   Function provenance: none
   Guard default state: condition_true_under_default
   Guard default state provenance: validate(req)
   Guard effect: neutralizes_operation
   Guard effect provenance: validate(req)
   Reentry state propagation: not_applicable
   Reentry provenance: none
   Requires explicit non-default action: false
   Override provenance: none
   Contract addresses override: not_applicable
   Scope provenance: none
"""
BLOCKING_FIELDS = """Role: additional
   Description: other_sink(req.raw) still receives unvalidated input
   Operation present in evidence: present
   Operation provenance: other_sink(req.raw)
   Preceding guard: present
   Guard provenance: validate(req)
   Function provenance: none
   Guard default state: condition_true_under_default
   Guard default state provenance: validate(req)
   Guard effect: no_effect
   Guard effect provenance: other_sink(req.raw)
   Reentry state propagation: not_applicable
   Reentry provenance: none
   Requires explicit non-default action: not_applicable
   Override provenance: none
   Contract addresses override: not_applicable
   Scope provenance: none
"""
PRIMARY = "1. " + PRIMARY_FIELDS
BLOCKING = "2. " + BLOCKING_FIELDS
TAIL = "\nEdge cases:\n- none\n\nPotential issues:\n- none\n\nSummary:\n- none\n"
APPROVE = "Verification status: VERIFIED_FIXED\n\n"


class _FakeLLM:
    def __init__(self, response):
        self.response = response

    def complete(self, system, user, stage=None):
        return self.response


def _challenge(response):
    return pc.challenge_patch(VULN, PATCH, _FakeLLM(response), code_context=CTX)


def _decision(challenger):
    """The decision _build_report produces for this Challenger result with
    every non-Challenger axis positive (clean, applies, low impact)."""
    report = pl._build_report(pl.PipelineResult(
        vulnerability_text=VULN, patch=PATCH, review="**Explanation:**\nok\n", score_text="",
        challenger=challenger,
        impact={"impact_level": "low", "changed_files": ["app.py"], "affected_files": [],
                "changed_symbols": ["handler"], "impact_summary": "", "recommendations": [],
                "usage_matches": []},
        hygiene=[], applicability=APPLIES, repo_root=None, detected_language="python",
    ))
    return next(line for line in report.splitlines() if line.startswith("## "))[3:]


GREEN = "🟢 DEPLOY AFTER VALIDATION"


class TestValidStructuredResponseUnchanged:
    def test_1_valid_structured_no_blocking_concern_can_be_green(self):
        challenger = _challenge(APPROVE + "Concerns:\n\n" + PRIMARY + TAIL)
        assert challenger["verification_status"] == "VERIFIED_FIXED"
        assert challenger["still_vulnerable"] is False
        assert _decision(challenger) == GREEN

    def test_2_valid_structured_blocking_concern_is_manual_review(self):
        challenger = _challenge(APPROVE + "Concerns:\n\n" + PRIMARY + "\n" + BLOCKING + TAIL)
        assert [c["consequence"] for c in challenger["concerns"]] == ["NON_BLOCKING", "BLOCKING"]
        assert challenger["still_vulnerable"] is True
        assert _decision(challenger) != GREEN

    def test_7_stated_approval_never_overrides_a_blocking_concern(self):
        challenger = _challenge(
            "Verification status: VERIFIED_FIXED\nStill vulnerable: No\n\nConcerns:\n\n"
            + PRIMARY + "\n" + BLOCKING + TAIL
        )
        assert challenger["still_vulnerable"] is True
        assert _decision(challenger) != GREEN


# RB-1: no trustworthy structured evidence -> the stated verdict is ignored.
UNSTRUCTURED_RESPONSES = {
    "missing_concerns_section": "Verification status: VERIFIED_FIXED\n\nSummary:\nThe patch fixes the issue.\n",
    "legacy_still_vulnerable_no": "Still vulnerable: No\n\nEdge cases:\n- none\n\nSummary:\nLooks fixed.\n",
    "legacy_full_example": (
        "Verification status: VERIFIED_FIXED\n\nEdge cases:\n- Binary encodings\n\n"
        "Potential issues:\n- Missing tests for unicode usernames\n\nSummary:\n- Fine.\n"
    ),
    "bold_concerns_header": APPROVE + "**Concerns:**\n\n" + PRIMARY + "\n" + BLOCKING + TAIL,
    "markdown_heading_concerns": APPROVE + "### Concerns\n\n" + PRIMARY + "\n" + BLOCKING + TAIL,
    "h2_concerns_with_colon": APPROVE + "## Concerns:\n\n" + PRIMARY + "\n" + BLOCKING + TAIL,
    "indented_concerns_header": APPROVE + " Concerns:\n\n" + PRIMARY + "\n" + BLOCKING + TAIL,
    "concerns_header_no_colon": APPROVE + "Concerns\n\n" + PRIMARY + "\n" + BLOCKING + TAIL,
    "approve_with_malformed_concerns": (
        "Verification status: VERIFIED_FIXED\nStill vulnerable: No\n\nConcerns:\n\n"
        "the patch is fine, nothing to report\n" + TAIL
    ),
    "empty_response": "",
}


@pytest.mark.parametrize("name", sorted(UNSTRUCTURED_RESPONSES))
def test_rb1_no_trustworthy_structured_evidence_fails_closed(name):
    challenger = _challenge(UNSTRUCTURED_RESPONSES[name])
    assert challenger["still_vulnerable"] is True, name
    assert challenger["verification_status"] != "VERIFIED_FIXED", name
    assert _decision(challenger) != GREEN, name


# RB-2: a BLOCKING concern whose block header differs from "N. Role:".
BLOCK_HEADER_VARIANTS = {
    "paren_number": "2) ",
    "bold_role_label": "2. **Role:**",
    "bold_number_and_role": "**2. Role:**",
    "bullet_no_number": "- ",
    "concern_word_number": "Concern 2 - ",
    "number_without_dot": "2 ",
    "markdown_heading_number": "### 2. ",
    "no_number": "",
}


# RB-2 variants found by the post-fix adversarial pass: the merged block is
# detected by its duplicated field labels, not by its header format.
MERGED_BLOCK_VARIANTS = {
    "role_dash": "2. " + BLOCKING_FIELDS.replace("Role:", "Role -", 1),
    "role_equals": "2. " + BLOCKING_FIELDS.replace("Role:", "Role =", 1),
    "role_line_missing": "2. " + BLOCKING_FIELDS.replace("Role: additional\n", "", 1),
    "no_header_no_role": BLOCKING_FIELDS.replace("Role: additional\n", "", 1),
}


@pytest.mark.parametrize("name", sorted(MERGED_BLOCK_VARIANTS))
def test_rb2_merged_concern_block_fails_closed(name):
    response = APPROVE + "Concerns:\n\n" + PRIMARY + "\n" + MERGED_BLOCK_VARIANTS[name] + TAIL
    challenger = _challenge(response)
    assert challenger["still_vulnerable"] is True, name
    assert _decision(challenger) != GREEN, name


@pytest.mark.parametrize("name", sorted(BLOCK_HEADER_VARIANTS))
def test_rb2_blocking_concern_with_variant_header_never_disappears(name):
    prefix = BLOCK_HEADER_VARIANTS[name]
    blocking = BLOCKING_FIELDS
    if prefix.endswith("**Role:**"):
        blocking = BLOCKING_FIELDS.replace("Role:", "", 1)
    response = APPROVE + "Concerns:\n\n" + PRIMARY + "\n" + prefix + blocking + TAIL
    challenger = _challenge(response)
    assert challenger["still_vulnerable"] is True, name
    assert challenger["verification_status"] != "VERIFIED_FIXED", name
    assert _decision(challenger) != GREEN, name


def test_rb2_duplicate_concerns_sections_fail_closed():
    response = (
        APPROVE + "Concerns:\n\n" + PRIMARY + "\n" + BLOCKING
        + "\nConcerns:\n\n" + PRIMARY + TAIL
    )
    challenger = _challenge(response)
    assert challenger["still_vulnerable"] is True
    assert _decision(challenger) != GREEN


def test_rb2_canonical_two_block_response_still_parses_both_blocks():
    challenger = _challenge(APPROVE + "Concerns:\n\n" + PRIMARY + "\n" + BLOCKING + TAIL)
    assert len(challenger["concerns"]) == 2
    assert challenger["verification_status"] == "RESIDUAL_VULNERABILITY"


# ---------------------------------------------------------------------------
# RB-3: zero attribution is not Low Risk
# ---------------------------------------------------------------------------

def _repo(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text), encoding="utf-8")
    return tmp_path


def _impact(repo, diff):
    cwd = os.getcwd()
    os.chdir(repo)
    try:
        return LightweightImpactAnalyzer().analyze(diff).to_dict()
    finally:
        os.chdir(cwd)


VIEWS = """\
def login_required(f):
    return f


def delete_user(request):
    return request
"""
CALLER = "from app.views import delete_user\n\n\ndef route(r):\n    return delete_user(r)\n"

DECORATOR_ONLY = """\
--- a/app/views.py
+++ b/app/views.py
@@ -4,2 +4,3 @@

+@login_required
 def delete_user(request):
"""
BODY_CHANGE_NO_CALLERS = """\
--- a/app/lonely.py
+++ b/app/lonely.py
@@ -1,2 +1,2 @@
 def lonely(x):
-    return x
+    return x + 1
"""
C_FILE_CHANGE = """\
--- a/src/decode.c
+++ b/src/decode.c
@@ -1,3 +1,3 @@
 int decode(char *s) {
-    return s[0];
+    return s ? s[0] : 0;
 }
"""
NEW_FILE = """\
--- /dev/null
+++ b/app/new_helper.py
@@ -0,0 +1,2 @@
+def helper():
+    return 1
"""


def _rb3_repo(tmp_path):
    return _repo(tmp_path, {
        "app/__init__.py": "",
        "app/views.py": VIEWS,
        "app/a.py": CALLER, "app/b.py": CALLER, "app/c.py": CALLER,
        "app/lonely.py": "def lonely(x):\n    return x\n",
        "app/broken.py": "def broken(x):\n    return x\nprint 'py2 only'\n",
        "src/decode.c": "int decode(char *s) {\n    return s[0];\n}\n",
    })


@pytest.mark.parametrize("name,diff", [
    ("decorator_only", DECORATOR_ONLY),
    ("non_python_file", C_FILE_CHANGE),
    ("python_plus_non_python", BODY_CHANGE_NO_CALLERS + C_FILE_CHANGE),
    ("unparseable_python", (
        "--- a/app/broken.py\n+++ b/app/broken.py\n@@ -1,2 +1,2 @@\n"
        " def broken(x):\n-    return x\n+    return x or 0\n"
    )),
])
def test_rb3_unattributed_change_is_unavailable_not_low(tmp_path, name, diff):
    impact = _impact(_rb3_repo(tmp_path), diff)
    assert impact["impact_level"] == "unavailable", (name, impact)
    assert pl._resolve_impact_level(impact) == "unavailable"


@pytest.mark.parametrize("name,diff", [
    ("deleted_file", "--- a/app/lonely.py\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-def lonely(x):\n-    return x\n"),
    ("hunk_with_one_unattributable_insertion_run", (
        "--- a/app/views.py\n+++ b/app/views.py\n@@ -1,6 +1,8 @@\n def login_required(f):\n"
        "+    f = f\n     return f\n \n \n+@login_required\n def delete_user(request):\n"
        "     return request\n"
    )),
])
def test_rb3_partially_or_never_analyzed_change_is_unavailable(tmp_path, name, diff):
    impact = _impact(_rb3_repo(tmp_path), diff)
    assert impact["impact_level"] == "unavailable", (name, impact)


@pytest.mark.parametrize("name,diff", [
    ("attributed_body_change_without_callers", BODY_CHANGE_NO_CALLERS),
    ("new_file_has_no_preexisting_callers", NEW_FILE),
    ("import_line_plus_attributed_body_change", (
        "--- a/app/lonely.py\n+++ b/app/lonely.py\n@@ -1,2 +1,3 @@\n+import os\n"
        " def lonely(x):\n-    return x\n+    return os.fspath(x)\n"
    )),
])
def test_rb3_genuinely_supported_low_is_preserved(tmp_path, name, diff):
    impact = _impact(_rb3_repo(tmp_path), diff)
    assert impact["impact_level"] == "low", (name, impact)


def test_rb3_missing_impact_level_is_unavailable_not_low():
    assert pl._resolve_impact_level({}) == "unavailable"
    assert pl._resolve_impact_level({"impact_level": None}) == "unavailable"


@pytest.mark.parametrize("level", ["unavailable", None])
def test_rb3_unknown_impact_never_satisfies_green(level):
    challenger = _challenge(APPROVE + "Concerns:\n\n" + PRIMARY + TAIL)
    signals = pl._compute_trust_signals(
        [], APPLIES, pl._classify_challenger(challenger), "Good", level,
    )
    assert signals["deployment_safety"]["value"] == "Not Verified"
    rec = pl._build_recommendation_v1(
        signals, still_vulnerable=False, defect_count=0,
        verification_status="VERIFIED_FIXED", structured_challenger=True,
    )
    assert rec["decision"] == "Manual Review Required"


def test_rb3_decorator_only_fix_end_to_end_is_not_green(tmp_path):
    impact = _impact(_rb3_repo(tmp_path), DECORATOR_ONLY)
    challenger = _challenge(APPROVE + "Concerns:\n\n" + PRIMARY + TAIL)
    report = pl._build_report(pl.PipelineResult(
        vulnerability_text=VULN, patch=DECORATOR_ONLY, review="**Explanation:**\nok\n", score_text="",
        challenger=challenger, impact=impact, hygiene=[], applicability=APPLIES,
        repo_root=None, detected_language="python",
    ))
    assert next(line for line in report.splitlines() if line.startswith("## ")) != f"## {GREEN}"
    assert "| Is deployment risk low? | ? Not verified |" in report


# ---------------------------------------------------------------------------
# RB-4: sink inventory never reads outside repo_root
# ---------------------------------------------------------------------------

SECRET = "sk-OUTSIDE-SECRET-123"


def _rb4_repo(tmp_path):
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    (repo / "app" / "nested").mkdir(parents=True)
    outside.mkdir()
    (repo / "app" / "run.py").write_text("import os\n\ndef run(cmd):\n    os.system(cmd)\n", encoding="utf-8")
    (repo / "app" / "nested" / "deep.py").write_text(
        "import os\n\ndef deep(cmd):\n    os.system(cmd + 'x')\n", encoding="utf-8")
    (outside / "ops.py").write_text(
        f"import os\n\ndef rotate():\n    os.system('deploy --token={SECRET}')\n", encoding="utf-8")
    (outside / "pkg").mkdir()
    (outside / "pkg" / "inner.py").write_text(
        f"import os\n\ndef inner():\n    os.system('{SECRET}-dir')\n", encoding="utf-8")
    (repo / "app" / "ops_link.py").symlink_to(outside / "ops.py")
    (repo / "app" / "linked_dir").symlink_to(outside / "pkg", target_is_directory=True)
    (repo / "app" / "inrepo_link.py").symlink_to(repo / "app" / "run.py")
    return repo


def test_rb4_in_repo_and_nested_files_are_inspected(tmp_path):
    files = {s["file"] for s in extract_repo_sinks(_rb4_repo(tmp_path), "COMMAND_INJECTION")}
    assert "app/run.py" in files
    assert "app/nested/deep.py" in files


def test_rb4_symlink_escaping_repo_root_is_not_read(tmp_path):
    sinks = extract_repo_sinks(_rb4_repo(tmp_path), "COMMAND_INJECTION")
    files = {s["file"] for s in sinks}
    assert "app/ops_link.py" not in files
    assert not any(f.startswith("app/linked_dir/") for f in files)
    assert not any(SECRET in s["snippet"] for s in sinks)


def test_rb4_external_secret_never_reaches_prompt_context(tmp_path):
    repo = _rb4_repo(tmp_path)
    context = build_vulnerability_pattern_context(
        "OS command injection (CWE-78): attacker-controlled input reaches os.system.", "", repo,
    )
    assert "app/run.py" in context  # the inventory itself still renders
    assert SECRET not in context
    assert "ops_link.py" not in context


def test_rb4_symlink_to_in_repo_target_keeps_existing_semantics(tmp_path):
    files = {s["file"] for s in extract_repo_sinks(_rb4_repo(tmp_path), "COMMAND_INJECTION")}
    assert "app/inrepo_link.py" in files


# ---------------------------------------------------------------------------
# RB-5: a Challenger response the provider marked truncated fails closed
# ---------------------------------------------------------------------------

class _FakeAdapter:
    """Stands in for the shared provider adapter only; `call_llm` (which
    records `stop_reason`) and `LLMClient.complete` run for real."""

    def __init__(self, text, stop_reason):
        self.text, self.stop_reason = text, stop_reason

    def complete(self, model, system, messages, max_tokens):
        from utilities.llm.adapter import CompletionResult, TextBlock
        return CompletionResult(
            content=(TextBlock(text=self.text),), input_tokens=1, output_tokens=1,
            stop_reason=self.stop_reason,
        )


@pytest.fixture
def live_llm(monkeypatch):
    """A real LLMClient whose provider call returns (text, stop_reason)."""
    from utilities.autopatcher import llm_client

    def make(text, stop_reason, clear=True):
        monkeypatch.setattr(llm_client, "_resolve_active_provider", lambda: "anthropic")
        monkeypatch.setattr(llm_client, "_resolve_model", lambda provider, fallback: "test-model")
        monkeypatch.setattr(llm_client, "_resolve_max_tokens", lambda: 4096)
        monkeypatch.setattr(llm_client, "_get_or_build_adapter",
                            lambda provider: _FakeAdapter(text, stop_reason))
        if clear:
            llm_client.clear_call_metadata()
        client = llm_client.LLMClient.__new__(llm_client.LLMClient)
        client.model = "test-model"
        return client

    return make


def _challenge_live(llm):
    return pc.challenge_patch(VULN, PATCH, llm, code_context=CTX)


CLEAN_COMPLETE = APPROVE + "Concerns:\n\n" + PRIMARY + TAIL
WITH_BLOCKING = APPROVE + "Concerns:\n\n" + PRIMARY + "\n" + BLOCKING + TAIL


def test_rb5_1_complete_clean_response_end_turn_unchanged(live_llm):
    challenger = _challenge_live(live_llm(CLEAN_COMPLETE, "end_turn"))
    assert challenger["verification_status"] == "VERIFIED_FIXED"
    assert challenger["still_vulnerable"] is False
    assert _decision(challenger) == GREEN


@pytest.mark.parametrize("stop_reason", ["max_tokens", "length"])
def test_rb5_2_complete_looking_clean_response_marked_truncated_fails_closed(live_llm, stop_reason):
    challenger = _challenge_live(live_llm(CLEAN_COMPLETE, stop_reason))
    assert challenger["still_vulnerable"] is True
    assert challenger["verification_status"] != "VERIFIED_FIXED"
    assert _decision(challenger) != GREEN


def test_rb5_3_truncated_immediately_before_a_blocking_concern(live_llm):
    cut = WITH_BLOCKING[: WITH_BLOCKING.index("2. Role:")]
    challenger = _challenge_live(live_llm(cut, "max_tokens"))
    assert challenger["still_vulnerable"] is True
    assert _decision(challenger) != GREEN


def test_rb5_4_truncated_in_the_middle_of_a_concern(live_llm):
    cut = WITH_BLOCKING[: WITH_BLOCKING.index("Operation provenance: other_sink")]
    challenger = _challenge_live(live_llm(cut, "max_tokens"))
    assert challenger["still_vulnerable"] is True
    assert _decision(challenger) != GREEN


@pytest.mark.parametrize("response", [
    "Verification status: VERIFIED_FIXED\n\nSummary:\nThe patch fixes it.\n",
    APPROVE + "**Concerns:**\n\n" + PRIMARY + TAIL,
    APPROVE + "Concerns:\n\n" + PRIMARY + "\n2) " + BLOCKING_FIELDS + TAIL,
], ids=["legacy", "header_variant", "numbering_variant"])
def test_rb5_5_malformed_or_ambiguous_plus_truncation_fails_closed(live_llm, response):
    challenger = _challenge_live(live_llm(response, "max_tokens"))
    assert challenger["still_vulnerable"] is True
    assert _decision(challenger) != GREEN


def test_rb5_6_normal_blocking_concern_unchanged(live_llm):
    challenger = _challenge_live(live_llm(WITH_BLOCKING, "end_turn"))
    assert challenger["verification_status"] == "RESIDUAL_VULNERABILITY"
    assert [c["consequence"] for c in challenger["concerns"]] == ["NON_BLOCKING", "BLOCKING"]
    assert _decision(challenger) != GREEN


def test_rb5_absent_metadata_keeps_existing_semantics():
    """A caller-supplied client that records no call metadata (no
    stop_reason at all) is not treated as truncated."""
    from utilities.autopatcher import llm_client
    llm_client.clear_call_metadata()
    challenger = _challenge(CLEAN_COMPLETE)
    assert challenger["verification_status"] == "VERIFIED_FIXED"
    assert challenger["still_vulnerable"] is False


def test_rb5_stale_truncation_from_an_earlier_call_is_not_applied(live_llm):
    """Only metadata recorded by THIS Challenger call counts: an earlier
    truncated Challenger call must not taint a later complete one."""
    _challenge_live(live_llm(CLEAN_COMPLETE, "max_tokens"))
    challenger = _challenge_live(live_llm(CLEAN_COMPLETE, "end_turn", clear=False))
    assert challenger["verification_status"] == "VERIFIED_FIXED"
    assert challenger["still_vulnerable"] is False


def test_enrichment_constants_never_follow_a_symlink_out_of_the_repo(tmp_path):
    """PR #763 review: InvestigationContext constants are read only from files
    resolving inside repo_root; an in-repo symlink keeps working."""
    from types import SimpleNamespace

    from utilities.autopatcher.candidate_enrichment import _collect_repo_constants

    repo, outside = tmp_path / "repo", tmp_path / "outside"
    repo.mkdir()
    outside.mkdir()
    (outside / "secret.py").write_text('CANARY = "outside-repository"\n', encoding="utf-8")
    (repo / "real.py").write_text('INSIDE = "in-repository"\n', encoding="utf-8")
    (repo / "escape.py").symlink_to(outside / "secret.py")
    (repo / "alias.py").symlink_to(repo / "real.py")
    index = SimpleNamespace(by_file={"escape.py": [], "alias.py": [], "real.py": []})
    constants = _collect_repo_constants(repo, index)
    assert "escape.py" not in constants
    assert "outside-repository" not in repr(constants)
    assert "in-repository" in repr(constants.get("alias.py"))
    assert "in-repository" in repr(constants.get("real.py"))
