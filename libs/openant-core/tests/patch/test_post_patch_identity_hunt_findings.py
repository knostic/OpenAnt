"""PR #763 independent HUNT review, findings N9-N10: the trusted post-change
definition of a patched function.

N9: an edit that keeps a function's line count read `unchanged`, so its
complete post-change source was never produced and the Challenger could not
verify a correct fix.
N10: a duplicate-name function's line-suffixed id (`render#L8`) was looked up
again in the patched copy, where it named a different definition, and that
definition's source became trusted evidence.

Drives the real Python parser on a pre-patch and a patched copy, then the
production anchor derivation, evaluation (called exactly as pipeline.py calls
it, with the applied diff and the pre-patch context) and definition rendering.
"""

from __future__ import annotations

import difflib
import os
from pathlib import Path
from unittest import mock

import pytest

from utilities.autopatcher import post_patch_evaluation as pe
from utilities.autopatcher.candidate_enrichment import build_investigation_context
from utilities.autopatcher.patch_challenger import challenge_patch


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setenv("AUTOPATCHER_PARSER_QUIET", "1")
    monkeypatch.setenv("LLM_PROVIDER", "mock")


def _diff(before: str, after: str, path: str = "item.py") -> str:
    return "".join(difflib.unified_diff(
        before.splitlines(True), after.splitlines(True), fromfile="a/" + path, tofile="b/" + path,
    ))


def _evaluate(tmp_path: Path, before: str, after: str, diff: "str | None" = None, path: str = "item.py"):
    for name, text in (("pre", before), ("post", after)):
        (tmp_path / name / Path(path).parent).mkdir(parents=True, exist_ok=True)
        (tmp_path / name / path).write_text(text)
    pre = build_investigation_context(tmp_path / "pre", tmp_path / "pre_out")
    post = build_investigation_context(tmp_path / "post", tmp_path / "post_out")
    delta = _diff(before, after, path) if diff is None else diff
    anchors = pe.derive_patch_touched_anchors(delta, tmp_path / "pre", pre, [])
    observations = pe.evaluate_anchors(anchors, post, patch_diff=delta, pre_patch_context=pre)
    rendered, definitions = pe.post_patch_definitions(observations, post, max_chars=100_000)
    _evaluate.rendered = rendered
    return delta, observations, definitions


def _statuses(observations):
    return {o.anchor_key.func_id: o.status for o in observations}


# ---------------------------------------------------------------------------
# N9 -- an in-place edit is a change.
# ---------------------------------------------------------------------------

DELIVER = ("def deliver(value, consume):\n    value = str(value)\n"
           + "".join(f"    counter = {i}\n" for i in range(6)) + "    return consume(value)\n")
INPLACE = DELIVER.replace("    value = str(value)\n", "    value = str(value).strip()\n")
OTHER = "\n\ndef helper(x):\n    return x + 1\n"


def _guard_reply(guard: str) -> str:
    return (
        "Verification status: VERIFIED_FIXED\n\nConcerns:\n\n1. Role: primary\n"
        "   Description: Whether outer whitespace reaches the consumer.\n"
        "   Operation present in evidence: present\n   Operation provenance: consume(value)\n"
        f"   Preceding guard: present\n   Guard provenance: {guard}\n   Function provenance: none\n"
        "   Guard default state: condition_true_under_default\n"
        f"   Guard default state provenance: {guard}\n"
        f"   Guard effect: neutralizes_operation\n   Guard effect provenance: {guard}\n"
        "   Reentry state propagation: not_applicable\n   Reentry provenance: none\n"
        "   Requires explicit non-default action: false\n   Override provenance: none\n"
        "   Contract addresses override: not_applicable\n   Scope provenance: none\n"
        "\nEdge cases:\n- none\n\nPotential issues:\n- none\n\nSummary:\n- none\n"
    )


class TestN9InPlaceEdits:
    def test_same_line_count_edit_is_changed_with_its_definition(self, tmp_path):
        _, observations, definitions = _evaluate(tmp_path, DELIVER, INPLACE)
        assert _statuses(observations) == {"item.py:deliver": "changed"}
        assert [d["source"] for d in definitions] == [INPLACE.rstrip()]
        assert observations[0].details == "edited in place (same lines)"

    def test_in_place_fix_can_now_be_verified(self, tmp_path):
        """The legitimate fix whose guard sits outside the hunk (far from the
        operation) verifies through its complete definition, exactly like the
        same fix written as an inserted line."""
        delta, _, definitions = _evaluate(tmp_path, DELIVER, INPLACE)
        # The Challenger trusts a definition only when it was also shown one.
        ctx = (f"#### Target definition: `item.py:deliver` (lines 1–9)\n\n```python\n{DELIVER}```\n"
               + _evaluate.rendered)
        llm = mock.MagicMock()
        llm.complete.return_value = _guard_reply("value = str(value).strip()")
        result = challenge_patch("Outer whitespace must be removed before consume.", delta, llm,
                                 code_context=ctx, provenance_context=ctx, post_patch_definitions=definitions)
        assert result["verification_status"] == "VERIFIED_FIXED"

    @pytest.mark.parametrize("after,guard", [
        # the in-place edit puts the cited text AFTER the operation
        (DELIVER.replace("    return consume(value)\n", "    return consume(value) or str(value).strip()\n"),
         "str(value).strip()"),
        # the in-place edit REMOVES the guard the model still cites
        (DELIVER.replace("    value = str(value)\n", "    value = value\n"), "value = str(value)"),
    ], ids=["guard-text-after-operation", "guard-removed-in-place"])
    def test_the_new_definition_never_vouches_for_a_misplaced_guard(self, tmp_path, after, guard):
        delta, _, definitions = _evaluate(tmp_path, DELIVER, after)
        assert definitions, "the in-place edit now yields its definition"
        ctx = (f"#### Target definition: `item.py:deliver` (lines 1–9)\n\n```python\n{DELIVER}```\n"
               + _evaluate.rendered)
        llm = mock.MagicMock()
        llm.complete.return_value = _guard_reply(guard)
        result = challenge_patch("Outer whitespace must be removed before consume.", delta, llm,
                                 code_context=ctx, provenance_context=ctx, post_patch_definitions=definitions)
        assert result["verification_status"] != "VERIFIED_FIXED"

    def test_untouched_function_stays_unchanged_without_a_definition(self, tmp_path):
        before = DELIVER + OTHER
        after = INPLACE + OTHER
        pre_anchor_diff = _diff(before, after)
        _, observations, definitions = _evaluate(tmp_path, before, after, pre_anchor_diff)
        statuses = _statuses(observations)
        assert statuses.get("item.py:deliver") == "changed"
        assert "item.py:helper" not in statuses or statuses["item.py:helper"] == "unchanged"
        assert all(d["label"] != "helper" for d in definitions)

    def test_signature_edit_is_followed_through_its_body(self, tmp_path):
        """The definition line itself changes (a new default): identity comes
        from the surviving body lines, all inside one function of that name."""
        after = DELIVER.replace("def deliver(value, consume):", "def deliver(value, consume, strict=True):")
        _, observations, definitions = _evaluate(tmp_path, DELIVER, after)
        assert _statuses(observations) == {"item.py:deliver": "changed"}
        assert [d["source"] for d in definitions] == [after.rstrip()]

    def test_fully_rewritten_function_is_unresolved_not_guessed(self, tmp_path):
        before = "def deliver(value):\n    return value\n"
        after = "def deliver(value, strict=True):\n    return value.strip() if strict else value\n"
        _, observations, definitions = _evaluate(tmp_path, before, after)
        assert _statuses(observations) == {"item.py:deliver": "unresolved"}
        assert definitions == []

    def test_header_that_does_not_describe_the_patched_copy_fails_closed(self, tmp_path):
        """The diff's header places the edit inside `helper`, while the
        patched copy has it in `deliver` (an application at an offset): the
        line mapping disagrees with the copy's text, so no definition is
        trusted rather than one read at the wrong place."""
        before, after = DELIVER + OTHER, INPLACE + OTHER
        true_diff = _diff(before, after)
        wrong = true_diff.replace("@@ -1,5 +1,5 @@", "@@ -12,5 +12,5 @@")
        assert wrong != true_diff
        _, observations, definitions = _evaluate(tmp_path / "wrong", before, after, wrong)
        assert definitions == []
        assert all(o.status != "changed" for o in observations)
        _, _, control = _evaluate(tmp_path / "true", before, after, true_diff)
        assert [d["source"] for d in control] == [INPLACE.rstrip()]

    def test_deleted_function_disappears(self, tmp_path):
        before = DELIVER + OTHER
        after = DELIVER
        _, observations, definitions = _evaluate(tmp_path, before, after)
        assert _statuses(observations).get("item.py:helper") == "disappeared"
        assert all(d["label"] != "helper" for d in definitions)


# ---------------------------------------------------------------------------
# N10 -- a duplicate-name id never resolves to another definition.
# ---------------------------------------------------------------------------

OVERLOADS = ('from typing import overload\n\n\n@overload\ndef render(x: int) -> str: ...\n'
             '@overload\ndef render(x: str) -> str: ...\ndef render(x):\n    s = str(x)\n'
             '    return "<p>" + s + "</p>"\n')
FIXED = OVERLOADS.replace("    s = str(x)\n", "    s = html.escape(str(x))\n")
IMPLEMENTATION = 'def render(x):\n    s = html.escape(str(x))\n    return "<p>" + s + "</p>"'


def _implementation_definitions(definitions):
    return [d for d in definitions if "return" in d["source"]]


class TestN10DuplicateNameIdentity:
    @pytest.mark.parametrize("shift", [1, 2, 5], ids=["one-line", "two-lines", "five-lines"])
    def test_shifted_overloads_keep_the_implementation(self, tmp_path, shift):
        after = "import html\n" * 1 + "# shift\n" * (shift - 1) + FIXED
        _, observations, definitions = _evaluate(tmp_path, OVERLOADS, after)
        assert IMPLEMENTATION in [d["source"] for d in definitions]
        for d in definitions:
            # every trusted source is the definition its own anchor named
            assert d["source"].startswith(("@overload", "def render(x):"))
            if d["source"].startswith("@overload"):
                assert "html" not in d["source"]
        assert all(o.status != "disappeared" for o in observations)

    def test_overload_stub_is_never_the_implementations_evidence(self, tmp_path):
        after = "import html\nimport re\n" + FIXED
        _, observations, definitions = _evaluate(tmp_path, OVERLOADS, after)
        impl_obs = [o for o in observations if o.before_value.start_line == 8]
        assert len(impl_obs) == 1 and impl_obs[0].after_value.start_line == 10
        assert _implementation_definitions(definitions) == [
            {"path": "item.py", "label": "render#L10", "start_line": 10, "end_line": 12, "source": IMPLEMENTATION}
        ]

    def test_a_new_same_name_function_inserted_earlier_does_not_take_the_identity(self, tmp_path):
        """The patch adds another `render` above: ids shift onto the new one."""
        before = "def render(x):\n    return str(x)\n\n\ndef render(x):\n    s = str(x)\n    return s\n"
        after = ("def render(x):\n    return repr(x)\n\n\ndef render(x):\n    return str(x)\n\n\n"
                 "def render(x):\n    s = html.escape(str(x))\n    return s\n")
        _, observations, definitions = _evaluate(tmp_path, before, after)
        sources = [d["source"] for d in definitions]
        assert "def render(x):\n    s = html.escape(str(x))\n    return s" in sources
        assert "def render(x):\n    return repr(x)" not in sources

    def test_identical_bodies_are_kept_apart(self, tmp_path):
        body = "    a = x + 1\n    return a\n"
        before = "def run(x):\n" + body + "\n\ndef run(x):\n" + body
        after = "# moved\n" + "def run(x):\n" + body + "\n\ndef run(x):\n" + body.replace("x + 1", "x + 2")
        _, observations, definitions = _evaluate(tmp_path, before, after)
        assert [d["source"] for d in definitions] == ["def run(x):\n    a = x + 2\n    return a"]

    def test_without_the_diff_the_previous_lookup_is_kept(self, tmp_path):
        """Callers that do not pass the diff (none in production) keep the
        id lookup; the pipeline always passes it (see pipeline.py)."""
        for name, text in (("pre", OVERLOADS), ("post", FIXED)):
            (tmp_path / name).mkdir()
            (tmp_path / name / "item.py").write_text(text)
        pre = build_investigation_context(tmp_path / "pre", tmp_path / "pre_out")
        post = build_investigation_context(tmp_path / "post", tmp_path / "post_out")
        anchors = pe.derive_patch_touched_anchors(_diff(OVERLOADS, FIXED), tmp_path / "pre", pre, [])
        observations = pe.evaluate_anchors(anchors, post)
        assert {o.evaluated_via for o in observations} == {pe._RESOLVED_FUNCTION_EVALUATED_VIA}


class TestR1ModuleLevelUnit:
    """CVE investigation R1: the `<file>:__module__` unit is not a function
    and has no same-name ambiguity; the by-diff identity must not turn an
    untouched one into `unresolved`."""

    PRE = "import os\n\nBASE = '/srv'\n\n\ndef read(p):\n    return open(os.path.join(BASE, p)).read()\n"

    def _module_status(self, tmp_path, after):
        from utilities.autopatcher.post_patch_investigation import (
            Anchor, ResolvedFunctionKey, ResolvedFunctionValue,
        )
        for name, text in (("pre", self.PRE), ("post", after)):
            (tmp_path / name).mkdir()
            (tmp_path / name / "item.py").write_text(text)
        pre = build_investigation_context(tmp_path / "pre", tmp_path / "pre_out")
        post = build_investigation_context(tmp_path / "post", tmp_path / "post_out")
        unit = next(f for f in pre.index.list_functions_in_file("item.py") if f.get("unitType") == "module_level")
        anchor = Anchor(
            kind="resolved_function", candidate_path="item.py",
            key=ResolvedFunctionKey(func_id=unit["id"], name="__module__", class_name=None, unit_type="module_level"),
            before_value=ResolvedFunctionValue(start_line=unit["startLine"], end_line=unit["endLine"]),
            source="candidate_enrichment",
        )
        observation = pe.evaluate_anchors(
            [anchor], post, patch_diff=_diff(self.PRE, after), pre_patch_context=pre,
        )[0]
        return observation.status

    def test_untouched_module_unit_is_unchanged(self, tmp_path):
        after = self.PRE.replace("    return open(", "    p = os.path.basename(p)\n    return open(")
        assert self._module_status(tmp_path, after) == "unchanged"

    def test_function_identity_is_still_by_diff(self, tmp_path):
        """The function in the same patch still goes through the diff."""
        after = self.PRE.replace("    return open(", "    p = os.path.basename(p)\n    return open(")
        _, observations, definitions = _evaluate(tmp_path, self.PRE, after)
        assert {o.evaluated_via for o in observations} == {pe._RESOLVED_FUNCTION_BY_DIFF_EVALUATED_VIA}
        assert [d["label"] for d in definitions] == ["read"]


def test_pipeline_passes_the_diff_and_pre_patch_context():
    """The production call site uses the identity-preserving evaluation."""
    source = Path(pe.__file__).with_name("pipeline.py").read_text()
    call = source[source.index("_post_patch_observations = evaluate_anchors("):][:600]
    assert "patch_diff=_investigated_patch" in call and "pre_patch_context=_pre_patch_resolution_context" in call


if os.name == "nt":  # pragma: no cover
    pytestmark = pytest.mark.skip(reason="parser fixtures use POSIX paths")
