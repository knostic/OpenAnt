"""Regression tests: post-patch source evidence is not lost when (1)
repository grounding fell back (no candidates, no pre-patch anchors), (2)
the changed source unit is not Python, or (3) an indexed unit's `code` is
not span-exact.

Generic fixtures only. Hermetic: LLM_PROVIDER=mock, no network.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest import mock

import pytest

from utilities.agentic_enhancer.reachability_analyzer import ReachabilityAnalyzer
from utilities.agentic_enhancer.repository_index import RepositoryIndex
from utilities.autopatcher.candidate_enrichment import InvestigationContext
from utilities.autopatcher.post_patch_evaluation import (
    AnchorObservation,
    compute_coverage,
    derive_patch_touched_anchors,
    post_patch_definitions,
    render_post_patch_definitions,
)
from utilities.autopatcher.post_patch_investigation import ResolvedFunctionKey, ResolvedFunctionValue
from utilities.autopatcher.remediation_planner import _render_definition_block


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _unit(func_id, start, end, unit_type="function", code=None, class_name=None):
    return {
        "name": func_id.rsplit(":", 1)[-1], "startLine": start, "endLine": end,
        "unitType": unit_type, "className": class_name, "code": code,
    }


def _context(functions, repo_path=None, constants=None) -> InvestigationContext:
    return InvestigationContext(
        index=RepositoryIndex({"functions": functions}, repo_path=str(repo_path) if repo_path else None),
        call_graph={}, reverse_call_graph={},
        reachability=ReachabilityAnalyzer(functions, {}, set()),
        constants=constants or {},
    )


def _diff(path, hunks):
    """hunks: list of (old_start, context_before, added_lines, context_after)."""
    out = [f"--- a/{path}", f"+++ b/{path}"]
    for old_start, before, added, after in hunks:
        n_old = len(before) + len(after)
        out.append(f"@@ -{old_start},{n_old} +{old_start},{n_old + len(added)} @@")
        out += [f" {l}" for l in before] + [f"+{l}" for l in added] + [f" {l}" for l in after]
    return "\n".join(out) + "\n"


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _changed(func_id, path, start, end):
    return AnchorObservation(
        anchor_kind="resolved_function",
        anchor_key=ResolvedFunctionKey(func_id=func_id, name=func_id.rsplit(":", 1)[-1], class_name=None, unit_type="function"),
        candidate_path=path, status="changed",
        before_value=ResolvedFunctionValue(start, end - 1), after_value=ResolvedFunctionValue(start, end),
        details=None, source="test", evaluated_via="test", origin="patch_touched",
    )


# A generic class method in a non-Python source file.
_JS_PRE = (
    "class Thing {\n"                      # 1
    "  constructor (input) {\n"            # 2
    "    this.items = input.map(i => this.parse(i))\n"  # 3
    "  }\n"                                # 4
    "\n"                                   # 5
    "  parse (value) {\n"                  # 6
    "    value = value.trim()\n"           # 7
    "\n"                                   # 8
    "    const key = value.toLowerCase()\n"  # 9
    "    const parts = key.split(',')\n"   # 10
    "    const size = parts.length\n"      # 11
    "    return use(parts, size)\n"        # 12
    "  }\n"                                # 13
    "}\n"                                  # 14
)
_GUARD = "if (value.length > LIMIT) { throw new Error('too long') }"
_JS_POST = _JS_PRE.replace(
    "    value = value.trim()\n\n",
    "    value = value.trim()\n\n    " + _GUARD + "\n\n", 1,
)
_JS_PATCH = _diff("lib/thing.js", [(
    6,
    ["  parse (value) {", "    value = value.trim()", ""],
    [f"    {_GUARD}", ""],
    ["    const key = value.toLowerCase()", "    const parts = key.split(',')", "    const size = parts.length"],
)])


def _js_functions(pre=True, parse_code=None):
    end = 13 if pre else 15
    return {
        "lib/thing.js:Thing.constructor": _unit("lib/thing.js:Thing.constructor", 2, 4, "constructor", class_name="Thing"),
        "lib/thing.js:Thing.parse": _unit("lib/thing.js:Thing.parse", 6, end, "class_method", code=parse_code, class_name="Thing"),
    }


# ---------------------------------------------------------------------------
# Implementation 2 -- patch-to-source-unit resolution
# ---------------------------------------------------------------------------

class TestSourceUnitResolution:
    def test_3_python_function_still_resolves(self, tmp_path):
        _write(tmp_path, "a.py", "def foo(x):\n    y = x\n    return y\n")
        diff = _diff("a.py", [(1, ["def foo(x):", "    y = x"], ["    y = clean(y)"], ["    return y"])])
        ctx = _context({"a.py:foo": _unit("a.py:foo", 1, 3)})
        anchors = derive_patch_touched_anchors(diff, tmp_path, ctx, [])
        assert [(a.kind, a.key.func_id) for a in anchors] == [("resolved_function", "a.py:foo")]

    def test_4_changed_line_in_indexed_non_python_method_resolves(self, tmp_path):
        _write(tmp_path, "lib/thing.js", _JS_PRE)
        anchors = derive_patch_touched_anchors(_JS_PATCH, tmp_path, _context(_js_functions()), [])
        assert [(a.kind, a.key.func_id, a.origin) for a in anchors] == [
            ("resolved_function", "lib/thing.js:Thing.parse", "patch_touched"),
        ]
        cov = compute_coverage(_JS_PATCH, anchors, tmp_path, _context(_js_functions()))
        assert cov.covered == ("lib/thing.js:Thing.parse",) and cov.unattributed == 0

    @pytest.mark.parametrize("ext", [".rb", ".go", ".xyz"])
    def test_5_resolution_depends_on_index_metadata_not_extension(self, tmp_path, ext):
        rel = f"src/unit{ext}"
        _write(tmp_path, rel, "begin\n  a = 1\n  b = 2\nend\n")
        diff = _diff(rel, [(1, ["begin", "  a = 1"], ["  a = sanitize(a)"], ["  b = 2", "end"])])
        fid = f"{rel}:unit"
        assert [a.key.func_id for a in derive_patch_touched_anchors(diff, tmp_path, _context({fid: _unit(fid, 1, 4)}), [])] == [fid]
        # same file, no indexed unit -> nothing resolved (never guessed)
        assert derive_patch_touched_anchors(diff, tmp_path, _context({}), []) == []

    def test_6_constant_resolution_stays_python_only(self, tmp_path):
        from utilities.autopatcher.post_patch_evaluation import _resolve_patch_touched_elements

        _write(tmp_path, "lib/conf.js", "const LIMIT = 10\nconst OTHER = 2\n")
        diff = _diff("lib/conf.js", [(1, [], ["// note"], ["const LIMIT = 10", "const OTHER = 2"])])
        constants = {"lib/conf.js": {"LIMIT": {"line": 1, "end_line": 1, "outcome": "literal"}}}
        elements, unattributed = _resolve_patch_touched_elements(diff, tmp_path, _context({}, constants=constants))
        assert elements == [] and unattributed == 1
        # Python constant resolution is unchanged
        _write(tmp_path, "conf.py", "LIMIT = 10\nOTHER = 2\n")
        pdiff = _diff("conf.py", [(1, [], ["# note"], ["LIMIT = 10", "OTHER = 2"])])
        pconst = {"conf.py": {"LIMIT": {"line": 1, "end_line": 1, "outcome": "literal"}}}
        elements, _ = _resolve_patch_touched_elements(pdiff, tmp_path, _context({}, constants=pconst))
        assert [e.kind for e in elements] == ["constant_value"]

    def test_module_level_unit_still_never_anchored(self, tmp_path):
        _write(tmp_path, "lib/m.js", "const a = 1\nconst b = 2\nconst c = 3\n")
        diff = _diff("lib/m.js", [(1, ["const a = 1"], ["const z = 0"], ["const b = 2", "const c = 3"])])
        ctx = _context({"lib/m.js:__module__": _unit("lib/m.js:__module__", 1, 3, "module_level")})
        assert derive_patch_touched_anchors(diff, tmp_path, ctx, []) == []

    def test_10_multiple_changed_units_resolve_independently(self, tmp_path):
        _write(tmp_path, "lib/two.js", "function a () {\n  x()\n  y()\n}\nfunction b () {\n  p()\n  q()\n}\n")
        diff = _diff("lib/two.js", [
            (1, ["function a () {", "  x()"], ["  guardA()"], ["  y()", "}"]),
            (5, ["function b () {", "  p()"], ["  guardB()"], ["  q()", "}"]),
        ])
        ctx = _context({"lib/two.js:a": _unit("lib/two.js:a", 1, 4), "lib/two.js:b": _unit("lib/two.js:b", 5, 8)})
        anchors = derive_patch_touched_anchors(diff, tmp_path, ctx, [])
        assert sorted((a.key.func_id, a.before_value) for a in anchors) == [
            ("lib/two.js:a", ResolvedFunctionValue(1, 4)), ("lib/two.js:b", ResolvedFunctionValue(5, 8)),
        ]

    def test_11_equally_specific_distinct_units_are_ambiguous(self, tmp_path):
        """Two different indexed units with the SAME smallest span both
        contain the changed line -- no unit is chosen."""
        from utilities.autopatcher.post_patch_evaluation import _resolve_patch_touched_elements

        _write(tmp_path, "lib/dup.js", "const f = () => {\n  a()\n  b()\n}\n")
        diff = _diff("lib/dup.js", [(1, ["const f = () => {", "  a()"], ["  g()"], ["  b()", "}"])])
        ctx = _context({"lib/dup.js:f": _unit("lib/dup.js:f", 1, 4), "lib/dup.js:f#stmt": _unit("lib/dup.js:f#stmt", 1, 4, "statement")})
        elements, unattributed = _resolve_patch_touched_elements(diff, tmp_path, ctx)
        assert elements == [] and unattributed == 1
        assert derive_patch_touched_anchors(diff, tmp_path, ctx, []) == []

    def test_11b_strictly_smaller_unit_still_wins(self, tmp_path):
        _write(tmp_path, "lib/nest.js", "class C {\n  m () {\n    a()\n  }\n}\n")
        diff = _diff("lib/nest.js", [(2, ["  m () {", "    a()"], ["    g()"], ["  }", "}"])])
        ctx = _context({"lib/nest.js:C": _unit("lib/nest.js:C", 1, 5, "class"), "lib/nest.js:C.m": _unit("lib/nest.js:C.m", 2, 4)})
        assert [a.key.func_id for a in derive_patch_touched_anchors(diff, tmp_path, ctx, [])] == ["lib/nest.js:C.m"]


# ---------------------------------------------------------------------------
# Implementation 3 -- span-exact post-patch source
# ---------------------------------------------------------------------------

def _span_lines(text, start, end):
    return "".join(text.splitlines(keepends=True)[start - 1:end])


class TestSpanExactRendering:
    def test_7_rendered_text_is_the_indexed_span_not_parser_code(self, tmp_path):
        _write(tmp_path, "lib/thing.js", _JS_POST)
        trivia_code = "\n\n// leading comment outside the span\n" + _span_lines(_JS_POST, 6, 15)
        ctx = _context(_js_functions(pre=False, parse_code=trivia_code), repo_path=tmp_path)
        rendered = render_post_patch_definitions(
            [_changed("lib/thing.js:Thing.parse", "lib/thing.js", 6, 15)], ctx, max_chars=100_000,
        )
        expected = _render_definition_block(
            "lib/thing.js", "Thing.parse", 6, 15, _span_lines(_JS_POST, 6, 15), heading_label="Post-patch definition",
        )
        assert expected in rendered
        assert "leading comment outside the span" not in rendered

    def test_python_span_exact_rendering_equals_previous_code_rendering(self, tmp_path):
        src = "import os\n\n\ndef f(p):\n    p = clean(p)\n    return os.path.join('/base', p)\n"
        _write(tmp_path, "m.py", src)
        code = _span_lines(src, 4, 6)
        ctx = _context({"m.py:f": _unit("m.py:f", 4, 6, code=code)}, repo_path=tmp_path)
        rendered = render_post_patch_definitions([_changed("m.py:f", "m.py", 4, 6)], ctx, max_chars=100_000)
        assert _render_definition_block("m.py", "f", 4, 6, code, heading_label="Post-patch definition") in rendered

    @pytest.mark.parametrize("start, end", [(7, 6), (0, 3), (None, 6), (6, None), ("6", 15), (6, 99)])
    def test_8_invalid_or_inconsistent_span_fails_closed(self, tmp_path, start, end):
        _write(tmp_path, "lib/thing.js", _JS_POST)
        functions = {"lib/thing.js:Thing.parse": _unit("lib/thing.js:Thing.parse", start, end, code=_JS_POST)}
        ctx = _context(functions, repo_path=tmp_path)
        assert render_post_patch_definitions(
            [_changed("lib/thing.js:Thing.parse", "lib/thing.js", 6, 15)], ctx, max_chars=100_000,
        ) == ""

    @pytest.mark.parametrize("case", ["missing_file", "no_repo_path", "blank_range"])
    def test_9_unreadable_range_fails_closed_never_falls_back_to_code(self, tmp_path, case):
        good_code = _span_lines(_JS_POST, 6, 15)
        if case == "blank_range":
            _write(tmp_path, "lib/thing.js", "\n" * 20)
        elif case == "no_repo_path":
            _write(tmp_path, "lib/thing.js", _JS_POST)
        repo_path = None if case == "no_repo_path" else tmp_path
        ctx = _context(_js_functions(pre=False, parse_code=good_code), repo_path=repo_path)
        assert render_post_patch_definitions(
            [_changed("lib/thing.js:Thing.parse", "lib/thing.js", 6, 15)], ctx, max_chars=100_000,
        ) == ""

    def test_10b_multiple_units_render_independent_blocks(self, tmp_path):
        src = "function a () {\n  x()\n}\nfunction b () {\n  y()\n}\n"
        _write(tmp_path, "lib/two.js", src)
        ctx = _context({"lib/two.js:a": _unit("lib/two.js:a", 1, 3), "lib/two.js:b": _unit("lib/two.js:b", 4, 6)}, repo_path=tmp_path)
        rendered = render_post_patch_definitions(
            [_changed("lib/two.js:a", "lib/two.js", 1, 3), _changed("lib/two.js:b", "lib/two.js", 4, 6)], ctx, max_chars=100_000,
        )
        assert rendered.count("#### Post-patch definition:") == 2
        assert _render_definition_block("lib/two.js", "a", 1, 3, _span_lines(src, 1, 3), heading_label="Post-patch definition") in rendered
        assert _render_definition_block("lib/two.js", "b", 4, 6, _span_lines(src, 4, 6), heading_label="Post-patch definition") in rendered

    def test_12_insufficient_capacity_omits_block(self, tmp_path):
        _write(tmp_path, "lib/thing.js", _JS_POST)
        ctx = _context(_js_functions(pre=False), repo_path=tmp_path)
        assert render_post_patch_definitions(
            [_changed("lib/thing.js:Thing.parse", "lib/thing.js", 6, 15)], ctx, max_chars=40,
        ) == ""


# ---------------------------------------------------------------------------
# 13/14 -- block-local ordering and cross-function isolation
# ---------------------------------------------------------------------------

def _concern(op_prov, role="primary"):
    return (
        f"1. Role: {role}\n   Description: Whether over-long input still reaches the work.\n"
        "   Operation present in evidence: present\n   Preceding guard: present\n"
        f"   Guard provenance: {_GUARD}\n   Function provenance: none\n"
        f"   Operation provenance: {op_prov}\n"
        "   Guard default state: condition_true_under_default\n   Guard default state provenance: const LIMIT = 256\n"
        "   Guard effect: prevents_operation\n   Guard effect provenance: throw new Error('too long')\n"
        "   Reentry state propagation: not_applicable\n   Reentry provenance: none\n"
        "   Requires explicit non-default action: false\n   Override provenance: none\n"
        "   Contract addresses override: not_applicable\n   Scope provenance: none\n"
    )


def _challenge(concern, corpus, patch, definitions=None):
    from utilities.autopatcher.patch_challenger import challenge_patch

    llm = mock.MagicMock()
    llm.complete.return_value = (
        "Verification status: VERIFIED_FIXED\n\nConcerns:\n\n" + concern
        + "\nEdge cases:\n- none\n\nPotential issues:\n- none\n\nSummary:\n- none\n"
    )
    return challenge_patch(
        "Over-long input is processed.", patch, llm, code_context=corpus, provenance_context=corpus,
        post_patch_definitions=definitions,
    )


class TestOrderingWithSpanExactBlocks:
    def _corpus(self, tmp_path):
        _write(tmp_path, "lib/thing.js", _JS_POST + "const LIMIT = 256\n")
        pre_block = _render_definition_block("lib/thing.js", "Thing.constructor", 2, 4, _span_lines(_JS_PRE, 2, 4))
        pre_parse = _render_definition_block("lib/thing.js", "Thing.parse", 6, 13, _span_lines(_JS_PRE, 6, 13))
        ctx = _context(_js_functions(pre=False, parse_code="\n\n" + _span_lines(_JS_POST, 6, 15)), repo_path=tmp_path)
        # the rendered text and its trusted structured records, as the pipeline passes both
        post, self._definitions = post_patch_definitions(
            [_changed("lib/thing.js:Thing.parse", "lib/thing.js", 6, 15)], ctx, max_chars=100_000,
        )
        assert post and self._definitions
        return "\n\n".join([pre_block, pre_parse, "# lib/thing.js (lines 16-16)\nconst LIMIT = 256\n", post])

    def test_13_same_function_operation_orders_inside_span_exact_block(self, tmp_path):
        result = _challenge(_concern("return use(parts, size)"), self._corpus(tmp_path), _JS_PATCH, self._definitions)
        c = result["concerns"][0]
        assert c["reachability_facts"]["preceding_guard"] == "present"
        assert c["default_execution_reachability"] == "blocked" and c["consequence"] == "NON_BLOCKING"

    def test_14_operation_in_a_different_function_gains_no_evidence(self, tmp_path):
        result = _challenge(
            _concern("this.items = input.map(i => this.parse(i))"), self._corpus(tmp_path), _JS_PATCH, self._definitions,
        )
        c = result["concerns"][0]
        assert c["reachability_facts"]["preceding_guard"] == "unresolved"
        assert c["consequence"] == "UNRESOLVED" and result["verification_status"] == "INSUFFICIENT_EVIDENCE"


# ---------------------------------------------------------------------------
# Implementation 1 -- post-patch investigation after grounding fallback
# ---------------------------------------------------------------------------

_HANDLER = (
    "def handle(payload, sink):\n"
    "    data = payload.get(\"body\")\n"
    "    data = data or \"\"\n"
    "    size = len(data)\n"
    "    if size > 10:\n"
    "        size = 10\n"
    "    sink.write(data)\n"
    "    return size\n"
)
_HANDLER_PATCH = (
    "```diff\n--- a/app/handler.py\n+++ b/app/handler.py\n@@ -1,5 +1,6 @@\n"
    " def handle(payload, sink):\n     data = payload.get(\"body\")\n+    data = scrub(data)\n"
    "     data = data or \"\"\n     size = len(data)\n     if size > 10:\n```"
)
_UNINDEXED_ONLY_PATCH = (
    "```diff\n--- a/docs/notes.txt\n+++ b/docs/notes.txt\n@@ -1,2 +1,3 @@\n"
    " first line\n+inserted line\n second line\n```"
)


def _repo(root: Path) -> None:
    # app/auth.py is what the shared harness's advisory text grounds to; the
    # patch touches app/handler.py, which grounding never selects.
    _write(root, "app/auth.py", (
        "import sqlite3\n\ndb = sqlite3.connect(\"users.db\")\n\n"
        "def authenticate(username, password):\n"
        "    query = f\"SELECT * FROM users WHERE username='{username}'\"\n"
        "    return db.execute(query).fetchone() is not None\n"
    ))
    _write(root, "app/handler.py", _HANDLER)
    _write(root, "docs/notes.txt", "first line\nsecond line\n")
    for cmd in (["git", "init"], ["git", "config", "user.email", "t@t.com"], ["git", "config", "user.name", "T"],
                ["git", "add", "-A"], ["git", "commit", "-m", "init"]):
        subprocess.run(cmd, cwd=root, capture_output=True)


def _empty_grounding(*a, **kw):
    from utilities.autopatcher.repository_grounding_models import RepositoryGroundingResult
    return RepositoryGroundingResult(rendered_context="", candidates=[], decisions=[], extraction_signals={}, budget=None)


def _run(tmp_path, patch, extra=()):
    from tests.patch.test_pipeline_post_patch_investigation import _CHALLENGER_CLEAN, _run_pipeline

    repo = tmp_path / "repo"
    _repo(repo)
    result, report, calls, mocks = _run_pipeline(
        tmp_path, patches_gen=[patch], patches_chall=[_CHALLENGER_CLEAN], repo_root=str(repo), extra_patches=list(extra),
    )
    challenge = next(m for m in mocks if getattr(m, "_mock_name", None) == "challenge_patch")
    return result, report, challenge.call_args.kwargs


class TestFallbackGroundingPostPatch:
    def test_1_fallback_grounding_still_enters_post_patch_investigation(self, tmp_path):
        result, report, kwargs = _run(
            tmp_path, _HANDLER_PATCH,
            [mock.patch("utilities.autopatcher.repo_locator.ground_repository", side_effect=_empty_grounding)],
        )
        assert result.post_patch_observations is not None
        # no fabricated pre-patch evidence: only what the diff itself touched
        assert {o.origin for o in result.post_patch_observations} == {"patch_touched"}
        assert [o.anchor_key.func_id for o in result.post_patch_observations] == ["app/handler.py:handle"]
        assert "## Post-Patch Investigation" in kwargs["code_context"]
        block_heading = "#### Post-patch definition: `app/handler.py:handle` (lines 1–9)"
        assert block_heading in kwargs["code_context"] and block_heading in kwargs["provenance_context"]
        assert "Not evaluated for this run" not in report

    def test_1b_fallback_with_no_resolvable_unit_fabricates_nothing(self, tmp_path):
        result, report, kwargs = _run(
            tmp_path, _UNINDEXED_ONLY_PATCH,
            [mock.patch("utilities.autopatcher.repo_locator.ground_repository", side_effect=_empty_grounding)],
        )
        # nothing genuine to re-evaluate -> reported as not evaluated, exactly
        # as before; never an "evaluated, nothing found" section
        assert result.post_patch_observations is None
        assert "Not evaluated for this run" in report
        assert "#### Post-patch definition:" not in kwargs["code_context"]
        assert "## Post-Patch Investigation" not in kwargs["code_context"]

    def test_2_grounded_run_does_not_rebuild_pre_patch_context(self, tmp_path):
        import utilities.autopatcher.candidate_enrichment as ce

        with mock.patch.object(ce, "build_investigation_context", side_effect=ce.build_investigation_context) as spy:
            result, report, kwargs = _run(tmp_path, _HANDLER_PATCH)
        # S1 (pre-patch, grounded) + S4 (patched copy) -- exactly as before
        assert spy.call_count == 2
        assert result.post_patch_observations is not None
        assert any(o.origin == "pre_patch" for o in result.post_patch_observations)
