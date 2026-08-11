"""Tests for the experimental remediation_planner module, including the
deterministic Planner -> enrichment bridge."""

from __future__ import annotations

import json
import re
from unittest import mock

import pytest

from utilities.autopatcher.remediation_planner import RemediationPlanResult

_EMPTY = RemediationPlanResult(rendered="", target_files=[], target_symbols=[])

_WELL_FORMED = {
    "remediation_mechanism": "Strip sensitive headers before following a cross-origin redirect.",
    "target_files": ["src/urllib3/util/retry.py", "src/urllib3/poolmanager.py"],
    "target_symbols": ["Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT"],
    "security_invariant": "Sensitive request headers must not cross origins on redirect.",
    "required_edits": ["Add 'Cookie' to DEFAULT_REMOVE_HEADERS_ON_REDIRECT."],
    "approaches_to_avoid": ["Do not add a separate ad-hoc header-stripping mechanism."],
    "explicit_unknowns": [],
}


def _make_context(functions=None, constants=None, repo_path=None):
    """A real (not mocked) InvestigationContext, built from a minimal real
    RepositoryIndex/ReachabilityAnalyzer -- so symbol-resolution tests
    exercise the actual lookup code, not a stand-in. `repo_path` is
    required for RepositoryIndex.read_file_section to work at all (it
    returns None with no repo_path set), so pass it whenever a test needs
    a constant's source read back."""
    from utilities.agentic_enhancer.reachability_analyzer import ReachabilityAnalyzer
    from utilities.agentic_enhancer.repository_index import RepositoryIndex
    from utilities.autopatcher.candidate_enrichment import InvestigationContext

    functions = functions or {}
    index = RepositoryIndex({"functions": functions}, repo_path=str(repo_path) if repo_path else None)
    reachability = ReachabilityAnalyzer(functions, {}, set())
    return InvestigationContext(
        index=index, call_graph={}, reverse_call_graph={},
        reachability=reachability, constants=constants or {},
    )


# ---------------------------------------------------------------------------
# generate_remediation_plan() -- rendered Markdown (unchanged in spirit,
# now returned inside RemediationPlanResult.rendered)
# ---------------------------------------------------------------------------

class TestParsing:
    def test_parses_well_formed_json(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_plan

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps(_WELL_FORMED)

        result = generate_remediation_plan("some vuln", llm, code_context="some evidence")

        assert "Security invariant:" in result.rendered
        assert "Sensitive request headers must not cross origins on redirect." in result.rendered
        assert "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in result.rendered

    def test_parses_fenced_json(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_plan

        llm = mock.MagicMock()
        llm.complete.return_value = "```json\n" + json.dumps(_WELL_FORMED) + "\n```"

        result = generate_remediation_plan("some vuln", llm)

        assert "Likely remediation mechanism:" in result.rendered

    def test_malformed_json_returns_empty(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_plan

        llm = mock.MagicMock()
        llm.complete.return_value = "not json at all, just prose."

        assert generate_remediation_plan("some vuln", llm) == _EMPTY

    def test_non_dict_json_returns_empty(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_plan

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps(["a", "list", "not", "a", "dict"])

        assert generate_remediation_plan("some vuln", llm) == _EMPTY

    def test_empty_response_returns_empty(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_plan

        llm = mock.MagicMock()
        llm.complete.return_value = ""

        assert generate_remediation_plan("some vuln", llm) == _EMPTY

    def test_non_string_response_returns_empty_without_raising(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_plan

        llm = mock.MagicMock()
        llm.complete.return_value = mock.MagicMock()

        assert generate_remediation_plan("some vuln", llm) == _EMPTY

    def test_llm_error_returns_empty_without_raising(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_plan

        llm = mock.MagicMock()
        llm.complete.side_effect = RuntimeError("boom")

        assert generate_remediation_plan("some vuln", llm) == _EMPTY

    def test_all_empty_fields_returns_empty_not_bare_heading(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_plan

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps({
            "remediation_mechanism": None, "target_files": [], "target_symbols": [],
            "security_invariant": None, "required_edits": [], "approaches_to_avoid": [],
            "explicit_unknowns": [],
        })

        assert generate_remediation_plan("some vuln", llm).rendered == ""

    def test_partial_fields_only_render_present_sections(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_plan

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps({
            "remediation_mechanism": None, "target_files": [], "target_symbols": [],
            "security_invariant": None, "required_edits": [], "approaches_to_avoid": [],
            "explicit_unknowns": ["Could not determine which file owns the fix."],
        })

        result = generate_remediation_plan("some vuln", llm)

        assert "Explicit unknowns:" in result.rendered
        assert "Could not determine which file owns the fix." in result.rendered
        assert "Security invariant:" not in result.rendered
        assert "Required edits:" not in result.rendered


class TestStageLabel:
    def test_stage_label_is_remediation_planning(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_plan

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps(_WELL_FORMED)

        generate_remediation_plan("some vuln", llm, code_context="ctx")

        _args, kwargs = llm.complete.call_args
        assert kwargs.get("stage") == "remediation_planning"


class TestUserMessageContent:
    def test_code_context_included_when_present(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_plan

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps(_WELL_FORMED)

        generate_remediation_plan("some vuln", llm, code_context="EVIDENCE_MARKER")

        _system, user_message = llm.complete.call_args[0]
        assert "## Repository evidence" in user_message
        assert "EVIDENCE_MARKER" in user_message

    def test_no_evidence_section_when_code_context_empty(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_plan

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps(_WELL_FORMED)

        generate_remediation_plan("some vuln", llm)

        _system, user_message = llm.complete.call_args[0]
        assert "## Repository evidence" not in user_message


# ---------------------------------------------------------------------------
# generate_remediation_plan() -- parsed (unverified) target_files/target_symbols
# ---------------------------------------------------------------------------

class TestPlanResultParsing:
    def test_well_formed_response_preserves_target_files_and_symbols(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_plan

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps(_WELL_FORMED)

        result = generate_remediation_plan("some vuln", llm)

        assert result.target_files == ["src/urllib3/util/retry.py", "src/urllib3/poolmanager.py"]
        assert result.target_symbols == ["Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT"]

    def test_malformed_json_has_no_proposals(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_plan

        llm = mock.MagicMock()
        llm.complete.return_value = "not json"

        result = generate_remediation_plan("some vuln", llm)
        assert result.target_files == []
        assert result.target_symbols == []

    def test_llm_error_has_no_proposals(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_plan

        llm = mock.MagicMock()
        llm.complete.side_effect = RuntimeError("boom")

        result = generate_remediation_plan("some vuln", llm)
        assert result.target_files == []
        assert result.target_symbols == []

    def test_non_list_target_files_coerced_to_empty_list(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_plan

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps({**_WELL_FORMED, "target_files": "not-a-list"})

        result = generate_remediation_plan("some vuln", llm)
        assert result.target_files == []

    def test_non_string_items_in_target_files_are_dropped(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_plan

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps({**_WELL_FORMED, "target_files": ["a.py", 123, None, "b.py"]})

        result = generate_remediation_plan("some vuln", llm)
        assert result.target_files == ["a.py", "b.py"]


# ---------------------------------------------------------------------------
# _verify_file() -- path safety
# ---------------------------------------------------------------------------

class TestVerifyFile:
    def test_valid_relative_file_canonicalized(self, tmp_path):
        from utilities.autopatcher.remediation_planner import _verify_file

        target = tmp_path / "src" / "foo.py"
        target.parent.mkdir(parents=True)
        target.write_text("pass\n", encoding="utf-8")

        assert _verify_file("src/foo.py", tmp_path) == "src/foo.py"

    def test_absolute_path_rejected(self, tmp_path):
        from utilities.autopatcher.remediation_planner import _verify_file
        assert _verify_file("/etc/passwd", tmp_path) is None

    def test_traversal_path_rejected(self, tmp_path):
        from utilities.autopatcher.remediation_planner import _verify_file
        assert _verify_file("../outside.py", tmp_path) is None
        assert _verify_file("src/../../outside.py", tmp_path) is None

    def test_missing_file_rejected(self, tmp_path):
        from utilities.autopatcher.remediation_planner import _verify_file
        assert _verify_file("does/not/exist.py", tmp_path) is None

    def test_directory_rejected(self, tmp_path):
        from utilities.autopatcher.remediation_planner import _verify_file
        (tmp_path / "src").mkdir()
        assert _verify_file("src", tmp_path) is None

    def test_non_string_input_rejected(self, tmp_path):
        from utilities.autopatcher.remediation_planner import _verify_file
        assert _verify_file(123, tmp_path) is None
        assert _verify_file(None, tmp_path) is None

    def test_empty_string_rejected(self, tmp_path):
        from utilities.autopatcher.remediation_planner import _verify_file
        assert _verify_file("", tmp_path) is None
        assert _verify_file("   ", tmp_path) is None


# ---------------------------------------------------------------------------
# _resolve_symbol() -- symbol verification
# ---------------------------------------------------------------------------

class TestResolveSymbol:
    def test_file_symbol_pair_resolves_correct_line(self, tmp_path):
        target = tmp_path / "src" / "util" / "retry.py"
        target.parent.mkdir(parents=True)
        target.write_text("class Retry:\n    pass\n", encoding="utf-8")

        context = _make_context(functions={
            "src/util/retry.py:Retry.method": {
                "name": "method", "startLine": 12, "endLine": 20, "className": "Retry",
            },
        })

        from utilities.autopatcher.remediation_planner import _resolve_symbol
        result = _resolve_symbol("src/util/retry.py:Retry.method", tmp_path, context)

        assert result == ("src/util/retry.py", "Retry.method", 12)

    def test_symbol_resolving_only_in_another_file_is_rejected(self, tmp_path):
        (tmp_path / "a.py").write_text("class A:\n    pass\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("class B:\n    pass\n", encoding="utf-8")

        context = _make_context(functions={
            "b.py:B.method": {"name": "method", "startLine": 5, "endLine": 8, "className": "B"},
        })

        from utilities.autopatcher.remediation_planner import _resolve_symbol
        # Planner claims the symbol lives in a.py; it only really exists in b.py.
        assert _resolve_symbol("a.py:A.method", tmp_path, context) is None

    def test_symbol_resolves_via_constants_table_when_not_a_function(self, tmp_path):
        target = tmp_path / "src" / "util" / "retry.py"
        target.parent.mkdir(parents=True)
        target.write_text(
            "class Retry:\n    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(['Authorization'])\n",
            encoding="utf-8",
        )

        context = _make_context(constants={
            "src/util/retry.py": {
                "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT": {
                    "qualified_name": "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                    "class_name": "Retry", "name": "DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                    "line": 2, "end_line": 2,
                },
            },
        })

        from utilities.autopatcher.remediation_planner import _resolve_symbol
        result = _resolve_symbol(
            "src/util/retry.py:Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT", tmp_path, context
        )

        assert result == ("src/util/retry.py", "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT", 2)

    def test_bare_symbol_no_file_hint_resolves_via_index(self, tmp_path):
        (tmp_path / "retry.py").write_text("class Retry:\n    pass\n", encoding="utf-8")
        context = _make_context(functions={
            "retry.py:Retry.method": {"name": "method", "startLine": 3, "endLine": 4, "className": "Retry"},
        })

        from utilities.autopatcher.remediation_planner import _resolve_symbol
        result = _resolve_symbol("method", tmp_path, context)

        assert result == ("retry.py", "method", 3)

    def test_unresolvable_symbol_returns_none(self, tmp_path):
        context = _make_context()
        from utilities.autopatcher.remediation_planner import _resolve_symbol
        assert _resolve_symbol("does_not_exist_anywhere", tmp_path, context) is None

    def test_no_context_returns_none(self, tmp_path):
        from utilities.autopatcher.remediation_planner import _resolve_symbol
        assert _resolve_symbol("anything", tmp_path, None) is None

    def test_stated_file_that_fails_verification_rejects_pairing(self, tmp_path):
        context = _make_context(functions={
            "real.py:real.method": {"name": "method", "startLine": 1, "endLine": 2},
        })
        from utilities.autopatcher.remediation_planner import _resolve_symbol
        assert _resolve_symbol("/etc/passwd:method", tmp_path, context) is None


# ---------------------------------------------------------------------------
# _resolve_symbol_details() -- class-qualifier disambiguation regression
# (same bare method name on two different classes, no file hint given --
# the exact urllib3 PoolManager.urlopen / HTTPConnectionPool.urlopen shape)
# ---------------------------------------------------------------------------

class TestClassQualifiedSymbolResolution:
    def _urlopen_context(self):
        return _make_context(functions={
            "poolmanager.py:PoolManager.urlopen": {
                "name": "urlopen", "startLine": 10, "endLine": 20, "className": "PoolManager",
            },
            "connectionpool.py:HTTPConnectionPool.urlopen": {
                "name": "urlopen", "startLine": 100, "endLine": 150, "className": "HTTPConnectionPool",
            },
        })

    def test_poolmanager_urlopen_resolves_to_poolmanager(self, tmp_path):
        from utilities.autopatcher.remediation_planner import _resolve_symbol
        result = _resolve_symbol("PoolManager.urlopen", tmp_path, self._urlopen_context())
        assert result == ("poolmanager.py", "PoolManager.urlopen", 10)

    def test_httpconnectionpool_urlopen_resolves_to_httpconnectionpool(self, tmp_path):
        from utilities.autopatcher.remediation_planner import _resolve_symbol
        result = _resolve_symbol("HTTPConnectionPool.urlopen", tmp_path, self._urlopen_context())
        assert result == ("connectionpool.py", "HTTPConnectionPool.urlopen", 100)

    def test_bare_urlopen_still_matches_first_result_as_before(self, tmp_path):
        # Unqualified proposals are unaffected by the class check -- bare
        # search_by_name behavior (whichever match comes first) is
        # unchanged, matching pre-fix semantics exactly.
        from utilities.autopatcher.remediation_planner import _resolve_symbol
        result = _resolve_symbol("urlopen", tmp_path, self._urlopen_context())
        assert result is not None
        assert result[1] == "urlopen"
        assert result[0] in ("poolmanager.py", "connectionpool.py")

    def test_qualified_symbol_for_nonexistent_class_fails_safely(self, tmp_path):
        # "SomeOtherClass.urlopen" -- the bare name exists, but never under
        # that class -- must fail closed, not fall back to a same-named
        # method on a different class.
        from utilities.autopatcher.remediation_planner import _resolve_symbol
        assert _resolve_symbol("SomeOtherClass.urlopen", tmp_path, self._urlopen_context()) is None

    def test_class_qualifier_rejects_cross_class_match_with_no_file_hint(self, tmp_path):
        # The exact bug shape: no file hint at all, so only the class
        # qualifier can disambiguate. Before the fix this returned
        # whichever match search_by_name happened to return first.
        from utilities.autopatcher.remediation_planner import _resolve_symbol_details
        context = self._urlopen_context()
        match = _resolve_symbol_details("PoolManager.urlopen", tmp_path, context)
        assert match is not None
        assert match.file == "poolmanager.py"
        assert match.func_id == "poolmanager.py:PoolManager.urlopen"

    def test_module_level_function_has_no_class_and_qualified_lookup_fails(self, tmp_path):
        # A function with no className at all (module-level) must not
        # match a qualified proposal -- None != "SomeClass" is a rejection,
        # never a class-qualifier bypass.
        context = _make_context(functions={
            "utils.py:helper": {"name": "helper", "startLine": 1, "endLine": 2},
        })
        from utilities.autopatcher.remediation_planner import _resolve_symbol
        assert _resolve_symbol("SomeClass.helper", tmp_path, context) is None
        # bare (unqualified) lookup for the same function still works
        assert _resolve_symbol("helper", tmp_path, context) == ("utils.py", "helper", 1)

    def test_existing_file_hint_disambiguation_unaffected(self, tmp_path):
        # Pre-existing behavior: a file hint alone already disambiguated
        # this case correctly (regardless of class). The class-qualifier
        # check must not change this outcome.
        (tmp_path / "poolmanager.py").write_text("class PoolManager:\n    pass\n", encoding="utf-8")
        from utilities.autopatcher.remediation_planner import _resolve_symbol
        result = _resolve_symbol(
            "poolmanager.py:PoolManager.urlopen", tmp_path, self._urlopen_context()
        )
        assert result == ("poolmanager.py", "PoolManager.urlopen", 10)

    def test_planner_symbols_bridge_resolves_correct_class_end_to_end(self, tmp_path):
        # End-to-end through the same bridge build_planner_evidence uses --
        # both target_symbols proposed bare (no file hint), each must
        # resolve to its OWN file/class, not collapse onto one.
        (tmp_path / "poolmanager.py").write_text("class PoolManager:\n    pass\n", encoding="utf-8")
        (tmp_path / "connectionpool.py").write_text("class HTTPConnectionPool:\n    pass\n", encoding="utf-8")
        context = self._urlopen_context()
        from utilities.autopatcher.remediation_planner import _resolve_planner_symbols

        plan = RemediationPlanResult(
            rendered="", target_files=["poolmanager.py", "connectionpool.py"],
            target_symbols=["PoolManager.urlopen", "HTTPConnectionPool.urlopen"],
        )
        resolved = _resolve_planner_symbols(plan, tmp_path, context)

        assert resolved["poolmanager.py"].label == "PoolManager.urlopen"
        assert resolved["connectionpool.py"].label == "HTTPConnectionPool.urlopen"


# ---------------------------------------------------------------------------
# build_planner_candidates() -- the adapter into RepositoryCandidate shape
# ---------------------------------------------------------------------------

class TestBuildPlannerCandidates:
    def test_no_target_files_returns_empty(self, tmp_path):
        from utilities.autopatcher.remediation_planner import build_planner_candidates
        plan = RemediationPlanResult(rendered="", target_files=[], target_symbols=[])
        assert build_planner_candidates(plan, tmp_path, None) == []

    def test_unverifiable_files_produce_no_candidates(self, tmp_path):
        from utilities.autopatcher.remediation_planner import build_planner_candidates
        plan = RemediationPlanResult(
            rendered="", target_files=["/etc/passwd", "../outside.py", "missing.py"], target_symbols=[],
        )
        assert build_planner_candidates(plan, tmp_path, None) == []

    def test_order_matches_planner_order_and_dedups(self, tmp_path):
        (tmp_path / "b.py").write_text("pass\n", encoding="utf-8")
        (tmp_path / "a.py").write_text("pass\n", encoding="utf-8")
        from utilities.autopatcher.remediation_planner import build_planner_candidates
        plan = RemediationPlanResult(rendered="", target_files=["b.py", "a.py", "b.py"], target_symbols=[])

        candidates = build_planner_candidates(plan, tmp_path, None)

        assert [c.path for c in candidates] == ["b.py", "a.py"]

    def test_cap_matches_existing_candidate_selection_cap(self, tmp_path):
        from utilities.autopatcher.candidate_selection import DEFAULT_MAX_CANDIDATES
        from utilities.autopatcher.remediation_planner import build_planner_candidates

        names = []
        for i in range(DEFAULT_MAX_CANDIDATES + 3):
            fname = f"f{i}.py"
            (tmp_path / fname).write_text("pass\n", encoding="utf-8")
            names.append(fname)

        plan = RemediationPlanResult(rendered="", target_files=names, target_symbols=[])
        candidates = build_planner_candidates(plan, tmp_path, None)

        assert len(candidates) == DEFAULT_MAX_CANDIDATES
        assert [c.path for c in candidates] == names[:DEFAULT_MAX_CANDIDATES]

    def test_verified_symbol_used_as_hit_line(self, tmp_path):
        (tmp_path / "retry.py").write_text("class Retry:\n    pass\n", encoding="utf-8")
        context = _make_context(functions={
            "retry.py:Retry.method": {"name": "method", "startLine": 7, "endLine": 9, "className": "Retry"},
        })
        from utilities.autopatcher.remediation_planner import build_planner_candidates
        plan = RemediationPlanResult(rendered="", target_files=["retry.py"], target_symbols=["retry.py:Retry.method"])

        candidates = build_planner_candidates(plan, tmp_path, context)

        assert len(candidates) == 1
        ev = candidates[0].evidence[0]
        assert ev.hit_line == 7
        assert ev.resolution_strategy == "planner_symbol_verified"
        assert ev.pass_name == "planner_proposed"

    def test_unresolved_symbol_does_not_suppress_file_candidate(self, tmp_path):
        (tmp_path / "retry.py").write_text("class Retry:\n    pass\n", encoding="utf-8")
        from utilities.autopatcher.remediation_planner import build_planner_candidates
        plan = RemediationPlanResult(rendered="", target_files=["retry.py"], target_symbols=["nonexistent_symbol_xyz"])

        candidates = build_planner_candidates(plan, tmp_path, None)

        assert len(candidates) == 1
        ev = candidates[0].evidence[0]
        assert ev.hit_line == 0
        assert ev.resolution_strategy == "planner_file_only"

    def test_candidate_has_no_grounding_tier(self, tmp_path):
        # best_tier (what render_repository_understanding's "best tier"
        # line actually reads) must stay None -- a Planner-origin candidate
        # must never claim an ordinary Repository Grounding tier.
        (tmp_path / "retry.py").write_text("pass\n", encoding="utf-8")
        from utilities.autopatcher.remediation_planner import build_planner_candidates
        plan = RemediationPlanResult(rendered="", target_files=["retry.py"], target_symbols=[])

        candidates = build_planner_candidates(plan, tmp_path, None)

        assert candidates[0].best_tier is None
        assert candidates[0].evidence[0].pass_name == "planner_proposed"


# ---------------------------------------------------------------------------
# build_planner_source_excerpts() -- verified real source, bounded
# ---------------------------------------------------------------------------

class TestBuildPlannerSourceExcerpts:
    def _candidate(self, path):
        from utilities.autopatcher.remediation_planner import DiscoveryEvidence, RepositoryCandidate
        return RepositoryCandidate(
            path=path,
            evidence=[DiscoveryEvidence(pass_name="planner_proposed", tier=0, matched_tokens=None,
                                         total_occurrences=None, hit_line=0, resolution_strategy="planner_file_only")],
            best_tier=None,
        )

    def test_function_symbol_renders_exact_source_with_path_and_line_range(self, tmp_path):
        target = tmp_path / "poolmanager.py"
        func_src = (
            "def urlopen(self, method, url, redirect=True, **kw):\n"
            "    # strip headers unsafe to forward on redirect\n"
            "    pass\n"
        )
        target.write_text("class PoolManager:\n" + "\n".join("    " + l for l in func_src.splitlines()) + "\n",
                           encoding="utf-8")
        context = _make_context(
            functions={
                "poolmanager.py:PoolManager.urlopen": {
                    "name": "urlopen", "startLine": 409, "endLine": 486, "className": "PoolManager",
                    "code": func_src,
                },
            },
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import (
            _resolve_planner_symbols, build_planner_candidates, build_planner_source_excerpts,
        )

        plan = RemediationPlanResult(
            rendered="", target_files=["poolmanager.py"], target_symbols=["poolmanager.py:PoolManager.urlopen"],
        )
        symbol_locations = _resolve_planner_symbols(plan, tmp_path, context)
        candidates = build_planner_candidates(plan, tmp_path, context, symbol_locations=symbol_locations)

        result = build_planner_source_excerpts(candidates, symbol_locations, tmp_path, context)

        assert "#### Verified source: `poolmanager.py:PoolManager.urlopen` (lines 409–486)" in result
        assert "def urlopen(self, method, url, redirect=True, **kw):" in result
        assert "strip headers unsafe to forward on redirect" in result

    def test_constant_symbol_renders_exact_defining_line(self, tmp_path):
        target = tmp_path / "retry.py"
        target.write_text(
            "class Retry:\n"
            "    DEFAULT_ALLOWED_METHODS = frozenset(['GET'])\n"
            "    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset([\"Authorization\"])\n",
            encoding="utf-8",
        )
        context = _make_context(
            constants={
                "retry.py": {
                    "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT": {
                        "qualified_name": "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                        "class_name": "Retry", "name": "DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                        "line": 3, "end_line": 3,
                    },
                },
            },
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import (
            _resolve_planner_symbols, build_planner_candidates, build_planner_source_excerpts,
        )

        plan = RemediationPlanResult(
            rendered="", target_files=["retry.py"],
            target_symbols=["retry.py:Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT"],
        )
        symbol_locations = _resolve_planner_symbols(plan, tmp_path, context)
        candidates = build_planner_candidates(plan, tmp_path, context, symbol_locations=symbol_locations)

        result = build_planner_source_excerpts(candidates, symbol_locations, tmp_path, context)

        assert "#### Verified source: `retry.py:Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT` (lines 3–3)" in result
        # exact repository capitalization/literal value -- not invented or normalized
        assert 'DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])' in result
        assert '"authorization"' not in result  # lowercase variant must never appear

    def test_file_only_candidate_does_not_use_module_level_as_symbol(self, tmp_path):
        target = tmp_path / "solo.py"
        target.write_text("x = 1\n", encoding="utf-8")
        candidate = self._candidate("solo.py")

        from utilities.autopatcher.remediation_planner import build_planner_source_excerpts
        result = build_planner_source_excerpts([candidate], {}, tmp_path, None)

        assert "__module__" not in result
        assert "(full file, 1 lines)" in result

    def test_full_file_fallback_used_when_no_symbol_resolves(self, tmp_path):
        target = tmp_path / "solo.py"
        target.write_text("line1\nline2\nline3\n", encoding="utf-8")
        candidate = self._candidate("solo.py")

        from utilities.autopatcher.remediation_planner import build_planner_source_excerpts
        result = build_planner_source_excerpts([candidate], {}, tmp_path, None)

        assert "#### Verified source: `solo.py` (full file, 3 lines)" in result
        assert "line1\nline2\nline3" in result

    def test_oversized_full_file_omitted_not_truncated(self, tmp_path):
        from utilities.autopatcher.evidence_fusion import DEFAULT_MAX_CHARS
        target = tmp_path / "huge.py"
        target.write_text("x = 1\n" * (DEFAULT_MAX_CHARS // 4), encoding="utf-8")
        candidate = self._candidate("huge.py")

        from utilities.autopatcher.remediation_planner import build_planner_source_excerpts
        result = build_planner_source_excerpts([candidate], {}, tmp_path, None)

        # nothing fit, so no partial/truncated block -- but the omission is
        # stated explicitly rather than silently returning nothing at all.
        assert "#### Verified source" not in result
        assert "huge.py" in result
        assert "omitted to stay within" in result

    def test_oversized_first_excerpt_does_not_suppress_later_excerpt(self, tmp_path):
        from utilities.autopatcher.evidence_fusion import DEFAULT_MAX_CHARS
        (tmp_path / "huge.py").write_text("x = 1\n" * (DEFAULT_MAX_CHARS // 4), encoding="utf-8")
        (tmp_path / "small.py").write_text("y = 2\n", encoding="utf-8")
        candidates = [self._candidate("huge.py"), self._candidate("small.py")]

        from utilities.autopatcher.remediation_planner import build_planner_source_excerpts
        result = build_planner_source_excerpts(candidates, {}, tmp_path, None)

        assert "#### Verified source: `small.py`" in result
        assert "y = 2" in result
        assert "huge.py" in result  # named in the omission note
        assert "omitted to stay within" in result

    def test_duplicate_candidate_paths_emit_once(self, tmp_path):
        (tmp_path / "solo.py").write_text("x = 1\n", encoding="utf-8")
        candidates = [self._candidate("solo.py"), self._candidate("solo.py")]

        from utilities.autopatcher.remediation_planner import build_planner_source_excerpts
        result = build_planner_source_excerpts(candidates, {}, tmp_path, None)

        assert result.count("#### Verified source") == 1

    def test_excerpt_order_matches_candidate_order(self, tmp_path):
        (tmp_path / "b.py").write_text("b = 1\n", encoding="utf-8")
        (tmp_path / "a.py").write_text("a = 1\n", encoding="utf-8")
        candidates = [self._candidate("b.py"), self._candidate("a.py")]

        from utilities.autopatcher.remediation_planner import build_planner_source_excerpts
        result = build_planner_source_excerpts(candidates, {}, tmp_path, None)

        assert result.index("b.py") < result.index("a.py")

    def test_no_candidates_returns_empty(self, tmp_path):
        from utilities.autopatcher.remediation_planner import build_planner_source_excerpts
        assert build_planner_source_excerpts([], {}, tmp_path, None) == ""

    def test_unreadable_file_omitted_not_raising(self, tmp_path):
        # Missing/unreadable is a distinct category from "omitted for
        # budget reasons" -- see test_omission_categories_distinguished.
        candidate = self._candidate("does_not_exist_on_disk.py")
        from utilities.autopatcher.remediation_planner import build_planner_source_excerpts
        result = build_planner_source_excerpts([candidate], {}, tmp_path, None)
        assert "#### Verified source" not in result
        assert "does_not_exist_on_disk.py" in result
        assert "source could not be read" in result

    def test_subheading_and_disclaimer_present(self, tmp_path):
        (tmp_path / "solo.py").write_text("x = 1\n", encoding="utf-8")
        candidate = self._candidate("solo.py")
        from utilities.autopatcher.remediation_planner import build_planner_source_excerpts
        result = build_planner_source_excerpts([candidate], {}, tmp_path, None)

        assert result.startswith("### Verified source from Planner-proposed candidates")
        assert "loaded from the target repository" in result
        assert "proposed by the Remediation Planner" in result
        assert "does not prove" in result


# ---------------------------------------------------------------------------
# build_planner_source_excerpts() -- two-pass priority (verified symbols
# strictly before any full-file fallback), and the _collections.py leak proof
# ---------------------------------------------------------------------------

class TestBuildPlannerSourceExcerptsPriority:
    def _candidate(self, path):
        from utilities.autopatcher.remediation_planner import DiscoveryEvidence, RepositoryCandidate
        return RepositoryCandidate(
            path=path,
            evidence=[DiscoveryEvidence(pass_name="planner_proposed", tier=0, matched_tokens=None,
                                         total_occurrences=None, hit_line=0, resolution_strategy="planner_file_only")],
            best_tier=None,
        )

    def test_fallback_first_in_order_does_not_block_a_later_verified_symbol(self, tmp_path):
        # This is the exact regression: a symbol-less (fallback-eligible)
        # candidate appears FIRST in Planner order; a verified symbol
        # excerpt for a DIFFERENT candidate appears second. The symbol
        # excerpt must still be included -- pass 1 processes ALL symbols
        # before pass 2 ever attempts a fallback, regardless of order.
        (tmp_path / "collections.py").write_text("x = 1\n" * 2000, encoding="utf-8")  # large, no symbol
        target = tmp_path / "retry.py"
        target.write_text("class Retry:\n    pass\n", encoding="utf-8")
        context = _make_context(
            functions={"retry.py:Retry.method": {"name": "method", "startLine": 2, "endLine": 2,
                                                  "className": "Retry", "code": "    pass\n"}},
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import (
            _resolve_planner_symbols, build_planner_candidates, build_planner_source_excerpts,
        )
        plan = RemediationPlanResult(
            rendered="", target_files=["collections.py", "retry.py"], target_symbols=["retry.py:Retry.method"],
        )
        symbol_locations = _resolve_planner_symbols(plan, tmp_path, context)
        candidates = build_planner_candidates(plan, tmp_path, context, symbol_locations=symbol_locations)
        assert [c.path for c in candidates] == ["collections.py", "retry.py"]  # fallback-eligible listed first

        result = build_planner_source_excerpts(candidates, symbol_locations, tmp_path, context)

        assert "#### Verified source: `retry.py:Retry.method`" in result

    def test_oversized_fallback_omitted_does_not_consume_budget_from_symbol(self, tmp_path):
        from utilities.autopatcher.evidence_fusion import DEFAULT_MAX_CHARS
        (tmp_path / "huge.py").write_text("x = 1\n" * (DEFAULT_MAX_CHARS // 4), encoding="utf-8")
        (tmp_path / "retry.py").write_text("class Retry:\n    pass\n", encoding="utf-8")
        context = _make_context(
            functions={"retry.py:Retry.method": {"name": "method", "startLine": 2, "endLine": 2,
                                                  "className": "Retry", "code": "    pass\n"}},
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import (
            _resolve_planner_symbols, build_planner_candidates, build_planner_source_excerpts,
        )
        plan = RemediationPlanResult(rendered="", target_files=["huge.py", "retry.py"], target_symbols=["retry.py:Retry.method"])
        symbol_locations = _resolve_planner_symbols(plan, tmp_path, context)
        candidates = build_planner_candidates(plan, tmp_path, context, symbol_locations=symbol_locations)

        result = build_planner_source_excerpts(candidates, symbol_locations, tmp_path, context)

        assert "#### Verified source: `retry.py:Retry.method`" in result
        assert "huge.py" in result  # named in the fallback omission note

    def test_oversized_symbol_excerpt_omitted_not_upgraded_to_full_file(self, tmp_path):
        # Requirement #4: if the verified function itself doesn't fit,
        # omit it explicitly -- never silently fall back to that same
        # file's whole content instead.
        from utilities.autopatcher.evidence_fusion import DEFAULT_MAX_CHARS
        target = tmp_path / "big_module.py"
        huge_body = "\n".join(f"    line_{i} = {i}" for i in range(DEFAULT_MAX_CHARS // 8))
        target.write_text(f"class C:\n    def method(self):\n{huge_body}\n", encoding="utf-8")
        context = _make_context(
            functions={"big_module.py:C.method": {
                "name": "method", "startLine": 2, "endLine": 2 + DEFAULT_MAX_CHARS // 8, "className": "C",
                "code": f"    def method(self):\n{huge_body}\n",
            }},
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import (
            _resolve_planner_symbols, build_planner_candidates, build_planner_source_excerpts,
        )
        plan = RemediationPlanResult(rendered="", target_files=["big_module.py"], target_symbols=["big_module.py:C.method"])
        symbol_locations = _resolve_planner_symbols(plan, tmp_path, context)
        candidates = build_planner_candidates(plan, tmp_path, context, symbol_locations=symbol_locations)

        result = build_planner_source_excerpts(candidates, symbol_locations, tmp_path, context)

        assert "#### Verified source" not in result  # neither the function nor a "full file" substitute
        assert "big_module.py:C.method" in result
        assert "symbol excerpt(s) omitted" in result

    def test_symbol_pass_order_is_deterministic(self, tmp_path):
        (tmp_path / "b.py").write_text("class B:\n    pass\n", encoding="utf-8")
        (tmp_path / "a.py").write_text("class A:\n    pass\n", encoding="utf-8")
        context = _make_context(
            functions={
                "b.py:B.m": {"name": "m", "startLine": 2, "endLine": 2, "className": "B"},
                "a.py:A.m": {"name": "m", "startLine": 2, "endLine": 2, "className": "A"},
            },
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import (
            _resolve_planner_symbols, build_planner_candidates, build_planner_source_excerpts,
        )
        plan = RemediationPlanResult(rendered="", target_files=["b.py", "a.py"], target_symbols=["b.py:B.m", "a.py:A.m"])
        symbol_locations = _resolve_planner_symbols(plan, tmp_path, context)
        candidates = build_planner_candidates(plan, tmp_path, context, symbol_locations=symbol_locations)

        result = build_planner_source_excerpts(candidates, symbol_locations, tmp_path, context)

        assert result.index("b.py:B.m") < result.index("a.py:A.m")

    def test_fallback_pass_order_is_deterministic(self, tmp_path):
        (tmp_path / "b.py").write_text("b = 1\n", encoding="utf-8")
        (tmp_path / "a.py").write_text("a = 1\n", encoding="utf-8")
        candidates = [self._candidate("b.py"), self._candidate("a.py")]

        from utilities.autopatcher.remediation_planner import build_planner_source_excerpts
        result = build_planner_source_excerpts(candidates, {}, tmp_path, None)

        assert result.index("b.py") < result.index("a.py")

    def test_omission_categories_distinguished(self, tmp_path):
        from utilities.autopatcher.evidence_fusion import DEFAULT_MAX_CHARS
        # one oversized symbol excerpt, one oversized fallback file, one
        # unreadable path -- each must land in its own, differently-worded
        # category, not a single undifferentiated list.
        huge_body = "\n".join(f"    x{i} = {i}" for i in range(DEFAULT_MAX_CHARS // 4))
        (tmp_path / "sym.py").write_text(f"class C:\n    def m(self):\n{huge_body}\n", encoding="utf-8")
        (tmp_path / "fb.py").write_text("y = 1\n" * (DEFAULT_MAX_CHARS // 4), encoding="utf-8")
        context = _make_context(
            functions={"sym.py:C.m": {
                "name": "m", "startLine": 2, "endLine": 2 + DEFAULT_MAX_CHARS // 4, "className": "C",
                "code": f"    def m(self):\n{huge_body}\n",
            }},
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import (
            _resolve_planner_symbols, build_planner_candidates, build_planner_source_excerpts,
        )
        plan = RemediationPlanResult(
            rendered="", target_files=["sym.py", "fb.py"], target_symbols=["sym.py:C.m"],
        )
        symbol_locations = _resolve_planner_symbols(plan, tmp_path, context)
        candidates = build_planner_candidates(plan, tmp_path, context, symbol_locations=symbol_locations)
        # A path that never existed is rejected during verification (never
        # reaches build_planner_source_excerpts at all) -- to exercise the
        # "source could not be read" category specifically, add a
        # candidate the same way build_planner_candidates would have, had
        # the file existed at verification time and then vanished before
        # this stage ran (e.g. a race), the one case a real read failure
        # can still occur here.
        candidates = candidates + [self._candidate("missing.py")]

        result = build_planner_source_excerpts(candidates, symbol_locations, tmp_path, context)

        assert "symbol excerpt(s) omitted to stay within" in result
        assert "full-file fallback(s) omitted to stay within" in result
        assert "source could not be read" in result
        assert "sym.py:C.m" in result
        assert "fb.py" in result
        assert "missing.py" in result

    def test_structural_evidence_remains_when_every_excerpt_omitted(self, tmp_path):
        from utilities.autopatcher.evidence_fusion import DEFAULT_MAX_CHARS
        (tmp_path / "huge.py").write_text("x = 1\n" * (DEFAULT_MAX_CHARS // 4), encoding="utf-8")
        from utilities.autopatcher.remediation_planner import build_planner_evidence
        plan = RemediationPlanResult(rendered="", target_files=["huge.py"], target_symbols=[])

        result = build_planner_evidence(plan, str(tmp_path), "vuln", None)

        assert result.startswith("## Planner-Proposed Candidate Evidence")
        assert "huge.py" in result
        assert "full-file fallback(s) omitted" in result

    def test_collections_py_absent_unless_in_target_files(self, tmp_path):
        # The exact regression from the real run: a file must never enter
        # the Planner-source block unless it is literally one of the
        # Planner's OWN (verified) target_files -- never introduced via
        # symbol resolution, enrichment, or any other path.
        (tmp_path / "src" / "urllib3").mkdir(parents=True)
        (tmp_path / "src" / "urllib3" / "_collections.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "retry.py").write_text("class Retry:\n    pass\n", encoding="utf-8")
        context = _make_context(
            functions={"retry.py:Retry.method": {"name": "method", "startLine": 2, "endLine": 2, "className": "Retry"}},
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import build_planner_evidence

        # _collections.py is NOT in target_files -- only retry.py is.
        plan = RemediationPlanResult(rendered="", target_files=["retry.py"], target_symbols=["retry.py:Retry.method"])
        result = build_planner_evidence(plan, str(tmp_path), "vuln", context)

        assert "_collections.py" not in result

    def test_realistic_constant_and_function_both_fit_default_budget(self, tmp_path):
        # Sized to match the real urllib3 measurement (constant excerpt
        # ~192 chars, PoolManager.urlopen excerpt ~3111 chars, overhead
        # ~317 chars -- 3620 total, under the existing 4000 budget once
        # prioritization is correct).
        from utilities.autopatcher.evidence_fusion import DEFAULT_MAX_CHARS
        retry_py = tmp_path / "src" / "urllib3" / "util" / "retry.py"
        retry_py.parent.mkdir(parents=True)
        retry_py.write_text(
            "class Retry:\n    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset([\"Authorization\"])\n",
            encoding="utf-8",
        )
        pool_py = tmp_path / "src" / "urllib3" / "poolmanager.py"
        urlopen_body = "\n".join(f"        line_{i} = {i}" for i in range(90))  # ~78-line-scale function
        urlopen_src = f"    def urlopen(self, method, url, redirect=True, **kw):\n{urlopen_body}\n"
        pool_py.write_text("class PoolManager:\n" + urlopen_src, encoding="utf-8")

        context = _make_context(
            functions={
                "src/urllib3/poolmanager.py:PoolManager.urlopen": {
                    "name": "urlopen", "startLine": 409, "endLine": 486, "className": "PoolManager",
                    "code": urlopen_src,
                },
            },
            constants={
                "src/urllib3/util/retry.py": {
                    "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT": {
                        "qualified_name": "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                        "class_name": "Retry", "name": "DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                        "line": 2, "end_line": 2,
                    },
                },
            },
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import build_planner_evidence
        plan = RemediationPlanResult(
            rendered="",
            target_files=["src/urllib3/util/retry.py", "src/urllib3/poolmanager.py"],
            target_symbols=[
                "src/urllib3/util/retry.py:Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                "src/urllib3/poolmanager.py:PoolManager.urlopen",
            ],
        )

        result = build_planner_evidence(plan, str(tmp_path), "Cookie header leaked on redirect", context)

        assert 'DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])' in result
        assert "def urlopen(self, method, url, redirect=True, **kw):" in result
        assert "omitted" not in result  # both fit; nothing dropped
        assert len(result) > 0


# ---------------------------------------------------------------------------
# build_planner_evidence() -- full bridge: verify -> enrich -> fuse -> render
# ---------------------------------------------------------------------------

class TestBuildPlannerEvidence:
    def test_no_repo_root_returns_empty(self):
        from utilities.autopatcher.remediation_planner import build_planner_evidence
        plan = RemediationPlanResult(rendered="", target_files=["a.py"], target_symbols=[])
        assert build_planner_evidence(plan, None, "vuln", None) == ""

    def test_no_proposals_returns_empty(self, tmp_path):
        from utilities.autopatcher.remediation_planner import build_planner_evidence
        plan = RemediationPlanResult(rendered="", target_files=[], target_symbols=[])
        assert build_planner_evidence(plan, str(tmp_path), "vuln", None) == ""

    def test_no_candidates_survive_verification_returns_empty(self, tmp_path):
        from utilities.autopatcher.remediation_planner import build_planner_evidence
        plan = RemediationPlanResult(rendered="", target_files=["/etc/passwd"], target_symbols=[])
        assert build_planner_evidence(plan, str(tmp_path), "vuln", None) == ""

    def test_reuses_enrichment_and_renders_with_planner_heading(self, tmp_path):
        (tmp_path / "retry.py").write_text("class Retry:\n    pass\n", encoding="utf-8")
        context = _make_context(functions={
            "retry.py:Retry.method": {"name": "method", "startLine": 2, "endLine": 2, "className": "Retry"},
        })
        from utilities.autopatcher.remediation_planner import build_planner_evidence
        plan = RemediationPlanResult(rendered="", target_files=["retry.py"], target_symbols=["retry.py:Retry.method"])

        result = build_planner_evidence(plan, str(tmp_path), "vuln", context)

        assert result.startswith("## Planner-Proposed Candidate Evidence")
        assert "retry.py" in result
        # a real fact produced by the EXISTING enrichment/rendering pipeline,
        # not something this bridge invents itself:
        assert "Resolved near grounding evidence" in result

    def test_disclaimer_present(self, tmp_path):
        (tmp_path / "retry.py").write_text("pass\n", encoding="utf-8")
        from utilities.autopatcher.remediation_planner import build_planner_evidence
        plan = RemediationPlanResult(rendered="", target_files=["retry.py"], target_symbols=[])

        result = build_planner_evidence(plan, str(tmp_path), "vuln", None)

        assert "proposed by the experimental Remediation Planner" in result
        assert "verified to exist in this repository" in result
        assert "None of this confirms" in result

    def test_no_confusing_internal_wording_leaked(self, tmp_path):
        (tmp_path / "retry.py").write_text("pass\n", encoding="utf-8")
        from utilities.autopatcher.remediation_planner import build_planner_evidence
        plan = RemediationPlanResult(rendered="", target_files=["retry.py"], target_symbols=[])

        result = build_planner_evidence(plan, str(tmp_path), "vuln", None)

        assert "synthetic candidate" not in result.lower()

    def test_ordinary_repository_understanding_heading_not_used(self, tmp_path):
        (tmp_path / "retry.py").write_text("pass\n", encoding="utf-8")
        from utilities.autopatcher.remediation_planner import build_planner_evidence
        plan = RemediationPlanResult(rendered="", target_files=["retry.py"], target_symbols=[])

        result = build_planner_evidence(plan, str(tmp_path), "vuln", None)

        assert not result.startswith("## Repository Understanding")

    def test_enrichment_failure_returns_empty_not_raises(self, tmp_path, monkeypatch):
        (tmp_path / "retry.py").write_text("pass\n", encoding="utf-8")
        from utilities.autopatcher.remediation_planner import build_planner_evidence

        def _boom(*a, **kw):
            raise RuntimeError("boom")

        monkeypatch.setattr("utilities.autopatcher.candidate_enrichment.enrich_candidates", _boom)

        plan = RemediationPlanResult(rendered="", target_files=["retry.py"], target_symbols=[])
        assert build_planner_evidence(plan, str(tmp_path), "vuln", None) == ""

    def test_fusion_failure_returns_empty_not_raises(self, tmp_path, monkeypatch):
        (tmp_path / "retry.py").write_text("pass\n", encoding="utf-8")
        from utilities.autopatcher.remediation_planner import build_planner_evidence

        def _boom(*a, **kw):
            raise RuntimeError("boom")

        monkeypatch.setattr("utilities.autopatcher.evidence_fusion.fuse_evidence", _boom)

        plan = RemediationPlanResult(rendered="", target_files=["retry.py"], target_symbols=[])
        assert build_planner_evidence(plan, str(tmp_path), "vuln", None) == ""

    def test_investigation_context_not_rebuilt(self, tmp_path, monkeypatch):
        (tmp_path / "retry.py").write_text("pass\n", encoding="utf-8")
        from utilities.autopatcher.remediation_planner import build_planner_evidence

        called = {"n": 0}

        def _fail_if_called(*a, **kw):
            called["n"] += 1
            raise AssertionError("build_investigation_context must not be called by the bridge")

        monkeypatch.setattr(
            "utilities.autopatcher.candidate_enrichment.build_investigation_context", _fail_if_called
        )

        plan = RemediationPlanResult(rendered="", target_files=["retry.py"], target_symbols=[])
        build_planner_evidence(plan, str(tmp_path), "vuln", None)

        assert called["n"] == 0

    def test_no_context_preserves_structural_evidence(self, tmp_path):
        # No InvestigationContext at all -- structural evidence still
        # renders (degraded, file/test-only). The full-file fallback in
        # build_planner_source_excerpts reads straight from disk and does
        # not itself need an index, so a small file-only candidate's whole
        # file is still included -- this is intentional, not a bug: no
        # context should never mean "no source at all" when a plain file
        # read is enough.
        (tmp_path / "retry.py").write_text("pass\n", encoding="utf-8")
        from utilities.autopatcher.remediation_planner import build_planner_evidence
        plan = RemediationPlanResult(rendered="", target_files=["retry.py"], target_symbols=[])

        result = build_planner_evidence(plan, str(tmp_path), "vuln", None)

        assert result.startswith("## Planner-Proposed Candidate Evidence")
        assert "### Verified source from Planner-proposed candidates" in result
        assert "#### Verified source: `retry.py` (full file, 1 lines)" in result

    def test_source_read_failure_preserves_structural_evidence(self, tmp_path, monkeypatch):
        (tmp_path / "retry.py").write_text("class Retry:\n    pass\n", encoding="utf-8")
        context = _make_context(
            functions={"retry.py:Retry.method": {"name": "method", "startLine": 2, "endLine": 2, "className": "Retry"}},
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import build_planner_evidence

        def _boom(*a, **kw):
            raise RuntimeError("boom")

        monkeypatch.setattr(
            "utilities.autopatcher.remediation_planner.build_planner_source_excerpts", _boom
        )

        plan = RemediationPlanResult(rendered="", target_files=["retry.py"], target_symbols=["retry.py:Retry.method"])
        result = build_planner_evidence(plan, str(tmp_path), "vuln", context)

        assert result.startswith("## Planner-Proposed Candidate Evidence")
        assert "Verified source from Planner-proposed candidates" not in result

    def test_urllib3_style_end_to_end_includes_constant_and_function_source(self, tmp_path):
        # The scenario this whole task exists to fix: a verified constant
        # AND a verified function, both with real source reaching the
        # rendered Planner evidence block.
        retry_py = tmp_path / "src" / "urllib3" / "util" / "retry.py"
        retry_py.parent.mkdir(parents=True)
        retry_py.write_text(
            "class Retry:\n"
            "    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset([\"Authorization\"])\n",
            encoding="utf-8",
        )
        pool_py = tmp_path / "src" / "urllib3" / "poolmanager.py"
        pool_py.write_text(
            "class PoolManager:\n"
            "    def urlopen(self, method, url, redirect=True, **kw):\n"
            "        pass\n",
            encoding="utf-8",
        )
        urlopen_src = "    def urlopen(self, method, url, redirect=True, **kw):\n        pass\n"

        context = _make_context(
            functions={
                "src/urllib3/poolmanager.py:PoolManager.urlopen": {
                    "name": "urlopen", "startLine": 2, "endLine": 3, "className": "PoolManager",
                    "code": urlopen_src,
                },
            },
            constants={
                "src/urllib3/util/retry.py": {
                    "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT": {
                        "qualified_name": "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                        "class_name": "Retry", "name": "DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                        "line": 2, "end_line": 2,
                    },
                },
            },
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import build_planner_evidence
        plan = RemediationPlanResult(
            rendered="",
            target_files=["src/urllib3/util/retry.py", "src/urllib3/poolmanager.py"],
            target_symbols=[
                "src/urllib3/util/retry.py:Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                "src/urllib3/poolmanager.py:PoolManager.urlopen",
            ],
        )

        result = build_planner_evidence(plan, str(tmp_path), "Cookie header leaked on redirect", context)

        assert 'DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])' in result
        assert "def urlopen(self, method, url, redirect=True, **kw):" in result
        assert "### Verified source from Planner-proposed candidates" in result
        # structural evidence still precedes the source subsection
        assert result.index("## Planner-Proposed Candidate Evidence") < result.index("### Verified source")


# ---------------------------------------------------------------------------
# No additional LLM call anywhere in the bridge
# ---------------------------------------------------------------------------

class TestNoAdditionalLLMCall:
    def test_build_planner_evidence_has_no_llm_parameter(self):
        import inspect
        from utilities.autopatcher.remediation_planner import build_planner_evidence
        assert "llm" not in inspect.signature(build_planner_evidence).parameters

    def test_build_planner_candidates_has_no_llm_parameter(self):
        import inspect
        from utilities.autopatcher.remediation_planner import build_planner_candidates
        assert "llm" not in inspect.signature(build_planner_candidates).parameters

    def test_resolve_symbol_has_no_llm_parameter(self):
        import inspect
        from utilities.autopatcher.remediation_planner import _resolve_symbol
        assert "llm" not in inspect.signature(_resolve_symbol).parameters

    def test_build_planner_source_excerpts_has_no_llm_parameter(self):
        import inspect
        from utilities.autopatcher.remediation_planner import build_planner_source_excerpts
        assert "llm" not in inspect.signature(build_planner_source_excerpts).parameters


# ---------------------------------------------------------------------------
# Pipeline wiring
# ---------------------------------------------------------------------------

class TestPipelineWiring:
    """The planner's rendered output, and the separate Planner-Proposed
    Candidate Evidence block, must both reach generate_patch()'s
    code_context in the required order -- without needing a real
    repo_root/grounding for the plan-text-only checks, since that call
    sits right after Repository Understanding regardless of whether
    grounding found anything."""

    def _run_with_mocks(self, plan_result, repo_root=None, extra_patches=()):
        patches = [
            mock.patch("utilities.autopatcher.pipeline.LLMClient"),
            mock.patch("utilities.autopatcher.remediation_planner.generate_remediation_plan",
                       return_value=plan_result),
            mock.patch("utilities.autopatcher.pipeline.generate_patch",
                       return_value="```diff\n--- a/f.py\n+++ b/f.py\n```"),
            mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok"),
            mock.patch("utilities.autopatcher.pipeline.challenge_patch", return_value={}),
            mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="score: 7"),
            mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
            mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
            mock.patch("utilities.autopatcher.patch_applicability.check_applicability",
                       return_value={"applicable": True, "skipped": False, "stderr": "",
                                     "exit_code": 0, "skipped_reason": None, "error": None}),
        ] + list(extra_patches)
        started = [p.start() for p in patches]
        try:
            started[0].return_value = mock.MagicMock()
            from utilities.autopatcher.pipeline import run
            run("some vuln", api_key="", repo_root=repo_root)
        finally:
            for p in patches:
                p.stop()
        mock_plan, mock_gen = started[1], started[2]
        return mock_plan, mock_gen

    def test_plan_output_reaches_code_context(self):
        plan_result = RemediationPlanResult(
            rendered="## Remediation Plan (experimental — not verified against the repository)\n\nPLAN_MARKER\n",
            target_files=[], target_symbols=[],
        )
        mock_plan, mock_gen = self._run_with_mocks(plan_result)

        assert mock_plan.called
        code_context = mock_gen.call_args.kwargs.get("code_context", "")
        assert "PLAN_MARKER" in code_context

    def test_empty_plan_omitted_from_code_context(self):
        _mock_plan, mock_gen = self._run_with_mocks(_EMPTY)

        code_context = mock_gen.call_args.kwargs.get("code_context", "")
        assert "Remediation Plan" not in code_context
        assert "Planner-Proposed Candidate Evidence" not in code_context

    def test_planner_evidence_reaches_code_context_after_plan(self, tmp_path):
        target = tmp_path / "src" / "urllib3" / "util" / "retry.py"
        target.parent.mkdir(parents=True)
        target.write_text(
            "class Retry:\n    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(['Authorization'])\n",
            encoding="utf-8",
        )
        plan_result = RemediationPlanResult(
            rendered="## Remediation Plan (experimental — not verified against the repository)\n\nPLAN_MARKER\n",
            target_files=["src/urllib3/util/retry.py"], target_symbols=[],
        )

        _mock_plan, mock_gen = self._run_with_mocks(plan_result, repo_root=str(tmp_path))

        code_context = mock_gen.call_args.kwargs.get("code_context", "")
        assert "PLAN_MARKER" in code_context
        assert "## Planner-Proposed Candidate Evidence" in code_context
        assert "src/urllib3/util/retry.py" in code_context
        assert code_context.index("PLAN_MARKER") < code_context.index("Planner-Proposed Candidate Evidence")

    def test_planner_evidence_failure_preserves_plan_and_pipeline_continues(self, tmp_path):
        plan_result = RemediationPlanResult(
            rendered="## Remediation Plan (experimental — not verified against the repository)\n\nPLAN_MARKER\n",
            target_files=["retry.py"], target_symbols=[],
        )
        boom = mock.patch(
            "utilities.autopatcher.remediation_planner.build_planner_evidence",
            side_effect=RuntimeError("boom"),
        )

        _mock_plan, mock_gen = self._run_with_mocks(plan_result, repo_root=str(tmp_path), extra_patches=[boom])

        code_context = mock_gen.call_args.kwargs.get("code_context", "")
        assert "PLAN_MARKER" in code_context
        assert "Planner-Proposed Candidate Evidence" not in code_context

    def test_patch_generator_receives_real_verified_symbol_source(self, tmp_path):
        # The exact scenario this task exists to fix: the Patch Generator's
        # initial code_context must contain the real repository-verified
        # constant source, not just structural facts about it.
        retry_py = tmp_path / "src" / "urllib3" / "util" / "retry.py"
        retry_py.parent.mkdir(parents=True)
        retry_py.write_text(
            "class Retry:\n"
            "    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset([\"Authorization\"])\n",
            encoding="utf-8",
        )
        context = _make_context(
            constants={
                "src/urllib3/util/retry.py": {
                    "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT": {
                        "qualified_name": "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                        "class_name": "Retry", "name": "DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                        "line": 2, "end_line": 2,
                    },
                },
            },
            repo_path=tmp_path,
        )
        plan_result = RemediationPlanResult(
            rendered="## Remediation Plan (experimental — not verified against the repository)\n\nPLAN_MARKER\n",
            target_files=["src/urllib3/util/retry.py"],
            target_symbols=["src/urllib3/util/retry.py:Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT"],
        )
        # Names the real path explicitly so ordinary Repository Grounding
        # also selects it (Pass 1, explicit path) -- that is what makes
        # CandidateSelection.used_fallback False, which gates whether an
        # InvestigationContext is even attempted at all.
        vuln_text = "See src/urllib3/util/retry.py for the affected code."

        with (
            mock.patch("utilities.autopatcher.pipeline.LLMClient") as mock_llm_cls,
            mock.patch("utilities.autopatcher.remediation_planner.generate_remediation_plan", return_value=plan_result),
            mock.patch("utilities.autopatcher.candidate_enrichment.build_investigation_context", return_value=context),
            mock.patch("utilities.autopatcher.pipeline.generate_patch",
                       return_value="```diff\n--- a/f.py\n+++ b/f.py\n```") as mock_gen,
            mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok"),
            mock.patch("utilities.autopatcher.pipeline.challenge_patch", return_value={}),
            mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="score: 7"),
            mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
            mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
            mock.patch("utilities.autopatcher.patch_applicability.check_applicability",
                       return_value={"applicable": True, "skipped": False, "stderr": "",
                                     "exit_code": 0, "skipped_reason": None, "error": None}),
        ):
            mock_llm_cls.return_value = mock.MagicMock()
            from utilities.autopatcher.pipeline import run
            run(vuln_text, api_key="", repo_root=str(tmp_path), investigation_output_dir=str(tmp_path / "out"))

        code_context = mock_gen.call_args.kwargs.get("code_context", "")
        assert 'DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])' in code_context


# ---------------------------------------------------------------------------
# Target Discovery relabeling (Call 1's epistemic role is now explicit)
# ---------------------------------------------------------------------------

class TestTargetDiscoveryRelabeled:
    def test_still_returns_target_files_and_symbols(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_plan

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps(_WELL_FORMED)

        result = generate_remediation_plan("some vuln", llm)

        assert result.target_files == ["src/urllib3/util/retry.py", "src/urllib3/poolmanager.py"]
        assert result.target_symbols == ["Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT"]

    def test_heading_is_target_discovery_not_remediation_plan(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_plan

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps(_WELL_FORMED)

        result = generate_remediation_plan("some vuln", llm)

        assert result.rendered.startswith("## Target Discovery Plan")
        assert "exploratory" in result.rendered
        assert not result.rendered.startswith("## Remediation Plan")


# ---------------------------------------------------------------------------
# generate_remediation_strategy() -- the second, distinct Planner call
# ---------------------------------------------------------------------------

_STRATEGY_WELL_FORMED = {
    "extended_mechanism": "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
    "target_files": ["src/urllib3/util/retry.py"],
    "target_symbols": ["src/urllib3/util/retry.py:Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT"],
    "required_edits": ["Add 'Cookie' to the existing DEFAULT_REMOVE_HEADERS_ON_REDIRECT frozenset."],
    "rejected_targets": [],
    "security_invariant": "Sensitive request headers must not cross origins on redirect.",
    "insufficient_evidence": [],
}

class TestFinalStrategySkipsWithoutEvidence:
    def test_skipped_when_planner_evidence_ctx_empty(self):
        from utilities.autopatcher.remediation_planner import (
            generate_remediation_strategy, _EMPTY_STRATEGY_RESULT,
        )

        llm = mock.MagicMock()
        result = generate_remediation_strategy(
            "some vuln", llm, None, None, planner_evidence_ctx="",
        )

        assert result == _EMPTY_STRATEGY_RESULT
        llm.complete.assert_not_called()

    def test_skipped_when_planner_evidence_ctx_whitespace_only(self):
        from utilities.autopatcher.remediation_planner import (
            generate_remediation_strategy, _EMPTY_STRATEGY_RESULT,
        )

        llm = mock.MagicMock()
        result = generate_remediation_strategy(
            "some vuln", llm, None, None, planner_evidence_ctx="   \n  ",
        )

        assert result == _EMPTY_STRATEGY_RESULT
        llm.complete.assert_not_called()


class TestFinalStrategyStageLabel:
    def test_stage_label_is_remediation_strategy(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_strategy

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps(_STRATEGY_WELL_FORMED)

        generate_remediation_strategy(
            "some vuln", llm, None, None, planner_evidence_ctx="EVIDENCE",
        )

        _args, kwargs = llm.complete.call_args
        assert kwargs.get("stage") == "remediation_strategy"


class TestFinalStrategyInputs:
    def test_user_message_contains_all_sections_in_order(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_strategy

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps(_STRATEGY_WELL_FORMED)

        generate_remediation_strategy(
            "VULN_MARKER", llm, None, None,
            repo_grounding_ctx="GROUNDING_MARKER",
            repository_understanding_ctx="UNDERSTANDING_MARKER",
            discovery_plan_ctx="DISCOVERY_MARKER",
            planner_evidence_ctx="EVIDENCE_MARKER",
        )

        _system, user_message = llm.complete.call_args[0]
        assert "VULN_MARKER" in user_message
        assert "GROUNDING_MARKER" in user_message
        assert "UNDERSTANDING_MARKER" in user_message
        assert "DISCOVERY_MARKER" in user_message
        assert "EVIDENCE_MARKER" in user_message
        # exact required ordering
        assert (
            user_message.index("VULN_MARKER")
            < user_message.index("GROUNDING_MARKER")
            < user_message.index("UNDERSTANDING_MARKER")
            < user_message.index("DISCOVERY_MARKER")
            < user_message.index("EVIDENCE_MARKER")
        )

    def test_optional_sections_omitted_when_empty(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_strategy

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps(_STRATEGY_WELL_FORMED)

        generate_remediation_strategy(
            "VULN_MARKER", llm, None, None, planner_evidence_ctx="EVIDENCE_MARKER",
        )

        _system, user_message = llm.complete.call_args[0]
        assert "Original Repository Grounding" not in user_message
        assert "Ordinary Repository Understanding" not in user_message
        assert "Initial Target Discovery" not in user_message

    def test_schema_has_no_diff_or_code_field(self):
        # The OUTPUT SCHEMA itself must never ask for a diff or code field
        # (the prohibition sentence "you do not write a diff" legitimately
        # contains the word "diff" -- that is the opposite of a violation,
        # so this checks the schema block specifically).
        strategy_prompt = _STRATEGY_PROMPT_PATH_TEXT()
        schema_start = strategy_prompt.index("## Output schema")
        schema_block = strategy_prompt[schema_start:].lower()
        assert '"diff"' not in schema_block
        assert '"code"' not in schema_block
        assert '"patch"' not in schema_block


def _STRATEGY_PROMPT_PATH_TEXT() -> str:
    from utilities.autopatcher.remediation_planner import _STRATEGY_PROMPT_PATH
    return _STRATEGY_PROMPT_PATH.read_text(encoding="utf-8")


class TestFinalStrategyPromptRepositoryAgnostic:
    def test_no_hardcoded_domain_terms_in_universal_prompt(self):
        text = _STRATEGY_PROMPT_PATH_TEXT().lower()
        for term in ("urllib3", "cookie", "header", "redirect", "python"):
            assert term not in text, f"prompt hardcodes domain-specific term: {term!r}"


class TestFinalStrategyEvidenceBinding:
    def test_verified_file_and_symbol_retained(self, tmp_path):
        from utilities.autopatcher.remediation_planner import generate_remediation_strategy

        target = tmp_path / "retry.py"
        target.write_text("class Retry:\n    X = 1\n", encoding="utf-8")
        context = _make_context(
            constants={"retry.py": {"Retry.X": {"qualified_name": "Retry.X", "line": 2, "end_line": 2}}},
            repo_path=tmp_path,
        )

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps({
            **_STRATEGY_WELL_FORMED,
            "target_files": ["retry.py"],
            "target_symbols": ["retry.py:Retry.X"],
        })

        result = generate_remediation_strategy(
            "vuln", llm, str(tmp_path), context, planner_evidence_ctx="EVIDENCE",
        )

        assert result.target_files == ["retry.py"]
        assert result.target_symbols == ["retry.py:Retry.X"]
        assert result.warnings == []
        assert "retry.py" in result.rendered
        # The disclaimer prose mentions this phrase unconditionally; only
        # the actual rendered SECTION (bold heading) indicates real drops.
        assert "**Unverified items removed:**" not in result.rendered

    def test_invented_file_removed_with_warning(self, tmp_path):
        from utilities.autopatcher.remediation_planner import generate_remediation_strategy

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps({
            **_STRATEGY_WELL_FORMED,
            "target_files": ["does/not/exist.py"],
            "target_symbols": [],
        })

        result = generate_remediation_strategy(
            "vuln", llm, str(tmp_path), None, planner_evidence_ctx="EVIDENCE",
        )

        assert result.target_files == []
        assert any("does/not/exist.py" in w for w in result.warnings)
        assert "**Unverified items removed:**" in result.rendered
        assert "does/not/exist.py" in result.rendered

    def test_invented_symbol_removed_with_warning(self, tmp_path):
        from utilities.autopatcher.remediation_planner import generate_remediation_strategy

        target = tmp_path / "retry.py"
        target.write_text("class Retry:\n    X = 1\n", encoding="utf-8")
        context = _make_context(
            constants={"retry.py": {"Retry.X": {"qualified_name": "Retry.X", "line": 2, "end_line": 2}}},
            repo_path=tmp_path,
        )

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps({
            **_STRATEGY_WELL_FORMED,
            "target_files": ["retry.py"],
            "target_symbols": ["retry.py:Retry.DOES_NOT_EXIST"],
        })

        result = generate_remediation_strategy(
            "vuln", llm, str(tmp_path), context, planner_evidence_ctx="EVIDENCE",
        )

        assert result.target_files == ["retry.py"]
        assert result.target_symbols == []
        assert any("Retry.DOES_NOT_EXIST" in w for w in result.warnings)
        assert "**Unverified items removed:**" in result.rendered

    def test_rejected_target_rendered_explicitly(self, tmp_path):
        from utilities.autopatcher.remediation_planner import generate_remediation_strategy

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps({
            **_STRATEGY_WELL_FORMED,
            "target_files": [],
            "target_symbols": [],
            "rejected_targets": ["src/urllib3/_collections.py — contradicted by verified source"],
        })

        result = generate_remediation_strategy(
            "vuln", llm, str(tmp_path), None, planner_evidence_ctx="EVIDENCE",
        )

        assert "Rejected discovery targets" in result.rendered
        assert "src/urllib3/_collections.py" in result.rendered


class TestFinalStrategyFailureDegradation:
    def test_malformed_json_returns_empty(self):
        from utilities.autopatcher.remediation_planner import (
            generate_remediation_strategy, _EMPTY_STRATEGY_RESULT,
        )

        llm = mock.MagicMock()
        llm.complete.return_value = "not json at all"

        result = generate_remediation_strategy(
            "vuln", llm, None, None, planner_evidence_ctx="EVIDENCE",
        )
        assert result == _EMPTY_STRATEGY_RESULT

    def test_llm_error_returns_empty(self):
        from utilities.autopatcher.remediation_planner import (
            generate_remediation_strategy, _EMPTY_STRATEGY_RESULT,
        )

        llm = mock.MagicMock()
        llm.complete.side_effect = RuntimeError("boom")

        result = generate_remediation_strategy(
            "vuln", llm, None, None, planner_evidence_ctx="EVIDENCE",
        )
        assert result == _EMPTY_STRATEGY_RESULT

    def test_empty_object_response_returns_empty_rendered(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_strategy

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps({})

        result = generate_remediation_strategy(
            "vuln", llm, None, None, planner_evidence_ctx="EVIDENCE",
        )
        assert result.rendered == ""
        assert result.target_files == []
        assert result.target_symbols == []

    def test_missing_investigation_context_degrades_safely(self, tmp_path):
        # context=None: file verification (no context needed) still works;
        # symbol verification (needs context) safely fails closed instead
        # of raising.
        from utilities.autopatcher.remediation_planner import generate_remediation_strategy

        target = tmp_path / "retry.py"
        target.write_text("class Retry:\n    X = 1\n", encoding="utf-8")

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps({
            **_STRATEGY_WELL_FORMED,
            "target_files": ["retry.py"],
            "target_symbols": ["retry.py:Retry.X"],
        })

        result = generate_remediation_strategy(
            "vuln", llm, str(tmp_path), None, planner_evidence_ctx="EVIDENCE",
        )

        assert result.target_files == ["retry.py"]
        assert result.target_symbols == []
        assert any("Retry.X" in w for w in result.warnings)


class TestFinalStrategyNoNewAnalysisOrDiff:
    def test_no_new_investigation_context_built(self, tmp_path, monkeypatch):
        from utilities.autopatcher.remediation_planner import generate_remediation_strategy

        def _fail_if_called(*a, **kw):
            raise AssertionError("build_investigation_context must not be called")

        monkeypatch.setattr(
            "utilities.autopatcher.candidate_enrichment.build_investigation_context", _fail_if_called
        )

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps(_STRATEGY_WELL_FORMED)

        generate_remediation_strategy(
            "vuln", llm, str(tmp_path), None, planner_evidence_ctx="EVIDENCE",
        )
        # no exception -- build_investigation_context was never reached

    def test_diff_field_in_response_ignored(self, tmp_path):
        from utilities.autopatcher.remediation_planner import generate_remediation_strategy

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps({
            **_STRATEGY_WELL_FORMED,
            "target_files": [],
            "target_symbols": [],
            "diff": "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-x\n+y\n",
        })

        result = generate_remediation_strategy(
            "vuln", llm, str(tmp_path), None, planner_evidence_ctx="EVIDENCE",
        )
        assert "--- a/x.py" not in result.rendered
        assert "@@" not in result.rendered


class TestNoAdditionalLLMCallStrategy:
    def test_generate_remediation_strategy_has_exactly_one_llm_param(self):
        import inspect
        from utilities.autopatcher.remediation_planner import generate_remediation_strategy
        params = inspect.signature(generate_remediation_strategy).parameters
        assert "llm" in params
        assert list(params).count("llm") == 1

    def test_verify_strategy_targets_has_no_llm_parameter(self):
        import inspect
        from utilities.autopatcher.remediation_planner import _verify_strategy_targets
        assert "llm" not in inspect.signature(_verify_strategy_targets).parameters


# ---------------------------------------------------------------------------
# Full pipeline: exactly two Planner LLM calls, correct context ordering
# ---------------------------------------------------------------------------

_DISCOVERY_JSON = {
    "remediation_mechanism": "extend the existing header-removal policy",
    "target_files": ["retry.py"],
    "target_symbols": [],
    "security_invariant": "Sensitive request headers must not cross origins on redirect.",
    "required_edits": ["(exploratory) possibly add Cookie to the policy set"],
    "approaches_to_avoid": [],
    "explicit_unknowns": [],
}

_STRATEGY_JSON = {
    "extended_mechanism": "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
    "target_files": ["retry.py"],
    "target_symbols": [],
    "required_edits": ["Add 'Cookie' to the existing DEFAULT_REMOVE_HEADERS_ON_REDIRECT frozenset."],
    "rejected_targets": [],
    "security_invariant": "Sensitive request headers must not cross origins on redirect.",
    "insufficient_evidence": [],
}


class TestFullPipelineCallCountAndOrdering:
    """Real generate_remediation_plan/generate_remediation_strategy (not
    mocked) -- only the LLM transport (LLMClient) and the unrelated Patch
    Generator/Challenger/Confidence stages are mocked, so this measures the
    actual number and stage-labeling of Planner-related LLM calls the
    pipeline makes end to end."""

    def _run(self, tmp_path, discovery_json, strategy_json, vuln_text="some vulnerability"):
        target = tmp_path / "retry.py"
        target.write_text(
            "class Retry:\n    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(['Authorization'])\n",
            encoding="utf-8",
        )

        def side_effect(system_prompt, user_message, stage="unknown"):
            if stage == "remediation_planning":
                return json.dumps(discovery_json)
            if stage == "remediation_strategy":
                return json.dumps(strategy_json)
            return "{}"

        mock_llm = mock.MagicMock()
        mock_llm.complete.side_effect = side_effect

        with (
            mock.patch("utilities.autopatcher.pipeline.LLMClient", return_value=mock_llm),
            mock.patch("utilities.autopatcher.pipeline.generate_patch",
                       return_value="```diff\n--- a/f.py\n+++ b/f.py\n```") as mock_gen,
            mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok"),
            mock.patch("utilities.autopatcher.pipeline.challenge_patch", return_value={}),
            mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="score: 7"),
            mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
            mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
            mock.patch("utilities.autopatcher.patch_applicability.check_applicability",
                       return_value={"applicable": True, "skipped": False, "stderr": "",
                                     "exit_code": 0, "skipped_reason": None, "error": None}),
        ):
            from utilities.autopatcher.pipeline import run
            run(vuln_text, api_key="", repo_root=str(tmp_path))

        return mock_llm, mock_gen

    def test_exactly_two_planner_llm_calls_no_third(self, tmp_path):
        mock_llm, _mock_gen = self._run(tmp_path, _DISCOVERY_JSON, _STRATEGY_JSON)

        stages = [kwargs.get("stage") for _args, kwargs in mock_llm.complete.call_args_list]
        assert stages.count("remediation_planning") == 1
        assert stages.count("remediation_strategy") == 1
        assert len(stages) == 2

    def test_final_strategy_reaches_code_context_after_planner_evidence(self, tmp_path):
        _mock_llm, mock_gen = self._run(tmp_path, _DISCOVERY_JSON, _STRATEGY_JSON)

        code_context = mock_gen.call_args.kwargs.get("code_context", "")
        assert "Target Discovery Plan" in code_context
        assert "Planner-Proposed Candidate Evidence" in code_context
        assert "Final Evidence-Backed Remediation Strategy" in code_context
        assert (
            code_context.index("Target Discovery Plan")
            < code_context.index("Planner-Proposed Candidate Evidence")
            < code_context.index("Final Evidence-Backed Remediation Strategy")
        )

    def test_only_slice_and_coverage_warning_may_follow_final_strategy_heading(self, tmp_path):
        # Superseded by the Final-Target Remediation Slice feature: the
        # Slice (and, when incomplete, its coverage warning) is now
        # explicitly REQUIRED to render after Final Strategy -- so "no
        # heading follows" is no longer the invariant. What must still
        # hold: no OTHER, unrelated heading (e.g. a repeat of an earlier
        # section) ever appears after it.
        _mock_llm, mock_gen = self._run(tmp_path, _DISCOVERY_JSON, _STRATEGY_JSON)

        code_context = mock_gen.call_args.kwargs.get("code_context", "")
        strategy_idx = code_context.index("## Final Evidence-Backed Remediation Strategy")
        allowed = ("## Final-Target Remediation Slice", "## Final-target source coverage warning")
        # Level-2 headings only ("## ", not "### "/"#### ") at the start of
        # a line -- a "#### Target definition" sub-block inside the Slice
        # section is not itself a top-level section and must not count.
        later_headings = [
            m.group(0) + code_context[m.end():m.end() + 60]
            for m in re.finditer(r"(?:^|\n)(## [^\n]*)", code_context)
            if m.start() > strategy_idx
        ]
        for heading_text in later_headings:
            assert any(a in heading_text for a in allowed), heading_text


class TestExtendExistingMechanismFixture:
    """Synthetic fixture proving the harness can represent and preserve a
    correct 'extend the existing policy' answer end to end -- verified
    source contains an existing policy constant AND a consumer that already
    enforces it; a mocked Final Strategy response selecting extension of
    that constant survives verification and renders distinctly from a
    'new parallel logic' framing. Does not require a live LLM."""

    def test_extension_of_existing_constant_is_preserved(self, tmp_path):
        from utilities.autopatcher.remediation_planner import (
            RemediationPlanResult, build_planner_evidence, generate_remediation_strategy,
        )

        retry_py = tmp_path / "retry.py"
        retry_py.write_text(
            "class Retry:\n"
            "    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset([\"Authorization\"])\n",
            encoding="utf-8",
        )
        pool_py = tmp_path / "poolmanager.py"
        pool_py.write_text(
            "class PoolManager:\n"
            "    def urlopen(self, method, url, redirect=True, **kw):\n"
            "        # already consults DEFAULT_REMOVE_HEADERS_ON_REDIRECT\n"
            "        pass\n",
            encoding="utf-8",
        )
        context = _make_context(
            functions={
                "poolmanager.py:PoolManager.urlopen": {
                    "name": "urlopen", "startLine": 2, "endLine": 4, "className": "PoolManager",
                },
            },
            constants={
                "retry.py": {
                    "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT": {
                        "qualified_name": "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                        "class_name": "Retry", "name": "DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                        "line": 2, "end_line": 2,
                    },
                },
            },
            repo_path=tmp_path,
        )

        discovery = RemediationPlanResult(
            rendered="", target_files=["retry.py", "poolmanager.py"],
            target_symbols=["retry.py:Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT", "poolmanager.py:PoolManager.urlopen"],
        )
        planner_evidence_ctx = build_planner_evidence(discovery, str(tmp_path), "Cookie leaked on redirect", context)
        assert planner_evidence_ctx  # sanity: real verified evidence exists

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps({
            "extended_mechanism": "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
            "target_files": ["retry.py"],
            "target_symbols": ["retry.py:Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT"],
            "required_edits": ["Add 'Cookie' to the existing DEFAULT_REMOVE_HEADERS_ON_REDIRECT frozenset."],
            "rejected_targets": ["poolmanager.py:PoolManager.urlopen — consumer already enforces the policy; no new logic needed there."],
            "security_invariant": "Sensitive request headers must not cross origins on redirect.",
            "insufficient_evidence": [],
        })

        result = generate_remediation_strategy(
            "Cookie leaked on redirect", llm, str(tmp_path), context,
            planner_evidence_ctx=planner_evidence_ctx,
        )

        assert result.target_files == ["retry.py"]
        assert result.target_symbols == ["retry.py:Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT"]
        assert result.warnings == []
        assert "Extended mechanism:** Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in result.rendered
        assert "Rejected discovery targets" in result.rendered
        assert "no new logic needed" in result.rendered


# ---------------------------------------------------------------------------
# Final-Target Remediation Slice
# ---------------------------------------------------------------------------

def _make_strategy(
    target_files=None, target_symbols=None, extended_mechanism=None, required_edits=None,
):
    from utilities.autopatcher.remediation_planner import RemediationStrategyResult
    return RemediationStrategyResult(
        rendered="", target_files=target_files or [], target_symbols=target_symbols or [],
        warnings=[], extended_mechanism=extended_mechanism, required_edits=required_edits or [],
    )


def _make_slice_result(**overrides):
    """A hand-built FinalTargetSliceResult with every field defaulted to
    "nothing covered yet" -- shared by Slice 1 and Slice 2 tests that need
    to simulate a specific initial state (rather than build one for real
    via build_final_target_slice)."""
    from utilities.autopatcher.remediation_planner import FinalTargetSliceResult
    base = dict(
        rendered="", covered_target_files=[], covered_target_symbols=[],
        uncovered_target_files=[], uncovered_target_symbols=[],
        coverage_complete=False, has_any_coverage=False, warning_text="",
        resolved_target_symbols=[], full_file_fallback_covered=[],
        edit_target_budget_exhausted=False,
        resolved_symbol_files={}, identifier_definition_covered=[],
    )
    base.update(overrides)
    return FinalTargetSliceResult(**base)


class TestSliceGatingAndNoNewLLM:
    def test_slice_construction_has_no_llm_parameter(self):
        import inspect
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        assert "llm" not in inspect.signature(build_final_target_slice).parameters

    def test_empty_strategy_produces_empty_slice_without_calling_anything(self, tmp_path):
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        strategy = _make_strategy()
        result = build_final_target_slice(strategy, str(tmp_path), None)
        assert result.rendered == ""
        assert result.coverage_complete is True
        assert result.has_any_coverage is False

    def test_no_repo_root_degrades_safely(self):
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        strategy = _make_strategy(target_files=["a.py"])
        result = build_final_target_slice(strategy, None, None)
        assert result.rendered == "" or "failed" in result.rendered.lower()

    def test_reuses_existing_investigation_context_no_rebuild(self, tmp_path, monkeypatch):
        (tmp_path / "a.py").write_text("class A:\n    X = 1\n", encoding="utf-8")
        context = _make_context(
            constants={"a.py": {"A.X": {"qualified_name": "A.X", "name": "X", "line": 2, "end_line": 2}}},
            repo_path=tmp_path,
        )

        def _fail_if_called(*a, **kw):
            raise AssertionError("build_investigation_context must not be called by the slice builder")

        monkeypatch.setattr(
            "utilities.autopatcher.candidate_enrichment.build_investigation_context", _fail_if_called
        )

        from utilities.autopatcher.remediation_planner import build_final_target_slice
        strategy = _make_strategy(target_files=["a.py"], target_symbols=["a.py:A.X"])
        build_final_target_slice(strategy, str(tmp_path), context)
        # no exception -- build_investigation_context was never reached

    def test_no_parser_reimport_triggered(self, tmp_path, monkeypatch):
        (tmp_path / "a.py").write_text("class A:\n    X = 1\n", encoding="utf-8")
        context = _make_context(
            constants={"a.py": {"A.X": {"qualified_name": "A.X", "name": "X", "line": 2, "end_line": 2}}},
            repo_path=tmp_path,
        )

        def _fail_if_called(*a, **kw):
            raise AssertionError("parse_repository must not be called by the slice builder")

        monkeypatch.setattr("utilities.autopatcher.candidate_enrichment.parse_repository", _fail_if_called)

        from utilities.autopatcher.remediation_planner import build_final_target_slice
        strategy = _make_strategy(target_files=["a.py"], target_symbols=["a.py:A.X"])
        build_final_target_slice(strategy, str(tmp_path), context)


class TestPaddedLineRange:
    """Unit tests for _padded_line_range / _rendered_end_line in isolation
    -- the pure arithmetic behind the patch-ready source window."""

    def test_pads_both_sides_symmetrically(self):
        from utilities.autopatcher.remediation_planner import _padded_line_range
        assert _padded_line_range(10, 10, 3) == (7, 13)

    def test_pads_a_multi_line_span(self):
        from utilities.autopatcher.remediation_planner import _padded_line_range
        assert _padded_line_range(10, 12, 3) == (7, 15)

    def test_clamps_start_to_1_never_negative_or_zero(self):
        from utilities.autopatcher.remediation_planner import _padded_line_range
        assert _padded_line_range(2, 2, 3) == (1, 5)
        assert _padded_line_range(1, 1, 3) == (1, 4)

    def test_zero_or_negative_pad_is_a_strict_noop(self):
        from utilities.autopatcher.remediation_planner import _padded_line_range
        assert _padded_line_range(10, 12, 0) == (10, 12)
        assert _padded_line_range(10, 12, -1) == (10, 12)

    def test_rendered_end_line_reflects_actual_source_not_the_request(self):
        """The header-accuracy guarantee: read_file_section may silently
        clamp past EOF, returning fewer lines than requested -- the header
        must claim only what was actually returned."""
        from utilities.autopatcher.remediation_planner import _rendered_end_line
        assert _rendered_end_line(1, "a\nb\nc\n") == 3
        assert _rendered_end_line(5, "only one line\n") == 5
        assert _rendered_end_line(5, "") == 5

    def test_rendered_end_line_matches_unclamped_request_when_within_bounds(self):
        from utilities.autopatcher.remediation_planner import _padded_line_range, _rendered_end_line
        start, end = _padded_line_range(10, 10, 3)
        source = "\n".join(f"line{i}" for i in range(start, end + 1)) + "\n"
        assert _rendered_end_line(start, source) == end


class TestExactConstantDefinition:
    def test_preserves_repository_text_and_capitalization_exactly(self, tmp_path):
        (tmp_path / "policy.py").write_text(
            "class Policy:\n    ALLOWED_VALUES = frozenset([\"ExistingValue\"])\n", encoding="utf-8",
        )
        context = _make_context(
            constants={"policy.py": {
                "Policy.ALLOWED_VALUES": {
                    "qualified_name": "Policy.ALLOWED_VALUES", "class_name": "Policy",
                    "name": "ALLOWED_VALUES", "line": 2, "end_line": 2,
                },
            }},
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        strategy = _make_strategy(target_files=["policy.py"], target_symbols=["policy.py:Policy.ALLOWED_VALUES"])

        result = build_final_target_slice(strategy, str(tmp_path), context)

        assert 'ALLOWED_VALUES = frozenset(["ExistingValue"])' in result.rendered
        # Patch-ready source window (see _DEFINITION_CONTEXT_LINES): the
        # constant's own span is line 2-2, padded by 3 lines each side to
        # 1-5 (max(1, 2-3)=1) -- clamped down to 1-2 here because the
        # fixture file only HAS 2 lines. The header must reflect what was
        # actually shown (see _rendered_end_line), not the unclamped request.
        assert "Target definition: `policy.py:Policy.ALLOWED_VALUES` (lines 1–2)" in result.rendered
        assert "policy.py:Policy.ALLOWED_VALUES" in result.covered_target_symbols

    def test_padded_with_real_surrounding_lines_when_file_is_large_enough(self, tmp_path):
        """The case this feature exists for: a short constant in a file
        with real, distinct neighbors on both sides must render WITH those
        neighbors -- not just the bare defining line -- so Patch Generation
        has exact repository text to anchor a unified diff hunk to."""
        lines = [f"# filler line {i}\n" for i in range(1, 10)]
        lines[4] = "class Policy:\n"  # line 5
        lines[5] = '    ALLOWED_VALUES = frozenset(["ExistingValue"])\n'  # line 6
        (tmp_path / "policy.py").write_text("".join(lines), encoding="utf-8")
        context = _make_context(
            constants={"policy.py": {
                "Policy.ALLOWED_VALUES": {
                    "qualified_name": "Policy.ALLOWED_VALUES", "class_name": "Policy",
                    "name": "ALLOWED_VALUES", "line": 6, "end_line": 6,
                },
            }},
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        strategy = _make_strategy(target_files=["policy.py"], target_symbols=["policy.py:Policy.ALLOWED_VALUES"])

        result = build_final_target_slice(strategy, str(tmp_path), context)

        # 3 lines before (3-5) and 3 after (7-9) are real, distinct repository
        # text -- not the bare 1-line span, and not invented.
        assert "Target definition: `policy.py:Policy.ALLOWED_VALUES` (lines 3–9)" in result.rendered
        assert "# filler line 3" in result.rendered
        assert "# filler line 9" in result.rendered
        assert 'ALLOWED_VALUES = frozenset(["ExistingValue"])' in result.rendered


class TestStrategyIdentifierExtraction:
    def test_dotted_snake_and_verified_identifiers_retained(self):
        from utilities.autopatcher.remediation_planner import _extract_identifiers_from_text
        text = "Extend Policy.ALLOWED_VALUES by adding to remove_sensitive_values."
        found = _extract_identifiers_from_text(text)
        assert "Policy.ALLOWED_VALUES" in found
        assert "remove_sensitive_values" in found

    def test_common_english_words_not_extracted(self):
        from utilities.autopatcher.remediation_planner import _extract_identifiers_from_text
        text = "Extend the existing policy instead of creating a new parallel mechanism."
        found = _extract_identifiers_from_text(text)
        assert found == []

    def test_camelcase_requires_at_least_two_humps(self):
        from utilities.autopatcher.remediation_planner import _extract_identifiers_from_text
        assert "PoolManager" in _extract_identifiers_from_text("See PoolManager for details.")
        # A single-hump capitalized word (sentence-initial or a bare class
        # name) is deliberately not treated as CamelCase on its own.
        assert "Retry" not in _extract_identifiers_from_text("Retry handles this case.")

    def test_verified_symbols_extracted_via_strategy_object(self):
        from utilities.autopatcher.remediation_planner import _extract_strategy_identifiers
        strategy = _make_strategy(target_symbols=["retry.py:Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT"])
        found = _extract_strategy_identifiers(strategy)
        assert "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in found
        assert "DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in found
        assert "Retry" in found  # class qualifier of a VERIFIED symbol is trusted, unlike bare prose

    def test_substring_of_dotted_identifier_not_duplicated(self):
        from utilities.autopatcher.remediation_planner import _extract_identifiers_from_text
        found = _extract_identifiers_from_text("Policy.ALLOWED_VALUES is the mechanism.")
        assert found.count("ALLOWED_VALUES") == 0  # only the dotted form is kept
        assert found.count("Policy.ALLOWED_VALUES") == 1

    def test_order_preserving_deduplication(self):
        from utilities.autopatcher.remediation_planner import _extract_strategy_identifiers
        strategy = _make_strategy(
            extended_mechanism="Policy.ALLOWED_VALUES",
            required_edits=["Extend Policy.ALLOWED_VALUES again."],
        )
        found = _extract_strategy_identifiers(strategy)
        assert found.count("Policy.ALLOWED_VALUES") == 1


class TestClassOnlyTargetDiscovery:
    def _context_with_policy_and_consumer(self, tmp_path):
        (tmp_path / "policy.py").write_text(
            "class Policy:\n    ALLOWED_VALUES = frozenset([\"a\"])\n", encoding="utf-8",
        )
        (tmp_path / "consumer.py").write_text(
            "class Consumer:\n"
            "    def validate(self, value):\n"
            "        if value not in Policy.ALLOWED_VALUES:\n"
            "            raise ValueError(value)\n"
            "        return True\n",
            encoding="utf-8",
        )
        context = _make_context(
            functions={
                "consumer.py:Consumer.validate": {
                    "name": "validate", "className": "Consumer", "startLine": 2, "endLine": 5,
                    "code": (
                        "    def validate(self, value):\n"
                        "        if value not in Policy.ALLOWED_VALUES:\n"
                        "            raise ValueError(value)\n"
                        "        return True\n"
                    ),
                },
            },
            constants={"policy.py": {
                "Policy.ALLOWED_VALUES": {
                    "qualified_name": "Policy.ALLOWED_VALUES", "class_name": "Policy",
                    "name": "ALLOWED_VALUES", "line": 2, "end_line": 2,
                },
            }},
            repo_path=tmp_path,
        )
        return context

    def test_class_only_target_does_not_trigger_immediate_full_file_fallback(self, tmp_path):
        context = self._context_with_policy_and_consumer(tmp_path)
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        strategy = _make_strategy(
            target_files=["policy.py"], target_symbols=[],
            extended_mechanism="Policy.ALLOWED_VALUES",
        )

        result = build_final_target_slice(
            strategy, str(tmp_path), context, planner_evidence_files=["consumer.py"],
        )

        assert "Full file (last resort)" not in result.rendered
        assert 'ALLOWED_VALUES = frozenset(["a"])' in result.rendered

    def test_class_only_target_discovers_relevant_constant_from_strategy_text(self, tmp_path):
        context = self._context_with_policy_and_consumer(tmp_path)
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        strategy = _make_strategy(
            target_files=["policy.py"], target_symbols=[],
            extended_mechanism="Policy.ALLOWED_VALUES",
            required_edits=["Add 'b' to Policy.ALLOWED_VALUES."],
        )

        result = build_final_target_slice(strategy, str(tmp_path), context)

        assert "policy.py" in result.covered_target_files
        assert "Target definition: `policy.py:Policy.ALLOWED_VALUES`" in result.rendered


class TestDefinitionAndUsageLookupVerification:
    def test_search_definitions_results_restricted_to_preferred_files(self, tmp_path):
        (tmp_path / "a.py").write_text("class A:\n    def m(self):\n        pass\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("class B:\n    def m(self):\n        pass\n", encoding="utf-8")
        context = _make_context(functions={
            "a.py:A.m": {"name": "m", "className": "A", "startLine": 2, "endLine": 3,
                         "code": "    def m(self):\n        pass\n"},
            "b.py:B.m": {"name": "m", "className": "B", "startLine": 2, "endLine": 3,
                         "code": "    def m(self):\n        pass\n"},
        }, repo_path=tmp_path)

        from utilities.autopatcher.remediation_planner import _lookup_identifier_definition
        found = _lookup_identifier_definition("m", ["b.py"], context)
        assert found is not None
        assert found.file == "b.py"  # never a.py -- not in preferred_files

    def test_search_usages_results_restricted_to_preferred_files(self, tmp_path):
        (tmp_path / "a.py").write_text("pass\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("pass\n", encoding="utf-8")
        context = _make_context(functions={
            "a.py:unrelated": {"name": "unrelated", "startLine": 1, "endLine": 1,
                                "code": "target_marker_value\n"},
            "b.py:consumer": {"name": "consumer", "startLine": 1, "endLine": 1,
                               "code": "target_marker_value\n"},
        }, repo_path=tmp_path)

        from utilities.autopatcher.remediation_planner import _lookup_identifier_usages
        found = _lookup_identifier_usages("target_marker_value", ["b.py"], context)
        assert [f for (f, *_rest) in found] == ["b.py"]

    def test_final_target_files_preferred_over_unrelated_matches(self, tmp_path):
        (tmp_path / "target.py").write_text("class T:\n    X = 1\n", encoding="utf-8")
        (tmp_path / "unrelated.py").write_text("class U:\n    X = 1\n", encoding="utf-8")
        context = _make_context(
            constants={
                "unrelated.py": {"U.X": {"qualified_name": "U.X", "name": "X", "line": 2, "end_line": 2}},
            },
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import _lookup_identifier_definition
        # "X" only exists in unrelated.py's constants table -- restricting
        # preferred_files to target.py alone must find nothing, proving no
        # whole-repository scan happens.
        found = _lookup_identifier_definition("X", ["target.py"], context)
        assert found is None


class TestFocusedWindows:
    def test_windows_include_exact_line_numbers(self, tmp_path):
        (tmp_path / "consumer.py").write_text(
            "class C:\n    def m(self):\n        marker_term\n        return 1\n", encoding="utf-8",
        )
        context = _make_context(functions={
            "consumer.py:C.m": {
                "name": "m", "className": "C", "startLine": 2, "endLine": 4,
                "code": "    def m(self):\n        marker_term\n        return 1\n",
            },
        }, repo_path=tmp_path)
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        strategy = _make_strategy(target_files=["consumer.py"], extended_mechanism="marker_term")

        result = build_final_target_slice(strategy, str(tmp_path), context, planner_evidence_files=["consumer.py"])
        assert "lines 2–4" in result.rendered or "lines 2\u20134" in result.rendered

    def test_windows_stay_inside_function_boundaries(self, tmp_path):
        big_body = "\n".join(f"        line_{i} = {i}" for i in range(60))
        (tmp_path / "consumer.py").write_text(
            f"class C:\n    def m(self):\n{big_body}\n        marker_term\n" + "\n".join(
                f"        after_{i} = {i}" for i in range(60)
            ) + "\n",
            encoding="utf-8",
        )
        code = (
            "    def m(self):\n" + big_body + "\n        marker_term\n"
            + "\n".join(f"        after_{i} = {i}" for i in range(60)) + "\n"
        )
        fn_start, fn_end = 2, 2 + len(code.split("\n")) - 1
        context = _make_context(functions={
            "consumer.py:C.m": {"name": "m", "className": "C", "startLine": fn_start, "endLine": fn_end, "code": code},
        }, repo_path=tmp_path)
        from utilities.autopatcher.remediation_planner import _lookup_identifier_usages, _merge_line_windows

        usages = _lookup_identifier_usages("marker_term", ["consumer.py"], context)
        assert len(usages) == 1
        _f, _label, u_fn_start, u_fn_end, offsets = usages[0]
        window = [
            (max(u_fn_start, u_fn_start + off - 15), min(u_fn_end, u_fn_start + off + 15))
            for off in offsets
        ]
        merged = _merge_line_windows(window)
        for start, end in merged:
            assert start >= u_fn_start
            assert end <= u_fn_end

    def test_overlapping_windows_merge_deterministically(self):
        from utilities.autopatcher.remediation_planner import _merge_line_windows
        merged = _merge_line_windows([(10, 20), (15, 25), (100, 110)])
        assert merged == [(10, 25), (100, 110)]

    def test_non_contiguous_windows_clearly_separated(self, tmp_path):
        (tmp_path / "consumer.py").write_text("x = 1\n" * 200, encoding="utf-8")
        context = _make_context(repo_path=tmp_path)
        from utilities.autopatcher.remediation_planner import _render_usage_window_block
        block = _render_usage_window_block("consumer.py", "C.m", [(1, 3), (50, 52)], context)
        assert "line(s) omitted" in block


class TestCategoryPriorityAndOrdering:
    def _context(self, tmp_path):
        (tmp_path / "policy.py").write_text(
            "class Policy:\n    ALLOWED_VALUES = frozenset([\"a\"])\n", encoding="utf-8",
        )
        return _make_context(
            constants={"policy.py": {
                "Policy.ALLOWED_VALUES": {
                    "qualified_name": "Policy.ALLOWED_VALUES", "class_name": "Policy",
                    "name": "ALLOWED_VALUES", "line": 2, "end_line": 2,
                },
            }},
            repo_path=tmp_path,
        )

    def test_definition_precedes_consumer_in_rendered_output(self, tmp_path):
        (tmp_path / "consumer.py").write_text(
            "class C:\n    def m(self):\n        Policy.ALLOWED_VALUES\n        return 1\n",
            encoding="utf-8",
        )
        context = self._context(tmp_path)
        # rebuild context including the consumer function too
        context = _make_context(
            functions={"consumer.py:C.m": {
                "name": "m", "className": "C", "startLine": 2, "endLine": 4,
                "code": "    def m(self):\n        Policy.ALLOWED_VALUES\n        return 1\n",
            }},
            constants={"policy.py": {
                "Policy.ALLOWED_VALUES": {
                    "qualified_name": "Policy.ALLOWED_VALUES", "class_name": "Policy",
                    "name": "ALLOWED_VALUES", "line": 2, "end_line": 2,
                },
            }},
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        strategy = _make_strategy(
            target_files=["policy.py"], target_symbols=["policy.py:Policy.ALLOWED_VALUES"],
        )
        result = build_final_target_slice(strategy, str(tmp_path), context, planner_evidence_files=["consumer.py"])
        assert result.rendered.index("Target definition") < result.rendered.index("Discovered consumer")

    def test_exact_definitions_never_displaced_by_budget(self, tmp_path, monkeypatch):
        from utilities.autopatcher import remediation_planner as rp
        monkeypatch.setattr(rp, "FINAL_TARGET_SLICE_MAX_CHARS", 60)  # smaller than even one definition block
        (tmp_path / "policy.py").write_text(
            "class Policy:\n    ALLOWED_VALUES = frozenset([\"a\"])\n", encoding="utf-8",
        )
        context = self._context(tmp_path)
        strategy = _make_strategy(target_files=["policy.py"], target_symbols=["policy.py:Policy.ALLOWED_VALUES"])
        result = rp.build_final_target_slice(strategy, str(tmp_path), context)
        # With a tiny budget the definition itself may not fit either --
        # what matters is that nothing LOWER priority ever appears instead.
        assert "Full file (last resort)" not in result.rendered

    def test_full_file_used_only_when_nothing_focused_available(self, tmp_path):
        (tmp_path / "opaque.py").write_text("x = 1\ny = 2\nz = 3\n", encoding="utf-8")
        context = _make_context(repo_path=tmp_path)
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        strategy = _make_strategy(target_files=["opaque.py"], extended_mechanism="NothingMatches.Here")
        result = build_final_target_slice(strategy, str(tmp_path), context)
        assert "Full file (last resort): `opaque.py`" in result.rendered


class TestBudgetBoundedness:
    def test_budget_is_bounded(self, tmp_path, monkeypatch):
        from utilities.autopatcher import remediation_planner as rp
        big_body = "\n".join(f"    x{i} = {i}" for i in range(2000))
        (tmp_path / "big.py").write_text(f"class C:\n{big_body}\n", encoding="utf-8")
        context = _make_context(repo_path=tmp_path)
        strategy = _make_strategy(target_files=["big.py"])
        result = rp.build_final_target_slice(strategy, str(tmp_path), context)
        assert len(result.rendered) <= rp.FINAL_TARGET_SLICE_MAX_CHARS

    def test_no_block_truncated_mid_line(self, tmp_path, monkeypatch):
        from utilities.autopatcher import remediation_planner as rp
        monkeypatch.setattr(rp, "FINAL_TARGET_SLICE_MAX_CHARS", 100)
        (tmp_path / "policy.py").write_text(
            "class Policy:\n    ALLOWED_VALUES = frozenset([\"a\"])\n", encoding="utf-8",
        )
        context = _make_context(
            constants={"policy.py": {
                "Policy.ALLOWED_VALUES": {
                    "qualified_name": "Policy.ALLOWED_VALUES", "class_name": "Policy",
                    "name": "ALLOWED_VALUES", "line": 2, "end_line": 2,
                },
            }},
            repo_path=tmp_path,
        )
        strategy = _make_strategy(target_files=["policy.py"], target_symbols=["policy.py:Policy.ALLOWED_VALUES"])
        result = rp.build_final_target_slice(strategy, str(tmp_path), context)
        if result.rendered:
            assert result.rendered.rstrip("\n").endswith("```")  # never cut off mid code-fence/line

    def test_duplicate_definitions_render_once(self, tmp_path):
        (tmp_path / "policy.py").write_text(
            "class Policy:\n    ALLOWED_VALUES = frozenset([\"a\"])\n", encoding="utf-8",
        )
        context = _make_context(
            constants={"policy.py": {
                "Policy.ALLOWED_VALUES": {
                    "qualified_name": "Policy.ALLOWED_VALUES", "class_name": "Policy",
                    "name": "ALLOWED_VALUES", "line": 2, "end_line": 2,
                },
            }},
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        # Same constant proposed twice, once directly and once discoverable
        # via extended_mechanism -- must render exactly once.
        strategy = _make_strategy(
            target_files=["policy.py"], target_symbols=["policy.py:Policy.ALLOWED_VALUES"],
            extended_mechanism="Policy.ALLOWED_VALUES",
        )
        result = build_final_target_slice(strategy, str(tmp_path), context)
        assert result.rendered.count("Target definition") == 1


class TestDeterministicFinalTargetOrder:
    def test_target_order_matches_strategy_order(self, tmp_path):
        (tmp_path / "b.py").write_text("class B:\n    Y = 2\n", encoding="utf-8")
        (tmp_path / "a.py").write_text("class A:\n    X = 1\n", encoding="utf-8")
        context = _make_context(
            constants={
                "b.py": {"B.Y": {"qualified_name": "B.Y", "name": "Y", "line": 2, "end_line": 2}},
                "a.py": {"A.X": {"qualified_name": "A.X", "name": "X", "line": 2, "end_line": 2}},
            },
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        strategy = _make_strategy(target_files=["b.py", "a.py"], target_symbols=["b.py:B.Y", "a.py:A.X"])
        result = build_final_target_slice(strategy, str(tmp_path), context)
        assert result.rendered.index("b.py:B.Y") < result.rendered.index("a.py:A.X")


class TestCoverageReporting:
    def test_complete_coverage_reported_correctly(self, tmp_path):
        (tmp_path / "policy.py").write_text(
            "class Policy:\n    ALLOWED_VALUES = frozenset([\"a\"])\n", encoding="utf-8",
        )
        context = _make_context(
            constants={"policy.py": {
                "Policy.ALLOWED_VALUES": {
                    "qualified_name": "Policy.ALLOWED_VALUES", "class_name": "Policy",
                    "name": "ALLOWED_VALUES", "line": 2, "end_line": 2,
                },
            }},
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        strategy = _make_strategy(target_files=["policy.py"], target_symbols=["policy.py:Policy.ALLOWED_VALUES"])
        result = build_final_target_slice(strategy, str(tmp_path), context)
        assert result.coverage_complete is True
        assert result.uncovered_target_files == []
        assert result.uncovered_target_symbols == []
        assert result.warning_text == ""

    def test_partial_coverage_reported_correctly(self, tmp_path):
        (tmp_path / "policy.py").write_text(
            "class Policy:\n    ALLOWED_VALUES = frozenset([\"a\"])\n", encoding="utf-8",
        )
        from utilities.autopatcher.remediation_planner import build_final_target_slice, FINAL_TARGET_SLICE_MAX_CHARS
        # Large enough that its full-file fallback cannot fit the
        # remaining budget after the (tiny) policy.py definition -- a
        # small opaque file would otherwise trivially get "covered" via
        # full-file fallback, which is not what this test is checking.
        (tmp_path / "opaque.py").write_text("x = 1\n" * (FINAL_TARGET_SLICE_MAX_CHARS // 3), encoding="utf-8")
        context = _make_context(
            constants={"policy.py": {
                "Policy.ALLOWED_VALUES": {
                    "qualified_name": "Policy.ALLOWED_VALUES", "class_name": "Policy",
                    "name": "ALLOWED_VALUES", "line": 2, "end_line": 2,
                },
            }},
            repo_path=tmp_path,
        )
        strategy = _make_strategy(
            target_files=["policy.py", "opaque.py"], target_symbols=["policy.py:Policy.ALLOWED_VALUES"],
        )
        result = build_final_target_slice(strategy, str(tmp_path), context)
        assert result.coverage_complete is False
        assert "opaque.py" in result.uncovered_target_files
        assert result.has_any_coverage is True
        assert "coverage warning" in result.warning_text.lower()
        assert "Uncovered" in result.warning_text

    def test_zero_coverage_prevents_first_patch_generator_call(self, tmp_path):
        from unittest import mock as _mock
        plan_result = _make_strategy  # not used directly; construct via helper below

        strategy = _make_strategy(target_files=["missing.py"], target_symbols=["missing.py:Missing.thing"])
        context = _make_context(repo_path=tmp_path)  # nothing resolves; file doesn't even exist on disk
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        result = build_final_target_slice(strategy, str(tmp_path), context)
        assert result.has_any_coverage is False
        assert result.rendered == ""

    def test_partial_coverage_continues_with_explicit_warning_not_silence(self, tmp_path):
        (tmp_path / "policy.py").write_text(
            "class Policy:\n    ALLOWED_VALUES = frozenset([\"a\"])\n", encoding="utf-8",
        )
        context = _make_context(
            constants={"policy.py": {
                "Policy.ALLOWED_VALUES": {
                    "qualified_name": "Policy.ALLOWED_VALUES", "class_name": "Policy",
                    "name": "ALLOWED_VALUES", "line": 2, "end_line": 2,
                },
            }},
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        strategy = _make_strategy(
            target_files=["policy.py", "opaque_missing.py"], target_symbols=["policy.py:Policy.ALLOWED_VALUES"],
        )
        result = build_final_target_slice(strategy, str(tmp_path), context)
        assert result.warning_text  # non-empty, explicit
        assert result.rendered  # slice still renders what WAS found


class TestSliceFailureSafety:
    def test_construction_failure_degrades_safely(self, tmp_path, monkeypatch):
        from utilities.autopatcher import remediation_planner as rp

        def _boom(*a, **kw):
            raise RuntimeError("boom")

        monkeypatch.setattr(rp, "_build_final_target_slice_inner", _boom)
        strategy = _make_strategy(target_files=["a.py"], target_symbols=["a.py:A.x"])
        result = rp.build_final_target_slice(strategy, str(tmp_path), None)
        assert result.coverage_complete is False
        assert result.has_any_coverage is False
        assert "failed" in result.rendered.lower()
        assert result.warning_text


class TestExistingSectionsUnaffected:
    def test_planner_evidence_unchanged_shape(self, tmp_path):
        # build_planner_evidence's own contract (heading, disclaimer,
        # structural+source shape) is untouched by this feature -- smoke
        # check that it still behaves exactly as its own dedicated tests
        # already prove.
        (tmp_path / "retry.py").write_text("class Retry:\n    pass\n", encoding="utf-8")
        from utilities.autopatcher.remediation_planner import build_planner_evidence
        plan = RemediationPlanResult(rendered="", target_files=["retry.py"], target_symbols=[])
        result = build_planner_evidence(plan, str(tmp_path), "vuln", None)
        assert result.startswith("## Planner-Proposed Candidate Evidence")

    def test_final_strategy_rendering_unchanged_shape(self):
        from utilities.autopatcher.remediation_planner import generate_remediation_strategy
        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps(_STRATEGY_WELL_FORMED)
        result = generate_remediation_strategy(
            "vuln", llm, None, None, planner_evidence_ctx="EVIDENCE",
        )
        assert result.rendered.startswith("## Final Evidence-Backed Remediation Strategy")


class TestPipelineContextOrderingWithSlice:
    def test_slice_and_coverage_warning_ordered_after_strategy(self, tmp_path):
        target = tmp_path / "policy.py"
        target.write_text("class Policy:\n    ALLOWED_VALUES = frozenset(['a'])\n", encoding="utf-8")

        def side_effect(system_prompt, user_message, stage="unknown"):
            if stage == "remediation_planning":
                return json.dumps({
                    "remediation_mechanism": "extend policy", "target_files": ["policy.py"],
                    "target_symbols": [], "security_invariant": "stub", "required_edits": [],
                    "approaches_to_avoid": [], "explicit_unknowns": [],
                })
            if stage == "remediation_strategy":
                return json.dumps({
                    "extended_mechanism": "Policy.ALLOWED_VALUES",
                    "target_files": ["policy.py", "missing_target.py"],
                    "target_symbols": ["policy.py:Policy.ALLOWED_VALUES"],
                    "required_edits": ["stub edit"], "rejected_targets": [],
                    "security_invariant": "stub", "insufficient_evidence": [],
                })
            return "{}"

        mock_llm = mock.MagicMock()
        mock_llm.complete.side_effect = side_effect

        with (
            mock.patch("utilities.autopatcher.pipeline.LLMClient", return_value=mock_llm),
            mock.patch("utilities.autopatcher.pipeline.generate_patch",
                       return_value="```diff\n--- a/f.py\n+++ b/f.py\n```") as mock_gen,
            mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok"),
            mock.patch("utilities.autopatcher.pipeline.challenge_patch", return_value={}),
            mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="score: 7"),
            mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
            mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
            mock.patch("utilities.autopatcher.patch_applicability.check_applicability",
                       return_value={"applicable": True, "skipped": False, "stderr": "",
                                     "exit_code": 0, "skipped_reason": None, "error": None}),
        ):
            from utilities.autopatcher.pipeline import run
            run("some vulnerability", api_key="", repo_root=str(tmp_path))

        code_context = mock_gen.call_args.kwargs.get("code_context", "")
        assert "Final Evidence-Backed Remediation Strategy" in code_context
        assert "Final-Target Remediation Slice" in code_context
        strategy_idx = code_context.index("Final Evidence-Backed Remediation Strategy")
        slice_idx = code_context.index("Final-Target Remediation Slice")
        assert strategy_idx < slice_idx
        if "coverage warning" in code_context.lower():
            warning_idx = code_context.lower().index("coverage warning")
            assert slice_idx < warning_idx

    def test_zero_coverage_skips_patch_generator_call_in_full_pipeline(self, tmp_path):
        # Exercises pipeline.py's OWN wiring decision (react correctly to
        # has_any_coverage=False) directly, rather than fighting the full
        # real Grounding/Planner/Final-Strategy verification chain just to
        # engineer a zero-coverage outcome deep inside it -- that
        # algorithm-level behavior is already covered by
        # TestCoverageReporting above.
        target = tmp_path / "policy.py"
        target.write_text("class Policy:\n    ALLOWED_VALUES = frozenset(['a'])\n", encoding="utf-8")

        def side_effect(system_prompt, user_message, stage="unknown"):
            if stage == "remediation_planning":
                return json.dumps({
                    "remediation_mechanism": "extend policy", "target_files": ["policy.py"],
                    "target_symbols": [], "security_invariant": "stub", "required_edits": [],
                    "approaches_to_avoid": [], "explicit_unknowns": [],
                })
            if stage == "remediation_strategy":
                return json.dumps({
                    "extended_mechanism": "Policy.ALLOWED_VALUES", "target_files": ["policy.py"],
                    "target_symbols": ["policy.py:Policy.ALLOWED_VALUES"],
                    "required_edits": ["stub edit"], "rejected_targets": [],
                    "security_invariant": "stub", "insufficient_evidence": [],
                })
            return "{}"

        mock_llm = mock.MagicMock()
        mock_llm.complete.side_effect = side_effect

        zero_coverage_result = mock.MagicMock(
            rendered="", warning_text="## Final-target source coverage warning\n\n*none found*\n",
            coverage_complete=False, has_any_coverage=False,
            covered_target_files=[], covered_target_symbols=[],
            uncovered_target_files=["policy.py"], uncovered_target_symbols=["policy.py:Policy.ALLOWED_VALUES"],
        )

        with (
            mock.patch("utilities.autopatcher.pipeline.LLMClient", return_value=mock_llm),
            mock.patch("utilities.autopatcher.remediation_planner.build_final_target_slice",
                       return_value=zero_coverage_result),
            mock.patch("utilities.autopatcher.pipeline.generate_patch",
                       return_value="```diff\n--- a/f.py\n+++ b/f.py\n```") as mock_gen,
            mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok"),
            mock.patch("utilities.autopatcher.pipeline.challenge_patch", return_value={}),
            mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="score: 7"),
            mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
            mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
            mock.patch("utilities.autopatcher.patch_applicability.check_applicability",
                       return_value={"applicable": None, "skipped": True, "stderr": "",
                                     "exit_code": None, "skipped_reason": "empty diff", "error": None}),
        ):
            from utilities.autopatcher.pipeline import run
            run("some vulnerability", api_key="", repo_root=str(tmp_path))

        assert not mock_gen.called

    def test_zero_coverage_no_patch_stderr_shows_no_patch_produced(self, tmp_path, capsys):
        """Regression for the terminal/report consistency fix: the SAME
        real, zero-coverage pipeline.run() as the test above -- which
        deterministically ends with result.patch == "" -- must print
        NO PATCH PRODUCED to stderr, never a Recommendation Policy
        decision such as Manual Review Required, as its primary outcome
        line (the Go CLI streams this stderr verbatim)."""
        target = tmp_path / "policy.py"
        target.write_text("class Policy:\n    ALLOWED_VALUES = frozenset(['a'])\n", encoding="utf-8")

        def side_effect(system_prompt, user_message, stage="unknown"):
            if stage == "remediation_planning":
                return json.dumps({
                    "remediation_mechanism": "extend policy", "target_files": ["policy.py"],
                    "target_symbols": [], "security_invariant": "stub", "required_edits": [],
                    "approaches_to_avoid": [], "explicit_unknowns": [],
                })
            if stage == "remediation_strategy":
                return json.dumps({
                    "extended_mechanism": "Policy.ALLOWED_VALUES", "target_files": ["policy.py"],
                    "target_symbols": ["policy.py:Policy.ALLOWED_VALUES"],
                    "required_edits": ["stub edit"], "rejected_targets": [],
                    "security_invariant": "stub", "insufficient_evidence": [],
                })
            return "{}"

        mock_llm = mock.MagicMock()
        mock_llm.complete.side_effect = side_effect

        zero_coverage_result = mock.MagicMock(
            rendered="", warning_text="## Final-target source coverage warning\n\n*none found*\n",
            coverage_complete=False, has_any_coverage=False,
            covered_target_files=[], covered_target_symbols=[],
            uncovered_target_files=["policy.py"], uncovered_target_symbols=["policy.py:Policy.ALLOWED_VALUES"],
        )

        with (
            mock.patch("utilities.autopatcher.pipeline.LLMClient", return_value=mock_llm),
            mock.patch("utilities.autopatcher.remediation_planner.build_final_target_slice",
                       return_value=zero_coverage_result),
            mock.patch("utilities.autopatcher.pipeline.generate_patch",
                       return_value="```diff\n--- a/f.py\n+++ b/f.py\n```") as mock_gen,
            mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok"),
            mock.patch("utilities.autopatcher.pipeline.challenge_patch", return_value={}),
            mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="score: 7"),
            mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
            mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
            mock.patch("utilities.autopatcher.patch_applicability.check_applicability",
                       return_value={"applicable": None, "skipped": True, "stderr": "",
                                     "exit_code": None, "skipped_reason": "empty diff", "error": None}),
        ):
            from utilities.autopatcher.pipeline import run
            report = run("some vulnerability", api_key="", repo_root=str(tmp_path))

        assert not mock_gen.called
        captured = capsys.readouterr()
        assert "[pipeline] Recommendation:" in captured.err
        assert "⚫ NO PATCH PRODUCED" in captured.err
        assert "Manual Review Required" not in captured.err
        assert "NO PATCH PRODUCED" in report


class TestGenericExtendVsParallelFixture:
    """Synthetic, fully generic (non-urllib3) fixture: an existing policy
    constant, a consumer that already enforces it, a Final Strategy
    selecting that policy -- the slice must contain only the exact
    definition and the focused consumer, never a parallel implementation."""

    def test_slice_contains_only_definition_and_consumer(self, tmp_path):
        (tmp_path / "policy.py").write_text(
            "class Policy:\n    ALLOWED_VALUES = frozenset([\"a\"])\n", encoding="utf-8",
        )
        (tmp_path / "consumer.py").write_text(
            "class Consumer:\n"
            "    def validate(self, value):\n"
            "        if value not in Policy.ALLOWED_VALUES:\n"
            "            raise ValueError(value)\n"
            "        return True\n"
            "\n"
            "    def unrelated_method(self):\n"
            "        return 42\n",
            encoding="utf-8",
        )
        context = _make_context(
            functions={
                "consumer.py:Consumer.validate": {
                    "name": "validate", "className": "Consumer", "startLine": 2, "endLine": 5,
                    "code": (
                        "    def validate(self, value):\n"
                        "        if value not in Policy.ALLOWED_VALUES:\n"
                        "            raise ValueError(value)\n"
                        "        return True\n"
                    ),
                },
                "consumer.py:Consumer.unrelated_method": {
                    "name": "unrelated_method", "className": "Consumer", "startLine": 7, "endLine": 8,
                    "code": "    def unrelated_method(self):\n        return 42\n",
                },
            },
            constants={"policy.py": {
                "Policy.ALLOWED_VALUES": {
                    "qualified_name": "Policy.ALLOWED_VALUES", "class_name": "Policy",
                    "name": "ALLOWED_VALUES", "line": 2, "end_line": 2,
                },
            }},
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        strategy = _make_strategy(
            target_files=["policy.py"], target_symbols=["policy.py:Policy.ALLOWED_VALUES"],
            extended_mechanism="Policy.ALLOWED_VALUES",
            required_edits=["Add 'b' to the existing Policy.ALLOWED_VALUES frozenset."],
        )

        result = build_final_target_slice(strategy, str(tmp_path), context, planner_evidence_files=["consumer.py"])

        assert 'ALLOWED_VALUES = frozenset(["a"])' in result.rendered
        assert "Consumer.validate" in result.rendered
        assert "unrelated_method" not in result.rendered  # no unrelated/parallel source pulled in
        assert "Full file (last resort)" not in result.rendered


class TestUrllib3StyleDeterministicSelfContained:
    """Self-contained (no external checkout dependency) urllib3-shaped
    fixture proving: exact constant definition, exact consumer block,
    combined size, no full file, no full oversized function, no live LLM."""

    def test_definition_and_consumer_without_full_file_or_full_function(self, tmp_path):
        retry_dir = tmp_path / "src" / "urllib3" / "util"
        retry_dir.mkdir(parents=True)
        # A deliberately large retry.py -- large enough that a full-file
        # fallback would visibly dominate the budget if it were ever used.
        filler = "\n".join(f"# filler line {i}" for i in range(400))
        retry_py = retry_dir / "retry.py"
        retry_py.write_text(
            f"{filler}\nclass Retry:\n    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset([\"Authorization\"])\n{filler}\n",
            encoding="utf-8",
        )
        pool_dir = tmp_path / "src" / "urllib3"
        pool_py = pool_dir / "poolmanager.py"
        consumer_code = (
            "    def urlopen(self, method, url, redirect=True, **kw):\n"
            "        retries = kw.get('retries')\n"
            "        if retries.remove_headers_on_redirect:\n"
            "            for header in list(kw.get('headers', {})):\n"
            "                if header.lower() in retries.remove_headers_on_redirect:\n"
            "                    pass\n"
            "        return None\n"
        )
        pool_py.write_text(f"class PoolManager:\n{consumer_code}", encoding="utf-8")

        const_line = 401  # 400 filler lines (1..400) + line 401 is "class Retry:" -- constant is line 402
        context = _make_context(
            functions={
                "src/urllib3/poolmanager.py:PoolManager.urlopen": {
                    "name": "urlopen", "className": "PoolManager", "startLine": 2, "endLine": 8,
                    "code": consumer_code,
                },
            },
            constants={
                "src/urllib3/util/retry.py": {
                    "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT": {
                        "qualified_name": "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                        "class_name": "Retry", "name": "DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                        "line": 402, "end_line": 402,
                    },
                },
            },
            repo_path=tmp_path,
        )

        from utilities.autopatcher.remediation_planner import build_final_target_slice, FINAL_TARGET_SLICE_MAX_CHARS
        strategy = _make_strategy(
            target_files=["src/urllib3/util/retry.py"], target_symbols=[],
            extended_mechanism="DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
            required_edits=["Add 'Cookie' to remove_headers_on_redirect."],
        )

        result = build_final_target_slice(
            strategy, str(tmp_path), context,
            planner_evidence_files=["src/urllib3/poolmanager.py"],
        )

        assert 'DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])' in result.rendered
        assert "PoolManager.urlopen" in result.rendered
        assert "Discovered consumer" in result.rendered
        assert "Full file (last resort)" not in result.rendered
        assert str(retry_py.read_text(encoding="utf-8")) not in result.rendered  # no full file text
        assert len(result.rendered) < FINAL_TARGET_SLICE_MAX_CHARS
        assert "src/urllib3/util/retry.py" in result.covered_target_files
        print(f"\n[urllib3-style self-contained proof] rendered chars: {len(result.rendered)}")

    def test_constant_discovered_via_one_hop_when_absent_from_strategy_text(self, tmp_path):
        # The exact fixed bug: strategy text names only the lowercase
        # attribute/mechanism, NEVER the constant's own bare name -- so
        # category 2 (strategy-term lookup) cannot find it. The selected
        # Retry.__init__ consumer window (found via the "remove_headers_
        # on_redirect" strategy term) references the bare constant name
        # directly as a default value, exactly like real urllib3 -- only
        # the one-hop expansion can surface its exact definition.
        retry_dir = tmp_path / "src" / "urllib3" / "util"
        retry_dir.mkdir(parents=True)
        retry_py = retry_dir / "retry.py"
        init_code = (
            "    def __init__(\n"
            "        self,\n"
            "        remove_headers_on_redirect=DEFAULT_REMOVE_HEADERS_ON_REDIRECT,\n"
            "    ):\n"
            "        self.remove_headers_on_redirect = remove_headers_on_redirect\n"
        )
        retry_py.write_text(
            f"class Retry:\n    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset([\"Authorization\"])\n\n{init_code}",
            encoding="utf-8",
        )
        context = _make_context(
            functions={
                "src/urllib3/util/retry.py:Retry.__init__": {
                    "name": "__init__", "className": "Retry", "startLine": 4, "endLine": 8,
                    "code": init_code,
                },
            },
            constants={
                "src/urllib3/util/retry.py": {
                    "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT": {
                        "qualified_name": "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                        "class_name": "Retry", "name": "DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                        "line": 2, "end_line": 2,
                    },
                },
            },
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        strategy = _make_strategy(
            target_files=["src/urllib3/util/retry.py"], target_symbols=[],
            extended_mechanism="remove_headers_on_redirect",  # never the constant's own bare name
            required_edits=["Add Cookie to remove_headers_on_redirect."],
        )

        result = build_final_target_slice(strategy, str(tmp_path), context)

        assert 'DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])' in result.rendered
        assert result.rendered.index("Target definition") < result.rendered.index("Discovered consumer")


class TestOneHopDependencyExpansion:
    def _retry_style_context(self, tmp_path, init_code, const_line=2, const_end=2, gap=""):
        """`gap` (default "", so every existing caller is unaffected) inserts
        extra lines between the constant and __init__ -- used by the budget
        test below to keep the padded definition window (see
        _DEFINITION_CONTEXT_LINES) from bleeding into the consumer function
        in this otherwise tiny fixture."""
        retry_py = tmp_path / "retry.py"
        retry_py.write_text(
            f"class Retry:\n    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset([\"Authorization\"])\n\n{gap}{init_code}",
            encoding="utf-8",
        )
        init_start = 4 + gap.count("\n")
        return _make_context(
            functions={
                "retry.py:Retry.__init__": {
                    "name": "__init__", "className": "Retry", "startLine": init_start,
                    "endLine": init_start + init_code.count("\n") - 1,
                    "code": init_code,
                },
            },
            constants={
                "retry.py": {
                    "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT": {
                        "qualified_name": "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                        "class_name": "Retry", "name": "DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                        "line": const_line, "end_line": const_end,
                    },
                },
            },
            repo_path=tmp_path,
        )

    def test_consumer_reference_causes_definition_to_be_added(self, tmp_path):
        init_code = (
            "    def __init__(self, remove_headers_on_redirect=DEFAULT_REMOVE_HEADERS_ON_REDIRECT):\n"
            "        self.remove_headers_on_redirect = remove_headers_on_redirect\n"
        )
        context = self._retry_style_context(tmp_path, init_code)
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        strategy = _make_strategy(
            target_files=["retry.py"], extended_mechanism="remove_headers_on_redirect",
        )
        result = build_final_target_slice(strategy, str(tmp_path), context)
        assert 'DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])' in result.rendered

    def test_definition_renders_before_consumer(self, tmp_path):
        init_code = (
            "    def __init__(self, remove_headers_on_redirect=DEFAULT_REMOVE_HEADERS_ON_REDIRECT):\n"
            "        self.remove_headers_on_redirect = remove_headers_on_redirect\n"
        )
        context = self._retry_style_context(tmp_path, init_code)
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        strategy = _make_strategy(target_files=["retry.py"], extended_mechanism="remove_headers_on_redirect")
        result = build_final_target_slice(strategy, str(tmp_path), context)
        assert result.rendered.index("Target definition") < result.rendered.index("Discovered consumer")

    def test_exact_capitalization_and_brackets_preserved(self, tmp_path):
        init_code = (
            "    def __init__(self, remove_headers_on_redirect=DEFAULT_REMOVE_HEADERS_ON_REDIRECT):\n"
            "        pass\n"
        )
        context = self._retry_style_context(tmp_path, init_code)
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        strategy = _make_strategy(target_files=["retry.py"], extended_mechanism="remove_headers_on_redirect")
        result = build_final_target_slice(strategy, str(tmp_path), context)
        # exact literal syntax, capitalization, and bracket type (square + frozenset call) preserved verbatim
        assert 'DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])' in result.rendered

    def test_disambiguation_prefers_same_class_and_file(self):
        from utilities.autopatcher.remediation_planner import _disambiguate_constant_candidates
        candidates = [
            ("other.py", "Other.X", {"name": "X", "line": 1, "end_line": 1}),
            ("retry.py", "Retry.X", {"name": "X", "line": 2, "end_line": 2}),
        ]
        chosen, reason = _disambiguate_constant_candidates(
            candidates, source_file="retry.py", source_class="Retry",
            symbol_matches={}, strategy_target_files=["retry.py", "other.py"],
        )
        assert reason is None
        assert chosen == ("retry.py", "Retry.X", {"name": "X", "line": 2, "end_line": 2})

    def test_disambiguation_prefers_final_strategy_target_file(self):
        from utilities.autopatcher.remediation_planner import _disambiguate_constant_candidates
        candidates = [
            ("unrelated.py", "Unrelated.X", {"name": "X", "line": 1, "end_line": 1}),
            ("target.py", "Target.X", {"name": "X", "line": 2, "end_line": 2}),
        ]
        # Neither shares the referencing block's own class/file -- tier 3
        # (same Final Strategy target file) must still disambiguate.
        chosen, reason = _disambiguate_constant_candidates(
            candidates, source_file="consumer.py", source_class="Consumer",
            symbol_matches={}, strategy_target_files=["target.py"],
        )
        assert reason is None
        assert chosen[0] == "target.py"

    def test_unique_bounded_match_is_used(self):
        from utilities.autopatcher.remediation_planner import _disambiguate_constant_candidates
        candidates = [("only.py", "Only.X", {"name": "X", "line": 1, "end_line": 1})]
        chosen, reason = _disambiguate_constant_candidates(
            candidates, source_file="consumer.py", source_class=None,
            symbol_matches={}, strategy_target_files=[],
        )
        assert reason is None
        assert chosen[0] == "only.py"

    def test_ambiguous_equal_priority_matches_are_skipped_safely(self):
        from utilities.autopatcher.remediation_planner import _disambiguate_constant_candidates
        candidates = [
            ("a.py", "A.X", {"name": "X", "line": 1, "end_line": 1}),
            ("b.py", "B.X", {"name": "X", "line": 2, "end_line": 2}),
        ]
        # Neither matches the source class/file, neither is a Final
        # Strategy target file -- every tier is tied at 2 candidates.
        chosen, reason = _disambiguate_constant_candidates(
            candidates, source_file="consumer.py", source_class="Consumer",
            symbol_matches={}, strategy_target_files=["unrelated_target.py"],
        )
        assert chosen is None
        assert reason is not None
        assert "ambiguous" in reason

    def test_ambiguous_match_does_not_raise_or_fail_the_run(self, tmp_path):
        (tmp_path / "a.py").write_text("class A:\n    X = 1\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("class B:\n    X = 2\n", encoding="utf-8")
        (tmp_path / "consumer.py").write_text(
            "class C:\n    def m(self):\n        return X\n", encoding="utf-8",
        )
        context = _make_context(
            functions={"consumer.py:C.m": {
                "name": "m", "className": "C", "startLine": 2, "endLine": 3,
                "code": "    def m(self):\n        return X\n",
            }},
            constants={
                "a.py": {"A.X": {"qualified_name": "A.X", "name": "X", "line": 2, "end_line": 2}},
                "b.py": {"B.X": {"qualified_name": "B.X", "name": "X", "line": 2, "end_line": 2}},
            },
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        strategy = _make_strategy(target_files=["consumer.py"], extended_mechanism="C.m")
        result = build_final_target_slice(
            strategy, str(tmp_path), context, planner_evidence_files=["a.py", "b.py"],
        )
        assert "A.X" not in result.rendered
        assert "B.X" not in result.rendered  # ambiguous -- neither guessed

    def test_existing_definition_not_duplicated(self, tmp_path):
        init_code = (
            "    def __init__(self, remove_headers_on_redirect=DEFAULT_REMOVE_HEADERS_ON_REDIRECT):\n"
            "        pass\n"
        )
        context = self._retry_style_context(tmp_path, init_code)
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        # The constant is ALREADY a verified target symbol (category 1)
        # AND also referenced inside the selected consumer -- must render
        # exactly once, not twice via one-hop.
        strategy = _make_strategy(
            target_files=["retry.py"],
            target_symbols=["retry.py:Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT"],
            extended_mechanism="remove_headers_on_redirect",
        )
        result = build_final_target_slice(strategy, str(tmp_path), context)
        assert result.rendered.count("Target definition") == 1

    def test_expansion_is_one_hop_only(self, tmp_path):
        # consumer references REFERENCED_CONST; REFERENCED_CONST's OWN
        # definition body references SECOND_HOP_CONST. SECOND_HOP_CONST
        # must NEVER be expanded -- only one hop from the originally
        # selected source (the consumer), never from a newly-added
        # dependency definition.
        (tmp_path / "chain.py").write_text(
            "class Chain:\n"
            "    SECOND_HOP_CONST = 1\n"
            "    REFERENCED_CONST = SECOND_HOP_CONST\n"
            "    def m(self):\n"
            "        return REFERENCED_CONST\n",
            encoding="utf-8",
        )
        context = _make_context(
            functions={"chain.py:Chain.m": {
                "name": "m", "className": "Chain", "startLine": 4, "endLine": 5,
                "code": "    def m(self):\n        return REFERENCED_CONST\n",
            }},
            constants={"chain.py": {
                "Chain.REFERENCED_CONST": {
                    "qualified_name": "Chain.REFERENCED_CONST", "name": "REFERENCED_CONST", "line": 3, "end_line": 3,
                },
                "Chain.SECOND_HOP_CONST": {
                    "qualified_name": "Chain.SECOND_HOP_CONST", "name": "SECOND_HOP_CONST", "line": 2, "end_line": 2,
                },
            }},
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        strategy = _make_strategy(target_files=["chain.py"], extended_mechanism="REFERENCED_CONST")
        result = build_final_target_slice(strategy, str(tmp_path), context)
        assert "Chain.REFERENCED_CONST" in result.rendered  # one hop: consumer -> REFERENCED_CONST
        assert "Chain.SECOND_HOP_CONST" not in result.rendered  # NOT a second hop: REFERENCED_CONST's body -> SECOND_HOP_CONST

    def test_comment_does_not_trigger_unrelated_constant(self, tmp_path):
        (tmp_path / "policy.py").write_text("class Policy:\n    UNRELATED = 1\n", encoding="utf-8")
        (tmp_path / "consumer.py").write_text(
            "class C:\n"
            "    def m(self):\n"
            "        # see UNRELATED for details\n"
            "        return 1\n",
            encoding="utf-8",
        )
        context = _make_context(
            functions={"consumer.py:C.m": {
                "name": "m", "className": "C", "startLine": 2, "endLine": 4,
                "code": "    def m(self):\n        # see UNRELATED for details\n        return 1\n",
            }},
            constants={"policy.py": {
                "Policy.UNRELATED": {"qualified_name": "Policy.UNRELATED", "name": "UNRELATED", "line": 2, "end_line": 2},
            }},
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        strategy = _make_strategy(target_files=["consumer.py"], extended_mechanism="UNRELATED")
        result = build_final_target_slice(
            strategy, str(tmp_path), context, planner_evidence_files=["policy.py"],
        )
        # The comment text itself is legitimately preserved verbatim as
        # part of the consumer's own selected source (never stripped) --
        # what must NOT happen is a SEPARATE one-hop definition block for
        # policy.py:Policy.UNRELATED being added on the strength of a
        # reference that only ever appeared inside a comment.
        assert "Target definition: `policy.py:Policy.UNRELATED`" not in result.rendered

    def test_budget_priority_definition_ahead_of_consumer(self, tmp_path, monkeypatch):
        from utilities.autopatcher import remediation_planner as rp
        init_code = (
            "    def __init__(self, remove_headers_on_redirect=DEFAULT_REMOVE_HEADERS_ON_REDIRECT):\n"
            "        pass\n"
        )
        # `gap` keeps __init__ far enough from the constant that the padded
        # definition window (_DEFINITION_CONTEXT_LINES on each side) doesn't
        # bleed into the consumer's own lines -- otherwise, in this small a
        # fixture, "the definition" and "the consumer" would overlap and this
        # test would no longer isolate what it's testing (budget priority
        # between two genuinely separate blocks).
        gap = "".join(f"    # gap line {i}\n" for i in range(1, 7))
        context = self._retry_style_context(tmp_path, init_code, gap=gap)
        strategy = _make_strategy(target_files=["retry.py"], extended_mechanism="remove_headers_on_redirect")
        # A budget just large enough for the (now patch-ready, padded) exact
        # definition but too small to ALSO fit the consumer window -- the
        # definition must still win the budget over the consumer that
        # referenced it. Measured against this fixture: the padded
        # definition block is 221 characters; definition + consumer combined
        # is 434. 300 sits cleanly between the two.
        monkeypatch.setattr(rp, "FINAL_TARGET_SLICE_MAX_CHARS", 300)
        result = rp.build_final_target_slice(strategy, str(tmp_path), context)
        assert 'DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])' in result.rendered
        assert "Discovered consumer" not in result.rendered

    def test_extract_source_constant_refs_is_conservative(self):
        from utilities.autopatcher.remediation_planner import _extract_source_constant_refs
        code = (
            "    # see MAX_RETRIES for details\n"
            "    def m(self, value=DEFAULT_VALUE):\n"
            "        x = \"a string with WORDS in it\"\n"
            "        return value\n"
        )
        found = _extract_source_constant_refs(code)
        assert "DEFAULT_VALUE" in found
        assert "MAX_RETRIES" not in found  # full-line comment skipped

    def test_generic_extend_vs_parallel_fixture_still_passes(self, tmp_path):
        # Smoke re-check: the earlier, unrelated generic proof (policy
        # constant + consumer, no reference chain at all) must still
        # behave identically with the one-hop step added.
        (tmp_path / "policy.py").write_text(
            "class Policy:\n    ALLOWED_VALUES = frozenset([\"a\"])\n", encoding="utf-8",
        )
        context = _make_context(
            constants={"policy.py": {
                "Policy.ALLOWED_VALUES": {
                    "qualified_name": "Policy.ALLOWED_VALUES", "class_name": "Policy",
                    "name": "ALLOWED_VALUES", "line": 2, "end_line": 2,
                },
            }},
            repo_path=tmp_path,
        )
        from utilities.autopatcher.remediation_planner import build_final_target_slice
        strategy = _make_strategy(target_files=["policy.py"], target_symbols=["policy.py:Policy.ALLOWED_VALUES"])
        result = build_final_target_slice(strategy, str(tmp_path), context)
        assert result.coverage_complete is True
        assert result.rendered.count("Target definition") == 1


# ---------------------------------------------------------------------------
# Slice 1 -- Edit Readiness Gate
# ---------------------------------------------------------------------------

class TestBuildIntendedEdits:
    """Test 1 (intended edit derivation) + Test 2 (file-level fallback
    only when no target symbol exists)."""

    def test_one_intended_edit_per_verified_target_symbol(self):
        from utilities.autopatcher.remediation_planner import IntendedEdit, build_intended_edits
        strategy = _make_strategy(
            target_files=["src/mod.py"],
            target_symbols=["src/mod.py:Class.CONST_A", "src/mod.py:Class.method_b"],
        )
        edits = build_intended_edits(strategy)
        assert IntendedEdit(file="src/mod.py", symbol="src/mod.py:Class.CONST_A") in edits
        assert IntendedEdit(file="src/mod.py", symbol="src/mod.py:Class.method_b") in edits
        # both target_symbols already carry a file hint naming this file --
        # no separate file-level edit is added on top of them.
        assert len(edits) == 2

    def test_bare_symbol_with_no_file_hint_still_produces_its_own_edit(self):
        from utilities.autopatcher.remediation_planner import IntendedEdit, build_intended_edits
        strategy = _make_strategy(target_files=["src/mod.py"], target_symbols=["bare_name"])
        edits = build_intended_edits(strategy)
        assert IntendedEdit(file=None, symbol="bare_name") in edits

    def test_bare_symbol_with_resolved_file_produces_exactly_one_edit(self):
        """Regression: a bare (file-hint-less) target_symbol that resolves
        to a file ALSO named in target_files must not produce a second,
        spurious file-level IntendedEdit for the same logical target --
        the prior review's confirmed bare-symbol duplication bug."""
        from utilities.autopatcher.remediation_planner import (
            FinalTargetSliceResult, IntendedEdit, build_intended_edits,
        )
        strategy = _make_strategy(target_files=["a.py"], target_symbols=["Class.method"])
        slice_result = FinalTargetSliceResult(
            rendered="", covered_target_files=[], covered_target_symbols=[],
            uncovered_target_files=[], uncovered_target_symbols=[],
            coverage_complete=True, has_any_coverage=False, warning_text="",
            resolved_target_symbols=[], full_file_fallback_covered=[],
            edit_target_budget_exhausted=False,
            resolved_symbol_files={"Class.method": "a.py"}, identifier_definition_covered=[],
        )
        edits = build_intended_edits(strategy, slice_result)
        assert edits == [IntendedEdit(file="a.py", symbol="Class.method")]

    def test_duplicate_target_symbols_are_deduplicated(self):
        from utilities.autopatcher.remediation_planner import build_intended_edits
        strategy = _make_strategy(target_symbols=["a.py:X", "a.py:X"])
        edits = build_intended_edits(strategy)
        assert len(edits) == 1

    def test_no_file_level_edit_when_a_symbol_already_covers_the_file(self):
        """Test 2: 'Add a file-level intended edit only when a verified
        target file has no corresponding verified target symbol.'"""
        from utilities.autopatcher.remediation_planner import IntendedEdit, build_intended_edits
        strategy = _make_strategy(target_files=["a.py"], target_symbols=["a.py:X"])
        edits = build_intended_edits(strategy)
        assert edits == [IntendedEdit(file="a.py", symbol="a.py:X")]

    def test_file_level_edit_added_only_for_the_file_with_no_symbol(self):
        from utilities.autopatcher.remediation_planner import IntendedEdit, build_intended_edits
        strategy = _make_strategy(target_files=["a.py", "b.py"], target_symbols=["a.py:X"])
        edits = build_intended_edits(strategy)
        assert IntendedEdit(file="a.py", symbol="a.py:X") in edits
        assert IntendedEdit(file="b.py", symbol=None) in edits
        assert len(edits) == 2

    def test_empty_strategy_produces_no_intended_edits(self):
        from utilities.autopatcher.remediation_planner import build_intended_edits
        assert build_intended_edits(_make_strategy()) == []


class TestCheckEditReadinessDirect:
    """Test 4 (unrelated block from the correct file does not satisfy
    readiness) + Test 5 (a block containing the exact resolved identifier
    does satisfy readiness), exercised directly against hand-built
    FinalTargetSliceResult values -- no repository, no LLM."""

    @staticmethod
    def _slice_result(**overrides):
        from utilities.autopatcher.remediation_planner import FinalTargetSliceResult
        base = dict(
            rendered="## Final-Target Remediation Slice\n", covered_target_files=[],
            covered_target_symbols=[], uncovered_target_files=[], uncovered_target_symbols=[],
            coverage_complete=True, has_any_coverage=True, warning_text="",
            resolved_target_symbols=[], full_file_fallback_covered=[],
            edit_target_budget_exhausted=False,
            resolved_symbol_files={}, identifier_definition_covered=[],
        )
        base.update(overrides)
        return FinalTargetSliceResult(**base)

    def test_symbol_edit_ready_when_covered_target_symbols_contains_it(self):
        from utilities.autopatcher.remediation_planner import IntendedEdit, check_edit_readiness
        edit = IntendedEdit(file="a.py", symbol="a.py:X")
        result = check_edit_readiness([edit], self._slice_result(covered_target_symbols=["a.py:X"]))
        assert result.edit_source_ready is True
        assert result.ready_edits[0].role == "edit_target"
        assert result.unready_edits == []

    def test_symbol_edit_not_ready_when_resolved_but_not_covered_is_missing_target_source(self):
        from utilities.autopatcher.remediation_planner import IntendedEdit, check_edit_readiness
        edit = IntendedEdit(file="a.py", symbol="a.py:X")
        # resolved (present in resolved_target_symbols) but never made it
        # into the rendered slice (not in covered_target_symbols) --
        # e.g. a read failure, or an oversized function.
        result = check_edit_readiness(
            [edit], self._slice_result(resolved_target_symbols=["a.py:X"])
        )
        assert result.edit_source_ready is False
        assert result.unready_edits[0].reason == "missing_target_source"

    def test_symbol_edit_not_ready_when_never_resolved_is_unresolved_symbol(self):
        from utilities.autopatcher.remediation_planner import IntendedEdit, check_edit_readiness
        edit = IntendedEdit(file="a.py", symbol="a.py:X")
        result = check_edit_readiness([edit], self._slice_result())
        assert result.edit_source_ready is False
        assert result.unready_edits[0].reason == "unresolved_symbol"

    def test_file_only_edit_ready_only_via_full_file_fallback_covered(self):
        """Test 5: the block containing the exact resolved identifier
        (here: the full-file fallback that passed identifier-containment)
        satisfies readiness."""
        from utilities.autopatcher.remediation_planner import IntendedEdit, check_edit_readiness
        edit = IntendedEdit(file="a.py", symbol=None)
        result = check_edit_readiness(
            [edit],
            self._slice_result(covered_target_files=["a.py"], full_file_fallback_covered=["a.py"]),
        )
        assert result.edit_source_ready is True
        assert result.ready_edits[0].role == "edit_target"

    def test_file_only_edit_not_ready_when_file_covered_by_unrelated_block(self):
        """Test 4: 'An unrelated block from the correct file does not
        satisfy readiness.' The file IS in covered_target_files (SOME
        block -- e.g. a one-hop constant or a usage window -- was
        rendered from it) but NOT via full_file_fallback_covered, so
        nothing ties that block to the actual intended edit."""
        from utilities.autopatcher.remediation_planner import IntendedEdit, check_edit_readiness
        edit = IntendedEdit(file="a.py", symbol=None)
        result = check_edit_readiness(
            [edit],
            self._slice_result(covered_target_files=["a.py"], full_file_fallback_covered=[]),
        )
        assert result.edit_source_ready is False
        assert result.unready_edits[0].reason == "missing_identifier"

    def test_file_only_edit_not_ready_when_file_has_no_source_at_all(self):
        from utilities.autopatcher.remediation_planner import IntendedEdit, check_edit_readiness
        edit = IntendedEdit(file="a.py", symbol=None)
        result = check_edit_readiness([edit], self._slice_result())
        assert result.edit_source_ready is False
        assert result.unready_edits[0].reason == "missing_target_source"

    def test_strategy_ready_false_when_no_intended_edits(self):
        from utilities.autopatcher.remediation_planner import check_edit_readiness
        result = check_edit_readiness([], self._slice_result())
        assert result.strategy_ready is False
        assert result.edit_source_ready is False

    def test_failure_reasons_deduplicated_in_first_seen_order(self):
        from utilities.autopatcher.remediation_planner import IntendedEdit, check_edit_readiness
        edits = [
            IntendedEdit(file="a.py", symbol="a.py:X"),
            IntendedEdit(file="b.py", symbol="b.py:Y"),
        ]
        result = check_edit_readiness(edits, self._slice_result())
        assert result.failure_reasons == ["unresolved_symbol"]


class TestEditTargetBudgetExhaustion:
    """Test 8: budget exhaustion across edit targets fails closed instead
    of silently selecting an arbitrary subset."""

    def test_edit_target_budget_exhausted_flag_set_when_targets_alone_exceed_budget(self, tmp_path, monkeypatch):
        from utilities.autopatcher import remediation_planner as rp
        lines = [f"line{i}\n" for i in range(1, 20)]
        lines[1] = "CONST_A = 1\n"
        lines[10] = "CONST_B = 2\n"
        (tmp_path / "mod.py").write_text("".join(lines), encoding="utf-8")
        context = _make_context(
            constants={"mod.py": {
                "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 2, "end_line": 2},
                "CONST_B": {"qualified_name": "CONST_B", "class_name": None, "name": "CONST_B", "line": 11, "end_line": 11},
            }},
            repo_path=tmp_path,
        )
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A", "mod.py:CONST_B"])
        # Both constants resolve; a budget too small to fit even ONE
        # padded definition block forces edit_target_budget_exhausted.
        monkeypatch.setattr(rp, "FINAL_TARGET_SLICE_MAX_CHARS", 10)
        result = rp.build_final_target_slice(strategy, str(tmp_path), context)
        assert result.edit_target_budget_exhausted is True
        # Not silently narrowed to "coverage complete" -- both remain uncovered.
        assert set(result.uncovered_target_symbols) == {"mod.py:CONST_A", "mod.py:CONST_B"}

    def test_readiness_reports_target_budget_exhausted_not_a_silent_subset(self, tmp_path, monkeypatch):
        from utilities.autopatcher import remediation_planner as rp
        lines = [f"line{i}\n" for i in range(1, 20)]
        lines[1] = "CONST_A = 1\n"
        lines[10] = "CONST_B = 2\n"
        (tmp_path / "mod.py").write_text("".join(lines), encoding="utf-8")
        context = _make_context(
            constants={"mod.py": {
                "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 2, "end_line": 2},
                "CONST_B": {"qualified_name": "CONST_B", "class_name": None, "name": "CONST_B", "line": 11, "end_line": 11},
            }},
            repo_path=tmp_path,
        )
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A", "mod.py:CONST_B"])
        monkeypatch.setattr(rp, "FINAL_TARGET_SLICE_MAX_CHARS", 10)
        slice_result = rp.build_final_target_slice(strategy, str(tmp_path), context)
        intended_edits = rp.build_intended_edits(strategy)
        readiness = rp.check_edit_readiness(intended_edits, slice_result)
        assert readiness.edit_source_ready is False
        assert all(u.reason == "target_budget_exhausted" for u in readiness.unready_edits)
        # Never claims readiness for a symbol the budget couldn't fit,
        # even if the OTHER one happened to squeeze in.
        assert len(readiness.unready_edits) == len(intended_edits) - len(readiness.ready_edits)


class TestEditTargetOrderedBeforeSupportingContext:
    """Test 3: edit target source is ordered (committed to the shared
    budget) before supporting context -- a function edit target with no
    strategy-term anchor (Category 4, edit-target role) must not be
    displaced by a one-hop-discovered constant (supporting-context role)
    competing for the same tight budget."""

    def test_function_edit_target_wins_budget_over_one_hop_constant(self, tmp_path, monkeypatch):
        from utilities.autopatcher import remediation_planner as rp
        file_text = (
            "class Mod:\n"
            "    CONST_X = 1\n"
            "\n"
            "    def target_func(self):\n"
            "        return CONST_X\n"
        )
        (tmp_path / "mod.py").write_text(file_text, encoding="utf-8")
        func_code = "    def target_func(self):\n        return CONST_X\n"
        context = _make_context(
            functions={"mod.py:Mod.target_func": {
                "name": "target_func", "className": "Mod", "startLine": 4, "endLine": 5,
                "code": func_code,
            }},
            constants={"mod.py": {"Mod.CONST_X": {
                "qualified_name": "Mod.CONST_X", "class_name": "Mod", "name": "CONST_X",
                "line": 2, "end_line": 2,
            }}},
            repo_path=tmp_path,
        )
        # No strategy term anchors inside target_func's own body (nothing
        # extracted from extended_mechanism/required_edits matches text
        # inside it), so it can only be covered via Category 4 (compact
        # full function) -- competing directly with the one-hop constant
        # CONST_X (discovered by scanning target_func's own rendered body)
        # for a budget too small to fit both.
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:Mod.target_func"])

        # Measure: function-only vs function+one-hop-constant.
        monkeypatch.setattr(rp, "FINAL_TARGET_SLICE_MAX_CHARS", 1_000_000)
        full_result = rp.build_final_target_slice(strategy, str(tmp_path), context)
        function_only_size = len(full_result.rendered)
        assert "target_func" in full_result.rendered
        assert "CONST_X = 1" in full_result.rendered  # one-hop constant present when budget is generous

        # Now set a budget that fits the function alone but not the
        # one-hop constant too.
        just_function_size = function_only_size - len("CONST_X = 1")  # rough lower slack
        monkeypatch.setattr(rp, "FINAL_TARGET_SLICE_MAX_CHARS", max(1, just_function_size - 50))
        tight_result = rp.build_final_target_slice(strategy, str(tmp_path), context)

        # The edit target (the function itself) must still be included --
        # this is the actual thing that must never be displaced.
        assert "target_func" in tight_result.rendered
        assert "mod.py:Mod.target_func" in tight_result.covered_target_symbols
        # The one-hop supporting constant may or may not fit depending on
        # exact slack -- not the point of this test either way. What
        # matters is asserted above: the edit target itself always wins.


class TestEditReadinessGatesPatchGeneration:
    """Test 6 (partial readiness skips Patch Generation), Test 7 (complete
    readiness preserves current Patch Generation behavior), and Test 9
    (no new LLM calls introduced) -- exercised through the real
    pipeline.py wiring (build_intended_edits/check_edit_readiness run for
    real), with only build_final_target_slice's OWN return value mocked,
    same pattern as TestPipelineContextOrderingWithSlice above."""

    @staticmethod
    def _side_effect(stage_calls):
        def side_effect(system_prompt, user_message, stage="unknown"):
            stage_calls.append(stage)
            if stage == "remediation_planning":
                return json.dumps({
                    "remediation_mechanism": "extend policy", "target_files": ["policy.py"],
                    "target_symbols": [], "security_invariant": "stub", "required_edits": [],
                    "approaches_to_avoid": [], "explicit_unknowns": [],
                })
            if stage == "remediation_strategy":
                return json.dumps({
                    "extended_mechanism": "Policy.ALLOWED_VALUES", "target_files": ["policy.py"],
                    "target_symbols": ["policy.py:Policy.ALLOWED_VALUES"],
                    "required_edits": ["stub edit"], "rejected_targets": [],
                    "security_invariant": "stub", "insufficient_evidence": [],
                })
            return "{}"
        return side_effect

    def _run(self, tmp_path, slice_result, stage_calls):
        target = tmp_path / "policy.py"
        target.write_text("class Policy:\n    ALLOWED_VALUES = frozenset(['a'])\n", encoding="utf-8")

        mock_llm = mock.MagicMock()
        mock_llm.complete.side_effect = self._side_effect(stage_calls)

        with (
            mock.patch("utilities.autopatcher.pipeline.LLMClient", return_value=mock_llm),
            mock.patch("utilities.autopatcher.remediation_planner.build_final_target_slice",
                       return_value=slice_result),
            mock.patch("utilities.autopatcher.pipeline.generate_patch",
                       return_value="```diff\n--- a/f.py\n+++ b/f.py\n```") as mock_gen,
            mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok"),
            mock.patch("utilities.autopatcher.pipeline.challenge_patch", return_value={}),
            mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="score: 7"),
            mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
            mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
            mock.patch("utilities.autopatcher.patch_applicability.check_applicability",
                       return_value={"applicable": True, "skipped": False, "stderr": "",
                                     "exit_code": 0, "skipped_reason": None, "error": None}),
        ):
            from utilities.autopatcher.pipeline import run
            run("some vulnerability", api_key="", repo_root=str(tmp_path))
        return mock_gen

    def test_partial_readiness_skips_patch_generation(self, tmp_path):
        """Test 6. Deliberately a case has_any_coverage=True (the OLD gate
        would have proceeded) but the actual intended edit's symbol is
        neither resolved nor covered -- only unrelated coverage exists.
        The new Gate must still skip Patch Generation."""
        stage_calls: list = []
        unready_result = mock.MagicMock(
            rendered="## Final-Target Remediation Slice\n\nsome unrelated content\n",
            warning_text="", coverage_complete=False, has_any_coverage=True,
            covered_target_files=["policy.py"], covered_target_symbols=[],
            uncovered_target_files=[], uncovered_target_symbols=["policy.py:Policy.ALLOWED_VALUES"],
            resolved_target_symbols=[], full_file_fallback_covered=[],
            edit_target_budget_exhausted=False,
        )
        mock_gen = self._run(tmp_path, unready_result, stage_calls)
        assert not mock_gen.called

    def test_complete_readiness_preserves_current_patch_generation_behavior(self, tmp_path):
        """Test 7. The intended edit's own symbol IS covered -- Patch
        Generation must run exactly as it always has."""
        stage_calls: list = []
        # NOTE: run() is called with no investigation_output_dir, so
        # _investigation_context stays None -- _resolve_symbol_details
        # returns None for everything, and _verify_strategy_targets
        # therefore ALWAYS drops the mock LLM's own claimed target_symbol
        # ("policy.py:Policy.ALLOWED_VALUES") as unverified, regardless of
        # what this mocked Slice result claims about it. The REAL
        # intended edit build_intended_edits derives is therefore
        # file-only (IntendedEdit(file="policy.py", symbol=None)) -- ready
        # only via full_file_fallback_covered, not covered_target_symbols.
        ready_result = mock.MagicMock(
            rendered="## Final-Target Remediation Slice\n\nDEFAULT source\n",
            warning_text="", coverage_complete=True, has_any_coverage=True,
            covered_target_files=["policy.py"], covered_target_symbols=[],
            uncovered_target_files=[], uncovered_target_symbols=[],
            resolved_target_symbols=[], full_file_fallback_covered=["policy.py"],
            edit_target_budget_exhausted=False,
        )
        mock_gen = self._run(tmp_path, ready_result, stage_calls)
        assert mock_gen.called

    def test_no_new_llm_call_stage_introduced(self, tmp_path):
        """Test 9. The Edit Readiness Gate must add zero new LLM calls --
        only the pre-existing remediation_planning/remediation_strategy
        stages (plus whatever Patch Generation itself calls) ever appear."""
        stage_calls: list = []
        # NOTE: run() is called with no investigation_output_dir, so
        # _investigation_context stays None -- _resolve_symbol_details
        # returns None for everything, and _verify_strategy_targets
        # therefore ALWAYS drops the mock LLM's own claimed target_symbol
        # ("policy.py:Policy.ALLOWED_VALUES") as unverified, regardless of
        # what this mocked Slice result claims about it. The REAL
        # intended edit build_intended_edits derives is therefore
        # file-only (IntendedEdit(file="policy.py", symbol=None)) -- ready
        # only via full_file_fallback_covered, not covered_target_symbols.
        ready_result = mock.MagicMock(
            rendered="## Final-Target Remediation Slice\n\nDEFAULT source\n",
            warning_text="", coverage_complete=True, has_any_coverage=True,
            covered_target_files=["policy.py"], covered_target_symbols=[],
            uncovered_target_files=[], uncovered_target_symbols=[],
            resolved_target_symbols=[], full_file_fallback_covered=["policy.py"],
            edit_target_budget_exhausted=False,
        )
        self._run(tmp_path, ready_result, stage_calls)
        assert set(stage_calls) <= {
            "remediation_planning", "remediation_strategy", "patch_challenger",
            "patch_review", "confidence_scorer", "finding_calibration",
        }
        assert "edit_readiness" not in stage_calls

    def test_acquisition_runs_and_still_skips_when_it_cannot_help(self, tmp_path):
        """Test 14 (Slice 2). build_final_target_slice is mocked to
        always return the SAME unready result regardless of input args,
        so Slice 2's own per-edit retries genuinely execute (real code,
        not skipped) but can never improve on it -- readiness must still
        be incomplete after acquisition exhausts its rounds, and Patch
        Generation must still be skipped."""
        stage_calls: list = []
        unready_result = mock.MagicMock(
            rendered="## Final-Target Remediation Slice\n\nsome unrelated content\n",
            warning_text="", coverage_complete=False, has_any_coverage=True,
            covered_target_files=["policy.py"], covered_target_symbols=[],
            uncovered_target_files=[], uncovered_target_symbols=["policy.py:Policy.ALLOWED_VALUES"],
            resolved_target_symbols=[], full_file_fallback_covered=[],
            identifier_definition_covered=[], edit_target_budget_exhausted=False,
            resolved_symbol_files={},
        )
        mock_gen = self._run(tmp_path, unready_result, stage_calls)
        assert not mock_gen.called

    def test_acquisition_introduces_no_unexpected_llm_call_stage(self, tmp_path):
        """Test 12 (Slice 2, pipeline level). Same as
        test_no_new_llm_call_stage_introduced, but forcing Slice 2's
        deterministic acquisition loop to actually run (initial readiness
        is incomplete here, unlike that test's always-ready fixture).
        Because this fixture stays unready even after Slice 2, Slice 3's
        guided acquisition also runs -- its one, explicit, expected new
        stage ("guided_context_request", Slice 3's own contract) is
        allowed; nothing else is."""
        stage_calls: list = []
        unready_result = mock.MagicMock(
            rendered="## Final-Target Remediation Slice\n\nsome unrelated content\n",
            warning_text="", coverage_complete=False, has_any_coverage=True,
            covered_target_files=["policy.py"], covered_target_symbols=[],
            uncovered_target_files=[], uncovered_target_symbols=["policy.py:Policy.ALLOWED_VALUES"],
            resolved_target_symbols=[], full_file_fallback_covered=[],
            identifier_definition_covered=[], edit_target_budget_exhausted=False,
            resolved_symbol_files={},
        )
        self._run(tmp_path, unready_result, stage_calls)
        assert set(stage_calls) <= {
            "remediation_planning", "remediation_strategy", "guided_context_request",
            "patch_challenger", "patch_review", "confidence_scorer", "finding_calibration",
        }
        assert "edit_readiness" not in stage_calls
        assert "acquisition" not in stage_calls


class TestEditReadinessNoLLMParameter:
    """Test 9 (unit level, mirrors TestSliceGatingAndNoNewLLM above)."""

    def test_build_intended_edits_has_no_llm_parameter(self):
        import inspect
        from utilities.autopatcher.remediation_planner import build_intended_edits
        assert "llm" not in inspect.signature(build_intended_edits).parameters

    def test_check_edit_readiness_has_no_llm_parameter(self):
        import inspect
        from utilities.autopatcher.remediation_planner import check_edit_readiness
        assert "llm" not in inspect.signature(check_edit_readiness).parameters


# ---------------------------------------------------------------------------
# Slice 2 -- Deterministic Pre-Patch Retrieval
# ---------------------------------------------------------------------------

class TestDeterministicAcquisitionNoLLMParameter:
    def test_run_deterministic_acquisition_has_no_llm_parameter(self):
        import inspect
        from utilities.autopatcher.remediation_planner import run_deterministic_acquisition
        assert "llm" not in inspect.signature(run_deterministic_acquisition).parameters


class TestAmbiguousConstantCandidateRejected:
    """Test 5, part 1 (unit level): _disambiguate_constant_candidates
    (existing, unmodified) correctly refuses an equal-priority tie rather
    than guessing -- the mechanism Slice 2 relies on for ambiguity
    rejection during acquisition."""

    def test_ambiguous_tie_returns_none_not_a_guess(self):
        from utilities.autopatcher.remediation_planner import _disambiguate_constant_candidates
        candidates = [
            ("a.py", "X.AMBIG", {"name": "AMBIG", "line": 2, "end_line": 2}),
            ("a.py", "Y.AMBIG", {"name": "AMBIG", "line": 6, "end_line": 6}),
        ]
        chosen, reason = _disambiguate_constant_candidates(
            candidates, source_file="a.py", source_class=None, symbol_matches={},
            strategy_target_files=["a.py"],
        )
        assert chosen is None
        assert "ambiguous" in reason


class TestDeterministicAcquisition:
    """Tests 2, 3, 4, 6, 7, 8, 9, 10, 11, 13 for
    run_deterministic_acquisition -- exercised against a real (not
    mocked) InvestigationContext/RepositoryIndex, same convention as the
    rest of this module's slice-builder tests."""

    def test_complete_initial_readiness_performs_no_acquisition_work(self):
        """Test 13."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition,
        )
        slice_result = _make_slice_result(covered_target_symbols=["a.py:X"])
        edit = IntendedEdit(file="a.py", symbol="a.py:X")
        readiness = check_edit_readiness([edit], slice_result)
        assert readiness.edit_source_ready is True

        result = run_deterministic_acquisition(
            _make_strategy(target_symbols=["a.py:X"]), None, None, slice_result, readiness,
        )
        assert result.rounds_used == 0
        assert result.attempts == []
        assert result.slice_result is slice_result

    def test_unresolved_symbol_becomes_ready_after_retrieval(self, tmp_path):
        """Test 2. Simulates an initial pass that, for whatever reason
        (e.g. a transient failure while processing OTHER targets in the
        same build_final_target_slice call -- see that function's own
        except-branch), never resolved this symbol at all, even though
        the repository itself genuinely has it. A per-edit retrieval
        attempt is isolated from whatever caused the original failure,
        so it succeeds where the (simulated) initial pass didn't."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition,
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")

        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)
        assert initial_readiness.unready_edits[0].reason == "unresolved_symbol"

        result = run_deterministic_acquisition(strategy, str(tmp_path), context, initial_slice, initial_readiness)
        assert result.rounds_used >= 1
        assert result.attempts[0].success is True
        final_readiness = check_edit_readiness([edit], result.slice_result)
        assert final_readiness.edit_source_ready is True

    def test_file_level_edit_becomes_ready_via_identifier_definition(self, tmp_path):
        """Test 3."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition,
        )
        (tmp_path / "policy.py").write_text(
            "class Policy:\n    ALLOWED_VALUES = frozenset(['a'])\n", encoding="utf-8",
        )
        context = _make_context(constants={"policy.py": {
            "Policy.ALLOWED_VALUES": {
                "qualified_name": "Policy.ALLOWED_VALUES", "class_name": "Policy",
                "name": "ALLOWED_VALUES", "line": 2, "end_line": 2,
            },
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["policy.py"], extended_mechanism="Policy.ALLOWED_VALUES")
        edit = IntendedEdit(file="policy.py", symbol=None)

        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)
        assert initial_readiness.unready_edits[0].reason == "missing_target_source"

        result = run_deterministic_acquisition(strategy, str(tmp_path), context, initial_slice, initial_readiness)
        final_readiness = check_edit_readiness([edit], result.slice_result)
        assert final_readiness.edit_source_ready is True
        assert "policy.py" in result.slice_result.identifier_definition_covered

    def test_unrelated_same_file_match_never_satisfies_readiness(self, tmp_path):
        """Test 4. A strategy-derived term that is only USED (not
        defined) inside the target file must never satisfy a file-level
        edit -- a usage window is supporting-context, never an edit
        target or an identifier definition. Since transactional
        acquisition (_try_commit_acquisition) now rolls back any
        candidate that never makes its own targeted edit ready, this
        usage window is never committed into the running slice at all
        -- so the file stays entirely uncovered ("missing_target_source"),
        never partially covered by content that could never have
        satisfied it anyway ("missing_identifier", the OLD, non-
        transactional outcome asserted here before this fix)."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition,
        )
        (tmp_path / "consumer.py").write_text(
            "class C:\n    def m(self):\n        SOME_TERM\n        return 1\n", encoding="utf-8",
        )
        context = _make_context(functions={
            "consumer.py:C.m": {
                "name": "m", "className": "C", "startLine": 2, "endLine": 4,
                "code": "    def m(self):\n        SOME_TERM\n        return 1\n",
            },
        }, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["consumer.py"], extended_mechanism="SOME_TERM")
        edit = IntendedEdit(file="consumer.py", symbol=None)

        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)

        result = run_deterministic_acquisition(strategy, str(tmp_path), context, initial_slice, initial_readiness)
        final_readiness = check_edit_readiness([edit], result.slice_result)
        assert final_readiness.edit_source_ready is False
        assert final_readiness.unready_edits[0].reason == "missing_target_source"
        assert result.slice_result is initial_slice  # rolled back -- nothing committed

    def test_never_promotes_ambiguous_one_hop_candidate(self, tmp_path):
        """Test 5, part 2 (behavioral, through acquisition): the edit
        target itself becomes ready, but an ambiguous SCREAMING_SNAKE_CASE
        reference inside it is never promoted via one-hop, exactly as
        the existing (unmodified) one-hop step already guarantees."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition,
        )
        (tmp_path / "consumer.py").write_text(
            "class X:\n    AMBIG = 1\n\n\nclass Y:\n    AMBIG = 2\n\n\ndef m():\n    return AMBIG\n",
            encoding="utf-8",
        )
        context = _make_context(
            functions={"consumer.py:m": {
                "name": "m", "className": None, "startLine": 9, "endLine": 10,
                "code": "def m():\n    return AMBIG\n",
            }},
            constants={"consumer.py": {
                "X.AMBIG": {"qualified_name": "X.AMBIG", "class_name": "X", "name": "AMBIG", "line": 2, "end_line": 2},
                "Y.AMBIG": {"qualified_name": "Y.AMBIG", "class_name": "Y", "name": "AMBIG", "line": 6, "end_line": 6},
            }},
            repo_path=tmp_path,
        )
        strategy = _make_strategy(target_files=["consumer.py"], target_symbols=["consumer.py:m"])
        edit = IntendedEdit(file="consumer.py", symbol="consumer.py:m")

        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)

        result = run_deterministic_acquisition(strategy, str(tmp_path), context, initial_slice, initial_readiness)
        final_readiness = check_edit_readiness([edit], result.slice_result)
        assert final_readiness.edit_source_ready is True  # the edit target itself resolves fine
        assert "AMBIG = 1" not in result.slice_result.rendered
        assert "AMBIG = 2" not in result.slice_result.rendered

    def test_retrieval_respects_the_verified_target_file(self, tmp_path):
        """Test 6. Two files share a same-named constant; the edit names
        one specific file, and retrieval must resolve to exactly that
        file's own definition, never the other's."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition,
        )
        (tmp_path / "a.py").write_text("CONST_A = 1\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("CONST_A = 2\n", encoding="utf-8")
        context = _make_context(constants={
            "a.py": {"CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1}},
            "b.py": {"CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1}},
        }, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["a.py"], target_symbols=["a.py:CONST_A"])
        edit = IntendedEdit(file="a.py", symbol="a.py:CONST_A")

        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)

        result = run_deterministic_acquisition(strategy, str(tmp_path), context, initial_slice, initial_readiness)
        assert result.attempts[0].resolved_file == "a.py"
        assert "CONST_A = 2" not in result.slice_result.rendered

    def test_edit_target_source_ordered_ahead_of_supporting_context(self, tmp_path, monkeypatch):
        """Test 7 -- mirrors TestEditTargetOrderedBeforeSupportingContext,
        through run_deterministic_acquisition's own per-round budget: a
        round budget too small for both the function edit target and its
        one-hop constant must still include the edit target."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition,
        )
        file_text = (
            "class Mod:\n    CONST_X = 1\n\n    def target_func(self):\n        return CONST_X\n"
        )
        (tmp_path / "mod.py").write_text(file_text, encoding="utf-8")
        context = _make_context(
            functions={"mod.py:Mod.target_func": {
                "name": "target_func", "className": "Mod", "startLine": 4, "endLine": 5,
                "code": "    def target_func(self):\n        return CONST_X\n",
            }},
            constants={"mod.py": {"Mod.CONST_X": {
                "qualified_name": "Mod.CONST_X", "class_name": "Mod", "name": "CONST_X",
                "line": 2, "end_line": 2,
            }}},
            repo_path=tmp_path,
        )
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:Mod.target_func"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:Mod.target_func")

        # A round budget that fits the function alone but not the
        # one-hop constant too (measured the same way the existing
        # ordering test measures it).
        monkeypatch.setattr(rp, "FINAL_TARGET_SLICE_MAX_CHARS", 1_000_000)
        full_result = rp.build_final_target_slice(strategy, str(tmp_path), context)
        assert "CONST_X = 1" in full_result.rendered
        tight_budget = max(1, len(full_result.rendered) - len("CONST_X = 1") - 50)
        monkeypatch.setattr(rp, "MAX_NEW_SOURCE_CHARS_PER_ROUND", tight_budget)

        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)
        result = run_deterministic_acquisition(strategy, str(tmp_path), context, initial_slice, initial_readiness)

        assert "target_func" in result.slice_result.rendered
        final_readiness = check_edit_readiness([edit], result.slice_result)
        assert final_readiness.edit_source_ready is True

    def test_stops_immediately_once_readiness_is_complete(self, tmp_path):
        """Test 8. Two edits, both resolvable in round 1 -- rounds_used
        must be 1, never running the second (unnecessary) round."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition,
        )
        (tmp_path / "a.py").write_text("CONST_A = 1\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("CONST_B = 2\n", encoding="utf-8")
        context = _make_context(constants={
            "a.py": {"CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1}},
            "b.py": {"CONST_B": {"qualified_name": "CONST_B", "class_name": None, "name": "CONST_B", "line": 1, "end_line": 1}},
        }, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["a.py", "b.py"], target_symbols=["a.py:CONST_A", "b.py:CONST_B"])
        edits = [IntendedEdit(file="a.py", symbol="a.py:CONST_A"), IntendedEdit(file="b.py", symbol="b.py:CONST_B")]

        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness(edits, initial_slice)
        result = run_deterministic_acquisition(strategy, str(tmp_path), context, initial_slice, initial_readiness)

        assert result.rounds_used == 1
        final_readiness = check_edit_readiness(edits, result.slice_result)
        assert final_readiness.edit_source_ready is True

    def test_stops_after_max_rounds_when_never_ready(self, tmp_path):
        """Test 9. A symbol that never resolves stays unready every
        round -- the loop must still terminate at MAX_ACQUISITION_ROUNDS,
        never looping indefinitely."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition,
        )
        (tmp_path / "mod.py").write_text("x = 1\n", encoding="utf-8")
        context = _make_context(repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:NoSuchSymbol"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:NoSuchSymbol")

        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)
        result = run_deterministic_acquisition(strategy, str(tmp_path), context, initial_slice, initial_readiness)

        assert result.rounds_used == rp.MAX_ACQUISITION_ROUNDS
        final_readiness = check_edit_readiness([edit], result.slice_result)
        assert final_readiness.edit_source_ready is False

    def test_per_round_character_limit_is_enforced(self, tmp_path, monkeypatch):
        """Test 10. A round budget too small for an otherwise-resolvable
        target's own block must be DIAGNOSED as "target_budget_exhausted"
        for this attempt -- never silently spend the full remaining
        TOTAL budget instead of the smaller per-round cap. Since
        transactional acquisition (_try_commit_acquisition) rolls back
        any candidate that doesn't make its own edit ready, that
        diagnosis lives on the ATTEMPT itself (`attempts[0].
        failure_reason`); the PERSISTED slice/readiness is untouched by
        the rolled-back candidate, so re-deriving readiness from
        `result.slice_result` now correctly shows whatever the edit's
        readiness was BEFORE this attempt ("unresolved_symbol" here,
        never "target_budget_exhausted" -- that would incorrectly imply
        the budget-exhausted attempt left some trace behind)."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition,
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")

        monkeypatch.setattr(rp, "MAX_NEW_SOURCE_CHARS_PER_ROUND", 1)  # far smaller than any real block
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)
        result = run_deterministic_acquisition(strategy, str(tmp_path), context, initial_slice, initial_readiness)

        assert result.attempts[0].failure_reason == "target_budget_exhausted"
        assert result.slice_result is initial_slice  # rolled back -- nothing committed
        final_readiness = check_edit_readiness([edit], result.slice_result)
        assert final_readiness.edit_source_ready is False
        assert final_readiness.unready_edits[0].reason == initial_readiness.unready_edits[0].reason

    def test_total_budget_exhaustion_fails_closed(self, tmp_path):
        """Test 11. When the slice already consumed the entire hard total
        budget, acquisition must refuse to add anything more (available
        <= 0) and fail closed -- never exceed FINAL_TARGET_SLICE_MAX_CHARS."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition,
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")

        # Simulate a slice that already consumed the entire hard budget.
        initial_slice = _make_slice_result(rendered="x" * rp.FINAL_TARGET_SLICE_MAX_CHARS)
        initial_readiness = check_edit_readiness([edit], initial_slice)
        result = run_deterministic_acquisition(strategy, str(tmp_path), context, initial_slice, initial_readiness)

        assert result.attempts[0].success is False
        assert result.attempts[0].failure_reason == "target_budget_exhausted"
        assert len(result.slice_result.rendered) == rp.FINAL_TARGET_SLICE_MAX_CHARS  # nothing more added


class TestTransactionalAcquisition:
    """Regression coverage for the urllib3-run fix: acquisition candidates
    (Slice 2's run_deterministic_acquisition and Slice 3's
    run_guided_acquisition) must be committed transactionally --
    _try_commit_acquisition merges one candidate into a TEMPORARY working
    slice, recomputes Edit Readiness, and only actually advances the
    running slice (and only then lets the caller deduct from its own
    round/total character budget) when that merge made the checked
    edit(s) ready. Before this fix, a candidate that never improved
    readiness was still merged permanently and still consumed budget --
    exactly what made a LATER, more accurate attempt fail with
    "target_budget_exhausted"/"context_request_limit_reached" purely
    because an earlier, unhelpful one had already spent shared budget."""

    def test_unsuccessful_acquisition_is_rolled_back(self, tmp_path):
        """Test 1. A candidate that resolves and renders fine, but never
        makes its OWN targeted edit ready, must be rolled back --
        _try_commit_acquisition returns the ORIGINAL slice unchanged,
        never the merged one, and reports committed=False."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, _try_commit_acquisition, build_final_target_slice,
        )
        (tmp_path / "consumer.py").write_text(
            "class C:\n    def m(self):\n        SOME_TERM\n        return 1\n", encoding="utf-8",
        )
        context = _make_context(functions={
            "consumer.py:C.m": {
                "name": "m", "className": "C", "startLine": 2, "endLine": 4,
                "code": "    def m(self):\n        SOME_TERM\n        return 1\n",
            },
        }, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["consumer.py"], extended_mechanism="SOME_TERM")
        edit = IntendedEdit(file="consumer.py", symbol=None)

        current_slice = _make_slice_result()
        addition = build_final_target_slice(strategy, str(tmp_path), context, planner_evidence_files=())
        assert addition.rendered  # a genuine, non-empty usage-window candidate

        slice_to_use, readiness, committed = _try_commit_acquisition(current_slice, addition, strategy, [edit])
        assert committed is False
        assert slice_to_use is current_slice
        assert slice_to_use.rendered == ""

    def test_rolled_back_acquisition_does_not_consume_budget(self, tmp_path, monkeypatch):
        """Test 2. Two unready edits in the SAME round: the first's own
        candidate never improves its readiness (rolled back), the second
        needs the round's FULL character budget to succeed. A round
        budget sized to fit ONLY the second edit's block -- never both --
        must still let the second edit succeed, because the first's
        rolled-back candidate must not have deducted anything from
        round_budget_remaining."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition,
        )
        (tmp_path / "consumer.py").write_text(
            "class C:\n    def m(self):\n        SOME_TERM\n        return 1\n", encoding="utf-8",
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(
            functions={"consumer.py:C.m": {
                "name": "m", "className": "C", "startLine": 2, "endLine": 4,
                "code": "    def m(self):\n        SOME_TERM\n        return 1\n",
            }},
            constants={"mod.py": {
                "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
            }},
            repo_path=tmp_path,
        )
        strategy = _make_strategy(
            target_files=["consumer.py", "mod.py"], target_symbols=["mod.py:CONST_A"],
            extended_mechanism="SOME_TERM",
        )
        edit_fail = IntendedEdit(file="consumer.py", symbol=None)
        edit_success = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")
        edits = [edit_fail, edit_success]  # consumer.py's (rolled-back) attempt runs first

        # Room for the CONST_A block alone (~437 chars), never for both
        # it and consumer.py's usage-window candidate (~512 chars) --
        # the OLD, non-transactional code would exhaust this on
        # consumer.py's own never-helps-readiness candidate and leave
        # mod.py unready too.
        monkeypatch.setattr(rp, "MAX_NEW_SOURCE_CHARS_PER_ROUND", 600)

        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness(edits, initial_slice)
        result = run_deterministic_acquisition(strategy, str(tmp_path), context, initial_slice, initial_readiness)

        success_attempt = next(a for a in result.attempts if a.intended_edit == edit_success)
        assert success_attempt.success is True
        assert success_attempt.failure_reason is None

    def test_later_acquisition_can_still_succeed(self, tmp_path, monkeypatch):
        """Test 3. Same setup as Test 2, viewed from the overall outcome:
        the LATER edit's own readiness must actually become ready by the
        end of acquisition, not merely report success on one attempt."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition,
        )
        (tmp_path / "consumer.py").write_text(
            "class C:\n    def m(self):\n        SOME_TERM\n        return 1\n", encoding="utf-8",
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(
            functions={"consumer.py:C.m": {
                "name": "m", "className": "C", "startLine": 2, "endLine": 4,
                "code": "    def m(self):\n        SOME_TERM\n        return 1\n",
            }},
            constants={"mod.py": {
                "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
            }},
            repo_path=tmp_path,
        )
        strategy = _make_strategy(
            target_files=["consumer.py", "mod.py"], target_symbols=["mod.py:CONST_A"],
            extended_mechanism="SOME_TERM",
        )
        edit_fail = IntendedEdit(file="consumer.py", symbol=None)
        edit_success = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")
        edits = [edit_fail, edit_success]

        monkeypatch.setattr(rp, "MAX_NEW_SOURCE_CHARS_PER_ROUND", 600)
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness(edits, initial_slice)
        result = run_deterministic_acquisition(strategy, str(tmp_path), context, initial_slice, initial_readiness)

        final_readiness = check_edit_readiness(edits, result.slice_result)
        success_readiness = check_edit_readiness([edit_success], result.slice_result)
        assert success_readiness.edit_source_ready is True
        assert edit_fail in [u.edit for u in final_readiness.unready_edits]  # never resolvable; unaffected

    def test_committed_acquisition_remains_unchanged(self, tmp_path, monkeypatch):
        """Test 4. Once an edit's candidate IS committed, a LATER,
        different edit's rolled-back attempt (including on a subsequent
        round) must leave the already-committed content completely
        untouched -- same rendered text, same covered symbol."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition,
        )
        (tmp_path / "consumer.py").write_text(
            "class C:\n    def m(self):\n        SOME_TERM\n        return 1\n", encoding="utf-8",
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(
            functions={"consumer.py:C.m": {
                "name": "m", "className": "C", "startLine": 2, "endLine": 4,
                "code": "    def m(self):\n        SOME_TERM\n        return 1\n",
            }},
            constants={"mod.py": {
                "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
            }},
            repo_path=tmp_path,
        )
        strategy = _make_strategy(
            target_files=["consumer.py", "mod.py"], target_symbols=["mod.py:CONST_A"],
            extended_mechanism="SOME_TERM",
        )
        edit_fail = IntendedEdit(file="consumer.py", symbol=None)
        edit_success = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")
        edits = [edit_fail, edit_success]

        monkeypatch.setattr(rp, "MAX_NEW_SOURCE_CHARS_PER_ROUND", 600)
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness(edits, initial_slice)
        result = run_deterministic_acquisition(strategy, str(tmp_path), context, initial_slice, initial_readiness)

        # mod.py:CONST_A committed in round 1; consumer.py keeps being
        # (rolled-back) retried in round 2 since it never resolves --
        # the committed CONST_A content must survive that untouched.
        assert result.rounds_used >= 2
        assert "CONST_A = 1" in result.slice_result.rendered
        assert "mod.py:CONST_A" in result.slice_result.covered_target_symbols
        rendered_after = result.slice_result.rendered
        assert rendered_after.count("CONST_A = 1") == 1  # never re-committed/duplicated

    def test_readiness_identical_before_and_after_rollback(self, tmp_path):
        """Test 5. Rolling back a candidate must leave Edit Readiness
        (for the SAME edits, computed against the slice actually carried
        forward) byte-for-byte identical to what it was before that
        candidate was ever attempted."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, _try_commit_acquisition, build_final_target_slice,
        )
        (tmp_path / "consumer.py").write_text(
            "class C:\n    def m(self):\n        SOME_TERM\n        return 1\n", encoding="utf-8",
        )
        context = _make_context(functions={
            "consumer.py:C.m": {
                "name": "m", "className": "C", "startLine": 2, "endLine": 4,
                "code": "    def m(self):\n        SOME_TERM\n        return 1\n",
            },
        }, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["consumer.py"], extended_mechanism="SOME_TERM")
        edit = IntendedEdit(file="consumer.py", symbol=None)

        current_slice = _make_slice_result()
        readiness_before = check_edit_readiness([edit], current_slice)

        addition = build_final_target_slice(strategy, str(tmp_path), context, planner_evidence_files=())
        slice_to_use, _attempt_readiness, committed = _try_commit_acquisition(
            current_slice, addition, strategy, [edit],
        )
        assert committed is False

        readiness_after = check_edit_readiness([edit], slice_to_use)
        assert readiness_after == readiness_before

    def test_slice3_can_succeed_after_failed_slice2_attempt(self, tmp_path):
        """Test 6. Slice 2's own deterministic attempt for a file-only
        edit rolls back (the strategy's own extended_mechanism only
        names a term that's USED, not defined, in the file). Slice 3's
        subsequent guided request -- naming the identifier that's
        ACTUALLY needed -- must still succeed cleanly afterward, proving
        Slice 2's rolled-back attempt left no trace for Slice 3 to
        inherit (neither in the slice nor in its own budget)."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition, run_guided_acquisition,
        )
        (tmp_path / "policy.py").write_text(
            "class Policy:\n    ALLOWED_VALUES = frozenset(['a'])\n\n\n"
            "def uses_other():\n    OTHER_TERM\n    return 1\n",
            encoding="utf-8",
        )
        context = _make_context(
            functions={"policy.py:uses_other": {
                "name": "uses_other", "className": None, "startLine": 5, "endLine": 7,
                "code": "def uses_other():\n    OTHER_TERM\n    return 1\n",
            }},
            constants={"policy.py": {
                "Policy.ALLOWED_VALUES": {
                    "qualified_name": "Policy.ALLOWED_VALUES", "class_name": "Policy",
                    "name": "ALLOWED_VALUES", "line": 2, "end_line": 2,
                },
            }},
            repo_path=tmp_path,
        )
        strategy = _make_strategy(target_files=["policy.py"], extended_mechanism="OTHER_TERM")
        edit = IntendedEdit(file="policy.py", symbol=None)

        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)

        slice2_result = run_deterministic_acquisition(strategy, str(tmp_path), context, initial_slice, initial_readiness)
        assert all(a.success is False for a in slice2_result.attempts)
        assert slice2_result.slice_result is initial_slice  # rolled back every time

        readiness_after_slice2 = check_edit_readiness([edit], slice2_result.slice_result)
        assert readiness_after_slice2.edit_source_ready is False

        llm = _guided_llm({"context_requests": [{
            "request_type": "identifier_definition", "file_hint": "policy.py",
            "symbol": None, "identifier": "ALLOWED_VALUES", "reason": "need the constant definition",
        }]})
        slice3_result = run_guided_acquisition(
            strategy, "vuln text", llm, str(tmp_path), context,
            slice2_result.slice_result, readiness_after_slice2,
            deterministic_attempts=slice2_result.attempts,
        )
        assert slice3_result.readiness.edit_source_ready is True
        assert "policy.py" in slice3_result.slice_result.identifier_definition_covered


# ---------------------------------------------------------------------------
# Slice 3 -- Bounded LLM-guided pre-patch context retrieval
# ---------------------------------------------------------------------------

def _guided_llm(response_obj):
    llm = mock.MagicMock()
    llm.complete.return_value = json.dumps(response_obj)
    return llm


class TestGuidedAcquisitionNoLLMParameterOnHelpers:
    def test_resolve_guided_symbol_has_no_llm_parameter(self):
        import inspect
        from utilities.autopatcher.remediation_planner import _resolve_guided_symbol
        assert "llm" not in inspect.signature(_resolve_guided_symbol).parameters

    def test_resolve_guided_identifier_has_no_llm_parameter(self):
        import inspect
        from utilities.autopatcher.remediation_planner import _resolve_guided_identifier
        assert "llm" not in inspect.signature(_resolve_guided_identifier).parameters


class TestGuidedAcquisitionSkipping:
    """Tests 1-3."""

    def test_skipped_when_initial_readiness_complete(self):
        """Test 1. No LLM call at all when readiness is already complete."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        slice_result = _make_slice_result(covered_target_symbols=["a.py:X"])
        edit = IntendedEdit(file="a.py", symbol="a.py:X")
        readiness = check_edit_readiness([edit], slice_result)
        assert readiness.edit_source_ready is True

        llm = mock.MagicMock()
        result = run_guided_acquisition(
            _make_strategy(target_symbols=["a.py:X"]), "vuln", llm, "/tmp/repo", None,
            slice_result, readiness,
        )
        assert result.rounds_used == 0
        assert result.attempts == []
        assert not llm.complete.called

    def test_skipped_when_slice_2_makes_readiness_complete(self, tmp_path):
        """Test 2, pipeline level: the same fixture used for Slice 1/2's
        own "complete readiness" pipeline test must still never reach
        Slice 3 -- "guided_context_request" must not appear in
        stage_calls."""
        stage_calls: list = []
        ready_result = mock.MagicMock(
            rendered="## Final-Target Remediation Slice\n\nDEFAULT source\n",
            warning_text="", coverage_complete=True, has_any_coverage=True,
            covered_target_files=["policy.py"], covered_target_symbols=[],
            uncovered_target_files=[], uncovered_target_symbols=[],
            resolved_target_symbols=[], full_file_fallback_covered=["policy.py"],
            identifier_definition_covered=[], edit_target_budget_exhausted=False,
            resolved_symbol_files={},
        )
        harness = TestEditReadinessGatesPatchGeneration()
        mock_gen = harness._run(tmp_path, ready_result, stage_calls)
        assert mock_gen.called
        assert "guided_context_request" not in stage_calls

    def test_runs_only_after_slice_2_remains_incomplete(self, tmp_path):
        """Test 3, pipeline level: when Slice 2 cannot help,
        "guided_context_request" DOES appear in stage_calls."""
        stage_calls: list = []
        unready_result = mock.MagicMock(
            rendered="## Final-Target Remediation Slice\n\nsome unrelated content\n",
            warning_text="", coverage_complete=False, has_any_coverage=True,
            covered_target_files=["policy.py"], covered_target_symbols=[],
            uncovered_target_files=[], uncovered_target_symbols=["policy.py:Policy.ALLOWED_VALUES"],
            resolved_target_symbols=[], full_file_fallback_covered=[],
            identifier_definition_covered=[], edit_target_budget_exhausted=False,
            resolved_symbol_files={},
        )
        harness = TestEditReadinessGatesPatchGeneration()
        harness._run(tmp_path, unready_result, stage_calls)
        assert "guided_context_request" in stage_calls


class TestGuidedAcquisitionResolution:
    """Tests 4, 5, 15: valid requests resolve deterministically and
    improve readiness."""

    def test_valid_symbol_definition_request_resolves_and_improves_readiness(self, tmp_path):
        """Test 4 + Test 15."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)

        llm = _guided_llm({"context_requests": [{
            "request_type": "symbol_definition", "file_hint": "mod.py", "symbol": "mod.py:CONST_A",
            "identifier": None, "reason": "need exact source for the intended edit",
        }]})

        result = run_guided_acquisition(strategy, "vuln text", llm, str(tmp_path), context, initial_slice, initial_readiness)
        assert result.readiness.edit_source_ready is True
        assert result.attempts[0].verified is True
        assert result.attempts[0].readiness_improved is True
        assert result.attempts[0].resolved_file == "mod.py"

    def test_valid_identifier_definition_request_resolves_and_improves_readiness(self, tmp_path):
        """Test 5 + Test 15 (file-level edit)."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "policy.py").write_text(
            "class Policy:\n    ALLOWED_VALUES = frozenset(['a'])\n", encoding="utf-8",
        )
        context = _make_context(constants={"policy.py": {
            "Policy.ALLOWED_VALUES": {
                "qualified_name": "Policy.ALLOWED_VALUES", "class_name": "Policy",
                "name": "ALLOWED_VALUES", "line": 2, "end_line": 2,
            },
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["policy.py"])
        edit = IntendedEdit(file="policy.py", symbol=None)
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)

        llm = _guided_llm({"context_requests": [{
            "request_type": "identifier_definition", "file_hint": "policy.py",
            "symbol": None, "identifier": "ALLOWED_VALUES", "reason": "need the constant's definition",
        }]})

        result = run_guided_acquisition(strategy, "vuln text", llm, str(tmp_path), context, initial_slice, initial_readiness)
        assert result.readiness.edit_source_ready is True
        assert "policy.py" in result.slice_result.identifier_definition_covered


class TestGuidedAcquisitionRejection:
    """Tests 6-14: every way an untrusted request must be rejected or
    ignored, never silently trusted."""

    def test_llm_provided_code_and_line_numbers_are_ignored(self, tmp_path):
        """Tests 6 + 7. Injected fake source/line numbers never reach the
        retrieved slice or the trace -- retrieval always re-reads real
        repository text independently."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)

        llm = _guided_llm({"context_requests": [{
            "request_type": "symbol_definition", "file_hint": "mod.py", "symbol": "mod.py:CONST_A",
            "identifier": None, "reason": "x",
            "code": "CONST_A = 'INJECTED_MALICIOUS_VALUE'",
            "line": 999, "start_line": 999, "end_line": 1000, "diff": "--- fake ---",
        }]})

        result = run_guided_acquisition(strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness)
        assert "INJECTED_MALICIOUS_VALUE" not in result.slice_result.rendered
        assert "--- fake ---" not in result.slice_result.rendered
        assert result.attempts[0].start_line == 1  # real line, never the injected 999
        assert result.readiness.edit_source_ready is True

    def test_unsupported_request_type_is_rejected(self):
        """Test 8."""
        from utilities.autopatcher.remediation_planner import (
            GuidedContextRequest, _validate_guided_request_schema,
        )
        request = GuidedContextRequest(
            intended_edit=None, request_type="shell_exec", file_hint=None,
            symbol="x", identifier=None, reason="y",
        )
        assert _validate_guided_request_schema(request) == "unsupported_request_type"

    def test_unsafe_file_path_is_rejected(self, tmp_path):
        """Test 9."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)

        llm = _guided_llm({"context_requests": [{
            "request_type": "symbol_definition", "file_hint": "../outside.py",
            "symbol": "mod.py:CONST_A", "identifier": None, "reason": "y",
        }]})
        result = run_guided_acquisition(strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness)
        assert result.attempts[0].failure_reason == "unsafe_file_path"
        assert result.readiness.edit_source_ready is False

    def test_unverified_nonexistent_file_hint_is_rejected(self, tmp_path):
        """Test 10. A syntactically-safe but nonexistent file_hint must
        still be rejected -- "unsafe_file_path" is the practical outcome
        _verify_file itself reports for both an unsafe path and a merely
        nonexistent one (it does not distinguish the two)."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)

        llm = _guided_llm({"context_requests": [{
            "request_type": "symbol_definition", "file_hint": "does_not_exist.py",
            "symbol": "mod.py:CONST_A", "identifier": None, "reason": "y",
        }]})
        result = run_guided_acquisition(strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness)
        assert result.attempts[0].failure_reason == "unsafe_file_path"

    def test_ambiguous_symbol_resolution_is_rejected(self, tmp_path):
        """Test 11."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "a.py").write_text("def m():\n    return 1\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("def m():\n    return 2\n", encoding="utf-8")
        context = _make_context(functions={
            "a.py:m": {"name": "m", "className": None, "startLine": 1, "endLine": 2, "code": "def m():\n    return 1\n"},
            "b.py:m": {"name": "m", "className": None, "startLine": 1, "endLine": 2, "code": "def m():\n    return 2\n"},
        }, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["a.py"], target_symbols=["a.py:m"])
        edit = IntendedEdit(file="a.py", symbol="a.py:m")
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)

        llm = _guided_llm({"context_requests": [{
            "request_type": "symbol_definition", "file_hint": None, "symbol": "m",
            "identifier": None, "reason": "y",
        }]})
        result = run_guided_acquisition(strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness)
        assert result.attempts[0].failure_reason == "ambiguous_symbol"
        assert result.readiness.edit_source_ready is False

    def test_cross_file_mismatch_is_rejected(self, tmp_path):
        """Test 12. The requested symbol's own embedded file
        ("a.py:m") contradicts a separately-given file_hint ("other.py")
        -- rejected before any resolution is even attempted."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "a.py").write_text("def m():\n    return 1\n", encoding="utf-8")
        (tmp_path / "other.py").write_text("x = 1\n", encoding="utf-8")
        context = _make_context(functions={
            "a.py:m": {"name": "m", "className": None, "startLine": 1, "endLine": 2, "code": "def m():\n    return 1\n"},
        }, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["a.py"], target_symbols=["a.py:m"])
        edit = IntendedEdit(file="a.py", symbol="a.py:m")
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)

        llm = _guided_llm({"context_requests": [{
            "request_type": "symbol_definition", "file_hint": "other.py",
            "symbol": "a.py:m",  # exact-string attribution match -- ignores file_hint for attribution
            "identifier": None, "reason": "y",
        }]})
        result = run_guided_acquisition(strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness)
        assert result.attempts[0].failure_reason == "cross_file_mismatch"
        assert result.readiness.edit_source_ready is False

    def test_request_unrelated_to_unready_edit_is_rejected(self, tmp_path):
        """Test 13. A request naming a file/symbol that matches NO
        current unready edit must be rejected, never guessed onto one."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\nCONST_B = 2\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
            "CONST_B": {"qualified_name": "CONST_B", "class_name": None, "name": "CONST_B", "line": 2, "end_line": 2},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)

        # Names a real, resolvable symbol -- but NOT the current unready
        # edit's own symbol, and no unready edit shares its file either.
        llm = _guided_llm({"context_requests": [{
            "request_type": "symbol_definition", "file_hint": "mod.py", "symbol": "CONST_B",
            "identifier": None, "reason": "y",
        }]})
        result = run_guided_acquisition(strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness)
        assert result.attempts[0].failure_reason == "unrelated_to_unready_edit"
        assert result.readiness.edit_source_ready is False

    def test_consumer_source_does_not_satisfy_a_separate_edit_target(self, tmp_path):
        """Test 14. An identifier_usage request retrieves a genuine
        consumer/usage window (source IS added, for Patch Generation's
        benefit) but must never mark readiness_improved for the
        attributed (file-level) edit -- only an exact definition/full-
        file-with-identifier can."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "consumer.py").write_text(
            "class C:\n    def m(self):\n        SOME_TERM\n        return 1\n", encoding="utf-8",
        )
        context = _make_context(functions={
            "consumer.py:C.m": {
                "name": "m", "className": "C", "startLine": 2, "endLine": 4,
                "code": "    def m(self):\n        SOME_TERM\n        return 1\n",
            },
        }, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["consumer.py"])
        edit = IntendedEdit(file="consumer.py", symbol=None)
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)

        llm = _guided_llm({"context_requests": [{
            "request_type": "identifier_usage", "file_hint": "consumer.py",
            "symbol": None, "identifier": "SOME_TERM", "reason": "how is it used",
        }]})
        result = run_guided_acquisition(strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness)
        assert result.attempts[0].readiness_improved is False
        assert result.readiness.edit_source_ready is False


class TestGuidedAcquisitionFileOnlyEditSymbolAttribution:
    """Regression coverage for the urllib3-run fix: a symbol_definition/
    enclosing_symbol request naming no existing target_symbol must still
    be attributable to a file-ONLY unready edit (edit.symbol is None) --
    but only when file_hint is an exact match for that edit's own file
    AND the requested symbol was already named by evidence gathered
    before the request ran (_guided_symbol_is_evidence_supported). Before
    this fix, EVERY such request was rejected outright as
    "unrelated_to_unready_edit", regardless of file_hint or evidence, so
    Slice 3 could never help a file-only edit whose Final Strategy named
    no target_symbol -- exactly the urllib3 run's observed failure."""

    def _make_retry_context(self, tmp_path):
        (tmp_path / "retry.py").write_text(
            "def Retry():\n    return 1\n\n\ndef Other():\n    return 2\n", encoding="utf-8",
        )
        return _make_context(functions={
            "retry.py:Retry": {
                "name": "Retry", "className": None, "startLine": 1, "endLine": 2,
                "code": "def Retry():\n    return 1\n",
            },
            "retry.py:Other": {
                "name": "Other", "className": None, "startLine": 4, "endLine": 5,
                "code": "def Other():\n    return 2\n",
            },
        }, repo_path=tmp_path)

    def test_file_only_edit_with_evidence_supported_symbol_is_accepted(self, tmp_path):
        """Test 1. file-only intended edit + related, evidence-supported,
        verified symbol -> accepted (attributed, resolved, and -- via the
        SAME unmodified deterministic retrieval Slice 2/3 already use --
        readiness for the file-only edit actually improves)."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        context = self._make_retry_context(tmp_path)
        strategy = _make_strategy(
            target_files=["retry.py"], required_edits=["Fix the Retry function to cap backoff delay"],
        )
        edit = IntendedEdit(file="retry.py", symbol=None)
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)
        assert initial_readiness.edit_source_ready is False

        llm = _guided_llm({"context_requests": [{
            "request_type": "symbol_definition", "file_hint": "retry.py", "symbol": "Retry",
            "identifier": None, "reason": "need the Retry class definition",
        }]})
        result = run_guided_acquisition(strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness)
        assert result.attempts[0].failure_reason is None
        assert result.attempts[0].verified is True
        assert result.attempts[0].resolved_file == "retry.py"
        assert result.attempts[0].readiness_improved is True
        assert result.readiness.edit_source_ready is True

    def test_file_only_edit_with_unrelated_symbol_is_rejected(self, tmp_path):
        """Test 2. The requested symbol resolves fine INSIDE the right
        file, but was never named anywhere in the evidence gathered so
        far -- must still be rejected, never attributed just because it
        happens to live in the same file."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        context = self._make_retry_context(tmp_path)
        strategy = _make_strategy(
            target_files=["retry.py"], required_edits=["Fix the Retry function to cap backoff delay"],
        )
        edit = IntendedEdit(file="retry.py", symbol=None)
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)

        llm = _guided_llm({"context_requests": [{
            "request_type": "symbol_definition", "file_hint": "retry.py", "symbol": "Other",
            "identifier": None, "reason": "need Other's definition too",
        }]})
        result = run_guided_acquisition(strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness)
        assert result.attempts[0].failure_reason == "unrelated_to_unready_edit"
        assert result.readiness.edit_source_ready is False

    def test_cross_file_symbol_is_rejected(self, tmp_path):
        """Test 3. file_hint matches the file-only edit's own file, and
        the bare symbol name IS evidence-supported -- so attribution
        succeeds -- but the request's own `symbol` string names a
        DIFFERENT file, contradicting the verified file_hint. Rejected
        by the existing, unmodified _resolve_guided_symbol cross-file
        check, never masked as a plain "attributed" success."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        context = self._make_retry_context(tmp_path)
        (tmp_path / "other.py").write_text("x = 1\n", encoding="utf-8")
        strategy = _make_strategy(
            target_files=["retry.py"], required_edits=["Fix the Retry function to cap backoff delay"],
        )
        edit = IntendedEdit(file="retry.py", symbol=None)
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)

        llm = _guided_llm({"context_requests": [{
            "request_type": "symbol_definition", "file_hint": "retry.py", "symbol": "other.py:Retry",
            "identifier": None, "reason": "need Retry",
        }]})
        result = run_guided_acquisition(strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness)
        assert result.attempts[0].failure_reason == "cross_file_mismatch"
        assert result.readiness.edit_source_ready is False

    def test_ambiguous_symbol_without_file_hint_is_rejected(self, tmp_path):
        """Test 4. Two DIFFERENT file-only unready edits both plausibly
        match the same evidence-supported bare symbol name, but the
        request names no file_hint at all -- condition 1 (file_hint must
        resolve EXACTLY to one edit's own file) is never satisfied by
        construction, so the request is rejected rather than guessed
        onto either file."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "a.py").write_text("def Retry():\n    return 1\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("def Retry():\n    return 2\n", encoding="utf-8")
        context = _make_context(functions={
            "a.py:Retry": {"name": "Retry", "className": None, "startLine": 1, "endLine": 2, "code": "def Retry():\n    return 1\n"},
            "b.py:Retry": {"name": "Retry", "className": None, "startLine": 1, "endLine": 2, "code": "def Retry():\n    return 2\n"},
        }, repo_path=tmp_path)
        strategy = _make_strategy(
            target_files=["a.py", "b.py"], required_edits=["Fix Retry in both a.py and b.py"],
        )
        edit_a = IntendedEdit(file="a.py", symbol=None)
        edit_b = IntendedEdit(file="b.py", symbol=None)
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit_a, edit_b], initial_slice)

        llm = _guided_llm({"context_requests": [{
            "request_type": "symbol_definition", "file_hint": None, "symbol": "Retry",
            "identifier": None, "reason": "need Retry, unclear which file",
        }]})
        result = run_guided_acquisition(strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness)
        assert result.attempts[0].failure_reason == "unrelated_to_unready_edit"
        assert result.readiness.edit_source_ready is False

    def test_existing_symbol_level_edit_attribution_is_unaffected(self, tmp_path):
        """Test 5. A symbol-having unready edit (edit.symbol is not
        None) must continue attributing/resolving/improving readiness
        exactly as before this fix, even in the presence of an
        UNRELATED file-only edit in the same unready set -- the new
        file-only branch must never interfere with the pre-existing
        symbol-having path."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        (tmp_path / "other_file.py").write_text("x = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py", "other_file.py"], target_symbols=["mod.py:CONST_A"])
        symbol_edit = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")
        file_only_edit = IntendedEdit(file="other_file.py", symbol=None)
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([symbol_edit, file_only_edit], initial_slice)

        llm = _guided_llm({"context_requests": [{
            "request_type": "symbol_definition", "file_hint": "mod.py", "symbol": "mod.py:CONST_A",
            "identifier": None, "reason": "need exact source for the intended edit",
        }]})
        result = run_guided_acquisition(strategy, "vuln text", llm, str(tmp_path), context, initial_slice, initial_readiness)
        assert result.attempts[0].verified is True
        assert result.attempts[0].readiness_improved is True
        assert result.attempts[0].resolved_file == "mod.py"
        assert "mod.py:CONST_A" in result.slice_result.covered_target_symbols


class TestGuidedAcquisitionBoundsAndStopping:
    """Tests 16-21."""

    def test_stops_immediately_once_readiness_is_complete(self, tmp_path):
        """Test 16. Two edits, both resolvable via one round's requests --
        must not run a second (unnecessary) round."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "a.py").write_text("CONST_A = 1\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("CONST_B = 2\n", encoding="utf-8")
        context = _make_context(constants={
            "a.py": {"CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1}},
            "b.py": {"CONST_B": {"qualified_name": "CONST_B", "class_name": None, "name": "CONST_B", "line": 1, "end_line": 1}},
        }, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["a.py", "b.py"], target_symbols=["a.py:CONST_A", "b.py:CONST_B"])
        edits = [IntendedEdit(file="a.py", symbol="a.py:CONST_A"), IntendedEdit(file="b.py", symbol="b.py:CONST_B")]
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness(edits, initial_slice)

        llm = _guided_llm({"context_requests": [
            {"request_type": "symbol_definition", "file_hint": "a.py", "symbol": "a.py:CONST_A", "identifier": None, "reason": "y"},
            {"request_type": "symbol_definition", "file_hint": "b.py", "symbol": "b.py:CONST_B", "identifier": None, "reason": "y"},
        ]})
        result = run_guided_acquisition(strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness)

        assert result.rounds_used == 1
        assert result.readiness.edit_source_ready is True
        assert llm.complete.call_count == 1

    def test_max_rounds_are_enforced(self, tmp_path):
        """Test 17. A request that never resolves stays unready every
        round -- the loop must still terminate at
        MAX_GUIDED_ACQUISITION_ROUNDS, never looping indefinitely, and
        must call the LLM exactly that many times (never more)."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "mod.py").write_text("x = 1\n", encoding="utf-8")
        context = _make_context(repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:NoSuchSymbol"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:NoSuchSymbol")
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)

        llm = _guided_llm({"context_requests": [{
            "request_type": "symbol_definition", "file_hint": "mod.py", "symbol": "mod.py:NoSuchSymbol",
            "identifier": None, "reason": "y",
        }]})
        result = run_guided_acquisition(strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness)

        assert result.rounds_used == rp.MAX_GUIDED_ACQUISITION_ROUNDS
        assert llm.complete.call_count == rp.MAX_GUIDED_ACQUISITION_ROUNDS
        assert result.readiness.edit_source_ready is False

    def test_request_count_limits_are_enforced(self, tmp_path):
        """Test 18: MAX_CONTEXT_REQUESTS_PER_ROUND and
        MAX_CONTEXT_REQUESTS_PER_EDIT are both enforced."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "mod.py").write_text("x = 1\n", encoding="utf-8")
        context = _make_context(repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:NoSuchSymbol"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:NoSuchSymbol")
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)

        # 3 requests offered in one round; only MAX_CONTEXT_REQUESTS_PER_ROUND (2) attempted.
        llm = _guided_llm({"context_requests": [
            {"request_type": "symbol_definition", "file_hint": "mod.py", "symbol": "mod.py:NoSuchSymbol", "identifier": None, "reason": "1"},
            {"request_type": "symbol_definition", "file_hint": "mod.py", "symbol": "mod.py:NoSuchSymbol", "identifier": None, "reason": "2"},
            {"request_type": "symbol_definition", "file_hint": "mod.py", "symbol": "mod.py:NoSuchSymbol", "identifier": None, "reason": "3"},
        ]})
        result = run_guided_acquisition(strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness)
        round_1_attempts = [a for a in result.attempts if a.round == 1]
        assert len(round_1_attempts) == rp.MAX_CONTEXT_REQUESTS_PER_ROUND

        # Across all rounds, at most MAX_CONTEXT_REQUESTS_PER_EDIT attempts
        # are ever actually PROCESSED (not immediately rejected for
        # already being at the per-edit cap) for the same edit -- 2
        # rounds * 2/round = 4 offered total for the one edit; cap is 2,
        # so the other 2 must be rejected with "context_request_limit_reached".
        processed_for_edit = [
            a for a in result.attempts
            if a.request.intended_edit is not None and a.failure_reason != "context_request_limit_reached"
        ]
        assert len(processed_for_edit) <= rp.MAX_CONTEXT_REQUESTS_PER_EDIT
        assert any(a.failure_reason == "context_request_limit_reached" for a in result.attempts)

    def test_source_character_limits_are_enforced(self, tmp_path, monkeypatch):
        """Test 19. A per-round budget too small for an otherwise-
        resolvable target's own block must leave it unready with
        "target_budget_exhausted" -- never silently spend the full
        remaining TOTAL budget instead of the smaller per-round cap."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)

        monkeypatch.setattr(rp, "MAX_GUIDED_SOURCE_CHARS_PER_ROUND", 1)  # far smaller than any real block
        llm = _guided_llm({"context_requests": [{
            "request_type": "symbol_definition", "file_hint": "mod.py", "symbol": "mod.py:CONST_A",
            "identifier": None, "reason": "y",
        }]})
        result = run_guided_acquisition(strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness)
        assert result.attempts[0].failure_reason == "target_budget_exhausted"
        assert result.readiness.edit_source_ready is False

    def test_malformed_json_fails_closed(self, tmp_path):
        """Test 20."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)

        llm = mock.MagicMock()
        llm.complete.return_value = "not json at all {{{"
        result = run_guided_acquisition(strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness)
        assert result.attempts == []
        assert result.readiness.edit_source_ready is False

    def test_empty_request_list_fails_closed(self, tmp_path):
        """Test 21."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)

        llm = _guided_llm({"context_requests": []})
        result = run_guided_acquisition(strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness)
        assert result.attempts == []
        assert result.readiness.edit_source_ready is False


class TestGuidedAcquisitionCallDiscipline:
    """Tests 22, 23, 25: exactly one narrow LLM call per round, never the
    Patch Generator/Planner/Final Strategy, and final incomplete readiness
    still skips Patch Generation."""

    def test_no_patch_generator_call_during_guided_acquisition(self, tmp_path):
        """Test 22 + Test 25, pipeline level."""
        stage_calls: list = []
        unready_result = mock.MagicMock(
            rendered="## Final-Target Remediation Slice\n\nsome unrelated content\n",
            warning_text="", coverage_complete=False, has_any_coverage=True,
            covered_target_files=["policy.py"], covered_target_symbols=[],
            uncovered_target_files=[], uncovered_target_symbols=["policy.py:Policy.ALLOWED_VALUES"],
            resolved_target_symbols=[], full_file_fallback_covered=[],
            identifier_definition_covered=[], edit_target_budget_exhausted=False,
            resolved_symbol_files={},
        )
        harness = TestEditReadinessGatesPatchGeneration()
        mock_gen = harness._run(tmp_path, unready_result, stage_calls)
        assert not mock_gen.called
        assert "guided_context_request" in stage_calls

    def test_planner_and_final_strategy_not_rerun(self, tmp_path):
        """Test 23. Exactly one remediation_planning and one
        remediation_strategy call, no matter how many guided rounds ran."""
        stage_calls: list = []
        unready_result = mock.MagicMock(
            rendered="## Final-Target Remediation Slice\n\nsome unrelated content\n",
            warning_text="", coverage_complete=False, has_any_coverage=True,
            covered_target_files=["policy.py"], covered_target_symbols=[],
            uncovered_target_files=[], uncovered_target_symbols=["policy.py:Policy.ALLOWED_VALUES"],
            resolved_target_symbols=[], full_file_fallback_covered=[],
            identifier_definition_covered=[], edit_target_budget_exhausted=False,
            resolved_symbol_files={},
        )
        harness = TestEditReadinessGatesPatchGeneration()
        harness._run(tmp_path, unready_result, stage_calls)
        assert stage_calls.count("remediation_planning") == 1
        assert stage_calls.count("remediation_strategy") == 1
        from utilities.autopatcher import remediation_planner as rp
        assert stage_calls.count("guided_context_request") == rp.MAX_GUIDED_ACQUISITION_ROUNDS


class TestGuidedAcquisitionRecommendationPolicyUnaffected:
    """Test 24."""

    def test_build_recommendation_v1_does_not_read_guided_acquisition(self):
        import inspect
        from utilities.autopatcher.pipeline import _build_recommendation_v1
        source = inspect.getsource(_build_recommendation_v1)
        assert "guided_acquisition" not in source
        assert "edit_readiness" not in source


class TestGuidedAcquisitionTraceArtifact:
    """Test 26."""

    def test_trace_artifact_contains_deterministic_and_guided_states(self, tmp_path, monkeypatch):
        import json as _json
        import os as _os

        stage_calls: list = []
        unready_result = mock.MagicMock(
            rendered="## Final-Target Remediation Slice\n\nsome unrelated content\n",
            warning_text="", coverage_complete=False, has_any_coverage=True,
            covered_target_files=["policy.py"], covered_target_symbols=[],
            uncovered_target_files=[], uncovered_target_symbols=["policy.py:Policy.ALLOWED_VALUES"],
            resolved_target_symbols=[], full_file_fallback_covered=[],
            identifier_definition_covered=[], edit_target_budget_exhausted=False,
            resolved_symbol_files={},
        )
        monkeypatch.setenv("AUTOPATCHER_DEBUG", "1")
        monkeypatch.chdir(tmp_path)
        harness = TestEditReadinessGatesPatchGeneration()
        # _run() itself writes into tmp_path/policy.py -- give it a fresh subdir.
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        harness._run(run_dir, unready_result, stage_calls)

        debug_dir = tmp_path / "reports" / "debug"
        files = list(debug_dir.glob("edit_readiness_*.json"))
        assert len(files) == 1
        doc = _json.loads(files[0].read_text(encoding="utf-8"))
        for key in (
            "initial_edit_readiness", "deterministic_acquisition",
            "readiness_after_deterministic_acquisition", "guided_acquisition",
            "final_edit_readiness", "patch_generation_skipped",
        ):
            assert key in doc
        assert doc["guided_acquisition"]["rounds"] >= 1
        assert "requests" in doc["guided_acquisition"]
        assert "verification_results" in doc["guided_acquisition"]
        assert doc["patch_generation_skipped"] is True
