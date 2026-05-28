"""Regression test — python parse_repository analyzer_output omits the call graph.

generate_analyzer_output() emitted only {"functions": {...}}, dropping the top-level callGraph /
reverseCallGraph that the analyzer_output schema carries (per the JS reference dependency_resolver +
PARSER_UPGRADE_PLAN) and that are already computed in call_graph_result. (The indirect_calls part of the
original filing is phantom and is excluded; filePath is derived from the func_id key by consumers
(RepositoryIndex / dependency_resolver do funcId.split(':')[0]), so it is not a per-function field.)
Fix: pass call_graph_result in and emit top-level callGraph / reverseCallGraph.
"""
import sys
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]  # libs/openant-core
sys.path.insert(0, str(CORE))
sys.path.insert(0, str(CORE / "parsers" / "python"))  # parse_repository's bare imports

import parse_repository  # noqa: E402

EXTRACTOR = {"functions": {
    "f.py:foo": {"name": "foo", "code": "def foo():\n    bar()", "unit_type": "function", "start_line": 1, "end_line": 2},
    "f.py:bar": {"name": "bar", "code": "def bar():\n    pass", "unit_type": "function", "start_line": 4, "end_line": 5},
}}
CALL_GRAPH = {
    "repository": "/x", "functions": EXTRACTOR["functions"], "classes": {}, "imports": {},
    "call_graph": {"f.py:foo": ["f.py:bar"]},
    "reverse_call_graph": {"f.py:bar": ["f.py:foo"]},
    "statistics": {},
}


def test_analyzer_output_includes_call_graph():
    """Post-fix: the analyzer output surfaces the top-level callGraph / reverseCallGraph from
    call_graph_result. Pre-fix generate_analyzer_output took only the extractor result (no call graph)."""
    out = parse_repository.generate_analyzer_output(EXTRACTOR, CALL_GRAPH)
    assert out["functions"]["f.py:foo"]["name"] == "foo"  # functions unchanged
    assert out.get("callGraph") == {"f.py:foo": ["f.py:bar"]}, f"callGraph missing/empty: {out.get('callGraph')!r}"
    assert out.get("reverseCallGraph") == {"f.py:bar": ["f.py:foo"]}, f"reverseCallGraph missing: {out.get('reverseCallGraph')!r}"


def test_analyzer_output_backward_compatible_without_call_graph():
    """Guard: with only the extractor result (no call graph), it still returns functions and simply omits
    the call-graph keys (back-compat for any 1-arg caller)."""
    out = parse_repository.generate_analyzer_output(EXTRACTOR)
    assert "functions" in out and out["functions"]["f.py:bar"]["name"] == "bar"
