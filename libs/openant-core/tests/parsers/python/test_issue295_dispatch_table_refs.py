"""Regression tests for issue #295 — dispatch-table targets are pruned with
their dispatcher kept.

The Python call-graph builder created an edge only when a function was
CALLED BY NAME. A function referenced as a dict-literal value or list
element — the standard dispatch-table pattern — produced no edge at all,
so live primary-flow code was excluded from analysis while the entry
point that reaches it was retained (confirmed in the wild: a prompt-defence
module's six `_TAG_RENDERERS[...]` targets were pruned with `build_prompt`
kept; 5,370 of 10,845 units pruned on that run).

The principle — a function reference that is not a call is still a
reachability edge — was already accepted twice in this file (name=func
bindings via _build_alias_map; f(func) callback args). A container literal
is the third member of that family, plus the dispatcher's subscript call.

Contract locked here (the issue's fixture, three reference shapes):
- no handler ends up with an empty caller set (suggestion 4);
- the DISPATCHER gets outgoing edges to every function its tables
  reference (HANDLERS[mode]() style subscript calls — suggestion 3), so
  targets sit on a path from the entry point, not merely off the module;
- a container-literal reference produces an edge from the enclosing unit
  (suggestion 1);
- the three forms — dict literal, list element, dict(...) kwarg — behave
  the same (the asymmetry was the tell);
- a subscript call over an UNKNOWN name still records nothing (no
  invented edges), and builtin names in containers are ignored.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from parsers.python.call_graph_builder import CallGraphBuilder  # noqa: E402
from parsers.python.function_extractor import FunctionExtractor  # noqa: E402


def _build(tmp_path: Path, source: str) -> CallGraphBuilder:
    (tmp_path / "app.py").write_text(textwrap.dedent(source))
    ex = FunctionExtractor(str(tmp_path))
    units = ex.extract_all()
    cg = CallGraphBuilder(units)
    cg.build_call_graph()
    return cg


_FIXTURE = """
    def handler_a(): return 1
    def handler_b(): return 2
    def handler_c(): return 3

    HANDLERS = {'a': handler_a}          # dict literal value
    LIST_REF = [handler_b]               # list element
    BUILT    = dict(c=handler_c)         # dict() call kwarg

    def main():
        mode = "a"
        HANDLERS[mode]()
        LIST_REF[0]()
        BUILT["c"]()
"""


def test_no_handler_has_empty_caller_set(tmp_path):
    cg = _build(tmp_path, _FIXTURE)
    for h in ("handler_a", "handler_b", "handler_c"):
        key = next(k for k in cg.call_graph if k.endswith(":" + h))
        callers = cg.reverse_call_graph.get(key, [])
        assert callers, f"{h} must have at least one caller (issue #295)"


def test_dispatcher_has_outgoing_edges_to_all_table_targets(tmp_path):
    """The pruning fix: the DISPATCHER (entry point) must reach its table
    targets, so they sit on a path from an entry point — a module-unit
    reference edge alone leaves them pruned when the module unit is not
    reachable."""
    cg = _build(tmp_path, _FIXTURE)
    main_edges = cg.call_graph.get("app.py:main", [])
    for h in ("handler_a", "handler_b", "handler_c"):
        assert f"app.py:{h}" in main_edges, (
            f"main's subscript dispatch must edge to {h}; got {main_edges}")


def test_container_literal_reference_edges_from_module(tmp_path):
    """Suggestion 1: a container-literal reference is an edge from the
    enclosing (module) scope — the family precedent (alias map, callback
    args) extended to dict/list literals."""
    cg = _build(tmp_path, _FIXTURE)
    for h in ("handler_a", "handler_b", "handler_c"):
        key = f"app.py:{h}"
        callers = cg.reverse_call_graph.get(key, [])
        assert "app.py:__module__" in callers, (h, callers)


def test_local_container_in_function_scope(tmp_path):
    """A table built INSIDE a function: the literal reference edge comes
    from that function, and the local subscript dispatch resolves."""
    cg = _build(tmp_path, """
        def h1(): return 1
        def h2(): return 2

        def dispatch(k):
            table = {'x': h1, 'y': h2}
            return table[k]()
    """)
    edges = cg.call_graph.get("app.py:dispatch", [])
    assert "app.py:h1" in edges and "app.py:h2" in edges, edges


def test_unknown_subscript_records_nothing(tmp_path):
    """Negative control: a subscript call over a name we never saw bound to
    a container of known functions records nothing — edges are only added,
    never invented."""
    cg = _build(tmp_path, """
        def h1(): return 1
        def main():
            data = load()          # unknown function
            return data['k']()     # subscript over non-container
    """)
    assert cg.call_graph.get("app.py:main", []) == []


def test_rebound_container_is_dropped_not_guessed(tmp_path):
    """A MODULE-scope name rebound to a different container: ambiguous for
    a per-name map — dispatch through it records nothing for main. The
    literal REFERENCE edges still hold (attributed to __module__, where the
    assignments live), which is exactly how the two edge sources differ."""
    cg = _build(tmp_path, """
        def h1(): return 1
        def h2(): return 2

        table = {'x': h1}
        table = {'y': h2}

        def main():
            return table['x']()
    """)
    main_edges = cg.call_graph.get("app.py:main", [])
    assert main_edges == [], (
        "dispatch through a rebound (ambiguous) container must record "
        f"nothing; got {main_edges}")
    # the reference edges belong to the module, where the literals live
    for h in ("h1", "h2"):
        assert "app.py:__module__" in cg.reverse_call_graph.get(
            f"app.py:{h}", [])


def test_builtin_names_in_containers_ignored(tmp_path):
    cg = _build(tmp_path, """
        def main():
            ops = {'p': print, 'l': len}
            return ops['p']('x')
    """)
    assert cg.call_graph.get("app.py:main", []) == []
