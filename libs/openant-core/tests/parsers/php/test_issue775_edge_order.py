"""Regression tests for #775: the PHP parser consumes its call-graph
edge lists unsorted — the #754 class, filed from its review cycle. (The Ruby
half lives at tests/parsers/ruby/test_issue775_edge_order.py; the C sibling
is #776, open.)

`parsers/php/call_graph_builder.py` and `parsers/ruby/call_graph_builder.py`
each build a caller's callee set in a `set()` (the tree-sitter path's
`_extract_calls_from_code` returns `Set[str]`) and the consumer filters that
set into a list WITHOUT sorting it, so every function's edge ORDER is whatever
the process's string hashing produced. The surfaces that follow that order are
the same class the C parser's #754 measured: `call_graph[func_id]` itself,
`reverse_call_graph`'s key-creation order (appended while iterating the
forward list), and the downstream artifacts (`call_graph.json` /
`dataset.json`) whose byte content permutes per seed — breaking byte-diff
comparisons and artifact checks.

The repair is the one line the C fix (PR #776) and the Python parser already
carry at their own consumers: `sorted(...)`.

The seed-varied rows drive the product's own `CallGraphBuilder` in fresh
interpreters with only `PYTHONHASHSEED` changed — the same control shape the
C fix's tests (PR #84's include-map family, #754's edge-order file) use.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[3]  # libs/openant-core
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

pytest.importorskip("tree_sitter_php")
from parsers.php.call_graph_builder import CallGraphBuilder as PhpBuilder  # noqa: E402

SEEDS = ("0", "1", "2", "3", "4", "7", "11")

# Eight same-file callees, so the unsorted set has 8! orders available and
# the hash seed reliably moves it. Names deliberately NOT in call-site order,
# so "sorted" is distinguishable from "source order" too.
CALLEES = ("alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta")

_PHP_MAIN = " ".join("%s();" % c for c in CALLEES)
_PHP_FN = "function %s() { /* %s */ }"

def _fixture(lang, main_code, fn_fmt):
    fns = {
        "main.%s:main" % lang: {
            "name": "main", "file_path": "main.%s" % lang, "code": main_code},
    }
    for c in CALLEES:
        fns["main.%s:%s" % (lang, c)] = {
            "name": c, "file_path": "main.%s" % lang,
            "code": fn_fmt % (c, c)}
    return {"functions": fns, "repository": "/r"}


def _driver(lang):
    return (
        "import json, sys; sys.path.insert(0, %r);"
        "from parsers.%s.call_graph_builder import CallGraphBuilder;"
        "eo = json.loads(sys.stdin.read());"
        "b = CallGraphBuilder(eo); b.build_call_graph();"
        "print(json.dumps({'edges': b.call_graph['main.%s:main'],"
        " 'rev_keys': list(b.reverse_call_graph.keys())}))"
        % (str(CORE), lang, lang)
    )


def _across_seeds(lang, eo):
    """Run the product's own builder once per PYTHONHASHSEED."""
    rows = []
    for seed in SEEDS:
        env = dict(os.environ, PYTHONHASHSEED=seed)
        out = subprocess.run(
            [sys.executable, "-B", "-c", _driver(lang)],
            input=json.dumps(eo), capture_output=True, text=True,
            env=env, cwd=str(CORE),
        )
        assert out.returncode == 0, "driver failed (seed=%s): %s" % (seed, out.stderr)
        rows.append(json.loads(out.stdout.strip().splitlines()[-1]))
    return rows


# --------------------------------------------------------------- the PHP half

def test_php_edge_order_is_deterministic_across_hashseeds():
    """THE #775 measurement: eight same-file callees, seven seeds — the
    unsorted consumer permutes the edge list (and the reverse graph's key
    creation order) per seed; the sorted consumer is seed-invariant."""
    eo = _fixture("php", _PHP_MAIN, _PHP_FN)
    b = PhpBuilder(eo)
    b.build_call_graph()
    assert len(b.call_graph["main.php:main"]) == len(CALLEES), (
        "the in-process drive holds: all %d callees resolve to edges (#775)"
        % len(CALLEES))
    rows = _across_seeds("php", eo)
    orders = {json.dumps(r["edges"]) for r in rows}
    assert len(orders) == 1, (
        "the PHP edge ORDER permutes across hash seeds (%d distinct orders) "
        "-- every recorded surface that follows it is seed-dependent (#775)"
        % len(orders))
    revs = {json.dumps(r["rev_keys"]) for r in rows}
    assert len(revs) == 1, (
        "the reverse graph's key-creation order permutes too (it appends "
        "while iterating the forward list) (#775)")


def test_php_edge_order_is_the_sorted_order():
    """The named repair: the PHP consumer emits the sorted order."""
    rows = _across_seeds("php", _fixture("php", _PHP_MAIN, _PHP_FN))
    edges = rows[0]["edges"]
    assert edges == sorted(edges), (
        "the PHP edge list must be the sorted order — the recorded output "
        "contract every downstream consumer can byte-diff against (#775)")
    b = PhpBuilder(_fixture("php", _PHP_MAIN, _PHP_FN))
    b.build_call_graph()
    in_process = b.call_graph["main.php:main"]
    assert in_process == sorted(in_process), (
        "the in-process drive agrees: the product's own PHP builder emits "
        "the sorted edge list (#775)")


# ------------------------------------------------- the cross-parser lock row

def test_both_parsers_match_the_python_consumers_contract():
    """The family's named contract: the PHP and Ruby consumers now match the
    Python parser's own consumer (`parsers/python/call_graph_builder.py`,
    `sorted(...)`) — the repair every sibling carries (the #754 line)."""
    pytest.importorskip("tree_sitter_ruby")  # the Ruby half of the lock (the php-pathed file stays self-contained)
    import parsers.php.call_graph_builder as php_mod
    import parsers.ruby.call_graph_builder as ruby_mod
    import inspect
    php_src = inspect.getsource(php_mod.CallGraphBuilder.build_call_graph)
    ruby_src = inspect.getsource(ruby_mod.CallGraphBuilder.build_call_graph)
    assert "valid_calls = sorted(" in php_src, (
        "the PHP consumer sorts (#775)")
    assert "valid_calls = sorted(" in ruby_src, (
        "the Ruby consumer sorts (#775)")
