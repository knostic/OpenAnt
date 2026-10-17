"""Regression tests for #775: the Ruby parser consumes its call-graph edge
lists unsorted — the #754 class, filed from its review cycle. (The PHP half
lives at tests/parsers/php/test_issue775_edge_order.py; the C sibling is
#776, open.)

`parsers/ruby/call_graph_builder.py` builds a caller's callee set in a
`set()` (the tree-sitter path's `_extract_calls_from_code` returns
`Set[str]`) and the consumer at `:942` filtered that set into a list
WITHOUT sorting it, so every function's edge ORDER was whatever the
process's string hashing produced — the same per-seed byte drift on
`call_graph.json` / `dataset.json` the #754 review measured on the C
parser. The repair is the one line the Python parser's own consumer
carries: `sorted(...)`.

The seed-varied rows drive the product's own `CallGraphBuilder` in fresh
interpreters with only `PYTHONHASHSEED` changed.
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

pytest.importorskip("tree_sitter_ruby")
from parsers.ruby.call_graph_builder import CallGraphBuilder as RubyBuilder  # noqa: E402

SEEDS = ("0", "1", "2", "3", "4", "7", "11")

# Eight same-file callees, so the unsorted set has 8! orders available and
# the hash seed reliably moves it. Names deliberately NOT in call-site order.
CALLEES = ("alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta")

_RUBY_MAIN = " ".join("%s" % c for c in CALLEES)
_RUBY_FN = "def %s\n  # %s\nend"


def _fixture():
    fns = {
        "main.ruby:main": {"name": "main", "file_path": "main.ruby",
                           "code": _RUBY_MAIN},
    }
    for c in CALLEES:
        fns["main.ruby:" + c] = {
            "name": c, "file_path": "main.ruby", "code": _RUBY_FN % (c, c)}
    return {"functions": fns, "repository": "/r"}


_DRIVER = (
    "import json, sys; sys.path.insert(0, %r);"
    "from parsers.ruby.call_graph_builder import CallGraphBuilder;"
    "eo = json.loads(sys.stdin.read());"
    "b = CallGraphBuilder(eo); b.build_call_graph();"
    "print(json.dumps({'edges': b.call_graph['main.ruby:main'],"
    " 'rev_keys': list(b.reverse_call_graph.keys())}))"
    % (str(CORE),)
)


def _across_seeds():
    """Run the product's own Ruby builder once per PYTHONHASHSEED."""
    rows = []
    for seed in SEEDS:
        env = dict(os.environ, PYTHONHASHSEED=seed)
        out = subprocess.run(
            [sys.executable, "-B", "-c", _DRIVER],
            input=json.dumps(_fixture()), capture_output=True, text=True,
            env=env, cwd=str(CORE),
        )
        assert out.returncode == 0, "driver failed (seed=%s): %s" % (seed, out.stderr)
        rows.append(json.loads(out.stdout.strip().splitlines()[-1]))
    return rows


def test_ruby_edge_order_is_deterministic_across_hashseeds():
    """THE #775 measurement (the Ruby half): eight same-file callees, seven
    seeds — the unsorted consumer permutes the edge list (and the reverse
    graph's key-creation order) per seed; the sorted consumer is
    seed-invariant."""
    eo = _fixture()
    b = RubyBuilder(eo)
    b.build_call_graph()
    assert len(b.call_graph["main.ruby:main"]) == len(CALLEES), (
        "the in-process drive holds: all %d callees resolve to edges (#775)"
        % len(CALLEES))
    rows = _across_seeds()
    orders = {json.dumps(r["edges"]) for r in rows}
    assert len(orders) == 1, (
        "the Ruby edge ORDER permutes across hash seeds (%d distinct orders) "
        "-- the same non-determinism the #754 review measured on the C "
        "parser and the #775 body measured on PHP (#775)" % len(orders))
    revs = {json.dumps(r["rev_keys"]) for r in rows}
    assert len(revs) == 1, (
        "the reverse graph's key-creation order permutes too (it appends "
        "while iterating the forward list) (#775)")


def test_ruby_edge_order_is_the_sorted_order():
    """The named repair: the Ruby consumer emits the sorted order."""
    rows = _across_seeds()
    edges = rows[0]["edges"]
    assert edges == sorted(edges), (
        "the Ruby edge list must be the sorted order — the recorded output "
        "contract every downstream consumer can byte-diff against (#775)")
    b = RubyBuilder(_fixture())
    b.build_call_graph()
    in_process = b.call_graph["main.ruby:main"]
    assert in_process == sorted(in_process), (
        "the in-process drive agrees: the product's own Ruby builder emits "
        "the sorted edge list (#775)")
