"""Closure::fromCallable('foo') records an edge to foo (reachability FN fix).

`Closure::fromCallable('dangerous')` names a real callable statically, but the scoped-call
resolver sent it to _resolve_class_call('Closure', 'fromCallable') (Closure is not a user
class -> None) and never inspected the string-literal argument, so the edge to `dangerous`
(a sink) was dropped.
"""
import os
import tempfile

from parsers.php.function_extractor import FunctionExtractor
from parsers.php.call_graph_builder import CallGraphBuilder


def _build(src: str):
    repo = os.path.realpath(tempfile.mkdtemp())
    p = os.path.join(repo, "app.php")
    with open(p, "w") as fh:
        fh.write(src)
    b = CallGraphBuilder(FunctionExtractor(repo).extract_all([p]))
    b.build_call_graph()
    return b


def _edges(b, caller_suffix):
    keys = [k for k in b.call_graph if k.endswith(caller_suffix)]
    return [e for k in keys for e in b.call_graph[k]]


def test_closure_fromcallable_string_target_resolved():
    b = _build(
        "<?php\n"
        "function dangerous($cmd){ system($cmd); }\n"
        "function viaClosure(){ $c = Closure::fromCallable('dangerous'); $c('x'); }\n"
    )
    assert any(e.endswith(":dangerous") for e in _edges(b, ":viaClosure")), (
        f"Closure::fromCallable('dangerous') must record an edge to dangerous; "
        f"got {_edges(b, ':viaClosure')}"
    )


def test_closure_fromcallable_unknown_target_no_phantom():
    # Precision: a fromCallable naming a function that does not exist yields no edge.
    b = _build(
        "<?php\n"
        "function viaClosure(){ $c = Closure::fromCallable('nope_missing'); $c('x'); }\n"
    )
    assert _edges(b, ":viaClosure") == [], (
        f"unknown fromCallable target must not invent an edge; got {_edges(b, ':viaClosure')}"
    )
