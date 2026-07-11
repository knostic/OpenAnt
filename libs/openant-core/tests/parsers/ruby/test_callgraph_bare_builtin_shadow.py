"""Bare call to a same-class method named like a builtin resolves (reachability FN fix).

`_resolve_bare_identifier` applied the builtin filter before checking for a same-scope
user function, so a bare (parenless) call to a same-class method whose name collides with
a Ruby builtin (e.g. `first`, `map`) was dropped -> the method (and any sink it reaches)
became unreachable. The with-args path already had this rescue (_has_scoped_user_function);
the bare path did not.
"""
import os
import tempfile

from parsers.ruby.function_extractor import FunctionExtractor
from parsers.ruby.call_graph_builder import CallGraphBuilder


def _build(src: str):
    repo = os.path.realpath(tempfile.mkdtemp())
    p = os.path.join(repo, "svc.rb")
    with open(p, "w") as fh:
        fh.write(src)
    b = CallGraphBuilder(FunctionExtractor(repo).extract_all([p]))
    b.build_call_graph()
    return b


def _edges(b, caller_suffix):
    keys = [k for k in b.call_graph if k.endswith(caller_suffix)]
    return [e for k in keys for e in b.call_graph[k]]


def test_bare_call_to_builtin_named_same_class_method_resolves():
    b = _build(
        "class Svc\n"
        "  def run\n    first\n  end\n"          # bare call to a builtin-named method
        "  def first\n    system('x')\n  end\n"  # same-class method (sink)
        "end\n"
    )
    assert any("Svc.first" in e for e in _edges(b, ":Svc.run")), (
        f"bare `first` must resolve to same-class Svc.first (not be dropped as a builtin); "
        f"got {_edges(b, ':Svc.run')}"
    )


def test_genuine_builtin_bare_call_not_rescued_to_unrelated():
    # Precision: with NO same-class/same-file `first`, a bare `first` is a genuine
    # builtin and must not be linked to an unrelated same-named method elsewhere.
    b = _build(
        "class A\n  def helper\n    system('y')\n  end\nend\n"
        "class B\n  def go\n    first\n  end\nend\n"   # `first`: genuine builtin, no user def
    )
    assert not any("first" in e.lower() for e in _edges(b, ":B.go")), (
        f"genuine builtin `first` must not be rescued to an unrelated method; got {_edges(b, ':B.go')}"
    )
