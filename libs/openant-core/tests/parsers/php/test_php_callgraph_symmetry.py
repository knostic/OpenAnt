"""Y-test (per-parser call-graph symmetry) for PHP — #702.

The suite the #147-#153 wave promised as a follow-up and never shipped.
Asserts the shared invariants via tests/parsers/_symmetry_shared.py over the
REAL parse_repository pipeline, plus the construct pins the PHP parser's edge
classes make load-bearing: a shared callee (bidirectional) and the NAMESPACE
BOUNDARY (a bare call resolves within its own namespace and must not leak to
a same-named function in another — the #298 wave's class).
"""

import json
import os
import sys

import pytest
import tempfile
from pathlib import Path

from core.parser_adapter import parse_repository

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _symmetry_shared import (  # noqa: E402
    assert_callgraph_symmetry,
    assert_graph_is_nonempty,
    assert_no_self_edges,
)

_REPO = {
    "app.php": """
        <?php
        namespace App\\Utils;
        function helper($x) { return $x + 1; }
        function shared() { }
        function a($x) { helper($x); shared(); }
        function b($x) { helper($x); shared(); }
        function leaf() { }
        function driver() { a(1); b(2); leaf(); }
    """,
    "other.php": """
        <?php
        namespace App\\Other;
        function helper($x) { return $x - 1; }
    """,
}


def _cg(files):
    with tempfile.TemporaryDirectory() as _repo, tempfile.TemporaryDirectory() as out:
        repo = os.path.realpath(_repo)
        for rel, content in files.items():
            p = os.path.join(repo, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(content)
        parse_repository(repo, out, language="php", processing_level="all",
                         skip_tests=True, name="r")
        return json.loads((Path(out) / "call_graph.json").read_text(encoding="utf-8"))


def _graph():
    cg = _cg(_REPO)
    return (set((cg.get("functions") or {}).keys()),
            cg.get("call_graph") or {}, cg.get("reverse_call_graph") or {})


def test_callgraph_symmetry_invariants():
    fids, fwd, rev = _graph()
    assert_callgraph_symmetry(fids, fwd, rev, context="php")
    assert_no_self_edges(fwd, context="php")
    assert_graph_is_nonempty(fwd, context="php")


def test_shared_callee_has_both_callers_in_reverse():
    """PHP function ids are namespace-qualified
    (``app.php:App\\Utils\\shared``), so the pins key on the
    fully-qualified ids the parser emits."""
    fids, fwd, rev = _graph()
    shared = [k for k in fids if k.endswith("Utils\\shared")]
    a = [k for k in fids if k.endswith("Utils\\a")]
    b = [k for k in fids if k.endswith("Utils\\b")]
    assert shared and a and b, f"the fixture is missing from the graph: {sorted(fids)}"
    assert set(rev[shared[0]]) == {a[0], b[0]}, (
        f"the shared callee's reverse set must carry both callers: "
        f"{rev[shared[0]]}")


@pytest.mark.xfail(strict=True, reason=(
    "#702's side-finding: the PHP parser resolves the fully-qualified "
    "cross-namespace call (\\App\\Utils\\helper) to the CURRENT "
    "namespace's same-name function — a false edge. STRICT xfail: when the "
    "parser is fixed this XPASSes and fails the suite, retiring the marker."))
def test_fq_cross_namespace_call_resolves_to_the_named_namespace():
    # extract explicitly — _cg() returns the builder's SEVEN-key dict (the
    # astra-audit catch: the tuple unpack raised ValueError before any
    # assertion, so the strict marker could NEVER XPASS and the retirement
    # was dead code)
    cg = _cg({
        "app.php": """
        <?php
        namespace App\\Utils;
        function helper($x) { return $x + 1; }
        """,
        "other.php": """
        <?php
        namespace App\\Other;
        function helper($x) { return $x - 1; }
        function cross() { \\App\\Utils\\helper(5); }
        """,
    })
    fids = set((cg.get("functions") or {}).keys())
    fwd = cg.get("call_graph") or {}
    cross = [k for k in fids if k.endswith("Other\\cross")]
    utils_helper = [k for k in fids if k.endswith("Utils\\helper")]
    other_helper = [k for k in fids if k.endswith("Other\\helper")]
    assert cross and utils_helper and other_helper, sorted(fids)
    callees = set(fwd[cross[0]])
    assert utils_helper[0] in callees, (
        f"the FQ call must edge to the NAMED namespace's helper; got "
        f"{sorted(callees)} — the current-namespace misresolution")
    # the ABSENCE pin: a PARTIAL fix emitting BOTH targets would XPASS and
    # retire the marker with the false edge still live — pin its absence
    assert other_helper[0] not in callees, (
        f"the false edge to the current-namespace helper must be ABSENT: "
        f"{sorted(callees)}")


def test_bare_call_resolves_within_its_own_namespace_only():
    """The #298-wave class: `helper()` bare-called inside App\\Utils must
    edge to the App\\Utils helper, and the App\\Other helper must NOT gain
    that caller (a namespace leak is a false edge — the phantom class's
    cross-namespace twin)."""
    fids, fwd, _ = _graph()
    a = [k for k in fwd if k.endswith("Utils\\a")]
    utils_helper = [k for k in fids if k.endswith("Utils\\helper")]
    other_helper = [k for k in fids if k.endswith("Other\\helper")]
    assert a and utils_helper and other_helper, (sorted(fids))
    callees = set(fwd[a[0]])
    assert utils_helper[0] in callees, (
        f"the in-namespace bare call lost its edge: {sorted(callees)}")
    # the OTHER namespace's helper must gain NO bare-call edge from a()
    other_callers = [caller for caller, cs in fwd.items()
                     if other_helper[0] in cs]
    assert not other_callers, (
        f"the cross-namespace bare call LEAKED to the other helper: "
        f"{other_callers}")
