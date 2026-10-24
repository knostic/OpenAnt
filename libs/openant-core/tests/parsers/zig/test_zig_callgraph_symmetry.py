"""Y-test (per-parser call-graph symmetry) for Zig — #702.

The suite the #147-#153 wave promised as a follow-up and never shipped (four
of nine parsers had one; zig was among the five that did not). Asserts the
shared invariants via tests/parsers/_symmetry_shared.py — exact bidirectional
consistency, node-realness, no self-edges — over the REAL parse_repository
pipeline, plus the two #702-intake cases for the alias-index fallback:

  (a) the FORCED-FAILURE OBSERVABILITY case: `_build_alias_index` raising
      must leave a NAMED signal (stderr) — at the base the wholesale alias
      drop was silent, indistinguishable from "no aliases existed", and a
      symmetric wholesale drop passes symmetry vacuously;
  (b) the CONSTRUCT-COVERAGE case (the healthy index): an aliased call's
      edge survives — the edge-vs-enumeration oracle an edge-only
      consistency check cannot replace.
"""

import json
import os
import sys
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
    "main.zig": """
        const std = @import("std");
        fn helper(x: u32) u32 { return x + 1; }
        fn shared() void {}
        fn x() void { shared(); }
        fn y() void { shared(); }
        fn driver() u32 {
            const f = helper;   // alias binding — the ONLY path to helper
            return f(1);
        }
        pub fn main() void {
            _ = driver();
            x();
            y();
        }
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
        parse_repository(repo, out, language="zig", processing_level="all",
                         skip_tests=True, name="r")
        return json.loads((Path(out) / "call_graph.json").read_text(encoding="utf-8"))


def _graph():
    cg = _cg(_REPO)
    return (set((cg.get("functions") or {}).keys()),
            cg.get("call_graph") or {}, cg.get("reverse_call_graph") or {})


def test_callgraph_symmetry_invariants():
    fids, fwd, rev = _graph()
    assert_callgraph_symmetry(fids, fwd, rev, context="zig")
    assert_no_self_edges(fwd, context="zig")
    assert_graph_is_nonempty(fwd, context="zig")


def test_shared_callee_has_both_callers_in_reverse():
    _, _, rev = _graph()
    callers = rev.get("main.zig:shared", [])
    assert set(callers) == {"main.zig:x", "main.zig:y"}, (
        f"the shared callee's reverse set must carry both callers: {callers}")


def test_aliased_call_edge_survives_a_healthy_index():
    """The #702-intake (b): the edge-vs-enumeration oracle — the alias
    binding `const f = helper` must produce the f-caller -> helper edge; an
    edge-only consistency check cannot detect its wholesale absence."""
    fids, fwd, rev = _graph()
    driver = [k for k in fwd if k.endswith(":driver")]
    assert driver, "the driver fixture is missing from the graph"
    callees = set(fwd[driver[0]])
    assert any(c.endswith(":helper") for c in callees), (
        f"the aliased call's edge to helper is absent — the alias-index "
        f"drop class the intake names: {sorted(callees)}")


def test_alias_index_failure_is_loud(monkeypatch):
    """The #702-intake (a): a `_build_alias_index` failure must leave a
    NAMED stderr signal. At the base the fallback emptied the whole alias
    map silently — nothing distinguished the total drop from "no aliases
    existed" — and the run completed complete-looking. RED at base.

    Drives the builder IN-PROCESS (parse_repository runs the whole parser
    stage in a subprocess — _parse_via_subprocess — where a monkeypatch
    cannot reach), over a minimal extractor_output carrying an alias."""
    import io
    # the PROD module directly (the symbol screen binds the witness to the
    # touched file; the importlib.isolated loader below would test itself):
    # parsers.zig.call_graph_builder has no intra-package relative imports,
    # so the direct import is the same code the subprocess pipeline runs.
    import parsers.zig.call_graph_builder as mod

    eo = {"functions": {
        "m.zig:helper": {"name": "helper", "file_path": "m.zig",
                         "code": "fn helper() void {}"},
        "m.zig:caller": {"name": "caller", "file_path": "m.zig",
                         "code": "const f = helper;\nfn caller() void { f(); }"},
        "m.zig:main": {"name": "main", "file_path": "m.zig",
                       "code": "pub fn main() void { caller(); }"},
    }}

    def _boom(self, name_to_ids):
        raise RuntimeError("injected fault: the alias index build fails")

    monkeypatch.setattr(mod.CallGraphBuilder, "_build_alias_index", _boom)
    buf = io.StringIO()
    real_stderr = sys.stderr
    sys.stderr = buf
    try:
        b = mod.CallGraphBuilder(eo)
        b.build_call_graph()
    finally:
        sys.stderr = real_stderr
    err = buf.getvalue()
    assert "alias" in err.lower(), (
        f"the alias-index failure was SILENT — the wholesale alias-edge "
        f"drop is indistinguishable from 'no aliases existed' (the "
        f"#702-intake silent-fallback class); stderr was {err!r}")
    assert "[zig]" in err, (
        f"the signal must NAME the parser: {err!r}")
    # the graceful degradation holds: the graph still forms via the other
    # paths — the alias-driven edge drops, main -> caller must survive
    fwd = b.call_graph
    assert "m.zig:main" in fwd and "m.zig:caller" in fwd["m.zig:main"], (
        f"the non-alias edge must survive the alias-index degradation: {fwd}")
    # the degradation's OWN evidence: the alias-driven caller -> helper edge
    # DROPPED (it exists healthily — the suite's oracle test pins that)
    assert "m.zig:caller" not in fwd or "m.zig:helper" not in fwd["m.zig:caller"], (
        f"the alias-index fault was not injected — the alias edge survived: {fwd}")
    # and the degraded graph is STILL symmetric (the drop is total, not
    # one-directional — the class the intake names)
    assert_callgraph_symmetry(set(eo["functions"].keys()), fwd,
                              b.reverse_call_graph, context="zig-degraded")
