"""Bug 1 regression: same-(file,name) C/C++ functions must not collapse to one
`func_id`. Two trigger families, two policies (see reachability-bugs.md Bug 1):

  * C++ overloads — `area(int)` and `area(int,int)` are BOTH real. They must
    survive as two distinct func_ids, and each must keep its OWN call edges
    (the conflation bug routed a call to overload-1 into overload-2's callee).
    The discriminator is folded into the func_id KEY only; the `name` field
    stays bare (`area`) so name-based call resolution still finds both.
  * `#ifdef`/`#else` redefinition — same name, same signature, different body.
    Only one is the compiled implementation; keep a SINGLE node and prefer the
    larger body (the `#else` stub is shorter regardless of source order).

Plus a regression guard: a uniquely-named function's id is byte-identical to the
pre-fix `path:name` form (the collision-only contract — non-colliding ids never
change, so the 299 hardcoded id literals across the suite are untouched).
"""
import sys
import tempfile
from pathlib import Path

import pytest

_CORE = Path(__file__).resolve().parents[3]
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))

pytest.importorskip("tree_sitter_c")

from parsers.c.function_extractor import FunctionExtractor  # noqa: E402
from parsers.c.call_graph_builder import CallGraphBuilder  # noqa: E402


def _extract(filename: str, source: str) -> dict:
    repo = Path(tempfile.mkdtemp()).resolve()
    fp = repo / filename
    fp.write_text(source)
    ex = FunctionExtractor(str(repo))
    ex.process_file(fp)
    return ex.functions


def test_cpp_overloads_both_survive():
    fns = _extract("ovl.cpp",
                   "int area(int s){return s*s;}\n"
                   "int area(int w,int h){return w*h;}\n")
    areas = [fid for fid, d in fns.items() if d["name"] == "area"]
    assert len(areas) == 2, f"both overloads must survive; got {areas}"
    assert len({fid for fid in areas}) == 2, "overload func_ids must be distinct"


def test_overload_ids_are_colon_free_in_name_part():
    # The discriminator must not introduce a colon into the name part of the id
    # (downstream diff_filter / repository_index rsplit on ':').
    fns = _extract("ovl.cpp",
                   "int f(int a){return a;}\n"
                   "int f(const char* s,int n){return n;}\n")
    for fid, d in fns.items():
        if d["name"] != "f":
            continue
        name_part = fid.split(":", 1)[1]  # everything after the path colon
        assert ":" not in name_part, f"colon leaked into discriminated id: {fid!r}"


def test_ifdef_else_keeps_larger_body_not_stub():
    # tree-sitter parses BOTH preprocessor arms; the #else stub comes last and,
    # pre-fix, overwrote the real implementation. Prefer the larger body.
    src = (
        "#ifdef FEATURE\n"
        "int run(int n){int t=0;for(int i=0;i<n;i++){t+=i*i;}return t;}\n"
        "#else\n"
        "int run(int n){(void)n;return 0;}\n"
        "#endif\n"
    )
    fns = _extract("if.c", src)
    runs = [d for d in fns.values() if d["name"] == "run"]
    assert len(runs) == 1, f"#ifdef/#else same-sig must keep ONE node; got {len(runs)}"
    assert "for" in runs[0]["code"], f"kept the stub, not the real impl: {runs[0]['code']!r}"


def test_overload_callees_not_conflated():
    # The real consequence of the bug: a call into one overload must reach ITS
    # callee, not the other overload's. Mirrors /tmp/bugrepro/conf.cpp.
    src = (
        "void alpha(){}\n"
        "void beta(){}\n"
        "int pick(int a){alpha();return a;}\n"
        "int pick(int a,int b){beta();return a+b;}\n"
    )
    fns = _extract("conf.cpp", src)
    b = CallGraphBuilder({"functions": fns, "includes": {}})
    b.build_call_graph()
    out = b.build() if hasattr(b, "build") else b.export()
    cg = out.get("call_graph", {})
    pick_ids = [fid for fid, d in fns.items() if d["name"] == "pick"]
    assert len(pick_ids) == 2, f"both pick overloads must exist; got {pick_ids}"
    all_pick_edges = {e for fid in pick_ids for e in cg.get(fid, [])}
    alpha_id = next(fid for fid, d in fns.items() if d["name"] == "alpha")
    beta_id = next(fid for fid, d in fns.items() if d["name"] == "beta")
    assert alpha_id in all_pick_edges, f"alpha() edge lost (conflation): {all_pick_edges}"
    assert beta_id in all_pick_edges, f"beta() edge lost (conflation): {all_pick_edges}"


def test_unique_name_id_is_byte_identical():
    # Collision-only contract: a uniquely-named function keeps the exact
    # `path:name` id — no discriminator appended when there is no collision.
    fns = _extract("u.c", "int solo(int x){return x+1;}\n")
    ids = [fid for fid, d in fns.items() if d["name"] == "solo"]
    assert ids == ["u.c:solo"], f"unique-name id changed (would break 299 literals): {ids}"
