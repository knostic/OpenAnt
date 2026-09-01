"""#327: the Swift call-graph builder emits the arithmetic-callee call site.

`_extract_calls` recorded a call only when the callee was a `simple_identifier` or a
`navigation_expression`. Tree-sitter parses `f() + g()` with an ARITHMETIC expression as the
callee of the outer call — neither branch matches, so g's site is not emitted and the edge is
lost. Executed at b501968: `tAdd()` called plainly resolves; the same `tAdd()` as the right
operand of `+` does not. The lost set: `+ - * / %` (additive/multiplicative shapes). `&&`, `??`,
`<`, ternary, compound assign, and parenthesised right operands all resolve — arithmetic
specifically, not binary expressions generally.

The fabrication guard: a fix that attributes the LEFT operand invents calls — `scale + t()`
would emit a phantom `scale` (a local Int, colliding with a real function name). Only the
RIGHTMOST postfix-callable operand is attributed, with the outer node's labels.
"""
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
from _helpers import build, edges  # noqa: E402


FIXTURE = """
func tAdd() -> Int { return 5 }
func lhsA() -> Int { return 3 }
func lhsB() -> Bool { return true }
func lhsC() -> Int? { return nil }
func lhsD() -> Int { return 3 }
func lhsE() -> Int { return 3 }
func mk() -> Helper { return Helper() }
struct Helper { func m() -> Int { return 1 } }
func f() -> Int { return 1 }
func scale() -> Int { return 7 }

func ctlAdd() -> Int { return tAdd() }
func binAdd() -> Int { return lhsA() + tAdd() }
func binSub() -> Int { return lhsA() - tAdd() }
func binMul() -> Int { return lhsA() * tAdd() }
func binDiv() -> Int { return lhsA() / tAdd() }
func binMod() -> Int { return lhsA() % tAdd() }
func twoCalls() -> Int { let c = 9; return c + tAdd() * lhsA() }
func binNav() -> Int { return lhsA() + mk().m() }
func noFabrication() -> Int { let scale = 3; return scale + tAdd() }
"""


def _run(src):
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        _, out = build(Path(d), {"A.swift": src})
    return out["call_graph"]



def test_arith_right_operand_resolves():
    """The issue's matrix: tAdd() lost as the right operand of + - * / %."""
    b = _run(FIXTURE)
    for fn in ("binAdd", "binSub", "binMul", "binDiv", "binMod"):
        edges = b.get(f"A.swift:{fn}", [])
        assert "A.swift:tAdd" in edges, (fn, edges)
        # wave r1 (three axes): the LEFT operand's own call was asserted
        # nowhere — a change that stopped pushing the additive's children
        # would keep every matrix test green.
        assert "A.swift:lhsA" in edges, (fn, edges)


def test_control_still_resolves():
    b = _run(FIXTURE)
    assert "A.swift:tAdd" in b.get("A.swift:ctlAdd", [])


def test_left_side_call_also_survives():
    """binNav's mk() — the LEFT operand's inner call — must not be lost."""
    b = _run(FIXTURE)
    edges = b.get("A.swift:binNav", [])
    assert "A.swift:Helper.m" in edges, edges
    # wave r1 (all axes): mk — the call nested in the right operand's
    # navigation chain — was asserted NOWHERE (the test only checked the
    # already-green Helper.m, pristine-safe; the docstring claimed this).
    assert "A.swift:mk" in edges, edges
    assert "A.swift:lhsA" in edges, edges


def test_no_phantom_left_operand():
    """The fabrication guard: `scale + tAdd()` where scale is a LOCAL Int — no
    edge to the scale FUNCTION; the rightmost postfix-callable operand only."""
    b = _run(FIXTURE)
    edges = b.get("A.swift:noFabrication", [])
    assert "A.swift:tAdd" in edges, edges
    assert "A.swift:scale" not in edges, edges


def test_two_calls_both_resolve():
    """`c + tAdd() * lhsA()` — both right-operand calls surface."""
    b = _run(FIXTURE)
    edges = b.get("A.swift:twoCalls", [])
    assert "A.swift:tAdd" in edges, edges
    assert "A.swift:lhsA" in edges, edges


def test_navigation_right_operand_self_receiver():
    """Wave r1 (fable): `1 + self.m()` — the reachable navigation shape (the
    early reduction makes the outer callee the navigation_expression the
    pre-existing branch handles; pins that the fix did not break it)."""
    src = """
struct S {
    func m() -> Int { return 1 }
    func n() -> Int { return 1 + self.m() }
}
"""
    b = _run(src)
    edges = b.get("A.swift:S.n", [])
    assert "A.swift:S.m" in edges, edges


def test_prefix_rightmost_operand_is_called():
    """Wave r1 (probed + confirmed): `a + -f()` — the hoisted suffix applies
    to the whole `-f()`, so the prefix's operand IS the callee (f is genuinely
    called). RED before this round (the site was silently lost)."""
    src = """
func f() -> Int { return 1 }
func pre() -> Int { return a + -f() }
"""
    b = _run(src)
    edges = b.get("A.swift:pre", [])
    assert "A.swift:f" in edges, edges


def test_labels_come_from_the_outer_node():
    """Wave r1 (opus): the commit's central design claim — labels/arity come
    from the OUTER node (the hoisted argument list) — was untested (every
    fixture was zero-arity). Pinned at the SITE level: the arithmetic-callee
    site carries the x label and arity 1 (reading the callee instead would
    yield labels=[] / arity=0 — the additive has no call_suffix)."""
    from _helpers import CallGraphBuilder
    src = "func pick() -> Int { return 2 + over(x: 1) }"
    bld = CallGraphBuilder({"functions": {}, "classes": {}, "files": {}})
    sites, _refs = bld._find_calls_in_code(src)
    arith = [s for s in sites if s["text"] == "over"]
    assert arith, sites
    s = arith[0]
    assert s["labels"] == ["x"], s
    assert s["arity"] == 1, s


def test_trailing_comment_operand_skipped(tmp_path):
    """famBCR panel (sonnet): the trailing-comment skip branch
    (`b /* cached */ + t /* hoisted */ (x)` — step back past the comment
    to the real operand) had zero coverage. Pinned with the file's own
    build helper: the callee t must still resolve through the comment."""
    src = """
func t() -> Int { return 1 }
func run() -> Int {
    let b = 2
    return b /* cached */ + t /* hoisted */ (x)
}
"""
    _, cg = build(tmp_path, {"app.swift": src})
    all_edges = edges(cg)
    assert ("run", "t") in all_edges, (
        f"the trailing comment must not hide the callee: {all_edges}")

