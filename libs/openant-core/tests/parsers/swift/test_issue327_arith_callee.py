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

CORE = str(Path(__file__).resolve().parents[3])  # libs/openant-core
if CORE not in sys.path:
    sys.path.insert(0, CORE)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _helpers import build  # noqa: E402


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


def _callers_of(fn):
    return fn


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


def test_control_still_resolves():
    b = _run(FIXTURE)
    assert "A.swift:tAdd" in b.get("A.swift:ctlAdd", [])


def test_left_side_call_also_survives():
    """binNav's mk() — the LEFT operand's inner call — must not be lost."""
    b = _run(FIXTURE)
    edges = b.get("A.swift:binNav", [])
    assert "A.swift:Helper.m" in edges, edges


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
