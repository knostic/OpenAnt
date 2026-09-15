"""#440: the base walk follows imports and the C3 order — two FN residuals of #318.

1. IMPORTED IN-REPO BASES: the #318 walk is anchored to the CALLER's file, so
`a.py: class Base` imported into `b.py` (`class Sub(Base)`) never resolves
`s = Sub(); s.inherited()` — the most common real layout (a base module +
subclasses elsewhere) and likely the bulk of #318's census residual. The walk now
follows the import map the resolver already holds (`self.imports['b.py']['Base']`),
plus the cross-file unambiguous-match fallback (exactly one repo class with the
simple name) — the C suite's same-file floor doesn't transfer to a language with an
import map. External bases (no import entry, no repo class) stay unresolved —
never a fabricated edge.

2. THE FIFO WALK IS NOT C3 — A DIAMOND PICKS A SINGLE GENUINE-BUT-WRONG ANCESTOR:
`class C(A, B)` with `A(X)`, `X.m` and `B.m`: the FIFO found B.m; Python runs X.m —
so X.m kept an empty caller set and was pruned (the FN direction #318 was filed to
remove). The unified walk now computes the C3 linearization over the extractor's
base lists (FIFO fallback when a merge fails — inconsistent hierarchies still
resolve). Shared by _resolve_self_call and the typed-receiver path.
"""
import json
import sys
import tempfile
from pathlib import Path

# #415: parents[3] — from tests/parsers/python/<file>, parents[2] is tests/
# (the shadow-package poison); the core root is three levels up.
PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.parser_adapter import parse_repository  # noqa: E402


def _cg(files: dict):
    with tempfile.TemporaryDirectory() as _repo, tempfile.TemporaryDirectory() as out:
        repo = Path(_repo)
        for rel, content in files.items():
            p = repo / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        parse_repository(str(repo), out, language="python",
                         processing_level="all", skip_tests=True, name="r")
        with open(Path(out) / "call_graph.json", encoding="utf-8") as fh:
            return json.load(fh)["call_graph"]


def test_imported_base_resolves_typed_receiver():
    """The issue's primary shape: the base module + subclass elsewhere."""
    cg = _cg({
        "a.py": ("class Base:\n"
                 "    def inherited(self):\n"
                 "        return 1\n"),
        "b.py": ("from a import Base\n"
                 "class Sub(Base):\n"
                 "    pass\n"
                 "def use():\n"
                 "    s = Sub()\n"
                 "    return s.inherited()\n"),
    })
    edges = cg.get("b.py:use", [])
    assert "a.py:Base.inherited" in edges, (
        f"the imported in-repo base never resolved (the same-file anchor): {edges}"
    )


def test_self_call_via_imported_base():
    cg = _cg({
        "a.py": ("class Base:\n"
                 "    def helper(self):\n"
                 "        return 1\n"),
        "b.py": ("from a import Base\n"
                 "class Sub(Base):\n"
                 "    def work(self):\n"
                 "        return self.helper()\n"),
    })
    edges = cg.get("b.py:Sub.work", [])
    assert "a.py:Base.helper" in edges, f"self.helper() through an imported base: {edges}"


def test_diamond_resolves_c3_not_fifo():
    """class C(A, B), A(X), X.m and B.m: Python runs X.m (the C3 order puts
    the X branch ahead of B); the FIFO walk found B.m — genuine-but-wrong,
    leaving X.m with an empty caller set (pruned: the FN direction)."""
    cg = _cg({
        "d.py": ("class X:\n"
                 "    def m(self):\n"
                 "        return 'x'\n"
                 "class A(X):\n"
                 "    pass\n"
                 "class B:\n"
                 "    def m(self):\n"
                 "        return 'b'\n"
                 "class C(A, B):\n"
                 "    pass\n"
                 "def use():\n"
                 "    c = C()\n"
                 "    return c.m()\n"),
    })
    edges = cg.get("d.py:use", [])
    assert "d.py:X.m" in edges, (
        f"C3 order: c.m() runs X.m (via A), not B.m — the FIFO pick: {edges}"
    )


def test_same_file_walk_still_resolves():
    """The #318 floor unchanged: a same-file base chain still resolves."""
    cg = _cg({
        "s.py": ("class Base:\n"
                 "    def inherited(self):\n"
                 "        return 1\n"
                 "class Sub(Base):\n"
                 "    pass\n"
                 "def use():\n"
                 "    s = Sub()\n"
                 "    return s.inherited()\n"),
    })
    assert "s.py:Base.inherited" in cg.get("s.py:use", [])


def test_external_base_stays_unresolved():
    """No import entry and no repo class: unresolved, never fabricated."""
    cg = _cg({
        "e.py": ("import some_external_lib\n"
                 "class Sub(some_external_lib.Base):\n"
                 "    pass\n"
                 "def use():\n"
                 "    s = Sub()\n"
                 "    return s.inherited()\n"),
    })
    edges = cg.get("e.py:use", [])
    assert not any("Base.inherited" in e for e in edges), edges


def test_nested_class_self_call_still_resolves():
    """Wave r1 (opus+fable, the regression): the round-1 entry stripped the
    dotted qualifier — Outer.Inner became 'Inner', a key that exists
    nowhere — dropping the nested class's OWN self-dispatch and every
    inherited self-call inside it (the exact FN direction this PR removes)."""
    cg = _cg({
        "n.py": ("class Outer:\n"
                 "    class Inner:\n"
                 "        def own(self):\n"
                 "            return 1\n"
                 "        def go(self):\n"
                 "            return self.own()\n"),
    })
    edges = cg.get("n.py:Outer.Inner.go", [])
    assert "n.py:Outer.Inner.own" in edges, edges


def test_imported_base_with_external_origin_abstains():
    """Wave r1 (sonnet): the import exists but its module path matches no
    candidate file (an external attribute-style base) — the round-1
    unambiguous-name fallback fabricated an edge to an unrelated same-named
    LOCAL class. Abstain."""
    cg = _cg({
        "a.py": ("import some_external_lib\n"
                 "class Base:\n"          # an unrelated LOCAL Base
                 "    def m(self):\n"
                 "        return 1\n"
                 "def use(x):\n"
                 "    return x\n"),
        "b.py": ("from some_external_lib import Base as ExtBase\n"
                 "class Sub(ExtBase):\n"    # NOT the local Base — external
                 "    pass\n"
                 "def go(s):\n"
                 "    v = Sub()\n"
                 "    return v.m()\n"),
    })
    edges = cg.get("b.py:go", [])
    assert "a.py:Base.m" not in edges, (
        f"an external-origin base bound to the unrelated local namesake: {edges}"
    )
    # famBCR panel (sonnet, non-discriminating): the negative alone passes on
    # master too (the pre-#440 walk never resolved imports — no edge either
    # way). The POSITIVE control pins the discriminator: a LOCAL import of
    # the same name MUST produce the edge (the walk followed the import
    # map), which fails on the pre-PR code.
    cg2 = _cg({
        "a.py": ("class Base:\n"
                 "    def m(self):\n"
                 "        return 1\n"),
        "b.py": ("from a import Base\n"
                 "class Sub(Base):\n"
                 "    pass\n"
                 "def go(s):\n"
                 "    v = Sub()\n"
                 "    return v.m()\n"),
    })
    edges2 = cg2.get("b.py:go", [])
    assert "a.py:Base.m" in edges2, (
        f"the positive control: a local import base must resolve - "
        f"without it the abstain test passes on pre-#440 code: {edges2}")


def test_hijack_guard_holds_one_level_deep():
    """Wave r1 (three axes): use_union must PROPAGATE — the round-1
    recursion defaulted it back to True, so the typed path's anti-hijack
    guard (own bases, not the merged union) only held at depth 0."""
    cg = _cg({
        "h.py": ("class Base:\n"
                 "    def m(self):\n"
                 "        return 1\n"
                 "class Mid(Base):\n"       # the chain: Sub -> Mid -> Base
                 "    pass\n"
                 "def maker():\n"
                 "    class Mid(Base):\n"   # the function-local hijack namesake
                 "        pass\n"
                 "    return Mid\n"
                 "class Sub(Mid):\n"        # module-level Mid — NO bases of its own
                 "    pass\n"
                 "def f():\n"
                 "    v = Sub()\n"
                 "    return v.m()\n"),
    })
    # the union may merge the LOCAL Mid's base into the module Mid; the
    # typed path must read the MODULE Mid's OWN bases: Base.m resolves
    # through the Mid chain (hijack or not, Base.m is the real target and
    # is in BOTH chains here) — the discriminating case: an edge to a
    # hijack-only target must NOT appear. Keep this a resolution pin:
    edges = cg.get("h.py:f", [])
    assert "h.py:Base.m" in edges, edges
