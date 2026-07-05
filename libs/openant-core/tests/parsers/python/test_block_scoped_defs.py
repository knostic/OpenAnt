"""Bug: functions/classes defined inside a BLOCK statement are dropped.

The Python extractor only recursed into `FunctionDef`/`ClassDef` bodies, never
into block statements (`if`/`elif`/`else`, `try`/`except`/`finally`, `for`/
`while`, `with`, `match`/`case`). So a `def` inside `if sys.version_info...`, a
`try/except ImportError` fallback, a `with`-guarded handler, or a CBV `if/else`
dispatcher was never a unit, never a call-graph node, and its body (including any
sink) leaked verbatim into the synthetic `:__module__` unit.

Investigated independent + judge (real interpreter). Fix descends into block
bodies at ALL depths (Python already keeps function-nested defs, so this matches
its baseline), reusing the existing keep-both (`#L<line>`) machinery, and closes
the `__module__` leak by covering every def/class span.
"""
import sys
import tempfile
from pathlib import Path

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.python.function_extractor import FunctionExtractor


def _extract(src: str) -> dict:
    repo = Path(tempfile.mkdtemp()).resolve()
    (repo / "m.py").write_text(src)
    ex = FunctionExtractor(str(repo))
    ex.process_file(repo / "m.py")
    return ex.functions


def _names(functions: dict):
    return sorted(k.split(":", 1)[1] for k in functions)


@pytest.mark.parametrize("wrap", [
    "if X:\n    {d}",
    "if X:\n    pass\nelse:\n    {d}",
    "try:\n    {d}\nexcept Exception:\n    pass",
    "try:\n    pass\nexcept Exception:\n    {d}",
    "try:\n    pass\nfinally:\n    {d}",
    "for i in r:\n    {d}",
    "while X:\n    {d}",
    "with open('x') as f:\n    {d}",
])
def test_block_scoped_def_is_extracted(wrap):
    src = "def top(): pass\n" + wrap.format(d="def blk(): return sink()")
    assert "blk" in _names(_extract(src)), f"block def dropped: {_names(_extract(src))}"


def test_match_case_def_is_extracted():
    src = "def top(): pass\nmatch v:\n    case 1:\n        def handler(): return 1\n"
    assert "handler" in _names(_extract(src))


def test_async_and_decorated_block_defs_extracted():
    src = (
        "import functools\n"
        "if X:\n"
        "    async def afn(): return 1\n"
        "if Y:\n"
        "    @functools.cache\n"
        "    def dfn(): return 2\n"
    )
    names = _names(_extract(src))
    assert "afn" in names and "dfn" in names, names


def test_class_in_block_and_its_methods_extracted():
    # A class inside a block, and its methods, must surface. The method
    # `Hidden.m` in the functions inventory proves the block-nested class was
    # descended into and processed (the class itself lands in `ex.classes`).
    src = "if TYPE_CHECKING:\n    class Hidden:\n        def m(self): return 1\n"
    names = _names(_extract(src))
    assert any(n.endswith("Hidden.m") for n in names), names


def test_function_internal_block_def_extracted_no_duplicate():
    src = (
        "def outer():\n"
        "    def direct(): return 1\n"
        "    if c:\n"
        "        def blocked(): return 2\n"
    )
    names = _names(_extract(src))
    assert names.count("direct") == 1, f"direct duplicated: {names}"
    assert "blocked" in names, f"function-internal block def dropped: {names}"


def test_sibling_block_same_name_keeps_both():
    src = (
        "if c:\n    def view(): return a()\n"
        "else:\n    def view(): return b()\n"
    )
    views = [n for n in _names(_extract(src)) if n.startswith("view")]
    assert len(views) == 2, f"both if/else view defs must survive: {views}"


def test_block_def_colliding_with_top_level_keeps_both():
    src = "def dup(): return 1\nif c:\n    def dup(): return 2\n"
    dups = [n for n in _names(_extract(src)) if n.startswith("dup")]
    assert len(dups) == 2, f"block def must not clobber top-level same-name: {dups}"


def test_module_unit_does_not_leak_block_def_body():
    # The block def's body (incl. its sink) must move into its own unit, not
    # leak verbatim into the synthetic :__module__ text.
    src = "if X:\n    def hidden(req):\n        return __import__('os').system(req)\n"
    fns = _extract(src)
    assert "hidden" in _names(fns), "hidden not surfaced"
    mod = next((v for k, v in fns.items() if k.endswith(":__module__")), None)
    if mod is not None:
        assert "system(req)" not in mod.get("code", ""), (
            "block def body leaked into __module__"
        )
