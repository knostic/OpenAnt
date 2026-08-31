"""#329: the Ruby extractor drops inline-visibility method definitions.

`private def foo` / `protected def foo` / `public def foo` (and the parenthesised /
singleton forms) are parsed by tree-sitter as a `call` named `private` whose argument
is a `method` node. The extractor's arg-form branch (merged PR #86 — `private :foo`
privatizes only the NAMED symbol, so consuming without descending is correct there)
matches on method name only, sets `handled = True`, and the nested def never reaches
the `method` handler: the unit is absent from `functions` and from the class roster.
A dropped method is a missing call-graph node — a tainted path THROUGH an
inline-visibility method disappears (the false-negative direction).

`module_function def x` and `private_class_method def x` survive (different call
names, not in the tuple), block-style `private` + `def x` survives (the bare-marker
toggle path) — same syntactic shape, different call name, opposite outcome: the
mechanism, per the issue's executed matrix.

The fix descends only when the visibility call actually WRAPS a definition — the
arg-form negative control (no phantom units, roster unchanged) must keep its
no-descent behaviour.
"""
import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
if str(_CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CORE_ROOT))

from parsers.ruby.function_extractor import FunctionExtractor


def _extract(tmp_path: Path, filename: str, source: str) -> dict:
    rb = tmp_path / filename
    rb.write_text(source)
    extractor = FunctionExtractor(str(tmp_path))
    return extractor.extract_all([filename])


def _names(result: dict) -> set:
    return {fd["name"] for fd in result["functions"].values()}


def test_inline_visibility_methods_are_extracted(tmp_path):
    """`private/protected/public def` units are extracted; the plain `def`
    control in the same class body proves the absences are not a harness artifact."""
    result = _extract(
        tmp_path,
        "inline.rb",
        "class C\n"
        "  private def a; end\n"
        "  protected def b; end\n"
        "  public def c; end\n"
        "  def plain; end\n"
        "end\n",
    )
    names = _names(result)
    assert "plain" in names, f"control missing — fixture failed to parse: {names}"
    for m in ("a", "b", "c"):
        assert m in names, (
            f"inline-visibility method {m!r} dropped (control 'plain' present): {names}"
        )
    # Units are class-qualified like plain defs.
    assert "inline.rb:C.a" in result["functions"]
    assert "inline.rb:C.b" in result["functions"]
    assert "inline.rb:C.c" in result["functions"]


def test_inline_visibility_singleton_is_extracted(tmp_path):
    """`private def self.x` — the inline singleton form; `def self.y` is the control."""
    result = _extract(
        tmp_path,
        "sing.rb",
        "class C\n"
        "  private def self.x; end\n"
        "  def self.y; end\n"
        "end\n",
    )
    names = _names(result)
    assert "y" in names, f"control missing — fixture failed to parse: {names}"
    assert "x" in names, f"inline singleton dropped (control 'y' present): {names}"
    assert "sing.rb:C.x" in result["functions"]


def test_inline_visibility_methods_reach_the_class_roster(tmp_path):
    """classes[...]['methods'] must not disagree with functions: the roster
    carries the inline methods too, with the `self.` prefix for singletons."""
    result = _extract(
        tmp_path,
        "roster.rb",
        "class C\n"
        "  private def a; end\n"
        "  def plain; end\n"
        "end\n"
        "class D\n"
        "  private def self.sing; end\n"
        "end\n",
    )
    roster_c = result["classes"]["roster.rb:C"]["methods"]
    assert "plain" in roster_c, f"control missing from roster: {roster_c}"
    assert "a" in roster_c, f"inline method missing from roster: {roster_c}"
    roster_d = result["classes"]["roster.rb:D"]["methods"]
    assert "self.sing" in roster_d, (
        f"inline singleton missing from roster (want 'self.sing'): {roster_d}"
    )


def test_arg_form_visibility_keeps_no_descent(tmp_path):
    """The negative control: `private :g` privatizes only the NAMED symbol —
    descending would emit phantom units from the symbols. Exactly the two defs."""
    result = _extract(
        tmp_path,
        "n.rb",
        "class D\n"
        "  def g; end\n"
        "  def h; end\n"
        "  private :g\n"
        "  protected :h\n"
        "end\n",
    )
    names = _names(result)
    assert names == {"g", "h"}, (
        f"arg-form visibility must not invent units (want exactly g, h): {names}"
    )
    roster = result["classes"]["n.rb:D"]["methods"]
    assert "g" in roster and "h" in roster
