"""Regression tests for the Ruby function_extractor (u11 blind-fix batch).

Six confirmed bugs in parsers/ruby/function_extractor.py, each driven through the
REAL FunctionExtractor on a temp .rb file so the parse/extract shape matches
production exactly. Assertions are on the exported `functions` dict.

  [6]  nested `def` inside a `def` body is never extracted   (assert present)
  [18] `def self.initialize` mis-typed 'constructor'          (assert singleton_method + is_singleton)
  [24] `define_method(:sym){}` not registered                 (assert sym present)
  [42] `alias`/`alias_method` aliased name not registered     (assert new name present)
  [44] method after bare `private` not marked private         (assert unit_type private_method)
  [50] method in nested class gets bare class_name            (assert class_name 'Outer::Inner')
"""

import sys
import tempfile
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.ruby.function_extractor import FunctionExtractor


def _extract(src: str, name: str = "m.rb") -> dict:
    """Write one Ruby source to a temp repo, run the real extractor, return functions."""
    repo = Path(tempfile.mkdtemp())
    (repo / name).write_text(src)
    extractor = FunctionExtractor(str(repo))
    output = extractor.extract_all([name])
    return output["functions"]


def _find(functions: dict, suffix: str):
    """Return the single func_data whose id ends with `suffix`, or None."""
    matches = [v for k, v in functions.items() if k.endswith(suffix)]
    assert len(matches) <= 1, f"expected <=1 func id ending {suffix!r}, got {list(functions)}"
    return matches[0] if matches else None


# ------------------------------------------------------------------ [6] nested def
def test_nested_def_is_extracted():
    """A `def inner` nested in `def outer`'s body must be extracted as a unit."""
    functions = _extract("def outer\n  def inner\n    1\n  end\nend\n")
    assert _find(functions, ":inner") is not None, (
        f"nested def 'inner' missing; got {list(functions)}"
    )
    # outer must still be present (no double-count regression)
    assert _find(functions, ":outer") is not None


# ------------------------------------------------------ [18] self.initialize ordering
def test_self_initialize_is_singleton_not_constructor():
    """`def self.initialize` is a class singleton method, not the instance constructor."""
    functions = _extract(
        "class Widget\n  def self.initialize\n    @count = 0\n  end\nend\n",
        "widget.rb",
    )
    fn = _find(functions, ":Widget.initialize")
    assert fn is not None, f"Widget.initialize missing; got {list(functions)}"
    assert fn["is_singleton"] is True, f"expected is_singleton True; got {fn['is_singleton']}"
    assert fn["unit_type"] == "singleton_method", (
        f"expected unit_type singleton_method; got {fn['unit_type']!r}"
    )


# ----------------------------------------------------------------- [24] define_method
def test_define_method_registers_symbol():
    """`define_method(:render){...}` must register `render` as a method unit."""
    functions = _extract(
        'def ctrl\n  1\nend\n\nclass Widget\n  define_method(:render) do\n    "x"\n  end\nend\n'
    )
    assert _find(functions, ":ctrl") is not None, "in-file control 'ctrl' missing (file parse)"
    fn = _find(functions, ":render") or _find(functions, ".render")
    assert fn is not None, f"define_method 'render' missing; got {list(functions)}"
    assert fn["name"] == "render", f"expected name 'render'; got {fn['name']!r}"
    assert fn["class_name"] == "Widget", f"expected class_name Widget; got {fn['class_name']!r}"


# ------------------------------------------------------------------------ [42] alias
def test_alias_keyword_registers_new_name():
    """`alias greet hello` must register `greet` as a method node."""
    functions = _extract(
        'def control\n  1\nend\nclass Greeter\n  def hello\n    "hi"\n  end\n'
        "  alias greet hello\nend\n"
    )
    assert _find(functions, ":Greeter.hello") is not None, "control method 'hello' missing"
    fn = _find(functions, ":Greeter.greet")
    assert fn is not None, f"aliased name 'greet' missing; got {list(functions)}"
    assert fn["name"] == "greet"
    assert fn["class_name"] == "Greeter"


def test_alias_method_call_registers_new_name():
    """`alias_method :greet, :hello` must register `greet` (distinct AST node from `alias`)."""
    functions = _extract(
        'class Greeter\n  def hello\n    "hi"\n  end\n  alias_method :greet, :hello\nend\n'
    )
    fn = _find(functions, ":Greeter.greet")
    assert fn is not None, f"alias_method name 'greet' missing; got {list(functions)}"
    assert fn["name"] == "greet"


# ------------------------------------------------------------------- [44] private kw
def test_method_after_private_keyword_is_private():
    """A method following a bare `private` keyword must be unit_type private_method."""
    functions = _extract(
        "class Foo\n  private\n\n  def secret\n    42\n  end\nend\n", "foo.rb"
    )
    fn = _find(functions, ":Foo.secret")
    assert fn is not None, f"Foo.secret missing; got {list(functions)}"
    assert fn["unit_type"] == "private_method", (
        f"expected unit_type private_method; got {fn['unit_type']!r}"
    )


def test_method_before_private_keyword_stays_public():
    """Precision guard: a method declared BEFORE `private` must stay public ('method')."""
    functions = _extract(
        "class Foo\n  def open_api\n    1\n  end\n\n  private\n\n  def secret\n    2\n  end\nend\n",
        "foo2.rb",
    )
    pub = _find(functions, ":Foo.open_api")
    assert pub is not None and pub["unit_type"] == "method", (
        f"public method mis-typed: {pub['unit_type'] if pub else None}"
    )


# ----------------------------------------------------------- [50] nested class_name
def test_nested_class_method_has_composed_class_name():
    """A method in `class Inner` nested in `class Outer` must have class_name 'Outer::Inner'."""
    functions = _extract(
        "class Outer\n  class Inner\n    def deep_method\n      1\n    end\n  end\nend\n",
        "n.rb",
    )
    fn = _find(functions, ".deep_method")
    assert fn is not None, f"deep_method missing; got {list(functions)}"
    assert fn["class_name"] == "Outer::Inner", (
        f"expected class_name 'Outer::Inner'; got {fn['class_name']!r}"
    )
