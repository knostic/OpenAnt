"""Regression test: Ruby class reopening must MERGE, not last-write-wins.

Reopening a class is idiomatic Ruby. The FunctionExtractor keyed each class
definition on ``<file>:<qualified_name>`` and did a plain dict assignment, so a
later ``class Widget ... end`` block silently overwrote the earlier one --
dropping the original superclass (breaking super-call and Sinatra::Base
resolution) and the earlier method list.
"""

import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
if str(_CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CORE_ROOT))

from parsers.ruby.function_extractor import FunctionExtractor


def _extract(tmp_path: Path, filename: str, source: str) -> dict:
    (tmp_path / filename).write_text(source)
    return FunctionExtractor(str(tmp_path)).extract_all([filename])


def test_reopen_preserves_superclass_and_merges_methods(tmp_path):
    result = _extract(
        tmp_path,
        "reopen.rb",
        "class Widget < Base\n"
        "  def foo; end\n"
        "end\n"
        "\n"
        "class Widget\n"          # reopened WITHOUT restating the superclass
        "  def bar; end\n"
        "end\n",
    )
    cls = result["classes"]["reopen.rb:Widget"]
    # Superclass from the first opening must survive the reopen.
    assert cls["superclass"] == "Base", cls
    # Both definitions' methods must be present (union, not overwrite).
    assert set(cls["methods"]) >= {"foo", "bar"}, cls


def test_distinct_module_same_name_classes_are_not_merged(tmp_path):
    """`module A; class Foo` and `module B; class Foo` are DISTINCT classes.

    The reopen-merge keys on class_id. If class_id omits the module namespace
    the two Foos collide and get wrongly merged (methods + superclass unioned).
    They must stay separate: A::Foo has only `a`, B::Foo has only `b`.
    """
    result = _extract(
        tmp_path,
        "modns.rb",
        "module A\n"
        "  class Foo\n"
        "    def a; end\n"
        "  end\n"
        "end\n"
        "\n"
        "module B\n"
        "  class Foo\n"
        "    def b; end\n"
        "  end\n"
        "end\n",
    )
    classes = result["classes"]
    a_foo = classes["modns.rb:A::Foo"]
    b_foo = classes["modns.rb:B::Foo"]
    # Two distinct entries, no cross-contamination of methods.
    assert set(a_foo["methods"]) == {"a"}, a_foo
    assert set(b_foo["methods"]) == {"b"}, b_foo
    assert a_foo["module_name"] == "A"
    assert b_foo["module_name"] == "B"
