"""Regression tests for the Ruby FunctionExtractor (7 extraction defects).

Each test pins one defect in
``libs/openant-core/parsers/ruby/function_extractor.py``.

Defects covered:
  - nested + compact module name flattening
  - define_method(:sym) { } metaprogramming
  - alias_method :a, :b class-body aliases
  - alias kw form (alias node) not extracted
  - visibility (private/protected) not tracked
  - controller privates over-flagged route_handler
  - top-level Sinatra DSL routes silently skipped

The module-basename ``function_extractor.py`` recurs across parsers
(python/ruby/php), so the import is package-qualified to load the Ruby one
unambiguously.
"""

import sys
from pathlib import Path

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[3]
if str(_CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CORE_ROOT))

from parsers.ruby.function_extractor import FunctionExtractor


def _extract(tmp_path: Path, filename: str, source: str) -> dict:
    """Write a Ruby source file under tmp_path and run the extractor over it."""
    rb = tmp_path / filename
    rb.write_text(source)
    extractor = FunctionExtractor(str(tmp_path))
    return extractor.extract_all([filename])


def _names(result: dict) -> set:
    """Set of bare method names across all extracted function units."""
    return {fd["name"] for fd in result["functions"].values()}


def _by_name(result: dict, name: str) -> dict:
    for fd in result["functions"].values():
        if fd["name"] == name:
            return fd
    raise AssertionError(f"no function unit named {name!r}; have {_names(result)}")


# --------------------------------------------------------------------------
# Nested & compact module name flattening
# --------------------------------------------------------------------------

def test_nested_module_name_concatenated(tmp_path):
    """`module Outer; module Inner` must qualify foo as Outer::Inner.foo."""
    result = _extract(
        tmp_path,
        "nested.rb",
        "module Outer\n  module Inner\n    def foo\n    end\n  end\nend\n",
    )
    foo = _by_name(result, "foo")
    assert foo["module_name"] == "Outer::Inner", (
        f"expected nested module Outer::Inner, got {foo['module_name']!r}"
    )
    assert "nested.rb:Outer::Inner.foo" in result["functions"]


def test_compact_module_name_preserved(tmp_path):
    """`module Outer::Inner` (scope_resolution) must keep the full namespace."""
    result = _extract(
        tmp_path,
        "compact.rb",
        "module Outer::Inner\n  def run\n  end\nend\n",
    )
    run = _by_name(result, "run")
    assert run["module_name"] == "Outer::Inner", (
        f"compact module name dropped: module_name={run['module_name']!r}, "
        f"unit_type={run['unit_type']!r}"
    )
    # And it must NOT be misclassified as a bare top-level function.
    assert run["unit_type"] != "function"


# --------------------------------------------------------------------------
# define_method metaprogramming
# --------------------------------------------------------------------------

def test_define_method_block_and_brace_extracted(tmp_path):
    """define_method(:sym) with do..end and { } blocks must emit method units."""
    result = _extract(
        tmp_path,
        "dm.rb",
        "class C\n"
        "  define_method(:dynamic_hello) do\n    1\n  end\n"
        "  define_method(:another_dyn) { |x| x }\n"
        "  def regular_method\n  end\nend\n",
    )
    names = _names(result)
    assert "dynamic_hello" in names, f"define_method do..end dropped; have {names}"
    assert "another_dyn" in names, f"define_method {{ }} dropped; have {names}"
    # The dynamically defined methods must also appear on the class methods list.
    cls = result["classes"]["dm.rb:C"]
    assert "dynamic_hello" in cls["methods"]
    assert "another_dyn" in cls["methods"]


# --------------------------------------------------------------------------
# alias_method call form
# --------------------------------------------------------------------------

def test_alias_method_call_form_extracted(tmp_path):
    """`alias_method :aliased, :original` must emit a method unit for aliased."""
    result = _extract(
        tmp_path,
        "am.rb",
        "class Foo\n"
        "  def original\n  end\n"
        "  alias_method :aliased, :original\n"
        "  alias_method \"strkey\", \"original\"\nend\n",
    )
    names = _names(result)
    assert "aliased" in names, f"alias_method symbol form dropped; have {names}"
    assert "strkey" in names, f"alias_method string form dropped; have {names}"
    assert "aliased" in result["classes"]["am.rb:Foo"]["methods"]


# --------------------------------------------------------------------------
# alias keyword form
# --------------------------------------------------------------------------

def test_alias_keyword_form_extracted(tmp_path):
    """`alias kw_aliased original` (alias node) must emit a method unit."""
    result = _extract(
        tmp_path,
        "ak.rb",
        "class Foo\n"
        "  def original\n  end\n"
        "  alias kw_aliased original\nend\n",
    )
    names = _names(result)
    assert "kw_aliased" in names, f"alias keyword form dropped; have {names}"
    assert "kw_aliased" in result["classes"]["ak.rb:Foo"]["methods"]


# --------------------------------------------------------------------------
# Visibility tracking
# --------------------------------------------------------------------------

def test_visibility_tracked_and_threaded(tmp_path):
    """Methods after a bare `private` marker must carry visibility=private."""
    result = _extract(
        tmp_path,
        "vis.rb",
        "class Bar\n"
        "  def pub\n  end\n"
        "  private\n"
        "  def priv\n  end\n"
        "  protected\n"
        "  def prot\n  end\nend\n",
    )
    assert _by_name(result, "pub")["visibility"] == "public"
    assert _by_name(result, "priv")["visibility"] == "private"
    assert _by_name(result, "prot")["visibility"] == "protected"


def test_arg_form_private_does_not_leak_visibility(tmp_path):
    """`private :sym` (call form) must NOT privatize subsequent defs.

    Regression guard for the visibility fix: the inner `private` identifier of
    the `private :sym` call node must not leak into the bare-marker toggle.
    """
    result = _extract(
        tmp_path,
        "argvis.rb",
        "class Svc\n"
        "  def pub\n  end\n"
        "  private :pub\n"
        "  def still_public\n  end\nend\n",
    )
    assert _by_name(result, "still_public")["visibility"] == "public"


# --------------------------------------------------------------------------
# Controller privates over-flagged route_handler
# --------------------------------------------------------------------------

def test_controller_private_methods_not_route_handlers(tmp_path):
    """Private params helpers / before_action targets are NOT route_handlers."""
    result = _extract(
        tmp_path,
        "users_controller.rb",
        "class UsersController\n"
        "  def index\n  end\n"
        "  private\n"
        "  def user_params\n  end\n"
        "  def set_user\n  end\nend\n",
    )
    # Public action stays a route handler.
    assert _by_name(result, "index")["unit_type"] == "route_handler"
    # Private helpers must NOT be route handlers (entry-point over-claim).
    assert _by_name(result, "user_params")["unit_type"] != "route_handler"
    assert _by_name(result, "set_user")["unit_type"] != "route_handler"


# --------------------------------------------------------------------------
# Top-level Sinatra DSL routes
# --------------------------------------------------------------------------

def test_sinatra_top_level_routes_extracted(tmp_path):
    """Top-level `get '/path' do..end` must emit a route_handler unit."""
    result = _extract(
        tmp_path,
        "app.rb",
        "get '/hello' do\n  'hi'\nend\n\n"
        "post '/items' do\n  'created'\nend\n",
    )
    handlers = [
        fd for fd in result["functions"].values()
        if fd["unit_type"] == "route_handler"
    ]
    routes = {fd["name"] for fd in handlers}
    assert "/hello" in routes or any("/hello" in (fd.get("qualified_name") or "") for fd in handlers), (
        f"Sinatra GET route not extracted as route_handler; handlers={routes}"
    )
    assert "/items" in routes or any("/items" in (fd.get("qualified_name") or "") for fd in handlers), (
        f"Sinatra POST route not extracted as route_handler; handlers={routes}"
    )
