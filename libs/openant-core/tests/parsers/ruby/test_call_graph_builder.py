"""Ruby call-graph resolution defects in parsers/ruby/call_graph_builder.py.

Each test pins one resolution defect. The module basename ``call_graph_builder.py``
(and ``function_extractor.py``) recurs across every parser, so both modules are
loaded under UNIQUE importlib names.

Defects covered:
  - module self/sibling call dropped (no methods_by_module index)
  - module fn leaks to an outside-module bare call (false edge)
  - Module.method cross-file unresolved
  - module-function same-module sibling resolved only by accident
  - module_function Module.method call edge dropped
  - super dispatch unresolved
  - Class.new(...) -> initialize untracked
  - send/public_send/__send__ literal-symbol dispatch dropped
  - require_relative not anchored to caller dir (basename collision)
  - require import matched by unanchored substring (wrong file)
  - require_relative '../...' not normalized against caller dir
"""
import importlib.util
import os
import sys
import tempfile
from pathlib import Path

CORE = Path(__file__).resolve().parents[3]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))


def _load(unique_name, relpath):
    spec = importlib.util.spec_from_file_location(unique_name, str(CORE / relpath))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_cgb = _load("ruby_call_graph_builder_isolated", "parsers/ruby/call_graph_builder.py")
_fe = _load("ruby_function_extractor_isolated", "parsers/ruby/function_extractor.py")
CallGraphBuilder = _cgb.CallGraphBuilder
FunctionExtractor = _fe.FunctionExtractor


def _build_from_sources(files):
    """Write Ruby sources, run the real extractor + builder, return the builder."""
    d = tempfile.mkdtemp()
    for name, code in files.items():
        path = os.path.join(d, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(code)
    extractor = FunctionExtractor(d)
    result = extractor.extract_all(list(files.keys()))
    builder = CallGraphBuilder(result)
    builder.build_call_graph()
    return builder


# --------------------------------------------------------------------------
# Module-function resolution cluster (shared root: no methods_by_module index)
# --------------------------------------------------------------------------

def test_module_singleton_self_call_resolves():
    """`def self.api` calling `self.helper` must edge to the module's helper."""
    b = _build_from_sources({
        "u.rb": "module Utils\n  def self.helper(x)\n    x\n  end\n"
                "  def self.api(i)\n    self.helper(i)\n  end\nend\n",
    })
    assert b.call_graph.get("u.rb:Utils.api") == ["u.rb:Utils.helper"], b.call_graph


def test_module_function_call_does_not_leak_to_outside_caller():
    """a bare `helper()` OUTSIDE Utils must NOT resolve to Utils.helper."""
    b = _build_from_sources({
        "utils.rb": "module Utils\n  def helper(x)\n    x\n  end\nend\n",
        "main.rb": "class App\n  def run\n    helper(1)\n  end\nend\n",
    })
    assert b.call_graph.get("main.rb:App.run") == [], (
        f"module leak: outside-module bare call resolved to a module fn: {b.call_graph}"
    )


def test_module_method_resolved_cross_file():
    """`Utils.helper(1)` from another file must edge to the module fn."""
    b = _build_from_sources({
        "utils.rb": "module Utils\n  module_function\n  def helper(x)\n    x\n  end\nend\n",
        "main.rb": "class App\n  def run\n    Utils.helper(1)\n  end\nend\n",
    })
    assert b.call_graph.get("main.rb:App.run") == ["utils.rb:Utils.helper"], b.call_graph


def test_module_function_sibling_resolves_by_module_not_accident():
    """A cross-file same-module sibling must resolve by module.

    `Utils.api` (a.rb) calls bare `helper`, defined in `Utils` in b.rb; a decoy
    `Other.helper` in c.rb makes the unsound unique-name fallback ambiguous, so at
    base the edge is dropped. The module-scoped resolution must pick b.rb's helper.
    """
    b = _build_from_sources({
        "a.rb": "module Utils\n  module_function\n  def api(i)\n    helper(i)\n  end\nend\n",
        "b.rb": "module Utils\n  module_function\n  def helper(x)\n    x\n  end\nend\n",
        "c.rb": "module Other\n  module_function\n  def helper(y)\n    y\n  end\nend\n",
    })
    assert b.call_graph.get("a.rb:Utils.api") == ["b.rb:Utils.helper"], b.call_graph


# --------------------------------------------------------------------------
# Inheritance / dispatch
# --------------------------------------------------------------------------

def test_super_resolves_to_superclass_method():
    """`super` in Child#greet must edge to Base#greet."""
    b = _build_from_sources({
        "a.rb": "class Base\n  def greet\n    1\n  end\nend\n"
                "class Child < Base\n  def greet\n    super\n  end\nend\n",
    })
    assert b.call_graph.get("a.rb:Child.greet") == ["a.rb:Base.greet"], b.call_graph


def test_constructor_new_resolves_to_initialize():
    """`Widget.new(1)` must edge to Widget#initialize."""
    b = _build_from_sources({
        "a.rb": "class Widget\n  def initialize(x)\n    @x = x\n  end\nend\n"
                "class App\n  def run\n    Widget.new(1)\n  end\nend\n",
    })
    assert b.call_graph.get("a.rb:App.run") == ["a.rb:Widget.initialize"], b.call_graph


def test_send_literal_symbol_dispatch_resolves():
    """send/public_send/__send__ with a literal symbol resolve the target."""
    for verb in ("send", "public_send", "__send__"):
        b = _build_from_sources({
            "a.rb": f"class App\n  def target\n    1\n  end\n"
                    f"  def run\n    {verb}(:target)\n  end\nend\n",
        })
        assert b.call_graph.get("a.rb:App.run") == ["a.rb:App.target"], (
            f"{verb}(:target) not resolved: {b.call_graph}"
        )


# --------------------------------------------------------------------------
# require_relative anchoring (one line-252 root: substring + no caller-dir anchor)
# --------------------------------------------------------------------------

def test_require_relative_anchored_to_caller_dir_on_collision():
    """`require_relative './helper'` must anchor to the caller's dir.

    Two files share the basename helper.rb; only the caller-dir one is the target.
    """
    b = _build_from_sources({
        "lib/sub/a.rb": "require_relative './helper'\ndef go\n  do_help(1)\nend\n",
        "lib/sub/helper.rb": "def do_help(x)\n  x\nend\n",
        "lib/other/helper.rb": "def do_help(y)\n  y\nend\n",
    })
    assert b.call_graph.get("lib/sub/a.rb:go") == ["lib/sub/helper.rb:do_help"], b.call_graph


def test_require_relative_parent_dir_normalized():
    """`require_relative '../lib/util'` normalized against the caller dir."""
    b = _build_from_sources({
        "app/main.rb": "require_relative '../lib/util'\ndef run\n  helper2(1)\nend\n",
        "lib/util.rb": "def helper2(x)\n  x\nend\n",
        "app/decoy.rb": "def helper2(y)\n  y\nend\n",
    })
    assert b.call_graph.get("app/main.rb:run") == ["lib/util.rb:helper2"], b.call_graph


def test_require_import_matches_anchored_file_not_substring():
    """`require 'util'` must bind lib/util.rb, not lib/util_extra.rb.

    Both files define `helper`, so the unique-name fallback cannot decide; only an
    anchored require match resolves it. The unanchored `'util' in file_path`
    substring would also match the decoy lib/util_extra.rb.
    """
    # The decoy is indexed FIRST so the unanchored substring scan reaches it
    # before the real target -- pinning the wrong-file binding at base.
    funcs = {
        "lib/util_extra.rb:helper": {
            "name": "helper", "file_path": "lib/util_extra.rb",
            "class_name": None, "module_name": None, "code": "",
        },
        "lib/util.rb:helper": {
            "name": "helper", "file_path": "lib/util.rb",
            "class_name": None, "module_name": None, "code": "",
        },
    }
    b = CallGraphBuilder({"functions": funcs, "classes": {},
                          "imports": {"caller.rb": {"util": "require"}}, "repository": "/r"})
    assert b._resolve_simple_call("helper", "caller.rb", None) == "lib/util.rb:helper", (
        "require 'util' must anchor to lib/util.rb, not the substring-matched decoy"
    )
