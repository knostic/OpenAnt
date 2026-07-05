"""Regression tests for the Ruby call graph builder (u10 blind-fix batch).

Five confirmed bugs in parsers/ruby/call_graph_builder.py, each driven through
the REAL pipeline (FunctionExtractor -> CallGraphBuilder) so the func_data shape
(indented `code`, `imports`, `class_name`, ...) matches production exactly.

  [1]  parenless free-function call drops the edge          (assert edge PRESENT)
  [8]  ClassName.method over-resolves to an unrelated file  (assert edge ABSENT)
  [11] user method named like a builtin gets filtered       (assert edge PRESENT)
  [31] m = method(:helper); m.call drops the edge           (assert edge PRESENT)
  [49] require 'auth' substring-matches authentication.rb   (assert edge ABSENT)
"""

import sys
import tempfile
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.ruby.function_extractor import FunctionExtractor
from parsers.ruby.call_graph_builder import CallGraphBuilder


def _build(files: dict) -> tuple[dict, CallGraphBuilder]:
    """Write Ruby sources to a temp repo, run the real two-stage pipeline."""
    repo = Path(tempfile.mkdtemp())
    for name, src in files.items():
        p = repo / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src)
    extractor = FunctionExtractor(str(repo))
    output = extractor.extract_all(list(files.keys()))
    builder = CallGraphBuilder(output)
    builder.build_call_graph()
    return output, builder


def _fid(output: dict, suffix: str) -> str:
    matches = [k for k in output["functions"] if k.endswith(suffix)]
    assert len(matches) == 1, f"expected one func id ending {suffix!r}, got {matches}"
    return matches[0]


# ----------------------------------------------------------------- [1] parenless
def test_parenless_free_function_call_is_an_edge():
    """`main` body is a bare `greet` (no parens) — the main->greet edge must exist."""
    output, builder = _build(
        {"app.rb": "def greet\n  puts 'hi'\nend\n\ndef main\n  greet\nend\n"}
    )
    caller = _fid(output, ":main")
    callee = _fid(output, ":greet")
    assert callee in builder.call_graph[caller], (
        f"parenless call edge missing: {caller} -> {callee}; got {builder.call_graph[caller]}"
    )


def test_parenless_local_variable_is_not_an_edge():
    """Precision guard: a bare identifier that is a LOCAL VAR must NOT become a call.

    `greet` here is a method name AND a local variable in `main`; the bare
    reference `greet` on the last line is a variable read, not a call.
    """
    output, builder = _build(
        {
            "app.rb": "def greet\n  puts 'hi'\nend\n\n"
            "def main\n  greet = 1\n  greet\nend\n"
        }
    )
    caller = _fid(output, ":main")
    callee = _fid(output, ":greet")
    assert callee not in builder.call_graph[caller], (
        f"local variable wrongly treated as a call: {caller} -> {callee}"
    )


def test_parenless_unknown_identifier_is_not_an_edge():
    """Precision guard: a bare identifier that is NOT a known function is not a call."""
    output, builder = _build(
        {"app.rb": "def greet\n  puts 'hi'\nend\n\ndef main\n  unknown_thing\nend\n"}
    )
    caller = _fid(output, ":main")
    # No edge to anything (unknown_thing is not a function).
    assert builder.call_graph[caller] == [], (
        f"unknown bare identifier produced an edge: {builder.call_graph[caller]}"
    )


# ------------------------------------------------- [8] cross-file over-resolution
def test_class_call_does_not_resolve_to_unrelated_file():
    """Worker is defined in an unrelated file with no require link — no edge."""
    output, builder = _build(
        {
            "caller.rb": "class Caller\n  def run\n    Worker.process()\n  end\nend\n",
            "decoy.rb": "class Worker\n  def process\n    42\n  end\nend\n",
        }
    )
    caller = _fid(output, ":Caller.run")
    forbidden = _fid(output, "decoy.rb:Worker.process")
    assert forbidden not in builder.call_graph[caller], (
        f"over-resolved to unrelated file: {caller} -> {forbidden}; "
        f"got {builder.call_graph[caller]}"
    )


def test_class_call_still_resolves_when_required():
    """Recall guard for [8]: when caller requires the defining file, edge stays."""
    output, builder = _build(
        {
            "caller.rb": "require_relative 'worker'\n"
            "class Caller\n  def run\n    Worker.process()\n  end\nend\n",
            "worker.rb": "class Worker\n  def process\n    42\n  end\nend\n",
        }
    )
    caller = _fid(output, ":Caller.run")
    callee = _fid(output, "worker.rb:Worker.process")
    assert callee in builder.call_graph[caller], (
        f"required class-call edge lost: {caller} -> {callee}; got {builder.call_graph[caller]}"
    )


# --------------------------------------------------------------- [11] builtin leak
def test_user_method_named_like_builtin_is_an_edge():
    """`render` is in RUBY_BUILTINS but here it is a user function in the same file."""
    output, builder = _build(
        {"app.rb": "def render\n  1\nend\n\ndef main\n  render()\nend\n"}
    )
    caller = _fid(output, ":main")
    callee = _fid(output, ":render")
    assert callee in builder.call_graph[caller], (
        f"user method named like builtin filtered: {caller} -> {callee}; "
        f"got {builder.call_graph[caller]}"
    )


def test_genuine_builtin_not_linked_to_unrelated_user_method():
    """Scope guard for [11]: a genuine builtin call must NOT link to a same-named
    user method in an UNRELATED file."""
    output, builder = _build(
        {
            "user.rb": "def main\n  puts('hi')\nend\n",
            "other.rb": "class Box\n  def puts\n    99\n  end\nend\n",
        }
    )
    caller = _fid(output, "user.rb:main")
    forbidden = _fid(output, "other.rb:Box.puts")
    assert forbidden not in builder.call_graph[caller], (
        f"genuine builtin linked to unrelated user method: {caller} -> {forbidden}"
    )


# ---------------------------------------------------------- [31] method-object var
def test_method_object_call_is_an_edge():
    """`m = method(:helper); m.call` — the caller_fn->helper edge must exist."""
    output, builder = _build(
        {
            "m.rb": "def helper\n  42\nend\n\n"
            "def caller_fn\n  m = method(:helper)\n  m.call\nend\n"
        }
    )
    caller = _fid(output, ":caller_fn")
    callee = _fid(output, ":helper")
    assert callee in builder.call_graph[caller], (
        f"method-object edge missing: {caller} -> {callee}; got {builder.call_graph[caller]}"
    )


# ------------------------------------------- [31] single-unconditional GUARD
def test_method_object_reassignment_not_resolved():
    """GUARD (reassignment): `m = method(:a); m = method(:b); m.call` is
    last-write-wins, so the binding is a "maybe". The guard must NOT assert a
    definite edge to EITHER target — pinned behavior: no edge at all."""
    output, builder = _build(
        {
            "m.rb": "def a\n  1\nend\n\ndef b\n  2\nend\n\n"
            "def caller_fn\n  m = method(:a)\n  m = method(:b)\n  m.call\nend\n"
        }
    )
    caller = _fid(output, ":caller_fn")
    a_id = _fid(output, "m.rb:a")
    b_id = _fid(output, "m.rb:b")
    edges = builder.call_graph[caller]
    assert a_id not in edges and b_id not in edges, (
        f"reassigned method-object asserted a maybe-binding as definite: {edges}"
    )


def test_method_object_conditional_binding_not_resolved():
    """GUARD (conditional): a binding inside an `if`/`else` branch is not
    unconditional, so `m.call` must NOT resolve (no edge to either target)."""
    output, builder = _build(
        {
            "m.rb": "def a\n  1\nend\n\ndef b\n  2\nend\n\n"
            "def caller_fn(cond)\n  if cond\n    m = method(:a)\n  else\n"
            "    m = method(:b)\n  end\n  m.call\nend\n"
        }
    )
    caller = _fid(output, ":caller_fn")
    a_id = _fid(output, "m.rb:a")
    b_id = _fid(output, "m.rb:b")
    edges = builder.call_graph[caller]
    assert a_id not in edges and b_id not in edges, (
        f"conditional method-object resolved despite non-unconditional binding: {edges}"
    )


# ------------------------------------------------ [49] substring import over-match
def test_require_does_not_substring_match_longer_filename():
    """require 'auth' must NOT match authentication.rb by substring.

    A same-named `shared_helper` is also defined in a third file so the
    global unique-name fallback (resolution step 4) CANNOT fire — that
    isolates the substring-import mechanism (step 3) as the only thing
    that could (wrongly) produce the forbidden edge.
    """
    output, builder = _build(
        {
            "main.rb": "require 'auth'\ndef caller_fn\n  shared_helper()\nend\n",
            "authentication.rb": "def shared_helper\n  1\nend\n",
            "elsewhere.rb": "def shared_helper\n  2\nend\n",
        }
    )
    caller = _fid(output, "main.rb:caller_fn")
    forbidden = "authentication.rb:shared_helper"
    assert forbidden not in builder.call_graph[caller], (
        f"require substring over-matched: {caller} -> {forbidden}; "
        f"got {builder.call_graph[caller]}"
    )


def test_require_resolves_by_basename_equality():
    """Recall guard for [49]: require 'auth' DOES resolve to auth.rb (basename eq).

    A same-named decoy defeats the unique-name fallback, so a passing edge
    must come from the basename-equality require match (step 3).
    """
    output, builder = _build(
        {
            "main.rb": "require 'auth'\ndef caller_fn\n  shared_helper()\nend\n",
            "auth.rb": "def shared_helper\n  1\nend\n",
            "elsewhere.rb": "def shared_helper\n  2\nend\n",
        }
    )
    caller = _fid(output, "main.rb:caller_fn")
    callee = "auth.rb:shared_helper"
    assert callee in builder.call_graph[caller], (
        f"basename-equal require edge lost: {caller} -> {callee}; "
        f"got {builder.call_graph[caller]}"
    )
