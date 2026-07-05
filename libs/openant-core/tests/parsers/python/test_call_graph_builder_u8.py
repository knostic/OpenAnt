"""Regression tests for four confirmed call_graph_builder bugs (u8 bundle).

Each test drives the REAL parser pipeline: write source file(s) to a temp
repo, run FunctionExtractor, build the call graph with CallGraphBuilder, then
assert the edge that should exist (or the false edge that must NOT exist).

Bugs covered:
  [10] builtin-filter leak  — user fn named like a stdlib module (`time`) loses
        its call edge because _is_builtin short-circuits before same-file lookup.
  [12] dataflow alias       — `fn = helper; fn()` loses the edge to `helper`.
  [27] import over-resolution — `import alpha; alpha.run()` spuriously resolves
        to a free function named `alpha` (matched on module tail, not call name).
  [46] inherited-self dispatch — `self.shared()` calling an inherited base
        method isn't resolved.
"""

import sys
import tempfile
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.python.function_extractor import FunctionExtractor
from parsers.python.call_graph_builder import CallGraphBuilder


def _build(files: dict) -> CallGraphBuilder:
    """Write {relpath: source} into a temp repo, run the real pipeline."""
    d = tempfile.mkdtemp()
    for rel, src in files.items():
        p = Path(d) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src)
    extractor_output = FunctionExtractor(d).extract_all()
    builder = CallGraphBuilder(extractor_output)
    builder.build_call_graph()
    return builder


# ---------------------------------------------------------------- [10]
def test_user_fn_named_like_stdlib_module_resolves():
    """A user fn named `time` (a stdlib module name) must still get its edge."""
    builder = _build({
        "m.py": "def time():\n    return 1\n\ndef main():\n    time()\n",
    })
    caller = "m.py:main"
    callee = "m.py:time"
    assert callee in builder.call_graph[caller], (
        f"Edge {caller} -> {callee} missing (builtin filter leaked).\n"
        f"  Got: {builder.call_graph[caller]}"
    )


def test_genuine_builtin_call_not_linked_to_unrelated_samename_fn():
    """SCOPE guard: a genuine `time()` builtin call in file b.py must NOT link
    to a user `def time()` in an UNRELATED file a.py (no cross-file leak)."""
    builder = _build({
        "a.py": "def time():\n    return 1\n",
        "b.py": "def consume():\n    return time()\n",
    })
    caller = "b.py:consume"
    bad = "a.py:time"
    assert bad not in builder.call_graph.get(caller, []), (
        f"False cross-file edge {caller} -> {bad} (builtin call wrongly linked).\n"
        f"  Got: {builder.call_graph.get(caller, [])}"
    )


# ---------------------------------------------------------------- [12]
def test_function_value_alias_resolves():
    """`fn = helper; fn()` must produce main -> helper."""
    builder = _build({
        "m.py": "def helper():\n    return 1\n\ndef main():\n    fn = helper\n    fn()\n",
    })
    caller = "m.py:main"
    callee = "m.py:helper"
    assert callee in builder.call_graph[caller], (
        f"Edge {caller} -> {callee} missing (alias not followed).\n"
        f"  Got: {builder.call_graph[caller]}"
    )


# ---------------------------------------------------- [12] single-assign GUARD
def test_alias_reassignment_not_resolved():
    """GUARD (reassignment): `fn = a; fn = b; fn()` is last-write-wins, so the
    binding is a "maybe". The guard must NOT assert a definite edge to EITHER
    target — pinned behavior: no alias edge at all (fall through to no edge)."""
    builder = _build({
        "m.py": (
            "def a():\n    return 1\n\n"
            "def b():\n    return 2\n\n"
            "def main():\n    fn = a\n    fn = b\n    fn()\n"
        ),
    })
    caller = "m.py:main"
    edges = builder.call_graph.get(caller, [])
    assert "m.py:a" not in edges and "m.py:b" not in edges, (
        f"reassigned alias asserted a maybe-binding as definite: {edges}"
    )


def test_alias_conditional_binding_not_resolved():
    """GUARD (conditional): an alias bound inside if/else is not unconditional,
    so it must NOT be resolved (no edge to either branch's target)."""
    builder = _build({
        "m.py": (
            "def a():\n    return 1\n\n"
            "def b():\n    return 2\n\n"
            "def main(cond):\n"
            "    if cond:\n        fn = a\n    else:\n        fn = b\n"
            "    fn()\n"
        ),
    })
    caller = "m.py:main"
    edges = builder.call_graph.get(caller, [])
    assert "m.py:a" not in edges and "m.py:b" not in edges, (
        f"conditional alias resolved despite non-unconditional binding: {edges}"
    )


# ---------------------------------------------------------------- [27]
def test_import_module_call_does_not_false_link_to_samename_free_fn():
    """`import alpha; alpha.run()` must NOT link caller -> free fn `alpha`."""
    builder = _build({
        "m.py": "import alpha\n\ndef alpha():\n    return 1\n\ndef caller():\n    return alpha.run()\n",
    })
    caller = "m.py:caller"
    bad = "m.py:alpha"
    assert bad not in builder.call_graph.get(caller, []), (
        f"False edge {caller} -> {bad} (matched module tail, not call name).\n"
        f"  Got: {builder.call_graph.get(caller, [])}"
    )


# ---------------------------------------------------------------- [46]
def test_inherited_self_method_resolves():
    """self.shared() inherited from a base class must resolve to Base.shared."""
    builder = _build({
        "m.py": (
            "class Base:\n"
            "    def shared(self):\n"
            "        return 1\n"
            "\n"
            "class Child(Base):\n"
            "    def run(self):\n"
            "        return self.shared()\n"
        ),
    })
    caller = "m.py:Child.run"
    callee = "m.py:Base.shared"
    assert callee in builder.call_graph[caller], (
        f"Edge {caller} -> {callee} missing (inherited self-call not resolved).\n"
        f"  Got: {builder.call_graph[caller]}"
    )
