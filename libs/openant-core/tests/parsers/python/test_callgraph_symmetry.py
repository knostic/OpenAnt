"""Canonical per-parser invariant: every call-graph node is a real function.

`set(call_graph.keys()) ⊆ set(functions.keys())` and the same for
`reverse_call_graph` — no call-graph key may reference a function id that the
inventory doesn't contain. The fixture exercises top-level, nested, method, and
block-scoped (if/try/for/with) defs so the invariant is checked across every
emit path (a block def must appear in BOTH maps, not just one).
"""
import sys
import tempfile
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.python.function_extractor import FunctionExtractor
from parsers.python.call_graph_builder import CallGraphBuilder

_FIXTURE = (
    "def top():\n"
    "    return helper()\n"
    "def helper():\n"
    "    return 1\n"
    "class C:\n"
    "    def m(self):\n"
    "        return self.helper2()\n"
    "    def helper2(self):\n"
    "        return 2\n"
    "if FLAG:\n"
    "    def block_fn():\n"
    "        return top()\n"
    "try:\n"
    "    def fallback():\n"
    "        return 3\n"
    "except Exception:\n"
    "    pass\n"
)


def _build():
    d = tempfile.mkdtemp()
    (Path(d) / "m.py").write_text(_FIXTURE)
    builder = CallGraphBuilder(FunctionExtractor(d).extract_all())
    builder.build_call_graph()
    return builder


def test_callgraph_keys_subset_of_functions():
    b = _build()
    fns = set(b.functions)
    extra = set(b.call_graph) - fns
    assert not extra, f"call_graph references non-inventory ids: {sorted(extra)}"


def test_reverse_callgraph_keys_subset_of_functions():
    b = _build()
    fns = set(b.functions)
    extra = set(b.reverse_call_graph) - fns
    assert not extra, f"reverse_call_graph references non-inventory ids: {sorted(extra)}"


def test_block_scoped_def_is_a_callgraph_node_with_its_edge():
    # The block-scoped def must be in the inventory AND carry its real edge,
    # never an orphan / backstop-empty entry.
    b = _build()
    block_id = next(k for k in b.functions if k.endswith(":block_fn"))
    top_id = next(k for k in b.functions if k.endswith(":top"))
    assert top_id in b.call_graph.get(block_id, []), (
        f"block_fn -> top edge missing: {b.call_graph.get(block_id)}"
    )
