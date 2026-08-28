"""Regression tests for issue #298 — C indirect dispatch records no edges.

The three canonical C indirect-dispatch idioms — an ops struct with
designated initialisers, an array of function pointers, and a
struct-array command table dispatched by index — produced NO edge at all,
so the dispatching function had zero out-edges and every target was
orphaned. In C, function-pointer dispatch is the language's polymorphism
mechanism (kernel file_operations, driver op tables, syscall tables,
plugin vtables), so these are exactly the edges that carry
attacker-reachable control flow into a handler — and the dispatcher is
retained while its targets are pruned (#295's shape, in C).

The machinery for "a function referenced without being called" already
existed in this file (_extract_callback_args covers register_handler(cb));
initialisers and subscript/member dispatch are the missing members of that
family.

Contract locked here (the issue's fixture + controls):
- every table target gets a caller, and every dispatcher gets outgoing
  edges to its table's targets (over-seed is the safe direction);
- a direct-call CONTROL keeps its edge (null-result meaningfulness);
- unknown subscript bases and non-function initialiser values still
  record nothing (no invented edges).
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from parsers.c.call_graph_builder import CallGraphBuilder  # noqa: E402
from parsers.c.function_extractor import FunctionExtractor  # noqa: E402


def _build(tmp_path: Path, source: str) -> CallGraphBuilder:
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "d.c").write_text(textwrap.dedent(source))
    ex = FunctionExtractor(str(tmp_path))
    units = ex.extract_all()
    cg = CallGraphBuilder(units)
    cg.build_call_graph()
    return cg


_FIXTURE = """
    static void h_a(void) {}
    static void h_b(void) {}
    static void my_read(int x) {}
    static void direct_target(void) {}

    struct ops { void (*read)(int); };
    static struct ops o = { .read = my_read };
    static void (*tbl[])(void) = { h_a, h_b };

    void use_ops(int x)      { o.read(x); }
    void use_tbl(int i)      { tbl[i](); }
    void direct_caller(void) { direct_target(); }
"""


def test_control_direct_call_edge_exists(tmp_path):
    cg = _build(tmp_path, _FIXTURE)
    assert "src/d.c:direct_target" in cg.call_graph.get("src/d.c:direct_caller", [])


def test_ops_struct_dispatch_edges(tmp_path):
    """o.read(x) through a struct initialised with designated
    initialisers: use_ops edges to my_read; my_read gets a caller."""
    cg = _build(tmp_path, _FIXTURE)
    assert "src/d.c:my_read" in cg.call_graph.get("src/d.c:use_ops", [])
    assert "src/d.c:use_ops" in cg.reverse_call_graph.get("src/d.c:my_read", [])


def test_function_pointer_table_dispatch_edges(tmp_path):
    """tbl[i]() through an array of function pointers: use_tbl edges to
    both table targets."""
    cg = _build(tmp_path, _FIXTURE)
    edges = cg.call_graph.get("src/d.c:use_tbl", [])
    assert "src/d.c:h_a" in edges and "src/d.c:h_b" in edges, edges


def test_no_target_orphaned(tmp_path):
    """The issue's headline consequence: no dispatch target ends up with an
    empty caller set while its dispatcher is kept."""
    cg = _build(tmp_path, _FIXTURE)
    for fn in ("h_a", "h_b", "my_read"):
        callers = cg.reverse_call_graph.get(f"src/d.c:{fn}", [])
        assert callers, f"{fn} must have at least one caller (issue #298)"


def test_struct_array_command_table_dispatch(tmp_path):
    """cmds[i].fn() — a struct-array command table: the field call over a
    subscripted known container dispatches to every function the table's
    initialisers reference."""
    cg = _build(tmp_path, """
        struct cmd { const char *name; void (*fn)(void); };
        static struct cmd cmds[] = {
            {"a", cmd_a},
            {"b", cmd_b},
        };
        static void cmd_a(void) {}
        static void cmd_b(void) {}

        void run_cmd(int i) { cmds[i].fn(); }
    """)
    edges = cg.call_graph.get("src/d.c:run_cmd", [])
    assert "src/d.c:cmd_a" in edges and "src/d.c:cmd_b" in edges, edges


def test_local_table_in_function(tmp_path):
    """A table built INSIDE a function body: same dispatch through the
    local name."""
    cg = _build(tmp_path, """
        static void h1(void) {}
        static void h2(void) {}

        void dispatch(int i) {
            static void (*t[])(void) = { h1, h2 };
            t[i]();
        }
    """)
    edges = cg.call_graph.get("src/d.c:dispatch", [])
    assert "src/d.c:h1" in edges and "src/d.c:h2" in edges, edges


def test_unknown_subscript_base_records_nothing(tmp_path):
    """Negative control: a subscript call over a name with no known
    function-referencing initialiser records nothing — edges are only
    added, never invented."""
    cg = _build(tmp_path, """
        static void sink(void) {}

        void f(int i) {
            int data[3] = {1, 2, 3};
            data[i] = i + 1;      /* not a call at all */
            g(i);                 /* unknown callee */
        }
    """)
    assert cg.call_graph.get("src/d.c:f", []) == []


def test_non_function_initializer_values_ignored(tmp_path):
    """An initialiser of non-function values creates no container edges."""
    cg = _build(tmp_path, """
        void f(void) {
            int nums[] = {1, 2, 3};
            (void)nums[0];
        }
    """)
    assert cg.call_graph.get("src/d.c:f", []) == []
