"""Regression tests for the C call graph builder — builtin-name-collision leak.

Bug report (BUG-NEW-2026-06-02-c-builtin_filter_leak, OpenAnt base 601e588):
    A call to a *user-defined* function whose name collides with a C
    stdlib/POSIX builtin (e.g. `close`, which is in STDLIB_FUNCTIONS) produces
    NO edge in the call graph, because `_resolve_call` short-circuits with
    `return None` on `_is_stdlib(call_name)` BEFORE it ever consults the
    same-file user-function table. The callee is then falsely "isolated" /
    unreachable.

Root cause:
    parsers/c/call_graph_builder.py `_resolve_call` — the `_is_stdlib` filter
    runs first; the same-file lookup (step 1) is never reached for a colliding
    name.

Fix scope decision (see report): the pre-check is SCOPED to same-file
user-defined functions only. A genuine stdlib call (e.g. a real `printf` with
NO same-file definition) must still resolve to None — we must NOT route a
colliding name through a global cross-file single-match that could wrongly
link a real stdlib call to an unrelated same-named user function elsewhere.
"""

import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.c.call_graph_builder import CallGraphBuilder


def _make_extractor_output() -> dict:
    """User function `close` (collides with POSIX stdlib) + a caller, same file.

    Mirrors function_extractor output shape: each function id is
    `<file>:<name>` and func_data carries name / file_path / code.
    """
    file_path = "main.c"
    return {
        "repository": "/tmp/fake",
        "functions": {
            f"{file_path}:close": {
                "name": "close",
                "file_path": file_path,
                "code": "void close(int x) {\n}\n",
            },
            f"{file_path}:caller": {
                "name": "caller",
                "file_path": file_path,
                "code": "void caller(void) {\n    close(3);\n}\n",
            },
        },
    }


def test_user_function_colliding_with_stdlib_name_gets_edge():
    """caller() calls a same-file user `close` — the edge must exist."""
    builder = CallGraphBuilder(_make_extractor_output())
    builder.build_call_graph()

    caller = "main.c:caller"
    callee = "main.c:close"

    assert callee in builder.call_graph[caller], (
        f"Forward call graph missing edge to same-file user function whose "
        f"name collides with a stdlib builtin.\n"
        f"  Expected: {caller} -> {callee}\n"
        f"  Got: {builder.call_graph[caller]}"
    )


def test_user_function_colliding_with_stdlib_name_reverse_edge():
    """The colliding-name callee must list its caller in the reverse graph."""
    builder = CallGraphBuilder(_make_extractor_output())
    builder.build_call_graph()

    caller = "main.c:caller"
    callee = "main.c:close"

    callers = builder.reverse_call_graph.get(callee, [])
    assert caller in callers, (
        f"Reverse call graph missing caller for colliding-name user function.\n"
        f"  Expected to contain: {caller}\n"
        f"  Got: {callers}"
    )


def _make_real_stdlib_output() -> dict:
    """A genuine stdlib call with NO same-file user definition.

    `printf` is a real stdlib call here and there is NO user-defined `printf`
    anywhere — it must still resolve to nothing (no spurious edge).
    """
    file_path = "real.c"
    return {
        "repository": "/tmp/fake",
        "functions": {
            f"{file_path}:greet": {
                "name": "greet",
                "file_path": file_path,
                "code": 'void greet(void) {\n    printf("hi");\n}\n',
            },
        },
    }


def test_real_stdlib_call_still_filtered():
    """A real stdlib call with no same-file user def must produce NO edge."""
    builder = CallGraphBuilder(_make_real_stdlib_output())
    builder.build_call_graph()

    caller = "real.c:greet"
    assert builder.call_graph[caller] == [], (
        f"Real stdlib call should not resolve to any edge.\n"
        f"  Got: {builder.call_graph[caller]}"
    )


def _make_cross_file_stdlib_output() -> dict:
    """SCOPE guard: a real stdlib call in file A must NOT link to a same-named
    user function defined in an UNRELATED file B (no include relationship).

    File A (`a.c`) calls `open(...)` — a genuine stdlib call. File B (`b.c`)
    happens to define a user function `open`. With NO include linking them,
    the call in A must NOT be wired to B's `open`.
    """
    return {
        "repository": "/tmp/fake",
        "functions": {
            "a.c:user_a": {
                "name": "user_a",
                "file_path": "a.c",
                "code": "void user_a(void) {\n    open(0);\n}\n",
            },
            "b.c:open": {
                "name": "open",
                "file_path": "b.c",
                "code": "void open(int x) {\n}\n",
            },
        },
    }


def test_cross_file_stdlib_not_wrongly_linked():
    """A real stdlib call must not be linked to an unrelated same-named user
    function in another (non-included) file."""
    builder = CallGraphBuilder(_make_cross_file_stdlib_output())
    builder.build_call_graph()

    caller = "a.c:user_a"
    assert builder.call_graph[caller] == [], (
        f"Real stdlib call wrongly linked across files to an unrelated "
        f"same-named user function.\n"
        f"  Got: {builder.call_graph[caller]}"
    )


def test_regex_fallback_resolves_colliding_user_function():
    """Sibling site: the regex fallback (_extract_calls_regex) must also resolve
    a same-file user function whose name collides with a stdlib builtin, instead
    of dropping it via an _is_stdlib pre-gate."""
    builder = CallGraphBuilder(_make_extractor_output())
    caller_id = "main.c:caller"
    calls = builder._extract_calls_regex("close(3);", caller_id)
    assert "main.c:close" in calls, (
        f"Regex fallback dropped the colliding-name same-file user function.\n"
        f"  Got: {calls}"
    )


def test_regex_fallback_still_filters_real_stdlib():
    """Sibling scope guard: the regex fallback must still drop a genuine stdlib
    call with no same-file user definition."""
    builder = CallGraphBuilder(_make_real_stdlib_output())
    calls = builder._extract_calls_regex('printf("hi");', "real.c:greet")
    assert calls == set(), (
        f"Regex fallback wrongly resolved a real stdlib call.\n  Got: {calls}"
    )
