"""Bug 2 regression: a `static inline` function defined in an INCLUDED header
is callable from the including translation unit (the header-inline idiom — each
TU gets its own copy). The resolver dropped the edge because `_is_visible_from`
treated any cross-file `static` as internal-linkage-invisible, which is correct
for a `.c` translation unit but wrong for an included `.h` header.

Paired must-preserve: tests/parsers/c/test_c_call_resolution_precision.py
::test_unique_name_fallback_skips_static_in_other_file — a `static` fn in another
`.c` must STILL NOT resolve cross-TU. This fix only un-blocks included headers.
"""
import sys
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[3]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

pytest.importorskip("tree_sitter_c")

from parsers.c.call_graph_builder import CallGraphBuilder  # noqa: E402


def _build(eo):
    b = CallGraphBuilder(eo)
    b.build_call_graph()
    out = b.build() if hasattr(b, "build") else b.export()
    return out.get("call_graph", {})


def test_static_inline_in_included_header_resolves():
    eo = {
        "functions": {
            "m.c:caller": {"name": "caller", "file_path": "m.c",
                           "code": "int caller(int n){ return helper(n); }"},
            "h.h:helper": {"name": "helper", "file_path": "h.h",
                           "is_static": True, "is_inline": True,
                           "code": "static inline int helper(int x){ return x + 1; }"},
        },
        "includes": {"m.c": ["h.h"], "h.h": []},
    }
    edges = _build(eo).get("m.c:caller", [])
    assert "h.h:helper" in edges, f"static-inline header call dropped: {edges}"


def test_static_in_other_dot_c_still_rejected():
    # The #84 precision invariant, re-asserted locally: a static fn in another
    # .c TU must NOT resolve (no #include relationship; genuinely file-local).
    eo = {
        "functions": {
            "a.c:caller": {"name": "caller", "file_path": "a.c",
                           "code": "void caller(void){ helper(); }"},
            "b.c:helper": {"name": "helper", "file_path": "b.c", "is_static": True,
                           "code": "static void helper(void){}"},
        },
        "includes": {"a.c": [], "b.c": []},
    }
    edges = _build(eo).get("a.c:caller", [])
    assert "b.c:helper" not in edges, f"static helper() in b.c wrongly resolved cross-TU: {edges}"


def test_non_static_in_included_header_still_resolves():
    # Guard: a normal (extern) header function must keep resolving (no regression).
    eo = {
        "functions": {
            "m.c:caller": {"name": "caller", "file_path": "m.c",
                           "code": "int caller(int n){ return ext_helper(n); }"},
            "api.h:ext_helper": {"name": "ext_helper", "file_path": "api.h",
                                 "is_static": False,
                                 "code": "int ext_helper(int x);"},
        },
        "includes": {"m.c": ["api.h"], "api.h": []},
    }
    edges = _build(eo).get("m.c:caller", [])
    assert "api.h:ext_helper" in edges, f"extern header call dropped: {edges}"
