"""Import-resolution precision/recall for the Python call graph builder.

Bug (byproduct-deepcheck 2026-06-12, P4): `_resolve_import` Strategy 2 matched a
function's file to the imported module with a bare string `endswith` on the dotted
module path:

    module_path.endswith(expected_module) or expected_module.endswith(module_path)

That `endswith` matched ACROSS component boundaries: `from utils import helper`
bound to `extra_utils.py:helper` because `'extra_utils'.endswith('utils')`. No
Python module layout produces that (the module `utils` is not the file
`extra_utils.py`), so it is a genuinely-false edge.

Fix: match by dotted COMPONENTS, in EITHER direction — the imported module is a
component-suffix of the file path (a repo-root prefix on the file, `src/pkg/auth.py`
for `pkg.auth`) OR the file path is a component-suffix of the imported module (the
repo-IS-the-package self-import, `auth.py` == `myapp/auth.py` recorded shallow, for
`from myapp.auth import ...`). Both directions are real layouts and are kept; only the
substring-crossing matches are dropped.

Note: `from pkg.auth import login` -> a top-level `auth.py` is NOT provably false —
it is structurally identical to the repo-is-package self-import, so under the
"never miss a real edge" rule it is kept (a false edge is triageable; a dropped real
edge silently removes attack surface from the reachability filter).

These tests pin both the precision drops (substring-crossing edges gone) AND recall
(every component-suffix match, both directions, still resolves).
"""

import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.python.call_graph_builder import CallGraphBuilder


def _build(functions: dict, imports: dict) -> CallGraphBuilder:
    b = CallGraphBuilder({"repository": "/tmp/fake", "imports": imports,
                          "classes": {}, "functions": functions})
    b.build_call_graph()
    return b


def _fn(file_path, name, code, class_name=None):
    return {"name": name, "qualified_name": (f"{class_name}.{name}" if class_name else name),
            "file_path": file_path, "class_name": class_name, "unit_type": "function", "code": code}


# ---------- PRECISION: substring-crossing (genuinely-false) edges must NOT appear ----------

def test_no_false_edge_substring_module():
    """`from utils import helper` must NOT bind to extra_utils.py (substring suffix)."""
    fns = {"main.py:run": _fn("main.py", "run", "def run():\n    return helper()\n"),
           "utils.py:other": _fn("utils.py", "other", "def other():\n    return 0\n"),
           "extra_utils.py:helper": _fn("extra_utils.py", "helper", "def helper():\n    return 1\n")}
    b = _build(fns, {"main.py": {"helper": "utils.helper"}})
    assert "extra_utils.py:helper" not in b.call_graph.get("main.py:run", []), (
        f"false edge to extra_utils.py:helper: {b.call_graph.get('main.py:run')}")


def test_no_false_edge_substring_module_auth():
    """`from auth import login` must NOT bind to extra_auth.py."""
    fns = {"main.py:run": _fn("main.py", "run", "def run():\n    return login()\n"),
           "extra_auth.py:login": _fn("extra_auth.py", "login", "def login():\n    return 1\n")}
    b = _build(fns, {"main.py": {"login": "auth.login"}})
    assert "extra_auth.py:login" not in b.call_graph.get("main.py:run", []), (
        f"false edge to extra_auth.py:login: {b.call_graph.get('main.py:run')}")


# ---------- RECALL: legitimate imports must STILL resolve (no findings lost) ----------

def test_recall_exact_package_path():
    """`from pkg.auth import login` with a real pkg/auth.py MUST resolve."""
    fns = {"main.py:run": _fn("main.py", "run", "def run():\n    return login()\n"),
           "pkg/auth.py:login": _fn("pkg/auth.py", "login", "def login():\n    return 1\n")}
    b = _build(fns, {"main.py": {"login": "pkg.auth.login"}})
    assert "pkg/auth.py:login" in b.call_graph.get("main.py:run", []), (
        f"legit package import dropped: {b.call_graph.get('main.py:run')}")


def test_recall_repo_root_prefix():
    """`from pkg.auth import login` with src/pkg/auth.py (repo-root prefix) MUST resolve."""
    fns = {"main.py:run": _fn("main.py", "run", "def run():\n    return login()\n"),
           "src/pkg/auth.py:login": _fn("src/pkg/auth.py", "login", "def login():\n    return 1\n")}
    b = _build(fns, {"main.py": {"login": "pkg.auth.login"}})
    assert "src/pkg/auth.py:login" in b.call_graph.get("main.py:run", []), (
        f"legit repo-root-prefixed import dropped: {b.call_graph.get('main.py:run')}")


def test_recall_top_level_module():
    """`from auth import login` with a real top-level auth.py MUST resolve."""
    fns = {"main.py:run": _fn("main.py", "run", "def run():\n    return login()\n"),
           "auth.py:login": _fn("auth.py", "login", "def login():\n    return 1\n")}
    b = _build(fns, {"main.py": {"login": "auth.login"}})
    assert "auth.py:login" in b.call_graph.get("main.py:run", []), (
        f"legit top-level import dropped: {b.call_graph.get('main.py:run')}")


def test_recall_repo_is_package_self_import(tmp_path=None):
    """`from myapp.auth import login` with the repo recorded shallow (`auth.py` ==
    `myapp/auth.py`) MUST resolve — the repo-IS-the-package self-import. This is the
    reverse-direction (import deeper than the recorded file) case; a forward-only
    component match would WRONGLY drop it (recall regression caught by review)."""
    fns = {"main.py:run": _fn("main.py", "run", "def run():\n    return login()\n"),
           "auth.py:login": _fn("auth.py", "login", "def login():\n    return 1\n")}
    b = _build(fns, {"main.py": {"login": "myapp.auth.login"}})
    assert "auth.py:login" in b.call_graph.get("main.py:run", []), (
        f"repo-is-package self-import dropped (reverse-direction recall regression): "
        f"{b.call_graph.get('main.py:run')}")


def test_recall_reverse_prefix_nested(tmp_path=None):
    """`from a.b.c import func` with the file recorded as `b/c.py` MUST resolve
    (nested namespace/package layout — file shallower than the absolute import)."""
    fns = {"main.py:run": _fn("main.py", "run", "def run():\n    return func()\n"),
           "b/c.py:func": _fn("b/c.py", "func", "def func():\n    return 1\n")}
    b = _build(fns, {"main.py": {"func": "a.b.c.func"}})
    assert "b/c.py:func" in b.call_graph.get("main.py:run", []), (
        f"nested reverse-prefix import dropped: {b.call_graph.get('main.py:run')}")


def test_recall_relative_import_preserved():
    """Adversarial recall guard: a relative import `from . import helper` (stored as a
    bare name with no module) must STILL resolve — the precision fix must not drop the
    name-only resolution path the old code provided for relative imports."""
    fns = {"pkg/main.py:run": _fn("pkg/main.py", "run", "def run():\n    return helper()\n"),
           "pkg/util.py:helper": _fn("pkg/util.py", "helper", "def helper():\n    return 1\n")}
    # `from . import helper` -> extractor stores imports['helper'] = 'helper' (bare, no module)
    b = _build(fns, {"pkg/main.py": {"helper": "helper"}})
    assert "pkg/util.py:helper" in b.call_graph.get("pkg/main.py:run", []), (
        f"relative-import resolution dropped by the precision fix: "
        f"{b.call_graph.get('pkg/main.py:run')}")
