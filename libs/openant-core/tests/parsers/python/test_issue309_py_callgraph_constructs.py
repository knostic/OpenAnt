"""Regression tests for issue #309 — four Python call-graph constructs
resolve to no call edge, leaving live functions with empty caller sets
(reachability then cannot distinguish them from dead code).

The four (each reproduced with a control that DOES resolve, so a null
result is never a broken harness):
1. `from pkg import f` where f is DEFINED in pkg/__init__.py (a re-export
   through the same file resolves; the definition does not);
2. `from X import f as g` (the import alias: the extractor records
   g→X.f, but the resolver looks for a function named g at X's path);
3. a `@property` READ (an ast.Attribute in Load context — the builder
   walks only ast.Call; calling the property's result DOES emit an edge);
4. a method on a type-annotated parameter (ast.arg.annotation is never
   read; a local `w = Widget()` receiver resolves).

Contract: each construct gains its edge — the over-seed direction for
reachability (a reference/edge that is not a call is still reachability
signal — the #295 family). WHAT IS SCANNED does not change for any
control case.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

# #415: parents[2] from tests/parsers/python/<file> is `tests/` — and tests/parsers
# is a REGULAR package that outranks the source parsers/ namespace, so every
# later in-process parsers.* import in the same pytest batch resolved into the
# TEST directory. The insert needs the CORE root, parents[3].
PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.parser_adapter import parse_repository  # noqa: E402


def _cg(files: dict):
    with tempfile.TemporaryDirectory() as _repo, tempfile.TemporaryDirectory() as out:
        repo = Path(_repo)
        for rel, content in files.items():
            p = repo / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        parse_repository(str(repo), out, language="python",
                       processing_level="all", skip_tests=True, name="r")
        with open(Path(out) / "call_graph.json", encoding="utf-8") as fh:
            return json.load(fh)["call_graph"]


def test_init_definition_resolves():
    cg = _cg({
        "pkg/impl.py": "def reexported(): return 2\n",
        "pkg/__init__.py": ("from .impl import reexported\n"
                            "def defined_here(): return 1\n"),
        "main.py": ("from pkg import defined_here\n"
                    "from pkg import reexported\n"
                    "def caller():\n"
                    "    defined_here()\n"
                    "    reexported()\n"),
    })
    edges = cg.get("main.py:caller", [])
    assert "pkg/impl.py:reexported" in edges, edges       # control
    assert "pkg/__init__.py:defined_here" in edges, edges  # the defect


def test_import_alias_resolves():
    cg = _cg({
        "pkg/impl.py": ("def f_a(): return 1\n"
                        "def f_b(): return 2\n"
                        "def f_c(): return 3\n"),
        "main.py": ("from pkg.impl import f_a as aliased\n"
                    "from pkg.impl import f_b\n"
                    "import pkg.impl as mod\n"
                    "def c_funcalias():  aliased()\n"
                    "def c_plain():      f_b()\n"
                    "def c_modalias():   mod.f_c()\n"),
    })
    assert "pkg/impl.py:f_a" in cg.get("main.py:c_funcalias", []), cg
    assert "pkg/impl.py:f_b" in cg.get("main.py:c_plain", [])       # control
    assert "pkg/impl.py:f_c" in cg.get("main.py:c_modalias", [])    # control


def test_property_read_emits_reference_edge():
    cg = _cg({
        "app.py": ("class Widget:\n"
                   "    @property\n"
                   "    def secret_prop(self): return 1\n"
                   "    def normal_method(self): return 2\n"
                   "def reads_property():\n"
                   "    w = Widget()\n"
                   "    return w.secret_prop\n"
                   "def calls_method():\n"
                   "    w = Widget()\n"
                   "    return w.normal_method()\n"),
    })
    assert "app.py:Widget.normal_method" in cg.get("app.py:calls_method", [])
    assert "app.py:Widget.secret_prop" in cg.get("app.py:reads_property", []), (
        "a @property READ is the idiomatic use of the property; the reference"
        "edge is the over-seed direction (a property reached only by reads "
        "is otherwise indistinguishable from dead code)")


def test_annotated_parameter_receiver_resolves():
    cg = _cg({
        "shapes.py": ("class Widget:\n"
                      "    def m_annotated(self): return 1\n"
                      "    def m_local(self): return 2\n"
                      "    def m_modlevel(self): return 3\n"
                      "WIDGET = Widget()\n"
                      "def via_annotated_param(w: Widget):  return w.m_annotated()\n"
                      "def via_local_var():\n"
                      "    w = Widget()\n"
                      "    return w.m_local()\n"
                      "def via_module_instance():           return WIDGET.m_modlevel()\n"),
    })
    assert "shapes.py:Widget.m_annotated" in cg.get("shapes.py:via_annotated_param", [])
    assert "shapes.py:Widget.m_local" in cg.get("shapes.py:via_local_var", [])  # control
