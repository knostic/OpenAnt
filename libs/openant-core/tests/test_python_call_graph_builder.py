"""Regression tests for Python call-graph builder (parsers/python/call_graph_builder.py) edge-fidelity bugs.

Seven independent defects in the Python CallGraphBuilder, each pinned by its own test:

__init__.py re-export: _resolve_import never probes package ``__init__.py`` nor follows
  ``from .submodule import name`` re-exports, so a call to a name re-exported via a package
  __init__.py (ubiquitous in Python public APIs) gets no call edge.
Local-variable type dispatch: obj.method() on a local variable of a locally-known type
  (``v = ClassName(); v.method()``) is routed to _resolve_module_call, which only knows
  imports/same-file class NAMES, never a local var's bound type -> edge dropped.
super() resolution: the super().method() branch in
  _resolve_call_node returns None unconditionally ("skip for now"), so an inherited
  parent method reachable only via super() is dropped from the graph -- even when the
  parent class is in the repo (cross-file inheritance).
Deterministic ordering: per-function callee lists are built by iterating a Python
  ``set`` with no sorted(), so call_graph / reverse_call_graph value ORDER is
  PYTHONHASHSEED-dependent -> non-deterministic output on identical input.
HOF callback arguments: higher-order-function callback arguments
  (``map(func, xs)``, ``sorted(xs, key=func)``) are never read -- _resolve_call_node only
  inspects node.func, never node.args/node.keywords -> callback-only functions look
  unreachable.

Loads call_graph_builder under a UNIQUE importlib module name (the bare
'call_graph_builder' basename is shared by the c/go/php/ruby/zig parsers, so a plain
import would pollute sys.modules for the rest of the suite).
"""
import importlib.util
import sys
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]                  # libs/openant-core
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))                           # for utilities.* imported by the module

_spec = importlib.util.spec_from_file_location(
    "py_call_graph_builder_isolated", str(CORE / "parsers" / "python" / "call_graph_builder.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
CallGraphBuilder = _mod.CallGraphBuilder


def _fn(file_path, name, code, class_name=None):
    """Build one entry in the extractor 'functions' map."""
    fid = f"{file_path}:{class_name + '.' if class_name else ''}{name}"
    data = {"name": name, "file_path": file_path, "code": code}
    if class_name:
        data["class_name"] = class_name
    return fid, data


def _build(functions, imports=None, classes=None):
    out = {
        "repository": "/tmp/fake",
        "functions": functions,
        "imports": imports or {},
        "classes": classes or {},
    }
    b = CallGraphBuilder(out)
    b.build_call_graph()
    return b


# ---- __init__.py re-export resolution ----
def test_init_reexport_resolved_to_origin():
    helpers = "utils/helpers.py"
    init = "utils/__init__.py"
    main = "main.py"
    fns = {}
    fns.update(dict([_fn(helpers, "sanitize", "def sanitize(x):\n    return x\n")]))
    # utils/__init__.py re-exports sanitize via `from .helpers import sanitize`
    fid, data = _fn(main, "handler", "def handler(self):\n    return sanitize(self.value)\n")
    fns[fid] = data
    imports = {
        # main.py imports sanitize from the package `utils` (re-export consumer)
        main: {"sanitize": "utils.sanitize"},
        init: {"sanitize": "utils.helpers.sanitize"},
    }
    # function_extractor records __init__.py imports under the package file path.
    b = _build(fns, imports=imports)
    edges = b.call_graph.get(f"{main}:handler", [])
    assert f"{helpers}:sanitize" in edges, (
        f"re-exported sanitize not resolved through utils/__init__.py: {edges}")


# ---- local-variable type dispatch ----
def test_local_var_type_dispatch_resolved():
    f = "app.py"
    fns = {}
    fid_m, data_m = _fn(f, "run", "def run(self):\n    return self.x\n", class_name="Service")
    fns[fid_m] = data_m
    caller = ("def use():\n"
              "    svc = Service()\n"
              "    return svc.run()\n")
    fid_c, data_c = _fn(f, "use", caller)
    fns[fid_c] = data_c
    classes = {f"{f}:Service": {"name": "Service", "file_path": f, "bases": []}}
    b = _build(fns, classes=classes)
    edges = b.call_graph.get(f"{f}:use", [])
    assert f"{f}:Service.run" in edges, (
        f"svc.run() on local var of known type Service not resolved: {edges}")


# ---- super().method() resolution ----
def test_super_call_resolved_cross_file():
    base_f = "base.py"
    child_f = "main.py"
    fns = {}
    fid_b, data_b = _fn(base_f, "process", "def process(self):\n    return 1\n", class_name="Base")
    fns[fid_b] = data_b
    child_code = "def process(self):\n    return super().process()\n"
    fid_c, data_c = _fn(child_f, "process", child_code, class_name="Child")
    fns[fid_c] = data_c
    classes = {
        f"{base_f}:Base": {"name": "Base", "file_path": base_f, "bases": []},
        f"{child_f}:Child": {"name": "Child", "file_path": child_f, "bases": ["Base"]},
    }
    b = _build(fns, classes=classes)
    edges = b.call_graph.get(f"{child_f}:Child.process", [])
    assert f"{base_f}:Base.process" in edges, (
        f"super().process() not resolved to cross-file parent Base.process: {edges}")


# ---- deterministic ordering ----
def test_call_lists_are_sorted_deterministic():
    f = "m.py"
    fns = {}
    for name in ("zeta", "alpha", "mid"):
        fid, data = _fn(f, name, f"def {name}():\n    return 1\n")
        fns[fid] = data
    caller = "def driver():\n    return zeta() + alpha() + mid()\n"
    fid_d, data_d = _fn(f, "driver", caller)
    fns[fid_d] = data_d
    b = _build(fns)
    edges = b.call_graph.get(f"{f}:driver", [])
    assert edges == sorted(edges), f"call_graph edge list is not deterministically sorted: {edges}"


# ---- HOF callback arguments tracked ----
def test_hof_callback_arg_tracked():
    f = "h.py"
    fns = {}
    fid_cb, data_cb = _fn(f, "scorer", "def scorer(x):\n    return x\n")
    fns[fid_cb] = data_cb
    caller = "def driver(items):\n    return sorted(items, key=scorer)\n"
    fid_d, data_d = _fn(f, "driver", caller)
    fns[fid_d] = data_d
    b = _build(fns)
    edges = b.call_graph.get(f"{f}:driver", [])
    assert f"{f}:scorer" in edges, (
        f"HOF callback 'scorer' passed to sorted(key=...) not tracked as an edge: {edges}")
