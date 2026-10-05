"""Regression tests for issue #627 — order-dependent parser-test failures.

``pytest tests/parsers`` failed 12 tests on a clean master (4 in
``test_issue309_py_callgraph_constructs.py``, 8 in
``test_issue440_mro_import_bases.py``) while every file alone, the two
failing files together, and the full suite passed.

Root cause (bisected to the poisoning file
``tests/parsers/c/test_empty_seed_keep_all.py``): it execs
``parsers/c/test_pipeline.py`` for its ``CPipelineTest``, and that
module — like ``parsers/python/parse_repository.py`` and the PHP and
Ruby pipeline scripts (Go, JavaScript, and Swift use qualified
imports; their loaders leak sys.path state but do not poison the
bare-name cache) — imports its parser machinery under BARE module names
(``function_extractor``, ``call_graph_builder``, ``repository_scanner``,
``unit_generator``) via a ``sys.path`` entry. The exec leaves the C
versions in ``sys.modules``; a later ``parse_repository(language="python")``
then gets the C ``FunctionExtractor`` (first-import wins), whose
statistics lack ``standalone_functions`` — the resolution-shaped failures.

The full suite passes only because some earlier test happens to import the
PYTHON bare names first — order decides the winner, which is exactly the
flakiness class. The fix is loader isolation (snapshot/restore of ``sys.path`` and
``sys.modules`` at loader ENTRY, around the exec — new keys removed,
replaced keys restored), applied to the loaders whose pipelines import
bare names: c, zig, php, ruby.

Contract pinned here (self-contained — the poisoning is reproduced
WITHIN one test, so no invocation order is required to see it):
- after ``_load_pipeline()`` returns, ``sys.path`` and ``sys.modules``
  are byte-identical to the pre-call state (the exec left no import
  state behind);
- the end-to-end repro: exec the C pipeline loader, then run a python
  ``parse_repository`` resolution that depends on the python-shaped
  statistics — it must not see the C machinery.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

# Load the poisoner's loader by path (no package context between sibling
# test files — the same importlib idiom the poisoner itself uses).
_POISONER = pathlib.Path(__file__).resolve().parent / "test_empty_seed_keep_all.py"
_spec = importlib.util.spec_from_file_location("issue627_poisoner_loader", _POISONER)
_poisoner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_poisoner)
_load_pipeline = _poisoner._load_pipeline


def test_load_pipeline_leaves_no_import_state():
    before_path = list(sys.path)
    before_modules = dict(sys.modules)
    _load_pipeline()
    assert sys.path == before_path, (
        "the pipeline exec must restore sys.path — a leftover parser-dir "
        "entry shadows later imports (order-dependent failures, #627)")
    assert sys.modules.keys() == before_modules.keys(), (
        "the pipeline exec must not leave new modules in sys.modules — "
        "the bare parser names it imports poison every later "
        "same-named import (order-dependent failures, #627)")
    for k, m in before_modules.items():
        assert sys.modules[k] is m, (
            f"module {k!r} was replaced by the pipeline exec — the "
            "replaced object poisons later imports (#627)")


def test_python_resolution_after_c_pipeline_exec():
    # The end-to-end repro of the 12 failures: exec the C pipeline loader
    # (the poisoner), then run the python call-graph resolution the
    # failing tests ran — the python statistics keys must exist.
    import json
    import tempfile
    from pathlib import Path

    _load_pipeline()  # the poisoning exec (post-fix: state-isolated)

    from core.parser_adapter import parse_repository

    with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as out:
        rp = Path(repo)
        (rp / "pkg").mkdir()
        (rp / "pkg" / "__init__.py").write_text(
            "def defined_here(): return 1\n")
        (rp / "main.py").write_text(
            "from pkg import defined_here\n"
            "def caller():\n    return defined_here()\n")
        parse_repository(str(rp), out, language="python",
                         processing_level="all", skip_tests=True, name="r")
        call_graph = json.loads(
            (Path(out) / "call_graph.json").read_text())["call_graph"]
    # the python extractor's statistics carried standalone_functions
    # (the KeyError of the poisoned run); the graph itself resolves the
    # re-export — the resolution shape the 12 failing tests asserted.
    assert "main.py:caller" in call_graph
    # the resolution shape the 12 failing tests asserted: the init-defined
    # re-exported symbol resolves (the poisoned run got the C extractor,
    # whose statistics lack the python keys)
    edges = call_graph.get("main.py:caller", {})
    assert any("defined_here" in str(k) for k in list(edges) + [
        e for v in (edges.values() if isinstance(edges, dict) else [])
        for e in (v if isinstance(v, (list, dict)) else [v])]), (
        "the pkg.__init__-defined symbol must resolve in the call graph")
