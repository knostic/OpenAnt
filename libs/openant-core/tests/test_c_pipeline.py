"""Regression tests for three defects in parsers/c/test_pipeline.py.

1. The C CodeQL `database create` command omits `--build-mode=none`, so cpp
   defaults to autobuild and silently degrades (drops findings) on no-build/autotools repos.
2. Overall success ANDed over ALL stages, so an OPTIONAL stage (CodeQL,
   reachability, context enhancer, exploitable) failing/skipping forced a spurious pipeline failure.
3. The six same-named parsers/<lang>/test_pipeline.py orchestrators (CLI
   runners, not tests) collide under `pytest parsers/` (import-file-mismatch). __init__.py does NOT fix
   it -- their bare local imports make them un-importable as package modules -- so a root conftest
   collect_ignore_glob excludes them from collection.

The _compute_success test contains its import: c/test_pipeline.py does bare local imports
(`from repository_scanner import ...`) that would pollute sys.modules with c's parser modules and
shadow the python parser tests -- so the import is done inside the test under a unique name and the
polluting entries are popped in a finally.
"""
import importlib.util
import sys
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]                 # libs/openant-core
C_SRC = CORE / "parsers" / "c" / "test_pipeline.py"


# source-read (the codeql cmd cannot run without the CodeQL CLI)
def test_codeql_create_uses_build_mode_none():
    text = C_SRC.read_text()
    create_idx = text.index("'codeql', 'database', 'create'")
    overwrite_idx = text.index("'--overwrite'", create_idx)
    create_cmd = text[create_idx:overwrite_idx]
    assert "'--build-mode=none'" in create_cmd, \
        "C codeql `database create` must pass --build-mode=none (no autobuild on no-build cpp repos)"


# behavioral, with contained import + sys.modules cleanup
def test_compute_success_ignores_optional_stage_failures():
    cdir = str(CORE / "parsers" / "c")
    added = cdir not in sys.path
    if added:
        sys.path.insert(0, cdir)
    before = set(sys.modules)
    try:
        spec = importlib.util.spec_from_file_location("c_test_pipeline_isolated", str(C_SRC))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        ct = mod.CPipelineTest.__new__(mod.CPipelineTest)  # skip __init__ (no repo I/O needed)

        # required stage ok, optional stages failed -> overall success is True
        ct.results = {"stages": {
            "c_parser": {"success": True},
            "codeql_analysis": {"success": False},
            "reachability_filter": {"success": False},
        }}
        assert ct._compute_success() is True, "optional-stage failures must not fail the pipeline"

        # required stage fails -> overall success is False
        ct.results["stages"]["c_parser"]["success"] = False
        assert ct._compute_success() is False, "a required stage failure must fail the pipeline"
    finally:
        if added:
            sys.path.remove(cdir)
        for m in set(sys.modules) - before:
            root = m.split(".")[0]
            if root in ("repository_scanner", "function_extractor", "call_graph_builder",
                        "unit_generator", "c_test_pipeline_isolated"):
                sys.modules.pop(m, None)


# the parsers/<lang>/test_pipeline.py orchestrators (CLI runners, NOT
# pytest tests) must be excluded from collection so their shared basename does not collide under
# `pytest parsers/` (import-file-mismatch). __init__.py does not fix it -- the orchestrators' bare
# local imports make them un-importable as package modules -- so we exclude them from collection.
def test_parser_orchestrators_excluded_from_pytest_collection():
    conftest = CORE / "conftest.py"
    assert conftest.exists(), "libs/openant-core/conftest.py missing (collect_ignore for orchestrators)"
    text = conftest.read_text()
    assert "collect_ignore_glob" in text and "parsers/*/test_pipeline.py" in text, \
        "root conftest must collect_ignore_glob the parsers/*/test_pipeline.py orchestrators"
