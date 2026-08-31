"""#415: a directory-only pytest run behaves like individual runs.

Running pytest on a single test-DIRECTORY (not the full suite) hits cross-test import
pollution: a test module's IMPORT-TIME `sys.path.insert` (e.g. #299's header inserts
`tests/` — and `tests/parsers/` is a regular package, which SHADOWS the source
`parsers/` namespace package) makes every later in-process import of
`parsers.<lang>.<module>` resolve into the TEST directory and fail
(`ModuleNotFoundError: No module named 'parsers.swift.repository_scanner'`). The
named instances (swift/rust/python batches, PRs #394/#398/#407) share the shape: each
file passes alone, the batch self-pollinates, and the full-suite ordering never hits
it — a LOCAL developer-experience defect, not a CI one.

The two tests below mirror the real pair in one file, in the poisoner-then-victim
order a directory batch produces: the first does exactly what
`test_issue299_swift_container_dispatch.py`'s import block does, the second exactly
what `test_swift_prune_telemetry.py::_load_pipeline` does. The conftest's
between-test import-state fixture (baseline sys.path captured at conftest import —
BEFORE any test module mutates it — plus a parsers-flavored sys.modules purge) is
what makes the second pass.
"""
import importlib.util
import os
import sys
from pathlib import Path

_CORE = Path(__file__).resolve().parents[2]


def test_poisoner_inserts_tests_dir_like_the_299_header():
    """The pre-#415 batch state, reproduced minimally and SELF-CLEANED (the
    convention this fix asks of runtime import-state mutation): tests/ on
    sys.path binds sys.modules['parsers'] to tests/parsers/ — the regular
    package that outranks the source namespace — which is exactly what the
    un-fixed #299 header left behind for the next test in the batch."""
    entry = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    sys.path.insert(0, entry)
    try:
        import parsers  # noqa: F401, E402 — binds the test-dir shadow
        assert "parsers" in sys.modules
    finally:
        sys.path.remove(entry)


def test_victim_loads_the_swift_pipeline_after_the_poisoner():
    """Exactly test_swift_prune_telemetry's _load_pipeline: an importlib exec of
    parsers/swift/test_pipeline.py, whose package imports must resolve against
    the SOURCE parsers/ — not the test-dir shadow the previous test installed."""
    spec = importlib.util.spec_from_file_location(
        "swift_pipeline_iso_415red", _CORE / "parsers" / "swift" / "test_pipeline.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)   # ModuleNotFoundError on a polluted batch
    assert hasattr(mod, "main"), "the swift pipeline module did not load"
    # And the package import resolved against the SOURCE tree.
    from parsers.swift import repository_scanner as rs
    assert str(_CORE / "parsers") in str(rs.__file__), (
        "parsers.swift.repository_scanner resolved against the TEST shadow, "
        f"not the source tree: {rs.__file__}"
    )
