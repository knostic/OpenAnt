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
    the SOURCE parsers/. Runs against the FORCED post-poison state (this
    test's own setup re-installs both halves the way a real off-by-one
    header would leave them), so the victim exercises the CONFTEST's cleanup
    in the order the fixture actually fires — order-independent."""
    # re-install the poison the way a header leaves it (both halves) —
    # and purge the parsers.* family FIRST: an in-batch run has earlier
    # tests' REAL modules cached, and the sys.modules cache would serve
    # them past the shadow (the historical failing state was a process
    # where no parsers import had run yet — the purge reproduces exactly
    # that, deterministically, in any batch order).
    import types
    for _n in [n for n in list(sys.modules)
               if n == "parsers" or n.startswith("parsers.")]:
        del sys.modules[_n]
    entry = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    shadow = types.ModuleType("parsers")
    shadow.__file__ = str(Path(entry) / "parsers" / "__init__.py")
    shadow.__path__ = [str(Path(entry) / "parsers")]
    sys.path.insert(0, entry)
    sys.modules["parsers"] = shadow
    # the poison persists INTO this test (no cleanup) — the fixture at the
    # NEXT setup clears it; here we verify the victim itself would fail:
    spec = importlib.util.spec_from_file_location(
        "swift_pipeline_iso_415chk", _CORE / "parsers" / "swift" / "test_pipeline.py")
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
        raise AssertionError("the poisoned state did NOT break the load — the repro is vacuous")
    except ModuleNotFoundError:
        pass
    finally:
        sys.path.remove(entry)
        for _n in [n for n in list(sys.modules)
                   if n == "parsers" or n.startswith("parsers.")]:
            del sys.modules[_n]   # the failed import bound parsers.swift to the shadow too
    # cleaned state: the load succeeds and resolves against the SOURCE tree
    spec = importlib.util.spec_from_file_location(
        "swift_pipeline_iso_415ok", _CORE / "parsers" / "swift" / "test_pipeline.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert hasattr(mod, "main"), "the swift pipeline module did not load"
    from parsers.swift import repository_scanner as rs
    assert str(_CORE / "parsers") in str(rs.__file__), (
        "parsers.swift.repository_scanner resolved against the TEST shadow, "
        f"not the source tree: {rs.__file__}"
    )


def test_the_fixture_neutralizes_a_real_header_insert():
    """Wave r1 (fable, the HIGH finding): the old fixture only cured the
    SELF-REMOVING poisoner — a real header's tests/ insert persists for the
    process lifetime, and the very next parsers.* import re-bound the
    shadow despite the unbind. The fixture now strips the shadow-path ENTRY
    too: simulate a real header (insert, NO cleanup) and verify the next
    test's setup state."""
    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location(
        "parsers_conftest_iso_415", Path(__file__).parent / "conftest.py")
    _cmod = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_cmod)
    _strip = _cmod._strip_shadow_path_entries
    import types

    entry = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    sys.path.insert(0, entry)          # a real header leaves this behind
    shadow = types.ModuleType("parsers")
    shadow.__file__ = str(Path(entry) / "parsers" / "__init__.py")
    shadow.__path__ = [str(Path(entry) / "parsers")]
    sys.modules["parsers"] = shadow    # ...and this
    try:
        # the fixture's strip (what the NEXT test's setup runs):
        removed = _strip()
        assert entry in [str(r) for r in removed] or entry not in sys.path
        assert entry not in sys.path, "the poison entry survived the strip"
        for _n in [n for n in list(sys.modules)
                   if n == "parsers" or n.startswith("parsers.")]:
            del sys.modules[_n]
        import parsers
        assert "tests" not in str(getattr(parsers, "__file__", "")), (
            f"the shadow re-bound after the strip: {getattr(parsers, '__file__', None)}"
        )
    finally:
        if entry in sys.path:
            sys.path.remove(entry)
        for _n in [n for n in list(sys.modules)
                   if n == "parsers" or n.startswith("parsers.")]:
            del sys.modules[_n]
