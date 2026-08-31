"""#415: a directory-only pytest run behaves like individual runs.

Running pytest on a single test-DIRECTORY (not the full suite) hits cross-test import
pollution: a test module's header can leave ``sys.modules['parsers']`` bound to the
TEST-DIR shadow (``tests/parsers/`` is a REGULAR package that outranks the source
``parsers/`` namespace whenever ``tests/`` lands on sys.path), so every later
in-process import of ``parsers.<lang>.<module>`` in the same batch resolves into the
test directory and fails (``ModuleNotFoundError: No module named
'parsers.swift.repository_scanner'``). Each file passes alone; the batch self-pollinates;
the full-suite ordering never hits it — a LOCAL developer-experience defect, not a CI
one. Named instances: the swift / rust / python directory batches (PRs #394 / #398 / #407).

This conftest is the SAFETY NET of the fix, not its whole: headers that insert the wrong
directory are corrected at their source (the #299/#309 headers inserted ``tests/`` where
they needed the core root), and tests that mutate import state at RUNTIME are expected
to restore it themselves. Between tests, the SHADOW is surgically unbound: if
``sys.modules['parsers']`` (or a ``parsers.*`` submodule) resolves under the TESTS tree
instead of the source tree, it is a stale test-directory binding and is deleted so the
next import re-resolves against the source. The REAL package is deliberately left warm —
the full-suite ordering shares it across root-level tests, and re-importing modules
mid-suite (unbinding the real package between every test) breaks 113 of them by mixing
old and new module objects. sys.path is deliberately NOT reset: test headers legitimately
install their own directory (the runtime ``from _helpers import ...`` pattern), and a
global baseline restore would break exactly those. No production code changes.
"""
import sys
from pathlib import Path

import pytest

_TESTS_TREE = Path(__file__).resolve().parents[1]          # .../tests
_SRC_TREE = Path(__file__).resolve().parents[2] / "parsers"  # .../parsers


def _is_shadow(name, mod):
    """True when a `parsers`-flavored module resolves under the TESTS tree."""
    if name != "parsers" and not name.startswith("parsers."):
        return False
    paths = []
    f = getattr(mod, "__file__", None)
    if isinstance(f, str):
        paths.append(Path(f))
    p = getattr(mod, "__path__", None)
    if p:
        paths.extend(Path(str(entry)) for entry in p)
    if not paths:
        return False
    return all(_TESTS_TREE == t or _TESTS_TREE in t.parents for t in paths)


def _is_stale_bare_stage_module(name, mod):
    """RETIRED (kept documented, not wired): a bare parser-stage name
    (repository_scanner, function_extractor, ...) bound from the SOURCE
    tree is the cross-language sibling-basename collision — in an
    all-languages-one-process batch, a bare name bound from
    parsers/<lang-A> serves a parsers/<lang-B> import (the observed
    failure: the python parse reusing C's repository_scanner scanned 0
    Python files). Unbinding it between tests does NOT fix that batch — the
    re-import resolves against ACCUMULATED header-inserted parser dirs in
    sys.path order, so the wrong language's module comes right back — and
    it broke 15 full-order tests by re-importing parser stage modules that
    root-level tests hold warm references into. The real fix is migrating
    the per-language pipelines' sibling imports to unique names —
    PRODUCTION code, explicitly out of this issue's scope ("no production
    code changes"). Documented here so the next person does not re-derive
    the dead end."""
    return False


@pytest.fixture(autouse=True)
def _clean_import_state():
    """Unbind a stale test-directory `parsers` shadow before and after each
    test (the shadow is what a directory batch's ModuleNotFoundErrors come
    from; the real source package stays warm — the full-suite ordering
    shares it across root-level tests)."""

    def _unbind_stale():
        for name in [n for n, m in list(sys.modules.items())
                     if _is_shadow(n, m)]:
            del sys.modules[name]

    _unbind_stale()
    yield
    _unbind_stale()
