"""Regression tests for issue #273 — two wrong-trust paths in locating
config/languages.json.

(1) The context corrector's fixed four-``.parent`` walk matched only the
checkout depth; in a wheel install the config sits two parents up, so the
walk missed and ``except Exception: pass`` silently fell back to the frozen
``_FALLBACK_SKIP_DIRS`` — installed layouts never saw config updates to
skip_dirs. Fix: route through the registry's own resolver.

(2) The resolver's CWD-upward fallback trusts the scanned repo: a
``config/languages.json`` planted in the working directory could supply
``parser.script`` — and ``_CORE_ROOT / script`` does NOT constrain an
absolute path (``Path('/a') / '/b' == Path('/b')``), so the planted script
was executed via ``sys.executable``. Fix: ``parser_script_path`` resolves
and requires the result to stay under ``_CORE_ROOT`` (absolute values and
``..``/symlink escapes rejected), closing the exec vector for EVERY config
source; the CWD leg gains stderr visibility (the residual data-only trust
becomes loud).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.language_registry import (  # noqa: E402
    _CORE_ROOT, LanguageSpec, parser_script_path,
)


def _spec_with_script(script):
    return LanguageSpec(
        name="testlang", extensions=(".t",),
        parser_mode="subprocess", parser_script=script,
        bootstrap=None, fence="test", docker_template=None, enabled=True,
    )


def test_absolute_script_value_rejected(monkeypatch):
    """A planted absolute parser.script must NOT resolve to itself
    (Path('/root') / '/abs' == '/abs' — the exec vector #273 names)."""
    import core.language_registry as lr

    monkeypatch.setattr(
        lr, "load_registry",
        lambda: {"testlang": _spec_with_script("/tmp/evil.py")})
    assert parser_script_path("testlang") is None


def test_dotdot_escape_rejected(monkeypatch):
    import core.language_registry as lr

    monkeypatch.setattr(
        lr, "load_registry",
        lambda: {"testlang": _spec_with_script("../../etc/passwd")})
    assert parser_script_path("testlang") is None


def test_legitimate_relative_script_resolves(monkeypatch):
    import core.language_registry as lr

    real = (Path(__file__).parent.parent / "parsers" / "python"
            / "parse_repository.py").relative_to(_CORE_ROOT)
    monkeypatch.setattr(
        lr, "load_registry",
        lambda: {"testlang": _spec_with_script(str(real))})
    p = parser_script_path("testlang")
    assert p is not None
    assert p.is_relative_to(_CORE_ROOT.resolve())


def test_corrector_uses_registry_resolver(monkeypatch):
    """(1): the corrector routes through find_languages_config — no more
    fixed-depth walk (which missed wheel layouts and silently degraded)."""
    import utilities.context_corrector as cc

    calls = {"n": 0}

    def _fake_find():
        calls["n"] += 1
        return Path("/nonexistent/does/not/matter")

    monkeypatch.setattr(
        "core.language_registry.find_languages_config", _fake_find)
    # call the real function; it should consult the resolver (even though
    # the returned path does not exist — the CALL is the contract)
    cc._canonical_skip_dirs()
    assert calls["n"] >= 1, (
        "context_corrector must resolve config via find_languages_config, "
        "not a fixed-depth .parent walk"
    )


def test_cwd_leg_visibility(capsys, monkeypatch, tmp_path):
    """(2) residual made loud — driving the REAL fallback order: the file
    leg must miss, the CWD leg must hit via the REAL _search_upward walk
    from Path.cwd()."""
    import core.language_registry as lr

    # Make the FILE leg miss: the repo tree has no config above core/
    # (it does in the checkout — so point _search_upward's file-leg start
    # at an empty temp dir via patching find's first call only). Simplest
    # honest drive: chdir into tmp_path WITH a config, and make the
    # __file__ leg miss by patching _search_upward to distinguish legs.
    real_search = lr._search_upward

    def _leg_aware_search(start):
        # file leg starts under libs/openant-core/core; cwd leg at cwd
        if "openant-core" in str(start):
            return None  # the file leg misses
        return real_search(start)  # the CWD leg uses the REAL walk

    monkeypatch.setattr(lr, "_search_upward", _leg_aware_search)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config").mkdir(exist_ok=True)
    (tmp_path / "config" / "languages.json").write_text('{"languages": {}}')
    found = lr.find_languages_config()
    assert found is not None
    assert found == (tmp_path / "config" / "languages.json").resolve()
    err = capsys.readouterr().err
    assert "working directory" in err, (
        f"the CWD-leg config source must be visible on stderr (got {err!r})"
    )


def test_caller_rejects_guarded_script_clearly(monkeypatch, tmp_path):
    """Wave catch (3-seat convergence): the SOLE caller of
    parser_script_path must handle None with a clear, typed message —
    not spawn sys.executable 'None' and fail misleadingly."""
    import pytest as _pytest
    import core.language_registry as lr
    import core.parser_adapter as pa

    bad = {"testlang": _spec_with_script("/tmp/evil.py")}
    monkeypatch.setattr(lr, "load_registry", lambda: bad)
    monkeypatch.setattr(pa, "load_registry", lambda: bad)
    with _pytest.raises(RuntimeError, match="containment guard"):
        pa._parse_via_subprocess(
            language="testlang", repo_path=str(tmp_path),
            output_dir=str(tmp_path / "out"),
            processing_level="all",
        )


def test_model_registry_cwd_leg_visibility(capsys, monkeypatch, tmp_path):
    """The model_registry sibling gains the same CWD-leg note (wave catch:
    the identical wrong-trust shape shipped unpatched there)."""
    import core.model_registry as mr

    real_search = mr._search_upward

    def _leg_aware_search(start):
        # file leg starts under libs/openant-core/core; cwd leg at cwd
        if "openant-core" in str(start):
            return None
        return real_search(start)

    monkeypatch.setattr(mr, "_search_upward", _leg_aware_search)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config").mkdir(exist_ok=True)
    (tmp_path / "config" / "models.json").write_text('{"models": []}')
    found = mr.find_models_config()
    assert found is not None, (
        f"CWD leg should find {tmp_path}/config/models.json — "
        f"check _search_upward leg detection"
    )
    err = capsys.readouterr().err
    assert "working directory" in err
