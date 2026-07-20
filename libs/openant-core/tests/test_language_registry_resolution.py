"""Config resolution must survive layouts other than the monorepo checkout.

`_LANGUAGES_CONFIG` was a bare four-parents-up path. That resolves correctly
in-repo and nowhere else — under an installed layout it points outside the
distribution. Because `supported_languages()` now runs during argparse
construction, a missing config took down the ENTIRE CLI: `openant --help`
raised FileNotFoundError before parsing a flag.

The Go side already got this right (search upward from exe and cwd, and
degrade rather than die at flag-registration time). These tests hold the
Python side to the same contract.
"""

from pathlib import Path

import pytest

import core.language_registry as lr


@pytest.fixture(autouse=True)
def _clear_caches():
    lr._load_config.cache_clear()
    lr.load_registry.cache_clear()
    yield
    lr._load_config.cache_clear()
    lr.load_registry.cache_clear()


class TestResolution:
    def test_finds_the_config_in_the_repo_layout(self):
        assert lr.find_languages_config() is not None
        assert lr.find_languages_config().is_file()

    def test_env_override_wins(self, tmp_path, monkeypatch):
        cfg = tmp_path / "languages.json"
        cfg.write_text('{"skip_dirs": [], "extensions": {}, "languages": {}}')
        monkeypatch.setenv("OPENANT_LANGUAGES_CONFIG", str(cfg))
        assert lr.find_languages_config() == cfg

    def test_env_override_pointing_nowhere_is_ignored_not_fatal(self, monkeypatch):
        """A stale env var must not be more destructive than no env var."""
        monkeypatch.setenv("OPENANT_LANGUAGES_CONFIG", "/nonexistent/languages.json")
        assert lr.find_languages_config() is not None, (
            "a bad override should fall through to the search, not kill the CLI"
        )


class TestDegradeRatherThanDie:
    """The contract the Go side documents: help text must never be fatal."""

    def test_supported_languages_returns_empty_when_config_is_missing(self, monkeypatch):
        monkeypatch.setattr(lr, "find_languages_config", lambda: None)
        assert lr.supported_languages() == []

    def test_extension_map_refuses_rather_than_degrading(self, monkeypatch):
        """Contract change: describing degrades, working does not.

        This previously asserted ``extension_map() == {}``. Returning an empty map
        is fine for anything that merely lists languages, but detection built on it
        finds zero files and reports "repository has no supported source files" —
        which sends the operator to inspect their repository when the fault is a
        broken installation. Raising here names the real cause; ``--help`` is
        unaffected because it goes through ``supported_languages()``, which still
        degrades (asserted directly above and by test_cli_still_builds_without_a_config).
        """
        monkeypatch.setattr(lr, "find_languages_config", lambda: None)
        with pytest.raises(RuntimeError, match="installation problem"):
            lr.extension_map()

    def test_skip_dirs_degrades(self, monkeypatch):
        monkeypatch.setattr(lr, "find_languages_config", lambda: None)
        assert lr.skip_dirs() == frozenset()

    def test_cli_still_builds_without_a_config(self, monkeypatch):
        """The actual regression: `openant --help` must not crash."""
        monkeypatch.setattr(lr, "find_languages_config", lambda: None)
        from openant.cli import build_parser

        parser = build_parser()
        assert parser is not None

    def test_parsing_a_language_without_config_fails_loudly(self, monkeypatch, tmp_path):
        """Degrading help text is fine; silently parsing nothing is not.

        Accepts RuntimeError as well as ValueError. Both are loud, which is what
        this test is really about — but RuntimeError now arrives from
        ``require_registry`` with a message naming the installation, instead of
        ValueError's "no supported source files", which blamed the repository. The
        distinction matters: a repository with a real .py file in it, as here, is
        exactly the case where the old message was actively misleading.
        """
        monkeypatch.setattr(lr, "find_languages_config", lambda: None)
        from core.parser_adapter import detect_languages

        (tmp_path / "a.py").write_text("x = 1")
        with pytest.raises((ValueError, RuntimeError)) as exc:
            detect_languages(str(tmp_path))
        assert "installation problem" in str(exc.value), (
            "the failure must name the install, not the scanned repository"
        )
