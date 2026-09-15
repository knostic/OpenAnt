"""Tests for the JS parser's lazy npm-install bootstrap.

Covers `_ensure_js_parser_dependencies` in core.parser_adapter: behavior when
node_modules is present, missing, partially installed, npm is unavailable, or
`npm install` fails. These tests monkeypatch subprocess and shutil.which so
they don't need Node.
"""
from pathlib import Path

import pytest

from core import parser_adapter


@pytest.fixture
def fake_parser_dir(tmp_path, monkeypatch):
    """Point _JS_PARSER_DIR at a tmp dir (with package.json) so tests don't
    touch the real one."""
    monkeypatch.setattr(parser_adapter, "_JS_PARSER_DIR", tmp_path)
    # All happy-path tests assume package.json exists. Tests that need to
    # exercise the missing-package.json branch can delete it.
    (tmp_path / "package.json").write_text('{"name": "fake"}')
    return tmp_path


def _mark_installed(parser_dir: Path) -> None:
    """Create the success sentinel npm writes after a complete install."""
    nm = parser_dir / "node_modules"
    nm.mkdir(exist_ok=True)
    (nm / ".package-lock.json").write_text("{}")


def test_skips_install_when_deps_already_installed(fake_parser_dir, monkeypatch):
    _mark_installed(fake_parser_dir)

    calls = []
    monkeypatch.setattr(parser_adapter.subprocess, "run", lambda *a, **kw: calls.append((a, kw)))
    monkeypatch.setattr(parser_adapter.shutil, "which", lambda name: "/usr/bin/npm")

    parser_adapter._ensure_js_parser_dependencies()

    assert calls == []


def test_retries_install_when_node_modules_partially_installed(fake_parser_dir, monkeypatch):
    """A killed prior install leaves node_modules/ but no .package-lock.json
    sentinel. The bootstrap must retry rather than skip."""
    (fake_parser_dir / "node_modules").mkdir()  # no .package-lock.json -> partial

    calls = []

    class _Ok:
        returncode = 0

    def _fake_popen(cmd, **kwargs):
        calls.append((cmd, kwargs))

        class _P:
            pid = 123
            def wait(self, timeout=None):
                _mark_installed(fake_parser_dir)  # npm wrote the sentinel
                return 0
            def kill(self):
                pass
        return _P()

    monkeypatch.setattr(parser_adapter.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(parser_adapter.shutil, "which", lambda name: "/usr/bin/npm")

    parser_adapter._ensure_js_parser_dependencies()

    assert len(calls) == 1, "Partial node_modules should trigger a re-install"


def test_runs_npm_install_when_node_modules_missing(fake_parser_dir, monkeypatch):
    calls = []

    def _fake_popen(cmd, **kwargs):
        calls.append((cmd, kwargs))

        class _P:
            pid = 123
            def wait(self, timeout=None):
                _mark_installed(fake_parser_dir)  # npm wrote the sentinel
                return 0
            def kill(self):
                pass
        return _P()

    monkeypatch.setattr(parser_adapter.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(parser_adapter.shutil, "which", lambda name: "/usr/bin/npm")

    parser_adapter._ensure_js_parser_dependencies()

    assert len(calls) == 1
    cmd, kwargs = calls[0]
    assert cmd == ["/usr/bin/npm", "install"]
    assert kwargs["cwd"] == str(fake_parser_dir)


def test_raises_when_npm_not_on_path(fake_parser_dir, monkeypatch):
    monkeypatch.setattr(parser_adapter.shutil, "which", lambda name: None)

    with pytest.raises(RuntimeError, match="npm"):
        parser_adapter._ensure_js_parser_dependencies()


def test_raises_when_package_json_missing(fake_parser_dir, monkeypatch):
    """If the JS parser dir has no package.json, surface a clear error rather
    than silently letting npm create an empty install."""
    (fake_parser_dir / "package.json").unlink()

    monkeypatch.setattr(parser_adapter.shutil, "which", lambda name: "/usr/bin/npm")

    with pytest.raises(RuntimeError, match="package.json not found"):
        parser_adapter._ensure_js_parser_dependencies()


def test_raises_when_npm_install_fails(fake_parser_dir, monkeypatch):
    def _fail_popen(cmd, **kwargs):
        class _P:
            pid = 123
            def wait(self, timeout=None):
                return 1
            def kill(self):
                pass
        return _P()

    monkeypatch.setattr(parser_adapter.subprocess, "Popen", _fail_popen)
    monkeypatch.setattr(parser_adapter.shutil, "which", lambda name: "/usr/bin/npm")

    with pytest.raises(RuntimeError, match="npm install.*exit code 1"):
        parser_adapter._ensure_js_parser_dependencies()


def test_install_failure_message_includes_repro_command(fake_parser_dir, monkeypatch):
    """The error message must tell the user how to reproduce the install
    locally so they can read npm's diagnostics."""
    def _fail_popen(cmd, **kwargs):
        class _P:
            pid = 123
            def wait(self, timeout=None):
                return 1
            def kill(self):
                pass
        return _P()

    monkeypatch.setattr(parser_adapter.subprocess, "Popen", _fail_popen)
    monkeypatch.setattr(parser_adapter.shutil, "which", lambda name: "/usr/bin/npm")

    with pytest.raises(RuntimeError) as exc_info:
        parser_adapter._ensure_js_parser_dependencies()

    msg = str(exc_info.value)
    assert "npm install" in msg
    assert str(fake_parser_dir) in msg


def test_parse_javascript_surfaces_bootstrap_error(fake_parser_dir, monkeypatch):
    """When bootstrap fails, _parse_javascript must not run the Node subprocess."""
    monkeypatch.setattr(parser_adapter.shutil, "which", lambda name: None)

    ran_node = []
    monkeypatch.setattr(
        parser_adapter.subprocess,
        "run",
        lambda *a, **kw: ran_node.append((a, kw)),
    )

    with pytest.raises(RuntimeError, match="npm"):
        parser_adapter._parse_javascript(
            repo_path="/tmp/fake-repo",
            output_dir="/tmp/fake-out",
            processing_level="all",
        )

    assert ran_node == [], "Node subprocess should not run when bootstrap fails"


def test_concurrent_bootstrap_serialized_by_lock(fake_parser_dir, monkeypatch):
    """The lockfile must serialize installs: the second caller, blocked behind
    the first, must observe the sentinel on entry and skip its own install."""
    install_count = 0

    def _fake_popen(cmd, **kwargs):
        nonlocal install_count
        install_count += 1

        class _P:
            pid = 123
            def wait(self, timeout=None):
                _mark_installed(fake_parser_dir)  # npm wrote the sentinel
                return 0
            def kill(self):
                pass
        return _P()

    monkeypatch.setattr(parser_adapter.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(parser_adapter.shutil, "which", lambda name: "/usr/bin/npm")

    # Two sequential calls in the same process: first installs and writes the
    # sentinel, second sees the sentinel and is a no-op. (True multi-process
    # concurrency is exercised by the OS lock; we just verify the
    # re-check-under-lock + sentinel logic.)
    parser_adapter._ensure_js_parser_dependencies()
    parser_adapter._ensure_js_parser_dependencies()

    assert install_count == 1
