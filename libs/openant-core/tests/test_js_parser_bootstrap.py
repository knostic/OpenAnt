"""Tests for the JS parser's lazy npm-install bootstrap.

Covers `_ensure_js_parser_dependencies` in core.parser_adapter: behavior when
node_modules is present, missing, partially installed, npm is unavailable, or
`npm install` fails. These tests monkeypatch subprocess and shutil.which so
they don't need Node.
"""
import json
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


# ---------------------------------------------------------------------------
# STALENESS of an already-COMPLETED install
#
# The completion sentinel answers "did an install finish?" but not "did it
# install what the lockfile now pins". Merging a lockfile bump (e.g. a
# transitive security upgrade) therefore fixed no existing checkout: the
# marker still existed, so the bootstrap skipped and the old tree was reused
# indefinitely.
#
# The fixtures below are RELATIONAL: each test supplies BOTH the committed
# lockfile and the marker, and asserts on the relationship between them. No
# test pins a version this repository happens to ship today, so a future
# dependency bump cannot silently invert any assertion here.
# ---------------------------------------------------------------------------

def _entry(version, *, integrity=None, **flags):
    """One ``packages`` entry in the shape npm writes (version + integrity).

    ``flags`` carries the ``optional``/``dev`` markers npm stamps on entries
    that are not part of the default production install.
    """
    entry = {"version": version, "integrity": integrity or f"sha512-bytes-of-{version}"}
    entry.update(flags)
    return entry


def _write_committed_lock(parser_dir: Path, packages: dict) -> None:
    """Write the tracked ``package-lock.json``.

    It carries a root ``""`` entry describing the project itself, which the
    marker never has -- verified against a real ``npm ci`` tree.
    """
    doc = {
        "name": "javascript_parser",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {"": {"name": "javascript_parser", "version": "1.0.0"}, **packages},
    }
    (parser_dir / "package-lock.json").write_text(json.dumps(doc, indent=2))


def _write_marker(parser_dir: Path, packages: dict) -> None:
    """Write ``node_modules/.package-lock.json``, npm's completion sentinel.

    Mirrors a real installed tree: no root ``""`` entry, and only the
    platform-optional packages that were actually installed.
    """
    nm = parser_dir / "node_modules"
    nm.mkdir(exist_ok=True)
    doc = {
        "name": "javascript_parser",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": dict(packages),
    }
    (nm / ".package-lock.json").write_text(json.dumps(doc, indent=2))


def _record_installs(monkeypatch, parser_dir: Path):
    """Record npm invocations; a "successful" install refreshes the marker."""
    calls = []

    def _fake_popen(cmd, **kwargs):
        calls.append((cmd, kwargs))

        class _P:
            pid = 123

            def wait(self, timeout=None):
                return 0

            def kill(self):
                pass

        return _P()

    monkeypatch.setattr(parser_adapter.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(parser_adapter.shutil, "which", lambda name: "/usr/bin/npm")
    return calls


def test_rebootstraps_when_marker_versions_are_stale(fake_parser_dir, monkeypatch):
    """A completed install that predates a lockfile bump must be refreshed.

    The committed lock pins a newer brace-expansion than the installed tree
    carries. Before the staleness check this skipped on the marker's mere
    existence, so merging the bump fixed nothing on any existing checkout.
    """
    _write_committed_lock(fake_parser_dir, {
        "node_modules/brace-expansion": _entry("5.0.12"),
    })
    _write_marker(fake_parser_dir, {
        "node_modules/brace-expansion": _entry("5.0.9"),
    })

    calls = _record_installs(monkeypatch, fake_parser_dir)

    parser_adapter._ensure_js_parser_dependencies()

    assert len(calls) == 1, "a lockfile bump must re-run npm install"
    assert calls[0][0] == ["/usr/bin/npm", "install"]


def test_marker_matching_the_lock_skips_install(fake_parser_dir, monkeypatch):
    """The no-false-positive case: an up-to-date tree must NOT reinstall.

    This is the assertion that makes the staleness check safe to ship: if it
    were wrong in this direction every parse would shell out to npm.
    """
    packages = {
        "node_modules/minimatch": _entry("10.2.4"),
        "node_modules/brace-expansion": _entry("5.0.9"),
    }
    _write_committed_lock(fake_parser_dir, packages)
    _write_marker(fake_parser_dir, packages)

    calls = _record_installs(monkeypatch, fake_parser_dir)

    parser_adapter._ensure_js_parser_dependencies()

    assert calls == [], "an up-to-date install must not be repeated"


def test_optional_platform_entries_absent_from_marker_do_not_trigger_reinstall(
    fake_parser_dir, monkeypatch
):
    """Platform-optional natives are expected to be missing from the marker.

    The committed lock enumerates every platform's prebuilt binary; a given
    machine installs exactly the one that matches. Comparing those entries
    would make the tree permanently STALE and run npm install on every single
    parse, so they are excluded from the comparison on both sides.
    """
    native = "node_modules/@scoped/native"
    _write_committed_lock(fake_parser_dir, {
        "node_modules/minimatch": _entry("10.2.4"),
        f"{native}-linux-x64": _entry("7.0.2", optional=True),
        f"{native}-darwin-arm64": _entry("7.0.2", optional=True),
        f"{native}-win32-x64": _entry("7.0.2", optional=True),
    })
    _write_marker(fake_parser_dir, {
        "node_modules/minimatch": _entry("10.2.4"),
        # only the native matching this machine was installed
        f"{native}-darwin-arm64": _entry("7.0.2", optional=True),
    })

    calls = _record_installs(monkeypatch, fake_parser_dir)

    parser_adapter._ensure_js_parser_dependencies()

    assert calls == [], "platform-optional entries must not force a reinstall"


def test_dev_entries_absent_from_marker_do_not_trigger_reinstall(
    fake_parser_dir, monkeypatch
):
    """A production install omits devDependencies; that is not staleness."""
    _write_committed_lock(fake_parser_dir, {
        "node_modules/minimatch": _entry("10.2.4"),
        "node_modules/some-test-tool": _entry("1.2.3", dev=True),
    })
    _write_marker(fake_parser_dir, {
        "node_modules/minimatch": _entry("10.2.4"),
    })

    calls = _record_installs(monkeypatch, fake_parser_dir)

    parser_adapter._ensure_js_parser_dependencies()

    assert calls == [], "dev-only entries must not force a reinstall"


def test_rebootstraps_when_marker_integrity_differs_at_same_version(
    fake_parser_dir, monkeypatch
):
    """Same version string, different bytes -- still stale.

    A republished or tampered tarball keeps the version and changes the
    integrity hash, which is exactly the case a version-only comparison
    would wave through.
    """
    _write_committed_lock(fake_parser_dir, {
        "node_modules/minimatch": _entry("10.2.4", integrity="sha512-NEW-BYTES"),
    })
    _write_marker(fake_parser_dir, {
        "node_modules/minimatch": _entry("10.2.4", integrity="sha512-OLD-BYTES"),
    })

    calls = _record_installs(monkeypatch, fake_parser_dir)

    parser_adapter._ensure_js_parser_dependencies()

    assert len(calls) == 1, "an integrity change at the same version is stale"


def test_marker_with_an_extra_package_reads_stale(fake_parser_dir, monkeypatch):
    """The comparison is SYMMETRIC: an extra INSTALLED package is stale too.

    A one-way "is everything the lock requires present?" check would call
    this tree fresh. It is not: the extra package is a dependency the lock no
    longer pins (a removed or downgraded transitive), and it stays loadable
    on disk -- which is precisely the reachability a dependency removal is
    meant to eliminate.
    """
    _write_committed_lock(fake_parser_dir, {
        "node_modules/minimatch": _entry("10.2.4"),
    })
    _write_marker(fake_parser_dir, {
        "node_modules/minimatch": _entry("10.2.4"),
        "node_modules/brace-expansion": _entry("5.0.9"),
    })

    calls = _record_installs(monkeypatch, fake_parser_dir)

    parser_adapter._ensure_js_parser_dependencies()

    assert len(calls) == 1, "an extra installed package must read as stale"


def test_torn_marker_rebootstraps_without_raising(fake_parser_dir, monkeypatch):
    """A half-written marker must re-bootstrap, never raise.

    npm rewrites the marker in place, so a concurrent parse can read it
    mid-write. Both call sites (the pre-lock fast path and the re-check under
    the lock) run this code, so an exception here would abort the parse
    instead of waiting for the install.
    """
    _write_committed_lock(fake_parser_dir, {
        "node_modules/minimatch": _entry("10.2.4"),
    })
    nm = fake_parser_dir / "node_modules"
    nm.mkdir(exist_ok=True)
    (nm / ".package-lock.json").write_text('{"packages": {"node_modules/mini')

    calls = _record_installs(monkeypatch, fake_parser_dir)

    parser_adapter._ensure_js_parser_dependencies()

    assert len(calls) == 1, "a torn marker must re-bootstrap under the lock"


def test_torn_committed_lock_rebootstraps_without_raising(fake_parser_dir, monkeypatch):
    """An unparseable committed lock re-bootstraps rather than crashing."""
    (fake_parser_dir / "package-lock.json").write_text("{ not json at all")
    _write_marker(fake_parser_dir, {
        "node_modules/minimatch": _entry("10.2.4"),
    })

    calls = _record_installs(monkeypatch, fake_parser_dir)

    parser_adapter._ensure_js_parser_dependencies()

    assert len(calls) == 1, "an unparseable lock must re-bootstrap, not raise"


def test_missing_committed_lock_preserves_skip(fake_parser_dir, monkeypatch):
    """With no lockfile to compare against, the sentinel alone still decides.

    There is nothing to be stale relative to, and an install cannot be made
    reproducible anyway, so the pre-existing behaviour is preserved.
    """
    _mark_installed(fake_parser_dir)
    assert not (fake_parser_dir / "package-lock.json").exists()

    calls = _record_installs(monkeypatch, fake_parser_dir)

    parser_adapter._ensure_js_parser_dependencies()

    assert calls == [], "no lockfile -> the completion sentinel alone decides"
