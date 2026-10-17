"""#795: the JS parser bootstrap installs with `npm ci`, never rewriting the
committed `package-lock.json`.

The #795 class: the bootstrap's `npm install` is permitted to rewrite the
committed lock when its resolution drifts from the lock's recorded state —
dirtying the user's tree and silently drifting the lock. `npm ci` installs
FROM the committed lock and never writes it; the bootstrap must carry that
contract.
"""
import json
import pathlib
import shutil
import urllib.request

import pytest

from core import parser_adapter

_MS_210_RESOLVED = "https://registry.npmjs.org/ms/-/ms-2.1.0.tgz"
_MS_210_INTEGRITY = (
    "sha512-gVZHb22Z7YDyiiaoGld9LD4tUuDDxdkDJUEfTIej9LFePFqiE9JxI0q"
    "TFfu6tD7Wu03lg7skmVwTmA6XkeMlPQ=="
)
_MS_FLOATING_SPEC = "^2.1.0"
# The fixture lock is the LEGACY v1 shape (`dependencies`-keyed): the oldest
# deterministic member of the #795 class — a resolution state `npm install`
# must rewrite (the v1->v3 format conversion, a silent success on the base
# verb) while `npm ci` reads it without ever writing (the pinned contract).

_REGISTRY_PROBE_URL = "https://registry.npmjs.org/ms"


def _registry_reachable(timeout_s: float = 3.0) -> bool:
    try:
        urllib.request.urlopen(_REGISTRY_PROBE_URL, timeout=timeout_s)
    except OSError:
        return False
    return True


def _write_lock_fixture(fx_dir):
    """A committed `package-lock.json` whose recorded state `npm install`
    rewrites — the legacy v1 format (`dependencies`-keyed, lockfileVersion 1)
    pinning ms@2.1.0 with the real registry integrity: `npm install` converts
    it to the v3 shape (a silent rewrite of a tracked file, the #795 class),
    `npm ci` installs exactly the pinned 2.1.0 and never writes it."""
    fx_dir.mkdir(parents=True, exist_ok=True)
    (fx_dir / "package.json").write_text(json.dumps(
        {"name": "fx", "version": "1.0.0",
         "dependencies": {"ms": _MS_FLOATING_SPEC}}, indent=2) + "\n")
    (fx_dir / "package-lock.json").write_text(json.dumps(
        {"name": "fx", "version": "1.0.0", "lockfileVersion": 1,
         "requires": True,
         "dependencies": {
             "ms": {"version": "2.1.0", "resolved": _MS_210_RESOLVED,
                    "integrity": _MS_210_INTEGRITY},
         }}, indent=2) + "\n")
    return (fx_dir / "package.json").read_bytes(), (fx_dir / "package-lock.json").read_bytes()


def test_the_bootstrap_verb_is_ci_never_install(tmp_path, monkeypatch):
    """The bootstrap invokes `npm ci` — the verb whose contract is "install
    from the committed lock, never write it". `npm install` is the #795 bug:
    a resolution drift past the lock rewrites a tracked file (#795)."""
    (tmp_path / "package.json").write_text('{"name": "fx"}')
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

    monkeypatch.setattr(parser_adapter, "_JS_PARSER_DIR", tmp_path)
    monkeypatch.setattr(parser_adapter.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(parser_adapter.shutil, "which", lambda name: "/usr/bin/npm")

    parser_adapter._ensure_js_parser_dependencies()

    assert len(calls) == 1
    cmd, kwargs = calls[0]
    assert cmd == ["/usr/bin/npm", "ci"], (
        "the bootstrap installs with npm ci — npm install rewrites the "
        "committed lock on resolution drift (#795)")
    assert kwargs["cwd"] == str(tmp_path)
    import inspect
    src = inspect.getsource(parser_adapter._ensure_js_parser_dependencies)
    assert '"ci"]' in src and '"install"]' not in src, (
        "the bootstrap's own argv is ci and no install path remains "
        "in the function (#795)")


def test_the_bootstrap_prose_names_the_ci_verb():
    """#795's prose half (the fable r1 finding-2 class): every instruction a
    dev or operator could follow to bootstrap the parser by hand must name the
    ci verb -- an ``npm install`` left anywhere in the bootstrap's own prose
    (the docstrings, the comments, the pipeline doc) reproduces #795 by hand.
    Binds the five docstring/comment prose sites (the module-level #325
    bound comment included) + the pipeline doc."""
    import inspect
    pins_src = inspect.getsource(parser_adapter._lock_dependency_pins)
    gate_src = inspect.getsource(parser_adapter._js_deps_installed)
    ensure_src = inspect.getsource(parser_adapter._ensure_js_parser_dependencies)
    assert "re-run ``npm ci`` on every single parse" in pins_src, (
        "the stale-loop prose names the verb the loop would re-run (#795)")
    assert "npm ci install is in place" in gate_src, (
        "the gate's docstring names the ci install it checks for (#795)")
    assert "``npm ci`` in the same directory" in ensure_src, (
        "the concurrency prose names the serialized command (#795)")
    assert '"the npm ci bootstrap"' in ensure_src, (
        "the lock's operator-facing label (what=) names the ci bootstrap, "
        "never the banned hyphen-form (#795)")
    assert '"the npm-install bootstrap"' not in ensure_src, (
        "the banned hyphen-form label stays out of the bootstrap (#795)")
    assert "the bounded npm ci" in ensure_src, (
        "the wait-budget comment names the bounded ci command — the fifth "
        "prose site (#795)")
    module_src = pathlib.Path(parser_adapter.__file__).read_text(encoding="utf-8")
    assert "#325: the npm ci bootstrap bound" in module_src, (
        "the #325 bound's own comment names the ci bootstrap (the module-level "
        "comment hunk_tool drops as comment-only — prose-bound here instead) "
        "(#795)")
    assert "#325: the npm-install bootstrap bound" not in module_src, (
        "the banned hyphen-form stays out of the #325 bound comment (#795)")
    doc = (pathlib.Path(parser_adapter._JS_PARSER_DIR)
           / "PARSER_PIPELINE.md").read_text(encoding="utf-8")
    assert "npm ci  # Installs dependencies" in doc, (
        "the pipeline doc's bootstrap instruction installs from the "
        "committed lock, never install-drifts it (#795)")


def test_the_committed_lock_is_never_rewritten_by_the_bootstrap(
        tmp_path, monkeypatch):
    """The end-to-end contract (#795's expected behavior): the bootstrap
    installs FROM the committed lock — the lock's bytes never change, and the
    installed tree is exactly the lock's pins. At the #795 bug state,
    `npm install` silently rewrites the tracked lock (the v1 fixture's
    format conversion) — a run the user never asked to make."""
    if shutil.which("npm") is None:
        pytest.skip("npm is not on PATH — the lock-rewrite witness needs it")
    if not _registry_reachable():
        pytest.skip("the npm registry is unreachable — the lock-rewrite "
                    "witness needs one tarball fetch")
    pkg_before, lock_before = _write_lock_fixture(tmp_path)
    monkeypatch.setattr(parser_adapter, "_JS_PARSER_DIR", tmp_path)

    parser_adapter._ensure_js_parser_dependencies()

    lock_after = (tmp_path / "package-lock.json").read_bytes()
    assert lock_after == lock_before, (
        "the committed package-lock.json was rewritten by the bootstrap — "
        "a tracked file the user never asked to change (#795)")
    assert (tmp_path / "package.json").read_bytes() == pkg_before
    installed = json.loads(
        (tmp_path / "node_modules" / "ms" / "package.json").read_bytes())
    assert installed["version"] == "2.1.0", (
        "npm ci must install exactly the lock's pin (2.1.0), never a "
        "re-resolution of the range — the drift the rewrite carried (#795)")
