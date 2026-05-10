"""Tests for Windows-specific path/encoding handling in JS and Go parser pipelines.

These tests cover three fixes that prevent OpenAnt from running correctly on
Windows.

Coverage by platform:
- ``test_to_posix_path_normalises_backslashes`` — cross-platform; verifies the
  normalisation helper directly via ``node -e`` (skipped only if Node is absent).
- ``test_typescript_analyzer_strips_crlf_from_file_list`` — cross-platform;
  CRLF stripping is equally testable on POSIX.
- ``test_typescript_analyzer_accepts_backslash_paths`` — Windows-only; backslash
  absolute paths are meaningless on POSIX so the end-to-end scenario can only
  run there.
- ``test_pipeline_uses_ascii_fallback_on_cp1252_stdout`` and the Unicode
  counterpart — cross-platform; cp1252 stdout encoding can be simulated anywhere.
- ``test_no_bare_path_calls_in_typescript_analyzer`` — cross-platform static
  scanner; greps typescript_analyzer.js for path.X() calls missing toPosixPath(),
  mirroring the PR #45 antipattern-prevention pattern.
"""
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

PARSERS_DIR = Path(__file__).parent.parent / "parsers"
JS_PARSERS_DIR = PARSERS_DIR / "javascript"
GO_PARSERS_DIR = PARSERS_DIR / "go"
TS_ANALYZER = JS_PARSERS_DIR / "typescript_analyzer.js"
PATH_UTILS = JS_PARSERS_DIR / "path_utils.js"
JS_NODE_MODULES = JS_PARSERS_DIR / "node_modules"


# ---------------------------------------------------------------------------
# JS analyzer: backslash paths must be normalised before reaching ts-morph
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not shutil.which("node"),
    reason="Node.js not available",
)
def test_to_posix_path_normalises_backslashes():
    """toPosixPath() must replace every backslash with a forward slash.

    Calls the *actual* function from path_utils.js (not a reimplementation),
    so a regression in the live regex is caught on all platforms. Also covers
    the UNC path contract documented in path_utils.js: ``\\\\server\\share\\...``
    must become ``//server/share/...``.
    """
    # Require path_utils.js directly — it has no ts-morph dependency, so
    # node_modules is not required. We use \x5c (hex for backslash) in the
    # JS string literals to avoid Python/Node string-escaping ambiguity.
    path_utils = str(PATH_UTILS).replace("\\", "/")
    script = (
        "const {toPosixPath} = require(" + json.dumps(path_utils) + ");"
        + r"console.log(JSON.stringify([toPosixPath('C:\x5cUsers\x5cfoo\x5cbar.js'),toPosixPath('\x5c\x5cserver\x5cshare\x5cfoo.js')]));"
    )
    result = subprocess.run(
        ["node", "-e", script],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, f"node failed: {result.stderr}"
    results = json.loads(result.stdout.strip())
    assert results[0] == "C:/Users/foo/bar.js", (
        f"regular path: {results[0]!r}"
    )
    assert results[1] == "//server/share/foo.js", (
        f"UNC path: {results[1]!r}"
    )


@pytest.mark.skipif(
    sys.platform != "win32"
    or not shutil.which("node")
    or not JS_NODE_MODULES.exists(),
    reason="Windows-only (backslash paths are non-absolute on POSIX) and "
    "requires Node.js and JS parser npm dependencies",
)
def test_typescript_analyzer_accepts_backslash_paths(tmp_path):
    """Regression: ts-morph silently drops files when given backslash paths.

    On Windows, ``path.relative()`` and ``path.resolve()`` produce paths
    separated by ``\\``. ts-morph treats backslash as an escape character
    when matching paths it has already added, so without explicit
    normalisation the analyzer reports zero functions even for valid input.
    This test only runs on Windows because a Linux/macOS absolute path
    (``/tmp/...``) with all slashes replaced becomes ``\\tmp\\...`` which
    Node does not treat as absolute, making the test unsound on POSIX.
    """
    # Create a simple repo
    repo = tmp_path / "repo"
    src = repo / "src"
    src.mkdir(parents=True)
    (src / "module.js").write_text(
        "function greet(name) { return `hello ${name}`; }\n"
        "module.exports = { greet };\n",
        encoding="utf-8",
    )

    # Write a file list using backslash separators (the Windows-native form).
    # On POSIX this is otherwise meaningless input, but the analyzer's
    # normalisation step should still accept it.
    file_list = tmp_path / "files.txt"
    abs_path = str(src / "module.js")
    backslash_path = abs_path.replace("/", "\\")
    file_list.write_text(backslash_path + "\n", encoding="utf-8")

    out_file = tmp_path / "analyzer_output.json"
    result = subprocess.run(
        [
            "node",
            str(TS_ANALYZER),
            str(repo),
            "--files-from",
            str(file_list),
            "--output",
            str(out_file),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, (
        f"analyzer failed:\nSTDERR:\n{result.stderr}\nSTDOUT:\n{result.stdout}"
    )
    data = json.loads(out_file.read_text(encoding="utf-8"))

    # Functions must be found, regardless of slash flavour in the input.
    assert data.get("functions"), (
        f"expected at least one function; got {data.get('functions')!r}"
    )
    func_names = [f.get("name") for f in data["functions"].values()]
    assert "greet" in func_names

    # Function ids must be POSIX-form (forward slashes only). Backslash
    # leakage into ids would break downstream Python consumers.
    for func_id in data["functions"]:
        assert "\\" not in func_id, f"functionId contains backslash: {func_id!r}"


@pytest.mark.skipif(
    not shutil.which("node") or not JS_NODE_MODULES.exists(),
    reason="Node.js or JS parser npm dependencies not available",
)
def test_typescript_analyzer_strips_crlf_from_file_list(tmp_path):
    """Regression: file lists written on Windows have CRLF line endings.

    Splitting on ``\\n`` alone leaves a trailing ``\\r`` on each path,
    which ts-morph then fails to resolve. Confirm the analyzer accepts
    a CRLF-terminated file list and produces a non-empty result.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.js").write_text("function alpha() {}\n", encoding="utf-8")
    (repo / "b.js").write_text("function beta() {}\n", encoding="utf-8")

    file_list = tmp_path / "files.txt"
    # Explicit CRLF, plus a trailing blank line that should be tolerated.
    content = "\r\n".join([str(repo / "a.js"), str(repo / "b.js"), ""])
    file_list.write_bytes(content.encode("utf-8"))

    out_file = tmp_path / "out.json"
    result = subprocess.run(
        [
            "node",
            str(TS_ANALYZER),
            str(repo),
            "--files-from",
            str(file_list),
            "--output",
            str(out_file),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, (
        f"analyzer failed:\nSTDERR:\n{result.stderr}\nSTDOUT:\n{result.stdout}"
    )
    data = json.loads(out_file.read_text(encoding="utf-8"))
    func_names = [f.get("name") for f in data.get("functions", {}).values()]
    assert "alpha" in func_names
    assert "beta" in func_names


# ---------------------------------------------------------------------------
# Static regression scanner: toPosixPath() must wrap every path.X() call
# ---------------------------------------------------------------------------

# Match path.relative/resolve/join call sites (non-method-name contexts).
# dirname/basename/normalize/isAbsolute are intentionally excluded: they
# preserve (not change) the separator style of their input, so they are safe
# as long as the *input* is already normalised — which is the precondition
# enforced by toPosixPath() at the point where Windows paths enter the system.
# If you add a path method that *produces* new separators (e.g. path.format),
# add it to this regex.
_BARE_PATH_CALL_RE = re.compile(r"\bpath\.(relative|resolve|join)\s*\(")
# Match JS comment lines so JSDoc / inline comments don't trip the scanner.
_JS_COMMENT_LINE_RE = re.compile(r"^\s*(?://|\*)")


def test_no_bare_path_calls_in_typescript_analyzer():
    """Regression: every path.relative/resolve/join() in typescript_analyzer.js
    must be accompanied by toPosixPath() within 6 lines.

    Mirrors the pattern from PR #45 (test_no_bare_open, test_no_bare_pathlib_text_io,
    etc.) that prevents contributors from reintroducing encoding antipatterns.
    Here the guarded antipattern is passing a raw path.X() result to ts-morph
    or storing it as a functionId component without normalising backslashes first.

    The ±6-line window covers all current wrapping patterns:
    - same-line:        ``toPosixPath(path.resolve(...))``
    - split-line:       ``toPosixPath(\\n  path.relative(...))`` (toPosixPath 1 line before)
    - assign-then-wrap: ``const v = path.join(...);\\n...\\ntoPosixPath(v)`` (up to 5 lines after,
      including interleaved comment lines)

    Scoped to typescript_analyzer.js only — other JS parser files (context_assembler,
    repository_scanner, etc.) legitimately call path.X() without toPosixPath because
    they don't interact with ts-morph.
    """
    text = TS_ANALYZER.read_text(encoding="utf-8")
    lines = text.splitlines()
    offenders = []
    for i, line in enumerate(lines):
        if _JS_COMMENT_LINE_RE.match(line):
            continue
        if _BARE_PATH_CALL_RE.search(line):
            lo = max(0, i - 6)
            hi = min(len(lines), i + 7)
            window = "\n".join(lines[lo:hi])
            if "toPosixPath(" not in window:
                offenders.append(f":{i + 1}: {line.strip()}")
    assert not offenders, (
        f"Found path.relative/resolve/join() without toPosixPath() in "
        f"{TS_ANALYZER.name}. Wrap the result with toPosixPath() — see "
        f"the CONTRACT comment on that function.\n  " + "\n  ".join(offenders)
    )


# ---------------------------------------------------------------------------
# test_pipeline.py: status output must stay safe on a cp1252 stdout
# ---------------------------------------------------------------------------


def _load_pipeline_module(name, source_path):
    """Import a parser test_pipeline.py module under a custom name.

    The two pipelines (JS, Go) live in sibling directories and both
    expose a module named ``test_pipeline``. We import them under
    distinct names so they coexist in this test process.

    The module is registered in ``sys.modules`` so that callers can
    reliably remove it afterwards (via ``sys.modules.pop(name, None)``)
    to prevent stale module-level state — such as ``_UNICODE_OK`` and
    ``SYM_*`` globals — from leaking into subsequent tests.

    ``sys.path`` is snapshot/restored around ``exec_module`` so that the
    module-level ``sys.path.insert`` calls in the pipeline files do not
    accumulate extra entries on repeated calls (e.g. across parametrized
    test runs).
    """
    spec = importlib.util.spec_from_file_location(name, source_path)
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so that relative imports inside the module
    # resolve correctly, and so callers can pop the module after use.
    sys.modules[name] = mod
    # Snapshot sys.path so that module-level sys.path.insert calls inside
    # the pipeline files do not leave behind permanent extra entries.
    path_snapshot = sys.path[:]
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        # Roll back the registration so the failed module does not pollute
        # sys.modules (CPython convention for importlib loaders).
        sys.modules.pop(name, None)
        raise
    finally:
        # Restore sys.path to prevent the module's own insertions from
        # accumulating across repeated calls.
        sys.path[:] = path_snapshot
    return mod


@pytest.fixture(params=["javascript", "go"])
def pipeline_module(request, monkeypatch):
    """Load the JS or Go test_pipeline module fresh under a synthetic stdout.

    We point ``sys.stdout`` at a buffer with a cp1252 encoding before the
    module is imported, so the module-level ``_stdout_supports_unicode()``
    check sees the constrained encoding. We then re-import each time to
    capture the fresh module-level state.
    """
    # Replace stdout with a cp1252-only buffer so the module-level helper
    # picks the ASCII fallback.
    fake_stdout = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", newline="")
    monkeypatch.setattr(sys, "stdout", fake_stdout)

    parsers_root = PARSERS_DIR
    parsers_parent = str(parsers_root.parent)
    already_on_path = parsers_parent in sys.path
    if not already_on_path:
        sys.path.insert(0, parsers_parent)  # so utilities.* imports work
    try:
        if request.param == "javascript":
            path = parsers_root / "javascript" / "test_pipeline.py"
            mod_name = "openant_test_js_pipeline_cp1252"
        else:
            path = parsers_root / "go" / "test_pipeline.py"
            mod_name = "openant_test_go_pipeline_cp1252"

        # Drop any cached version so module-level symbol detection re-runs.
        sys.modules.pop(mod_name, None)
        mod = _load_pipeline_module(mod_name, path)
        yield mod
    finally:
        # Remove the freshly loaded module so its stale cp1252-patched
        # module-level state (_UNICODE_OK, SYM_*) doesn't leak into later
        # tests that may load the same pipeline module.
        sys.modules.pop(mod_name, None)
        if not already_on_path:
            try:
                sys.path.remove(parsers_parent)
            except ValueError:
                pass


def test_pipeline_uses_ascii_fallback_on_cp1252_stdout(pipeline_module):
    """Status symbols must be ASCII-only on a cp1252-encoded stdout.

    The original pipelines printed ``✓``, ``✗`` and ``→`` directly, which
    crashed Python's print on cp1252 consoles (the Windows default).
    """
    assert pipeline_module._UNICODE_OK is False, (
        "_stdout_supports_unicode() should report False for cp1252 stdout"
    )
    assert pipeline_module.SYM_OK == "OK"
    assert pipeline_module.SYM_FAIL == "FAIL"
    assert pipeline_module.SYM_ARROW == "->"

    # And the ASCII fallbacks must round-trip through cp1252 without error.
    for s in (pipeline_module.SYM_OK, pipeline_module.SYM_FAIL, pipeline_module.SYM_ARROW):
        s.encode("cp1252")  # must not raise


@pytest.mark.parametrize(
    "mod_name,rel_path",
    [
        ("openant_test_js_pipeline_utf8", "javascript/test_pipeline.py"),
        ("openant_test_go_pipeline_utf8", "go/test_pipeline.py"),
    ],
)
def test_pipeline_uses_unicode_when_stdout_supports_it(monkeypatch, mod_name, rel_path):
    """When stdout can encode the symbols, prefer the prettier Unicode form.

    Covers both the JS and Go pipeline modules to ensure neither regresses
    to ASCII when the terminal supports Unicode.
    """
    # Reload under a UTF-8 stdout to confirm the other branch.
    fake_stdout = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", newline="")
    monkeypatch.setattr(sys, "stdout", fake_stdout)

    parsers_root = PARSERS_DIR
    parsers_parent = str(parsers_root.parent)
    already_on_path = parsers_parent in sys.path
    if not already_on_path:
        sys.path.insert(0, parsers_parent)
    try:
        sys.modules.pop(mod_name, None)
        mod = _load_pipeline_module(mod_name, parsers_root / rel_path)
        assert mod._UNICODE_OK is True
        # Use Unicode escape sequences rather than literal glyphs so that
        # assertion failure messages are safe on cp1252 consoles — printing
        # the literal characters (U+2713, U+2717, U+2192) would itself raise
        # UnicodeEncodeError on the very platform these tests guard against.
        assert mod.SYM_OK == "\u2713"  # CHECK MARK (U+2713)
        assert mod.SYM_FAIL == "\u2717"  # BALLOT X (U+2717)
        assert mod.SYM_ARROW == "\u2192"  # RIGHTWARDS ARROW (U+2192)
    finally:
        sys.modules.pop(mod_name, None)
        if not already_on_path:
            try:
                sys.path.remove(parsers_parent)
            except ValueError:
                pass
