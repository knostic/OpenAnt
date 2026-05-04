"""Tests for Windows-specific path/encoding handling in JS and Go parser pipelines.

These tests cover three fixes that prevent OpenAnt from running correctly on
Windows. They are meant to run on every platform — the bugs they protect
against are platform-independent in their failure modes (you can simulate a
backslash file list, a CRLF file list, and a cp1252-only stdout from any
host) and a regression on POSIX would still be a regression.
"""
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

PARSERS_DIR = Path(__file__).parent.parent / "parsers"
JS_PARSERS_DIR = PARSERS_DIR / "javascript"
GO_PARSERS_DIR = PARSERS_DIR / "go"
TS_ANALYZER = JS_PARSERS_DIR / "typescript_analyzer.js"
JS_NODE_MODULES = JS_PARSERS_DIR / "node_modules"


# ---------------------------------------------------------------------------
# JS analyzer: backslash paths must be normalised before reaching ts-morph
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="backslash path simulation only meaningful on Windows; "
    "replacing all forward slashes produces a non-absolute path on POSIX",
)
@pytest.mark.skipif(
    not shutil.which("node") or not JS_NODE_MODULES.exists(),
    reason="Node.js or JS parser npm dependencies not available",
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
# test_pipeline.py: status output must stay safe on a cp1252 stdout
# ---------------------------------------------------------------------------


def _load_pipeline_module(name, source_path):
    """Import a parser test_pipeline.py module under a custom name.

    The two pipelines (JS, Go) live in sibling directories and both
    expose a module named ``test_pipeline``. We import them under
    distinct names so they coexist in this test process.
    """
    spec = importlib.util.spec_from_file_location(name, source_path)
    mod = importlib.util.module_from_spec(spec)
    # The pipeline modules import siblings via sys.path manipulation;
    # let them do that as part of their normal import.
    spec.loader.exec_module(mod)
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
    sys.path.insert(0, str(parsers_root.parent))  # so utilities.* imports work
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
        try:
            sys.path.remove(str(parsers_root.parent))
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
    sys.path.insert(0, str(parsers_root.parent))
    try:
        sys.modules.pop(mod_name, None)
        mod = _load_pipeline_module(mod_name, parsers_root / rel_path)
        assert mod._UNICODE_OK is True
        assert mod.SYM_OK == "✓"
        assert mod.SYM_FAIL == "✗"
        assert mod.SYM_ARROW == "→"
    finally:
        sys.modules.pop(mod_name, None)
        try:
            sys.path.remove(str(parsers_root.parent))
        except ValueError:
            pass
