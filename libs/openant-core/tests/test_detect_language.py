"""Unit tests for ``detect_language`` in ``core.parser_adapter``.

These tests build small synthetic project trees with ``tmp_path`` and assert
that the dominant-extension heuristic reports the correct language. They run
without the Go CLI binary, so they always execute in CI even when the Go
toolchain isn't installed.

Covers item 13 of issue #16 (auto-detect language in ``init``).
"""
from pathlib import Path

import pytest

from core.parser_adapter import detect_language


def _write(p: Path, content: str = "") -> None:
    """Create a file with ``content`` at ``p``, including parent dirs."""
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


class TestDetectLanguagePython:
    def test_single_python_file(self, tmp_path: Path) -> None:
        _write(tmp_path / "main.py", "print('hi')\n")
        assert detect_language(str(tmp_path)) == "python"

    def test_dominant_python_with_unrelated_files(self, tmp_path: Path) -> None:
        for i in range(5):
            _write(tmp_path / f"mod_{i}.py")
        _write(tmp_path / "README.md", "# project")
        _write(tmp_path / "data.json", "{}")
        assert detect_language(str(tmp_path)) == "python"


class TestDetectLanguageJavaScript:
    def test_plain_javascript(self, tmp_path: Path) -> None:
        _write(tmp_path / "index.js", "module.exports = {};\n")
        _write(tmp_path / "lib.js")
        assert detect_language(str(tmp_path)) == "javascript"

    def test_typescript_classified_as_javascript(self, tmp_path: Path) -> None:
        # The shared config maps .ts/.tsx/.jsx/.mjs/.cjs to "javascript".
        for name in ("app.ts", "comp.tsx", "old.jsx", "esm.mjs", "cjs.cjs"):
            _write(tmp_path / name)
        assert detect_language(str(tmp_path)) == "javascript"

    def test_typescript_dominant_over_python(self, tmp_path: Path) -> None:
        for i in range(4):
            _write(tmp_path / f"src_{i}.ts")
        _write(tmp_path / "scripts" / "release.py")
        assert detect_language(str(tmp_path)) == "javascript"


class TestDetectLanguageGo:
    def test_single_go_file(self, tmp_path: Path) -> None:
        _write(tmp_path / "main.go", "package main\n")
        assert detect_language(str(tmp_path)) == "go"

    def test_go_dominant_over_other_extensions(self, tmp_path: Path) -> None:
        for i in range(6):
            _write(tmp_path / f"pkg_{i}.go")
        _write(tmp_path / "tools" / "fix.py")
        _write(tmp_path / "web" / "ui.js")
        assert detect_language(str(tmp_path)) == "go"


class TestDetectLanguageMixed:
    """Mixed-language repos must report the dominant language by file count.

    Unlike the per-language classes above which lean on skip_dirs to mask
    competing extensions, these cases place real source from two languages
    side-by-side at the root so the dominance heuristic itself is exercised.
    """

    def test_ts_dominant_over_python_at_root(self, tmp_path: Path) -> None:
        # 6 TS source files vs 4 Python tooling files at the same level —
        # mirrors a typical Node project that ships a few Python build
        # scripts. No skip_dirs trickery involved.
        for i in range(6):
            _write(tmp_path / "src" / f"mod_{i}.ts")
        for i in range(4):
            _write(tmp_path / "scripts" / f"tool_{i}.py")
        assert detect_language(str(tmp_path)) == "javascript"

    def test_python_dominant_over_javascript_at_root(self, tmp_path: Path) -> None:
        # Inverse case: Python repo with a small JS frontend.
        for i in range(7):
            _write(tmp_path / f"pkg_{i}.py")
        for i in range(3):
            _write(tmp_path / "frontend" / f"page_{i}.js")
        assert detect_language(str(tmp_path)) == "python"


class TestDetectLanguageSkipDirs:
    def test_node_modules_ignored(self, tmp_path: Path) -> None:
        # Two real .py files at the root, plus a noisy node_modules tree.
        # If skip_dirs weren't honoured, JS would (wrongly) win.
        _write(tmp_path / "main.py")
        _write(tmp_path / "lib.py")
        for i in range(20):
            _write(tmp_path / "node_modules" / f"pkg_{i}" / "index.js")
        assert detect_language(str(tmp_path)) == "python"

    def test_vendor_ignored(self, tmp_path: Path) -> None:
        _write(tmp_path / "cmd" / "main.go")
        _write(tmp_path / "internal" / "svc.go")
        for i in range(20):
            _write(tmp_path / "vendor" / f"dep_{i}" / "lib.py")
        assert detect_language(str(tmp_path)) == "go"


class TestDetectLanguageEmpty:
    def test_empty_directory_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="No supported source files"):
            detect_language(str(tmp_path))

    def test_only_unsupported_files_raises(self, tmp_path: Path) -> None:
        _write(tmp_path / "README.md", "# hi")
        _write(tmp_path / "data.json", "{}")
        with pytest.raises(ValueError, match="No supported source files"):
            detect_language(str(tmp_path))


class TestDetectLanguageNonGit:
    """Auto-detection is purely extension-based and must not require .git."""

    def test_non_git_directory_detected(self, tmp_path: Path) -> None:
        _write(tmp_path / "main.py")
        assert not (tmp_path / ".git").exists()
        assert detect_language(str(tmp_path)) == "python"
