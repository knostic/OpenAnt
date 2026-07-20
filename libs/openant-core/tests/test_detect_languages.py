"""Multi-language detection.

Companion to ``test_detect_language.py``, which is deliberately left unmodified
— its single-winner assertions are the back-compat guard proving
``detect_language`` still behaves exactly as before.
"""

import pytest

from core.parser_adapter import detect_language, detect_languages


def make_repo(root, files: dict[str, int]):
    """Create `count` files of each extension under root."""
    for ext, count in files.items():
        for i in range(count):
            (root / f"file{i}{ext}").write_text("x")


class TestCounts:
    def test_returns_the_full_count_map(self, tmp_path):
        make_repo(tmp_path, {".py": 3, ".js": 2, ".go": 1})
        assert detect_languages(str(tmp_path)) == {
            "python": 3, "javascript": 2, "go": 1,
        }

    def test_extensions_collapse_into_their_language(self, tmp_path):
        """.ts and .jsx both count as javascript; .hpp as c."""
        (tmp_path / "a.ts").write_text("x")
        (tmp_path / "b.jsx").write_text("x")
        (tmp_path / "c.hpp").write_text("x")
        assert detect_languages(str(tmp_path)) == {"javascript": 2, "c": 1}

    def test_unsupported_files_are_ignored(self, tmp_path):
        make_repo(tmp_path, {".py": 2})
        (tmp_path / "README.md").write_text("x")
        (tmp_path / "Makefile").write_text("x")
        assert detect_languages(str(tmp_path)) == {"python": 2}

    def test_nested_directories_are_walked(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        (deep / "x.py").write_text("x")
        (tmp_path / "y.py").write_text("x")
        assert detect_languages(str(tmp_path)) == {"python": 2}

    def test_extension_matching_is_case_insensitive(self, tmp_path):
        (tmp_path / "A.PY").write_text("x")
        assert detect_languages(str(tmp_path)) == {"python": 1}


class TestOrdering:
    def test_ordered_by_descending_count(self, tmp_path):
        make_repo(tmp_path, {".go": 1, ".py": 9, ".c": 5})
        assert list(detect_languages(str(tmp_path))) == ["python", "c", "go"]

    def test_ties_break_alphabetically(self, tmp_path):
        """Deterministic where max() was arbitrary and Go's was randomized."""
        make_repo(tmp_path, {".py": 2, ".js": 2})
        assert list(detect_languages(str(tmp_path))) == ["javascript", "python"]

    def test_ordering_is_stable_across_calls(self, tmp_path):
        make_repo(tmp_path, {".py": 3, ".js": 3, ".go": 3})
        first = list(detect_languages(str(tmp_path)))
        for _ in range(20):
            assert list(detect_languages(str(tmp_path))) == first


class TestSkipDirPruning:
    def test_skip_dirs_are_excluded(self, tmp_path):
        (tmp_path / "app.py").write_text("x")
        for skipped in ("node_modules", "vendor", ".git", "__pycache__", "dist"):
            d = tmp_path / skipped
            d.mkdir()
            (d / "ignored.js").write_text("x")
        assert detect_languages(str(tmp_path)) == {"python": 1}

    def test_skip_dirs_are_pruned_at_any_depth(self, tmp_path):
        (tmp_path / "app.py").write_text("x")
        deep = tmp_path / "packages" / "web" / "node_modules" / "dep" / "src"
        deep.mkdir(parents=True)
        (deep / "index.js").write_text("x")
        assert detect_languages(str(tmp_path)) == {"python": 1}

    def test_a_file_named_like_a_skip_dir_is_still_counted(self, tmp_path):
        """Pruning targets DIRECTORIES.

        The old per-file check tested every path component, so a file whose
        name collided with a skip_dir entry could be dropped. Directory
        pruning is the Go detector's semantics and the correct one.
        """
        (tmp_path / "build.py").write_text("x")
        (tmp_path / "vendor.go").write_text("x")
        assert detect_languages(str(tmp_path)) == {"go": 1, "python": 1}


class TestErrors:
    def test_empty_repo_raises(self, tmp_path):
        with pytest.raises(ValueError, match="No supported source files found"):
            detect_languages(str(tmp_path))

    def test_repo_with_only_unsupported_files_raises(self, tmp_path):
        (tmp_path / "README.md").write_text("x")
        with pytest.raises(ValueError, match="No supported source files found"):
            detect_languages(str(tmp_path))


class TestDetectLanguageBackCompat:
    """detect_language must remain exactly the dominant language."""

    def test_returns_the_dominant_language(self, tmp_path):
        make_repo(tmp_path, {".py": 7, ".js": 3})
        assert detect_language(str(tmp_path)) == "python"

    def test_agrees_with_the_head_of_detect_languages(self, tmp_path):
        make_repo(tmp_path, {".py": 4, ".js": 6, ".go": 1})
        assert detect_language(str(tmp_path)) == next(iter(detect_languages(str(tmp_path))))

    def test_raises_the_same_error_on_an_empty_repo(self, tmp_path):
        with pytest.raises(ValueError, match="No supported source files found"):
            detect_language(str(tmp_path))
