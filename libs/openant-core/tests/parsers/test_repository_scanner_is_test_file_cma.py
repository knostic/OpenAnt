"""Cross-language regression: repository_scanner test-file classification must be anchored.

Bug (path_substring_exclusion family, bundle entries [2] multi-lang + [22] zig):
  `is_test_file` (c/php/python/ruby) and `_is_test_file`/`_is_test_directory` (zig)
  classified a file/dir as a TEST using an UNANCHORED substring match
  (`for pattern in test_patterns: if pattern in path_lower`). Because `test_` is a
  substring of `latest_`/`greatest_`/`contest_`, and zig's bare `test`/`spec` tokens
  are substrings of `latest`/`contest`/`attestation`/`inspector`, real source files
  whose name merely CONTAINS a test token were silently classified as tests and
  DROPPED from extraction (default `skip_tests=True`).

Fix shape (one mechanism across all 5 langs): anchor the match to whole PATH
COMPONENTS (a directory part == test/tests/spec/specs) OR basename conventions
(`test_*`, `*_test.<ext>`, `*_spec.<ext>`, `*Test.<ext>`, `conftest.py`, etc.).

This test drives each scanner's classification predicate directly:
  - DECOY case: a real source whose name CONTAINS a token as substring -> NOT a test.
  - POSITIVE case: a genuine test file/dir -> still IS a test (don't over-narrow).

JS (`isTestFile` regex) and Go (`HasSuffix "_test.go"`) are already anchored and are
intentionally NOT exercised here.
"""

import sys
from pathlib import Path

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_CORE_ROOT))


def _make_scanner(lang, repo_path="/tmp/repo"):
    """Instantiate each language's RepositoryScanner with skip_tests on."""
    if lang == "c":
        from parsers.c.repository_scanner import RepositoryScanner
        return RepositoryScanner(repo_path, {"skip_tests": True})
    if lang == "php":
        from parsers.php.repository_scanner import RepositoryScanner
        return RepositoryScanner(repo_path, {"skip_tests": True})
    if lang == "python":
        from parsers.python.repository_scanner import RepositoryScanner
        return RepositoryScanner(repo_path, {"skip_tests": True})
    if lang == "ruby":
        from parsers.ruby.repository_scanner import RepositoryScanner
        return RepositoryScanner(repo_path, {"skip_tests": True})
    if lang == "zig":
        from parsers.zig.repository_scanner import RepositoryScanner
        return RepositoryScanner(repo_path, skip_tests=True)
    raise ValueError(lang)


def _is_test(lang, scanner, relative_path):
    """Call the per-language test-file classification predicate."""
    if lang == "zig":
        return scanner._is_test_file(relative_path)
    return scanner.is_test_file(relative_path)


# (lang, decoy_real_source_that_must_NOT_be_a_test)
DECOYS = [
    ("c", "latest_dir/main.c"),
    ("c", "contest/sol.c"),
    ("c", "src/protest.c"),
    ("php", "src/protest_api.php"),
    ("php", "app/latest_controller.php"),
    ("python", "pkg/latest.py"),
    ("python", "pkg/greatest_helper.py"),
    ("ruby", "lib/latest_x.rb"),
    ("ruby", "lib/contest.rb"),
    ("zig", "src/latest.zig"),
    ("zig", "src/contest.zig"),
    ("zig", "src/attestation.zig"),
    ("zig", "inspector/foo.zig"),
]

# (lang, genuine_test_file_that_MUST_still_be_classified_as_a_test)
POSITIVES = [
    ("c", "tests/test_foo.c"),
    ("c", "src/foo_test.c"),
    ("php", "tests/FooTest.php"),
    ("php", "src/test_helper.php"),
    ("python", "tests/test_foo.py"),
    ("python", "pkg/conftest.py"),
    ("ruby", "spec/foo_spec.rb"),
    ("ruby", "test/test_foo.rb"),
    ("zig", "test/foo.zig"),
    ("zig", "src/foo_test.zig"),
]


@pytest.mark.parametrize("lang,relative_path", DECOYS)
def test_decoy_real_source_not_classified_as_test(lang, relative_path):
    scanner = _make_scanner(lang)
    assert not _is_test(lang, scanner, relative_path), (
        f"{lang}: real source {relative_path!r} wrongly classified as a test "
        f"(unanchored substring match)"
    )


@pytest.mark.parametrize("lang,relative_path", POSITIVES)
def test_positive_genuine_test_still_classified(lang, relative_path):
    scanner = _make_scanner(lang)
    assert _is_test(lang, scanner, relative_path), (
        f"{lang}: genuine test {relative_path!r} must still be classified as a test"
    )


def test_zig_test_directory_decoy_not_excluded():
    """zig dir-level: `inspector`/`latest` dirs must NOT be treated as test dirs."""
    scanner = _make_scanner("zig")
    assert not scanner._is_test_directory("inspector")
    assert not scanner._is_test_directory("latest_dir")
    # positive: a real `test` dir IS a test dir
    assert scanner._is_test_directory("test")
    assert scanner._is_test_directory("tests")
    assert scanner._is_test_directory("spec")
