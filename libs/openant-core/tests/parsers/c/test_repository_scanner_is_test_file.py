"""Regression tests for the C repository scanner's test-file detection.

``RepositoryScanner.is_test_file`` matched its ``test_patterns`` as bare
substrings (``if pattern in path_lower``). Because
``test_patterns`` includes ``'test_'`` and ``'test/'``, ordinary source files
whose *name or path merely contains* those characters were wrongly skipped as
tests:

    - ``latest_value.c``  contains ``'test_'`` (la**test_**value) -> skipped
    - ``contest/foo.c``   contains ``'test/'`` (con**test/**)     -> skipped

The fix anchors the patterns to path *segments* and filename boundaries, so a
pattern only matches a whole directory segment (``test/``, ``tests/``, ``fuzz/``)
or a filename prefix/suffix (``test_``, ``_test.c``).
"""

import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]  # libs/openant-core
sys.path.insert(0, str(_CORE_ROOT))

from parsers.c.repository_scanner import RepositoryScanner


def _scanner() -> RepositoryScanner:
    # is_test_file is pure string logic; repo_path is unused by it.
    return RepositoryScanner(".")


def test_is_test_file_true_for_real_tests():
    """Genuine test files/dirs must still be detected (guards against over-correction)."""
    s = _scanner()
    assert s.is_test_file("test/foo.c") is True
    assert s.is_test_file("src/tests/bar.c") is True
    assert s.is_test_file("fuzz/baz.c") is True
    assert s.is_test_file("foo_test.c") is True
    assert s.is_test_file("test_foo.c") is True
    assert s.is_test_file("src/util/widget_test.cpp") is True
    # _test stem before any C/C++ source extension (the old substring check caught
    # .cc/.cxx via the '.c' prefix; the stem match preserves that):
    assert s.is_test_file("foo_test.cc") is True
    assert s.is_test_file("foo_test.cxx") is True


def test_is_test_file_false_for_substring_lookalikes():
    """Non-test files whose name/path merely CONTAINS a pattern
    must NOT be classified as tests."""
    s = _scanner()
    assert s.is_test_file("latest_value.c") is False   # contains 'test_'
    assert s.is_test_file("contest/foo.c") is False    # contains 'test/'
    assert s.is_test_file("src/greatest.c") is False   # contains 'test'
    assert s.is_test_file("attestation.cpp") is False  # contains 'test'
    assert s.is_test_file("mytest/foo.c") is False     # deceptive dir segment 'mytest'
    assert s.is_test_file("testing/foo.c") is False    # deceptive dir segment 'testing'
