"""Regression tests for the Python RepositoryScanner.is_test_file anchoring.

is_test_file previously used an unanchored
``pattern in path_lower`` substring scan over {'test_', '_test.py', 'tests/',
'/test/', 'conftest.py'}, so ordinary sources whose name merely *contains* a
token were misclassified as tests and silently dropped when skip_tests=True
(e.g. ``src/latest_release.py`` matched ``test_``; ``contests/foo.py`` matched
``tests/``). Fix: match directory components exactly + anchor filename rules to
the basename, using Python's own native conventions.
"""
import importlib.util
import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
if str(_CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CORE_ROOT))


def _load_scanner():
    # Unique module name: parsers/{python,php,ruby,zig}/repository_scanner.py
    # all share the basename, so importlib gets a per-parser unique name here.
    path = _CORE_ROOT / "parsers" / "python" / "repository_scanner.py"
    spec = importlib.util.spec_from_file_location("rs_python_is_test_file", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.RepositoryScanner


SCANNER = _load_scanner()


def _scan(repo="/tmp/repo"):
    return SCANNER(repo)


# --- non-test sources that the substring scan wrongly flagged (the bug) ---
def test_latest_release_is_not_a_test():
    assert _scan().is_test_file("src/latest_release.py") is False


def test_contests_dir_is_not_a_test_dir():
    assert _scan().is_test_file("contests/foo.py") is False


def test_pytest_helper_is_not_a_test():
    assert _scan().is_test_file("tools/pytest_helper.py") is False


# --- genuine Python test files must still be detected ---
def test_tests_dir_is_a_test():
    assert _scan().is_test_file("tests/test_x.py") is True


def test_test_prefix_basename_is_a_test():
    assert _scan().is_test_file("src/test_x.py") is True


def test_underscore_test_suffix_is_a_test():
    assert _scan().is_test_file("src/widget_test.py") is True


def test_conftest_is_a_test():
    assert _scan().is_test_file("src/conftest.py") is True
