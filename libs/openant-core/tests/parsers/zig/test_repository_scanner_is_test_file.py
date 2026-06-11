"""Regression tests for the Zig RepositoryScanner test detection anchoring.

TEST_PATTERNS previously held bare tokens
{'test','tests','spec','specs','_test','test_'} matched as substrings in BOTH
_is_test_directory (``pattern in dirname_lower``) and _is_test_file
(``pattern in part``), so ``latest``/``contest``/``attestation`` directories and
``src/fastest.zig`` were misclassified as tests and pruned/skipped when
skip_tests is on. Two-part fix: (1) anchor directory matching to whole names
and filename matching to stem prefix/suffix using Zig's native conventions;
(2) align the constructor skip_tests default to False (the other four parsers'
default), fixing the active-by-default silent data loss.
"""
import importlib.util
import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
if str(_CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CORE_ROOT))


def _load_scanner():
    path = _CORE_ROOT / "parsers" / "zig" / "repository_scanner.py"
    spec = importlib.util.spec_from_file_location("rs_zig_is_test_file", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.RepositoryScanner


SCANNER = _load_scanner()


def _scan(repo="/tmp/repo"):
    return SCANNER(repo)


# --- directories: bare 'test' substring no longer over-matches ---
def test_latest_dir_is_not_a_test_dir():
    assert _scan()._is_test_directory("latest") is False


def test_contest_dir_is_not_a_test_dir():
    assert _scan()._is_test_directory("contest") is False


def test_attestation_dir_is_not_a_test_dir():
    assert _scan()._is_test_directory("attestation") is False


def test_exact_test_dir_is_a_test_dir():
    assert _scan()._is_test_directory("test") is True


def test_exact_spec_dir_is_a_test_dir():
    assert _scan()._is_test_directory("spec") is True


# --- files: bare 'test' substring no longer over-matches ---
def test_fastest_file_is_not_a_test():
    assert _scan()._is_test_file("src/fastest.zig") is False


def test_file_under_latest_dir_is_not_a_test():
    assert _scan()._is_test_file("src/latest/main.zig") is False


def test_underscore_test_suffix_is_a_test():
    assert _scan()._is_test_file("src/main_test.zig") is True


def test_test_prefix_basename_is_a_test():
    assert _scan()._is_test_file("src/test_main.zig") is True


def test_file_under_test_dir_is_a_test():
    assert _scan()._is_test_file("test/main.zig") is True


# --- constructor default aligned with the other four parsers ---
def test_skip_tests_defaults_to_false():
    assert _scan().skip_tests is False
