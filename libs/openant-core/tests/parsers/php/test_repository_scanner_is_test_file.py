"""Regression tests for the PHP RepositoryScanner.is_test_file anchoring.

is_test_file previously used an unanchored
``pattern.lower() in path_lower`` substring scan over {'test_', '_test.php',
'Test.php', 'test/', 'tests/', 'spec/', 'phpunit'}. Because 'Test.php'
lowercased to 'test.php', ordinary PascalCase sources like ``Contest.php``
(``contest.php``) matched mid-token, and ``latest_helper.php`` matched
``test_``. Fix: match directory components exactly + anchor filename rules
(PSR PascalCase ``*Test.php`` on the original-case basename) using PHP's own
native PHPUnit conventions.
"""
import importlib.util
import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
if str(_CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CORE_ROOT))


def _load_scanner():
    path = _CORE_ROOT / "parsers" / "php" / "repository_scanner.py"
    spec = importlib.util.spec_from_file_location("rs_php_is_test_file", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.RepositoryScanner


SCANNER = _load_scanner()


def _scan(repo="/tmp/repo"):
    return SCANNER(repo)


# --- non-test sources that the substring scan wrongly flagged (the bug) ---
def test_contest_pascalcase_is_not_a_test():
    # 'Contest.php' -> lowercased 'contest.php' ends with 'test.php' (substring bug)
    assert _scan().is_test_file("src/Contest.php") is False


def test_latest_helper_is_not_a_test():
    assert _scan().is_test_file("src/latest_helper.php") is False


# --- genuine PHP test files must still be detected ---
def test_psr_pascalcase_test_suffix_is_a_test():
    assert _scan().is_test_file("tests/FooTest.php") is True


def test_psr_pascalcase_test_suffix_outside_tests_dir_is_a_test():
    assert _scan().is_test_file("src/FooTest.php") is True


def test_tests_dir_is_a_test():
    assert _scan().is_test_file("tests/Foo.php") is True


def test_spec_dir_is_a_test():
    assert _scan().is_test_file("spec/FooSpec.php") is True


def test_snake_test_suffix_is_a_test():
    assert _scan().is_test_file("src/widget_test.php") is True
