"""Regression tests for the Ruby RepositoryScanner.is_test_file anchoring.

is_test_file previously used an unanchored
``pattern in path_lower`` substring scan over {'test_', '_test.rb', '_spec.rb',
'test/', 'tests/', 'spec/'}, so ordinary sources whose name merely *contains* a
token were misclassified (e.g. ``lib/latest_release.rb`` matched ``test_``;
``contest/foo.rb`` matched ``test``... via ``tests/`` only on 'contests/').
Fix: match directory components exactly + anchor filename rules to the basename
using Ruby's own native Minitest/RSpec conventions.
"""
import importlib.util
import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
if str(_CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CORE_ROOT))


def _load_scanner():
    path = _CORE_ROOT / "parsers" / "ruby" / "repository_scanner.py"
    spec = importlib.util.spec_from_file_location("rs_ruby_is_test_file", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.RepositoryScanner


SCANNER = _load_scanner()


def _scan(repo="/tmp/repo"):
    return SCANNER(repo)


# --- non-test sources that the substring scan wrongly flagged (the bug) ---
def test_latest_release_is_not_a_test():
    assert _scan().is_test_file("lib/latest_release.rb") is False


def test_contest_dir_is_not_a_test_dir():
    assert _scan().is_test_file("contest/foo.rb") is False


# --- genuine Ruby test files must still be detected ---
def test_spec_suffix_is_a_test():
    assert _scan().is_test_file("spec/widget_spec.rb") is True


def test_minitest_test_suffix_is_a_test():
    assert _scan().is_test_file("test/widget_test.rb") is True


def test_test_prefix_basename_is_a_test():
    assert _scan().is_test_file("lib/test_widget.rb") is True


def test_spec_dir_is_a_test():
    assert _scan().is_test_file("spec/foo.rb") is True
