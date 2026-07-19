"""Regression: _get_string_value must not reference the removed ``ast.Str``.

``ast.Str`` was removed in CPython 3.12. The old code fell through to
``isinstance(node, ast.Str)`` for any node that is not a string ``ast.Constant``,
which raises ``AttributeError: module 'ast' has no attribute 'Str'`` on 3.12+.
``ast.Constant`` already covers string literals on every supported version.
"""
import ast
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from parsers.python.ast_parser import PythonRouteParser

# The RED only manifests where ast.Str is gone (3.12+); guard so it is a
# meaningful test on new runtimes and a clean skip on legacy ones.
pytestmark = pytest.mark.skipif(
    hasattr(ast, "Str"),
    reason="ast.Str still present (<3.12); the removed-alias crash cannot occur",
)


def test_non_string_node_returns_none(tmp_path):
    parser = PythonRouteParser(str(tmp_path))
    name_node = ast.parse("x", mode="eval").body  # ast.Name -> not a str constant
    assert parser._get_string_value(name_node) is None
    int_node = ast.parse("42", mode="eval").body  # int constant -> not a str
    assert parser._get_string_value(int_node) is None


def test_string_constant_still_resolves(tmp_path):
    parser = PythonRouteParser(str(tmp_path))
    str_node = ast.parse("'hi'", mode="eval").body
    assert parser._get_string_value(str_node) == "hi"
