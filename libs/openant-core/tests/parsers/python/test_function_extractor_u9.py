"""Regression tests for FunctionExtractor (u9 blind bug batch, 2026-06-08).

Six confirmed bugs in parsers/python/function_extractor.py:

  BUG 9  nested-def inside a function body is never extracted as a unit.
  BUG 21 module-level `handler = lambda ...` is never extracted as a unit.
  BUG 23 decorated function start_line points at `def` line, not the decorator
         (off-by-one; off-by-N for stacked decorators) while `code` includes them.
  BUG 34 `@x.setter` is classified 'method' not 'property', AND getter/setter
         share a func_id so the setter silently overwrites the getter.
  BUG 45 a method of a class nested inside another class is never extracted.
  BUG 48 unit_type='test' for any file whose path merely CONTAINS the substring
         'test' (e.g. latest.py), instead of a path-component check.

Each test writes a minimal source file under a tmp dir, runs the extractor,
and asserts on the returned dict (the parser operates on files, so we model
the real entry path: FunctionExtractor(repo).extract_all([rel_path])).
"""

import sys
from pathlib import Path

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.python.function_extractor import FunctionExtractor


def _extract(tmp_path: Path, filename: str, source: str) -> dict:
    """Write `source` to tmp_path/filename, extract, return the full result dict."""
    f = tmp_path / filename
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(source, encoding="utf-8")
    extractor = FunctionExtractor(str(tmp_path))
    return extractor.extract_all([filename])


# --- BUG 9: nested def inside a function body ---------------------------------

def test_bug9_nested_def_is_extracted(tmp_path):
    source = "def outer():\n    def inner():\n        return 1\n    return inner\n"
    result = _extract(tmp_path, "m.py", source)
    func_names = {fd["name"] for fd in result["functions"].values()}
    assert "inner" in func_names, (
        f"nested def 'inner' not extracted. functions={list(result['functions'])}"
    )


# --- BUG 21: module-level lambda assigned to a name ---------------------------

def test_bug21_module_level_lambda_is_extracted(tmp_path):
    source = "handler = lambda req: req.upper()\n"
    result = _extract(tmp_path, "m.py", source)
    func_names = {fd["name"] for fd in result["functions"].values()}
    assert "handler" in func_names, (
        f"module-level lambda 'handler' not extracted. functions={list(result['functions'])}"
    )


# --- BUG 23: decorated start_line includes the decorator line -----------------

def test_bug23_decorated_start_line_includes_decorator(tmp_path):
    source = "class Foo:\n    @staticmethod\n    def bar():\n        pass\n"
    result = _extract(tmp_path, "m.py", source)
    fid = "m.py:Foo.bar"
    assert fid in result["functions"], f"missing {fid}: {list(result['functions'])}"
    # @staticmethod is on line 2; def bar is on line 3. start_line must be 2.
    assert result["functions"][fid]["start_line"] == 2, (
        f"decorated start_line off-by-one: got {result['functions'][fid]['start_line']}, expected 2"
    )


def test_bug23_stacked_decorators_start_line(tmp_path):
    source = (
        "def d1(f):\n    return f\n\n"
        "def d2(f):\n    return f\n\n"
        "@d1\n@d2\ndef target():\n    pass\n"
    )
    result = _extract(tmp_path, "m.py", source)
    fid = "m.py:target"
    assert fid in result["functions"], f"missing {fid}: {list(result['functions'])}"
    # @d1 on line 7, @d2 on line 8, def target on line 9. start_line must be 7.
    assert result["functions"][fid]["start_line"] == 7, (
        f"stacked-decorator start_line wrong: got {result['functions'][fid]['start_line']}, expected 7"
    )


# --- BUG 34: property getter/setter ------------------------------------------

def test_bug34_property_setter_classified_and_not_collapsed(tmp_path):
    source = (
        "class C:\n"
        "    @property\n"
        "    def x(self):\n"
        "        return self._x\n"
        "\n"
        "    @x.setter\n"
        "    def x(self, value):\n"
        "        self._x = value\n"
    )
    result = _extract(tmp_path, "m.py", source)
    funcs = result["functions"]
    # Getter keeps the CANONICAL id; the setter is disambiguated by ROLE in the
    # qualified_name (order-independent) -- so both survive AND func_id stays
    # path:qualified_name (the call_graph_builder reconstruction invariant).
    assert "m.py:C.x" in funcs, f"getter lost its canonical id; ids={list(funcs)}"
    assert "m.py:C.x.setter" in funcs, f"setter not stored under role id; ids={list(funcs)}"
    getter, setter = funcs["m.py:C.x"], funcs["m.py:C.x.setter"]
    # Invariant: func_id == path:qualified_name for BOTH units.
    assert getter["qualified_name"] == "C.x", getter["qualified_name"]
    assert setter["qualified_name"] == "C.x.setter", setter["qualified_name"]
    # Both classified 'property'; roles distinguished.
    assert getter["unit_type"] == "property" and setter["unit_type"] == "property"
    assert getter["property_role"] == "getter", getter["property_role"]
    assert setter["property_role"] == "setter", setter["property_role"]


# --- BUG 45: nested class members ---------------------------------------------

def test_bug45_nested_class_method_is_extracted(tmp_path):
    source = (
        "class Outer:\n"
        "    class Inner:\n"
        "        def deep(self):\n"
        "            return 1\n"
        "    def shallow(self):\n"
        "        return 2\n"
    )
    result = _extract(tmp_path, "m.py", source)
    deep_units = [fd for fd in result["functions"].values() if fd["name"] == "deep"]
    assert deep_units, (
        f"nested-class method 'deep' not extracted. functions={list(result['functions'])}"
    )


# --- BUG 48: test classification by substring vs path component ---------------

def test_bug48_substring_test_not_classified_as_test(tmp_path):
    source = "def compute():\n    return 1\n"
    result = _extract(tmp_path, "latest.py", source)
    fid = "latest.py:compute"
    assert fid in result["functions"], f"missing {fid}: {list(result['functions'])}"
    assert result["functions"][fid]["unit_type"] == "function", (
        f"'latest.py' misclassified as test: got {result['functions'][fid]['unit_type']}, expected 'function'"
    )


def test_bug48_real_test_file_still_classified_test(tmp_path):
    """Guard: a genuine test file path component must STILL classify as test."""
    source = "def helper():\n    return 1\n"
    result = _extract(tmp_path, "tests/test_thing.py", source)
    fid = "tests/test_thing.py:helper"
    assert fid in result["functions"], f"missing {fid}: {list(result['functions'])}"
    assert result["functions"][fid]["unit_type"] == "test", (
        f"genuine test file not classified test: got {result['functions'][fid]['unit_type']}"
    )
