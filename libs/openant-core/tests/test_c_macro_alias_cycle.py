"""Regression test for F4: C call-graph builder must not crash on cyclic macro aliases.

A function-like ``#define`` pair such as::

    #define A(x) B(x)
    #define B(x) A(x)

produces ``macro_aliases = {"A": "B", "B": "A"}``. Before the fix,
``_resolve_call`` recursed on the aliased name with no cycle guard, so
resolving ``A`` recursed A->B->A->... until ``RecursionError`` aborted the
entire repository's C call-graph build.
"""

from __future__ import annotations

import pytest

tree_sitter_c = pytest.importorskip("tree_sitter_c")

from parsers.c.call_graph_builder import CallGraphBuilder


def _builder(macro_aliases):
    return CallGraphBuilder(
        {
            "functions": {},
            "includes": {},
            "macros": {},
            "macro_aliases": macro_aliases,
        }
    )


def test_cyclic_macro_alias_does_not_recurse():
    """Two-node alias cycle must resolve to None, not raise RecursionError."""
    builder = _builder({"A": "B", "B": "A"})
    # Must not raise; unresolved cyclic alias returns None.
    assert builder._resolve_call("A", "foo.c") is None
    assert builder._resolve_call("B", "foo.c") is None


def test_longer_macro_alias_cycle_terminates():
    """A 3-node alias cycle must also terminate."""
    builder = _builder({"A": "B", "B": "C", "C": "A"})
    assert builder._resolve_call("A", "foo.c") is None


def test_self_macro_alias_does_not_recurse():
    """A self-alias is short-circuited by the != guard but must stay safe."""
    builder = _builder({"A": "A"})
    assert builder._resolve_call("A", "foo.c") is None
