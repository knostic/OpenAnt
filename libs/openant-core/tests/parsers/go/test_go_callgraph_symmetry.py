"""Y-test (per-parser call-graph symmetry) for Go — #702.

The suite the #147-#153 wave promised as a follow-up and never shipped.
Asserts the shared invariants via tests/parsers/_symmetry_shared.py over the
REAL go_parser binary (the Go parser is a Go module — `go build` + the
`callgraph` subcommand — the #747 harness pattern: the binary builds into
tmp_path, never in-tree).

The function-id set comes from the binary's `extract` subcommand (the same
id format as the graphs) — the union-of-both-maps-keys node set is
TAUTOLOGICAL (a symmetric phantom edge adds its own key and passes
node-realness vacuously; the fable-r1 F2 catch).
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[3]
_GO_PARSER_DIR = _CORE_ROOT / "parsers" / "go" / "go_parser"

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _symmetry_shared import (  # noqa: E402
    assert_callgraph_symmetry,
    assert_graph_is_nonempty,
    assert_no_self_edges,
)

_MODULE = "fxsym"
_UTIL_GO = """package util

func Helper(x int) int { return x + 1 }
func Shared() {}
func Leaf() {}
"""
_MAIN_GO = """package cmd

import "@MOD@/internal/util"

func A(x int) int { util.Helper(x); util.Shared(); return 0 }
func B(x int) int { util.Helper(x); util.Shared(); return 0 }
func C() int { return util.Helper(3) }
func main() { A(1); B(2); util.Leaf(); C(); missing() }
"""


@pytest.fixture(scope="module")
def go_parser_binary(tmp_path_factory):
    if shutil.which("go") is None:
        pytest.skip("Go toolchain unavailable")
    out = tmp_path_factory.mktemp("symmetry_bin") / "go_parser"
    proc = subprocess.run(
        ["go", "build", "-o", str(out), "."],
        cwd=str(_GO_PARSER_DIR), capture_output=True, text=True,
    )
    if proc.returncode != 0:
        pytest.skip(f"go build failed (env):\n{proc.stderr[-2000:]}")
    # Windows appends .exe to the extensionless output — resolve to whichever
    # exists (the #747 lesson: a missing binary reads every shape as "no
    # edge" and the vacuous-green guard below would misread it as a drop).
    if not out.exists() and (out.parent / (out.name + ".exe")).exists():
        out = out.parent / (out.name + ".exe")
    assert out.exists(), (
        f"go build rc=0 but no executable at {out} — the fixture is broken, "
        "not the environment")
    return out


def _graph(binary, tmp_path):
    root = tmp_path / "tree"
    (root / "cmd").mkdir(parents=True)
    (root / "internal" / "util").mkdir(parents=True)
    (root / "go.mod").write_text(f"module {_MODULE}\n\ngo 1.21\n")
    (root / "internal" / "util" / "util.go").write_text(_UTIL_GO)
    # a plain replace, NEVER str.format: the Go source's own braces
    # (`{ return 0 }`) read as format placeholders (the #747 fixture-
    # hygiene lesson family)
    (root / "cmd" / "main.go").write_text(_MAIN_GO.replace("@MOD@", _MODULE))
    proc = subprocess.run([str(binary), "callgraph", str(root)],
                          capture_output=True, text=True)
    assert proc.returncode == 0, f"parser rc={proc.returncode}: {proc.stderr[-2000:]}"
    assert "failed to parse" not in proc.stderr, (
        "the FIXTURE is broken, not the parser:\n" + proc.stderr[-2000:])
    g = json.loads(proc.stdout)
    # the REAL function-id set comes from the binary's `extract` subcommand
    # (the same id format as the graphs): the UNION-of-keys node set the
    # first draft used is TAUTOLOGICAL — a symmetric phantom edge adds its
    # own key and passes node-realness vacuously (the fable-r1 F2 catch).
    ex = subprocess.run([str(binary), "extract", str(root)],
                        capture_output=True, text=True)
    assert ex.returncode == 0, f"extract rc={ex.returncode}: {ex.stderr[-2000:]}"
    exd = json.loads(ex.stdout)
    raw_fids = set((exd.get("functions") or {}).keys())
    fwd = g.get("call_graph") or {}
    rev = g.get("reverse_call_graph") or {}
    # Windows emits repo-relative keys with backslashes (the parser's own
    # callgraph.go keeps them) — normalise to forward slashes (the #747
    # lesson: every lookup misreads otherwise on the windows CI leg).
    fwd = {k.replace("\\", "/"): [c.replace("\\", "/") for c in v]
           for k, v in fwd.items()}
    rev = {k.replace("\\", "/"): [c.replace("\\", "/") for c in v]
           for k, v in rev.items()}
    return {k.replace("\\", "/") for k in raw_fids}, fwd, rev


def test_callgraph_symmetry_invariants(go_parser_binary, tmp_path):
    fids, fwd, rev = _graph(go_parser_binary, tmp_path)
    assert_callgraph_symmetry(fids, fwd, rev, context="go")
    assert_no_self_edges(fwd, context="go")
    assert_graph_is_nonempty(fwd, context="go")


def test_shared_callee_has_both_callers_in_reverse(go_parser_binary, tmp_path):
    _, _, rev = _graph(go_parser_binary, tmp_path)
    shared = [k for k in rev if k.endswith(":Shared")]
    a = [k for k in rev if k.endswith(":A")]
    b = [k for k in rev if k.endswith(":B")]
    assert shared and a and b, sorted(rev.keys())
    assert set(rev[shared[0]]) == {a[0], b[0]}, (
        f"the shared callee's reverse set must carry both callers: "
        f"{rev[shared[0]]}")


def test_undeclared_callee_is_not_a_phantom_node(go_parser_binary, tmp_path):
    """`missing()` in main is undeclared — no phantom node, no edge (the
    parser declines it; the pin guards the decline)."""
    fids, fwd, _ = _graph(go_parser_binary, tmp_path)
    assert not any(k.endswith(":missing") for k in fids), "phantom missing()"
    for callees in fwd.values():
        assert not any(c.endswith(":missing") for c in callees), (
            f"phantom edge to the undeclared callee: {callees}")


def test_package_call_edge_is_present(go_parser_binary, tmp_path):
    """The cross-package qualified call (`util.Helper(x)` inside cmd) is the
    go parser's own edge class — the #747 family; its edge must exist in
    BOTH directions."""
    fids, fwd, rev = _graph(go_parser_binary, tmp_path)
    caller = [k for k in fwd if k.endswith(":A")]
    helper = [k for k in fids if k.endswith(":Helper")]
    assert caller and helper, sorted(fids)
    assert helper[0] in fwd[caller[0]], (
        f"the package call's edge is absent: {fwd[caller[0]]}")
    assert caller[0] in rev[helper[0]], (
        "the reverse side lost the package call's caller")
