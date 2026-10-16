"""#781 end-to-end regression: the DIRECT method-call paths must not
fabricate a cross-package edge through the bare-name collision.

At the base (`parsers/go/go_parser/callgraph.go`, resolveMethodCall's
cross-package fall-through) the parser keys `methodsByType` repo-wide on
the BARE receiver type and holds BARE type names in `varTypes` -- and a
bare-written type is the caller's OWN package's type by construction (an
imported type is written qualified, a SelectorExpr, and `exprTypeName`
returns "" for it, contributing nothing to the body model). When the
caller's own package's same-named type does NOT provide the method (the
func-typed FIELD shape: a/backend declares `view` as a FIELD,
z/backend declares `view()` as a METHOD), the same-package preference
finds no candidate and the pick falls through to the OTHER package's
same-named method -- fabricating `a:backend.mk -> z:backend.view` on BOTH
direct paths: `b.view()` (the IsMethod arm) and `f := b.view; f()` (the
method-value-alias arm -- both build the same IsMethod CallInfo and route
into resolveMethodCall).

The fix: the categorical cross-package reject at resolveMethodCall's
tail -- a winner in ANOTHER package is a bare-name collision in every
shape the body model can produce EXCEPT a dot-import (`import . "m/f"`)
or a type alias (`type B = otherpkg.B`) -- the two shapes where the
other package's type IS written bare; both are the DECLARED residuals,
the same trade #746's CompositeValue gate ships (open PR #782, whose
dot-import residual this widens with the alias shape): the gate trades
those rare real edges for the deterministic fabrication kill.

The corpus control (executed at the cycle, runs/781/corpus-control.txt):
the gate fired 0 times on the OpenAnt CLI corpus -- which contains ZERO
cross-directory method edges (0 of the 1225 union edges), so the
control is a NO-HARM-ON-THIS-CORPUS statement (the gate's inertness
here), not a precision measurement; the only cross-binary diff edges
are singleton samples of the #777 build-tagged twin flip, present in
BOTH binaries. The issue's own OpenBao claim was not re-executed (no
OpenBao tree available).

Why this file exists ALONGSIDE the Go module: CI never runs `go test`
against the go_parser module (the `go test ./...` runs only in
apps/openant-cli; the go_parser module is only `go build`-ed). pytest
tests/ IS run, after the build -- so this is the witness that actually
guards the regression in CI. The drive follows the #746/#777 witness
conventions (the real binary built into tmp_path -- issue #686 records
that the in-tree rebuild is lockless on the Python side, so a test that
rebuilt in place would race any concurrent scan).

Shapes:

  S1 -- the DIRECT path (the declared witness, red at base):
        a/backend.go declares `backend` with a func-typed FIELD `view`;
        z/backend.go declares `backend` with a `view()` METHOD; a/mk.go
        calls `b.view()` -- the base fabricates the z edge, the fix
        records NO edge (the field call is an indirect call the model
        abstains from; it is never z's method).
  S2 -- the METHOD-VALUE-THEN-CALL path (the second declared witness,
        red at base): a/mk2.go binds `f := b.view` then calls `f()` --
        the alias arm fabricates the same z edge at the base.
  S3 -- the CONTROL (green at base AND head): a's OWN package's method
        (`b.realMethod()`) must still resolve -- the same-package
        preference is untouched by the gate.
  S4 -- the CONTROL (green at base AND head): z's INTERNAL edge
        (`z/caller.go:caller -> z/backend.go:view`) must survive -- the
        gate rejects CROSS-package winners only.
"""

import json
import subprocess
from pathlib import Path

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[3]
_GO_PARSER_DIR = _CORE_ROOT / "parsers" / "go" / "go_parser"

# The prod file under test (the #698 data-read route: a Go file cannot be a
# Python import; the C4 hunk-revert row for this file -- reverting the
# cross-package reject restores the fabrication and fails S1+S2 -- is the
# load-bearing proof).
_PROD_HUNK = "go_parser/callgraph.go"

# The fabricated edge's exact funcIDs (the issue's own measured shape).
_DIRECT_CALLER = "a/mk.go:mk"
_ALIAS_CALLER = "a/mk2.go:mk2"
_FABRICATED = "z/backend.go:backend.view"
_SAME_PKG_METHOD = "a/backend.go:backend.realMethod"
_Z_INTERNAL_CALLER = "z/caller.go:caller"

# The fabrication is DETERMINISTIC at the base (the "."+method suffix filter
# selects the unique matching candidate -- no map-iteration coin flip), so a
# single parse is sound; three fresh processes assert the determinism
# belt-and-braces (an unstable edge here would mean a DIFFERENT defect).
_RUNS = 3


@pytest.fixture(scope="module")
def binary(tmp_path_factory) -> Path:
    """Build the REAL go_parser binary into tmp_path (never the tree)."""
    out = tmp_path_factory.mktemp("issue781_bin") / "go_parser"
    proc = subprocess.run(
        ["go", "build", "-o", str(out), "."],
        cwd=str(_GO_PARSER_DIR), capture_output=True, text=True,
    )
    if proc.returncode != 0:
        # The compile-broken-prod-tree case is owned by CI's separate
        # go-build step (this suite runs after the build); this skip covers
        # only a local environment that cannot build the fixture binary.
        pytest.skip(f"go build failed (env; a broken prod tree is CI's go-build step's case, not this skip's):\n{proc.stderr[-2000:]}")
    # Windows: the observed #747-witness leg -- resolve .exe if the build
    # produced one (the fixture-build is the #686 lockless rule: never the tree)
    if not out.exists() and (out.parent / (out.name + ".exe")).exists():
        out = out.parent / (out.name + ".exe")
    assert out.exists(), (
        f"go build rc=0 but no executable at {out} — the fixture is broken, "
        "not the environment")
    return out


def _norm_slashes(s: str) -> str:
    """funcIDs are repo-relative paths and on Windows `filepath.Rel` emits
    them backslash-separated; every graph key and target is normalised
    before comparison."""
    return s.replace("\\", "/")


def _make_tree(tmp: Path) -> Path:
    """The two-package fixture from the issue's own measured shape: a/
    declares `backend` with a func-typed FIELD `view` (plus its own real
    method), z/ declares `backend` with a `view()` METHOD (plus a caller)."""
    root = tmp / "fx781"
    (root / "a").mkdir(parents=True)
    (root / "z").mkdir()
    (root / "go.mod").write_text("module m781\n\ngo 1.21\n", encoding="utf-8")
    (root / "a" / "backend.go").write_text(
        "package a\n\n"
        "type backend struct {\n"
        "\tview func()\n"
        "}\n\n"
        "func (b backend) realMethod() {}\n", encoding="utf-8")
    (root / "a" / "mk.go").write_text(
        "package a\n\n"
        "func mk() {\n"
        "\tvar b backend\n"
        "\tb.view()\n"
        "\tf := b.view\n"
        "\tf()\n"
        "\tb.realMethod()\n"
        "}\n", encoding="utf-8")
    (root / "a" / "mk2.go").write_text(
        "package a\n\n"
        "func mk2() {\n"
        "\tvar b backend\n"
        "\tf := b.view\n"
        "\tf()\n"
        "}\n", encoding="utf-8")
    (root / "z" / "backend.go").write_text(
        "package z\n\n"
        "type backend struct{}\n\n"
        "func (b backend) view() {}\n", encoding="utf-8")
    (root / "z" / "caller.go").write_text(
        "package z\n\n"
        "func caller() {\n"
        "\tvar b backend\n"
        "\tb.view()\n"
        "}\n", encoding="utf-8")
    return root


def _parse(binary: Path, tree: Path) -> dict:
    """One fresh parser process over the fixture; the call graph keyed by
    the caller funcID."""
    proc = subprocess.run(
        [str(binary), "callgraph", str(tree)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, f"the parser failed: rc={proc.returncode}"
    assert "failed to parse" not in proc.stderr, (
        f"the fixture is unparsable Go — every shape would read as "
        f"'no edge' and the witnesses would carry no information: "
        f"{proc.stderr[-500:]}")
    return {
        _norm_slashes(k): [_norm_slashes(t) for t in v]
        for k, v in json.loads(proc.stdout)["call_graph"].items()
    }


@pytest.fixture(scope="module")
def graphs(binary, tmp_path_factory) -> list:
    """_RUNS fresh parses; the fabrication being deterministic, every run
    must agree (an unstable edge is a different defect, not this one)."""
    outs = []
    for i in range(_RUNS):
        tree = _make_tree(tmp_path_factory.mktemp("issue781_tree%d" % i))
        outs.append(_parse(binary, tree))
    for other in outs[1:]:
        assert {
            k: sorted(v) for k, v in outs[0].items()
        } == {k: sorted(v) for k, v in other.items()}, (
            "the fixture's edges must be DETERMINISTIC across parser "
            "processes — an unstable edge here is a different defect "
            "(the #777 class), not the #781 fabrication")
    return outs


def test_the_direct_call_path_records_no_cross_package_edge(graphs):
    """S1: `b.view()` where view is a FIELD of the caller's own same-named
    type and a METHOD of another package's same-named type. The base
    fabricates z/backend.go:backend.view through resolveMethodCall's
    cross-package fall-through; the fix records NO edge (the field call is
    an indirect call the model abstains from -- it is never z's method).
    The fix lives in go_parser/callgraph.go (resolveMethodCall's tail) --
    the file named by _PROD_HUNK."""
    assert _PROD_HUNK == "go_parser/callgraph.go"
    for g in graphs:
        targets = g.get(_DIRECT_CALLER, [])
        assert _FABRICATED not in targets, (
            f"the direct call path fabricated a cross-package edge: "
            f"{_DIRECT_CALLER} -> {_FABRICATED} — the caller's own package "
            f"declares `view` as a FIELD, so the resolution is a bare-name "
            f"collision, never z's method")


def test_the_method_value_alias_path_records_no_cross_package_edge(graphs):
    """S2: `f := b.view; f()` — the method-value-then-call shape. The alias
    arm builds the same IsMethod CallInfo (the receiver's bare type) and
    routes into resolveMethodCall, so the base fabricates the same z edge;
    the fix records NO edge on this path too.
    The fix lives in go_parser/callgraph.go (resolveMethodCall's tail) --
    the file named by _PROD_HUNK."""
    assert _PROD_HUNK == "go_parser/callgraph.go"
    for g in graphs:
        targets = g.get(_ALIAS_CALLER, [])
        assert _FABRICATED not in targets, (
            f"the method-value alias path fabricated a cross-package edge: "
            f"{_ALIAS_CALLER} -> {_FABRICATED} — the bound method value "
            f"resolves through the caller's own package's FIELD, never "
            f"z's method")


def test_the_same_package_method_edge_survives(graphs):
    """S3: the CONTROL — the caller's OWN package's method
    (`b.realMethod()`) must still resolve on every run, at the base AND
    after the fix. If it does not, the gate is over-broad and S1/S2 carry
    no information (the fixture-validity lock)."""
    for g in graphs:
        targets = g.get(_DIRECT_CALLER, [])
        assert _SAME_PKG_METHOD in targets, (
            f"the same-package method edge must SURVIVE the gate: "
            f"{_DIRECT_CALLER} -> {_SAME_PKG_METHOD} missing from {targets}")


def test_the_other_packages_internal_edge_survives(graphs):
    """S4: the CONTROL — z's INTERNAL edge (z/caller.go:caller ->
    z/backend.go:view, the same-package resolution inside z) must survive
    on every run, at the base AND after the fix. The gate rejects
    CROSS-package winners only; if z's own edge dies, the gate inverts the
    caller-package test."""
    for g in graphs:
        targets = g.get(_Z_INTERNAL_CALLER, [])
        assert _FABRICATED in targets, (
            f"z's internal same-package edge must SURVIVE the gate: "
            f"{_Z_INTERNAL_CALLER} -> {_FABRICATED} missing from {targets}")
