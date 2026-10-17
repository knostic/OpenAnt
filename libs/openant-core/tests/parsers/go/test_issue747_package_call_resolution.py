"""#747 end-to-end regression: a cross-package Go call must resolve to the
package the file actually IMPORTED, deterministically.

At the base (`parsers/go/go_parser/callgraph.go:874-883`) `resolvePackageCall`
matched the import path's LAST COMPONENT against the candidate's directory
basename and returned the FIRST match over `c.functionsByName[funcName]` -- a
slice appended under Go map iteration in `buildIndexes` (:138-140). So a call
to `config.LoadConfig()` resolved to whichever same-basename sibling package
came first in map order: the wrong package, and a *different* wrong package
across parses of the identical tree.

Why this file exists ALONGSIDE the Go unit tests in
`parsers/go/go_parser/callgraph_packagecall_test.go`: at this commit CI never
runs `go test` against the go_parser module. `.github/workflows/test.yaml`
runs `go test ./...` only in `apps/openant-cli`; the go_parser module is only
`go build`-ed (the "Build go_parser binary" step of the python-tests job).
`pytest tests/` IS run by that same job, after the build -- so this is the
witness that actually guards the regression in CI.

Shape, after the issue's own published probe:

  S1 -- the import names a package the tree does not define, and two
        same-basename siblings do. STRUCTURALLY red at the base: whichever
        sibling wins is a wrong-package edge, so every outcome is wrong.
  S2 -- the import names a package that IS present, beside two same-basename
        siblings. Red at the base PROBABILISTICALLY: the issue reports the
        imported package chosen on 2 of 12 runs, and this repo's base probe
        measured 1 of 12 across 3 distinct outcomes, so the base passes a
        "correct on every run" assertion with probability about 12**-N.
  S3 -- the CONTROL: a uniquely-named package, which must resolve on every
        run at the base AND after the fix. If it does not, the fixture is
        broken and S1/S2 carry no information -- an earlier draft of the
        companion probe emitted Python-style single-quoted Go string literals,
        every file failed to parse, and all three shapes reported "no edge".
        The control is what caught it, so it is asserted, never skipped.

The parser binary is built into `tmp_path`, NEVER into the package tree:
issue #686 records that the in-tree rebuild is lockless on the Python side,
so a test that rebuilt in place would race any concurrent scan.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[3]
_GO_PARSER_DIR = _CORE_ROOT / "parsers" / "go" / "go_parser"

# Fresh processes per shape. Go randomises map iteration per process, so the
# base's wrong answer is sampled rather than fixed; 8 runs put the base's
# chance of passing S2 at roughly 12**-8.
_RUNS = 8

_CALLER = "cmd/main.go:main"
_CALLEE = "LoadConfig"


def _go_literal(value: str) -> str:
    """A Go string literal. json.dumps, never %r: Python's %r emits single
    quotes, which Go reads as a rune literal, and the file then does not
    parse at all."""
    return json.dumps(value)


@pytest.fixture(scope="module")
def go_parser_binary(tmp_path_factory):
    if shutil.which("go") is None:
        pytest.skip("Go toolchain unavailable")
    out = tmp_path_factory.mktemp("issue747_bin") / "go_parser"
    proc = subprocess.run(
        ["go", "build", "-o", str(out), "."],
        cwd=str(_GO_PARSER_DIR), capture_output=True, text=True,
    )
    if proc.returncode != 0:
        pytest.skip(f"go build failed (env):\n{proc.stderr[-2000:]}")
    # Windows: `go build -o <extensionless>` appends .exe to the OUTPUT FILE,
    # so the executable lives at out.exe while `out` is absent — resolve to
    # whichever exists, else every shape reads as "no edge" and the CONTROL
    # fails (observed on the windows-latest CI leg, run 38103904220).
    if not out.exists() and (out.parent / (out.name + ".exe")).exists():
        out = out.parent / (out.name + ".exe")
    # a SUCCESSFUL build that produced no executable is a broken fixture,
    # not an environment gap — this file is CI's ONLY regression guard for
    # #747 (go test never runs against this module in CI), so it must fail
    # LOUDLY, never silently skip (fable r5 F2).
    assert out.exists(), (
        f"go build rc=0 but no executable at {out} — the fixture is broken, "
        "not the environment")
    return out


def _make_tree(root: Path, package_dirs, import_path: str) -> Path:
    """A module with one `cmd/main.go` importing `import_path` and calling
    `config.LoadConfig()`, plus a `LoadConfig` in each of `package_dirs`."""
    (root / "go.mod").write_text("module fx747\n\ngo 1.21\n")
    for rel in package_dirs:
        d = root / rel
        d.mkdir(parents=True, exist_ok=True)
        (d / "config.go").write_text(
            "package {}\n\nfunc LoadConfig() string {{ return {} }}\n".format(
                Path(rel).name, _go_literal(rel))
        )
    cmd = root / "cmd"
    cmd.mkdir(parents=True, exist_ok=True)
    (cmd / "main.go").write_text(
        "package main\n\nimport {}\n\nfunc main() {{ _ = config.LoadConfig() }}\n".format(
            _go_literal(import_path))
    )
    return root


def _norm_slashes(s: str) -> str:
    """funcIDs are repo-relative paths, and on Windows `filepath.Rel` emits
    them backslash-separated (the parser's own callgraph.go:1111-1113 says
    so and keeps them). This witness speaks forward slashes (the issue's own
    published probe and every expected value here), so EVERY graph key,
    target and reverse-caller is normalised before comparison — the first
    push went CI-RED on windows-latest reading every lookup as empty."""
    return s.replace("\\", "/")


def _resolved_callee(binary: Path, tree: Path) -> str:
    """The funcID recorded as `cmd/main.go:main`'s LoadConfig callee, read
    out of BOTH graph maps the Python consumers read, cross-checked.

    Returns "" when no edge was recorded.
    """
    proc = subprocess.run([str(binary), "callgraph", str(tree)],
                          capture_output=True, text=True)
    assert proc.returncode == 0, f"parser rc={proc.returncode}: {proc.stderr[-2000:]}"
    assert "failed to parse" not in proc.stderr, (
        "the FIXTURE is broken, not the parser -- it could not be parsed:\n"
        + proc.stderr[-2000:])
    graph = json.loads(proc.stdout)

    _caller = _norm_slashes(_CALLER)
    # fable r6 F1: the map KEY itself is backslash-separated on Windows —
    # normalise the KEYS before the lookup, or forward=[] while the
    # normalised reverse finds the callee and the file's own
    # forward==reverse assert fires (an asymmetry red, not the empty one).
    _fwd = {_norm_slashes(k): v for k, v in
            (graph.get("call_graph") or {}).items()}
    forward = sorted(_norm_slashes(t) for t in _fwd.get(_caller, []) or []
                     if _norm_slashes(t).endswith(":" + _CALLEE))
    reverse = sorted(_norm_slashes(fid) for fid, callers in (graph.get("reverse_call_graph") or {}).items()
                     if _caller in [_norm_slashes(c) for c in (callers or [])]
                     and _norm_slashes(fid).endswith(":" + _CALLEE))
    # Each parser writes reverse_call_graph as the transpose of call_graph, and
    # the reachability consumer builds its forward graph FROM the reverse map --
    # a forward edge emitted without its transpose leaves both files
    # individually plausible while the edge is silently lost downstream.
    assert forward == reverse, (
        f"forward/reverse asymmetry for {_CALLER}: {forward} vs {reverse}")
    assert len(forward) <= 1, f"more than one {_CALLEE} callee recorded: {forward}"
    return forward[0] if forward else ""


@pytest.fixture(scope="module")
def outcomes(go_parser_binary, tmp_path_factory):
    """Every shape's resolved callee, once per fresh parser process."""
    shapes = {
        "S1": (["a/config", "b/config"], "fx747/z/config"),
        "S2": (["a/config", "b/config", "z/config"], "fx747/z/config"),
        "S3": (["uniq/config"], "fx747/uniq/config"),
    }
    out = {}
    for tag, (dirs, import_path) in shapes.items():
        tree = _make_tree(tmp_path_factory.mktemp("issue747_" + tag), dirs, import_path)
        out[tag] = [_resolved_callee(go_parser_binary, tree) for _ in range(_RUNS)]
    return out


def test_the_control_resolves_so_the_other_shapes_mean_something(outcomes):
    got = outcomes["S3"]
    expected = "uniq/config/config.go:LoadConfig"
    assert got == [expected] * _RUNS, (
        f"the uniquely-named package must resolve on every run; got {got}. "
        "If this fails the fixture is broken and S1/S2 are uninformative."
    )


def test_a_same_basename_sibling_is_never_the_imported_package(outcomes):
    """STRUCTURAL: the import is fx747/z/config, which this tree does not
    define, so the only correct answer is no edge. The base matched the
    basename `config` and emitted an edge into a/config or b/config on every
    run -- a wrong-package edge, which is a fabrication rather than a
    reachability-safe over-seed."""
    got = outcomes["S1"]
    wrong = sorted({g for g in got if g})
    assert wrong == [], (
        "the import names fx747/z/config, which this tree does not define, so "
        f"no edge may be recorded; {len(wrong)} distinct sibling target(s) were: "
        f"{wrong} (outcomes across {_RUNS} runs: {got})"
    )


def test_the_imported_package_wins_over_same_basename_siblings_every_run(outcomes):
    """Correctness AND determinism in one assertion: the imported package, on
    every run. The base measured 1 of 12 correct across 3 distinct outcomes."""
    got = outcomes["S2"]
    expected = "z/config/config.go:LoadConfig"
    assert got == [expected] * _RUNS, (
        f"expected {expected} on all {_RUNS} runs; got {sorted(set(got))} "
        f"({len(set(got))} distinct outcome(s) over {_RUNS} fresh parser "
        "processes -- a same-basename sibling winning, or the winner varying, "
        "is the #747 defect)"
    )


def test_the_resolution_is_a_single_canonical_value_not_merely_stable(outcomes):
    """The candidate order the base depended on is Go map order. A repair that
    only SORTED the index would still be order-dependent; the shipped repair
    scores every candidate and picks a total maximum, so the value is canonical.
    Asserted here as: one distinct outcome per shape across all runs."""
    distinct = {tag: sorted(set(vals)) for tag, vals in outcomes.items()}
    multi = {tag: vals for tag, vals in distinct.items() if len(vals) > 1}
    assert multi == {}, (
        f"these shapes resolved to more than one value across {_RUNS} fresh "
        f"parser processes: {multi}"
    )



# ---------------------------------------------------------------------------
# #747, second round: the MODULE PATH decides, not the import path's tail.
#
# The first round scored a candidate by how many whole path components of its
# directory matched the TAIL of the import path. That is sound only where the
# module path mirrors the directory layout; the module path itself was never
# read, so three ordinary layouts resolved wrongly or not at all. All three are
# driven here through the real parser binary, which is what CI runs.
# ---------------------------------------------------------------------------

_LAYOUT_SHAPES = {
    # S4 -- one go.mod in a SUBDIRECTORY (a polyglot repo), scanned from the
    # repo root, which is the path the pipeline passes. `backend/` appears in
    # no import path, so a component-suffix score is 0 for the only candidate
    # and the edge vanishes. Measured on OpenAnt's own apps/ scanned one
    # directory up: 1093 edges before the first round, 887 after.
    "S4": {
        "tree": {
            "frontend/app.js": "console.log('not Go');\n",
            "backend/go.mod": "module example.com/svc\n\ngo 1.21\n",
            "backend/cmd/main.go":
                'package main\n\nimport "example.com/svc/internal/store"\n\n'
                "func main() { _ = store.Open() }\n",
            "backend/internal/store/store.go":
                'package store\n\nfunc Open() string { return "store" }\n',
        },
        "caller": "backend/cmd/main.go:main",
        "expected": "backend/internal/store/store.go:Open",
        "why": "the module root is backend/, so example.com/svc/internal/store "
               "IS backend/internal/store",
    },
    # S5 -- a nested module with a MAJOR-VERSION suffix, the shape of the
    # issue's own corpus (openbao: `sdk/go.mod` declares
    # `github.com/openbao/openbao/sdk/v2`, 909 files import it). No directory
    # is ever named `v2`. Measured on openbao at 24fdfe68, root scan:
    # 2,680 correct edges lost to this shape alone. `internal/jsonutil` is the
    # same-basename decoy a basename match emitted instead.
    "S5": {
        "tree": {
            "go.mod": "module fx747mod\n\ngo 1.21\n",
            "sdk/go.mod": "module fx747mod/sdk/v2\n\ngo 1.21\n",
            "cmd/main.go":
                'package main\n\nimport "fx747mod/sdk/v2/helper/jsonutil"\n\n'
                "func main() { _ = jsonutil.Decode() }\n",
            "sdk/helper/jsonutil/j.go":
                'package jsonutil\n\nfunc Decode() string { return "sdk" }\n',
            "internal/jsonutil/decoy.go":
                'package jsonutil\n\nfunc Decode() string { return "decoy" }\n',
        },
        "caller": "cmd/main.go:main",
        "expected": "sdk/helper/jsonutil/j.go:Decode",
        "why": "the /v2 belongs to the module PATH, not to any directory, and "
               "the most specific of the two go.mod files wins",
    },
    # S6 -- the module path's last component is ALSO a directory name. `go
    # list` is the ground truth:
    #   go list -f '{{.ImportPath}} -> {{.Dir}}' example.com/x/app/config
    #   example.com/x/app/config -> <tree>/config
    # A trailing-component score prefers the DEEPER app/config/, which turns a
    # coin flip into a guaranteed wrong edge.
    "S6": {
        "tree": {
            "go.mod": "module example.com/x/app\n\ngo 1.21\n",
            "cmd/main.go":
                'package main\n\nimport "example.com/x/app/config"\n\n'
                "func main() { _ = config.Load() }\n",
            "config/config.go":
                'package config\n\nfunc Load() string { return "root" }\n',
            "app/config/config.go":
                'package config\n\nfunc Load() string { return "app" }\n',
        },
        "caller": "cmd/main.go:main",
        "expected": "config/config.go:Load",
        "why": "the module is example.com/x/app at the root, so "
               ".../app/config is config/, never the deeper app/config/",
    },
    # S7 -- the exactness has to cut both ways, or it is just another guess:
    # when a go.mod DOES cover the import path, a package the tree does not
    # contain is NO edge, not a fall-through to the heuristic. `b/store/` is a
    # genuine component suffix of the import path -- exactly what the
    # heuristic would have offered -- and still the wrong package.
    "S7": {
        "tree": {
            "go.mod": "module example.com/m\n\ngo 1.21\n",
            "cmd/main.go":
                'package main\n\nimport "example.com/m/a/b/store"\n\n'
                "func main() { _ = store.Open() }\n",
            "b/store/s.go":
                'package store\n\nfunc Open() string { return "wrong package" }\n',
        },
        "caller": "cmd/main.go:main",
        "callee_name": "Open",
        "expected": "",
        "why": "example.com/m/a/b/store is a/b/store, which this tree does "
               "not define, so no edge may be recorded",
    },
}


def _resolved_callee_for(binary: Path, tree: Path, caller: str, callee_name: str) -> str:
    """As _resolved_callee, for an arbitrary caller/callee pair."""
    proc = subprocess.run([str(binary), "callgraph", str(tree)],
                          capture_output=True, text=True)
    assert proc.returncode == 0, f"parser rc={proc.returncode}: {proc.stderr[-2000:]}"
    assert "failed to parse" not in proc.stderr, (
        "the FIXTURE is broken, not the parser -- it could not be parsed:\n"
        + proc.stderr[-2000:])
    graph = json.loads(proc.stdout)
    _caller = _norm_slashes(caller)
    # fable r6 F1: same class as _resolved_callee — normalise the map KEYS.
    _fwd = {_norm_slashes(k): v for k, v in
            (graph.get("call_graph") or {}).items()}
    forward = sorted(_norm_slashes(t) for t in _fwd.get(_caller, []) or []
                     if _norm_slashes(t).endswith(":" + callee_name))
    reverse = sorted(_norm_slashes(fid) for fid, callers in (graph.get("reverse_call_graph") or {}).items()
                     if _caller in [_norm_slashes(c) for c in (callers or [])]
                     and _norm_slashes(fid).endswith(":" + callee_name))
    assert forward == reverse, (
        f"forward/reverse asymmetry for {caller}: {forward} vs {reverse}")
    assert len(forward) <= 1, f"more than one {callee_name} callee recorded: {forward}"
    return forward[0] if forward else ""


@pytest.fixture(scope="module")
def layout_outcomes(go_parser_binary, tmp_path_factory):
    """Each module-layout shape's resolved callee, once per fresh process."""
    out = {}
    for tag, shape in _LAYOUT_SHAPES.items():
        root = tmp_path_factory.mktemp("issue747_" + tag)
        for rel, content in shape["tree"].items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        callee_name = shape.get("callee_name") or shape["expected"].split(":")[-1]
        out[tag] = [_resolved_callee_for(go_parser_binary, root, shape["caller"], callee_name)
                    for _ in range(_RUNS)]
    return out


@pytest.mark.parametrize("tag", sorted(_LAYOUT_SHAPES))
def test_the_module_path_decides_which_package_an_import_names(layout_outcomes, tag):
    shape = _LAYOUT_SHAPES[tag]
    got = layout_outcomes[tag]
    expected = shape["expected"]
    assert got == [expected] * _RUNS, (
        f"{tag}: expected {expected!r} on all {_RUNS} runs -- {shape['why']}; got "
        f"{sorted(set(got))} ({len(set(got))} distinct outcome(s)). An empty "
        "string means no edge at all: a cross-package call silently dropped."
    )
