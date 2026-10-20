"""#746 end-to-end regression: the Go call graph must record an edge when a
method value is held in a STRUCT-LITERAL FIELD or a NAMED-FUNC-TYPE container.

At the base (`parsers/go/go_parser/callgraph.go`) three omissions conspired:
`extractCalls`' `ast.Inspect` walk had no `*ast.CompositeLit` case, so a
composite literal in a function BODY was never read for function references;
`compositeFuncTargets` (:208-228) reads only `*ast.Ident`, so a method value
(`b.pathLoginUpdate`, a `SelectorExpr`) was dropped where the walk did reach a
literal; and `funcValuedElementType` (:235-249) requires a SYNTACTIC
`*ast.FuncType` element type, so `map[logical.Operation]framework.OperationFunc{...}`
-- a NAMED func type -- made the whole literal abstain.

The effect is the dominant Vault/OpenBao handler-registration idiom recording
no edge: the path-constructor is kept and every handler it registers prunes as
an orphan. #746 measured it on a committed openbao scan -- of 318
`framework.Path` Callback handlers, **253 of the 254 pruned had no recorded
caller**, including the AppRole login handler
(`builtin/credential/approle/path_login.go:backend.pathLoginUpdate`, an
unauthenticated network surface).

Why this file exists ALONGSIDE the Go unit tests in
`parsers/go/go_parser/callgraph_methodvalue_test.go`: CI never runs `go test`
against the go_parser module. `.github/workflows/CI.yaml` runs `go test ./...`
only in `apps/openant-cli` and `pytest tests/test_go_cli.py`; the go_parser
module is only `go build`-ed (the "Build go_parser binary" step of the
python-tests job). `pytest tests/` IS run by that same job, after the build --
so this is the witness that actually guards the regression in CI.

Shapes:

  B  -- the issue's OWN published fixture (its `n1_probe.py`), verbatim in
        shape: a struct-literal `Callback` field, a named-func-type map value,
        the #299 container-dispatch control, and the direct-call control.
        Red at the base on the two method-value edges; the two controls are
        green on BOTH sides, so a null result is meaningful rather than a
        broken fixture (#299's comment 1 withdrew an entire table row for
        exactly this reason: "A 'no callers' result on an unextracted function
        is meaningless").
  D  -- the PRECISION control: the resolution is the type check, and the
        cross-package package gate (fable r1 F1(a)) kills the bare-name
        collision class. `cfg.Timeout` / `cfg.Name` are plain STRUCT FIELDS
        whose names also belong to package-level FUNCTIONS. A fix that resolved composite-literal
        selectors by bare name would fabricate an edge here. #299's 2026-08-22
        ruling is binding: "a fabricated edge is not a safe over-seed: it
        invents reachability into a function that is never invoked." Green on
        BOTH sides.

The parser binary is built into `tmp_path`, NEVER into the package tree:
issue #686 records that the in-tree rebuild is lockless on the Python side, so
a test that rebuilt in place would race any concurrent scan.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[3]
_GO_PARSER_DIR = _CORE_ROOT / "parsers" / "go" / "go_parser"


@pytest.fixture(scope="module")
def go_parser_binary(tmp_path_factory):
    if shutil.which("go") is None:
        pytest.skip("Go toolchain unavailable")
    out = tmp_path_factory.mktemp("issue746_bin") / "go_parser"
    proc = subprocess.run(
        ["go", "build", "-o", str(out), "."],
        cwd=str(_GO_PARSER_DIR), capture_output=True, text=True,
    )
    if proc.returncode != 0:
        pytest.skip(f"go build failed (env):\n{proc.stderr[-2000:]}")
    # Windows: `go build -o <extensionless>` appends .exe to the OUTPUT FILE,
    # so the executable lives at out.exe while `out` is absent -- resolve to
    # whichever exists, else every lookup reads as "no edge" and the CONTROLS
    # fail (observed on the #747 cycle's windows-latest leg).
    if not out.exists() and (out.parent / (out.name + ".exe")).exists():
        out = out.parent / (out.name + ".exe")
    # A SUCCESSFUL build that produced no executable is a broken fixture, not
    # an environment gap -- this file is CI's ONLY regression guard for #746
    # (go test never runs against this module in CI), so it must fail LOUDLY,
    # never silently skip.
    assert out.exists(), (
        f"go build rc=0 but no executable at {out} -- the fixture is broken, "
        "not the environment")
    return out


def _norm_slashes(s: str) -> str:
    """funcIDs are repo-relative paths, and on Windows `filepath.Rel` emits
    them backslash-separated and the parser keeps them that way. This witness
    speaks forward slashes (the issue's own published probe and every expected
    value here), so EVERY graph KEY, target and reverse-caller is normalised
    before comparison. Both halves are load-bearing: the #747 cycle's first
    push went CI-red on windows-latest normalising only the VALUES, which left
    the forward map keyed on backslashes and every lookup empty."""
    return s.replace("\\", "/")


# The issue's own fixture (n1_probe.py), shape-for-shape.
_FIXTURE_B = """package fx

type Request struct{ Data map[string]string }
type Response struct{}
type OperationFunc func(*Request) (*Response, error)
type PathOperation struct{ Callback OperationFunc }
type Path struct {
    Operations map[string]*PathOperation
    Callbacks  map[string]OperationFunc
}
type backend struct{}
func (b *backend) pathLogin() *Path {
    return &Path{
        Operations: map[string]*PathOperation{
            "update": &PathOperation{Callback: b.pathLoginUpdate},
        },
        Callbacks: map[string]OperationFunc{
            "read": b.pathLoginRead,
        },
    }
}
func (b *backend) pathLoginUpdate(req *Request) (*Response, error) { return nil, nil }
func (b *backend) pathLoginRead(req *Request) (*Response, error)   { return nil, nil }
var tbl = map[string]func(){"a": handlerA}
func handlerA() {}
func dispatch(k string) { tbl[k]() }
func control(b *backend) { b.pathLoginDirect(nil) }
func (b *backend) pathLoginDirect(req *Request) (*Response, error) { return nil, nil }
"""

# The precision control: struct FIELD reads whose names collide with
# package-level FUNCTIONS.
_FIXTURE_D = """package fx

type Conf struct {
    Timeout int
    Name    string
}
type Out struct {
    T int
    N string
}
func Timeout() int { return 7 }
func Name() string { return "x" }
func build(cfg *Conf) *Out { return &Out{T: cfg.Timeout, N: cfg.Name} }
"""


def _graph(binary: Path, root: Path) -> dict:
    """Run the real parser binary end-to-end and return both graph maps with
    every key, target and reverse-caller slash-normalised."""
    proc = subprocess.run([str(binary), "callgraph", str(root)],
                          capture_output=True, text=True)
    assert proc.returncode == 0, f"parser rc={proc.returncode}: {proc.stderr[-2000:]}"
    assert "failed to parse" not in proc.stderr, (
        "the FIXTURE is broken, not the parser -- it could not be parsed:\n"
        + proc.stderr[-2000:])
    raw = json.loads(proc.stdout)
    fwd = {_norm_slashes(k): sorted(_norm_slashes(t) for t in (v or []))
           for k, v in (raw.get("call_graph") or {}).items()}
    rev = {_norm_slashes(k): sorted(_norm_slashes(c) for c in (v or []))
           for k, v in (raw.get("reverse_call_graph") or {}).items()}
    return {"forward": fwd, "reverse": rev}


def _tree(root: Path, name: str, src: str) -> Path:
    """The fixture file lives in a SUBDIRECTORY on purpose. funcIDs are
    repo-relative paths, so a flat `b.go` at the tree root yields funcIDs
    with NO path separator -- and then _norm_slashes below is a silent
    no-op and the Windows class this witness claims to cover is never
    exercised. `builtin/approle/b.go` mirrors the real OpenBao layout
    (`builtin/credential/approle/path_login.go`) AND makes the
    normalisation load-bearing: on Windows these keys arrive as
    `builtin\\approle\\b.go:...`."""
    (root / "go.mod").write_text("module fx746\n\ngo 1.21\n")
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(src)
    return root


@pytest.fixture(scope="module")
def graph_b(go_parser_binary, tmp_path_factory):
    return _graph(go_parser_binary,
                  _tree(tmp_path_factory.mktemp("issue746_b"), "builtin/approle/b.go", _FIXTURE_B))


@pytest.fixture(scope="module")
def graph_d(go_parser_binary, tmp_path_factory):
    return _graph(go_parser_binary,
                  _tree(tmp_path_factory.mktemp("issue746_d"), "internal/conf/c.go", _FIXTURE_D))


def test_the_controls_record_their_edges_so_the_rest_means_something(graph_b):
    """Both edges #746 reports as ALREADY WORKING must work here. If either
    fails, the fixture or the harness is broken and every assertion below is
    uninformative -- asserted, never skipped."""
    fwd = graph_b["forward"]
    assert "builtin/approle/b.go:handlerA" in fwd.get("builtin/approle/b.go:dispatch", []), (
        "the #299 container-dispatch control edge is MISSING "
        f"(dispatch -> handlerA); out-edges={fwd.get('builtin/approle/b.go:dispatch')}")
    assert "builtin/approle/b.go:backend.pathLoginDirect" in fwd.get("builtin/approle/b.go:control", []), (
        "the direct-call control edge is MISSING (control -> pathLoginDirect); "
        f"out-edges={fwd.get('builtin/approle/b.go:control')}")


def test_the_struct_literal_callback_field_records_its_edge(graph_b):
    """#746 mechanism 1 + 3: &PathOperation{Callback: b.pathLoginUpdate}.
    This is the shape the AppRole login handler is registered with."""
    fwd = graph_b["forward"]
    assert "builtin/approle/b.go:backend.pathLoginUpdate" in fwd.get("builtin/approle/b.go:backend.pathLogin", []), (
        "the struct-literal Callback field edge is NOT recorded "
        f"(pathLogin -> pathLoginUpdate); out-edges={fwd.get('builtin/approle/b.go:backend.pathLogin')}")


def test_the_named_func_type_container_records_its_edge(graph_b):
    """#746 mechanism 2: map[string]OperationFunc{"read": b.pathLoginRead} --
    a NAMED func element type, on which funcValuedElementType abstains."""
    fwd = graph_b["forward"]
    assert "builtin/approle/b.go:backend.pathLoginRead" in fwd.get("builtin/approle/b.go:backend.pathLogin", []), (
        "the named-func-type map edge is NOT recorded "
        f"(pathLogin -> pathLoginRead); out-edges={fwd.get('builtin/approle/b.go:backend.pathLogin')}")


def test_each_handler_has_a_recorded_caller_in_the_transpose(graph_b):
    """The reachability consumer builds its forward graph FROM the reverse map
    (`utilities/agentic_enhancer/reachability_analyzer.py`), so a forward edge
    emitted without its transpose leaves both graph files individually
    plausible while the edge is silently lost downstream. `callers: []` is
    exactly what #746 measured on 253 of 254 pruned handlers."""
    rev = graph_b["reverse"]
    for handler in ("builtin/approle/b.go:backend.pathLoginUpdate", "builtin/approle/b.go:backend.pathLoginRead"):
        assert "builtin/approle/b.go:backend.pathLogin" in rev.get(handler, []), (
            f"{handler} has NO recorded caller in reverse_call_graph "
            f"(callers={rev.get(handler)}) -- it still prunes as an orphan")


def test_the_two_graph_maps_are_exact_transposes(graph_b):
    """C5-graph, at L1 and on the real binary's own output: the transpose is
    WRITTEN by the parser, not derived at read time, so asymmetry is a real
    shipping defect and not a theoretical one."""
    fwd, rev = graph_b["forward"], graph_b["reverse"]
    from_forward = sorted((k, t) for k, ts in fwd.items() for t in ts)
    from_reverse = sorted((c, k) for k, cs in rev.items() for c in cs)
    assert from_forward == from_reverse, (
        "call_graph and reverse_call_graph are not transposes.\n"
        f"only in forward: {sorted(set(from_forward) - set(from_reverse))}\n"
        f"only in reverse: {sorted(set(from_reverse) - set(from_forward))}")


def test_a_struct_field_read_in_a_composite_literal_fabricates_no_edge(graph_d):
    """THE PRECISION CONTROL -- green on both sides. `cfg.Timeout` and
    `cfg.Name` are struct FIELDS; package-level funcs `Timeout` and `Name`
    exist in the same file. Per #299's 2026-08-22 ruling a fabricated edge is
    NOT a reachability-safe over-seed, so resolving a composite-literal
    selector by bare name is forbidden -- it must resolve only against the
    receiver's static type's method set."""
    fwd, rev = graph_d["forward"], graph_d["reverse"]
    for decoy in ("internal/conf/c.go:Timeout", "internal/conf/c.go:Name"):
        assert decoy not in fwd.get("internal/conf/c.go:build", []), (
            f"FABRICATED EDGE build -> {decoy}: a struct FIELD read was "
            f"resolved to a same-named function; out-edges={fwd.get('internal/conf/c.go:build')}")
        assert not rev.get(decoy), (
            f"FABRICATED EDGE in the transpose: {decoy} callers={rev.get(decoy)}")
