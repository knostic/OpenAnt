"""#777 end-to-end regression: an UNQUALIFIED Go call's same-package target
must resolve deterministically across parser processes.

At the base (`parsers/go/go_parser/callgraph.go`, resolveSimpleCall's
Priority 2) the same-package scan returned the FIRST match over
`c.functionsByFile`'s map iteration -- and Go randomises map order per
process. A `//go:build`-tagged pair (two same-named functions in two
same-dir files: `procgroup_unix.go` / `procgroup_other.go`) therefore
flipped its edge target on every fresh parse: the build-constraint-correct
target is decided by build tags the parser never reads, but the EDGE must
at least be STABLE -- the reachability consumer sees a different graph per
parse otherwise. The issue's corpus control measured all 8 unstable edges
on OpenAnt's own CLI corpus in this one shape.

The fix (#747's tie-break class): collect the same-dir candidates and
break the tie on the lexicographically smallest funcID -- a strict total
order, so the edge is stable across runs.

Why this file exists ALONGSIDE the Go module: CI never runs `go test`
against the go_parser module (the `go test ./...` runs only in
apps/openant-cli; the go_parser module is only `go build`-ed). pytest
tests/ IS run, after the build -- so this is the witness that actually
guards the regression in CI. The drive follows the #747 witness
convention — the package-qualified sibling drive (riding open PR #778)
has the same shape.

Shapes:

  S1 -- the tagged pair: the caller plus TWO same-named functions in two
        same-dir files. STRUCTURALLY the base emits ONE of the two targets
        per process and WHICH one is a coin flip, so N fresh processes must
        show the flip (>= 2 distinct) at the base and EXACTLY ONE — the
        lexicographically smallest funcID — after the fix.
  S2 -- the CONTROL: a uniquely-named same-dir callee, which must resolve
        on every run at the base AND after the fix. If it does not, the
        fixture is broken and S1 carries no information (the #747 probe's
        own lesson: its earlier draft emitted unparsable Go and every shape
        read as "no edge" until the control caught it).
  S3 -- Priority 1 (the same-file path, untouched by the fix): a caller
        whose OWN file defines the same-named function must resolve to the
        same-file target on every run, at the base AND after the fix.
  S4 -- Priority 3 (the unique cross-dir name, untouched by the fix): a
        name with exactly one repo-global definition must resolve to it on
        every run, at the base AND after the fix.

The parser binary is built into `tmp_path`, NEVER into the package tree:
issue #686 records that the in-tree rebuild is lockless on the Python
side, so a test that rebuilt in place would race any concurrent scan.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[3]
_GO_PARSER_DIR = _CORE_ROOT / "parsers" / "go" / "go_parser"

# Fresh processes per shape. Go randomises map iteration per process, so the
# base's flip is sampled rather than fixed. The MEASURED distribution on
# THIS fixture: a 400-run base battery gave 310 procgroup_other / 90
# procgroup_unix, an 80-run battery 68/12 (p ~0.78-0.85; the two-stage map
# model — buildIndexes fills functionsByFile from a randomised
# analyzer.Functions, then the resolver iterates that map — gives ~0.80), so
# the declared winner is the base's MAJORITY outcome. The hide event is ALL
# N runs picking the winner: P = p**N — an EMPIRICAL, independence-dependent
# bound, never a guaranteed RED probability. 60 runs put the hide chance
# under the conservative upper bound ~0.03% (0.875**60; ~1e-6 at the
# measured 0.80**60); 40 runs would have been ~0.5% at the 0.875 bound.
_RUNS = 60

_CALLER = "caller.go:doWork"
_CALLEE = "setProcGroupKill"
# The tagged pair, by build intent; the parser never reads the tags, but the
# FIXTURE mirrors the corpus shape (procgroup_unix.go / procgroup_other.go).
_UNIX_TWIN = "procgroup_unix.go:setProcGroupKill"
_OTHER_TWIN = "procgroup_other.go:setProcGroupKill"
# The fix's winner: the lexicographically smallest funcID of the pair.
_WINNER = _OTHER_TWIN


def _go_literal(value: str) -> str:
    """A Go string literal. json.dumps, never %r: Python's %r emits single
    quotes, which Go reads as a rune literal, and the file then does not
    parse at all."""
    return json.dumps(value)


@pytest.fixture(scope="module")
def go_parser_binary(tmp_path_factory):
    if shutil.which("go") is None:
        pytest.skip("Go toolchain unavailable")
    out = tmp_path_factory.mktemp("issue777_bin") / "go_parser"
    proc = subprocess.run(
        ["go", "build", "-o", str(out), "."],
        cwd=str(_GO_PARSER_DIR), capture_output=True, text=True,
    )
    if proc.returncode != 0:
        # The compile-broken-prod-tree case is owned by CI's separate
        # go-build step (this suite runs after the build); this skip covers
        # only a local environment that cannot build the fixture binary.
        pytest.skip(f"go build failed (env; a broken prod tree is CI's go-build step's case, not this skip's):\n{proc.stderr[-2000:]}")
    # Windows: the observed #747-witness leg — resolve .exe if the build
    # produced one (the fixture-build is the #686 lockless rule: never the tree)
    if not out.exists() and (out.parent / (out.name + ".exe")).exists():
        out = out.parent / (out.name + ".exe")
    assert out.exists(), (
        f"go build rc=0 but no executable at {out} — the fixture is broken, "
        "not the environment")
    return out


def _norm_slashes(s: str) -> str:
    """funcIDs are repo-relative paths and on Windows `filepath.Rel` emits
    them backslash-separated (the parser's own callgraph.go keeps them so);
    every graph key and target is normalised before comparison."""
    return s.replace("\\", "/")


def _write_tagged_pair(root: Path) -> None:
    (root / "procgroup_unix.go").write_text(
        "//go:build unix\n\npackage main\n\n"
        "func setProcGroupKill() {}\n", encoding="utf-8")
    (root / "procgroup_other.go").write_text(
        "//go:build !unix\n\npackage main\n\n"
        "func setProcGroupKill() {}\n", encoding="utf-8")


def _make_tree(tmp: Path, shape: str) -> Path:
    """One flat main package. S1: the caller + the tagged pair. S2: the
    caller + a uniquely-named same-dir callee. S3: the caller defines its
    own same-named function (the same-file priority). S4: the caller calls
    a name defined exactly once, in ANOTHER directory."""
    root = tmp / shape
    root.mkdir(parents=True)
    (root / "go.mod").write_text("module fx777\n\ngo 1.21\n", encoding="utf-8")
    if shape == "S1":
        (root / "caller.go").write_text(
            "package main\n\nfunc doWork() { setProcGroupKill() }\n",
            encoding="utf-8")
        _write_tagged_pair(root)
    elif shape == "S2":
        (root / "caller.go").write_text(
            "package main\n\nfunc doWork() { initUnique() }\n", encoding="utf-8")
        (root / "unique.go").write_text(
            "package main\n\nfunc initUnique() {}\n", encoding="utf-8")
    elif shape == "S3":
        # the same-file priority (Priority 1) must beat the same-dir twins:
        # the caller lives in ITS OWN file (zcaller.go), so a Priority-1
        # regression would resolve to the twin instead (r1-F1: the
        # earlier fixture put the target in caller.go itself, which the
        # min-scan answers identically — no discrimination)
        (root / "zcaller.go").write_text(
            "package main\n\nfunc doWork() { setProcGroupKill() }\n\n"
            "func setProcGroupKill() {}\n", encoding="utf-8")
        _write_tagged_pair(root)
    elif shape == "S4":
        (root / "caller.go").write_text(
            "package main\n\nfunc doWork() { globalHelper() }\n",
            encoding="utf-8")
        other = root / "other"
        other.mkdir()
        (other / "helper.go").write_text(
            "package other\n\nfunc globalHelper() {}\n", encoding="utf-8")
    return root


def _resolved_callee(binary: Path, tree: Path, caller: str, callee: str) -> str:
    """The funcID recorded as `caller`'s callee, read out of BOTH graph maps
    the Python consumers read, cross-checked. Returns "" when no edge."""
    proc = subprocess.run([str(binary), "callgraph", str(tree)],
                          capture_output=True, text=True)
    assert proc.returncode == 0, (
        f"parser rc={proc.returncode}: {proc.stderr[-2000:]}")
    assert "failed to parse" not in proc.stderr, (
        "the FIXTURE is broken, not the parser -- it could not be parsed:\n"
        + proc.stderr[-2000:])
    graph = json.loads(proc.stdout)
    _caller = _norm_slashes(caller)
    _fwd = {_norm_slashes(k): v for k, v in (graph.get("call_graph") or {}).items()}
    forward = sorted(_norm_slashes(t) for t in _fwd.get(_caller, []) or []
                     if _norm_slashes(t).endswith(":" + callee))
    reverse = sorted(_norm_slashes(fid) for fid, callers in
                     (graph.get("reverse_call_graph") or {}).items()
                     if _caller in [_norm_slashes(c) for c in (callers or [])]
                     and _norm_slashes(fid).endswith(":" + callee))
    # The parser writes reverse_call_graph as the transpose of call_graph —
    # a forward edge without its transpose is silently lost downstream.
    assert forward == reverse, (
        f"forward/reverse asymmetry for {caller}: {forward} vs {reverse}")
    assert len(forward) <= 1, f"more than one {callee} callee recorded: {forward}"
    return forward[0] if forward else ""


@pytest.fixture(scope="module")
def outcomes(go_parser_binary, tmp_path_factory):
    """Every shape's resolved callee, once per fresh parser process."""
    shapes = {
        "S1": (_CALLER, _CALLEE),
        "S2": ("caller.go:doWork", "initUnique"),
        "S3": ("zcaller.go:doWork", _CALLEE),
        "S4": ("caller.go:doWork", "globalHelper"),
    }
    out = {}
    for tag, (caller, callee) in shapes.items():
        tree = _make_tree(tmp_path_factory.mktemp("issue777_" + tag), tag)
        out[tag] = [_resolved_callee(go_parser_binary, tree, caller, callee)
                    for _ in range(_RUNS)]
    return out


def test_the_control_resolves_so_the_shape_means_something(outcomes):
    """S2: a uniquely-named same-dir callee resolves on every run — if this
    fails the fixture is broken and S1 is uninformative."""
    got = outcomes["S2"]
    assert got == ["unique.go:initUnique"] * _RUNS, (
        f"the uniquely-named same-dir callee must resolve on every run; got {got}")


def test_the_same_file_priority_still_wins(outcomes):
    """S3: the same-file definition (Priority 1, untouched by the fix)
    resolves on every run — the fix must not have broken it."""
    got = outcomes["S3"]
    assert got == ["zcaller.go:setProcGroupKill"] * _RUNS, (
        f"the same-file priority must resolve to the same-file target on "
        f"every run; got {got}")


def test_the_unique_cross_dir_name_still_resolves(outcomes):
    """S4: a repo-global unique name (Priority 3, untouched by the fix)
    resolves on every run."""
    got = outcomes["S4"]
    assert got == ["other/helper.go:globalHelper"] * _RUNS, (
        f"the unique cross-dir name must resolve on every run; got {got}")
    # the data-read route (the #698 class: a Go hunk cannot be a Python
    # import): the S1 witness's file names go_parser/callgraph.go, and the
    # C4 hunk-revert row for that file (the S1 battery failing at the base
    # state) is the load-bearing proof
    assert _PROD_HUNK == "go_parser/callgraph.go"


# The prod file under test (the #698 data-read route: a Go file cannot be a
# Python import; the C4 hunk-revert row for this file — reverting the
# Priority-2 tie-break restores the flip and fails S1 — is the
# load-bearing proof).
_PROD_HUNK = "go_parser/callgraph.go"


def test_the_build_tagged_pair_edge_is_stable_across_processes(outcomes):
    """S1: the tagged pair's edge target. At the base the map iteration
    coin-flips between the twins (>= 2 distinct targets across the fresh
    processes — the #777 flip, the issue's own corpus shape); after the fix
    EVERY process resolves to the lexicographically smallest funcID — the
    strict total order that makes the graph stable across parses.
    The fix lives in go_parser/callgraph.go (resolveSimpleCall's
    Priority 2) — the file named by _PROD_HUNK."""
    got = outcomes["S1"]
    assert got == [_WINNER] * _RUNS, (
        f"the tagged pair's edge must be STABLE: every fresh parser process "
        f"resolves to {_WINNER} (the lexicographically smallest funcID, the "
        f"#747 tie-break class); got {sorted(set(got))} across {_RUNS} runs "
        f"— the base's map-iteration coin flip (the #777 flip)")
