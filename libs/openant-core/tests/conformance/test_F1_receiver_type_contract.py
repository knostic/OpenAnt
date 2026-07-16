#!/usr/bin/env python3
"""F1 general-case receiver-symmetry conformance test (one spec, six runtimes).

Shared gold receiver-resolution contract: two methods with the SAME simple name
live on two different types (A.foo and B.foo) in the same file; a receiver
variable is typed to A (ctor / composite-literal / annotation). The call graph
MUST contain the edge to A.foo (no reachability false-negative) AND MUST NOT
contain the edge to B.foo (no same-name over-connection).

Run against a core tree via the IMPL_CORE env var (default: the patched
scratch copy). RED  when IMPL_CORE points at the pristine core (go self/var-name
drop, js class-name early-return, ruby positional-drop, zig same-file fan-out);
GREEN after the F1 patches are applied. The C and Python GOLD siblings pass in
BOTH states -- that is the proof the test encodes the gold contract, not the fix.

Usage:
    IMPL_CORE=/path/to/openant-core python3 F1-receiver-type-contract.test.py
    # or via pytest: IMPL_CORE=... python3 -m pytest F1-receiver-type-contract.test.py
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

IMPL_CORE = os.environ.get(
    "IMPL_CORE",
    "/private/tmp/claude-501/-Users-gadievron-Documents-ClaudeNew-OpenAnt-new-bugs-2/"
    "e77a0496-1f59-4f65-80e9-fa508d40fa3c/scratchpad/impl-core",
)


def _load_builder(rel_path, uniq):
    """Import a parser's call_graph_builder.py under a unique module name."""
    if IMPL_CORE not in sys.path:
        sys.path.insert(0, IMPL_CORE)
    spec = importlib.util.spec_from_file_location(uniq, str(Path(IMPL_CORE) / rel_path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.CallGraphBuilder


def _assert_symmetry(lang, edges, a_id, b_id):
    edges = list(edges or [])
    if a_id not in edges:
        raise AssertionError(
            f"[{lang}] expected edge to {a_id} (receiver typed A); got {edges} "
            f"-- reachability false-negative (typed-receiver method dropped)")
    if b_id in edges:
        raise AssertionError(
            f"[{lang}] did NOT expect edge to {b_id} (receiver is type A, not B); "
            f"got {edges} -- same-name over-connection false-positive")


# --------------------------------------------------------------------------- #
# Python (GOLD) -- must pass in both pristine and patched states.
# --------------------------------------------------------------------------- #
def check_python():
    CGB = _load_builder("parsers/python/call_graph_builder.py", "f1_py_cgb")
    data = {
        "repository": "/r",
        "functions": {
            "m.py:A.foo": {"name": "foo", "class_name": "A", "file_path": "m.py", "code": "def foo(self):\n    pass"},
            "m.py:B.foo": {"name": "foo", "class_name": "B", "file_path": "m.py", "code": "def foo(self):\n    pass"},
            "m.py:run": {"name": "run", "class_name": None, "file_path": "m.py",
                          "code": "def run():\n    a = A()\n    a.foo()"},
        },
        "classes": {"m.py:A": {"name": "A", "bases": []}, "m.py:B": {"name": "B", "bases": []}},
        "imports": {},
    }
    b = CGB(data)
    b.build_call_graph()
    _assert_symmetry("python(gold)", b.call_graph.get("m.py:run"), "m.py:A.foo", "m.py:B.foo")


# --------------------------------------------------------------------------- #
# C/C++ (GOLD) -- must pass in both pristine and patched states.
# --------------------------------------------------------------------------- #
def check_c():
    CGB = _load_builder("parsers/c/call_graph_builder.py", "f1_c_cgb")
    data = {
        "repository": "/r",
        "functions": {
            "m.cpp:A::foo": {"name": "foo", "class_name": "A", "file_path": "m.cpp", "code": "void foo() {}"},
            "m.cpp:B::foo": {"name": "foo", "class_name": "B", "file_path": "m.cpp", "code": "void foo() {}"},
            "m.cpp:run": {"name": "run", "file_path": "m.cpp",
                           "code": "void run() { A w; w.foo(); }"},
        },
        "class_bases": {"A": [], "B": []},
        "includes": {}, "macros": {}, "macro_aliases": {}, "prototypes": {},
    }
    b = CGB(data)
    b.build_call_graph()
    _assert_symmetry("c(gold)", b.call_graph.get("m.cpp:run"), "m.cpp:A::foo", "m.cpp:B::foo")


# --------------------------------------------------------------------------- #
# Ruby (F1 target).
# --------------------------------------------------------------------------- #
def check_ruby():
    CGB = _load_builder("parsers/ruby/call_graph_builder.py", "f1_rb_cgb")
    data = {
        "repository": "/r",
        "functions": {
            "m.rb:A#foo": {"name": "foo", "class_name": "A", "file_path": "m.rb", "code": "def foo\nend"},
            "m.rb:B#foo": {"name": "foo", "class_name": "B", "file_path": "m.rb", "code": "def foo\nend"},
            "m.rb:C#run": {"name": "run", "class_name": "C", "file_path": "m.rb",
                            "code": "def run\n  a = A.new\n  a.foo\nend"},
        },
        "classes": {"m.rb:A": {"name": "A", "file_path": "m.rb"},
                    "m.rb:B": {"name": "B", "file_path": "m.rb"},
                    "m.rb:C": {"name": "C", "file_path": "m.rb"}},
        "imports": {},
    }
    b = CGB(data)
    b.build_call_graph()
    _assert_symmetry("ruby", b.call_graph.get("m.rb:C#run"), "m.rb:A#foo", "m.rb:B#foo")


# --------------------------------------------------------------------------- #
# Zig (F1 target).
# --------------------------------------------------------------------------- #
def check_zig():
    CGB = _load_builder("parsers/zig/call_graph_builder.py", "f1_zig_cgb")
    data = {
        "repository": "/r", "classes": {}, "imports": {},
        "functions": {
            "m.zig:A.foo": {"name": "foo", "qualified_name": "A.foo", "class_name": "A",
                             "file_path": "m.zig", "code": "pub fn foo(self: A) void {}"},
            "m.zig:B.foo": {"name": "foo", "qualified_name": "B.foo", "class_name": "B",
                             "file_path": "m.zig", "code": "pub fn foo(self: B) void {}"},
            "m.zig:run": {"name": "run", "qualified_name": "run", "class_name": None,
                           "file_path": "m.zig", "code": "pub fn run() void { var a = A{}; a.foo(); }"},
        },
    }
    b = CGB(data)
    b.build_call_graph()
    _assert_symmetry("zig", b.call_graph.get("m.zig:run"), "m.zig:A.foo", "m.zig:B.foo")


# --------------------------------------------------------------------------- #
# JavaScript (F1 target) -- driven through node against dependency_resolver.js.
# --------------------------------------------------------------------------- #
_JS_DRIVER = r"""
const { DependencyResolver } = require(process.argv[2]);
const out = {
  functions: {
    'm.js:A.foo': { name: 'foo', className: 'A', code: 'foo() {}' },
    'm.js:B.foo': { name: 'foo', className: 'B', code: 'foo() {}' },
    // Receiver var name collides with class B but is constructed `new A()`:
    // it must dispatch on its real type A, not the collided class-name B.
    'm.js:caller': { name: 'caller', className: null, code: 'function caller(){ const B = new A(); B.foo(); }' },
  },
  classes: { 'm.js:A': {}, 'm.js:B': {} },
};
const r = new DependencyResolver(out); r.buildCallGraph();
process.stdout.write(JSON.stringify(r.callGraph['m.js:caller'] || []));
"""


def check_js():
    resolver = str(Path(IMPL_CORE) / "parsers/javascript/dependency_resolver.js")
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as fh:
        fh.write(_JS_DRIVER)
        driver = fh.name
    try:
        res = subprocess.run(["node", driver, resolver], capture_output=True, text=True, timeout=60)
        if res.returncode != 0:
            raise AssertionError(f"[js] node driver failed: {res.stderr.strip()}")
        edges = json.loads(res.stdout.strip() or "[]")
    finally:
        os.unlink(driver)
    _assert_symmetry("js", edges, "m.js:A.foo", "m.js:B.foo")


# --------------------------------------------------------------------------- #
# Go (F1 target) -- driven through `go test` on a scratch copy of the package.
# --------------------------------------------------------------------------- #
_GO_TEST = r'''package main

import "testing"

func f1contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestF1ReceiverTypeSymmetry(t *testing.T) {
	c := NewCallGraphBuilder("/repo")
	analyzer := &AnalyzerOutput{Functions: map[string]FunctionInfo{
		"m.go:A.foo": {Name: "foo", ClassName: "A", FilePath: "m.go", Code: "func (a *A) foo() {}"},
		"m.go:B.foo": {Name: "foo", ClassName: "B", FilePath: "m.go", Code: "func (b *B) foo() {}"},
		"m.go:Run":   {Name: "Run", ClassName: "", FilePath: "m.go", Code: "func Run() { w := A{}; w.foo() }"},
	}}
	cg, err := c.BuildCallGraph(analyzer)
	if err != nil {
		t.Fatalf("BuildCallGraph error: %v", err)
	}
	edges := cg.CallGraph["m.go:Run"]
	if !f1contains(edges, "m.go:A.foo") {
		t.Errorf("expected edge to m.go:A.foo (receiver w typed A), got %v", edges)
	}
	if f1contains(edges, "m.go:B.foo") {
		t.Errorf("did NOT expect edge to m.go:B.foo, got %v", edges)
	}
}
'''


def check_go():
    src = Path(IMPL_CORE) / "parsers/go/go_parser"
    tmp = tempfile.mkdtemp(prefix="f1-go-")
    try:
        dst = Path(tmp) / "go_parser"
        # Copy only .go + go.mod (skip prebuilt artifacts); exclude *_test.go to
        # avoid pulling unrelated tests, then drop in our symmetry test.
        dst.mkdir(parents=True)
        for p in src.iterdir():
            if p.is_file() and p.suffix in (".go", ".mod", ".sum") and not p.name.endswith("_test.go"):
                shutil.copy(p, dst / p.name)
        (dst / "f1_symmetry_test.go").write_text(_GO_TEST)
        res = subprocess.run(["go", "test", "-run", "TestF1ReceiverTypeSymmetry", "./..."],
                             cwd=str(dst), capture_output=True, text=True, timeout=180)
        if res.returncode != 0:
            raise AssertionError(f"[go] go test failed:\n{res.stdout}\n{res.stderr}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


ALL_CHECKS = [
    ("python(gold)", check_python),
    ("c(gold)", check_c),
    ("ruby", check_ruby),
    ("zig", check_zig),
    ("js", check_js),
    ("go", check_go),
]


def _run_all():
    failures = []
    for name, fn in ALL_CHECKS:
        try:
            fn()
            print(f"PASS  {name}")
        except Exception as exc:  # noqa: BLE001 - report every lang, don't stop early
            failures.append((name, exc))
            print(f"FAIL  {name}: {exc}")
    return failures


# pytest entry points (each lang an independent test)
def test_python_gold():
    check_python()


def test_c_gold():
    check_c()


def test_ruby():
    check_ruby()


def test_zig():
    check_zig()


def test_js():
    check_js()


def test_go():
    check_go()


if __name__ == "__main__":
    print(f"IMPL_CORE = {IMPL_CORE}")
    fails = _run_all()
    if fails:
        print(f"\n{len(fails)} FAILED")
        sys.exit(1)
    print("\nALL GREEN")
