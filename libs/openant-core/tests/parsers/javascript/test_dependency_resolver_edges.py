"""Resolver-level tests for dependency_resolver.js call-edge fidelity.

These drive DependencyResolver directly (no analyzer pipeline) by requiring
the module from a small Node harness, feeding it a synthetic analyzerOutput
(functions / classes), building the call graph, and asserting on the resulting
callGraph JSON. This isolates resolver behaviour from the upstream analyzer.

Covers:
  - bare call must not bind to a class method (over-resolution).
  - `const x = new C(); x.m()` must resolve to C.m (local-type dispatch).
  - a function's own name in its body must not create a self-edge.
  - CLI on malformed JSON must emit a human-readable diagnostic, not a raw crash.

Skips when Node.js or the parser's npm dependencies aren't installed.
"""
import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest


PARSERS_JS_DIR = Path(__file__).parent.parent.parent.parent / "parsers" / "javascript"
RESOLVER_JS = PARSERS_JS_DIR / "dependency_resolver.js"
NODE_MODULES = PARSERS_JS_DIR / "node_modules"

pytestmark = pytest.mark.skipif(
    not shutil.which("node") or not NODE_MODULES.exists(),
    reason="Node.js or JS parser npm dependencies not available",
)


def _build_call_graph(analyzer_output: dict) -> dict:
    """Run DependencyResolver on analyzer_output and return the resulting callGraph."""
    harness = textwrap.dedent(
        f"""
        const {{ DependencyResolver }} = require({json.dumps(str(RESOLVER_JS))});
        const out = JSON.parse(process.argv[1]);
        const r = new DependencyResolver(out, {{}});
        r.buildCallGraph();
        process.stdout.write(JSON.stringify(r.callGraph));
        """
    )
    result = subprocess.run(
        ["node", "-e", harness, "--", json.dumps(analyzer_output)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"resolver harness failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    return json.loads(result.stdout)


# ---------------------------------------------------------------------------
# bare-call class-method leak
# ---------------------------------------------------------------------------

def test_bare_call_does_not_bind_same_file_class_method():
    """`doWork()` must NOT resolve to same-file class method `Utils.doWork`."""
    cg = _build_call_graph(
        {
            "functions": {
                "a.js:Utils.doWork": {
                    "name": "Utils.doWork",
                    "className": "Utils",
                    "code": "doWork(){return 1;}",
                },
                "a.js:caller": {
                    "name": "caller",
                    "code": "function caller(){ doWork(); }",
                },
            },
            "classes": {"a.js:Utils": {}},
        }
    )
    assert "a.js:Utils.doWork" not in cg["a.js:caller"], (
        f"bare doWork() leaked to class method; edges={cg['a.js:caller']}"
    )


def test_bare_call_does_not_bind_unique_cross_file_class_method():
    """`format()` must NOT resolve to a unique cross-file class method `Utils.format`."""
    cg = _build_call_graph(
        {
            "functions": {
                "u.js:Utils.format": {
                    "name": "Utils.format",
                    "className": "Utils",
                    "code": "format(){return 1;}",
                },
                "a.js:caller": {
                    "name": "caller",
                    "code": "function caller(){ format(); }",
                },
            },
            "classes": {"u.js:Utils": {}},
        }
    )
    assert "u.js:Utils.format" not in cg["a.js:caller"], (
        f"bare format() leaked to cross-file class method; edges={cg['a.js:caller']}"
    )


def test_bare_call_to_top_level_function_still_resolves():
    """Control: a bare call to a genuine top-level function must still resolve."""
    cg = _build_call_graph(
        {
            "functions": {
                "a.js:doWork": {
                    "name": "doWork",
                    "code": "function doWork(){return 1;}",
                },
                "a.js:caller": {
                    "name": "caller",
                    "code": "function caller(){ doWork(); }",
                },
            },
            "classes": {},
        }
    )
    assert "a.js:doWork" in cg["a.js:caller"], (
        f"bare call to top-level function should resolve; edges={cg['a.js:caller']}"
    )


# ---------------------------------------------------------------------------
# local-variable type dispatch
# ---------------------------------------------------------------------------

def test_local_var_constructor_method_resolves():
    """`const x = new C(); x.m()` must resolve to `C.m`."""
    cg = _build_call_graph(
        {
            "functions": {
                "a.js:C.m": {"name": "C.m", "className": "C", "code": "m(){return 1;}"},
                "a.js:doWork": {
                    "name": "doWork",
                    "code": "function doWork(){ const x = new C(); x.m(); }",
                },
            },
            "classes": {"a.js:C": {}},
        }
    )
    assert "a.js:C.m" in cg["a.js:doWork"], (
        f"local-var x.m() should resolve to C.m; edges={cg['a.js:doWork']}"
    )


def test_local_var_let_and_var_forms_resolve():
    """`let`/`var` constructor declarations also resolve the method call."""
    cg = _build_call_graph(
        {
            "functions": {
                "a.js:C.m": {"name": "C.m", "className": "C", "code": "m(){return 1;}"},
                "a.js:withLet": {
                    "name": "withLet",
                    "code": "function withLet(){ let y = new C(); y.m(); }",
                },
                "a.js:withVar": {
                    "name": "withVar",
                    "code": "function withVar(){ var z = new C(); z.m(); }",
                },
            },
            "classes": {"a.js:C": {}},
        }
    )
    assert "a.js:C.m" in cg["a.js:withLet"], f"let form failed; edges={cg['a.js:withLet']}"
    assert "a.js:C.m" in cg["a.js:withVar"], f"var form failed; edges={cg['a.js:withVar']}"


def test_local_var_builtin_constructor_not_resolved():
    """`const m = new Map(); m.get()` must not spuriously resolve to a repo method."""
    cg = _build_call_graph(
        {
            "functions": {
                "a.js:Cache.get": {
                    "name": "Cache.get",
                    "className": "Cache",
                    "code": "get(){return 1;}",
                },
                "a.js:doWork": {
                    "name": "doWork",
                    "code": "function doWork(){ const m = new Map(); m.get('k'); }",
                },
            },
            "classes": {"a.js:Cache": {}},
        }
    )
    assert "a.js:Cache.get" not in cg["a.js:doWork"], (
        f"built-in Map receiver must not bind to Cache.get; edges={cg['a.js:doWork']}"
    )


# ---------------------------------------------------------------------------
# self-edge from own name in body
# ---------------------------------------------------------------------------

def test_function_own_name_does_not_create_self_edge():
    """A function's own name appearing in its body must not produce a self-edge."""
    cg = _build_call_graph(
        {
            "functions": {
                "auth.js:login": {
                    "name": "login",
                    "code": "function login(){ return doStuff(); }",
                },
                "auth.js:doStuff": {
                    "name": "doStuff",
                    "code": "function doStuff(){ return 1; }",
                },
            },
            "classes": {},
        }
    )
    assert "auth.js:login" not in cg["auth.js:login"], (
        f"function must not have a self-edge; edges={cg['auth.js:login']}"
    )
    # The genuine cross-function edge must survive.
    assert "auth.js:doStuff" in cg["auth.js:login"], (
        f"genuine edge to doStuff lost; edges={cg['auth.js:login']}"
    )


def test_genuine_recursion_self_edge_absent():
    """Even a truly self-recursive function should not list itself as a dependency.

    Self-edges inflate out-degree and create self-dependencies in bundles; the
    C-sibling call_graph_builder enforces `c != func_id`.
    """
    cg = _build_call_graph(
        {
            "functions": {
                "a.js:fact": {
                    "name": "fact",
                    "code": "function fact(n){ return n <= 1 ? 1 : n * fact(n - 1); }",
                },
            },
            "classes": {},
        }
    )
    assert "a.js:fact" not in cg["a.js:fact"], (
        f"recursive function must not self-edge; edges={cg['a.js:fact']}"
    )


# ---------------------------------------------------------------------------
# CLI JSON.parse must fail gracefully
# ---------------------------------------------------------------------------

def test_cli_malformed_json_emits_diagnostic(tmp_path):
    """`node dependency_resolver.js <malformed.json>` must print a readable error."""
    bad = tmp_path / "bad.json"
    bad.write_text("{bad json")
    result = subprocess.run(
        ["node", str(RESOLVER_JS), str(bad)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 1, f"expected exit 1, got {result.returncode}"
    combined = result.stdout + result.stderr
    assert str(bad) in combined, f"diagnostic should name the input file; got: {combined}"
    assert "SyntaxError" not in result.stderr.split("\n")[0], (
        f"first stderr line should be a diagnostic, not a raw V8 SyntaxError; got: {result.stderr}"
    )
    # No raw V8 stack trace pointing into the resolver source.
    assert "dependency_resolver.js:" not in result.stderr, (
        f"raw stack trace leaked to stderr: {result.stderr}"
    )


def test_cli_missing_file_still_guarded(tmp_path):
    """Control: the existing missing-file guard must remain intact."""
    missing = tmp_path / "nope.json"
    result = subprocess.run(
        ["node", str(RESOLVER_JS), str(missing)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 1
    assert "not found" in (result.stdout + result.stderr).lower()
