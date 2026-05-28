"""Tests for the JS analyzer call-graph extraction.

These run the typescript_analyzer.js Node script as a subprocess on inline
fixtures (mirroring test_express_route_handlers.py) and assert on the emitted
`functions` / `callGraph`.

Skips when Node.js or the parser's npm dependencies aren't installed.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest


PARSERS_JS_DIR = Path(__file__).parent.parent.parent.parent / "parsers" / "javascript"
NODE_MODULES = PARSERS_JS_DIR / "node_modules"

pytestmark = pytest.mark.skipif(
    not shutil.which("node") or not NODE_MODULES.exists(),
    reason="Node.js or JS parser npm dependencies not available",
)


def _analyze(repo_path, file_path):
    cmd = ["node", str(PARSERS_JS_DIR / "typescript_analyzer.js"), str(repo_path), str(file_path)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, (
        f"analyzer failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    return json.loads(result.stdout)


def _write(tmp_path, name, content, filename="file.js"):
    repo = tmp_path / name
    repo.mkdir(parents=True, exist_ok=True)
    fp = repo / filename
    fp.write_text(content)
    return repo, fp


def _names(edges):
    """Collect the textual call names from a callGraph edge list."""
    out = []
    for e in edges:
        if isinstance(e, dict):
            out.append(e.get("name") or e.get("functionId"))
        else:
            out.append(e)
    return out


# --- foundational call-edge extraction ------------------------------

def test_call_graph_records_callee(tmp_path):
    """`function a(){b();} function b(){}` -> callGraph['file.js:a'] names b.

    Regression for the `getDescendantsOfKind(funcNode.getKind())` bug that
    made every out-edge list empty.
    """
    repo, fp = _write(
        tmp_path,
        "sb1",
        "function a(){ b(); }\nfunction b(){ return 1; }\n",
    )
    out = _analyze(repo, fp)
    edges = out["callGraph"]["file.js:a"]
    assert "b" in _names(edges), f"expected a->b edge; callGraph['file.js:a']={edges}"


def test_arrow_function_call_edges(tmp_path):
    """Arrow function bodies must also yield out-edges."""
    repo, fp = _write(
        tmp_path,
        "sb1_arrow",
        "function helper(){ return 1; }\nconst run = () => { helper(); };\n",
    )
    out = _analyze(repo, fp)
    edges = out["callGraph"]["file.js:run"]
    assert "helper" in _names(edges), f"expected run->helper edge; got {edges}"


# --- call-edge content ----------------------------------------------

def test_callback_argument_edges(tmp_path):
    """`addEventListener('click', handler)` / `setTimeout(cb)` must record the
    callback identifier as a call edge."""
    repo, fp = _write(
        tmp_path,
        "sb4_cb",
        """
function handler(){ return 1; }
function register(){
  el.addEventListener('click', handler);
  setTimeout(handler, 10);
  [1,2].forEach(handler);
}
""",
    )
    out = _analyze(repo, fp)
    edges = out["callGraph"]["file.js:register"]
    names = _names(edges)
    assert "handler" in names, (
        f"callback identifier `handler` must be recorded as a call edge; got {names}"
    )


def test_call_name_normalized_to_identifier(tmp_path):
    """Chained / element-access callees must normalize to an identifier name,
    not a multiline raw span."""
    repo, fp = _write(
        tmp_path,
        "sb4_norm",
        """
function build(){
  return foo
    .bar()
    .baz();
}
""",
    )
    out = _analyze(repo, fp)
    edges = out["callGraph"]["file.js:build"]
    for name in _names(edges):
        assert name is not None
        assert "\n" not in name, f"call name must not be a multiline blob: {name!r}"
        # A normalized name is a bare identifier (the trailing member name).
        assert name.replace("$", "_").replace("_", "a").isalnum() or name == "", (
            f"call name should be a simple identifier, got {name!r}"
        )


def test_unresolved_calls_bucketed_into_indirect_calls(tmp_path):
    """Dynamic / unresolvable calls populate `indirect_calls` rather than
    silently vanishing."""
    repo, fp = _write(
        tmp_path,
        "sb4_indirect",
        """
function dispatch(cb){
  cb();
  obj['method']();
}
""",
    )
    out = _analyze(repo, fp)
    assert "indirect_calls" in out, "analyzer output must expose indirect_calls"
    # The unresolved callee(s) of dispatch should appear under indirect_calls.
    entry = out["indirect_calls"].get("file.js:dispatch", [])
    assert len(entry) >= 1, (
        f"expected dispatch's dynamic call(s) bucketed into indirect_calls; got {out['indirect_calls']}"
    )
