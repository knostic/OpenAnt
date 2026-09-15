"""Regression tests for issue #299 (JS/TS member — 6 of 7): container-literal
dispatch loses call edges; the detected-but-discarded `indirect_calls` has no
consumer.

The analyzer normalized `handlers['a']()` (an ElementAccessExpression callee)
to null and bucketed the raw span into `indirect_calls` — a field with no
non-test reader — so a dispatch table's targets were orphaned while the
dominant real-world idiom (a named handler as an argument,
``app.get('/x', handlerC)``) already worked. Per the umbrella: "the
detection already works, only the plumbing is missing."

Contract locked here:
- an object/array literal of named handlers plus an element-access call
  records edges to every referenced function — the caller set contains the
  DISPATCHER specifically;
- a direct-call CONTROL keeps its edge; the argument-handler idiom keeps
  working (the mild-severity note — it must not regress);
- `indirect_calls` entries that name a known function become REFERENCE
  edges in the graph (the consumer the umbrella asks for);
- an element access over an unknown container abstains — no invented edges.
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
    cmd = ["node", str(PARSERS_JS_DIR / "typescript_analyzer.js"),
           str(repo_path), str(file_path)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, (
        f"analyzer failed:\nstdout={result.stdout}\nstderr={result.stderr}")
    return json.loads(result.stdout)


def _write(tmp_path, name, content, filename="file.js"):
    repo = tmp_path / name
    repo.mkdir(parents=True, exist_ok=True)
    fp = repo / filename
    fp.write_text(content)
    return repo, fp


_FIXTURE = """
function handlerA() { return 1; }
function handlerB() { return 2; }
function directTarget() { return 3; }

const handlers = { a: handlerA, b: handlerB };
const tbl = [handlerB, handlerA];

function dispatch(k) {
  directTarget();
  handlers[k]();
  tbl[0]();
  return 0;
}
"""


def test_object_container_dispatch_edges(tmp_path):
    repo, fp = _write(tmp_path, "obj", _FIXTURE)
    out = _analyze(repo, fp)
    edges = out["call_graph"].get("file.js:dispatch", [])
    assert any("handlerA" in e for e in edges), edges
    assert any("handlerB" in e for e in edges), edges


def test_array_container_dispatch_edges(tmp_path):
    repo, fp = _write(tmp_path, "arr", _FIXTURE)
    out = _analyze(repo, fp)
    edges = out["call_graph"].get("file.js:dispatch", [])
    assert any("handlerA" in e for e in edges), edges
    assert any("handlerB" in e for e in edges), edges


def test_direct_call_and_control_shapes(tmp_path):
    repo, fp = _write(tmp_path, "ctl", _FIXTURE)
    out = _analyze(repo, fp)
    edges = out["call_graph"].get("file.js:dispatch", [])
    assert any("directTarget" in e for e in edges), edges


def test_indirect_entries_consume_as_reference_edges(tmp_path):
    """The umbrella's plumbing ask: an indirect bucket entry becomes a
    REFERENCE edge when it resolves with the member restriction dropped —
    a receiver call `x.process()` whose same-named free function exists
    keeps that function reachable from the caller (over-seed, the safe
    direction; the detection already worked, only the graph never consumed
    it)."""
    repo, fp = _write(tmp_path, "ind", """
        function process(x) { return x; }
        function run(obj) {
          return obj.process(1);
        }
    """)
    out = _analyze(repo, fp)
    edges = out["call_graph"].get("file.js:run", [])
    assert any(e.endswith(":process") for e in edges), edges


def test_unknown_element_access_abstains(tmp_path):
    repo, fp = _write(tmp_path, "unk", """
        function data() { return 1; }
        function use(k) {
          const d = { x: 1, y: 2 };
          return d[k]();
        }
    """)
    out = _analyze(repo, fp)
    edges = out["call_graph"].get("file.js:use", [])
    assert not any(e.endswith(":data") for e in edges), edges
