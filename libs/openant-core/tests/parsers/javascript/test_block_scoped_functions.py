"""Bug: block-scoped function declarations are silently dropped from BOTH the
function inventory and the call graph.

The analyzer enumerated functions via `sourceFile.getFunctions()` (top-level
only) in extractFunctionsFromFile AND buildCallGraphForFile, so a function
declared inside any block (if/else, try/catch, for/while/switch, bare {}) was
invisible — never a unit, never a reachability node, never an entry point. For a
SAST tool a vulnerable function gated behind `if (process.env.X)` or in a
`catch` fallback is then never analyzed.

Investigated independent + expert + judge. Settled scope (verified against the
`node` runtime):
  * MODULE-LEVEL block functions (no function-like ancestor) MUST be surfaced.
  * Functions nested inside another function/method stay omitted (their text
    rides inside the parent unit).
  * Functions inside a `static {}` class block stay omitted (uncallable).
  * Both loops patched in lockstep so callGraph keys == functions keys (the
    backstop must not mask a missing-edge gap).
  * Sibling-block same-name functions are both runtime-reachable -> keep BOTH
    via a `#L<line>` suffix (collision-only; unique names keep the clean id).
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


def _analyze(tmp_path, source, filename="a.js"):
    repo = tmp_path / "r"
    repo.mkdir(exist_ok=True)
    fp = repo / filename
    fp.write_text(source)
    cmd = ["node", str(PARSERS_JS_DIR / "typescript_analyzer.js"), str(repo), str(fp)]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, f"analyzer failed:\n{res.stderr}"
    return json.loads(res.stdout)


def _names(out):
    return sorted(k.split(":", 1)[1] for k in out["functions"])


# --- the core bug: module-level block functions surfaced in BOTH maps --------

@pytest.mark.parametrize("wrap", [
    "if (c) { %s }",
    "if (c) {} else { %s }",
    "try { %s } catch (e) {}",
    "try {} catch (e) { %s }",
    "for (let i=0;i<1;i++) { %s }",
    "while (c) { %s }",
    "switch (x) { case 1: { %s } }",
    "{ %s }",
])
def test_block_scoped_function_is_extracted(tmp_path, wrap):
    src = "function topLevel(){ return 1; }\n" + wrap % "function vuln(){ return sink(); }"
    out = _analyze(tmp_path, src)
    assert "vuln" in _names(out), f"block function dropped from inventory: {_names(out)}"
    # and it must be a real call-graph node, not a backstop-filled empty entry
    vuln_id = next(k for k in out["functions"] if k.endswith(":vuln"))
    assert vuln_id in out["callGraph"], "vuln missing from callGraph"
    edges = out["callGraph"][vuln_id]
    # callGraph edges are dicts: {"name": "sink", "resolved": bool, ...}
    edge_names = [e.get("name") if isinstance(e, dict) else e for e in edges]
    assert "sink" in edge_names, (
        f"vuln's outgoing edge to sink lost (backstop masked it): {edges}"
    )


def test_incoming_call_to_block_function_resolves(tmp_path):
    # A call TO a module-level block-scoped function must resolve in the RESOLVED
    # call graph, so the block function is reachable (not pruned). Guards the
    # sibling resolver site (_buildResolvedGraphs) — without it the function is a
    # unit but has no resolved incoming edge.
    src = "function caller(){ return helper(); }\nif (c) { function helper(){ return 1; } }\n"
    out = _analyze(tmp_path, src)
    caller_id = next(k for k in out["functions"] if k.endswith(":caller"))
    helper_id = next(k for k in out["functions"] if k.endswith(":helper"))
    assert helper_id in out["call_graph"].get(caller_id, []), (
        f"caller->helper not resolved: {out['call_graph'].get(caller_id)}"
    )
    assert caller_id in out["reverse_call_graph"].get(helper_id, []), (
        f"block fn has no resolved incoming edge: {out['reverse_call_graph'].get(helper_id)}"
    )


def test_invariant_callgraph_keys_equal_functions_keys(tmp_path):
    src = "if (c) { function a(){ b(); } }\nfunction b(){}\n"
    out = _analyze(tmp_path, src)
    assert set(out["functions"]) == set(out["callGraph"]), (
        "callGraph keys diverge from functions keys (lockstep broken)"
    )


# --- keep-both for sibling-block same-name (both runtime-reachable) -----------

def test_sibling_block_same_name_keeps_both(tmp_path):
    src = (
        "if (c) { function dup(){ return ifBranch(); } }\n"
        "else { function dup(){ return elseBranch(); } }\n"
    )
    out = _analyze(tmp_path, src)
    dups = [k for k in out["functions"] if k.split(":", 1)[1].startswith("dup")]
    assert len(dups) == 2, f"both sibling-block dup defs must survive; got {dups}"
    bodies = " ".join(out["functions"][k]["code"] for k in dups)
    assert "ifBranch" in bodies and "elseBranch" in bodies, f"a branch was dropped: {bodies}"


# --- the omit cases (must NOT over-extract) -----------------------------------

def test_function_nested_in_function_stays_omitted(tmp_path):
    out = _analyze(tmp_path, "function outer(){ function inner(){ return 1; } return inner(); }")
    assert "inner" not in _names(out), f"nested-in-function should be omitted: {_names(out)}"
    assert "outer" in _names(out)


def test_function_in_static_block_stays_omitted(tmp_path):
    # class static-init block: the function is block-scoped to the initializer
    # and callable nowhere -> must not become a (false-positive) unit.
    out = _analyze(tmp_path, "class C { static { function s(){ return 1; } } }")
    assert "s" not in _names(out), f"static-block function should be omitted: {_names(out)}"


# --- regression: unique top-level id unchanged --------------------------------

def test_unique_top_level_id_unchanged(tmp_path):
    out = _analyze(tmp_path, "function solo(){ return 1; }")
    ids = [k for k in out["functions"] if k.endswith("solo")]
    assert len(ids) == 1 and ids[0].endswith(":solo") and "#L" not in ids[0], (
        f"unique-name id must stay byte-identical: {ids}"
    )
