"""#330: module-top-level code becomes a unit — line-masked, never containment.

In a JS/TS file with at least one real function, code at module top level — IIFEs,
callbacks passed to top-level calls, bare driver calls, initialiser calls — belonged
to no emitted unit, and the call graph scans only emitted units' code, so calls made
at module load (including calls to sinks) never became edges. A sink reachable through
top-level bootstrap code alone got no incoming edge from it (the false-negative
direction). The old capture (`_extractTopLevelSideEffects`) fired only on files with
ZERO units.

The exclusion strategy is the point: the synthetic module unit must mask by EMITTED
UNIT LINE RANGES (the Python extractor's :__module__ precedent, which wrote down why),
NOT by whole-statement containment — containment drops the class/object-literal
boundary and leaks member bodies in, attributing their calls to module load, which is
not when they run (and with module_level entry-point seeding, fabricated reachability).
The b.js fixture below separates the two strategies: only the bootstrap call runs at
module load.
"""
import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

PARSERS_JS_DIR = Path(__file__).parent.parent.parent.parent / "parsers" / "javascript"
ANALYZER_JS = PARSERS_JS_DIR / "typescript_analyzer.js"
RESOLVER_JS = PARSERS_JS_DIR / "dependency_resolver.js"
NODE_MODULES = PARSERS_JS_DIR / "node_modules"

pytestmark = pytest.mark.skipif(
    not shutil.which("node") or not NODE_MODULES.exists(),
    reason="Node.js or JS parser npm dependencies not available",
)


def _analyze(repo_path, file_path):
    cmd = ["node", str(ANALYZER_JS), str(repo_path), str(file_path)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, (
        f"analyzer failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    return json.loads(result.stdout)


def _build_call_graph(analyzer_output: dict) -> dict:
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
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, f"resolver failed:\n{result.stderr}"
    return json.loads(result.stdout)


def _pipeline(tmp_path, name, source, filename="x.js"):
    repo = tmp_path / name
    repo.mkdir(parents=True, exist_ok=True)
    fp = repo / filename
    fp.write_text(source)
    return _analyze(repo, fp), _build_call_graph(_analyze(repo, fp))


X_JS = """function sink() { return 1; }
function realFn() { sink(); }
(function boot() { sink(); })();
[1].forEach(function () { sink(); });
main();
function main() { return 2; }
const initv = sink();
"""

B_JS = """class K {
  constructor() { this.v = 1; }
  method() { classOnlyHelper(); }
}
const handlers = {
  handle() { objLitHelper(); }
};
function classOnlyHelper() { return 1; }
function objLitHelper() { return 2; }
bootstrapCall();
function bootstrapCall() { return 3; }
"""


def test_toplevel_calls_reach_the_graph_in_multi_unit_file(tmp_path):
    """The issue's x.js: IIFE, callback, bare driver call and initialiser all
    call sink in a file with real units — the control edge realFn -> sink is
    present, so a missing module edge is the defect, not a broken harness."""
    out, cg = _pipeline(tmp_path, "m330x", X_JS)
    assert "x.js:realFn" in out["functions"], "control missing — fixture failed"
    assert cg.get("x.js:realFn") == ["x.js:sink"], "control edge missing"
    mod = cg.get("x.js:module")
    assert mod is not None, (
        "no module-scope unit: top-level bootstrap calls made no edges "
        f"(functions={list(out['functions'])})"
    )
    assert "x.js:sink" in mod, f"module unit must reach sink (IIFE/callback/init): {mod}"
    assert "x.js:main" in mod, f"module unit must reach main (bare driver call): {mod}"


def test_module_unit_emitted_with_type_and_range(tmp_path):
    out, _ = _pipeline(tmp_path, "m330t", X_JS)
    mod = out["functions"].get("x.js:module")
    assert mod is not None, f"no x.js:module unit: {list(out['functions'])}"
    assert mod["unitType"] == "module_level"
    assert mod["code"].strip(), "module unit must carry the residual text"


def test_no_phantom_member_edges_line_masked(tmp_path):
    """The fabrication guard: only bootstrapCall runs at module load. A
    containment-based exclusion yields the three phantom member edges; the
    line-masked residual must contain exactly the bootstrap call."""
    out, cg = _pipeline(tmp_path, "m330b", B_JS, filename="b.js")
    assert "b.js:bootstrapCall" in out["functions"], "control missing — fixture failed"
    mod = cg.get("b.js:module")
    assert mod is not None, f"no module unit for b.js: {list(out['functions'])}"
    assert "b.js:bootstrapCall" in mod, f"the genuine bootstrap edge is missing: {mod}"
    for phantom in ("b.js:classOnlyHelper", "b.js:handlers.handle", "b.js:objLitHelper"):
        assert phantom not in mod, (
            f"phantom edge {phantom} — member calls attributed to module load, "
            "which is not when they run (containment-style leak)"
        )


def test_single_side_effect_file_still_emits_sanitised(tmp_path):
    """The old fallback's domain (preload scripts): still >=1 unit, now under
    the sanitised `module` label — not the fabricated callee label
    `x.js:[1].forEach` (the issue's secondary note)."""
    repo = tmp_path / "m330p"
    repo.mkdir(parents=True, exist_ok=True)
    fp = repo / "file.js"
    fp.write_text("contextBridge.exposeInMainWorld('api', { ping: () => 1 });\n")
    out = _analyze(repo, fp)
    assert len(out["functions"]) >= 1, f"side-effect-only file must emit a unit: {out}"
    assert "file.js:module" in out["functions"]


def test_no_module_unit_without_a_residual_call(tmp_path):
    """Imports and covered units only — the residual has no call, so no
    module unit is emitted (the emit-when-contains-call gate)."""
    src = "import fs from 'fs';\nfunction a() { return 1; }\nfunction b() { return a(); }\n"
    out, _ = _pipeline(tmp_path, "m330n", src)
    assert "x.js:module" not in out["functions"], (
        f"no residual call — module unit must not be emitted: {list(out['functions'])}"
    )
