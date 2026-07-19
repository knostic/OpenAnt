"""Bug: TypeScript `namespace {}` / `module {}` bodies are not descended, so
classes and arrow/const functions declared inside a namespace are never
extracted.

`extractFunctionsFromFile` enumerated classes via `sourceFile.getClasses()` and
const-arrow functions via `sourceFile.getVariableStatements()`. Both return only
the source file's OWN top-level statements — a namespace body is its own
StatementedNode scope, so `class Shape {}` and `const f = () =>` declared inside
`namespace X {}` were invisible: never a unit, never a call-graph node, never an
entry point. (Plain `function` declarations inside a namespace were already
surfaced, because _moduleLevelFunctionNodes walks getDescendantsOfKind.)

Fix: descend every namespace/module body (at any nesting depth) that is not
inside a function, and extract its classes + variable statements too. Namespaces
nested inside a function stay omitted (their text rides inside the enclosing
unit), matching the existing block-scoped-function scope decision.
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


def _analyze(tmp_path, source, filename="a.ts"):
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


NAMESPACE_SRC = (
    "namespace Geometry {\n"
    "  export function area(r: number): number { return circ(r); }\n"
    "  function circ(r: number): number { return 2 * Math.PI * r; }\n"
    "  export class Shape { render(): void { area(1); } }\n"
    "  export const scale = (x: number) => x * 2;\n"
    "}\n"
)


def test_namespace_class_method_is_extracted(tmp_path):
    out = _analyze(tmp_path, NAMESPACE_SRC)
    assert "Shape.render" in _names(out), (
        f"class method inside namespace dropped: {_names(out)}"
    )


def test_namespace_arrow_const_is_extracted(tmp_path):
    out = _analyze(tmp_path, NAMESPACE_SRC)
    assert "scale" in _names(out), (
        f"const-arrow inside namespace dropped: {_names(out)}"
    )


def test_namespace_function_declarations_still_extracted(tmp_path):
    # regression: the paths that already worked must keep working.
    out = _analyze(tmp_path, NAMESPACE_SRC)
    names = _names(out)
    assert "area" in names and "circ" in names, names


def test_nested_namespace_members_extracted(tmp_path):
    src = (
        "namespace Outer {\n"
        "  export namespace Inner {\n"
        "    export class Deep { go(): void {} }\n"
        "    export const helper = () => 1;\n"
        "  }\n"
        "}\n"
    )
    out = _analyze(tmp_path, src)
    names = _names(out)
    assert "Deep.go" in names, f"nested-namespace class method dropped: {names}"
    assert "helper" in names, f"nested-namespace arrow dropped: {names}"


def test_namespace_inside_function_stays_omitted(tmp_path):
    # A namespace declared inside a function is not module-level; its members'
    # text rides inside the enclosing unit and must NOT be double-extracted.
    src = (
        "function outer() {\n"
        "  namespace Local { export class C { m(): void {} } }\n"
        "  return 1;\n"
        "}\n"
    )
    out = _analyze(tmp_path, src)
    names = _names(out)
    assert "C.m" not in names, f"function-nested namespace over-extracted: {names}"
    assert "outer" in names, names


def test_top_level_class_unchanged(tmp_path):
    # regression: a top-level class + arrow must still be extracted exactly once.
    src = "class Top { run(): void {} }\nconst top = () => 1;\n"
    out = _analyze(tmp_path, src)
    names = _names(out)
    assert "Top.run" in names and "top" in names, names
    assert names.count("Top.run") == 1


# --- FA3 revision: the inventory arm alone is a partial fix. A namespace member
# must also get its REAL outgoing edges in callGraph (buildCallGraphForFile must
# descend namespaces too), and a top-level unit must win over a same-name
# namespace member on id collision (first-wins). These tests assert the OUTGOING
# EDGE, not mere membership — the membership-only tests above were false-green.

def _edges(out, caller_id):
    """Outgoing edge target names for a callGraph key, or None if key absent."""
    cg = out.get("callGraph", {})
    if caller_id not in cg:
        return None
    return sorted(e["name"] for e in cg[caller_id] if e.get("name"))


EDGE_SRC = (
    "namespace Geometry {\n"
    "  function area(r: number): number { return 2 * Math.PI * r; }\n"
    "  export class Shape { render(): void { area(1); } }\n"
    "  export const scale = (x: number) => area(x);\n"
    "}\n"
)


def test_namespace_class_method_has_outgoing_edge(tmp_path):
    # Shape.render() calls area(). Before the callGraph arm descended namespaces,
    # this key existed (Step-4 backstop) but its edge list was empty [].
    out = _analyze(tmp_path, EDGE_SRC)
    edges = _edges(out, "a.ts:Shape.render")
    assert edges is not None, f"Shape.render missing from callGraph: {sorted(out.get('callGraph', {}))}"
    assert "area" in edges, f"Shape.render -> area edge dropped (empty backstop?): {edges}"


def test_namespace_arrow_has_outgoing_edge(tmp_path):
    # const scale = (x) => area(x); its outgoing edge to area must be walked.
    out = _analyze(tmp_path, EDGE_SRC)
    edges = _edges(out, "a.ts:scale")
    assert edges is not None, f"scale missing from callGraph: {sorted(out.get('callGraph', {}))}"
    assert "area" in edges, f"scale -> area edge dropped (empty backstop?): {edges}"


COLLISION_SRC = (
    "class Shape { render(): void { topHelper(); } }\n"
    "function topHelper(): void {}\n"
    "namespace NS {\n"
    "  export class Shape { render(): void { nsHelper(); } }\n"
    "  function nsHelper(): void {}\n"
    "}\n"
)


def test_top_level_wins_over_namespace_on_id_collision(tmp_path):
    # A top-level `class Shape` and a namespace `class Shape` both produce the id
    # `Shape.render`. Without a first-wins guard the later namespace member
    # OVERWROTE the top-level unit (and its edges). Top-level must be kept.
    out = _analyze(tmp_path, COLLISION_SRC)
    unit = out["functions"].get("a.ts:Shape.render")
    assert unit is not None, "Shape.render unit missing"
    assert unit.get("startLine") == 1, (
        f"namespace Shape.render (line 4) overwrote top-level (line 1): startLine={unit.get('startLine')}"
    )
    edges = _edges(out, "a.ts:Shape.render")
    assert edges == ["topHelper"], (
        f"callGraph for kept unit must be the top-level's edges, got {edges}"
    )
