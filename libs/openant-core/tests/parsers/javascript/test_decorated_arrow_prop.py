"""Regression: decorated arrow-function class properties are seeded as units.

PR #146 generalised decorator capture for class *methods*, but a decorated
arrow-function class property (NestJS/Angular `@Get() findAll = (req, res) =>
{...}`) is not returned by `getMethods()`, so it was never emitted as a unit —
hence never seeded as a route_handler entry point and its callees were pruned
as unreachable.

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


def _write(tmp_path, name, content, filename="cats.controller.ts"):
    repo = tmp_path / name
    repo.mkdir(parents=True, exist_ok=True)
    fp = repo / filename
    fp.write_text(content)
    return repo, fp


def test_decorated_arrow_property_seeded_as_route_handler(tmp_path):
    repo, fp = _write(
        tmp_path,
        "pr146_arrow_prop",
        "class CatsController {\n"
        "  @Get()\n"
        "  findAll = (req, res) => {\n"
        "    return res.send('all cats');\n"
        "  };\n"
        "  ping() { return 'pong'; }\n"
        "}\n",
    )
    out = _analyze(repo, fp)
    fn = next(
        (v for k, v in out["functions"].items() if k.endswith(":CatsController.findAll")),
        None,
    )
    assert fn is not None, (
        f"decorated arrow-function property must be emitted; got {list(out['functions'])}"
    )
    assert fn["decorators"] == ["@Get()"], fn["decorators"]
    assert fn["unitType"] == "route_handler", fn["unitType"]
    assert fn["className"] == "CatsController"


def _callees(out, id_suffix):
    """Callee names on the callGraph edge for the function whose id ends with
    id_suffix. Empty list if the id has no edges / no entry."""
    cg = out["callGraph"]
    key = next((k for k in cg if k.endswith(id_suffix)), None)
    if key is None:
        return []
    return [e.get("name") for e in cg[key]]


def test_decorated_arrow_property_callees_get_edges(tmp_path):
    """The transitive rescue: the handler's body call must produce a REAL
    outgoing callGraph edge, not an empty Step-4 backstop. buildCallGraphForFile
    must walk getProperties() arrow initializers, else the callee stays pruned."""
    repo, fp = _write(
        tmp_path,
        "pr146_arrow_prop_edges",
        "class CatsController {\n"
        "  @Get()\n"
        "  findAll = (req, res) => {\n"
        "    return this.svc.rescueMe();\n"
        "  };\n"
        "}\n",
    )
    out = _analyze(repo, fp)
    callees = _callees(out, ":CatsController.findAll")
    assert "rescueMe" in callees, (
        f"handler's body callee must get a callGraph edge (transitive rescue); "
        f"got {callees}"
    )


def test_class_expression_decorated_arrow_property(tmp_path):
    """A-class sibling: class *expressions* (module.exports = class {...}) carry
    the same property-arrow gap. The property must be a unit AND its callee must
    get an edge."""
    repo, fp = _write(
        tmp_path,
        "pr146_arrow_prop_classexpr",
        "module.exports = class CatsController {\n"
        "  @Get()\n"
        "  findAll = (req, res) => {\n"
        "    return this.svc.rescueMe();\n"
        "  };\n"
        "};\n",
    )
    out = _analyze(repo, fp)
    fn = next(
        (v for k, v in out["functions"].items() if k.endswith(":CatsController.findAll")),
        None,
    )
    assert fn is not None, (
        f"class-expression decorated arrow property must be emitted; "
        f"got {list(out['functions'])}"
    )
    assert fn["decorators"] == ["@Get()"], fn["decorators"]
    assert fn["className"] == "CatsController"
    callees = _callees(out, ":CatsController.findAll")
    assert "rescueMe" in callees, (
        f"class-expression handler's callee must get a callGraph edge; got {callees}"
    )


def test_class_decorated_controller_arrow_property_carries_class_decorator(tmp_path):
    """A-class completeness (FA3): the arrow-property unit must bundle the
    CLASS-level decorator too, exactly as the sibling METHOD paths do via the
    variadic `_decoratorTexts(classDecl, member)`. A NestJS `@Controller('cats')`
    on the class is what makes the route prefix / entry-point classification
    correct; if the property emission passes only the member node it silently
    drops the class decorator and the handler loses its controller context."""
    repo, fp = _write(
        tmp_path,
        "pr146_class_decorated_arrow_prop",
        "@Controller('cats')\n"
        "class CatsController {\n"
        "  @Get()\n"
        "  findAll = (req, res) => {\n"
        "    return res.send('all cats');\n"
        "  };\n"
        "}\n",
    )
    out = _analyze(repo, fp)
    fn = next(
        (v for k, v in out["functions"].items() if k.endswith(":CatsController.findAll")),
        None,
    )
    assert fn is not None, (
        f"decorated arrow-function property must be emitted; got {list(out['functions'])}"
    )
    # Both the class-level and the member-level decorators, mirroring methods.
    assert "@Controller('cats')" in fn["decorators"], (
        f"class-level decorator must be bundled onto the property unit "
        f"(mirrors method paths); got {fn['decorators']}"
    )
    assert "@Get()" in fn["decorators"], fn["decorators"]


def test_class_expression_decorated_controller_arrow_property_carries_class_decorator(
    tmp_path,
):
    """A-class completeness (FA3), class-EXPRESSION sibling: the class-expression
    property path must bundle the class decorator via `_decoratorTexts(classExpr,
    prop)`, matching its method sibling."""
    repo, fp = _write(
        tmp_path,
        "pr146_classexpr_decorated_arrow_prop",
        "module.exports = @Controller('cats') class CatsController {\n"
        "  @Get()\n"
        "  findAll = (req, res) => {\n"
        "    return res.send('all cats');\n"
        "  };\n"
        "};\n",
    )
    out = _analyze(repo, fp)
    fn = next(
        (v for k, v in out["functions"].items() if k.endswith(":CatsController.findAll")),
        None,
    )
    assert fn is not None, (
        f"class-expression decorated arrow property must be emitted; "
        f"got {list(out['functions'])}"
    )
    assert "@Controller('cats')" in fn["decorators"], (
        f"class-expression class-level decorator must be bundled onto the property "
        f"unit; got {fn['decorators']}"
    )
    assert "@Get()" in fn["decorators"], fn["decorators"]
