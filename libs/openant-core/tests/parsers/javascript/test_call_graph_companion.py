"""Tests for the call-graph/functions companion invariant.

Every function the analyzer emits into `functions` must also have a key in
`callGraph` (Pattern-A emit-without-companion).

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


def test_module_exports_property_has_companion(tmp_path):
    """module.exports.fn = function(){} must appear in callGraph too."""
    repo, fp = _write(
        tmp_path,
        "sb3_commonjs",
        "module.exports.userSearch = function (req, res) { return doThing(); };\n"
        "function doThing(){ return 1; }\n",
    )
    out = _analyze(repo, fp)
    funcs = set(out["functions"])
    graph = set(out["callGraph"])
    missing = funcs - graph
    assert not missing, f"functions without callGraph companion: {missing}"
    assert len(out["callGraph"]) == len(out["functions"])


def test_all_emit_paths_have_companions(tmp_path):
    """Object-literal exports, prototype assignments and class-expression
    methods must each get a callGraph companion."""
    repo, fp = _write(
        tmp_path,
        "sb3_mixed",
        """
function Foo(){}
Foo.prototype.bar = function(){ return helper(); };
function helper(){ return 1; }
module.exports = { util: () => doThing() };
function doThing(){ return 2; }
const Svc = class { run(){ return helper(); } };
""",
    )
    out = _analyze(repo, fp)
    funcs = set(out["functions"])
    graph = set(out["callGraph"])
    missing = funcs - graph
    assert not missing, f"functions without callGraph companion: {missing}"
    assert len(out["callGraph"]) == len(out["functions"])
