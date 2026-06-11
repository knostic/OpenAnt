"""Tests for the JS analyzer schema contract.

The analyzer must emit the snake_case `call_graph` / `reverse_call_graph`
(resolved id lists), `repository`, and per-function `parameters` — the same
contract the C/Python/Ruby sibling parsers satisfy. A pipeline-level test
confirms a non-entry reachable function survives the reachability filter.

Skips when Node.js or the parser's npm dependencies aren't installed.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


PARSERS_JS_DIR = Path(__file__).parent.parent.parent.parent / "parsers" / "javascript"
CORE_ROOT = Path(__file__).parent.parent.parent.parent
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


def test_analyzer_emits_snake_case_graphs(tmp_path):
    repo, fp = _write(
        tmp_path,
        "sb5_graphs",
        "function a(){ b(); }\nfunction b(){ return 1; }\n",
    )
    out = _analyze(repo, fp)
    assert "call_graph" in out, "analyzer must emit snake_case call_graph"
    assert "reverse_call_graph" in out, "analyzer must emit reverse_call_graph"
    assert out["call_graph"]["file.js:a"] == ["file.js:b"], (
        f"call_graph must list resolved callee ids; got {out['call_graph']}"
    )
    assert out["reverse_call_graph"].get("file.js:b") == ["file.js:a"], (
        f"reverse_call_graph must list resolved caller ids; got {out['reverse_call_graph']}"
    )


def test_analyzer_emits_repository(tmp_path):
    repo, fp = _write(tmp_path, "sb5_repo", "function a(){ return 1; }\n")
    out = _analyze(repo, fp)
    assert out.get("repository"), "analyzer must emit a repository path"


def test_analyzer_emits_parameters(tmp_path):
    repo, fp = _write(
        tmp_path,
        "sb5_params",
        "function add(x, y){ return x + y; }\n",
    )
    out = _analyze(repo, fp)
    fn = out["functions"]["file.js:add"]
    assert "parameters" in fn, "each function must carry a parameters list"
    assert fn["parameters"] == ["x", "y"], (
        f"parameters must list the parameter names; got {fn.get('parameters')}"
    )


def test_reachability_keeps_non_entry_callee(tmp_path):
    """Pipeline-level: a function reachable only as a callee of an entry point
    must survive the reachability filter, which depends on the analyzer's
    reverse_call_graph being populated."""
    repo, fp = _write(
        tmp_path,
        "sb5_reach",
        """
const express = require('express');
const app = express();
function helper(){ return 1; }
app.get('/x', (req, res) => { res.json(helper()); });
module.exports = app;
""",
    )
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    parser_script = PARSERS_JS_DIR / "test_pipeline.py"
    cmd = [
        sys.executable, str(parser_script),
        str(repo),
        "--output", str(output_dir),
        "--processing-level", "reachable",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=str(CORE_ROOT))
    assert result.returncode == 0, (
        f"pipeline failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )

    dataset = json.loads((output_dir / "dataset.json").read_text())
    ids = {u["id"] for u in dataset["units"]}
    assert any(uid.endswith(":helper") for uid in ids), (
        f"non-entry callee `helper` must survive reachability; surviving ids={ids}"
    )
