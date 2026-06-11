"""Tests for unit_generator.js functionId parsing.

A functionId has the shape "<filePath>:<functionName>" where the SEPARATOR is
the FIRST colon (this is the contract the dependency_resolver enforces with
`funcId.split(':')[0]`). The functionName itself may contain colons, e.g. an
Express route id like "src/r.ts:express(GET:/items/:id)".

unit_generator.js previously split on the LAST colon (`lastIndexOf(':')`), which
mangled both filePath and functionName for any multi-colon id. These tests drive
UnitGenerator.generateUnits via a node subprocess on a synthetic analyzer output
whose `functions` dict carries a multi-colon id, and assert the recovered
file_path is correct.

Skips when Node.js or the parser's npm dependencies aren't installed.
"""
import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest


PARSERS_JS_DIR = Path(__file__).parent.parent.parent.parent / "parsers" / "javascript"
NODE_MODULES = PARSERS_JS_DIR / "node_modules"

pytestmark = pytest.mark.skipif(
    not shutil.which("node") or not NODE_MODULES.exists(),
    reason="Node.js or JS parser npm dependencies not available",
)


def _generate_units(tmp_path, analyzer_output):
    """Run UnitGenerator.generateUnits(analyzer_output) via node and return the result dict."""
    out_json = tmp_path / "analyzer_output.json"
    out_json.write_text(json.dumps(analyzer_output))
    driver = tmp_path / "driver.js"
    driver.write_text(
        textwrap.dedent(
            f"""
            const fs = require('fs');
            const {{ UnitGenerator }} = require({json.dumps(str(PARSERS_JS_DIR / "unit_generator.js"))});
            const analyzerOutput = JSON.parse(fs.readFileSync({json.dumps(str(out_json))}, 'utf8'));
            const gen = new UnitGenerator('/repo', 'testds', {{ maxDepth: 1 }});
            const result = gen.generateUnits(analyzerOutput, null);
            process.stdout.write(JSON.stringify(result));
            """
        )
    )
    proc = subprocess.run(
        ["node", str(driver)], capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0, f"driver failed:\nstdout={proc.stdout}\nstderr={proc.stderr}"
    return json.loads(proc.stdout)


def test_multi_colon_function_id_recovers_file_path(tmp_path):
    """A multi-colon Express functionId must recover the true file path
    (everything before the FIRST colon), not be mangled by last-colon split.

    Regression guard: unit_generator.js used lastIndexOf(':'),
    so "src/r.ts:express(GET:/items/:id)" produced file_path
    "src/r.ts:express(GET:/items/" instead of "src/r.ts".
    """
    func_id = "src/r.ts:express(GET:/items/:id)"
    analyzer_output = {
        "functions": {
            func_id: {
                "name": "express(GET:/items/:id)",
                "code": "function(req,res){ return res.send('ok'); }",
                "startLine": 42,
                "endLine": 44,
            }
        },
        "classes": {},
        "callGraph": {},
    }
    result = _generate_units(tmp_path, analyzer_output)
    units = result["units"]
    assert len(units) == 1, f"expected 1 unit, got {len(units)}"
    file_path = units[0]["code"]["primary_origin"]["file_path"]
    assert file_path == "src/r.ts", (
        f"multi-colon id file_path must be 'src/r.ts' (first-colon split), "
        f"got {file_path!r}"
    )


def test_single_colon_function_id_still_parses(tmp_path):
    """The common single-colon id must still parse correctly (no regression)."""
    func_id = "src/util.ts:helper"
    analyzer_output = {
        "functions": {
            func_id: {
                "name": "helper",
                "code": "function helper(){ return 1; }",
                "startLine": 1,
                "endLine": 1,
            }
        },
        "classes": {},
        "callGraph": {},
    }
    result = _generate_units(tmp_path, analyzer_output)
    file_path = result["units"][0]["code"]["primary_origin"]["file_path"]
    assert file_path == "src/util.ts", f"single-colon file_path wrong: {file_path!r}"
