"""Regression (PR134): single-function mode crashed on a standalone function.

`extractSingleFunction` is a top-level function (no analyzer `this`), but its
path-2 standalone-function lookup called `this._moduleLevelFunctionNodes(...)`.
For a bare function ref (no class) path 1 is skipped and control reaches path 2,
where `this` is undefined -> `TypeError`, so `node typescript_analyzer.js <file>
<func>` exited non-zero and emitted no function.
"""
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


def _extract_single(tmp_path, source, func_ref, filename="a.js"):
    fp = tmp_path / filename
    fp.write_text(source)
    cmd = ["node", str(PARSERS_JS_DIR / "typescript_analyzer.js"), str(fp), func_ref]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60)


def test_single_function_module_level_block_scoped(tmp_path):
    # a module-level block-scoped function requested by bare name -> path 2
    src = "if (globalThis.flag) {\n  function target() { return 42; }\n}\n"
    res = _extract_single(tmp_path, src, "target")
    assert res.returncode == 0, f"single-function mode crashed:\n{res.stderr}"
    assert "target" in res.stdout
