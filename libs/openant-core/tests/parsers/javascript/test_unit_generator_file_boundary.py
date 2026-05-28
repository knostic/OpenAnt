"""Tests for FILE_BOUNDARY module-level export parity in the JS unit generator.

The JavaScript parser declared FILE_BOUNDARY as a
function-local `const` inside `_assembleEnhancedCode` and never exported it,
unlike the python/php/c/ruby parsers which expose it as a module-level constant
(python/unit_generator.py:60, php/c/ruby :35). That made the canonical boundary
marker un-importable and risked silent drift across language parsers.

These exercise the JS module's exports by running Node.js as a subprocess
(mirroring tests/parsers/javascript/test_express_route_handlers.py). They skip
when Node.js or the parser's npm dependencies aren't installed.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest


PARSERS_JS_DIR = Path(__file__).parent.parent.parent.parent / "parsers" / "javascript"
NODE_MODULES = PARSERS_JS_DIR / "node_modules"
UNIT_GENERATOR_JS = PARSERS_JS_DIR / "unit_generator.js"

# Canonical boundary marker shared with the python/php/c/ruby parsers.
# (Comment syntax differs by language: JS/PHP/C/Zig use `//`, python/ruby use `#`.)
EXPECTED_FILE_BOUNDARY = "\n\n// ========== File Boundary ==========\n\n"

pytestmark = pytest.mark.skipif(
    not shutil.which("node") or not NODE_MODULES.exists(),
    reason="Node.js or JS parser npm dependencies not available",
)


def _require_exports() -> dict:
    """require() the module in Node and return its exports as JSON."""
    script = (
        f"const m = require({json.dumps(str(UNIT_GENERATOR_JS))});"
        "process.stdout.write(JSON.stringify({"
        "keys: Object.keys(m),"
        "fileBoundaryType: typeof m.FILE_BOUNDARY,"
        "fileBoundary: m.FILE_BOUNDARY === undefined ? null : m.FILE_BOUNDARY,"
        "}));"
    )
    result = subprocess.run(
        ["node", "-e", script], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, (
        f"node require() failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    return json.loads(result.stdout)


def test_FILE_BOUNDARY_exported():
    """FILE_BOUNDARY must be a module-level export (importable by other modules)."""
    exports = _require_exports()
    assert "FILE_BOUNDARY" in exports["keys"], (
        "FILE_BOUNDARY is not exported from unit_generator.js; "
        f"module.exports keys = {exports['keys']}"
    )


def test_FILE_BOUNDARY_is_string():
    """The exported FILE_BOUNDARY must be the canonical boundary marker string."""
    exports = _require_exports()
    assert exports["fileBoundaryType"] == "string", (
        f"FILE_BOUNDARY should be a string, got type {exports['fileBoundaryType']!r}"
    )
    assert exports["fileBoundary"] == EXPECTED_FILE_BOUNDARY, (
        f"FILE_BOUNDARY value mismatch: {exports['fileBoundary']!r}"
    )
