"""Regression: context_assembler must not omit .mjs/.cjs (silent edge drop).

context_assembler.js's source-discovery glob (findSourceFiles, ~:87) and its import-resolution extension
lists (~:322, ~:465) only cover .js/.ts/.jsx/.tsx — never .mjs/.cjs. So ESM (.mjs) / CommonJS (.cjs) modules are
never loaded into the TypeScript program (getSourceFile -> undefined) and imports targeting them are silently
unresolved. The sibling repository_scanner.js already includes .mjs/.cjs in its sourceExtensions. Fix: add
.mjs/.cjs to the discovery glob and the resolution extension lists.

This drives the discovery root via the exported ContextAssembler.findSourceFiles (a .mjs/.cjs file must be
discovered). Skips portably where the JS parser's node deps aren't installed.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

PARSERS_JS_DIR = Path(__file__).parent.parent / "parsers" / "javascript"
NODE_MODULES = PARSERS_JS_DIR / "node_modules"

pytestmark = pytest.mark.skipif(
    not shutil.which("node") or not NODE_MODULES.exists(),
    reason="Node.js or JS parser npm dependencies not available",
)


def test_findsourcefiles_discovers_mjs_and_cjs(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.js").write_text("export {};\n")
    (repo / "esm.mjs").write_text("export const x = 1;\n")
    (repo / "cjs.cjs").write_text("module.exports = {};\n")

    ca_path = str(PARSERS_JS_DIR / "context_assembler.js")
    script = (
        "const {ContextAssembler}=require(%r);"
        "const path=require('path');"
        "const ca=new ContextAssembler(%r);"
        "const f=ca.findSourceFiles(%r);"
        "console.log(JSON.stringify(f.map(p=>path.basename(p))));"
    ) % (ca_path, str(repo), str(repo))

    r = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"node failed: {r.stderr}"
    found = json.loads(r.stdout.strip().splitlines()[-1])
    assert "esm.mjs" in found, f".mjs not discovered (discovery glob omits it): {found}"
    assert "cjs.cjs" in found, f".cjs not discovered (discovery glob omits it): {found}"
    assert "main.js" in found  # control: .js still discovered
