"""The reachability boundary that keeps the JS parser's glob matcher unused.

The JS parser depends on ``ts-morph``, whose ``@ts-morph/common`` requires
``minimatch``, which in turn requires ``brace-expansion``. That is the ONLY
path to either package in this parser's dependency graph (verified from
``package-lock.json``: ``@ts-morph/common -> minimatch -> brace-expansion``,
and nothing else depends on either).

The parser never asks ts-morph to match a path against a pattern: it adds
source files by exact path (``addSourceFileAtPath``) from a list the Python
side supplies. So the matcher is present on disk but never invoked, and an
advisory against it is not reachable through this parser.

That property is a function of HOW the parser calls ts-morph, not of what it
depends on -- so it is invisible to dependency tooling and one future
glob-bearing call would silently re-arm it. These tests pin it.

Two layers, deliberately:

1. A DYNAMIC probe (primary) -- instrument ``minimatch`` and run the real
   analyzer on a fixture, asserting zero invocations. It is immune to how the
   call is spelled, and it carries a POSITIVE CONTROL so a probe that silently
   stopped working cannot pass as "zero calls".
2. A STATIC scan (secondary) -- the glob-bearing ts-morph entry points. It
   needs no Node, so it still guards the boundary wherever the dynamic probe
   skips.
"""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

_JS_PARSER_DIR = Path(__file__).resolve().parents[1] / "parsers" / "javascript"
_ANALYZER = _JS_PARSER_DIR / "typescript_analyzer.js"

# ts-morph entry points that take a glob (or a tsconfig, which ts-morph
# expands with one). Each is a way to hand ts-morph a PATTERN instead of an
# exact path, which is what reaches minimatch.
_GLOB_BEARING_RULES = {
    # getSourceFiles() with no argument is fine: it returns the files already
    # added. getSourceFiles(pattern) filters them through minimatch.
    "getSourceFiles(<pattern>)": r"\.getSourceFiles\s*\(\s*(?!\s*\))",
    "addSourceFilesAtPaths()": r"\baddSourceFilesAtPaths\s*\(",
    "useInMemoryFileSystem": r"\buseInMemoryFileSystem\b",
    "tsConfigFilePath": r"\btsConfigFilePath\b",
    "glob()/globSync()": r"\.glob(Sync)?\s*\(",
    "direct require of the matcher": (
        r"require\(\s*['\"](minimatch|brace-expansion)['\"]\s*\)"
    ),
}

_PROBE_JS = """
// Count invocations of minimatch, not requires of it: @ts-morph/common
// requires minimatch eagerly at module load, so a require-counting probe
// would always fire. The namespace @ts-morph/common builds over the module
// uses live getters, so replacing the export here is visible at its call
// sites even though it loads later.
const fs = require('fs');
const out = process.env.OPENANT_MINIMATCH_PROBE_OUT;
const dir = process.env.OPENANT_MINIMATCH_PROBE_DIR;
let calls = 0;
try {
  const mm = require(require.resolve('minimatch', { paths: [dir] }));
  const orig = mm.minimatch;
  if (typeof orig !== 'function') {
    throw new Error('minimatch export is not a function');
  }
  mm.minimatch = function (...a) { calls += 1; return orig.apply(this, a); };
  process.on('exit', () => {
    try { fs.writeFileSync(out, String(calls)); } catch (e) {}
  });
} catch (e) {
  try { fs.writeFileSync(out, 'PROBE-ERROR: ' + e.message); } catch (e2) {}
}
"""

_CONTROL_JS = """
// Positive control: a glob-bearing ts-morph call. If instrumenting minimatch
// ever stops working, THIS test fails and the zero-call assertion in the
// companion test is correctly no longer trusted.
const dir = process.env.OPENANT_MINIMATCH_PROBE_DIR;
const { Project } = require(require.resolve('ts-morph', { paths: [dir] }));
const p = new Project({ compilerOptions: { allowJs: true, noResolve: true } });
p.addSourceFileAtPath(process.argv[2]);
p.getSourceFiles("**/*.ts");
"""

_FIXTURE_TS = """export function greet(name: string): string {
  return "hi " + name;
}
export function callsGreet(): string {
  return greet("world");
}
"""


def _require_node_and_deps():
    """Skip unless Node and the parser's installed matcher are both present."""
    if shutil.which("node") is None:
        pytest.skip("node is not on PATH")
    if not _ANALYZER.is_file():
        pytest.skip(f"analyzer not found at {_ANALYZER}")
    if not (_JS_PARSER_DIR / "node_modules" / "minimatch").is_dir():
        pytest.skip("JS parser dependencies are not installed (npm install not run)")


def _probe_env(tmp_path: Path, count_file: Path) -> dict:
    probe = tmp_path / "minimatch_probe.js"
    probe.write_text(_PROBE_JS)
    env = dict(os.environ)
    env["OPENANT_MINIMATCH_PROBE_OUT"] = str(count_file)
    env["OPENANT_MINIMATCH_PROBE_DIR"] = str(_JS_PARSER_DIR)
    # Inherited by the node process the analyzer runs in.
    env["NODE_OPTIONS"] = f"--require {probe}"
    return env


def _read_count(count_file: Path) -> int:
    assert count_file.is_file(), (
        "the probe wrote no count -- it never ran, so no conclusion can be "
        "drawn about minimatch"
    )
    raw = count_file.read_text().strip()
    assert not raw.startswith("PROBE-ERROR"), f"the probe failed to install: {raw}"
    return int(raw)


def test_probe_is_live_a_glob_bearing_call_reaches_minimatch(tmp_path):
    """POSITIVE CONTROL for the test below.

    A deliberately glob-bearing ts-morph call must be SEEN by the probe. This
    is what makes the companion test's "zero calls" meaningful rather than
    just "the probe is broken".
    """
    _require_node_and_deps()

    fixture = tmp_path / "a.ts"
    fixture.write_text(_FIXTURE_TS)
    control = tmp_path / "control.js"
    control.write_text(_CONTROL_JS)
    count_file = tmp_path / "control_count.txt"

    result = subprocess.run(
        ["node", str(control), str(fixture)],
        env=_probe_env(tmp_path, count_file),
        capture_output=True, text=True, timeout=300,
    )
    assert result.returncode == 0, f"control failed: {result.stderr}"

    assert _read_count(count_file) >= 1, (
        "a glob-bearing ts-morph call did NOT reach minimatch -- the probe no "
        "longer detects the thing it exists to detect, so the zero-call "
        "assertion in the companion test proves nothing"
    )


def test_real_parser_run_makes_no_minimatch_calls(tmp_path):
    """THE GUARD: a real analyzer run must not invoke the glob matcher.

    Runs the analyzer exactly as the pipeline does
    (``node typescript_analyzer.js <repo> --files-from <list> --output <out>``)
    and asserts zero minimatch invocations -- while also asserting the run did
    real work, so a parser that crashed early cannot pass this by doing
    nothing.
    """
    _require_node_and_deps()

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.ts").write_text(_FIXTURE_TS)
    file_list = tmp_path / "files.txt"
    file_list.write_text(str(repo / "a.ts") + "\n")
    out_file = tmp_path / "analyzer_output.json"
    count_file = tmp_path / "parse_count.txt"

    result = subprocess.run(
        ["node", str(_ANALYZER), str(repo),
         "--files-from", str(file_list), "--output", str(out_file)],
        env=_probe_env(tmp_path, count_file),
        capture_output=True, text=True, timeout=600,
    )
    assert result.returncode == 0, (
        f"analyzer failed: {result.stderr[-2000:]}"
    )

    # NOT VACUOUS: the parse must actually have analysed the fixture, or
    # "zero minimatch calls" would be true of any no-op.
    assert out_file.is_file(), "analyzer produced no output file"
    analyzed = json.loads(out_file.read_text())
    functions = analyzed.get("functions") or {}
    assert len(functions) >= 2, (
        f"the analyzer did not do real work (functions={len(functions)}); "
        "the zero-call result would be vacuous"
    )

    calls = _read_count(count_file)
    assert calls == 0, (
        f"a real parse made {calls} minimatch call(s). The parser is expected "
        "to add source files by EXACT path (addSourceFileAtPath) from the "
        "supplied file list; a glob-bearing call makes minimatch and "
        "brace-expansion reachable from this parser. If the new call is "
        "intended, that reachability is now real and must be assessed."
    )


def test_parser_sources_contain_no_glob_bearing_calls():
    """STATIC layer: no glob-bearing ts-morph entry point in the parser.

    Runs without Node, so the boundary stays guarded wherever the dynamic
    probe skips (no toolchain, dependencies not installed).

    Two KNOWN HOLES, which are why the dynamic probe above is the primary
    layer and this one is secondary:

    * **multiline no-arg calls** -- the ``getSourceFiles`` rule distinguishes
      ``getSourceFiles()`` from ``getSourceFiles(pattern)`` by looking ahead
      for the closing paren. Scanning whole-file text handles a newline
      between them, but a comment there (``getSourceFiles(/* none */)``)
      reads as an argument and would be a false POSITIVE.
    * **aliasing forms** -- ``const g = p.getSourceFiles; g(pattern)``,
      ``p["getSourceFiles"](pattern)``, a pattern reaching ts-morph through a
      variable or helper, or a computed ``require()``. Textual scanning
      cannot see any of these; only the dynamic probe can.
    """
    sources = sorted(_JS_PARSER_DIR.glob("*.js"))
    assert sources, f"no parser sources found under {_JS_PARSER_DIR}"

    offenders = []
    for path in sources:
        text = path.read_text(encoding="utf-8", errors="replace")
        for label, pattern in _GLOB_BEARING_RULES.items():
            for match in re.finditer(pattern, text):
                line = text.count("\n", 0, match.start()) + 1
                offenders.append(f"{path.name}:{line}: {label} -> {match.group(0)!r}")

    assert not offenders, (
        "glob-bearing ts-morph call(s) introduced in the JS parser:\n  "
        + "\n  ".join(offenders)
        + "\n\nThese make minimatch (and brace-expansion) reachable from the "
        "parser. The parser adds source files by exact path from the file "
        "list the Python side supplies; if a pattern-based call is genuinely "
        "needed, the reachability it creates must be assessed rather than "
        "this test relaxed."
    )
