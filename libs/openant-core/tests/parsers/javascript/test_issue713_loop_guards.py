"""Regression locks: one pathological JS/TS file must not abort the whole repo's parse (#713).

`TypeScriptAnalyzer.analyzeFiles` guards only Step 1 (the file-adding loop). Steps 2 and 3
-- extraction and call-graph building -- were bare, and the only catch above them is the
CLI's outer handler, which prints and `process.exit(1)`. So a single file throwing during
the ts-morph tree walk (a `RangeError` from a deeply nested source, or any extractor bug)
took the entire repository's JS/TS unit inventory to zero: a total false negative for the
language on that repo, reported as a parse failure rather than as a skipped file.

The Python / C / Ruby / PHP extractors all degrade instead -- count the file in
`files_with_errors`, warn on stderr, continue (`_process_file_guarded`, PR #136 / #170).
This ports that contract to the JS analyzer, which is implemented in JavaScript and so
never received it.

These tests drive the real entry points: the production CLI (`--files-from` / `--output`,
the shape `parsers/javascript/test_pipeline.py::run_typescript_analyzer` uses) for the
real-file witnesses, and `analyzeFiles` itself for the injected ones.

Skips when Node.js or the parser's npm dependencies aren't installed.
"""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


PARSERS_JS_DIR = Path(__file__).parent.parent.parent.parent / "parsers" / "javascript"
ANALYZER = PARSERS_JS_DIR / "typescript_analyzer.js"
NODE_MODULES = PARSERS_JS_DIR / "node_modules"

pytestmark = pytest.mark.skipif(
    not shutil.which("node") or not NODE_MODULES.exists(),
    reason="Node.js or JS parser npm dependencies not available",
)

# A file whose tree walk overflows V8's stack -> RangeError, raised AFTER the file is
# successfully added to the project (so Step 1's existing guard never sees it). A long
# binary-operator chain: `return 1+1+...+1;`. Measured at the fix base: `addSourceFileAtPath`
# succeeds, `extractFunctionsFromFile` and `buildCallGraphForFile` both throw, and the
# sibling file in the same project still extracts cleanly -- which is what makes this a
# per-file-isolation witness rather than a whole-program one (see
# test_deep_member_chain_degrades_instead_of_aborting for the shape where it is not).
_STACK_BLOWER = "function deep(){ return " + "1+" * 50000 + "1; }\n"

# A deep MEMBER-ACCESS chain overflows while the TypeScript binder walks the shared
# program, so it is not isolable per file -- every file's extraction throws. Kept as its
# own witness because the promise it falsifies is the weaker one: degrade, never abort.
_PROGRAM_BLOWER = "function deep(){ return a" + ".b" * 20000 + "; }\n"

_GOOD = "function alpha(x){ return beta(x); }\nfunction beta(y){ return y + 1; }\n"


def _repo(tmp_path, name, files):
    repo = tmp_path / name
    repo.mkdir(parents=True, exist_ok=True)
    for fname, src in files.items():
        (repo / fname).write_text(src)
    return repo


def _run_cli(tmp_path, repo, names):
    """Drive the analyzer exactly as the production pipeline does: a file list plus
    --output. Returns (CompletedProcess, parsed output or None)."""
    listing = tmp_path / f"{repo.name}_files.txt"
    listing.write_text("".join(f"{repo / n}\n" for n in names))
    out = tmp_path / f"{repo.name}_analyzer.json"
    proc = subprocess.run(
        ["node", str(ANALYZER), str(repo), "--files-from", str(listing), "--output", str(out)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    parsed = json.loads(out.read_text()) if out.exists() else None
    return proc, parsed


_DRIVER = """
// Drive analyzeFiles with a throw injected into one stage for exactly one file, then
// print the observable result. Mirrors the injected-crash template the Python extractor's
// robustness suite uses (tests/parsers/python/test_function_extractor_robustness.py):
// relying on a pathological fixture alone makes the test vacuous wherever the fixture
// stops being pathological.
const path = require("path");
const [analyzerPath, repoPath, stage, victim, ...files] = process.argv.slice(2);
const { TypeScriptAnalyzer } = require(analyzerPath);
const a = new TypeScriptAnalyzer(repoPath);
const method = stage === "extraction" ? "extractFunctionsFromFile" : "buildCallGraphForFile";
const orig = a[method].bind(a);
a[method] = function (sourceFile) {
  if (sourceFile.getFilePath().endsWith(victim)) {
    throw new RangeError("injected: Maximum call stack size exceeded");
  }
  return orig(sourceFile);
};
let payload;
try {
  const r = a.analyzeFiles(files.map((f) => path.join(repoPath, f)));
  payload = {
    escaped: null,
    functions: Object.keys(r.functions || {}).sort(),
    call_graph_keys: Object.keys(r.callGraph || {}).sort(),
    statistics: r.statistics || null,
  };
} catch (e) {
  payload = { escaped: `${e.constructor.name}: ${e.message}` };
}
console.log(JSON.stringify(payload));
"""


def _run_injected(tmp_path, repo, stage, victim, names):
    driver = tmp_path / f"{repo.name}_{stage}_driver.js"
    driver.write_text(_DRIVER)
    proc = subprocess.run(
        ["node", str(driver), str(ANALYZER), str(repo), stage, victim, *names],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, f"driver failed:\nstdout={proc.stdout}\nstderr={proc.stderr}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_pathological_file_does_not_abort_the_repo_parse(tmp_path):
    """A real deeply-nested file must cost its own units, not the repository's."""
    repo = _repo(tmp_path, "i713_cli", {"good.js": _GOOD, "deep.js": _STACK_BLOWER})
    proc, out = _run_cli(tmp_path, repo, ["good.js", "deep.js"])
    assert proc.returncode == 0, (
        "one pathological file aborted the whole parse "
        f"(rc={proc.returncode}); stderr={proc.stderr[-800:]}"
    )
    assert out is not None, "no analyzer output written -- the parse died"
    assert "good.js:alpha" in out["functions"], (
        f"the good file's units were lost; got {sorted(out['functions'])}"
    )
    # Bucket assignment, not just the sum: the crashed file must land in
    # files_with_errors and must NOT also be counted as processed.
    stats = out["statistics"]
    assert stats["files_with_errors"] == 1, f"crashed file not recorded once: {stats}"
    assert stats["files_processed"] == 1, f"crashed file mislabeled as processed: {stats}"
    assert "failed to process" in proc.stderr, "the per-file failure was never reported"
    # And the ONE loud summary line. Without it a degraded parse (which now exits 0)
    # is indistinguishable from a repo with no JS files: core/parser_adapter.py books
    # a 0-unit parse as success and emits no advisory of its own.
    assert "Files with errors: 1 of 2" in proc.stderr, (
        f"no summary line for the degraded parse; stderr={proc.stderr[-800:]}"
    )


def test_extraction_throw_is_isolated_and_bucketed(tmp_path):
    """Step 2's guard, exercised deterministically by injection."""
    repo = _repo(tmp_path, "i713_extract", {"good.js": _GOOD, "boom.js": "function one(){ return two(); }\nfunction two(){ return 2; }\n"})
    res = _run_injected(tmp_path, repo, "extraction", "boom.js", ["good.js", "boom.js"])
    assert res["escaped"] is None, f"the throw escaped analyzeFiles: {res['escaped']}"
    assert "good.js:alpha" in res["functions"], f"units lost: {res['functions']}"
    assert res["statistics"] == {"files_processed": 1, "files_with_errors": 1}, res["statistics"]
    # A file whose extraction failed must not acquire call-graph keys: `functions` never
    # received its ids, so building its edges would fabricate units the inventory does
    # not contain and break the len(callGraph) == len(functions) lockstep.
    phantom = set(res["call_graph_keys"]) - set(res["functions"])
    assert not phantom, f"call-graph keys with no function: {sorted(phantom)}"
    assert len(res["call_graph_keys"]) == len(res["functions"])


def test_call_graph_throw_is_isolated_and_bucketed(tmp_path):
    """Step 3's guard: the file keeps its units and loses only its edges."""
    repo = _repo(tmp_path, "i713_graph", {"good.js": _GOOD, "boom.js": "function one(){ return two(); }\nfunction two(){ return 2; }\n"})
    res = _run_injected(tmp_path, repo, "call_graph", "boom.js", ["good.js", "boom.js"])
    assert res["escaped"] is None, f"the throw escaped analyzeFiles: {res['escaped']}"
    assert "good.js:alpha" in res["functions"], f"units lost: {res['functions']}"
    assert "boom.js:one" in res["functions"], (
        "a call-graph failure must not cost the file its already-extracted units; "
        f"got {res['functions']}"
    )
    assert res["statistics"] == {"files_processed": 1, "files_with_errors": 1}, res["statistics"]
    phantom = set(res["call_graph_keys"]) - set(res["functions"])
    assert not phantom, f"call-graph keys with no function: {sorted(phantom)}"
    assert len(res["call_graph_keys"]) == len(res["functions"])


def test_deep_member_chain_degrades_instead_of_aborting(tmp_path):
    """The weaker half of the promise, on the shape where isolation is impossible.

    A deep member-access chain overflows inside the TypeScript binder's walk of the
    SHARED program, so every file's extraction throws, not just the pathological one.
    The guard still converts a hard failure (exit 1, no output, the Python adapter
    raising RuntimeError and aborting the entire scan) into a reported, counted
    degradation (exit 0, analyzer output written, the failures in files_with_errors).
    This is a documented limitation, asserted rather than hidden: the surviving units
    are NOT recovered for this shape.
    """
    repo = _repo(tmp_path, "i713_program", {"good.js": _GOOD, "deep.js": _PROGRAM_BLOWER})
    proc, out = _run_cli(tmp_path, repo, ["good.js", "deep.js"])
    assert proc.returncode == 0, (
        f"the analyzer aborted instead of degrading (rc={proc.returncode}); "
        f"stderr={proc.stderr[-800:]}"
    )
    assert out is not None, "no analyzer output written -- the parse died"
    stats = out["statistics"]
    assert stats["files_with_errors"] >= 1, f"the degradation was never recorded: {stats}"
    assert stats["files_processed"] + stats["files_with_errors"] == 2, stats
    assert f"Files with errors: {stats['files_with_errors']} of 2" in proc.stderr, (
        "a whole-program overflow degraded SILENTLY -- exit 0 with no summary is the "
        f"shape that reads as 'no JS in this repo'; stderr={proc.stderr[-800:]}"
    )


def test_step1_add_failure_counts_in_files_with_errors(tmp_path):
    """F1 (fable T1 r1): a file that cannot be ADDED to the project is an error, not an absence.

    Step 1 (`addSourceFileAtPath`) was already guarded, but its failures were invisible to
    the output: the file never enters the project, so the old denominator (the final
    source-file count) could not count it, and `statistics.files_with_errors` asserted a
    FALSE ZERO. The Python sibling counts read failures in the same bucket
    (`function_extractor.py` `_process_file_guarded`); this locks the same contract for
    Step 1 here. Worst case without it: a repo whose every file fails to add parses to
    exit 0 with `{files_processed: 0, files_with_errors: 0}` -- indistinguishable from a
    repo with no JS at all.
    """
    repo = _repo(tmp_path, "step1_bucket", {"good.js": _GOOD})
    locked = repo / "locked.js"
    locked.write_text(_GOOD)
    locked.chmod(0o000)
    try:
        # Windows chmod() only toggles the read-only flag (all other bits are
        # ignored), so the file stays readable and the EACCES path never fires;
        # the same is true under root. Same guard as test_scanner_contract.py.
        if os.access(locked, os.R_OK):
            pytest.skip("running as root or on a platform without enforced read permissions")
        proc, out = _run_cli(tmp_path, repo, ["good.js", "locked.js"])
    finally:
        locked.chmod(0o644)

    assert proc.returncode == 0, proc.stderr
    assert out is not None
    # The good file's units survive...
    assert "good.js:alpha" in out["functions"]
    # ...and the locked file is booked as an error, with the honest denominator
    # (the distinct input list, not the surviving source-file count).
    assert out["statistics"]["files_with_errors"] == 1
    assert out["statistics"]["files_processed"] == 1
    # The loud summary line fires for Step-1 failures too, not only Step-2/3.
    assert "Files with errors: 1 of 2" in proc.stderr


def test_duplicate_and_aliased_inputs_count_once(tmp_path):
    """F4/F5 (fable T1 r2/r3): the denominator is the DISTINCT resolved input set.

    A list that repeats a file -- verbatim, via `..`, or via `//` -- must not
    inflate `files_processed` (ts-morph keys the project by resolved path, so
    the file is parsed once; the statistics must agree). Locks the dedup so a
    revert to the raw `.length` denominator fails here.
    """
    repo = _repo(tmp_path, "alias_dedupe", {"good.js": _GOOD})
    (repo / "sub").mkdir()
    good = repo / "good.js"
    sep = os.sep

    proc, out = _run_cli(
        tmp_path,
        repo,
        [
            "good.js",
            str(good),
            f"sub{sep}..{sep}good.js",
            f"{good.parent}{sep}{sep}good.js",
        ],
    )

    assert proc.returncode == 0, proc.stderr
    assert out is not None
    assert "good.js:alpha" in out["functions"]
    assert out["statistics"]["files_with_errors"] == 0
    assert out["statistics"]["files_processed"] == 1
    assert "Files with errors" not in proc.stderr


def test_step1_missing_file_counts_in_files_with_errors(tmp_path):
    """The Step-1 bucket on every platform: a file that does not exist.

    The chmod witness above is skipped on Windows (chmod() there only toggles
    the read-only flag) and under root; this one exercises the SAME Step-1
    catch -- addSourceFileAtPath throwing, the file never entering the
    project -- with no platform dependency at all.
    """
    repo = _repo(tmp_path, "step1_missing", {"good.js": _GOOD})

    proc, out = _run_cli(tmp_path, repo, ["good.js", "nope.js"])

    assert proc.returncode == 0, proc.stderr
    assert out is not None
    assert "good.js:alpha" in out["functions"]
    assert out["statistics"]["files_with_errors"] == 1
    assert out["statistics"]["files_processed"] == 1
    assert "Files with errors: 1 of 2" in proc.stderr
