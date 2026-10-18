"""#801 end-to-end regression: the JavaScript scanner's exclusion
policy reaches PARITY with Python's — the hidden-directory RULE (not one
more literal name) and the test-file skipper's extension set closed over
the c-/m-prefixed forms.

At the base (``parsers/javascript/repository_scanner.js``) the two gaps
the campaign executed:

* the hidden-directory exclusion was a LITERAL LIST (``.git``, ``.svn``,
  ``.hg``, ``.next``, ``.cache``... — never ``.github``), while Python's
  scanner has had the RULE all along (``if dir_name.startswith('.'):
  return True``) — so ``.github/actions/*.cjs`` CI units landed in a paid
  kept set (five of them, whose checkpoints then became DOTFILES
  invisible to the ``glob("*.json")`` idiom — the 58,301-vs-58,306 gap).
  A rule cannot drift per-name; the list stays for the named non-hidden
  dirs (node_modules, dist, build...).
* the test-file skipper's pattern (``/\\.(test|spec)\\.[jt]sx?$/``)
  matched js|jsx|ts|tsx but not cjs/mjs — a one-character class gap, so
  ``.github/actions/check-pr-test-health/action.test.cjs`` (a CI test
  file) reached the kept set and was PAID for three runs.

The fix: ``dirName.startsWith('.')`` at ``shouldExcludeDirectory`` (the
rule, mirroring Python) and the extension set broadened to
``[jt]sx?|[cm]js`` (mirroring the scanner's own sourceExtensions list).

Hermetic: the CLI drive exactly as the production pipeline runs it
(``node repository_scanner.js <repo> --output <out> [--skip-tests]`` —
the same shape test_js_parser.py uses).

Shapes:

  S1 -- the WITNESS (red at base): a fixture repo with ``.github/`` and
        other dot-directories containing source files — the scan yields
        ZERO files from any dot-directory (at the base, five .github
        .cjs files are collected).
  S2 -- the WITNESS (red at base): ``.test.cjs`` / ``.spec.mjs`` /
        ``_test.cjs`` files are SKIPPED under ``--skip-tests`` (at the
        base, action.test.cjs is collected and the skipper misses it).
  S3 -- the CONTROL (green at base AND head): the named non-hidden
        exclusions keep working (node_modules, dist, build) and the
        ordinary source files keep being collected (src/app.js, a
        .test.js sibling skipped at both trees — the old pattern's
        coverage class).
  S4 -- the CONTROL (green at base AND head): Python's own parity — the
        same fixture shapes under the PYTHON scanner yield the same
        exclusion verdicts (the rule was always there; the parity now
        holds in both directions).
"""

import json
import subprocess
from pathlib import Path

PARSERS_JS_DIR = Path(__file__).resolve().parents[3] / "parsers" / "javascript"
SCANNER = PARSERS_JS_DIR / "repository_scanner.js"

# The prod file under test (the data-read route: a JS file cannot be a
# Python import; the C4 hunk-revert rows for this file — the S1/S2
# battery failing at the reverted==base state — are the load-bearing proof).
_PROD_HUNK = "parsers/javascript/repository_scanner.js"


def _build_repo(tmp_path):
    repo = tmp_path / "fx801"
    src = repo / "src"
    src.mkdir(parents=True)
    (src / "app.js").write_text("export function app() { return 1; }\n",
                                encoding="utf-8")
    (src / "app.test.js").write_text(
        "export function appTest() { return 2; }\n", encoding="utf-8")
    gh = repo / ".github" / "actions" / "check-pr-test-health"
    gh.mkdir(parents=True)
    # the campaign's exact shape: a CI test file that evaded both gaps
    (gh / "action.test.cjs").write_text(
        "function check() { return 3; }\nmodule.exports = { check };\n",
        encoding="utf-8")
    (repo / ".github" / "dependabot.yml").write_text("x: 1\n", encoding="utf-8")
    agents = repo / ".agents" / "tools"
    agents.mkdir(parents=True)
    (agents / "helper.cjs").write_text("module.exports = 1;\n",
                                       encoding="utf-8")
    nm = repo / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text("module.exports = 2;\n", encoding="utf-8")
    dist = repo / "dist"
    dist.mkdir()
    (dist / "bundle.js").write_text("module.exports = 3;\n", encoding="utf-8")
    (repo / "foo.spec.mjs").write_text("export const s = 1;\n",
                                       encoding="utf-8")
    (repo / "bar_test.cjs").write_text("module.exports = 4;\n",
                                       encoding="utf-8")
    # the campaign's exact extension+form THROUGH the test-skipper (not
    # inside a dot-dir, so the directory rule cannot mask a skipper gap)
    (repo / "baz.test.cjs").write_text("module.exports = 5;\n",
                                      encoding="utf-8")
    (repo / "qux.spec.cjs").write_text("module.exports = 6;\n",
                                       encoding="utf-8")
    (repo / "quux.test.mjs").write_text("export const q = 7;\n",
                                        encoding="utf-8")
    return repo


def _run_scanner(tmp_path, repo, skip_tests=True):
    out = tmp_path / f"scan_{repo.name}.json"
    cmd = ["node", str(SCANNER), str(repo), "--output", str(out)]
    if skip_tests:
        cmd.append("--skip-tests")
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    assert proc.returncode == 0, f"the scanner failed: {proc.stderr[-800:]}"
    result = json.loads(out.read_text())
    # the scanner emits OS-native separators on Windows (src\app.js);
    # every path assertion in this file is separator-agnostic via the
    # forward-slash normalization (the #713 convention)
    for f in result["files"]:
        f["path"] = f["path"].replace("\\", "/")
    return result


# ---------------------------------------------------------------------------
# S1 — the hidden-directory rule (the witness)
# ---------------------------------------------------------------------------

def test_no_dot_directory_file_is_collected(tmp_path):
    """S1: a JavaScript scan excludes dot-directories at PARITY with
    Python — the RULE (dirName.startsWith('.')), not a literal list. At
    the base the .github CI files were collected (the campaign: five
    .github/*.cjs units in a paid kept set; their checkpoints became
    dotfiles invisible to the glob idiom).
    The fix lives in parsers/javascript/repository_scanner.js — the file
    named by _PROD_HUNK."""
    assert _PROD_HUNK == "parsers/javascript/repository_scanner.js"
    repo = _build_repo(tmp_path)
    out = _run_scanner(tmp_path, repo)
    dot_files = [f["path"] for f in out["files"]
                 if any(part.startswith(".") for part in
                        Path(f["path"]).parts[:-1])]
    assert dot_files == [], (
        f"dot-directories are excluded BY RULE (the Python parity); "
        f"got {dot_files}")
    # the campaign's exact shapes are absent: .github and .agents
    paths = [f["path"] for f in out["files"]]
    assert not any(".github" in p for p in paths), paths
    assert not any(".agents" in p for p in paths), paths
    # the .agents twin by NAME too (the campaign's dotfile-checkpoint shape:
    # a dot-dir file reaching the output is the class, whichever dot-dir)
    assert not any(p.endswith("helper.cjs") for p in paths), paths


# ---------------------------------------------------------------------------
# S2 — the skipper's extension set (the witness)
# ---------------------------------------------------------------------------

def test_the_cjs_mjs_test_forms_are_skipped(tmp_path):
    """S2: the c-/m-prefixed test forms are SKIPPED under --skip-tests —
    .test.cjs (the campaign's exact extension+form), .spec.mjs,
    _test.cjs, .spec.cjs, .test.mjs. At the base the pattern [jt]sx?
    missed every c-/m-prefixed extension (a one-character class gap).
    NOTE the mechanism split: the root-level .test.cjs here exercises
    the SKIPPER; the campaign's .github/action.test.cjs is excluded by
    the DIRECTORY rule (S1) and never reaches the skipper — a
    skipper-only regression (cjs dropped from the pattern again) would
    survive a battery without this root-level form (the r1-F2 catch)."""
    repo = _build_repo(tmp_path)
    out = _run_scanner(tmp_path, repo)
    assert _PROD_HUNK == "parsers/javascript/repository_scanner.js"
    paths = [f["path"] for f in out["files"]]
    assert not any(p.endswith("action.test.cjs") for p in paths), (
        f"the CI test file must be skipped (the campaign's paid three "
        f"times); got {[p for p in paths if p.endswith('.cjs')]}")
    assert not any(p.endswith("foo.spec.mjs") for p in paths), paths
    assert not any(p.endswith("bar_test.cjs") for p in paths), paths
    # the root-level forms BY NAME (the r2-F3 catch: the count floor alone
    # kills the mutant but names no leaked path on regression)
    assert not any(p.endswith("baz.test.cjs") for p in paths), paths
    assert not any(p.endswith("qux.spec.cjs") for p in paths), paths
    assert not any(p.endswith("quux.test.mjs") for p in paths), paths
    # the skipper's own count sees them (the secondary check)
    assert out["statistics"]["testFilesSkipped"] >= 6, out["statistics"]


# ---------------------------------------------------------------------------
# S3 — the controls (green at base AND head)
# ---------------------------------------------------------------------------

def test_the_named_exclusions_and_ordinary_files_stay(tmp_path):
    """S3: the named non-hidden exclusions keep working (node_modules,
    dist) and the ordinary source files keep being collected; the old
    pattern's coverage class (.test.js) keeps being skipped at BOTH
    trees."""
    repo = _build_repo(tmp_path)
    out = _run_scanner(tmp_path, repo)
    paths = [f["path"] for f in out["files"]]
    assert not any("node_modules" in p for p in paths), paths
    assert not any(p.startswith("dist/") for p in paths), paths
    assert not any(p.endswith("app.test.js") for p in paths), paths
    assert any(p.endswith("src/app.js") for p in paths), paths


# ---------------------------------------------------------------------------
# S4 — the Python parity control
# ---------------------------------------------------------------------------

def test_python_scanner_parity_on_the_same_shapes(tmp_path):
    """S4: the CONTROL — Python's scanner (the rule's origin) excludes
    the same dot-directories over the same shapes WHILE collecting the
    real source (green at base AND head: the parity this fix closes was
    always Python's behavior; the witness is that the parity HOLDS, not
    that Python changed). The fixtures carry .py twins so the control is
    non-vacuous — an empty collection would pass any not-any assert
    (the r1-F1 catch)."""
    repo = _build_repo(tmp_path)
    # .py twins so Python has something to collect at all — under BOTH
    # dot-dirs (the .agents branch was vacuous at r2: the r2-F4 catch)
    (repo / "root.py").write_text("def root(): pass\n", encoding="utf-8")
    (repo / ".github" / "ci.py").write_text("def ci(): pass\n", encoding="utf-8")
    (repo / ".agents" / "tools" / "h.py").write_text("def h(): pass\n",
                                                     encoding="utf-8")

    from parsers.python.repository_scanner import (
        RepositoryScanner as PyScanner,
    )
    s = PyScanner(str(repo), {"skip_tests": True})
    result = s.scan()
    py_paths = [f["path"] if isinstance(f, dict) else str(f)
                for f in result["files"]]
    # NON-VACUOUS: the real source is collected
    assert any(p.endswith("root.py") for p in py_paths), py_paths
    assert len(py_paths) >= 1, py_paths
    # the parity: the dot-directories excluded
    assert not any(".github" in p for p in py_paths), py_paths
    assert not any(".agents" in p for p in py_paths), py_paths
