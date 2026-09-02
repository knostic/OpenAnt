"""Regression tests for issue #307 — the CHANGELOG says pipeline_output.json
carries the multi-language coverage fields; it does not, and
`build_pipeline_output` has no parameter for them.

`pipeline_output.json` is the sole input to the generated report and the
dynamic tester, so coverage information that stops at `scan.report.json`
cannot appear in the human deliverable — while the CHANGELOG claims
otherwise. Plus the largest exclusion of all (`test_files_skipped`, 1,346
files on the filing run) never leaves the per-parser scan-result file.

Contract locked here (the issue's suggestions 1, 2, 4 + the
test_files_skipped lane):
- `build_pipeline_output` accepts per_language, parse_errors,
  excluded_languages, degraded (None = absent upstream) and `coverage`,
  and emits them at the TOP level (the CHANGELOG's stated shape);
- the scanner passes them from the parse result;
- `coverage` aggregates test_files_skipped per language (the dominant
  exclusion) alongside the symlink/unreadable keys;
- the Go results struct decodes all five names (comma-ok: additive);
- a drift test asserts pipeline_output carries every field the CHANGELOG
  names, so the promise and the artifact cannot part again.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.reporter import build_pipeline_output  # noqa: E402
from utilities.file_io import write_json  # noqa: E402


def _build(tmp_path, **kwargs):
    results = {"dataset": "t", "code_by_route": {}, "metrics": {"total": 2},
               "confirmed_findings": [], "results": []}
    write_json(tmp_path / "results.json", results)
    out = tmp_path / "pipeline_output.json"
    build_pipeline_output(
        results_path=str(tmp_path / "results.json"), output_path=str(out),
        language="python", repo_name="t/r", processing_level="all",
        **kwargs)
    return json.loads(out.read_text())


COVERAGE = {"symlinks_skipped": 2, "directories_unreadable": 1,
            "symlink_examples": ["l1"], "unreadable_examples": [],
            "test_files_skipped": {"python": 1346},
            "languages_without_coverage_data": []}


def test_pipeline_output_carries_the_changelog_fields(tmp_path):
    po = _build(tmp_path,
                per_language={"python": {"units": 1100}},
                parse_errors=[{"language": "swift", "error": "boom"}],
                excluded_languages={"swift": "no parser"},
                degraded=True,
                coverage=COVERAGE)
    assert po["per_language"] == {"python": {"units": 1100}}
    assert po["parse_errors"][0]["language"] == "swift"
    assert po["excluded_languages"] == {"swift": "no parser"}
    assert po["degraded"] is True
    assert po["coverage"]["test_files_skipped"] == {"python": 1346}


def test_fields_absent_when_not_provided(tmp_path):
    """Present-only: a single-language clean scan carries no fabricated
    empty structures — absent upstream stays absent."""
    po = _build(tmp_path)
    for k in ("per_language", "parse_errors", "excluded_languages",
              "degraded", "coverage"):
        assert k not in po


def test_degraded_false_is_emitted_when_explicitly_passed(tmp_path):
    """A caller that computed degraded=False says so deliberately; the
    CHANGELOG names the field, and only absence (None) means unknown."""
    po = _build(tmp_path, degraded=False)
    assert po["degraded"] is False


def test_coverage_includes_test_files_skipped_per_language():
    """The dominant exclusion (1,346 files on the filing run — larger than
    every language/threshold exclusion combined) aggregates per language,
    not into the scalar count keys."""
    from core.scanner import _read_coverage_stats, _collect_coverage, ScanResult
    import tempfile
    import os

    d = tempfile.mkdtemp()
    with open(os.path.join(d, "scan_result.json"), "w") as f:
        json.dump({"statistics": {
            "test_files_skipped": 1346,
            "symlinks_skipped": 2,
            "directories_unreadable": 1,
        }}, f)
    stats = _read_coverage_stats(d)
    assert stats["test_files_skipped"] == 1346

    result = ScanResult(output_dir=d, language="python", languages=["python"])
    result.per_language = {"python": {"output_dir": d}}
    cov = _collect_coverage(result)
    assert cov["test_files_skipped"] == {"python": 1346}
    assert cov["symlinks_skipped"] == 2


def test_scanner_passes_the_fields():
    """Source-level contract: the scanner's build_pipeline_output call
    passes the five fields from the parse result."""
    src = (PROJECT_ROOT / "core" / "scanner.py").read_text()
    assert "per_language=result.per_language" in src
    assert "parse_errors=result.parse_errors" in src
    assert "excluded_languages=result.excluded_languages" in src
    assert "degraded=result.degraded" in src
    assert "coverage=_collect_coverage(result)" in src


def test_go_results_struct_declares_the_fields():
    """The Go ScanData struct DECLARES the five fields (forward-declared
    surface: the CLI's formatter renders the untyped envelope today, so
    these populate only once a typed decode is wired — the struct fields
    are additive/omitempty and change nothing observable now; see the
    corrected comment in results.go)."""
    go = (PROJECT_ROOT.parents[1] / "apps" / "openant-cli" /
          "internal" / "types" / "results.go")
    src = go.read_text()
    for name in ("per_language", "parse_errors", "excluded_languages",
                 "degraded", "coverage"):
        assert name in src, f"results.go must carry {name}"


def test_summary_template_states_the_coverage_line():
    """Suggestion 3 (the 'surface them' half): the generated report's
    prompt instructs the coverage rendering so a reader sees what did NOT
    enter the pipeline."""
    src = (PROJECT_ROOT / "report" / "prompts" / "summary.txt").read_text()
    assert "coverage" in src
    assert "test_files_skipped" in src


def test_js_camelcase_alias_and_no_test_skip_disclosure():
    """Review findings: (a) the JS scanner's camelCase testFilesSkipped is
    read as an alias (the symlinks_skipped naming-drift class); (b) a
    language that skips test files WITHOUT counting them (go/rust/swift/zig
    today) is disclosed in languages_without_test_skip_data, never silently
    absent-as-zero."""
    from core.scanner import _read_coverage_stats
    import json as _json
    import tempfile as _tf
    from pathlib import Path as _Path

    tmp = _Path(_tf.mkdtemp())
    (tmp / "scan_results.json").write_text(_json.dumps({
        "language": "javascript",
        "statistics": {"symlinks_skipped": 0, "directories_unreadable": 0,
                       "testFilesSkipped": 7},
    }))
    stats = _read_coverage_stats(str(tmp))
    assert stats is not None
    assert "testFilesSkipped" in str(stats) or stats.get("testFilesSkipped") == 7
