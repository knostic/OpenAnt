"""The on-disk artifacts must carry context provenance + coverage.

Two artifacts are the operator's record of a scan: ``scan.report.json`` (the
aggregate report) and ``pipeline_output.json`` (the findings envelope). Before
this contract they omitted three things that make a scan auditable:

* ``context_source`` — which path supplied the security model. A scan run under
  the wrong model (a repo-supplied threat model that says "nothing is a vuln")
  looked byte-identical to a correct one.
* the multi-language coverage fields (``per_language``, ``parse_errors``,
  ``degraded`` …) — a merged or degraded scan was indistinguishable from a
  clean single-language one.
* the walker's skipped-symlink / unreadable-directory counts, and the sha256 of
  a repo-supplied threat model (R5 provenance).

These tests read the FILES ON DISK. Asserting on ``ScanResult.to_dict()`` is
exactly what let the gap survive: ``to_dict()`` had the fields, but the code that
wrote ``scan.report.json`` hand-built a summary that dropped them. The mutation
that proves these tests bite: revert ``_write_scan_report`` to the hand-built
summary (units_count/language/metrics/steps_* only) and every disk assertion
below goes red while ``to_dict()`` stays green.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.reporter import build_pipeline_output
from core.scanner import _write_scan_report
from core.schemas import ScanResult
from report.generator import _context_provenance_header


def _read(path: Path) -> dict:
    return json.loads(path.read_text())


# ---------------------------------------------------------------------------
# scan.report.json — the aggregate report
# ---------------------------------------------------------------------------

def _scan_result_with_symlinks(out: Path, lang: str = "python") -> None:
    """Write the per-language scan-result file the coverage aggregator reads.

    The coverage figures live in the parser's ``scan_result.json`` statistics —
    NOT in dataset.json — so this fixture reproduces the real on-disk shape.
    """
    (out / "scan_result.json").write_text(json.dumps({
        "statistics": {
            "total_files": 3,
            "symlinks_skipped": 2,
            "symlink_examples": [f"{out}/evil.py", f"{out}/evildir"],
            "directories_unreadable": 1,
            "unreadable_examples": [f"{out}/locked: Permission denied"],
        }
    }))


def test_scan_report_carries_threat_model_provenance_and_coverage(tmp_path: Path):
    out = tmp_path / "run"
    out.mkdir()
    _scan_result_with_symlinks(out)

    result = ScanResult(
        output_dir=str(out),
        language="python",
        units_count=3,
        languages=["python"],
        context_source="threat_model",
        threat_model_sha256="deadbeef" * 8,
        threat_model_warnings=["every input source marked trusted"],
    )
    report_path = _write_scan_report(str(out), result, step_reports=[])

    summary = _read(Path(report_path))["summary"]

    # context provenance
    assert summary["context_source"] == "threat_model"
    assert summary["threat_model_sha256"] == "deadbeef" * 8
    assert summary["threat_model_warnings"] == [
        "every input source marked trusted"
    ]

    # multi-language coverage fields
    assert summary["languages"] == ["python"]
    assert summary["degraded"] is False
    assert "per_language" in summary
    assert "parse_errors" in summary
    assert "excluded_languages" in summary

    # walker coverage aggregate (symlinks refused, dirs unreadable)
    cov = summary["coverage"]
    assert cov["symlinks_skipped"] == 2
    assert cov["directories_unreadable"] == 1
    assert len(cov["symlink_examples"]) == 2
    assert len(cov["unreadable_examples"]) == 1
    # python instruments coverage, so it is NOT disclosed as missing data.
    assert cov["languages_without_coverage_data"] == []


def test_scan_report_omits_sha_when_no_threat_model(tmp_path: Path):
    """Negative control: sha KEY ABSENT (not the empty-string hash) with no TM."""
    out = tmp_path / "run"
    out.mkdir()

    result = ScanResult(
        output_dir=str(out),
        language="python",
        units_count=1,
        context_source="generated",
    )
    report_path = _write_scan_report(str(out), result, step_reports=[])
    summary = _read(Path(report_path))["summary"]

    assert summary["context_source"] == "generated"
    assert "threat_model_sha256" not in summary
    # No scan_result file present -> the language is disclosed as not-measured,
    # not silently zeroed (see test_coverage_missing_scan_file_is_disclosed*).
    assert summary["coverage"]["symlinks_skipped"] == 0
    assert "python" in summary["coverage"]["languages_without_coverage_data"]


def test_coverage_probe_discloses_uninstrumented_languages(tmp_path: Path):
    """An uninstrumented parser (Go) is DISCLOSED, never summed as a false 0.

    The Go fixture below is the REAL shape the Go parser emits — camelCase-only
    statistics with NO snake_case coverage keys. Building it from the actual
    interface (not a hand-simplified snake_case dict) is the whole point: an
    earlier version of this test used a snake_case Go/JS fixture, which was a
    fake looser than the real parser output and masked the false-0 bug. The
    assertion keys on the coverage PROBE (was the language instrumented?), so a
    fixture that lies about the parser's output can no longer make it pass.
    """
    out = tmp_path / "run"
    (out / "python").mkdir(parents=True)
    (out / "go").mkdir()
    _scan_result_with_symlinks(out / "python", "python")  # instrumented, 2 skipped
    # Real Go output: camelCase, no symlinks_skipped / directories_unreadable.
    (out / "go" / "scan_results.json").write_text(json.dumps({
        "statistics": {
            "totalFiles": 4,
            "byExtension": {".go": 4},
            "directoriesExcluded": 1,
        }
    }))

    result = ScanResult(
        output_dir=str(out),
        languages=["python", "go"],
        per_language={
            "python": {"output_dir": str(out / "python")},
            "go": {"output_dir": str(out / "go")},
        },
    )
    report_path = _write_scan_report(str(out), result, step_reports=[])
    cov = _read(Path(report_path))["summary"]["coverage"]

    # Only python's skips are counted; Go's absent keys are NOT summed as 0.
    assert cov["symlinks_skipped"] == 2
    assert cov["directories_unreadable"] == 1
    # Go is disclosed as uninstrumented; a bare "0" would have been a false
    # assurance. python (instrumented) is NOT in the list.
    assert cov["languages_without_coverage_data"] == ["go"]


def test_coverage_missing_scan_file_is_disclosed_not_zeroed(tmp_path: Path):
    """A language with no scan-result file is disclosed, not silently zeroed."""
    out = tmp_path / "run"
    out.mkdir()
    result = ScanResult(output_dir=str(out), language="python", languages=["python"])
    report_path = _write_scan_report(str(out), result, step_reports=[])
    cov = _read(Path(report_path))["summary"]["coverage"]
    assert cov["symlinks_skipped"] == 0
    assert cov["languages_without_coverage_data"] == ["python"]


# ---------------------------------------------------------------------------
# pipeline_output.json — the findings envelope
# ---------------------------------------------------------------------------

def _minimal_results(path: Path) -> None:
    path.write_text(json.dumps({
        "dataset": "demo",
        "results": [],
        "metrics": {"vulnerable": 0, "safe": 0, "inconclusive": 0},
    }))


def test_pipeline_output_carries_context_source_and_sha(tmp_path: Path):
    results = tmp_path / "results.json"
    _minimal_results(results)
    out = tmp_path / "pipeline_output.json"

    build_pipeline_output(
        results_path=str(results),
        output_path=str(out),
        repo_name="demo",
        language="python",
        context_source="threat_model",
        threat_model_sha256="cafe" * 16,
        threat_model_warnings=["all input sources marked trusted"],
    )

    data = _read(out)
    assert data["context_source"] == "threat_model"
    assert data["threat_model_sha256"] == "cafe" * 16
    assert data["threat_model_warnings"] == ["all input sources marked trusted"]


def test_pipeline_output_defaults_none_and_omits_sha(tmp_path: Path):
    """Negative control: standalone build has context_source 'none', no sha key."""
    results = tmp_path / "results.json"
    _minimal_results(results)
    out = tmp_path / "pipeline_output.json"

    build_pipeline_output(
        results_path=str(results),
        output_path=str(out),
        repo_name="demo",
        language="python",
    )

    data = _read(out)
    assert data["context_source"] == "none"
    assert "threat_model_sha256" not in data


# ---------------------------------------------------------------------------
# R5 report header — deterministic, un-suppressible by a hostile threat model
# ---------------------------------------------------------------------------

def test_provenance_header_fires_only_for_threat_model():
    # Built-in / generated context: NO banner (negative control).
    assert _context_provenance_header({"context_source": "generated"}) == ""
    assert _context_provenance_header({"context_source": "none"}) == ""

    header = _context_provenance_header({
        "context_source": "threat_model",
        "threat_model_sha256": "abc123",
        "threat_model_warnings": ["every input source marked trusted"],
    })
    assert "repo-controlled file" in header
    assert "abc123" in header
    assert "every input source marked trusted" in header


def test_provenance_header_survives_missing_optional_fields():
    """A threat-model context with no sha/warnings still gets the banner."""
    header = _context_provenance_header({"context_source": "threat_model"})
    assert "repo-controlled file" in header
