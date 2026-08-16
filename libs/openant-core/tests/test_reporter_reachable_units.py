"""Tests for ``core.reporter`` honest ``reachable_units`` reporting (F1).

Regression coverage for a report-correctness bug: ``build_pipeline_output``
hardcoded ``pipeline_stats.reachable_units = total_units`` — i.e. it asserted
that *every* analyzed unit was reachable, even though the reachability filter
(``core/parser_adapter.apply_reachability_filter``) may have pruned most of
them. The true reachable count is persisted by the parse step into
``<scan_dir>/dataset.json`` under ``metadata.reachability_filter.reachable_units``;
the reporter simply never read it. On a real scan (e.g. neqo: 2883 -> 892) the
human-facing summary report (``report/prompts/summary.txt`` interpolates
``pipeline_stats.reachable_units``) therefore stated a falsehood — the exact
artifact that misled a reviewer into a "reachability is broken" misdiagnosis.

These tests pin the fix:
1. When a reachability-filter record exists, the report's ``reachable_units``
   reflects the TRUE filtered count, not ``total_units``.
2. When units were analyzed but NO reachability-filter record exists and a
   filtering level was requested (the free-function-parser / not-recorded
   blind spot), the report does not silently assert full reachability — it
   carries a warning and flags that filtering was not recorded.
3. Absent/unfiltered scans keep the safe fallback without a spurious warning.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.reporter import build_pipeline_output
from utilities.file_io import write_json


def _run_build(
    tmp_path: Path,
    *,
    metrics: dict,
    reachability_filter: dict | None,
    processing_level: str | None = "reachable",
    dataset_metadata_extra: dict | None = None,
) -> dict:
    """Invoke ``build_pipeline_output`` with a controlled results.json +
    sibling dataset.json, returning the parsed ``pipeline_output.json``.
    """
    results = {
        "dataset": "test",
        "code_by_route": {"app.py:foo": "def foo(): pass"},
        "metrics": metrics,
        "confirmed_findings": [],
    }
    results_path = tmp_path / "results.json"
    write_json(results_path, results)

    # The parse step writes dataset.json as a sibling of results.json; the
    # reachability filter stamps metadata.reachability_filter onto it.
    if reachability_filter is not None or dataset_metadata_extra is not None:
        metadata: dict = {}
        if reachability_filter is not None:
            metadata["reachability_filter"] = reachability_filter
        if dataset_metadata_extra:
            metadata.update(dataset_metadata_extra)
        write_json(tmp_path / "dataset.json", {"units": [], "metadata": metadata})

    out_path = tmp_path / "pipeline_output.json"
    build_pipeline_output(
        results_path=str(results_path),
        output_path=str(out_path),
        language="python",
        repo_name="test/repo",
        processing_level=processing_level,
    )
    return json.loads(out_path.read_text())


def test_reachable_units_reflects_true_filtered_count(tmp_path: Path):
    """reachable_units == the filter's real kept count, not total_units."""
    out = _run_build(
        tmp_path,
        metrics={"total": 10, "errors": 0},
        reachability_filter={
            "original_units": 10,
            "reachable_units": 2,
            "reduction_percentage": 80,
        },
    )
    stats = out["pipeline_stats"]
    assert stats["total_units"] == 10
    # The bug: this was hardcoded to total_units (10). Truth is 2.
    assert stats["reachable_units"] == 2, (
        f"expected true filtered count 2, got {stats['reachable_units']} "
        "(reporter fabricated reachable_units = total_units)"
    )
    assert stats.get("reachability_filter_applied") is True


def test_missing_reachability_record_warns_not_asserts(tmp_path: Path):
    """Filtering requested but no rf record -> warn, don't claim full reach."""
    out = _run_build(
        tmp_path,
        metrics={"total": 10, "errors": 0},
        reachability_filter=None,               # e.g. rust/zig: no rf metadata
        dataset_metadata_extra={"language": "rust"},
        processing_level="reachable",
    )
    stats = out["pipeline_stats"]
    assert stats.get("reachability_filter_applied") is False
    warnings = stats.get("reachability_warnings") or []
    assert warnings, "expected a reachability warning when no rf record exists"
    assert any("reachab" in w.lower() for w in warnings)


def test_malformed_dataset_json_degrades_safely(tmp_path: Path):
    """A corrupt dataset.json must not crash the report; it degrades to fallback."""
    results = {"dataset": "t", "code_by_route": {}, "metrics": {"total": 5, "errors": 0},
               "confirmed_findings": []}
    write_json(tmp_path / "results.json", results)
    (tmp_path / "dataset.json").write_text("{not valid json")
    out_path = tmp_path / "pipeline_output.json"
    build_pipeline_output(
        results_path=str(tmp_path / "results.json"), output_path=str(out_path),
        language="python", repo_name="t/r", processing_level="reachable",
    )
    stats = json.loads(out_path.read_text())["pipeline_stats"]
    assert stats["reachable_units"] == 5           # safe fallback, no crash
    assert stats["reachability_filter_applied"] is False


def test_rf_record_present_but_no_count_keeps_fallback(tmp_path: Path):
    """rf record exists but lacks reachable_units -> applied True, count fallback, no warning."""
    out = _run_build(
        tmp_path,
        metrics={"total": 7, "errors": 0},
        reachability_filter={"reduction_percentage": 0},   # no reachable_units key
        processing_level="reachable",
    )
    stats = out["pipeline_stats"]
    assert stats["reachability_filter_applied"] is True
    assert stats["reachable_units"] == 7
    assert not (stats.get("reachability_warnings") or [])


def test_blackout_warning_surfaced_from_rf_record(tmp_path: Path):
    """A blackout warning recorded on the rf record reaches the report."""
    out = _run_build(
        tmp_path,
        metrics={"total": 100, "errors": 0},
        reachability_filter={"original_units": 100, "reachable_units": 100,
                             "reduction_percentage": 0,
                             "warning": "No entry points detected; keeping all units"},
        processing_level="reachable",
    )
    stats = out["pipeline_stats"]
    assert any("entry point" in w.lower() for w in stats.get("reachability_warnings") or [])


def test_original_units_and_reduction_surfaced(tmp_path: Path):
    """The pruning is made visible (original + reduction), not just the kept count."""
    out = _run_build(
        tmp_path,
        metrics={"total": 892, "errors": 0},
        reachability_filter={"original_units": 2883, "reachable_units": 892,
                             "reduction_percentage": 69},
        processing_level="reachable",
    )
    stats = out["pipeline_stats"]
    assert stats["reachable_units"] == 892
    assert stats["original_units"] == 2883
    assert stats["reachability_reduction_percentage"] == 69


def test_limit_run_reachable_exceeds_total_warns(tmp_path: Path):
    """--limit truncates analysis below the kept set: keep the true reachable
    count but warn so reachable_units > total_units is never silently shown."""
    out = _run_build(
        tmp_path,
        metrics={"total": 100, "errors": 0},          # analysis limited to 100
        reachability_filter={"original_units": 2883, "reachable_units": 892,
                             "reduction_percentage": 69},
        processing_level="reachable",
    )
    stats = out["pipeline_stats"]
    assert stats["reachable_units"] == 892            # true kept count preserved
    assert stats["total_units"] == 100
    warnings = stats.get("reachability_warnings") or []
    assert any("exceeds analyzed total_units" in w for w in warnings), (
        "expected a warning explaining reachable_units > total_units under --limit"
    )


def test_unfiltered_level_has_no_spurious_warning(tmp_path: Path):
    """processing_level='all' means no filter by design -> no warning."""
    out = _run_build(
        tmp_path,
        metrics={"total": 10, "errors": 0},
        reachability_filter=None,
        processing_level="all",
    )
    stats = out["pipeline_stats"]
    assert not (stats.get("reachability_warnings") or []), (
        "unfiltered scans must not emit a reachability warning"
    )
