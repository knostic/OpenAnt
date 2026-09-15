"""The post-LLM re-filter must persist its per-language stats onto the dataset.

BUG-2: the loop rebuilds ``dataset = {**dataset, "units": kept}`` from the
ORIGINAL (pre-LLM) metadata, discarding the ``reachability_filter`` record each
``apply_reachability_filter`` call stamped. The reporter then reads no record
and renders "reachability filtering not applied" on a scan that DID prune via
the LLM-seeded re-filter — a machine-readable artifact stating the opposite of
what happened.

This drives the real loop end-to-end (fully offline, LLM stubbed) and asserts
the persisted metadata carries a real, per-language, reconciling record.

Reuses the offline multi-language harness from
``test_scanner_refilter_loop_executes`` so both files exercise ONE loop.
"""

import json
import os
from pathlib import Path

import pytest

import core.scanner as scanner_mod

# Reuse the exact offline fixtures that already drive the loop body (repo,
# fake_parsers, stub_llm_reachability, _offline). Loading the module as a
# fixture plugin makes them available without a by-name import (which would
# shadow the fixture parameters and trip ruff F811).
pytest_plugins = ("test_scanner_refilter_loop_executes",)


@pytest.fixture(autouse=True)
def _stub_analyze(monkeypatch):
    """Keep this test $0. The offline harness stubs ``analyze_reachability`` but
    NOT the Stage-1 analyze LLM: ``scan_repository`` calls
    ``core.analyzer.run_analysis`` unconditionally against the live key, so an
    un-stubbed run bills real API on every CI invocation. The refilter record
    this test asserts on is produced BEFORE analyze, so a no-op stub is faithful.
    """
    import core.analyzer as analyzer_mod
    from core.schemas import AnalyzeResult

    def _fake(*a, **k):
        out = k["output_dir"]
        rp = os.path.join(out, "results.json")
        with open(rp, "w") as fh:
            json.dump({"results": [], "code_by_route": {}, "metrics": {}}, fh)
        return AnalyzeResult(results_path=rp)

    monkeypatch.setattr(analyzer_mod, "run_analysis", _fake)


def _run(repo, out):
    return scanner_mod.scan_repository(
        repo_path=str(repo), output_dir=str(out),
        languages=["python", "javascript"],
        processing_level="reachable",
        llm_reachability=True,
        generate_context=False, generate_report=False,
        enhance=False, verify=False,
    )


class TestRefilterMetadataPersisted:
    def test_reachability_filter_record_is_stamped(self, repo, tmp_path,
                                                   fake_parsers,
                                                   stub_llm_reachability):
        """RED on base: line 587 rebuilds from stale metadata -> no record."""
        out = tmp_path / "out"
        result = _run(repo, out)
        dataset = json.loads(Path(result.dataset_path).read_text())
        rf = (dataset.get("metadata") or {}).get("reachability_filter")
        assert rf is not None, (
            "the post-LLM re-filter pruned units but stamped NO "
            "reachability_filter record — reporter will say 'not applied'"
        )

    def test_record_is_per_language(self, repo, tmp_path, fake_parsers,
                                    stub_llm_reachability):
        """A merged multi-language scan must not collapse to one language's stats."""
        out = tmp_path / "out"
        result = _run(repo, out)
        dataset = json.loads(Path(result.dataset_path).read_text())
        rf = (dataset.get("metadata") or {}).get("reachability_filter") or {}
        per_lang = rf.get("per_language") or {}
        assert set(per_lang) >= {"python", "javascript"}, (
            f"per_language should cover both languages, got {set(per_lang)} "
            "(overfit to the first-parsed language?)"
        )

    def test_aggregate_reconciles_with_kept_units(self, repo, tmp_path,
                                                  fake_parsers,
                                                  stub_llm_reachability):
        """The stamped reachable_units MUST equal the units that survived."""
        out = tmp_path / "out"
        result = _run(repo, out)
        dataset = json.loads(Path(result.dataset_path).read_text())
        rf = (dataset.get("metadata") or {}).get("reachability_filter") or {}
        assert rf.get("reachable_units") == len(dataset["units"]), (
            "the aggregate reachable_units does not match the surviving unit "
            "count — a fabricated/miscomputed record is worse than none"
        )

    def test_blackout_warning_is_lifted_to_top_level(self, repo, tmp_path,
                                                     fake_parsers,
                                                     stub_llm_reachability):
        """A language that blacks out (no entry points -> flows through
        unfiltered) stamps a per-language ``warning``. The aggregate MUST lift it
        to the top-level ``warning`` the reporter reads (reporter.py:505), or the
        report claims 'filter applied, N% reduction' while hiding the blackout.
        The harness's javascript has NO entry point, so it blacks out.
        """
        out = tmp_path / "out"
        result = _run(repo, out)
        dataset = json.loads(Path(result.dataset_path).read_text())
        rf = (dataset.get("metadata") or {}).get("reachability_filter") or {}
        per_lang = rf.get("per_language") or {}
        # Precondition: javascript did produce a per-language warning.
        assert (per_lang.get("javascript") or {}).get("warning"), (
            "expected the javascript blackout to stamp a per-language warning"
        )
        # The fix under test: it must be surfaced at the top level.
        assert isinstance(rf.get("warning"), str) and rf["warning"], (
            "per-language blackout warning was not lifted to the top-level "
            "'warning' the reporter reads — the record hides the blackout"
        )
        assert "javascript" in rf["warning"]
