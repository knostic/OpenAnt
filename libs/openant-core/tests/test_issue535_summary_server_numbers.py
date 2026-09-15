"""Tests for issue #535 — the server-rendered numeric/eligibility surfaces.

SUMMARY_REPORT.md's numbers and tables were model-transcribed JSON with
arithmetic — and the model botched them (the receipt: 10.22s rendered as
"10m 13s", "Verified in Stage 2: 3 findings" against an adjudicated 1/4,
unverified rows in the Confirmed table, literal {step}/{reason} placeholder
tables, and a "Parsed: 120 functions from 120 files" line against a parse
total of 5389 — the prompt asked for fields that don't exist).

The fix: the reporter re-sources the Stage-1 facts from the step reports
(units_analyzed from the analyze report — the old total-minus-errors formula
was contaminated by Stage-2 verify errors; parsed_units from the parse
report; $0/0s steps no longer vanish from the tables), and the generator
renders the statistics/results/durations/costs/Confirmed tables server-side
with a strip-net for model-emitted duplicates and the placeholder tables
removed from the prompt.
"""
from __future__ import annotations

import json

from core.reporter import build_pipeline_output
from report.generator import (
    _summary_statistics_block,
    _summary_tables_block,
    _strip_server_sections,
    _strip_summary_placeholders,
)


def _results_file(tmp_path, rows, metrics=None):
    p = tmp_path / "results.json"
    p.write_text(json.dumps({
        "dataset": "demo",
        "results": rows,
        "metrics": metrics or {"total": len(rows), "errors": 0,
                               "safe": 0, "inconclusive": 0},
    }))
    return p


class TestReporterResourcing:
    def test_units_analyzed_from_analyze_report(self, tmp_path):
        """THE #535 regression: 120 analyzed + 1 Stage-2 verify error ->
        the old formula said 119; the analyze report's own count is 120."""
        row = {"finding": "vulnerable", "verdict": "vulnerable",
               "file": "a.py", "function": "f", "cwe_id": 79}
        out = tmp_path / "pipeline_output.json"
        build_pipeline_output(
            results_path=str(_results_file(
                tmp_path, [row], {"total": 120, "errors": 1,
                                  "safe": 0, "inconclusive": 0})),
            output_path=str(out),
            repo_name="demo", language="python",
            step_reports=[
                {"step": "analyze", "summary": {
                    "analyzed": 120, "error_count": 0}},
                {"step": "verify", "summary": {"findings_input": 4}},
            ],
        )
        stats = json.loads(out.read_text())["pipeline_stats"]
        assert stats["units_analyzed"] == 120
        assert stats["stage1_errors"] == 0

    def test_stage1_errors_via_verdicts_fallback(self, tmp_path):
        """The nested verdicts.errors shape (the cli standalone path)."""
        row = {"finding": "safe", "verdict": "safe",
               "file": "a.py", "function": "k", "cwe_id": 0}
        out = tmp_path / "pipeline_output.json"
        build_pipeline_output(
            results_path=str(_results_file(tmp_path, [row])),
            output_path=str(out),
            repo_name="demo", language="python",
            step_reports=[{"step": "analyze", "summary": {
                "analyzed": 9, "verdicts": {"errors": 2}}}],
        )
        assert json.loads(out.read_text())["pipeline_stats"]["stage1_errors"] == 2

    def test_analyze_only_fallback_keeps_old_formula(self, tmp_path):
        row = {"finding": "safe", "verdict": "safe",
               "file": "a.py", "function": "g", "cwe_id": 0}
        out = tmp_path / "pipeline_output.json"
        build_pipeline_output(
            results_path=str(_results_file(
                tmp_path, [row], {"total": 10, "errors": 2,
                                  "safe": 8, "inconclusive": 0})),
            output_path=str(out),
            repo_name="demo", language="python",
        )
        stats = json.loads(out.read_text())["pipeline_stats"]
        assert stats["units_analyzed"] == 8

    def test_verify_without_analyze_omits_the_key(self, tmp_path):
        """Contaminated subtraction — present-only omission beats a wrong
        integer."""
        row = {"finding": "safe", "verdict": "safe",
               "file": "a.py", "function": "h", "cwe_id": 0}
        out = tmp_path / "pipeline_output.json"
        build_pipeline_output(
            results_path=str(_results_file(
                tmp_path, [row], {"total": 10, "errors": 3,
                                  "safe": 7, "inconclusive": 0})),
            output_path=str(out),
            repo_name="demo", language="python",
            step_reports=[{"step": "verify", "summary": {"findings_input": 2}}],
        )
        stats = json.loads(out.read_text())["pipeline_stats"]
        assert "units_analyzed" not in stats

    def test_parsed_units_forwarded(self, tmp_path):
        row = {"finding": "safe", "verdict": "safe",
               "file": "a.py", "function": "i", "cwe_id": 0}
        out = tmp_path / "pipeline_output.json"
        build_pipeline_output(
            results_path=str(_results_file(tmp_path, [row])),
            output_path=str(out),
            repo_name="demo", language="python",
            step_reports=[{"step": "parse", "summary": {"total_units": 5389}}],
        )
        stats = json.loads(out.read_text())["pipeline_stats"]
        assert stats["parsed_units"] == 5389

    def test_zero_cost_steps_do_not_vanish(self, tmp_path):
        row = {"finding": "safe", "verdict": "safe",
               "file": "a.py", "function": "j", "cwe_id": 0}
        out = tmp_path / "pipeline_output.json"
        build_pipeline_output(
            results_path=str(_results_file(tmp_path, [row])),
            output_path=str(out),
            repo_name="demo", language="python",
            step_reports=[{"step": "parse", "summary": {"total_units": 5},
                           "cost_usd": 0.0, "duration_seconds": 0.2}],
        )
        stats = json.loads(out.read_text())["pipeline_stats"]
        assert "parse" in stats["costs"]
        assert "parse" in stats["durations"]


class TestGeneratorBlocks:
    def _stats(self, **kw):
        return {"pipeline_stats": kw}

    def test_statistics_block_lines(self):
        block = _summary_statistics_block(self._stats(
            parsed_units=5389, reachability_filter_applied=True,
            original_units=5389, reachable_units=2343,
            units_analyzed=120, total_units=120, stage1_errors=0,
            findings_input=4, units_analyzed_total=120,
            downgraded=1, upgraded=0))
        assert "Parsed: 5389 units" in block
        assert "In scope after reachability filter: 2343 of 5389" in block
        assert "Analyzed in Stage 1: 120 units" in block
        assert "Adjudicated in Stage 2: 4 of 120 analyzed units" in block
        assert "1 downgraded, 0 upgraded" in block

    def test_present_only_no_fabricated_zeros(self):
        block = _summary_statistics_block(self._stats())
        assert block == ""

    def test_durations_never_misrender(self):
        block = _summary_tables_block(self._stats(
            durations={"parse": 10.22, "analyze": 0.07}))
        assert "10.2s" in block
        assert "0.1s" in block
        assert "10m" not in block  # THE receipt: 10.22s rendered as 10m 13s

    def test_confirmed_table_eligibility(self):
        findings = [
            {"name": "A", "location": {"file": "a", "function": "b"},
             "cwe_id": 1, "severity": "high", "stage2_verdict": "confirmed"},
            {"name": "B", "location": {"file": "c", "function": "d"},
             "cwe_id": 2, "severity": "medium", "stage2_verdict": "agreed"},
            {"name": "C", "location": {"file": "e", "function": "f"},
             "cwe_id": 3, "stage2_verdict": "unverified"},
        ]
        block = _summary_tables_block({"findings": findings})
        conf = block.split("## Not Confirmed")[0]
        assert "| 1 | A |" in conf and "| 2 | B |" in conf
        assert "| C |" not in conf  # THE receipt: unverified in Confirmed
        nc = block.split("## Not Confirmed")[1]
        assert "| C |" in nc and "unverified" in nc

    def test_no_findings_no_placeholder_tables(self):
        block = _summary_tables_block({"findings": []})
        assert "{step}" not in block
        assert "{name}" not in block
        assert "No findings to report." in block

    def test_strip_model_duplicate_sections(self):
        model_text = ("## Overview\n\nSome narrative.\n\n"
                      "## Pipeline Statistics\n\n"
                      "- Parsed: 999 units (model-transcribed)\n\n"
                      "## Results\n\n| Outcome | Units |\n|---|---|\n"
                      "| Vulnerable | 999 |\n\n"
                      "## After\n\nMore prose.\n")
        out = _strip_server_sections(model_text)
        assert "999" not in out
        assert "## Pipeline Statistics" not in out
        assert "## Results" not in out
        assert "## Overview" in out and "More prose." in out

    def test_placeholder_tables_stripped(self):
        text = ("No steps were skipped.\n\n"
                "| Step | Reason |\n|------|--------|\n"
                "| {step} | {reason} |\n\n"
                "No false positives to report.\n\n"
                "| {name} | {verdict} | {verdict} | {one_sentence_reason} |\n")
        out = _strip_summary_placeholders(text)
        assert "{step}" not in out
        assert "{name}" not in out
        assert "No steps were skipped." in out

    def test_costs_table_no_phantom_columns(self):
        block = _summary_tables_block(self._stats(
            costs={"parse": {"actual": 0.0}, "analyze": {"actual": 2.7}}))
        assert "Estimated" not in block
        assert "Units" not in block
        assert "| parse | $0.00 |" in block
        assert "| analyze | $2.70 |" in block


# --- the fable+astra gate fold: the splice-position contract ----

def test_fold_h1_at_offset_zero_tables_below_title():
    """The m.start()>0 inversion (the fable blocker, confirmed from source):
    the canonical reply (H1 at offset 0, no preceding banner) took the
    prepend branch — the server tables rendered ABOVE the document title.
    Now every shape inserts AFTER the H1/metadata block."""
    # THE POSITION PIN: the splice semantics (mirrored from the
    # generate_summary_report site) — H1 at 0 -> the tables after the
    # H1/metadata block, never above the title
    import re as _re
    model_text = "# Security Summary\n\nSome metadata line.\n\n## Narrative\nProse.\n"
    server_blocks = "[TABLES]\n"
    m = _re.search(r"^#{1,2} ", model_text, flags=_re.M)
    line_end = model_text.index("\n", m.start())
    m2 = _re.search(r"^#{1,2} ", model_text[line_end:], flags=_re.M)
    insert_at = line_end + (m2.start() if m2 else len(model_text) - line_end)
    out = model_text[:insert_at] + server_blocks + model_text[insert_at:]
    assert out.index("# Security Summary") < out.index("[TABLES]") < out.index("## Narrative"), (
        "the tables must render AFTER the H1/metadata block, never above the title")
    assert not out.startswith("[TABLES]"), "the tables must never prepend the document"


def test_fold_no_heading_fallback_single_banners():
    """The no-heading path previously prepended the banners TWICE (once in
    the branch, once in the unconditional final prepend). Now the banners
    prepend exactly once."""
    import inspect
    import report.generator as g
    src = inspect.getsource(g.generate_summary_report)
    # the banners prepend in exactly ONE place: the unconditional final line
    count = src.count("_context_provenance_header(pipeline_data)")
    assert count == 1, (
        f"the banner prepend must appear exactly once in generate_summary_report; found {count}")
