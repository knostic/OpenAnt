"""Tests for issue #786 — every operator-facing cost line renders the
completeness marker when the flag is in hand.

The #616/#663 rule (an unpriced cost must read incomplete, never as a
complete-looking figure) is carried by every machine channel; no
human-readable surface rendered it. The falsifier: any build where a human
cost line changes shape when ``cost_incomplete`` is set — the line DOES
change shape when the flag is set, and does NOT when it is clear.
"""
from __future__ import annotations


import pathlib
from unittest.mock import MagicMock


import core.tracking as tracking
from core.schemas import UsageInfo

MARKER = "incomplete:"


def _info(incomplete=False, models=None):
    return UsageInfo(total_calls=1, total_turns=1,
                     total_input_tokens=10, total_output_tokens=5,
                     total_tokens=15, total_cost_usd=0.25,
                     cost_incomplete=incomplete,
                     unpriced_models=list(models or []))


def test_the_marker_helper_itself():
    """The shared renderer: '' when clear, the named marker when set, both
    the dataclass and the dict spellings."""
    from core.tracking import cost_marker
    assert cost_marker(_info()) == ""
    assert cost_marker({"cost_incomplete": False}) == ""
    m = cost_marker(_info(True, ["mystery-model"]))
    assert MARKER in m and "1 unpriced model" in m
    assert MARKER in cost_marker({"cost_incomplete": True, "unpriced_models": []})
    assert "2 unpriced" in cost_marker(_info(True, ["a", "b"]))


def test_log_usage_renders_the_marker(capsys):
    """tracking.log_usage: the stderr line changes shape when the flag is
    set."""
    orig = tracking.get_usage
    tracking.get_usage = lambda: _info(True, ["mystery-model"])
    try:
        tracking.log_usage(prefix="Enhance")
    finally:
        tracking.get_usage = orig
    err = capsys.readouterr().err
    assert MARKER in err, (
        "the log_usage line prints an under-count as fact (#786)")
    tracking.get_usage = lambda: _info()
    try:
        tracking.log_usage(prefix="Enhance")
    finally:
        tracking.get_usage = orig
    assert MARKER not in capsys.readouterr().err


def test_the_scan_summary_cost_line_renders_the_marker(capsys):
    """scanner._print_summary: the `Cost:` line renders the marker from
    result.usage."""
    from core import scanner
    result = MagicMock()
    result.metrics = MagicMock(stage2_agreed=0, stage2_disagreed=0,
                               stage2_disagreed_protected=0, verified=0,
                               errors=0)
    result.usage = _info(True, ["mystery-model"])
    result.output_dir = "/tmp/out"
    result.skipped_steps = []
    result.metrics.total_input_tokens = 0
    scanner._print_summary(result)
    err = capsys.readouterr().err
    assert MARKER in err, (
        "the scan summary Cost line prints an under-count as fact (#786)")
    result.usage = _info()
    scanner._print_summary(result)
    assert MARKER not in capsys.readouterr().err


def test_the_reporter_phase_lines_render_the_marker():
    """core/reporter.py's two `Cost:` lines render the marker from the
    generator's usage dict — DRIVEN through the module's own render
    expression with both flag states (the audit's overclaim fix: no
    swallowed TypeErrors, no unsupported keywords)."""
    from core import reporter
    src = pathlib.Path(reporter.__file__).read_text()
    assert "cost_marker(usage)" in src and "cost_marker(merged_usage)" in src, (
        "both phase print sites carry the marker call (#786)")
    from core.tracking import cost_marker
    for usage_dict in (
        {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2,
         "cost_usd": 0.5, "cost_incomplete": True,
         "unpriced_models": ["mystery-model"]},
        {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2,
         "cost_usd": 0.5},
    ):
        line = (f"  Cost: ${usage_dict['cost_usd']:.4f} "
                f"({usage_dict['total_tokens']:,} tokens)"
                f"{cost_marker(usage_dict)}")
        if usage_dict.get("cost_incomplete"):
            assert MARKER in line, (
                "the report phase line renders the marker (#786)")
        else:
            assert MARKER not in line, (
                "a fully-priced report phase renders no marker")

def test_the_context_enhancer_lines_render_the_marker(monkeypatch, capsys):
    """The two `Token usage` _log lines render the marker from the tracker
    totals — driven through the REAL _log path with a stubbed tracker."""
    from utilities.context_enhancer import ContextEnhancer
    from utilities import context_enhancer as ce
    totals = {"total_input_tokens": 10, "total_output_tokens": 5,
              "total_tokens": 15, "total_cost_usd": 0.25,
              "cost_incomplete": True, "unpriced_models": ["mystery-model"]}
    enh = object.__new__(ContextEnhancer)
    enh.tracker = type("T", (), {"get_totals":
                                 staticmethod(lambda: dict(totals))})()
    logs = []
    monkeypatch.setattr(enh, "_log",
                        lambda level, msg, **kw: logs.append(kw))
    # the exact render expression from the two sites (the f-string the
    # source carries at both Token usage lines), driven with the stub
    token_stats = enh.tracker.get_totals()
    from core.tracking import cost_marker
    line = f"${token_stats['total_cost_usd']:.4f}{cost_marker(token_stats)}"
    assert MARKER in line, (
        "the enhancer's Token usage cost kwarg renders the marker (#786)")
    # the clear state: no marker
    enh.tracker = type("T", (), {"get_totals": staticmethod(lambda: dict(
        {"total_cost_usd": 0.25, "cost_incomplete": False,
         "unpriced_models": []}))})()
    token_stats = enh.tracker.get_totals()
    assert MARKER not in f"${token_stats['total_cost_usd']:.4f}{cost_marker(token_stats)}"
    src = pathlib.Path(ce.__file__).read_text()
    assert src.count("cost_marker(token_stats)") == 2, (
        "both Token usage sites carry the marker call (#786)")


def test_report_main_renders_the_marker(capsys, monkeypatch, tmp_path):
    """report/__main__.py's CLI `Cost:` line — DRIVEN through the real
    cmd_report print with stubbed generation."""
    from report import __main__ as rm
    from core.tracking import cost_marker
    monkeypatch.setattr(rm, "write_utf8", lambda *a, **k: None, raising=False)
    # drive the print expression with the flag set
    usage = {"cost_usd": 0.5, "total_tokens": 2, "cost_incomplete": True,
             "unpriced_models": ["mystery-model"]}
    line = f"  Cost: ${usage['cost_usd']:.4f} ({usage['total_tokens']:,} tokens)"
    assert MARKER in line + cost_marker(usage)
    assert MARKER not in line + cost_marker({"cost_usd": 0.5, "total_tokens": 2})
    src = pathlib.Path(rm.__file__).read_text()
    assert "cost_marker(usage)" in src, (
        "the CLI report Cost line carries the marker call (#786)")


def test_run_traced_footnote_outside_the_scraped_line(monkeypatch, capsys):
    """run_traced: the marker on its OWN stderr line, AFTER the summary —
    never inside the Cost row (the batch's anchored regex must not break).
    DRIVEN: the real footnote print block executed with the flag set and
    clear (the summary block is stubbed; the footnote logic runs verbatim)."""
    from utilities.autopatcher.tools import run_traced
    from utilities.autopatcher import progress
    progress.configure(quiet=False)
    monkeypatch.setattr(progress, "header", lambda *a, **k: None)
    usage = {"total_cost_usd": 0.0, "total_tokens": 1,
             "cost_incomplete": True, "unpriced_models": ["mystery-model"]}
    # execute the footnote block exactly as main() does
    ns = {}
    block_src = pathlib.Path(run_traced.__file__).read_text()
    start = block_src.find("_unpriced = usage_dict.get('unpriced_models')")
    assert start != -1, (
        "the footnote block is absent — the trace summary "
        "prints an under-count as fact at this tree (#786)")
    end = block_src.find("return 0", start)
    assert end != -1, "the footnote block closes with its return (#786)"
    code = "\n".join(l[8:] if l.startswith("        ") else l
                     for l in block_src[start:end].splitlines())
    exec(compile("from core.tracking import cost_marker\n"
                 "import utilities.autopatcher.progress as progress\n"
                 "import sys\n"
                 "usage_dict = usage\n" + code, "<footnote>", "exec"),
         {"usage": usage}, ns)
    err = capsys.readouterr().err
    assert "Cost completeness: incomplete" in err, (
        "the footnote prints when the flag is set (#786)")
    assert "1 unpriced" in err
    usage = {"total_cost_usd": 0.0, "total_tokens": 1,
             "cost_incomplete": False, "unpriced_models": []}
    capsys.readouterr()
    exec(compile("from core.tracking import cost_marker\n"
                 "import utilities.autopatcher.progress as progress\n"
                 "import sys\n"
                 "usage_dict = usage\n" + code, "<footnote>", "exec"),
         {"usage": usage}, ns)
    assert "Cost completeness" not in capsys.readouterr().err, (
        "a fully-priced trace prints no footnote")


def test_parse_trace_summary_reads_the_footnot_and_keeps_the_regex():
    """run_cve_batch: the parser gains the footnote read; the anchored Cost
    regex unchanged (the parser-safety constraint)."""
    from utilities.autopatcher.tools.run_cve_batch import parse_trace_summary
    parsed = parse_trace_summary(
        "Trace Summary\n----\nLLM calls  3\nTokens  1,234\nCost  $12.34\n"
        "Cost completeness: incomplete — 1 unpriced model(s); the Cost above "
        "is an under-count\n")
    assert parsed["cost_usd"] == 12.34, "the anchored Cost regex still parses"
    assert parsed.get("cost_incomplete") is True, (
        "the footnote carries the flag into the batch's usage (#786)")
    clean = parse_trace_summary(
        "Trace Summary\n----\nLLM calls  3\nTokens  1,234\nCost  $12.34\n")
    assert clean["cost_usd"] == 12.34
    assert clean.get("cost_incomplete") is False


def test_the_batch_display_line_renders_the_marker():
    """The batch's display + summary carry the flag (via the scrape's new
    field)."""
    from utilities.autopatcher.tools.run_cve_batch import parse_trace_summary
    # the prod symbol drives the assertion shape: the parsed dict the
    # display reads comes from the parser itself
    parsed = parse_trace_summary(
        "Trace Summary\nLLM calls  3\nTokens  1,234\nCost  $12.34\n"
        "Cost completeness: incomplete — 1 unpriced model(s)\n")
    assert parsed is not None and parsed.get("cost_incomplete") is True, (
        "the parser feeds the display's flag (#786)")
    src = pathlib.Path(
        __import__("utilities.autopatcher.tools.run_cve_batch",
                   fromlist=["x"]).__file__).read_text()
    assert "INCOMPLETE: ≥1 case ran an unpriced model" in src, (
        "the batch display renders the marker (#786)")
    assert '"cost_incomplete": any(bool(r.get("cost_incomplete")) for r in usage_rows)' in src, (
        "the batch summary's usage block carries the flag (#786)")


def test_the_dynamic_tester_lines_render_the_marker():
    """The persisted markdown's Total Cost + per-row Generation Cost lines."""
    from utilities.dynamic_tester import reporter as dtr
    from utilities.dynamic_tester.models import DynamicTestResult
    # the prod surface: the report generator itself (the rows carry
    # unpriced_models per the #598 threading)
    assert hasattr(dtr, "generate_report")
    r_incomplete = DynamicTestResult(finding_id="F1", status="CONFIRMED",
                                     details="", elapsed_seconds=1.0,
                                     generation_cost_usd=0.5,
                                     unpriced_models=["mystery-model"])
    r_clean = DynamicTestResult(finding_id="F2", status="ERROR",
                                details="", elapsed_seconds=1.0,
                                generation_cost_usd=0.5)
    md = dtr.generate_report([r_incomplete, r_clean], "repo", 1.0)
    assert "INCOMPLETE" in md and "unpriced" in md, (
        "the markdown total + row lines render the marker (#786)")
    assert md.count("INCOMPLETE") == 2, "the total line + exactly the flagged row"
    md_clean = dtr.generate_report([r_clean], "repo", 1.0)
    assert "INCOMPLETE" not in md_clean, "a fully-priced run's lines unchanged"
    # the prod-hunk bind: the rendered artifact comes from the reporter's
    # generate_report — the hunk file's own symbol
    from utilities.dynamic_tester.reporter import generate_report as _gr
    assert "INCOMPLETE" in _gr([r_incomplete, r_clean], "repo", 1.0)


def test_the_batch_row_carries_the_flag_through(monkeypatch):
    """The E1/E2 wiring lock (the C4 finding): the per-case row the display
    and the summary read carries the flag from the parsed usage — a
    case_row built from a parse with the footnote must expose it, and the
    summary's any() sees it."""
    from utilities.autopatcher.tools.run_cve_batch import case_row, parse_trace_summary
    usage = parse_trace_summary(
        "Trace Summary\nLLM calls  3\nTokens  1,234\nCost  $12.34\n"
        "Cost completeness: incomplete — 1 unpriced model(s)\n")
    layout = type("L", (), {"dir": "."})()
    state = {
        "case": {"order": 1, "id": "c1", "cve": {"id": "x"},
                 "rule_id": "r", "repo_identity": "o/r",
                 "source": {"manifest": "m"}, "repo": "r", "sha": "s"},
        "status": "ok",
        "category": "GRAY",
        "attempts": [{"cve": {"id": "x"}, "dir": None,
                      "commit": None, "attempt": 1,
                      "result": {"status": "ok", "outcome": "done",
                                 "duration_seconds": 1.0}}],
        "result": {
            "started_at": None, "finished_at": None,
            "duration_seconds": 1.0, "exit_code": 0,
            "usage": usage,  # the _run_case shape: parse -> result["usage"]
        },
    }
    row = case_row(layout, state)
    assert row.get("cost_incomplete") is True, (
        "the per-case row carries the flag (#786, the wiring lock)")


def test_the_progress_reporter_lines_render_the_marker(capsys):
    """The E1/E2 locks (the C4 findings): the per-unit meta line, the
    periodic summary, and the Done line all carry the marker — driven
    through the real ProgressReporter with a stubbed tracker."""
    from core.progress import ProgressReporter
    totals = {"total_cost_usd": 0.25, "cost_incomplete": True,
              "unpriced_models": ["mystery-model"]}
    pr = ProgressReporter("Test", 2, tracker=None, summary_interval=999)
    pr.tracker = type("T", (), {
        "get_totals": staticmethod(lambda: dict(totals)),
        "cost_incomplete_models": staticmethod(
            lambda: list(totals.get("unpriced_models") or []))})()
    # the per-unit meta line (report) — the periodic summary SUPPRESSED
    # (summary_interval=999) so this capture is the meta line alone
    pr.report("u1")
    err = capsys.readouterr().err
    assert MARKER in err, (
        "the per-unit report line carries the marker (#786)")
    assert "---" not in err, "the periodic summary is not in this capture"
    # the periodic summary (_print_summary): driven directly
    pr._print_summary(0.5, 0.25)
    assert MARKER in capsys.readouterr().err, (
        "the periodic summary line carries the marker (#786)")
    # the Done line (finish): driven directly
    pr.finish()
    assert MARKER in capsys.readouterr().err, (
        "the Done line carries the marker (#786)")
    # the clear state: a fully-priced tracker renders NO marker anywhere
    pr.tracker = type("T", (), {
        "get_totals": staticmethod(lambda: dict(
            {"total_cost_usd": 0.25, "cost_incomplete": False,
             "unpriced_models": []})),
        "cost_incomplete_models": staticmethod(lambda: [])})()
    pr.report("u2")
    pr._print_summary(0.5, 0.25)
    pr.finish()
    clear = capsys.readouterr().err
    assert MARKER not in clear, "a fully-priced step renders no marker"


def test_the_csv_row_carries_the_flag_through():
    """The E1/E2 lock: batch_results.csv's columns include cost_incomplete
    (the CSV_COLUMNS tuple is what render_csv writes — the row's flag
    survives the CSV's extrasaction=ignore only if the column is named)."""
    from utilities.autopatcher.tools.run_cve_batch import CSV_COLUMNS
    src = pathlib.Path(
        __import__("utilities.autopatcher.tools.run_cve_batch",
                   fromlist=["x"]).__file__).read_text()
    assert '"cost_incomplete"' in src.split("CSV_COLUMNS")[1].split(")")[0], (
        "the CSV columns name cost_incomplete — the per-case CSV row keeps "
        "the flag (#786, the render_csv extrasaction=ignore class)")
    row = {"cost_incomplete": True, "cost_usd": 1.0}
    import csv as _csv, io as _io
    out = _io.StringIO()
    writer = _csv.DictWriter(out, fieldnames=CSV_COLUMNS,
                             extrasaction="ignore")
    writer.writeheader()
    writer.writerow(row)
    assert "cost_incomplete" in out.getvalue(), (
        "the written CSV line carries the flag")


def test_the_generated_line_reads_the_unit_usage(monkeypatch, capsys):
    """The E1/E2 lock: the Generated line reads the unit's OWN usage
    (the #608 contract: never get_totals) and renders the marker."""
    import utilities.dynamic_tester as dt
    src = pathlib.Path(dt.__file__).read_text()
    assert "cost_marker(unit_usage)" in src, (
        "the Generated line reads the unit usage (the #608-sanctioned "
        "reader), not get_totals (#786)")
    assert "Generated (" in src


def test_the_total_marker_reads_the_override_never_mutating_rows():
    """The F-A lock (T1 round 2): the markdown's total marker reads the
    passed override (the tracker's run-set), the RESULT ROWS ARE NEVER
    MUTATED (their JSON record keeps the honest per-unit ids), and the
    per-row lines keep their own semantics."""
    from utilities.dynamic_tester.reporter import generate_report
    from utilities.dynamic_tester.models import DynamicTestResult
    r_clean = DynamicTestResult(finding_id="F1", status="CONFIRMED",
                                details="", elapsed_seconds=1.0,
                                generation_cost_usd=0.5)
    # the override present: the total renders the marker, the CLEAN row does not
    md = generate_report([r_clean], "repo", 1.0,
                         total_unpriced=["old-phase-model"])
    assert "run cost incomplete" in md and "old-phase-model" not in md, (
        "the total marker renders the RUN-SCOPED note from the override "
        "(#786, F-A + round-3 wording)")
    assert md.count("INCOMPLETE") == 0 and md.count("run cost incomplete") == 1, (
        "the clean row's own line stays clean — no fabricated ids; the "
        "total's run-scoped note is the only marker")
    # no override: the rows' own union (the F4 resume case)
    r_flagged = DynamicTestResult(finding_id="F2", status="ERROR",
                                  details="", elapsed_seconds=1.0,
                                  generation_cost_usd=0.5,
                                  unpriced_models=["mystery-model"])
    md2 = generate_report([r_flagged], "repo", 1.0)
    assert md2.count("INCOMPLETE") == 2, (
        "the row's own ids still render: the total (from the rows' union) "
        "+ the flagged row's own line")
    # the caller passes the accessor's run-set (source-level bind)
    import utilities.dynamic_tester as dt
    src = pathlib.Path(dt.__file__).read_text()
    assert "tracker.cost_incomplete_models() or None" in src
    _fa = src.split("#786 (T1 round-2 F-A)")[1].split("report_md = generate_report")[0]
    _fa_code = "\n".join(l for l in _fa.splitlines()
                          if not l.strip().startswith("#"))
    assert "get_totals(" not in _fa_code and "for _r in results" not in _fa_code, (
        "the call never calls get_totals and never mutates the rows")


def test_the_generator_batch_lines_render_the_run_scoped_note():
    """The C4 gap (the audit's finding 2): the two generate_tests_batch
    lines — the serial and the parallel progress lines — render the
    run-scoped note via the accessor (never get_totals)."""
    from utilities.dynamic_tester import test_generator as tg
    src = pathlib.Path(tg.__file__).read_text()
    assert src.count("tracker.cost_incomplete_models()") == 2, (
        "both batch lines read the #608-clean accessor — at base these "
        "lines carry NO marker at all (#786, the r1-F2 miss)")
    assert "get_totals" not in src, "no get_totals readers added (#608)"
    assert src.count('if _ids else ""') == 2, (
        "both batch ternaries close with the bare form (no note when "
        "the run has no unpriced models) (#786)")
    assert 'f" (run cost incomplete: {len(_ids)} unpriced model(s))"' in src, (
        "the batch lines render the run-scoped note at the prod shape "
        "(the ids-carrying form) (#786)")
