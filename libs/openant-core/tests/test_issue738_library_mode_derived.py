"""#738 — when app-context classifies a target as ``library``, the
reachability filter has already pruned the public API: the classification
arrives too late to matter, and nothing suggests re-running with
``--library-mode``. The campaign's measured evidence: swift-jpeg
classified ``library`` (conf 0.85), ran unflagged — 23 of 414 units kept
(94% pruned, the decoder core gone); re-run WITH the flag: 288 units
(12.5x coverage). grpc-swift: ``HTTP2ToRawGRPCStateMachine`` (38 units)
pruned as orphans. The classification is nondeterministic across runs
(the compounding hazard: Libnotify flipped library→unsupported on resume),
so an operator who checks once cannot rely on the flag being right.

THE RULING (the issue's shape 1 + shape 2):
  1. the DERIVATION: the --llm-reachability re-filter (the one filter that
     runs AFTER app-context exists) derives the library seeding from the
     classification it can already see — the CLI flag absent AND the
     payload says ``library`` ⇒ the exported public API seeds the BFS;
     the derivation is RECORDED (the step summary's present-only
     ``library_mode_derived`` marker + the stderr note), because the
     classification's nondeterminism means the artifact must show WHICH
     mode the run used.
  2. the DIRECTIVE: in default mode (no --llm-reachability) there is no
     post-context re-filter to derive into — the scan prints the
     re-run suggestion at the app-context step instead.

Shapes:
  S1 -- the WITNESS (the regression shape, end-to-end): the REAL scan
        with --llm-reachability, a library-classified payload, a corpus
        whose only structural seed is a `main` that does NOT reach the
        exported API: the exported surface is KEPT (the derivation
        seeded it) — at base the same scan prunes it — and the step
        report carries the derived marker.
  S2 -- the control: the same scan with a web_app payload → NO
        derivation (the exported API pruned, no marker — the flag-less
        behavior unchanged).
  S3 -- the explicit-flag control: --library-mode on the CLI → the same
        kept set, NO derived marker (the flag was explicit).
  S4 -- the default-mode directive: the scan WITHOUT --llm-reachability,
        the library payload → the re-run suggestion prints (the parse-time
        filter already pruned; the scan says so).
  S5 -- the web_app default-mode control: no suggestion.
  S6 -- the marker's absent-by-default pin: the plain llm-reach step
        summary carries no library_mode_derived key when nothing derived.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# The corpus: `main` is the only structural seed; it reaches `helper`
# only. The exported API (Exported -> Internal) is NOT reachable from
# main — the pure-library shape the issue measured (the pruned set
# included the decoder core).
_FUNCTIONS = {
    "app.go:main": {"name": "main", "is_exported": True,
                    "file_path": "app.go"},
    "app.go:helper": {"name": "helper", "is_exported": False,
                      "file_path": "app.go"},
    "lib.go:Exported": {"name": "Exported", "is_exported": True,
                        "file_path": "lib.go"},
    "lib.go:Internal": {"name": "Internal", "is_exported": False,
                        "file_path": "lib.go"},
}
_REVERSE = {
    "app.go:helper": ["app.go:main"],
    "lib.go:Internal": ["lib.go:Exported"],
}
_UNITS = [{"id": i, "unit_type": "function", "code": {"primary_code": "..."}}
          for i in _FUNCTIONS]


def _write_corpus(out_dir: Path):
    """The parse stub's job: dataset.json + the FLAT legacy
    call_graph.json (resolve_call_graph_dirs' {None: run_dir} shape)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "dataset.json").write_text(json.dumps(
        {"units": _UNITS, "metadata": {}}))
    (out_dir / "call_graph.json").write_text(json.dumps(
        {"functions": _FUNCTIONS, "call_graph": {}, "reverse_call_graph": _REVERSE}))
    (out_dir / "analyzer.json").write_text("{}")


def _install(monkeypatch, tmp_path: Path, app_type: str):
    """The offline scaffold: parse stubbed (writes the corpus), the
    app-context generator stubbed (writes the payload with app_type),
    the llm-reach analyzer stubbed (no signals), the probe stubbed.
    The REACHABILITY FILTER, the re-filter, the derivation and the
    directive all run REAL."""
    import core.parser_adapter as parser_adapter
    import core.analyzer as analyzer
    import core.llm_reachability as llm_reach
    import utilities.llm as llm_mod
    from context.application_context import ApplicationContext

    class _ParseResult:
        def __init__(self, output_dir):
            self.dataset_path = str(Path(output_dir) / "dataset.json")
            self.analyzer_output_path = str(Path(output_dir) / "analyzer.json")
            self.units_count = len(_UNITS)
            self.language = "go"
            self.processing_level = "all"   # parse defers filtering to the re-run

    def _fake_parse(*, output_dir, **kwargs):
        _write_corpus(Path(output_dir))
        return _ParseResult(output_dir)

    class _AnalyzeResult:
        def __init__(self, output_dir):
            self.results_path = str(Path(output_dir) / "results.json")
            Path(self.results_path).write_text(json.dumps(
                {"results": [], "code_by_route": {}}))
            from core.analyzer import AnalysisMetrics
            self.metrics = AnalysisMetrics(
                total=len(_UNITS), vulnerable=0, bypassable=0,
                inconclusive=0, protected=0, safe=len(_UNITS), errors=0)

    def _fake_analyze(*, output_dir, **kwargs):
        return _AnalyzeResult(output_dir)

    def _fake_context(*args, **kwargs):
        return ApplicationContext(
            application_type=app_type, purpose="test",
            confidence=0.85, source="llm")

    monkeypatch.setattr(parser_adapter, "parse_repository", _fake_parse)
    monkeypatch.setattr(analyzer, "run_analysis", _fake_analyze)

    import core.scanner as scanner_mod
    monkeypatch.setattr(scanner_mod, "generate_application_context",
                        _fake_context)
    monkeypatch.setattr(llm_reach, "analyze_reachability",
                        lambda *a, **k: [])
    monkeypatch.setattr(llm_reach, "signals_to_json", lambda s: [])
    monkeypatch.setattr(
        llm_mod, "probe_registry_or_raise", lambda *a, **k: None)
    return scanner_mod


def _scan(monkeypatch, tmp_path: Path, app_type: str, *,
          llm_reachability: bool, library_mode: bool = False,
          level: str = "reachable"):
    scanner_mod = _install(monkeypatch, tmp_path, app_type)
    out = tmp_path / f"out-{app_type}-{llm_reachability}-{library_mode}"
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        r = scanner_mod.scan_repository(
            repo_path=str(tmp_path),
            output_dir=str(out),
            language="go",
            generate_context=True,
            llm_reachability=llm_reachability,
            library_mode=library_mode,
            processing_level=level,
            verify=False,
            generate_report=False,
            dynamic_test=False,
            enhance=False,
        )
    return r, out, err.getvalue()


def _final_unit_ids(result) -> set:
    """The units that survived into the final dataset."""
    from utilities.file_io import read_json
    data = read_json(result.dataset_path) or {}
    return {u.get("id") for u in (data.get("units") or [])}


# ---------------------------------------------------------------------------
# S1 — the derivation witness (the regression shape, end-to-end)
# ---------------------------------------------------------------------------
def test_library_payload_derives_the_seeding_and_keeps_the_api(
        tmp_path, monkeypatch):
    result, out, err = _scan(monkeypatch, tmp_path, "library",
                             llm_reachability=True)
    # the derivation keyed on the payload the scan can see — pin the read
    # through the REAL helper (the classification IS library)
    from core.scanner import _read_app_type
    assert _read_app_type(
        str(out / "application_context.json")) == "library"
    ids = _final_unit_ids(result)
    # the exported surface is KEPT — the derivation seeded it
    assert {"lib.go:Exported", "lib.go:Internal"} <= ids, (
        f"the library-classified scan still pruned the exported public "
        f"API (kept: {sorted(ids)!r}) — the #738 gap")
    # the derivation is RECORDED: the step report + the stderr note
    reach = json.loads((out / "llm-reachability.report.json").read_text())
    assert reach["summary"].get("library_mode_derived") is True, (
        f"the derived marker is absent: {reach['summary']!r}")
    assert "--library-mode DERIVED" in err
    # and the corpus's own seed set is intact (main + helper also kept)
    assert {"app.go:main", "app.go:helper"} <= ids
    # F3 (the nondeterminism disclosure): the reachability_filter METADATA
    # records the mode — the operator diffing two dataset.json coverage
    # deltas reads THIS record, not the step report
    from utilities.file_io import read_json as _rj
    _md = (_rj(result.dataset_path) or {}).get("metadata") or {}
    _rf = _md.get("reachability_filter") or {}
    assert _rf.get("library_mode") is True, (
        f"the filter metadata lost the seeding mode: {_rf!r}")
    assert _rf.get("library_mode_derived") is True, (
        f"the filter metadata lost the derived marker: {_rf!r}")
    # the PER-LANGUAGE record carries the mode too (the parser_adapter
    # branch records — a reader diffing one language's coverage reads
    # the per-language copy, not the aggregate)
    _per_lang = _rf.get("per_language") or {}
    assert all(r.get("library_mode") is True for r in _per_lang.values()), (
        f"a per-language filter record lost the seeding mode: {_per_lang!r}")


# ---------------------------------------------------------------------------
# S2/S3 — the no-derivation controls
# ---------------------------------------------------------------------------
def test_web_app_payload_never_derives(tmp_path, monkeypatch):
    result, out, err = _scan(monkeypatch, tmp_path, "web_app",
                             llm_reachability=True)
    ids = _final_unit_ids(result)
    # the flag-less behavior UNCHANGED: the exported API stays pruned
    assert "lib.go:Exported" not in ids, (
        f"a web_app scan kept the library surface: {sorted(ids)!r}")
    reach = json.loads((out / "llm-reachability.report.json").read_text())
    assert "library_mode_derived" not in reach["summary"], (
        "a web_app scan grew a derived marker")
    assert "DERIVED" not in err


def test_explicit_flag_never_marks_derived(tmp_path, monkeypatch):
    result, out, err = _scan(monkeypatch, tmp_path, "library",
                             llm_reachability=True, library_mode=True)
    ids = _final_unit_ids(result)
    assert {"lib.go:Exported", "lib.go:Internal"} <= ids, (
        f"the explicit --library-mode lost the exported surface: {sorted(ids)!r}")
    reach = json.loads((out / "llm-reachability.report.json").read_text())
    assert "library_mode_derived" not in reach["summary"], (
        "an explicit CLI flag read as derived")
    assert "DERIVED" not in err


# ---------------------------------------------------------------------------
# S4/S5 — the default-mode directive
# ---------------------------------------------------------------------------
def test_default_mode_library_payload_prints_the_directive(
        tmp_path, monkeypatch):
    result, out, err = _scan(monkeypatch, tmp_path, "library",
                             llm_reachability=False)
    # the directive keyed on the payload the scan can see — pin the read
    # through the REAL helper (the classification IS library)
    from core.scanner import _read_app_type
    assert _read_app_type(
        str(out / "application_context.json")) == "library", (
        "the payload the scan classified is not a library — the directive "
        "fired for the wrong reason")
    assert "re-run with --library-mode" in err, (
        "the default-mode library scan never told the operator the public "
        "API was pruned — the #738 shape-2 ask")


def test_default_mode_web_app_prints_no_directive(tmp_path, monkeypatch):
    _, _, err = _scan(monkeypatch, tmp_path, "web_app",
                      llm_reachability=False)
    assert "re-run with --library-mode" not in err


def test_default_mode_library_with_flag_prints_no_directive(
        tmp_path, monkeypatch):
    _, _, err = _scan(monkeypatch, tmp_path, "library",
                      llm_reachability=False, library_mode=True)
    assert "re-run with --library-mode" not in err, (
        "the operator already set the flag — the directive would be noise")


# ---------------------------------------------------------------------------
# S6 — the marker absent by default (present-only)
# ---------------------------------------------------------------------------
def test_level_all_never_derives(tmp_path, monkeypatch):
    """processing_level="all" never filters — the derivation is moot and
    must not fire (the re-filter block is level-gated). The T1-r1 F1
    catch: this path NEVER ENTERS the re-filter block, so the pre-stage
    local is what keeps the summary build from crashing the step into
    skipped/failed (an in-block-only assignment took every --level all
    run's llm-reach telemetry down with an UnboundLocalError the #268
    guard swallowed) — assert the STEP STATUS, not just the kept set."""
    result, out, err = _scan(monkeypatch, tmp_path, "library",
                             llm_reachability=True, level="all")
    ids = _final_unit_ids(result)
    assert len(ids) == len(_UNITS), (
        f"level=all filtered the corpus: {sorted(ids)!r}")
    assert "DERIVED" not in err
    # the step SUCCEEDED — the whole telemetry intact (the F1 falsifier)
    reach = json.loads((out / "llm-reachability.report.json").read_text())
    assert reach["status"] == "success", (
        f"the level-all llm-reach step degraded: {reach.get('status')!r} "
        f"({reach.get('summary', {}).get('reason', '')!r})")
    assert "library_mode_derived" not in reach["summary"]


def test_no_call_graph_never_derives_and_step_stays_green(
        tmp_path, monkeypatch):
    """The second crash path (the T1-r1 F1 catch): a parser that persists
    NO call_graph.json takes the else-branch — the re-filter block is
    skipped, the summary build still reads the flag, and the step must
    stay green with its own warning, never crash into skipped/failed."""
    import core.scanner as scanner_mod
    # the parse stub that writes NO call_graph.json
    import core.parser_adapter as parser_adapter

    def _bare_parse(*, output_dir, **kwargs):
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "dataset.json").write_text(json.dumps(
            {"units": _UNITS, "metadata": {}}))
        (out / "analyzer.json").write_text("{}")

        class _PR:
            dataset_path = str(out / "dataset.json")
            analyzer_output_path = str(out / "analyzer.json")
            units_count = len(_UNITS)
            language = "go"
            processing_level = "all"
        return _PR()

    monkeypatch.setattr(parser_adapter, "parse_repository", _bare_parse)
    import core.analyzer as analyzer
    import core.llm_reachability as llm_reach
    import utilities.llm as llm_mod

    class _AnalyzeResultBare:
        def __init__(self, output_dir):
            self.results_path = str(Path(output_dir) / "results.json")
            Path(self.results_path).write_text(json.dumps(
                {"results": [], "code_by_route": {}}))
            from core.analyzer import AnalysisMetrics
            self.metrics = AnalysisMetrics(
                total=len(_UNITS), vulnerable=0, bypassable=0,
                inconclusive=0, protected=0, safe=len(_UNITS), errors=0)

    monkeypatch.setattr(analyzer, "run_analysis",
                        lambda *, output_dir, **kw: _AnalyzeResultBare(output_dir))
    monkeypatch.setattr(llm_reach, "analyze_reachability",
                        lambda *a, **k: [])
    monkeypatch.setattr(llm_reach, "signals_to_json", lambda s: [])
    monkeypatch.setattr(
        llm_mod, "probe_registry_or_raise", lambda *a, **k: None)

    out = tmp_path / "out-nocg"
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        scanner_mod.scan_repository(
            repo_path=str(tmp_path), output_dir=str(out),
            language="go", generate_context=False,
            llm_reachability=True, processing_level="reachable",
            verify=False, generate_report=False, dynamic_test=False,
            enhance=False,
        )
    reach = json.loads((out / "llm-reachability.report.json").read_text())
    assert reach["status"] == "success", (
        f"the no-call-graph llm-reach step degraded: {reach.get('status')!r}")
    assert "library_mode_derived" not in reach["summary"]
    assert "refiltering" in err.getvalue() or "re-filter" in err.getvalue(), (
        "the no-call-graph warning is gone")


# ---------------------------------------------------------------------------
# S9 — the KEEP-ALL branch's record carries the mode too: a corpus with NO
# real seeds (pure-private library) + the explicit flag takes the
# empty-seed safety net, and its record must still name the seeding mode
# ---------------------------------------------------------------------------
def test_keep_all_record_carries_the_mode(tmp_path, monkeypatch):
    import core.scanner as scanner_mod
    import core.parser_adapter as parser_adapter
    import core.analyzer as analyzer
    import core.llm_reachability as llm_reach
    import utilities.llm as llm_mod

    # a pure-private corpus: nothing exported, no main — library seeding
    # finds nothing and the empty-seed safety net fires (the keep-all)
    funcs = {
        "priv.go:_hidden": {"name": "_hidden", "is_exported": False,
                            "file_path": "priv.go"},
    }
    units = [{"id": i, "unit_type": "function",
              "code": {"primary_code": "..."}} for i in funcs]

    class _PR:
        def __init__(self, output_dir):
            self.dataset_path = str(Path(output_dir) / "dataset.json")
            self.analyzer_output_path = str(Path(output_dir) / "analyzer.json")
            self.units_count = len(units)
            self.language = "go"
            self.processing_level = "all"

    def _fake_parse(*, output_dir, **kwargs):
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "dataset.json").write_text(json.dumps(
            {"units": units, "metadata": {}}))
        (out / "call_graph.json").write_text(json.dumps(
            {"functions": funcs, "call_graph": {},
             "reverse_call_graph": {}}))
        (out / "analyzer.json").write_text("{}")
        return _PR(output_dir)

    class _AR:
        def __init__(self, output_dir):
            self.results_path = str(Path(output_dir) / "results.json")
            Path(self.results_path).write_text(json.dumps(
                {"results": [], "code_by_route": {}}))
            from core.analyzer import AnalysisMetrics
            self.metrics = AnalysisMetrics(
                total=len(units), vulnerable=0, bypassable=0,
                inconclusive=0, protected=0, safe=len(units), errors=0)

    monkeypatch.setattr(parser_adapter, "parse_repository", _fake_parse)
    monkeypatch.setattr(analyzer, "run_analysis",
                        lambda *, output_dir, **kw: _AR(output_dir))
    monkeypatch.setattr(llm_reach, "analyze_reachability",
                        lambda *a, **k: [])
    monkeypatch.setattr(llm_reach, "signals_to_json", lambda s: [])
    monkeypatch.setattr(
        llm_mod, "probe_registry_or_raise", lambda *a, **k: None)

    out = tmp_path / "out-keepall"
    import contextlib, io
    with contextlib.redirect_stderr(io.StringIO()):
        r = scanner_mod.scan_repository(
            repo_path=str(tmp_path), output_dir=str(out),
            language="go", generate_context=False,
            llm_reachability=True, library_mode=True,
            processing_level="reachable",
            verify=False, generate_report=False, dynamic_test=False,
            enhance=False,
        )
    from utilities.file_io import read_json as _rj
    _rf = ((_rj(r.dataset_path) or {}).get("metadata") or {}).get(
        "reachability_filter") or {}
    # the keep-all fired (the safety net)
    assert "warning" in _rf, f"the keep-all did not fire: {_rf!r}"
    assert _rf.get("library_mode") is True, (
        f"the keep-all record lost the seeding mode: {_rf!r}")
    per = _rf.get("per_language") or {}
    assert all(x.get("library_mode") is True for x in per.values()), (
        f"the keep-all per-language record lost the mode: {per!r}")
