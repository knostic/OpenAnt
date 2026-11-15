"""#714: the reporter's narrow-except sidecar reads — broadened + pinned, and
the report-step skip hoisted pre-build.

PR #257 broadened two `except (OSError, json.JSONDecodeError)` reads in
`core/scanner.py` to `except Exception` because `read_json` opens strict
UTF-8 and raises `UnicodeDecodeError` (a `ValueError`), escaping the narrow
clause. It named "a parallel narrow-except JSON read in `core/reporter.py`"
as a follow-up. #714 found FOUR such reads in reporter.py (the review
rounds then traced the same class to EIGHT more reads along the file's
consumer paths — the scan, the parse CLI, the report package, and the
report-data loader's three reads); the issue's own executed repro:

  a dataset.json with an invalid byte raised UnicodeDecodeError out of
  `_load_reachability_metadata` and ABORTED report building.

The falsifier: "a bad-encoding sidecar that the reporter degrades past, and a
pipeline_output.json carrying a dynamic-test or report skip."
"""

import json
import os
import sys
from pathlib import Path

import pytest


_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))


def _bad_encoding_file(dirpath, name, prefix=b"{}"):
    """A sidecar file with a valid JSON prefix + an invalid UTF-8 byte:
    `read_json` opens strict UTF-8, so json.load raises UnicodeDecodeError
    (the ValueError outside the old narrow clause)."""
    path = os.path.join(dirpath, name)
    with open(path, "wb") as fh:
        fh.write(prefix + b'"\xff\xfe"}')
    return path


# --- the four reporter sidecar reads: degrade, never abort ---

def test_a_bad_encoding_dataset_json_degrades(tmp_path, capsys):
    """THE issue's own executed repro: _load_reachability_metadata on a
    bad-encoding dataset.json must return None (the degrade contract), not
    raise UnicodeDecodeError (the abort it did at base)."""
    from core.reporter import _load_reachability_metadata
    _bad_encoding_file(str(tmp_path), "dataset.json",
                       b'{"metadata": {"reachability_filter": {"selected": 1}}, "x": ')
    assert _load_reachability_metadata(str(tmp_path)) is None
    # the warning names the file (the #257 per-site pattern)
    captured = capsys.readouterr()
    assert "dataset.json" in captured.err


def test_a_bad_encoding_diff_manifest_degrades(tmp_path, capsys):
    """The diff-manifest read: a bad-encoding manifest means "no diff" —
    the block degrades to None, never crashes."""
    from core.reporter import _load_diff_metadata
    _bad_encoding_file(str(tmp_path), "diff_manifest.json",
                        b'{"base_ref": "main", ')
    assert _load_diff_metadata(str(tmp_path)) is None
    assert "diff_manifest.json" in capsys.readouterr().err


def test_a_bad_encoding_diff_filter_report_degrades(tmp_path, capsys):
    """The diff-filter-report read: the block degrades to "no filter
    stats", never crashes."""
    from core.reporter import _load_diff_metadata
    # the manifest must parse for the filter read to be reached
    with open(os.path.join(str(tmp_path), "diff_manifest.json"), "w") as fh:
        json.dump({"base_ref": "main"}, fh)
    _bad_encoding_file(str(tmp_path), "diff_filter.report.json")
    block = _load_diff_metadata(str(tmp_path))
    assert block is not None and "units_in_diff" not in block
    assert "diff_filter.report.json" in capsys.readouterr().err


def test_a_bad_encoding_call_graph_degrades(tmp_path, capsys):
    """The call-graph read: the dedup path degrades to the input
    confirmed set, never crashes."""
    from core.reporter import _dedup_caller_callee
    _bad_encoding_file(str(tmp_path), "call_graph.json")
    confirmed = [{"route_key": "x", "cwe_id": 1}]
    out = _dedup_caller_callee(confirmed, [{"route_key": "x", "cwe_id": 1}],
                               os.path.join(str(tmp_path), "call_graph.json"))
    assert out == confirmed, "the bad-encoding call graph must degrade to the input set"
    assert "call_graph.json" in capsys.readouterr().err


def test_a_good_sidecar_still_loads(tmp_path):
    """The control: a valid sidecar loads exactly as before."""
    from core.reporter import _load_reachability_metadata
    path = os.path.join(str(tmp_path), "dataset.json")
    with open(path, "w") as fh:
        json.dump({"metadata": {"reachability_filter": {"selected": 5, "total": 10}}}, fh)
    md = _load_reachability_metadata(str(tmp_path))
    assert md is not None
    assert md["selected"] == 5


# --- the shape class (B1, the r1 review): valid JSON, wrong top level ---

@pytest.mark.parametrize("shape", ["[]", "null", '"s"', "1"])
def test_a_non_dict_manifest_degrades(tmp_path, shape):
    """A pipeline-produced sidecar with a corrupted top-level type is
    still corruption — it degrades to "no diff" (the
    _load_reachability_metadata site's own isinstance precedent), never
    an AttributeError abort out of the .get() below the try."""
    from core.reporter import _load_diff_metadata
    with open(os.path.join(str(tmp_path), "diff_manifest.json"), "w") as fh:
        fh.write(shape)
    assert _load_diff_metadata(str(tmp_path)) is None


@pytest.mark.parametrize("shape", ["[]", "null", '"s"', "1"])
def test_a_non_dict_call_graph_degrades(tmp_path, shape):
    """Same shape class on the call-graph read: degrade to the input
    confirmed set, never an AttributeError abort."""
    from core.reporter import _dedup_caller_callee
    with open(os.path.join(str(tmp_path), "call_graph.json"), "w") as fh:
        fh.write(shape)
    confirmed = [{"route_key": "x", "cwe_id": 1}]
    out = _dedup_caller_callee(confirmed, [],
                               os.path.join(str(tmp_path), "call_graph.json"))
    assert out == confirmed


def test_a_non_dict_filter_report_degrades_silently(tmp_path, capsys):
    """D1's true-message contract: a READ failure warns ("could not
    read"); a SHAPE failure (valid JSON, non-dict) degrades to no filter
    keys SILENTLY — the read succeeded, so the warning would be false."""
    from core.reporter import _load_diff_metadata
    with open(os.path.join(str(tmp_path), "diff_manifest.json"), "w") as fh:
        json.dump({"base_ref": "main"}, fh)
    with open(os.path.join(str(tmp_path), "diff_filter.report.json"), "w") as fh:
        fh.write("[]")
    block = _load_diff_metadata(str(tmp_path))
    assert block is not None and "units_in_diff" not in block
    assert capsys.readouterr().err == "", (
        "a shape failure must not print a read failure's warning")


# --- the scanner's own site (F3, the r1 review): the same file, Step 1 ---

def test_a_bad_encoding_filter_report_does_not_abort_the_scan(
        tmp_path, monkeypatch):
    """F3: scanner.py's own read of diff_filter.report.json (the parse
    step's summary attach) used the SAME narrow clause — and inside
    step_context, which re-raises, a bad-encoding file ABORTED THE WHOLE
    SCAN at Step 1, before the reporter's degrade for the same file was
    ever reached. The scan must complete: the summary degrades to no
    diff_stats, pipeline_output.json still gets built."""
    repo = str(tmp_path / "repo")
    os.makedirs(repo)
    with open(os.path.join(repo, "a.py"), "w") as fh:
        fh.write("def f(): pass\n")
    out = str(tmp_path / "out")
    os.makedirs(out)
    # the planted bad-encoding sidecar: the parse step reads it because
    # it EXISTS in the output dir before the scan
    with open(os.path.join(out, "diff_filter.report.json"), "wb") as fh:
        fh.write(b'{"selected": 1, "\xff\xfe"}')
    _scan_with_stubbed_analysis(repo, out, monkeypatch)
    po = os.path.join(out, "pipeline_output.json")
    assert os.path.exists(po), "the scan aborted before the Step-6 build"


# --- the r2 sites: the parse CLI twin + the report-package reads ---

def test_the_parse_cli_degrades_a_bad_encoding_filter_report(tmp_path):
    """F1 (r2): `openant parse` — the public entry the Go CLI dispatches
    — had F3's exact twin clause on the same file, inside its own
    step_context. A bad-encoding diff_filter.report.json made a
    SUCCESSFUL parse exit rc=2 (status error) after every artifact was
    already written. The parse must complete and report success."""
    import subprocess
    repo = str(tmp_path / "repo")
    os.makedirs(repo)
    with open(os.path.join(repo, "a.py"), "w") as fh:
        fh.write("def f(): pass\n")
    out = str(tmp_path / "out")
    os.makedirs(out)
    with open(os.path.join(out, "diff_filter.report.json"), "wb") as fh:
        fh.write(b'{"selected": 1, "\xff\xfe"}')
    proc = subprocess.run(
        [sys.executable, "-m", "openant.cli", "parse", repo, "--output", out],
        capture_output=True, text=True, timeout=180,
        cwd=str(_CORE_ROOT),
    )
    assert proc.returncode == 0, (
        f"the parse aborted on the optional sidecar: {proc.stderr[-400:]}")
    assert "WARNING: could not read" in proc.stderr, (
        "the degrade must warn (the #257 per-site pattern)")


def test_the_csv_export_degrades_a_bad_encoding_pipeline_output(
        tmp_path, capsys):
    """F2a (r2): the CSV export's optional pipeline_output.json read — a
    bad-encoding file killed the WHOLE export via the child exit (the
    banner block is optional; the CSV is the deliverable). Degrade to no
    diff block."""
    from report.csv_export import _load_diff_block
    exp = os.path.join(str(tmp_path), "results.json")
    with open(exp, "w") as fh:
        fh.write("[]")
    with open(os.path.join(str(tmp_path), "pipeline_output.json"), "wb") as fh:
        fh.write(b'{"diff": {"mode": "incremental"}, "\xff\xfe"}')
    assert _load_diff_block(exp) is None
    assert "could not read" in capsys.readouterr().err


def test_the_html_report_degrades_a_bad_encoding_pipeline_output(
        tmp_path, capsys):
    """F2b (r2): the HTML report's read of the same optional file — the
    csv twin's sibling. Degrade to (None, None)."""
    from report.html_report import _load_pipeline_metadata
    exp = os.path.join(str(tmp_path), "results.json")
    with open(exp, "w") as fh:
        fh.write("[]")
    with open(os.path.join(str(tmp_path), "pipeline_output.json"), "wb") as fh:
        fh.write(b'{"repository": {"name": "x"}, "\xff\xfe"}')
    assert _load_pipeline_metadata(exp) == (None, None)
    assert "could not read" in capsys.readouterr().err


@pytest.mark.parametrize("shape", ["[]", "null"])
def test_the_report_package_reads_degrade_a_non_dict_pipeline_output(
        tmp_path, shape):
    """The shape class on the two report-package sites (B1's twin):
    a valid-JSON non-dict pipeline_output.json degrades, never an
    AttributeError out of the .get()."""
    from report.csv_export import _load_diff_block
    from report.html_report import _load_pipeline_metadata
    exp = os.path.join(str(tmp_path), "results.json")
    with open(exp, "w") as fh:
        fh.write("[]")
    with open(os.path.join(str(tmp_path), "pipeline_output.json"), "w") as fh:
        fh.write(shape)
    assert _load_diff_block(exp) is None
    assert _load_pipeline_metadata(exp) == (None, None)


# --- the r3 site: the LIVE HTML path (report-data + the step-report loader) ---

def test_report_data_degrades_a_bad_encoding_step_report(tmp_path):
    """F1 (r3): the report-data command — the HTML deliverable's live
    data source (the Go CLI's `openant report -f html` dispatches to it)
    — loaded *.report.json (a glob that CATCHES diff_filter.report.json,
    the very file three other sites degrade) behind the narrow clause.
    A bad-encoding file killed the whole command; the loader must skip
    the ONE file."""
    import subprocess
    out = str(tmp_path / "out")
    os.makedirs(out)
    with open(os.path.join(out, "results.json"), "w") as fh:
        fh.write('{"results": []}')
    with open(os.path.join(out, "dataset.json"), "w") as fh:
        fh.write('{"units": [], "metadata": {}}')
    with open(os.path.join(out, "diff_filter.report.json"), "wb") as fh:
        fh.write(b'{"selected": 1, "\xff\xfe"}')
    proc = subprocess.run(
        [sys.executable, "-m", "openant.cli", "report-data",
         os.path.join(out, "results.json"),
         "--dataset", os.path.join(out, "dataset.json")],
        capture_output=True, text=True, timeout=180,
        cwd=str(_CORE_ROOT),
    )
    assert proc.returncode == 0, (
        f"report-data died on the optional sidecar: {proc.stderr[-400:]}")
    assert "WARNING: could not read" in proc.stderr


def test_report_data_degrades_a_bad_encoding_pipeline_output(tmp_path):
    """F1's second arm (r3): report-data's own read of
    pipeline_output.json — the r2 F2 file — behind the same narrow
    clause. A bad-encoding file killed the command on the optional
    repo-info block."""
    import subprocess
    out = str(tmp_path / "out")
    os.makedirs(out)
    with open(os.path.join(out, "results.json"), "w") as fh:
        fh.write('{"results": []}')
    with open(os.path.join(out, "dataset.json"), "w") as fh:
        fh.write('{"units": [], "metadata": {}}')
    with open(os.path.join(out, "pipeline_output.json"), "wb") as fh:
        fh.write(b'{"repository": {"name": "x"}, "\xff\xfe"}')
    proc = subprocess.run(
        [sys.executable, "-m", "openant.cli", "report-data",
         os.path.join(out, "results.json"),
         "--dataset", os.path.join(out, "dataset.json")],
        capture_output=True, text=True, timeout=180,
        cwd=str(_CORE_ROOT),
    )
    assert proc.returncode == 0, (
        f"report-data died on the optional pipeline_output: "
        f"{proc.stderr[-400:]}")


def test_report_data_degrades_a_bad_encoding_dt_pair(tmp_path):
    """F1 (r4): the dt BRIDGE reads — cmd_report_data's FIRST reads of
    dynamic_test_results.json AND pipeline_output.json were bare; the
    r3-guarded second read is never reached when the first raises. With a
    dynamic-test run present (the shape every --dynamic-test scan
    leaves), a bad-encoding file in the pair killed report-data. Both
    degrade now: no bridge, the command completes."""
    import subprocess
    out = str(tmp_path / "out")
    os.makedirs(out)
    with open(os.path.join(out, "results.json"), "w") as fh:
        fh.write('{"results": []}')
    with open(os.path.join(out, "dataset.json"), "w") as fh:
        fh.write('{"units": [], "metadata": {}}')
    with open(os.path.join(out, "dynamic_test_results.json"), "w") as fh:
        json.dump({"results": [{"finding_id": "F1", "verdict": "confirmed"}]}, fh)
    with open(os.path.join(out, "pipeline_output.json"), "wb") as fh:
        fh.write(b'{"repository": {"name": "x"}, "\xff\xfe"}')
    proc = subprocess.run(
        [sys.executable, "-m", "openant.cli", "report-data",
         os.path.join(out, "results.json"),
         "--dataset", os.path.join(out, "dataset.json")],
        capture_output=True, text=True, timeout=180,
        cwd=str(_CORE_ROOT),
    )
    assert proc.returncode == 0, (
        f"report-data died on the dt-bridge pair: {proc.stderr[-400:]}")


@pytest.mark.parametrize("shape", ["[]", "null"])
def test_the_step_report_loader_drops_a_non_dict_report(tmp_path, shape):
    """The shape class on the loader (B1's twin): a valid-JSON non-dict
    step report must be dropped at the loader (the single home), never
    reach the four .get()-calling consumers."""
    from openant.cli import _load_step_reports
    with open(os.path.join(str(tmp_path), "parse.report.json"), "w") as fh:
        json.dump({"step": "parse", "status": "success"}, fh)
    with open(os.path.join(str(tmp_path), "bad.report.json"), "w") as fh:
        fh.write(shape)
    reports = _load_step_reports(str(tmp_path))
    assert [r.get("step") for r in reports] == ["parse"], (
        f"the non-dict report leaked through: {reports!r}")


# --- the report-step skip hoist ---

def test_the_report_step_skip_is_hoisted_pre_build():
    """The falsifier's second half: the report-step skip decision must be
    recorded BEFORE the Step-6 pipeline_output build, so the file the
    human summary reads carries it. Pinned at the source: the hoist
    exists in scanner.py before the Step-6 build and the old post-build
    record is gone."""
    src = (_CORE_ROOT / "core" / "scanner.py").read_text()
    # the hoist exists (before the Step-6 section)
    hoist_idx = src.index('if not generate_report:\n        _record_skip(result, "report", "not_requested")')
    build_idx = src.index("Step 6: Build pipeline_output.json")
    assert hoist_idx < build_idx, (
        "the report-skip hoist must precede the Step-6 build")
    # the old post-build record is gone
    old_form = 'print(_step_label("Skipping report generation (--no-report)."), file=sys.stderr)\n        _record_skip(result, "report", "not_requested")'
    assert old_form not in src, (
        "the old post-build report skip survived")


def _scan_with_stubbed_analysis(repo, out, monkeypatch):
    """A real in-process `scan_repository()` run, hermetic offline (the
    #209 fixture pattern): the credential probe + the config resolve are
    neutered, and the TWO LLM steps (parse is local; the analysis is the
    LLM one) return canned on-disk shapes. The Step-6 build is NOT
    stubbed — the real `build_pipeline_output` must write the real
    skipped_steps, or the test would pin nothing."""
    from pathlib import Path as _P
    import utilities.llm as llm_mod
    import core.parser_adapter as parser_adapter
    import core.analyzer as analyzer
    import core.tracking as tracking

    monkeypatch.setattr(
        llm_mod, "probe_registry_or_raise", lambda *a, **k: None, raising=True)
    _orig_resolve = llm_mod.resolve_llm_config
    monkeypatch.setattr(
        llm_mod, "resolve_llm_config",
        lambda cf, name: _orig_resolve(cf, None), raising=True)

    class _ParseResult:
        def __init__(self, output_dir):
            self.dataset_path = str(_P(output_dir) / "dataset.json")
            self.analyzer_output_path = str(_P(output_dir) / "analyzer.json")
            self.units_count = 1
            self.language = "python"
            self.processing_level = "reachable"

    def _fake_parse(*, output_dir, **kwargs):
        pr = _ParseResult(output_dir)
        _P(pr.dataset_path).write_text('{"units": []}')
        _P(pr.analyzer_output_path).write_text("{}")
        return pr

    def _fake_analysis(*, output_dir, **kwargs):
        from core.schemas import AnalyzeResult
        rp = str(_P(output_dir) / "results.json")
        # the experiment envelope `build_pipeline_output` reads: a dict
        # with a "results" key, not a bare list
        _P(rp).write_text(json.dumps({"results": []}))
        return AnalyzeResult(results_path=rp)

    monkeypatch.setattr(parser_adapter, "parse_repository", _fake_parse)
    monkeypatch.setattr(analyzer, "run_analysis", _fake_analysis)
    tracking.reset_tracking()

    from core import scanner
    return scanner.scan_repository(
        repo_path=repo,
        output_dir=out,
        generate_context=False,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_test=False,
    )


def test_pipeline_output_carries_a_report_skip(tmp_path, monkeypatch):
    """End-to-end (the falsifier's second half, the report arm): a
    --no-report scan's pipeline_output.json carries the report skip — the
    two machine artifacts must agree. At base the Step-6 build ran before
    the Step-8 record, so the file the human summary reads said no skips
    while scan.report.json listed one."""
    repo = str(tmp_path / "repo")
    os.makedirs(repo)
    with open(os.path.join(repo, "a.py"), "w") as fh:
        fh.write("def f(): pass\n")
    out = str(tmp_path / "out")
    os.makedirs(out)
    result = _scan_with_stubbed_analysis(repo, out, monkeypatch)
    po = os.path.join(out, "pipeline_output.json")
    assert os.path.exists(po)
    with open(po) as fh:
        data = json.load(fh)
    # the file nests the skips under pipeline_stats (the human summary's
    # read path)
    steps = data.get("pipeline_stats", {}).get("skipped_steps", [])
    names = [s.get("step") for s in steps]
    assert "report" in names, (
        f"the report skip is absent from pipeline_output.json: {names}")
    # exactly once in the file: with the else-branch removal reverted the
    # old post-build record would append "report" a second time
    assert names.count("report") == 1, f"double-recorded: {names}"
    # the two artifacts agree — and the final list carries it exactly
    # once too (the duplicate would land in scan.report.json, written
    # from this list at Final)
    assert result.skipped_steps.count("report") == 1, (
        f"double-recorded in the final list: {result.skipped_steps}")


def test_pipeline_output_carries_a_dynamic_test_skip(tmp_path, monkeypatch):
    """The falsifier's second half, the dynamic-test arm: the default-off
    dynamic-test scan's pipeline_output.json carries the skip (the #799
    contract, re-verified end-to-end alongside its #714 twin)."""
    repo = str(tmp_path / "repo")
    os.makedirs(repo)
    with open(os.path.join(repo, "a.py"), "w") as fh:
        fh.write("def f(): pass\n")
    out = str(tmp_path / "out")
    os.makedirs(out)
    result = _scan_with_stubbed_analysis(repo, out, monkeypatch)
    po = os.path.join(out, "pipeline_output.json")
    assert os.path.exists(po)
    with open(po) as fh:
        data = json.load(fh)
    steps = data.get("pipeline_stats", {}).get("skipped_steps", [])
    names = [s.get("step") for s in steps]
    assert "dynamic-test" in names, (
        f"the dynamic-test skip is absent: {names}")
    assert "dynamic-test" in result.skipped_steps
