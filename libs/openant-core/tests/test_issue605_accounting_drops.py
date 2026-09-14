"""#605: silent accounting drops become loud — both sites.

Two sites silently discarded cost/token accounting on failure paths,
producing complete-looking zero artifacts (the inverse of #598's
wrong-rate substitution — the accounting VANISHES):

* the report-phase tracker hand-off (``_record_usage_in_tracker``):
  the only route by which the report step's spend reaches the tracker
  sat inside ``except Exception: pass`` — a failure there silently
  dropped the step's tokens, and the report step read as $0 / 0
  tokens with ``cost_incomplete=false``.
* the step-report cost snapshot (``_snapshot_usage``): any tracker
  exception substituted a complete-looking zero snapshot — and a
  fabricated baseline corrupts the step-over-step deltas (a failed END
  yields NEGATIVE cost; a failed START charges another step's spend).

The fix: the hand-off failure is COUNTED (a module-level counter — a
poisoned tracker cannot be trusted to count its own failure) and named
on stderr; a failed snapshot is a SENTINEL, the delta is written as
zeros WITHOUT subtracting, and the step's token_usage carries
``accounting_error: True`` — never a complete-looking zero. The marker
OR-aggregates at the scan level.

The consults' critical verification: the except path is NOT reached in
normal local-only operation (the tracker is an always-present singleton
and its imports are in-tree leaf modules) — marking it errored never
false-positives a local step.
"""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest  # noqa: E402
import utilities.llm_client as llm_client  # noqa: E402
from utilities.llm_client import (  # noqa: E402
    reset_global_tracker,
    reset_warning_state,
)


@pytest.fixture(autouse=True)
def _clean_accounting_counter():
    """The module counter AND the tracker reset per test — a test that
    records an error (or an unpriced call) never leaks the marker or the
    unpriced set into a later step-context assertion (the warning-state
    reset alone leaves _unpriced_models on the singleton)."""
    reset_global_tracker()
    yield
    reset_global_tracker()


class _Binding:
    model = "test/model-x"

    def __init__(self):
        self.adapter = _Adapter()


class _Adapter:
    def __init__(self):
        self.pricing = {"test/model-x": {"input": 2.0, "output": 4.0}}


class _EmptyAdapter:
    """An adapter whose pricing map genuinely misses the binding's model."""

    def __init__(self):
        self.pricing = {}


class _MissingBinding(_Binding):
    def __init__(self):
        super().__init__()
        self.adapter = _EmptyAdapter()




# ---------------------------------------------------------------------------
# the report-phase hand-off: counted, never silent
# ---------------------------------------------------------------------------

def test_the_handoff_failure_is_counted_and_named(monkeypatch, capsys):
    """A poisoned record_call: the report generation continues (the
    artifact survives) but the drop is COUNTED (the module-level counter
    surfaces in get_totals) and NAMED on stderr with the exception class."""
    from core import reporter as reporter_mod

    reset_warning_state()

    def _poison(*a, **kw):
        raise RuntimeError("tracker is poisoned")

    # class-level: an instance-level patch leaves the attribute on the
    # singleton past the test's undo
    monkeypatch.setattr(llm_client.TokenTracker, "record_call", _poison)
    reporter_mod._record_usage_in_tracker(
        {"input_tokens": 100, "output_tokens": 50, "total_tokens": 150},
        _Binding())
    err = capsys.readouterr().err
    assert "accounting hand-off failed" in err
    assert "RuntimeError" in err
    assert llm_client.get_global_tracker().get_totals()["accounting_errors"] == 1


def test_the_handoff_pricing_miss_flows_never_raises():
    """A pricing lookup miss (None) FLOWS into record_call (the loud path
    is record_call's own business — the hand-off does not pre-swallow it)."""
    from core import reporter as reporter_mod
    reset_warning_state()
    reporter_mod._record_usage_in_tracker(
        {"input_tokens": 100, "output_tokens": 50, "total_tokens": 150},
        _MissingBinding())
    # the tokens REACHED the tracker (never dropped)
    totals = llm_client.get_global_tracker().get_totals()
    assert totals["total_input_tokens"] >= 100
    assert "accounting_errors" not in totals  # healthy: the key is ABSENT (present-only), not 0


def test_the_healthy_handoff_is_unchanged():
    """The control: a healthy hand-off counts nothing, records the spend."""
    from core import reporter as reporter_mod
    reset_warning_state()
    reporter_mod._record_usage_in_tracker(
        {"input_tokens": 100, "output_tokens": 50, "total_tokens": 150},
        _Binding())
    # healthy: the key is ABSENT (the present-only contract — a healthy
    # run's totals serialize byte-identical to pre-#605)
    assert "accounting_errors" not in llm_client.get_global_tracker().get_totals()


# ---------------------------------------------------------------------------
# the step-report snapshot: the sentinel + the delta
# ---------------------------------------------------------------------------

def test_a_failed_end_snapshot_never_fabricates_a_delta(monkeypatch, tmp_path):
    """THE delta receipt: a step whose START snapshot is real (non-zero
    spend before it) and whose END is poisoned — pristine produced a
    NEGATIVE delta; post-fix: zeros + accounting_error, never negative."""
    from core import step_report as sr_mod
    reset_warning_state()
    tracker = llm_client.get_global_tracker()
    tracker.reset()
    tracker.record_call("m", 1000, 500,
                       pricing={"input": 2.0, "output": 4.0})

    # poison get_usage for the END snapshot only (the 2nd call)
    calls = {"n": 0}
    import core.tracking as tracking_mod
    real_get_usage = tracking_mod.get_usage  # capture BEFORE the patch

    def _poisoned_second():
        calls["n"] += 1
        if calls["n"] >= 2:
            raise RuntimeError("tracker exploded")
        return real_get_usage()

    monkeypatch.setattr("core.tracking.get_usage", _poisoned_second)
    with sr_mod.step_context("test-step", str(tmp_path)):
        pass
    report = json.loads((tmp_path / "test-step.report.json").read_text())
    # THE NEGATIVE-DELTA DISCRIMINATION: the healthy START carried a real
    # baseline (the $0.004 recorded before the step); pristine's fabricated
    # subtraction yielded cost = 0 - 0.004 < 0 — the post-fix shape is
    # zero + the marker (never negative, never fabricated).
    assert report["cost_usd"] == 0.0
    assert report["cost_usd"] >= 0.0  # the pristine receipt was negative
    assert report["token_usage"]["accounting_error"] is True
    assert report["token_usage"]["cost_incomplete"] is True
    assert report["token_usage"]["total_tokens"] == 0


def test_a_failed_start_snapshot_does_not_charge_the_next_step(monkeypatch, tmp_path):
    """A failed START with a healthy END: pristine charged the step the
    whole run's cumulative spend (a fabricated zero baseline); post-fix:
    the delta is unavailable — zeros + the marker."""
    from core import step_report as sr_mod
    reset_warning_state()
    tracker = llm_client.get_global_tracker()
    tracker.reset()
    calls = {"n": 0}
    import core.tracking as tracking_mod
    real_get_usage = tracking_mod.get_usage  # capture BEFORE the patch

    def _poisoned_first():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("tracker exploded at start")
        return real_get_usage()

    monkeypatch.setattr("core.tracking.get_usage", _poisoned_first)
    # the run carries an unpriced model — the healthy END snapshot's ids
    # must SURVIVE the sentinel (the which-model disclosure is not lost
    # to the start failure)
    tracker.record_call(model="mystery/model-s", input_tokens=3,
                        output_tokens=1)
    with sr_mod.step_context("test-step2", str(tmp_path)):
        pass
    report = json.loads((tmp_path / "test-step2.report.json").read_text())
    assert report["cost_usd"] == 0.0
    assert report["token_usage"]["accounting_error"] is True
    assert report["token_usage"]["unpriced_models"] == ["mystery/model-s"]


def test_a_healthy_local_step_never_flags(monkeypatch, tmp_path):
    """THE consults' critical verification: the local-only path (the
    always-present singleton, real empty totals) reads as a clean zero —
    the marker never false-positives a healthy step."""
    from core import step_report as sr_mod
    reset_warning_state()
    with sr_mod.step_context("local-step", str(tmp_path)):
        pass
    report = json.loads((tmp_path / "local-step.report.json").read_text())
    assert report["cost_usd"] == 0.0
    assert "accounting_error" not in report["token_usage"]
    assert "cost_incomplete" not in report["token_usage"]


def test_the_mid_run_drop_flags_the_next_healthy_step(tmp_path):
    """A mid-run accounting drop (another phase's hand-off failure) marks
    the NEXT healthy step's report too — the run-cumulative trade (the
    same accepted shape as #216's unpriced marker)."""
    from core import step_report as sr_mod
    reset_warning_state()
    llm_client.record_accounting_error()
    with sr_mod.step_context("after-drop", str(tmp_path)):
        pass
    report = json.loads((tmp_path / "after-drop.report.json").read_text())
    # BOTH markers, never one without the other (the dropped spend makes the
    # cost figure incomplete AND errored)
    assert report["token_usage"].get("accounting_error") is True
    assert report["token_usage"].get("cost_incomplete") is True


# ---------------------------------------------------------------------------
# the scan aggregate: the marker OR-aggregates
# ---------------------------------------------------------------------------

def test_the_scan_aggregate_carries_the_marker(tmp_path):
    """A step report with the marker ORs into the scan aggregate's
    token_usage — the drop never vanishes at the scan level (a BEHAVIORAL
    receipt: the real _write_scan_report with a synthetic step report)."""
    from core.schemas import ScanResult, AnalysisMetrics
    from core.scanner import _write_scan_report
    out = tmp_path / "out"
    out.mkdir()
    metrics = AnalysisMetrics(total=0, vulnerable=0, bypassable=0,
                              inconclusive=0, protected=0, safe=0, errors=0)
    result = ScanResult(output_dir=str(out), units_count=0,
                        language="python", metrics=metrics)
    step_reports = [{
        "step": "report", "status": "success", "cost_usd": 0.0,
        "duration_seconds": 0.1,
        "token_usage": {"input_tokens": 0, "output_tokens": 0,
                        "total_tokens": 0, "cost_incomplete": True,
                        "accounting_error": True},
    }]
    _write_scan_report(str(out), result, step_reports,
                       repo_path=str(tmp_path / "repo"))
    scan = json.loads((out / "scan.report.json").read_text())
    assert scan["token_usage"].get("accounting_error") is True
    assert scan["token_usage"].get("cost_incomplete") is True


def test_the_reset_clears_the_counter():
    reset_warning_state()
    llm_client.record_accounting_error()
    assert llm_client.get_global_tracker().get_totals()["accounting_errors"] == 1
    reset_warning_state()
    assert "accounting_errors" not in llm_client.get_global_tracker().get_totals()

def test_the_scan_aggregate_negative_is_silent(tmp_path):
    """The control: step reports WITHOUT the marker never fabricate it
    at the scan level (present-only, never a blanket key)."""
    from core.schemas import ScanResult, AnalysisMetrics
    from core.scanner import _write_scan_report
    out = tmp_path / "out"
    out.mkdir()
    metrics = AnalysisMetrics(total=0, vulnerable=0, bypassable=0,
                              inconclusive=0, protected=0, safe=0, errors=0)
    result = ScanResult(output_dir=str(out), units_count=0,
                        language="python", metrics=metrics)
    step_reports = [{
        "step": "parse", "status": "success", "cost_usd": 0.0,
        "duration_seconds": 0.1,
        "token_usage": {"input_tokens": 1, "output_tokens": 1,
                        "total_tokens": 2},
    }]
    _write_scan_report(str(out), result, step_reports,
                       repo_path=str(tmp_path / "repo"))
    scan = json.loads((out / "scan.report.json").read_text())
    assert "accounting_error" not in scan["token_usage"]
    assert "cost_incomplete" not in scan["token_usage"]


def test_unpriced_and_accounting_error_cooccur_all_keys(tmp_path):
    """#216's marker and #605's co-occur on one step: cost_incomplete +
    unpriced_models + accounting_error all present — never one displacing
    the other."""
    from core import step_report as sr_mod
    from utilities.llm_client import record_accounting_error
    tracker = llm_client.get_global_tracker()
    # an unpriced call (the #598/#216 loud path) + a counted hand-off drop
    tracker.record_call(model="mystery/model-x", input_tokens=10,
                        output_tokens=5)
    record_accounting_error()
    with sr_mod.step_context("co-step", str(tmp_path)):
        pass
    tu = json.loads((tmp_path / "co-step.report.json").read_text())["token_usage"]
    assert tu["cost_incomplete"] is True
    assert tu["unpriced_models"] == ["mystery/model-x"]
    assert tu["accounting_error"] is True
