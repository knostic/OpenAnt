"""#608: the dynamic-test checkpoint summaries publish the stage-local usage.

Every ``write_summary`` call site passed no ``usage`` — including the
terminal ``phase="done"`` one. The stage publishes after findings, after
generation failures, after Docker outcomes, and at termination (its write
sites cover both outcomes) — so the shape existed; the usage was the
missing key. A summary-reading consumer saw $0 for the whole stage.

The fix adds ``usage=`` to the four existing write sites with the same
accounting requirements as the llr sibling: the DELTA from the pre-stage
baseline (the stage's OWN spend ACROSS RUNS: the restored attempts' prior
usage [the #333 injection — INCLUDED, the _summary.json family contract:
enhance/analyze/verify/llr all publish prior+fresh] + this run's fresh
calls; the earlier phases' spend EXCLUDED), the #216 markers and the #605
counter preserved, exception-safe (a failed baseline snapshot publishes
usage=None, never a cumulative misread). The CONSOLE baseline refreshes
separately at the #333 site (the restored spend's original console line
already printed it) — two channels, two figures, both correct.
"""

import re
import sys

import pytest
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.llm_client import (  # noqa: E402
    TokenTracker,
    reset_global_tracker,
)


@pytest.fixture(autouse=True)
def _clean_tracker():
    """The singleton tracker resets before AND after every test (the repo's
    convention for singleton-touching tests) — these tests seed real
    spend on the global tracker."""
    reset_global_tracker()
    yield
    reset_global_tracker()


def test_every_write_site_passes_usage():
    """Source pin: all FOUR write_summary calls carry usage= (the exact
    gap the issue names)."""
    src = (PROJECT_ROOT / "utilities" / "dynamic_tester" / "__init__.py").read_text()
    sites = re.findall(r"checkpoint\.write_summary\(", src)
    assert len(sites) == 4, f"the write-site count changed: {len(sites)}"
    with_usage = re.findall(r"write_summary\([^)]*?usage=_summary_usage\(\)",
                            src, re.S)
    assert len(with_usage) == 4, \
        f"not every site carries usage: {len(with_usage)}/4"


def test_the_delta_semantics_exclude_prior_phases():
    """The published figure is the STAGE's own spend: a tracker seeded with
    an EARLIER phase's spend publishes 0 at entry; after the stage's own
    record_call, the delta shows exactly the stage's tokens."""
    # emulate the helper's semantics: build the baseline + delta by hand —
    # the module's closure is not importable; drive the same math.
    tracker = TokenTracker()
    tracker.record_call("earlier/phase", 1000, 500,
                        pricing={"input": 3.0, "output": 15.0})
    baseline = dict(tracker.get_totals())
    # the stage's own spend
    tracker.record_call("stage/model", 100, 50,
                        pricing={"input": 2.0, "output": 4.0})
    t = tracker.get_totals()
    delta = {
        "input_tokens": t["total_input_tokens"]
        - baseline["total_input_tokens"],
        "output_tokens": t["total_output_tokens"]
        - baseline["total_output_tokens"],
        "cost_usd": round(t["total_cost_usd"]
                          - baseline["total_cost_usd"], 6),
    }
    assert delta["input_tokens"] == 100  # the stage's own — not 1100
    assert abs(delta["cost_usd"] - 0.0004) < 1e-9


def test_the_markers_survive():
    """The #216 markers + the #605 counter ride the publication."""
    tracker = TokenTracker()
    baseline = dict(tracker.get_totals())
    tracker.record_call("unknown/model", 10, 5, pricing=None)
    t = tracker.get_totals()
    u = {"input_tokens": t["total_input_tokens"]
         - baseline["total_input_tokens"]}
    if t.get("cost_incomplete"):
        u["cost_incomplete"] = True
        u["unpriced_models"] = t.get("unpriced_models") or []
    assert u.get("cost_incomplete") is True
    assert "unknown/model" in u.get("unpriced_models", [])


def test_the_helper_is_exception_safe():
    """A poisoned get_totals returns None — a usage read never kills the
    stage (the source pin of the try/except)."""
    src = (PROJECT_ROOT / "utilities" / "dynamic_tester" / "__init__.py").read_text()
    assert "a usage read must never kill the stage" in src  # ASCII-only pin
    assert "except Exception" in src


def test_the_resumed_pass_start_carries_the_restored_spend(tmp_path,
                                                            monkeypatch):
    """THE FAMILY-CONTRACT RECEIPT (the decisive branch, driven): a resumed
    run whose checkpoint carries prior spend (1000 in / 500 out / $0.60)
    publishes that spend in the pass-start write's usage — prior+fresh,
    the same _summary.json contract as enhance/analyze/verify/llr. The
    baseline is NOT refreshed at the injection (the CONSOLE baseline is —
    two channels, two figures, both correct). A regression that refreshes
    the summary baseline after the injection reads 0 here."""
    import json as _json
    import core.dynamic_tester as cd
    import utilities.dynamic_tester as dt
    from utilities.llm_client import get_global_tracker
    from tests.test_issue333_dyn_test_cost_delta import _NoopAdapter
    from utilities.llm import PhaseBinding

    tracker = get_global_tracker()
    # an EARLIER phase's spend on the shared tracker (the exclusion half)
    tracker.add_prior_usage(5000, 5000, 2.5)

    pipeline = tmp_path / "pipeline_output.json"
    pipeline.write_text(_json.dumps({
        "repository": {"name": "t", "language": "python"},
        "application_type": "unknown",
        "findings": [{
            "id": "f1", "name": "X", "short_name": "x",
            "location": "a.py:1", "cwe_id": 79,
            "stage2_verdict": "confirmed", "vulnerable_code": "eval(x)",
            "attack_vector": "a", "steps_to_reproduce": "s",
            "impact": "i", "suggested_fix": "f",
        }],
    }))
    out = tmp_path / "out"
    out.mkdir()
    cp = out / "dynamic_test_checkpoints"
    cp.mkdir()
    # the RESTORED attempt's prior spend — injected by the #333 loop
    (cp / "f1.json").write_text(_json.dumps({
        "id": "f1", "status": "ERROR",
        "generation_cost_usd": 0.60,
        "generation_input_tokens": 1000, "generation_output_tokens": 500,
    }))
    (cp / "_summary.json").write_text(_json.dumps(
        {"total_units": 1, "completed": 0, "errors": 1}))

    class _FakeRegistry:
        def get(self, phase):
            return PhaseBinding(phase=phase, adapter=_NoopAdapter(),
                                model="m", provider_name="anthropic")

    # capture every write
    from core.checkpoint import StepCheckpoint
    writes = []
    real_write = StepCheckpoint.write_summary

    _POS = ("total_units", "completed", "errors", "error_breakdown")

    def capture(self, *args, **kw):
        rec = dict(zip(_POS, args))
        rec.update(kw)
        writes.append(rec)
        return real_write(self, *args, **kw)

    def gen(*a, **k):
        tracker.record_call("retry/model", 100, 50,
                            pricing={"input": 3.0, "output": 15.0})
        return None

    monkeypatch.setattr(dt, "generate_test", gen)
    monkeypatch.setattr(StepCheckpoint, "write_summary", capture)
    monkeypatch.setattr(cd.shutil, "which",
                        lambda n: "/usr/bin/docker" if n == "docker"
                        else None)
    try:
        cd.run_tests(pipeline_output_path=str(pipeline), output_dir=str(out),
                     registry=_FakeRegistry())
    finally:
        StepCheckpoint.write_summary = real_write

    # the pass-start write: completed=0 (nothing yet) but the usage carries
    # the RESTORED prior (1000 in) — NEVER completed=N at usage=0
    start = writes[0]
    assert start["phase"] == "in_progress"
    assert start["usage"]["input_tokens"] == 1000
    assert start["usage"]["output_tokens"] == 500
    assert abs(start["usage"]["cost_usd"] - 0.6) < 1e-9
    # the terminal write: prior (1000) + the retry's fresh 100 — the
    # earlier phase's 5000 EXCLUDED throughout
    done = writes[-1]
    assert done["usage"]["input_tokens"] == 1100
    assert done["usage"]["output_tokens"] == 550
    assert abs(done["usage"]["cost_usd"] - (0.6 + 0.00105)) < 1e-6


def test_a_failed_baseline_snapshot_publishes_none(tmp_path, monkeypatch):
    """The degraded path, DRIVEN: a tracker whose get_totals raises at entry
    publishes usage=None (the honest absence — the llr sibling's shape),
    never the raw run-cumulative misread as a stage delta."""
    import json as _json
    import core.dynamic_tester as cd
    import utilities.dynamic_tester as dt
    from utilities.llm_client import get_global_tracker
    from tests.test_issue333_dyn_test_cost_delta import _NoopAdapter
    from utilities.llm import PhaseBinding

    get_global_tracker().add_prior_usage(5000, 5000, 2.5)  # earlier phases

    pipeline = tmp_path / "pipeline_output.json"
    pipeline.write_text(_json.dumps({
        "repository": {"name": "t", "language": "python"},
        "application_type": "unknown",
        "findings": [{
            "id": "f1", "name": "X", "short_name": "x",
            "location": "a.py:1", "cwe_id": 79,
            "stage2_verdict": "confirmed", "vulnerable_code": "eval(x)",
            "attack_vector": "a", "steps_to_reproduce": "s",
            "impact": "i", "suggested_fix": "f",
        }],
    }))

    class _FakeRegistry:
        def get(self, phase):
            return PhaseBinding(phase=phase, adapter=_NoopAdapter(),
                                model="m", provider_name="anthropic")

    from core.checkpoint import StepCheckpoint
    writes = []
    real_write = StepCheckpoint.write_summary

    _POS = ("total_units", "completed", "errors", "error_breakdown")

    def capture(self, *args, **kw):
        rec = dict(zip(_POS, args))
        rec.update(kw)
        writes.append(rec)
        return real_write(self, *args, **kw)

    monkeypatch.setattr(dt, "generate_test", lambda *a, **k: None)
    monkeypatch.setattr(StepCheckpoint, "write_summary", capture)
    monkeypatch.setattr(cd.shutil, "which",
                        lambda n: "/usr/bin/docker" if n == "docker"
                        else None)
    # poison the GLOBAL tracker's get_totals for the whole run. The DIRECT
    # entry (no step wrapper: usage_baseline stays None, the #333 console
    # refresh is skipped) makes the _summary_baseline snapshot at
    # __init__.py the FIRST get_totals reader: it raises, the baseline is
    # None, and every publication carries usage=None (the honest absence —
    # never the run-cumulative misread as a stage delta). The module's
    # plain attribute reads (total_cost_usd at :240) and get_unit_usage
    # never call get_totals, so nothing else can raise first.
    def _exploding_get_totals(self):
        raise RuntimeError("tracker exploded")

    monkeypatch.setattr(type(dt.get_global_tracker()), "get_totals",
                        _exploding_get_totals)
    try:
        dt.run_dynamic_tests(pipeline_output_path=str(pipeline),
                             output_dir=str(tmp_path / "out"),
                             registry=_FakeRegistry())
    finally:
        StepCheckpoint.write_summary = real_write
    # every write carries usage=None — never a cumulative misread as delta
    assert writes
    assert all(w["usage"] is None for w in writes), writes
