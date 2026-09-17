"""#599: the two silent llr summary-write failure paths become loud, counted
diagnostics.

The FINAL write surfaced only through ``on_error`` — which the scan path
never passes — and the PASS-START write was ``except OSError: pass``,
silent even WITH a callback, while their init/per-unit siblings both print
to stderr. A failed write left a stale or absent checkpoint summary (the
Go resume sweep reads its phase) with no signal anywhere: the fail-open
design is correct and stays; the missing piece is the diagnostic.

The fix mirrors the siblings' if/else idiom at both sites with PHASE-NAMED
messages, and counts the failures into ``checkpoint_summary_write_failures``
(the step-report stats) — visible in the artifact without any callback.

The write-failure tests use a DELEGATING fake keyed on call order: llr
makes exactly two ``write_summary`` calls per pass (pass-start, final),
and the recorded phase sequence is asserted BEFORE the raise keying, so
call-order drift cannot silently retarget the injection.

Fully offline ($0).
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.checkpoint import StepCheckpoint  # noqa: E402
from core.llm_reachability import analyze_reachability  # noqa: E402
from tests.test_issue532_llr_resume import (  # noqa: E402
    FakeAdapter,
    FakeTracker,
    _binding,
    _canned,
    _make_unit,
    _sig,
)

_orig_write_summary = StepCheckpoint.write_summary


def _failing_write_summary(fail_on_call):
    """A delegating write_summary that raises OSError on the Nth call
    (1-based) and delegates the rest. Records every call's phase so the
    test asserts the sequence BEFORE the keying — retargeting drift
    fails the sequence assert loudly."""
    calls = []

    def _patched(self, *args, **kwargs):
        calls.append(kwargs.get("phase"))
        if len(calls) == fail_on_call:
            raise OSError("disk full")
        return _orig_write_summary(self, *args, **kwargs)

    return _patched, calls


def _run(tmp_path, **kwargs):
    cp = str(tmp_path / "llm_reach_checkpoints")
    dataset = {"units": [_make_unit("a:f1")]}
    return analyze_reachability(
        dataset, binding=_binding(FakeAdapter([_canned(_sig("a:f1"))])),
        checkpoint_path=cp, tracker=FakeTracker(), **kwargs), cp


def test_pass_start_write_failure_is_loud_counted_and_fail_open(
        monkeypatch, tmp_path):
    """The first call (pass-start, phase=in_progress) fails: the failure
    reaches on_error, the counter reads 1, the pass still returns its
    signals (fail-open), and the per-unit records persist — a summary
    failure must NOT disable checkpointing (the init failure does; this
    must not)."""
    patched, calls = _failing_write_summary(1)
    monkeypatch.setattr(StepCheckpoint, "write_summary", patched)
    errors = []
    signals, cp = _run(tmp_path, on_error=errors.append)

    assert [s.unit_id for s in signals] == ["a:f1"]  # fail-open holds
    assert calls[0] == "in_progress"  # the sequence assert, pre-keying
    assert any("pass-start summary write failed" in e for e in errors)
    assert any("stale or absent" in e for e in errors)
    # per-unit records persist: only the SUMMARY write failed (the
    # record's own id is the receipt — the filename stem normalizes it)
    assert any(r.get("id") == "a:f1" for r in _load_records(cp).values())


def test_pass_start_failure_counts_into_stats(monkeypatch, tmp_path):
    """The count reaches the stats dict the report carries — on a FRESH
    checkpoint dir (an already-persisted record would be adopted and the
    pass shape would differ from the one under test)."""
    patched, calls = _failing_write_summary(1)
    monkeypatch.setattr(StepCheckpoint, "write_summary", patched)
    stats = {}
    analyze_reachability(
        {"units": [_make_unit("a:f1")]},
        binding=_binding(FakeAdapter([_canned(_sig("a:f1"))])),
        checkpoint_path=str(tmp_path / "cp2"), tracker=FakeTracker(),
        stats=stats)
    assert stats["checkpoint_summary_write_failures"] == 1


def _load_records(cp):
    import json
    d = Path(cp)
    out = {}
    for f in d.glob("*.json"):
        if f.name == "_summary.json":
            continue
        try:
            out[f.stem] = json.loads(f.read_text())
        except Exception:
            continue
    return out


def test_final_write_failure_is_loud_and_leaves_the_stale_phase(
        monkeypatch, tmp_path):
    """The second call (final, phase=done) fails: the on-disk summary keeps
    the pass-start's phase=in_progress (the stale-state consequence the
    issue names), the counter reads 1, the distinct final-phase message
    surfaces."""
    # #603: the write sequence is [pass-start, per-batch x N, final] —
    # the final write is the LAST call; fail on it (the per-batch
    # publications before it succeed and leave in_progress on disk).
    calls = []
    def _fail_last(self, *args, **kwargs):
        calls.append(kwargs.get("phase"))
        if kwargs.get("phase") == "done":
            raise OSError("disk full")
        return _real_write_summary(self, *args, **kwargs)
    _real_write_summary = StepCheckpoint.write_summary
    monkeypatch.setattr(StepCheckpoint, "write_summary", _fail_last)
    errors = []
    signals, cp = _run(tmp_path, on_error=errors.append)

    assert [s.unit_id for s in signals] == ["a:f1"]
    assert calls[0] == "in_progress" and calls[-1] == "done"
    assert StepCheckpoint.read_summary(cp)["phase"] == "in_progress"
    assert any("final summary write failed" in e for e in errors)
    assert any("needless resume" in e for e in errors)


def test_both_writes_fail_counts_two(monkeypatch, tmp_path):
    """Both writes fail: the counter INCREMENTS (2), not assigns-once —
    the two isolated count==1 tests cannot distinguish those."""
    calls = []
    def _all_fail(self, *args, **kwargs):
        calls.append(kwargs.get("phase"))
        raise OSError("disk full")
    monkeypatch.setattr(StepCheckpoint, "write_summary", _all_fail)
    stats = {}
    cp = str(tmp_path / "llm_reach_checkpoints")
    analyze_reachability(
        {"units": [_make_unit("a:f1")]},
        binding=_binding(FakeAdapter([_canned(_sig("a:f1"))])),
        checkpoint_path=cp, tracker=FakeTracker(), stats=stats)
    assert calls[0] == "in_progress" and calls[-1] == "done"  # #603: the sequence pin (per-batch publications in between)
    assert stats["checkpoint_summary_write_failures"] == 2


def test_pass_start_failure_leaves_stale_done_suppressing_resume(
        monkeypatch, tmp_path):
    """The suppressed-resume hazard (the review round's catch): the prior
    pass's phase="done" summary SURVIVES a failed pass-start write — the
    Go resume sweep reads done && errors==0 and suppresses the prompt
    entirely. All existing pass-start-failure tests use fresh dirs (the
    absent case); this pins the STALE case."""
    import json as _json
    from core.llm_reachability import analyze_reachability
    from tests.test_issue532_llr_resume import (
        FakeAdapter, FakeTracker, _binding, _make_unit, _canned, _sig)

    cp = str(tmp_path / "cp")
    dataset = {"units": [_make_unit("a:f1")]}
    canned = _canned(_sig("a:f1"))

    # Seed a completed prior pass (phase=done).
    analyze_reachability(
        dataset, binding=_binding(FakeAdapter([canned])),
        checkpoint_path=cp, tracker=FakeTracker(), stats={})
    from pathlib import Path as _P
    summary = _P(cp) / "_summary.json"
    assert _json.loads(summary.read_text())["phase"] == "done"

    # Fail ONLY the pass-start write (the first call); the final write
    # succeeds (fresh responses served).
    calls = {"n": 0}
    real = StepCheckpoint.write_summary
    def patched(self, *a, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("injected pass-start failure")
        return real(self, *a, **kw)
    monkeypatch.setattr(StepCheckpoint, "write_summary", patched)

    analyze_reachability(
        dataset, binding=_binding(FakeAdapter([canned])),
        checkpoint_path=cp, tracker=FakeTracker(), stats={})
    # THE PIN: the stale done SURVIVED the failed write — the resume
    # sweep would read it and suppress the prompt (the hazard the stderr
    # message names).
    assert _json.loads(summary.read_text())["phase"] == "done"


def test_no_callback_prints_to_stderr(monkeypatch, tmp_path, capfd):
    """Without on_error BOTH phases print their [LLMReach]-prefixed,
    phase-named lines to stderr (the sibling idiom) — parametrized so a
    message swap between the two sites regresses loudly."""
    wording = {
        "pass-start": "stale or absent",       # the pass-start hazard's direction
        "final": "needless resume",            # the final hazard's direction
    }
    for i, (fail_on, phase_name) in enumerate(
            ((1, "pass-start"), ("done", "final")), start=1):
        # #603: the final write is the LAST call (phase=="done"), not the
        # 2nd — the per-batch publications sit between.
        if fail_on == "done":
            _real = StepCheckpoint.write_summary
            def _fail_done(self, *args, **kwargs):
                if kwargs.get("phase") == "done":
                    raise OSError("disk full")
                return _real(self, *args, **kwargs)
            monkeypatch.setattr(StepCheckpoint, "write_summary", _fail_done)
        else:
            patched, calls = _failing_write_summary(fail_on)
            monkeypatch.setattr(StepCheckpoint, "write_summary", patched)
        # a FRESH dir per iteration: a shared dir would make iteration 2
        # an adopt-all pass (its shape differs from the one under test).
        _run(tmp_path / f"cp-{i}")  # no on_error
        out = capfd.readouterr().err
        assert f"[LLMReach] {phase_name} summary write failed" in out
        assert wording[phase_name] in out


def test_empty_units_leaves_the_key_absent(tmp_path):
    """The empty-units early return bypasses the whole counter block (zero
    units means zero write attempts) — the key stays ABSENT like its six
    sibling counters; the scanner defaults it to 0."""
    stats = {}
    analyze_reachability(
        {"units": []}, binding=_binding(FakeAdapter([])),
        checkpoint_path=str(tmp_path / "cp"), tracker=FakeTracker(),
        stats=stats)
    assert "checkpoint_summary_write_failures" not in stats
    assert "batches_dropped" not in stats  # the sibling absence contract


def test_scanner_summary_shape_carries_the_key_and_stays_success(tmp_path):
    """The scanner-line contract: the step-report summary carries
    ``checkpoint_summary_write_failures`` WITHOUT feeding error_count —
    a summary-write failure alone must leave the step SUCCESS (the pass
    succeeded; the artifact alone is degraded; folding it in would flip
    the #541 partial contract wrongly)."""
    from core.step_report import step_context
    import json

    with step_context("llm-reachability", str(tmp_path)) as ctx:
        ctx.summary = {
            "units_reviewed": 2,
            "batches_dropped": 0,
            "batches_failed": 0,
            "units_not_reviewed": 0,
            "checkpoint_summary_write_failures": 1,
            "error_count": 0 + 0,  # the artifact failure does NOT feed it
        }
    with open(tmp_path / "llm-reachability.report.json") as fh:
        rep = json.load(fh)
    assert rep["summary"]["checkpoint_summary_write_failures"] == 1
    assert rep["summary"]["error_count"] == 0
    assert rep["status"] == "success"  # the #541 contract stays intact


def test_scanner_source_enumerates_the_key():
    """Source-level pin: the scanner's llr summary block (the explicit-
    enumeration contract) forwards the key — without this line the
    counter reaches nothing in a scan (the stderr print would be the
    only in-scan signal)."""
    src = (PROJECT_ROOT / "core" / "scanner.py").read_text()
    assert '"checkpoint_summary_write_failures": reach_stats.get(' in src
    # and the guard: the key must NOT appear in the error_count fold.
    # BALANCED-PAREN scan (the review round's catch: the first-`)` slice
    # ended at the inner .get()'s paren — appending the key on a new line
    # inside the fold passed the pin vacuously; the 2/8-green-on-master
    # was the tell). Scan to depth 0 from the fold's opening paren.
    start = src.index('"error_count": (reach_stats.get("batches_dropped"')
    open_paren = src.index("(", start)
    depth = 0
    end = open_paren
    for i in range(open_paren, len(src)):
        if src[i] == "(":
            depth += 1
        elif src[i] == ")":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    fold = src[start:end]
    assert "checkpoint_summary_write_failures" not in fold, (
        f"the key leaked into the error_count fold: {fold!r}")
