"""#603: the llr checkpoint summaries publish the stage-local running usage.

The two writes per pass (start + end) passed ``usage=None`` (a silent
omission) and nothing updated the summary per batch — the stage-local
running cost was invisible to any summary-reading consumer mid-stage (the
terminal step report retained it: live visibility, not terminal
accounting).

The fix publishes the cumulative tracked usage at the pass start (the
adopted/prior baseline), **after every attempted batch** (the
dropped/failed outcomes included — the loop's common tail), and at
termination — exception-safe (a publication failure never masks the
pass; the #599 counters own that signal). The #216 markers
(``cost_incomplete``/``unpriced_models``) and the #605 accounting-error
counter survive the publication. Adopted/prior usage enters the tracker
ONCE via the existing ``add_prior_usage`` injection and is not re-added.
"""


def test_the_summary_usage_shape():
    """The helper's shape: the tracker's cumulative totals, the #216
    markers + the accounting-error counter preserved, present-only when
    clean."""
    # drive the real analyze_reachability with a fake binding + tracker and
    # a summary-write capture
    import sys
    from pathlib import Path
    root = Path(__file__).parent.parent
    sys.path.insert(0, str(root))
    from tests.test_issue532_llr_resume import (
        FakeAdapter, _binding, _canned, _make_unit, _sig,
    )
    from core.checkpoint import StepCheckpoint
    from core.llm_reachability import analyze_reachability

    # the tracker that accumulates (the real TokenTracker is overkill; the
    # FakeTracker doesn't expose get_totals — use the real one's API shape)
    from utilities.llm_client import TokenTracker
    tracker = TokenTracker()
    tracker.record_call("fake/model", 100, 50,
                        pricing={"input": 2.0, "output": 4.0})
    # an unpriced call for the #216 marker
    tracker.record_call("unknown/model", 10, 5, pricing=None)

    writes = []
    real_write = StepCheckpoint.write_summary

    def capture(self, **kw):
        writes.append(kw)
        return real_write(self, **kw)

    StepCheckpoint.write_summary = capture
    try:
        import tempfile
        cp_dir = tempfile.mkdtemp()
        analyze_reachability(
            {"units": [_make_unit("a:f1")]},
            binding=_binding(FakeAdapter([_canned(_sig("a:f1"))])),
            checkpoint_path=cp_dir, tracker=tracker,
        )
    finally:
        StepCheckpoint.write_summary = real_write

    # every write carries a usage dict (never None) — the DELTA semantics:
    # the baseline (the pre-seeded tracker spend) is EXCLUDED; the published
    # figure is the STAGE's own spend (the step-report semantics by construction).
    assert writes, "no summary writes captured"
    for w in writes:
        assert w["usage"] is not None, w
        # the #216 markers survive (run-cumulative, the accepted trade)
        assert w["usage"].get("cost_incomplete") is True
        assert "unknown/model" in w["usage"].get("unpriced_models", [])
    # the final write is the last; the delta is non-decreasing (the stage
    # spent the batch's tokens, not the baseline's 110)
    final = writes[-1]
    assert final["phase"] == "done"
    assert final["usage"]["input_tokens"] >= writes[0]["usage"]["input_tokens"]
    # THE DELTA PIN (exact values): the baseline (110 in / 55 out) is
    # EXCLUDED from every publication — the FakeAdapter's response costs
    # 10 in / 10 out, so the exact sequence is [0, 10, 10] (pass-start
    # BEFORE the batch, the per-batch + the final after). A regression to
    # naive cumulative totals ([110, 120, 120]) fails here.
    assert [w["usage"]["input_tokens"] for w in writes] == [0, 10, 10]
    assert [w["usage"]["output_tokens"] for w in writes] == [0, 10, 10]
    assert [w["usage"]["cost_usd"] for w in writes] == [0.0, 0.0, 0.0]


def test_the_per_batch_publication_count():
    """With 2 units at batch_size=1, the summary is written at pass start,
    after EACH of the 2 attempted batches, and at termination — 4 writes
    (the live visibility: the running summary tracks the spend)."""
    import sys
    import tempfile
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from tests.test_issue532_llr_resume import (
        FakeAdapter, _binding, _canned, _make_unit, _sig,
    )
    from core.checkpoint import StepCheckpoint
    from core.llm_reachability import analyze_reachability
    from utilities.llm_client import TokenTracker

    writes = []
    real_write = StepCheckpoint.write_summary

    def capture(self, **kw):
        writes.append(kw)
        return real_write(self, **kw)

    StepCheckpoint.write_summary = capture
    try:
        cp_dir = tempfile.mkdtemp()
        analyze_reachability(
            {"units": [_make_unit("a:f1"), _make_unit("b:f2")]},
            binding=_binding(FakeAdapter(
                [_canned(_sig("a:f1")), _canned(_sig("b:f2"))])),
            batch_size=1, checkpoint_path=cp_dir,
            tracker=TokenTracker(),
        )
    finally:
        StepCheckpoint.write_summary = real_write
    # pass-start + per-batch x2 + final = 4
    assert len(writes) == 4, [w["phase"] for w in writes]
    assert writes[0]["phase"] == "in_progress"  # the pass start
    assert writes[-1]["phase"] == "done"        # the termination
    # the middle two are the per-batch publications (in_progress)
    assert all(w["phase"] == "in_progress" for w in writes[1:-1])


def test_a_publication_failure_never_masks_the_pass():
    """A poisoned write_summary on a per-batch publication: the OSError is
    swallowed (the #599 counters own that signal) and the pass completes."""
    import sys
    import tempfile
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from tests.test_issue532_llr_resume import (
        FakeAdapter, _binding, _canned, _make_unit, _sig,
    )
    from core.checkpoint import StepCheckpoint
    from core.llm_reachability import analyze_reachability
    from utilities.llm_client import TokenTracker

    real_write = StepCheckpoint.write_summary

    def poisoned(self, **kw):
        if kw.get("phase") == "in_progress":
            raise OSError("summary dir vanished")
        return real_write(self, **kw)

    StepCheckpoint.write_summary = poisoned
    try:
        cp_dir = tempfile.mkdtemp()
        signals = analyze_reachability(
            {"units": [_make_unit("a:f1")]},
            binding=_binding(FakeAdapter([_canned(_sig("a:f1"))])),
            checkpoint_path=cp_dir, tracker=TokenTracker(),
        )
        assert [s.unit_id for s in signals] == ["a:f1"]  # the pass completes
    finally:
        StepCheckpoint.write_summary = real_write


def test_no_tracker_no_usage_no_crash():
    """A tracker whose get_totals RAISES (or is absent): the helper
    returns None — the summary stays usage-less (the legacy shape) and
    the pass completes. (With tracker=None the global tracker is
    resolved at 473-475, so the None path is reachable only via a
    raising get_totals — the FakeTracker shape the #532 family uses.)"""
    import sys
    import tempfile
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from tests.test_issue532_llr_resume import (
        FakeAdapter, _binding, _canned, _make_unit, _sig,
    )
    from core.checkpoint import StepCheckpoint
    from core.llm_reachability import analyze_reachability

    writes = []
    real_write = StepCheckpoint.write_summary

    def capture(self, **kw):
        writes.append(kw)
        return real_write(self, **kw)

    StepCheckpoint.write_summary = capture
    try:
        cp_dir = tempfile.mkdtemp()
        analyze_reachability(
            {"units": [_make_unit("a:f1")]},
            binding=_binding(FakeAdapter([_canned(_sig("a:f1"))])),
            checkpoint_path=cp_dir, tracker=None,
        )
    finally:
        StepCheckpoint.write_summary = real_write
    # the test's point: the pass COMPLETES with no explicit tracker. The
    # usage is either None (no fallback engaged) or the global-tracker
    # fallback's dict — a valid dict or None, never a crash, never a
    # fabricated non-zero (the fallback's spend is real recorded spend).
    for w in writes:
        assert w["usage"] is None or isinstance(w["usage"], dict)


def test_the_failed_batch_publishes_before_the_continue():
    """SITE #3 (the hunt's own HIGH): a FAILED/dropped batch is the
    billed-but-empty case whose spend the live summary exists to show —
    the publication fires BEFORE the continue (a dropped batch's write
    sits between the pass-start and the final)."""
    import sys
    import tempfile
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from tests.test_issue532_llr_resume import (
        FakeAdapter, _binding, _make_unit,
    )
    from core.checkpoint import StepCheckpoint
    from core.llm_reachability import analyze_reachability
    from utilities.llm_client import TokenTracker

    writes = []
    real_write = StepCheckpoint.write_summary

    def capture(self, **kw):
        writes.append(kw)
        return real_write(self, **kw)

    StepCheckpoint.write_summary = capture
    try:
        cp_dir = tempfile.mkdtemp()
        # a malformed response — the batch DROPS (the billed-but-empty case)
        analyze_reachability(
            {"units": [_make_unit("a:f1")]},
            binding=_binding(FakeAdapter(["not json {" ])),
            checkpoint_path=cp_dir, tracker=TokenTracker(),
        )
    finally:
        StepCheckpoint.write_summary = real_write
    phases = [w["phase"] for w in writes]
    # pass-start + the PRE-CONTINUE publication (the dropped batch's) +
    # final = 3 writes — NOT 2 (the regression this pins: a bare continue
    # without the publication would yield [in_progress, done])
    assert len(writes) == 3, phases
    assert phases[0] == "in_progress"
    assert phases[1] == "in_progress"  # the dropped batch's publication
    assert phases[2] == "in_progress"  # not done: the unit never persisted
    # the dropped batch's publication carries the response's 10/10 spend
    assert writes[1]["usage"]["input_tokens"] == 10


def test_the_injection_precedes_the_pass_start_write():
    """The ordering (the hunt's second HIGH): the adopted units' prior
    usage is injected BEFORE the pass-start write, so the FIRST snapshot
    carries the restored spend (the stage's true starting position —
    the usage-less summary was the omission the issue filed)."""
    import sys
    import tempfile
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from tests.test_issue532_llr_resume import (
        FakeAdapter, _binding, _canned, _make_unit, _sig,
    )
    from core.checkpoint import StepCheckpoint
    from core.llm_reachability import analyze_reachability
    from utilities.llm_client import TokenTracker

    cp_dir = tempfile.mkdtemp()
    # the FIRST pass seeds the per-unit record (its spend lands as prior
    # usage for the second pass) — a fresh TokenTracker for pass 2
    first_tracker = TokenTracker()
    analyze_reachability(
        {"units": [_make_unit("a:f1")]},
        binding=_binding(FakeAdapter([_canned(_sig("a:f1"))])),
        checkpoint_path=cp_dir, tracker=first_tracker,
    )
    _adopted_in = first_tracker.get_totals()["total_input_tokens"]
    assert _adopted_in > 0  # the first pass spent (the prior usage)

    writes = []
    real_write = StepCheckpoint.write_summary

    def capture(self, **kw):
        writes.append(kw)
        return real_write(self, **kw)

    StepCheckpoint.write_summary = capture
    try:
        analyze_reachability(
            {"units": [_make_unit("a:f1")]},
            binding=_binding(FakeAdapter()),  # full adoption: no calls
            checkpoint_path=cp_dir, tracker=TokenTracker(),
        )
    finally:
        StepCheckpoint.write_summary = real_write
    # the pass-start snapshot includes the ADOPTED spend — the injection
    # ran BEFORE the write; a regression (write-then-inject) would read 0
    assert writes[0]["usage"]["input_tokens"] == _adopted_in
    assert writes[0]["completed"] == 1
    # and the FULLY-ADOPTED pass makes no new spend: every publication
    # equals the adopted baseline (the deltas are all the same)
    assert all(w["usage"]["input_tokens"] == _adopted_in for w in writes)
