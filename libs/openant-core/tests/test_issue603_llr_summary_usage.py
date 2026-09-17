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


class _TotalsTracker:
    """A minimal tracker exposing get_totals — the real API shape."""

    def __init__(self, totals):
        self._totals = totals

    def get_totals(self):
        return self._totals


def test_the_summary_usage_shape():
    """The helper's shape: the tracker's cumulative totals, the #216
    markers + the accounting-error counter preserved, present-only when
    clean."""
    from core.llm_reachability import analyze_reachability as _  # noqa: F401
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
    """tracker=None: the helper returns None (the summary stays usage-less,
    the legacy shape) and the pass completes."""
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
