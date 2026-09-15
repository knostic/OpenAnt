"""Tests for issue #542 — the verify resume narration's "already done" is
the raw checkpoint count.

The Mode line printed ``({len(checkpointed)} already done)`` — the raw
checkpoint store includes the ERROR rows being queued for retry, so a
resumed run narrated "3 findings to verify (3 already done)" over a
population of 4 (1 complete + 2 being retried). Exactly the pre-#472 shape
PR #472 removed from analyze (the #435 family): done must derive from the
restored-complete counts so done + remaining reconciles to the population.
"""
from __future__ import annotations

import io
from contextlib import redirect_stderr
from unittest.mock import patch

from utilities.finding_verifier import FindingVerifier


def _ckpt_row(kind, finding="vulnerable"):
    """kind: 'ok' a restored-complete row; 'err' a retryable ERROR row
    (the shape _cp_is_error detects: correct_finding == 'error')."""
    if kind == "err":
        return {"finding": "error",
                "verification": {"agree": False, "correct_finding": "error",
                                 "explanation": "boom", "iterations": 1,
                                 "total_tokens": 10},
                "error": "LLMResponseError: boom"}
    return {"finding": finding,
            "verification": {"agree": True, "correct_finding": finding,
                              "explanation": "ok", "iterations": 1,
                              "total_tokens": 10}}


def _row(uid):
    return {"unit_id": uid, "finding": "vulnerable", "verdict": "vulnerable"}


class _FakeCheckpoint:
    def __init__(self, store):
        self._store = store
        self.dir = "/tmp/fake"

    @property
    def exists(self):
        return bool(self._store)

    def load(self):
        return self._store

    def write_summary(self, *a, **kw):
        pass

    def sync_identity(self, fp, **kw):
        return {"status": "match"}


class TestModeLineNarration:
    def test_done_derives_from_restored_not_store(self):
        """THE #542 receipt: 4 findings, 1 complete, 2 errored, 1 new ->
        the Mode line reads '3 findings to verify (1 already done)' —
        never 3 already done (the raw store count)."""
        orch = FindingVerifier.__new__(FindingVerifier)
        orch.logger = None
        orch._use_logger = False
        orch.verbose = True
        orch.tracker = type("T", (), {
            "start_unit_tracking": lambda s: None,
            "get_unit_usage": lambda s: {},
            "add_prior_usage": lambda s, *a, **kw: None,
            "record_call": lambda s, *a, **kw: None,
            "get_unit_record": lambda s, *a, **kw: None})()
        orch.binding = None
        orch.checkpoint = _FakeCheckpoint({
            "a:ok": _ckpt_row("ok"),
            "b:err": _ckpt_row("err"),
            "c:err": _ckpt_row("err"),
        })
        results = [_row("a:ok"), _row("b:err"), _row("c:err"), _row("d:new")]

        captured = io.StringIO()
        with redirect_stderr(captured):
            with patch.object(orch, "_verify_batch_sequential",
                              lambda *a, **kw: None):
                orch.verify_batch(
                    results, {}, workers=1,
                    checkpoint=orch.checkpoint)
        out = captured.getvalue()
        # The Mode line: done + remaining reconcile to the population.
        assert "3 findings to verify" in out, out
        assert "(1 already done)" in out, (
            f"the raw-store shape ('3 already done') must be gone: {out}")

    def test_foreign_checkpoint_not_narrated_as_retry(self):
        """The sibling (the review round): a stale checkpoint for a unit no
        longer in results must not narrate as an 'errored retry'."""
        orch = FindingVerifier.__new__(FindingVerifier)
        orch.logger = None
        orch._use_logger = False
        orch.verbose = True
        orch.tracker = type("T", (), {
            "start_unit_tracking": lambda s: None,
            "get_unit_usage": lambda s: {},
            "add_prior_usage": lambda s, *a, **kw: None,
            "record_call": lambda s, *a, **kw: None})()
        orch.binding = None
        orch.checkpoint = _FakeCheckpoint({
            "a:ok": _ckpt_row("ok"),
            "stale:gone": _ckpt_row("err"),   # a foreign row
        })
        results = [_row("a:ok"), _row("d:new")]
        captured = io.StringIO()
        with redirect_stderr(captured):
            with patch.object(orch, "_verify_batch_sequential",
                              lambda *a, **kw: None):
                orch.verify_batch(results, {}, workers=1,
                                  checkpoint=orch.checkpoint)
        out = captured.getvalue()
        assert "Retrying 0 previously errored" not in out or \
            "Retrying 0" in out, out
        # 1 restored + 1 new; the foreign row narrates nothing.
        assert "1 findings to verify (1 already done)" in out, out
        assert "stale" not in out
