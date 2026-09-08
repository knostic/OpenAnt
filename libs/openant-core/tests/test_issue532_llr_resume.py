"""Tests for issue #532 — the llm-reachability resume/adopt contract.

The stage gains the checkpoint family's resume machinery: per-unit records
(signals + reviewed-ness + a code projection hash), backend-identity gated via
the family's ``sync_identity``; dropped/exception batches leave NO records
(absence IS the retry marker); adopted signals replay through
``apply_signals`` under the CURRENT promotion policy (promote-only
preserved); restored usage lands as prior usage, never as zero nor as new
spend.

Hermetic: the FakeAdapter pattern from test_llm_reachability.py — no network,
no API key. The tracker is stubbed (the three surfaces this stage touches:
start/get unit tracking + add_prior_usage).
"""
from __future__ import annotations

import json
import os
from typing import List

from core.llm_reachability import (
    analyze_reachability,
    apply_signals,
)


# ---------------------------------------------------------------------------
# Harness (mirrors test_llm_reachability.py)
# ---------------------------------------------------------------------------

class FakeAdapter:
    name = "anthropic"
    supports_tools = True

    def __init__(self, responses: List[str] | None = None):
        self._responses = list(responses or [])
        self.calls: List[dict] = []

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        from utilities.llm import CompletionResult, TextBlock

        prompt = messages[0].content[0].text
        self.calls.append({"prompt": prompt, "max_tokens": max_tokens,
                           "model": model})
        if not self._responses:
            text = '{"signals": []}'
        else:
            text = self._responses.pop(0)
        return CompletionResult(
            content=[TextBlock(text)],
            input_tokens=10,
            output_tokens=10,
            stop_reason="end_turn",
        )

    def validate(self, model):
        pass


class FakeTracker:
    """The three tracker surfaces this stage touches (llm_client.TokenTracker)."""

    def __init__(self):
        self.prior_calls: List[dict] = []
        self._current = {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}

    def record_call(self, *, model=None, input_tokens=0, output_tokens=0,
                    pricing=None, usage_details=None):
        self._current["input_tokens"] += input_tokens or 0
        self._current["output_tokens"] += output_tokens or 0
        self._current["cost_usd"] += 0.01  # deterministic per-call price

    def start_unit_tracking(self):
        self._current = {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}

    def get_unit_usage(self):
        return dict(self._current)

    def add_prior_usage(self, input_tokens, output_tokens, cost_usd,
                        unpriced_models=None):
        self.prior_calls.append(
            {"input_tokens": input_tokens, "output_tokens": output_tokens,
             "cost_usd": cost_usd})


def _binding(adapter):
    from utilities.llm import PhaseBinding

    return PhaseBinding(
        phase="llm_reach",
        adapter=adapter,
        model="claude-test",
        provider_name="anthropic",
    )


def _make_unit(unit_id: str, code: str = "pass", **kw) -> dict:
    unit = {"id": unit_id, "unit_type": kw.pop("unit_type", "function"),
            "code": {"primary_code": code}}
    unit.update(kw)
    return unit


def _canned(*signals) -> str:
    return json.dumps({"signals": list(signals)})


def _sig(unit_id, kind="entry_point", confidence="high", reason="reads argv"):
    return {"unit_id": unit_id, "kind": kind, "confidence": confidence,
            "reason": reason}


# ---------------------------------------------------------------------------
# The resume/adopt contract
# ---------------------------------------------------------------------------

class TestAdopt:
    def test_second_run_adopts_records_and_makes_no_new_calls(self, tmp_path):
        """THE #532 regression: a relaunch with existing per-unit records must
        not re-pay for units whose code projection is unchanged."""
        cp = str(tmp_path / "llm_reach_checkpoints")
        dataset = {"units": [_make_unit("a:f1"), _make_unit("b:f2")]}
        canned = _canned(_sig("a:f1"), _sig("b:f2", kind="external_input"))

        first = analyze_reachability(
            dataset, binding=_binding(FakeAdapter([canned])),
            checkpoint_path=cp, tracker=FakeTracker(),
        )
        assert len(first) == 2

        # Second run: a fresh adapter with NO canned responses would blow up
        # (pop from empty) if any unit re-ran; with full adoption it is never
        # called at all.
        second = analyze_reachability(
            dataset, binding=_binding(FakeAdapter()),
            checkpoint_path=cp, tracker=FakeTracker(),
        )
        assert {s.unit_id for s in second} == {"a:f1", "b:f2"}
        assert {s.kind for s in second} == {"entry_point", "external_input"}

    def test_edited_unit_reruns_only_itself(self, tmp_path):
        cp = str(tmp_path / "llm_reach_checkpoints")
        u1, u2 = _make_unit("a:f1"), _make_unit("b:f2")
        dataset = {"units": [u1, u2]}
        analyze_reachability(
            dataset, binding=_binding(FakeAdapter([_canned(_sig("a:f1"), _sig("b:f2"))])),
            checkpoint_path=cp, tracker=FakeTracker(),
        )
        # Edit one unit's code: its projection no longer matches the record.
        u2["code"]["primary_code"] = "def changed(): return 2"
        adapter = FakeAdapter([_canned(_sig("b:f2"))])
        analyze_reachability(
            dataset, binding=_binding(adapter), checkpoint_path=cp,
            tracker=FakeTracker(),
        )
        assert len(adapter.calls) == 1
        assert "b:f2" in adapter.calls[0]["prompt"]

    def test_new_unit_runs_foreign_record_ignored(self, tmp_path):
        cp = str(tmp_path / "llm_reach_checkpoints")
        dataset = {"units": [_make_unit("a:f1")]}
        analyze_reachability(
            dataset, binding=_binding(FakeAdapter([_canned(_sig("a:f1"))])),
            checkpoint_path=cp, tracker=FakeTracker(),
        )
        dataset = {"units": [_make_unit("a:f1"), _make_unit("c:f3")]}
        adapter = FakeAdapter([_canned(_sig("c:f3"))])
        analyze_reachability(
            dataset, binding=_binding(adapter), checkpoint_path=cp,
            tracker=FakeTracker(),
        )
        assert len(adapter.calls) == 1

    def test_removed_unit_record_not_adopted(self, tmp_path):
        cp = str(tmp_path / "llm_reach_checkpoints")
        dataset = {"units": [_make_unit("a:f1"), _make_unit("b:f2")]}
        analyze_reachability(
            dataset, binding=_binding(FakeAdapter([_canned(_sig("a:f1"), _sig("b:f2"))])),
            checkpoint_path=cp, tracker=FakeTracker(),
        )
        # b:f2 removed: its foreign record must not inject a signal.
        dataset = {"units": [_make_unit("a:f1")]}
        second = analyze_reachability(
            dataset, binding=_binding(FakeAdapter()), checkpoint_path=cp,
            tracker=FakeTracker(),
        )
        assert {s.unit_id for s in second} == {"a:f1"}


class TestRetryMarkers:
    def test_dropped_batch_writes_no_records(self, tmp_path):
        """A malformed batch must leave no records: absence IS the retry
        marker (the #386 counter family + #532's 'must not freeze drops')."""
        cp = str(tmp_path / "llm_reach_checkpoints")
        dataset = {"units": [_make_unit("a:f1"), _make_unit("b:f2")]}
        # Malformed JSON for the whole (single) batch.
        analyze_reachability(
            dataset, binding=_binding(FakeAdapter(["not json {"])),
            checkpoint_path=cp, tracker=FakeTracker(),
        )
        adapter = FakeAdapter([_canned(_sig("a:f1"), _sig("b:f2"))])
        analyze_reachability(
            dataset, binding=_binding(adapter), checkpoint_path=cp,
            tracker=FakeTracker(),
        )
        # Both units had no records -> both re-ran in one batch.
        assert len(adapter.calls) == 1

    def test_exception_batch_writes_no_records(self, tmp_path):
        cp = str(tmp_path / "llm_reach_checkpoints")
        dataset = {"units": [_make_unit("a:f1")]}

        class Boom(FakeAdapter):
            def complete(self, **kw):
                raise RuntimeError("provider exploded")

        analyze_reachability(
            dataset, binding=_binding(Boom()), checkpoint_path=cp,
            tracker=FakeTracker(),
        )
        adapter = FakeAdapter([_canned(_sig("a:f1"))])
        analyze_reachability(
            dataset, binding=_binding(adapter), checkpoint_path=cp,
            tracker=FakeTracker(),
        )
        assert len(adapter.calls) == 1

    def test_save_oserror_surfaced_not_fatal(self, tmp_path, monkeypatch):
        """The stage's own doctrine: advisory, never crash the pipeline. A
        checkpoint write failure costs persistence, not the pass."""
        from core import checkpoint as ckpt_mod

        cp = str(tmp_path / "llm_reach_checkpoints")
        dataset = {"units": [_make_unit("a:f1")]}
        errors: List[str] = []

        def flaky_save(self, unit_id, data):
            raise OSError("disk full")

        monkeypatch.setattr(ckpt_mod.StepCheckpoint, "save", flaky_save)
        signals = analyze_reachability(
            dataset, binding=_binding(FakeAdapter([_canned(_sig("a:f1"))])),
            checkpoint_path=cp, tracker=FakeTracker(), on_error=errors.append,
        )
        assert {s.unit_id for s in signals} == {"a:f1"}
        assert any("disk full" in e for e in errors)


class TestPromoteOnly:
    def test_adopted_signal_replays_under_current_promote_set(self, tmp_path, monkeypatch):
        """Adopted SIGNALS (not promotion outcomes): apply_signals runs fresh
        under the CURRENT OPENANT_PROMOTE_ENTRY_POINT_AT — a medium signal
        recorded under a strict set promotes under a widened one."""
        cp = str(tmp_path / "llm_reach_checkpoints")
        dataset = {"units": [_make_unit("a:f1")]}
        # First run under a config that promotes nothing (record the medium).
        monkeypatch.setenv("OPENANT_PROMOTE_ENTRY_POINT_AT", "high")
        analyze_reachability(
            dataset, binding=_binding(FakeAdapter(
                [_canned(_sig("a:f1", confidence="medium"))])),
            checkpoint_path=cp, tracker=FakeTracker(),
        )
        # Second run, full adoption, medium not promotable.
        signals = analyze_reachability(
            dataset, binding=_binding(FakeAdapter()), checkpoint_path=cp,
            tracker=FakeTracker(),
        )
        summary = apply_signals({"units": [_make_unit("a:f1")]}, signals)
        assert summary["entry_points_promoted"] == 0
        # Widen the set on the SAME adopted record: the medium now promotes —
        # the policy is read at APPLY time, never frozen in the record.
        monkeypatch.setenv("OPENANT_PROMOTE_ENTRY_POINT_AT", "high,medium")
        summary = apply_signals({"units": [_make_unit("a:f1")]}, signals)
        assert summary["entry_points_promoted"] == 1

    def test_adopted_signal_never_demotes(self, tmp_path):
        cp = str(tmp_path / "llm_reach_checkpoints")
        dataset = {"units": [_make_unit("a:f1")]}
        analyze_reachability(
            dataset, binding=_binding(FakeAdapter([_canned(_sig("a:f1"))])),
            checkpoint_path=cp, tracker=FakeTracker(),
        )
        kept = {"units": [_make_unit("a:f1", is_entry_point=True)]}
        signals = analyze_reachability(
            dataset, binding=_binding(FakeAdapter()), checkpoint_path=cp,
            tracker=FakeTracker(),
        )
        apply_signals(kept, signals)
        assert kept["units"][0]["is_entry_point"] is True


class TestBoundaries:
    def test_backend_change_invalidates_records(self, tmp_path):
        cp = str(tmp_path / "llm_reach_checkpoints")
        dataset = {"units": [_make_unit("a:f1")]}
        analyze_reachability(
            dataset, binding=_binding(FakeAdapter([_canned(_sig("a:f1"))])),
            checkpoint_path=cp, tracker=FakeTracker(),
        )
        # A different model = a different backend identity: adopt nothing.
        from utilities.llm import PhaseBinding
        other = PhaseBinding(
            phase="llm_reach", adapter=FakeAdapter([_canned(_sig("a:f1"))]),
            model="claude-other", provider_name="anthropic",
        )
        adapter = other.adapter
        analyze_reachability(dataset, binding=other, checkpoint_path=cp,
                             tracker=FakeTracker())
        assert len(adapter.calls) == 1

    def test_out_of_batch_signal_not_carried(self, tmp_path):
        """The disclosed behavior change: valid_unit_ids is per-batch, so a
        signal for a unit outside the producing batch is ungrounded by
        construction — adopted state must equal applied state."""
        cp = str(tmp_path / "llm_reach_checkpoints")
        # Two units, batch size forces two batches (one unit each).
        dataset = {"units": [_make_unit("a:f1"), _make_unit("b:f2")]}
        canned = [_canned(_sig("a:f1"), _sig("b:f2")),  # batch 1: a:f1 (+ out-of-batch b:f2)
                  _canned()]                             # batch 2: b:f2 (nothing)
        signals = analyze_reachability(
            dataset, binding=_binding(FakeAdapter(canned)), batch_size=1,
            checkpoint_path=cp, tracker=FakeTracker(),
        )
        # b:f2's signal came from batch 1 (out of batch) — filtered there.
        assert {s.unit_id for s in signals} == {"a:f1"}
        # The out-of-batch signal must NOT have been persisted into b:f2's
        # record (batch 2 reviewed it and found nothing — signals == []).
        import json as _json
        with open(os.path.join(cp, "b_f2.json")) as fh:
            rec_b = _json.load(fh)
        assert rec_b["signals"] == []
        assert rec_b["projection_sha"]
        # And a:f1's record carries only its own in-batch signal.
        with open(os.path.join(cp, "a_f1.json")) as fh:
            rec_a = _json.load(fh)
        assert [s["unit_id"] for s in rec_a["signals"]] == ["a:f1"]


class TestUsageAndSummary:
    def test_adopted_usage_lands_as_prior_usage(self, tmp_path):
        """Restored cost is PRIOR usage on the tracker — never zero, never
        counted as this run's new spend (the #26/#26b lessons)."""
        cp = str(tmp_path / "llm_reach_checkpoints")
        dataset = {"units": [_make_unit("a:f1")]}
        analyze_reachability(
            dataset, binding=_binding(FakeAdapter([_canned(_sig("a:f1"))])),
            checkpoint_path=cp, tracker=FakeTracker(),
        )
        tracker = FakeTracker()
        analyze_reachability(
            dataset, binding=_binding(FakeAdapter()), checkpoint_path=cp,
            tracker=tracker,
        )
        assert tracker.prior_calls, "adopted records must inject prior usage"
        assert tracker.prior_calls[0]["input_tokens"] > 0

    def test_summary_shape(self, tmp_path):
        """_summary.json: completed counts records (reviewed-ness incl. empty
        signals), errors=0 (the #311 summary-vs-status drift class: status()
        counts errors from FILES; dropped units live in the step report)."""
        from core.checkpoint import StepCheckpoint

        cp = str(tmp_path / "llm_reach_checkpoints")
        dataset = {"units": [_make_unit("a:f1"), _make_unit("b:f2")]}
        analyze_reachability(
            dataset, binding=_binding(FakeAdapter([_canned(_sig("a:f1"))])),
            checkpoint_path=cp, tracker=FakeTracker(),
        )
        s = StepCheckpoint.read_summary(cp)
        assert s["total_units"] == 2
        assert s["completed"] == 2  # b:f2 reviewed with no signal
        assert s["errors"] == 0
        assert s["incomplete"] == 0
        assert s["phase"] == "done"

    def test_summary_incomplete_when_batches_dropped(self, tmp_path):
        """#293 three-state invariant: un-reviewed units (a dropped batch)
        land in `incomplete`, phase stays in_progress — never a clean-done
        summary over a pass that did not complete (the review-wave finding)."""
        from core.checkpoint import StepCheckpoint

        cp = str(tmp_path / "llm_reach_checkpoints")
        dataset = {"units": [_make_unit("a:f1"), _make_unit("b:f2")]}
        # Malformed response drops the whole (single) batch.
        analyze_reachability(
            dataset, binding=_binding(FakeAdapter(["not json {"])),
            checkpoint_path=cp, tracker=FakeTracker(),
        )
        s = StepCheckpoint.read_summary(cp)
        assert s["completed"] == 0
        assert s["incomplete"] == 2
        assert s["errors"] == 0  # absence is the retry marker, not an error
        assert s["phase"] == "in_progress"


class TestWaveFixes:
    """The adversarial review round's (2026-09-08) findings, pinned."""

    def test_tracker_fallback_resolves_global(self, tmp_path):
        """The production shape: no tracker passed — the global tracker must
        still make records carry nonzero usage (records with zeros would
        restore zeros even after any later fix; the HIGH wave finding)."""
        from core.llm_reachability import analyze_reachability as ar

        cp = str(tmp_path / "llm_reach_checkpoints")
        dataset = {"units": [_make_unit("a:f1")]}
        ar(dataset, binding=_binding(FakeAdapter([_canned(_sig("a:f1"))])),
           checkpoint_path=cp)  # NOTE: no tracker kwarg — production shape
        import json as _json
        with open(os.path.join(cp, "a_f1.json")) as fh:
            rec = _json.load(fh)
        assert rec["usage"]["input_tokens"] > 0
        assert rec["usage"]["output_tokens"] > 0
        # #216: the fake model is unpriced in config -> the incomplete-cost
        # marker must travel into the record.
        assert rec["usage"].get("cost_incomplete") is True
        assert rec["usage"].get("unpriced_models") == ["claude-test"]

    def test_projection_hashes_the_prompt_bytes(self, tmp_path):
        """The golden invariant: projection_sha is over EXACTLY what the
        prompt sends — a `source`-fallback unit and a str-code unit must hash
        their real bytes, never crash, never hash empty (the wave finding:
        _unit_for_prompt's extraction, not a private reimplementation)."""
        cp = str(tmp_path / "llm_reach_checkpoints")
        dataset = {"units": [
            {"id": "s:f1", "unit_type": "function",
             "code": {"source": "reads_env()"}},   # source fallback
            {"id": "t:f1", "unit_type": "function",
             "code": "raw_string_body"},            # str code
        ]}
        adapter = FakeAdapter([_canned(), _canned()])
        analyze_reachability(
            dataset, binding=_binding(adapter), batch_size=1,
            checkpoint_path=cp, tracker=FakeTracker(),
        )
        # A str/source edit re-runs (the hashes captured real bytes).
        dataset["units"][0]["code"]["source"] = "edited_body()"
        dataset["units"][1]["code"] = "edited_str"
        rerun = FakeAdapter([_canned(), _canned()])
        analyze_reachability(
            dataset, binding=_binding(rerun), batch_size=1,
            checkpoint_path=cp, tracker=FakeTracker(),
        )
        assert len(rerun.calls) == 2  # both re-ran: neither hashed empty

    def test_malformed_prior_record_not_adopted(self, tmp_path):
        """A record whose signals are malformed must NOT adopt as reviewed —
        the unit re-runs (the FN direction)."""
        import json as _json

        cp = str(tmp_path / "llm_reach_checkpoints")
        dataset = {"units": [_make_unit("a:f1")]}
        analyze_reachability(
            dataset, binding=_binding(FakeAdapter([_canned(_sig("a:f1"))])),
            checkpoint_path=cp, tracker=FakeTracker(),
        )
        # Corrupt the record's signals in place.
        p = os.path.join(cp, "a_f1.json")
        with open(p) as fh:
            rec = _json.load(fh)
        rec["signals"] = [{"not": "a signal shape"}]
        with open(p, "w") as fh:
            _json.dump(rec, fh)
        rerun = FakeAdapter([_canned(_sig("a:f1"))])
        analyze_reachability(
            dataset, binding=_binding(rerun), checkpoint_path=cp,
            tracker=FakeTracker(),
        )
        assert len(rerun.calls) == 1  # re-ran, not adopted

    def test_checkpoint_init_oserror_runs_unpersisted(self, tmp_path, monkeypatch):
        """An unwritable checkpoint dir costs persistence, never the pass —
        the stage runs and returns signals."""
        from core.checkpoint import StepCheckpoint

        def boom(self, fingerprint, *, verbose=True):
            raise OSError("EACCES")

        monkeypatch.setattr(StepCheckpoint, "sync_identity", boom)
        cp = str(tmp_path / "llm_reach_checkpoints")
        dataset = {"units": [_make_unit("a:f1")]}
        errors: List[str] = []
        signals = analyze_reachability(
            dataset, binding=_binding(FakeAdapter([_canned(_sig("a:f1"))])),
            checkpoint_path=cp, tracker=FakeTracker(), on_error=errors.append,
        )
        assert {s.unit_id for s in signals} == {"a:f1"}
        assert any("unpersisted" in e for e in errors)


class TestDeepRefuteFixes:
    """The final adversarial round (2026-09-08), pinned."""

    def test_null_unit_type_coerces_not_crashes(self, tmp_path):
        """A malformed unit (unit_type=None / code=None) costs the hash one
        line, never the whole stage (the FN-direction deep-refute finding)."""
        cp = str(tmp_path / "llm_reach_checkpoints")
        dataset = {"units": [
            {"id": "n:f1", "unit_type": None, "code": None},
            _make_unit("a:f1"),
        ]}
        # batch 1 = n:f1 (malformed, empty reply); batch 2 = a:f1 (signal).
        adapter = FakeAdapter([_canned(), _canned(_sig("a:f1"))])
        signals = analyze_reachability(
            dataset, binding=_binding(adapter), batch_size=1,
            checkpoint_path=cp, tracker=FakeTracker(),
        )
        assert {s.unit_id for s in signals} == {"a:f1"}

    def test_pass_start_writes_in_progress_summary(self, tmp_path):
        """The stale-done hazard: a run killed mid-loop after a prior
        completed pass must leave phase=in_progress (the Go sweep reads
        phase=='done' && errors==0 as nothing-to-resume, checkpoint.go:115)."""
        from core.checkpoint import StepCheckpoint

        cp = str(tmp_path / "llm_reach_checkpoints")
        dataset = {"units": [_make_unit("a:f1"), _make_unit("b:f2")]}
        # A completed prior pass: summary says done.
        analyze_reachability(
            dataset, binding=_binding(FakeAdapter([_canned(_sig("a:f1"))])),
            checkpoint_path=cp, tracker=FakeTracker(),
        )
        assert StepCheckpoint.read_summary(cp)["phase"] == "done"
        # An interrupted re-run (one unit edited, killed before the loop can
        # finish): simulate by checking the START summary of a fresh call —
        # patch the adapter to raise mid-pass and verify the on-disk phase.
        class KillMidPass(FakeAdapter):
            def complete(self, **kw):
                raise RuntimeError("killed")

        # One unit edited: it re-runs, the pass dies mid-loop, and the
        # START summary (in_progress) is what survives on disk.
        dataset["units"][1]["code"]["primary_code"] = "def edited(): pass"
        analyze_reachability(
            dataset, binding=_binding(KillMidPass()), checkpoint_path=cp,
            tracker=FakeTracker(),
        )
        s = StepCheckpoint.read_summary(cp)
        assert s["phase"] == "in_progress"
        assert s["incomplete"] >= 1
