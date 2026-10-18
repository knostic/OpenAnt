"""#798 end-to-end regression: a signal for an in-dataset, out-of-batch
unit is a REAL reachability signal — the validation universe is the
DATASET's id index, never the current batch slice.

At the base (``core/llm_reachability.py``, ``_attempt``) the parse-time
validation set was the CURRENT BATCH's ids — ``batch_ids = {u.get("id")
for u in sub_batch}`` — so ``parse_response`` dropped a signal whose
``unit_id`` sat outside the responding batch as "unknown unit_id", even
when the unit EXISTS in the dataset and ``apply_signals`` could have
resolved it (its own ``by_id`` IS the dataset). The campaign's artifacts
(the issue's CODE-TRACED evidence, the SGLang completion run 1, 58,306
units): 61 of 95 skip events were in-dataset units — 10 of them
entry_point/high promotions that never landed.

The fix: ``valid_unit_ids`` is the DATASET index (built once, the full
dataset — not the ``max_units``-truncated review slice), so the skip
keeps its honest meaning: "absent from the dataset" (the genuine model
inventions). Two sibling counters land with it: the apply-time drop in
``apply_signals`` (the stale-id class: a checkpoint-adopted signal
replayed against a changed dataset) is now COUNTED, and the resume path
carries ``signals_cache_adopted`` — the resume-comparability companion
that explains a resumed run's zero parse-time skips.

Hermetic: the FakeAdapter pattern from test_llm_reachability.py /
test_issue532_llr_resume.py — no network, no API key.

Shapes:

  S1 -- the WITNESS (red at base): a 4-unit dataset, batch_size=2 (two
        batches); the model's answer to batch 1 carries an
        entry_point/high signal for a unit that sits in batch 2. The
        base drops it as "unknown unit_id" (the returned signal list is
        empty, the promotion never lands); after the fix the signal is
        returned, applied, and the unit is promoted.
  S2 -- the WITNESS (red at base): ``apply_signals`` drops a stale-id
        signal silently; the fix counts it in the returned summary's
        ``signals_dropped_unknown_unit``.
  S3 -- the WITNESS (red at base): a resume (the checkpoint path)
        adopts cached signals without parsing, so its
        ``signals_skipped_unknown_unit`` reads 0 with nothing explaining
        it; the fix adds ``signals_cache_adopted`` to the stats.
  S4 -- the CONTROL (green at base AND head): a signal for a unit
        absent from the DATASET entirely is still skipped and counted —
        the #602 contract (genuine model inventions) is untouched by the
        wider universe.
  S5 -- the r1-F1 BACKWARD shape (red at base): a signal parsed in a
        LATER batch for a unit whose record an EARLIER batch already
        wrote — the per-batch flush merges it into that record, so the
        resume's adopted state equals the applied state (without the
        flush: promoted 2 -> 1 across the resume, a divergence the diff
        itself introduced).
  S6 -- the r1-F1 ADOPTED-TARGET shape (red at base): run 1 records no
        signal for the unit; run 2 adopts it while a later batch signals
        it cross-batch — the flush merges into the ADOPTED record, so
        run 3 still replays it.
  S7 -- the r2-F5 RE-SIGNAL shape (red at base): the same unit signaled
        identically by two batches — the returned list dedupes on
        (unit_id, kind, confidence) like the records, so the step
        report's counts hold across a resume chain.
  S8 -- the r3-F1 STALE-BASE shape (red at base): a target cross-signaled
        by TWO later batches with DISTINCT (kind, confidence) — the
        per-batch flush's in-memory base refreshes after its own merge,
        so the record ACCUMULATES both and the resume replays both.
"""

import json
from typing import List

from core.llm_reachability import (
    ReachabilitySignal,
    analyze_reachability,
    apply_signals,
)


# ---------------------------------------------------------------------------
# Harness (mirrors test_llm_reachability.py / test_issue532_llr_resume.py)
# ---------------------------------------------------------------------------

class FakeAdapter:
    name = "anthropic"
    supports_tools = True

    def __init__(self, responses: List[str] | None = None):
        self._responses = list(responses or [])
        self.calls: List[dict] = []

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        from utilities.llm import CompletionResult, TextBlock

        self.calls.append({"prompt": messages[0].content[0].text,
                           "max_tokens": max_tokens, "model": model})
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
    """The tracker surfaces this stage touches (the #532 harness shape —
    TokenTracker's real method names; the add_prior_usage stub is
    permissive because the caller wraps it in `except Exception: pass`)."""

    def __init__(self):
        self._current = {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}

    def record_call(self, *, model=None, input_tokens=0, output_tokens=0,
                    pricing=None, usage_details=None):
        self._current["input_tokens"] += input_tokens or 0
        self._current["output_tokens"] += output_tokens or 0

    def start_unit_tracking(self):
        self._current = {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}

    def get_unit_usage(self):
        return dict(self._current)

    def get_totals(self):
        return dict(self._current)

    def add_prior_usage(self, *a, **kw):
        pass


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


def _dataset() -> dict:
    """Four units; with batch_size=2 the batches are [a.py:a, b.py:b] and
    [c.py:c, d.py:d]."""
    return {"units": [
        _make_unit("a.py:a"), _make_unit("b.py:b"),
        _make_unit("c.py:c"), _make_unit("d.py:d"),
    ]}


# ---------------------------------------------------------------------------
# S1 — the in-dataset, out-of-batch signal is a REAL signal
# ---------------------------------------------------------------------------

def test_an_in_dataset_out_of_batch_signal_survives_and_promotes():
    """S1: the model's answer to batch 1 ([a, b]) carries an entry_point/
    high signal for c.py:c — a unit in the DATASET but in batch 2. The
    base drops it as "unknown unit_id" (the batch-slice validation); the
    fix returns it, applies it, and the promotion lands."""
    out_of_batch = _sig("c.py:c", "entry_point", "high")
    dataset = _dataset()
    stats: dict = {}

    signals = analyze_reachability(
        dataset,
        binding=_binding(FakeAdapter([_canned(out_of_batch), _canned()])),
        batch_size=2,
        stats=stats,
    )

    # the signal is RETURNED (the base: dropped -> the list is empty)
    assert [s.unit_id for s in signals] == ["c.py:c"], (
        f"an in-dataset, out-of-batch signal is a REAL signal — the "
        f"validation universe is the dataset, not the batch slice; "
        f"got {[s.unit_id for s in signals]}")

    # and it APPLIES: the promotion lands through the real apply path
    summary = apply_signals(dataset, signals)
    assert summary["signals_applied"] == 1, summary
    assert summary["entry_points_promoted"] == 1, summary
    unit_c = next(u for u in dataset["units"] if u["id"] == "c.py:c")
    assert unit_c.get("is_entry_point") is True, (
        "the out-of-batch entry_point/high signal must promote its unit")


# ---------------------------------------------------------------------------
# S2 — the apply-time drop carries a counter
# ---------------------------------------------------------------------------

def test_apply_signals_counts_the_stale_id_drop():
    """S2: a signal whose unit_id is absent from THIS dataset (the
    stale-id class: a checkpoint-adopted signal replayed against a
    changed dataset, or a caller-supplied list) is dropped at apply time
    — and the drop is COUNTED in the returned summary. The base's
    summary carried no such key: 'every signal landed' was
    indistinguishable from 'some did not'."""
    stale = ReachabilitySignal(unit_id="gone.py:old", kind="entry_point",
                               confidence="high", reason="stale")
    summary = apply_signals({"units": [_make_unit("here.py:kept")]}, [stale])
    assert summary.get("signals_applied") == 0, summary
    assert summary.get("signals_dropped_unknown_unit") == 1, (
        f"the apply-time drop must be counted: {summary}")


# ---------------------------------------------------------------------------
# S3 — the resume record explains its own zero
# ---------------------------------------------------------------------------

def test_resume_carries_the_cache_adopted_counter(tmp_path):
    """S3: a resumed run adopts cached signals WITHOUT parsing, so its
    parse-time skip counter reads 0 — which previously read as 'nothing
    dropped' with nothing in the record explaining it. The fix adds
    ``signals_cache_adopted``: the resume's own stats name how many
    signals came from the checkpoint cache."""
    cp = str(tmp_path / "llm_reach_checkpoints")
    dataset1 = {"units": [_make_unit("a.py:f1")]}
    analyze_reachability(
        dataset1,
        binding=_binding(FakeAdapter([_canned(_sig("a.py:f1"))])),
        checkpoint_path=cp, tracker=FakeTracker(),
    )

    stats: dict = {}
    dataset2 = {"units": [_make_unit("a.py:f1")]}
    signals = analyze_reachability(
        dataset2,
        binding=_binding(FakeAdapter()),  # no new calls: everything adopts
        checkpoint_path=cp, tracker=FakeTracker(),
        stats=stats,
    )

    assert len(signals) == 1, "the cached signal replays (the #532 contract)"
    assert stats.get("units_adopted") == 1, stats
    assert stats.get("signals_skipped_unknown_unit", 0) == 0, (
        "the resume parses nothing, so its parse-time skip count is 0")
    assert stats.get("signals_cache_adopted") == 1, (
        f"the resume's record must name how many signals came from the "
        f"cache — the comparability companion that explains the 0: {stats}")


# ---------------------------------------------------------------------------
# S4 — the CONTROL: a genuine invention is still skipped
# ---------------------------------------------------------------------------

def test_a_signal_absent_from_the_dataset_is_still_skipped():
    """S4: the wider validation universe must NOT admit inventions — a
    signal for a unit absent from the DATASET entirely is skipped and
    counted exactly as before (the #602 contract, green at the base AND
    after the fix: this is the fixture-validity lock that the universe
    widened without opening it to everything)."""
    stats: dict = {}
    signals = analyze_reachability(
        {"units": [_make_unit("a.py:f")]},
        binding=_binding(FakeAdapter([_canned(_sig("zz.py:ghost"))])),
        stats=stats,
    )
    assert signals == [], "an invented unit_id must never yield a signal"
    assert stats["signals_skipped_unknown_unit"] == 1, (
        f"the genuine-invention skip stays counted: {stats}")
    assert stats["signals_skipped_unknown_unit_by_class"] == {
        "entry_point/high": 1}, stats


# ---------------------------------------------------------------------------
# S5/S6 — r1-F1: the BACKWARD cross-batch shape and the ADOPTED-target
# shape persist too (the per-batch flush)
# ---------------------------------------------------------------------------

def test_a_backward_cross_batch_signal_persists_for_the_resume(tmp_path):
    """S5 (the r1-F1 catch): a signal parsed in a LATER batch for a unit
    whose record was already written by an EARLIER batch. Without the
    per-batch flush the signal is applied in this run but its target's
    record never carries it — a resume at phase=done then silently
    adopts fewer signals than this run applied (the lane executed the
    divergence: promoted 2 -> 1; the parity HELD at the base because
    both runs dropped the signal there). With the flush the record is
    re-saved with the merged signal and the resume replays it."""
    cp = str(tmp_path / "llm_reach_checkpoints")
    dataset = {"units": [_make_unit("a.py:a"), _make_unit("b.py:b")]}
    # batch 1 ([a]): nothing; batch 2 ([b]): b's own signal AND a's —
    # a's record was written by batch 1, so the stash survives to the
    # flush (the BACKWARD direction).
    canned = [_canned(), _canned(_sig("b.py:b"), _sig("a.py:a"))]
    signals = analyze_reachability(
        dataset, binding=_binding(FakeAdapter(canned)), batch_size=1,
        checkpoint_path=cp, tracker=FakeTracker(),
    )
    assert {s.unit_id for s in signals} == {"a.py:a", "b.py:b"}

    import json as _json
    import os as _os
    with open(_os.path.join(cp, "a.py_a.json")) as fh:
        rec_a = _json.load(fh)
    assert [s["unit_id"] for s in rec_a["signals"]] == ["a.py:a"], (
        "the BACKWARD cross-batch signal must persist through the flush — "
        "else the resume's adopted state diverges from the applied state")

    # the resume replays the flushed record: adopted == applied
    stats: dict = {}
    replayed = analyze_reachability(
        dataset, binding=_binding(FakeAdapter()), batch_size=1,
        checkpoint_path=cp, tracker=FakeTracker(), stats=stats,
    )
    assert {s.unit_id for s in replayed} == {"a.py:a", "b.py:b"}
    assert stats.get("signals_cache_adopted") == 2, stats


def test_an_adopted_targets_cross_batch_signal_persists(tmp_path):
    """S6 (the r1-F1 catch, the adopted-target shape): run 1 reviews a
    unit and records NO signal for it; run 2 (the resume) ADOPTS it (its
    record is never rewritten this run) while the new unit's batch
    signals it cross-batch. The signal is applied in run 2 — the flush
    must merge it into the ADOPTED record so run 3 (the next resume)
    still replays it. At the base the cross-batch signal is dropped at
    parse, so run 2 applies nothing — the divergence is the fix's own."""
    cp = str(tmp_path / "llm_reach_checkpoints")
    dataset_a = {"units": [_make_unit("a.py:a")]}
    analyze_reachability(
        dataset_a, binding=_binding(FakeAdapter([_canned()])),
        checkpoint_path=cp, tracker=FakeTracker(),
    )

    # run 2: a ADOPTS (no re-parse); the NEW unit b's batch signals a
    # cross-batch — the adopted-target + cross-batch shape
    dataset_b = {"units": [_make_unit("a.py:a"), _make_unit("b.py:b")]}
    signals = analyze_reachability(
        dataset_b, binding=_binding(FakeAdapter([_canned(_sig("a.py:a"))])),
        batch_size=1, checkpoint_path=cp, tracker=FakeTracker(),
    )
    assert {s.unit_id for s in signals} == {"a.py:a"}, (
        "the cross-batch signal for the ADOPTED target must be carried "
        "(the dataset-wide universe)")

    import json as _json
    import os as _os
    with open(_os.path.join(cp, "a.py_a.json")) as fh:
        rec_a = _json.load(fh)
    assert [s["unit_id"] for s in rec_a["signals"]] == ["a.py:a"], (
        "the flush must merge the signal into the ADOPTED target's record — "
        "adopted state equals applied state across the resume chain")

    # run 3: everything adopts — the signal still replays
    replayed = analyze_reachability(
        dataset_b, binding=_binding(FakeAdapter()), batch_size=1,
        checkpoint_path=cp, tracker=FakeTracker(),
    )
    assert {s.unit_id for s in replayed} == {"a.py:a"}


# ---------------------------------------------------------------------------
# S7 — r2-F5: the re-signal shape (the returned list dedupes like the
# records, so the step report's counts hold across a resume chain)
# ---------------------------------------------------------------------------

def test_a_re_signaled_unit_yields_one_signal_and_stable_counts(tmp_path):
    """S7 (the r2-F5/r2 catch): the SAME unit signaled identically by TWO
    batches (a cross-batch re-signal + its own batch's copy). The record
    merge dedupes to one entry — and the RETURNED list must dedupe on the
    same key, else this run's signals_applied counts 2 while the record
    persists 1 and a resume counts 1: the step report's counts diverged
    across the resume chain by one per re-signal (the lane executed:
    run 2 n=2 / run 3 n=1)."""
    cp = str(tmp_path / "llm_reach_checkpoints")
    dataset = {"units": [_make_unit("a.py:a"), _make_unit("b.py:b")]}
    # batch 1 ([a]): signals b (cross-batch); batch 2 ([b]): signals b
    # again (its own copy) — the same (unit_id, kind, confidence).
    canned = [_canned(_sig("b.py:b")), _canned(_sig("b.py:b"))]
    signals = analyze_reachability(
        dataset, binding=_binding(FakeAdapter(canned)), batch_size=1,
        checkpoint_path=cp, tracker=FakeTracker(),
    )
    # the returned list carries ONE entry for the re-signaled unit
    assert [s.unit_id for s in signals] == ["b.py:b"], (
        f"the returned list must dedupe on (unit_id, kind, confidence) — "
        f"a re-signal across batches carries the same reachability fact "
        f"once: got {[s.unit_id for s in signals]}")

    # and this run's apply counts match the record's single entry, so a
    # resume's replay counts identically
    summary = apply_signals(dataset, signals)
    assert summary["signals_applied"] == 1, summary

    import json as _json
    import os as _os
    with open(_os.path.join(cp, "b.py_b.json")) as fh:
        rec_b = _json.load(fh)
    assert len(rec_b["signals"]) == 1, rec_b

    # the resume replays ONE signal — the counts stable across the chain
    stats: dict = {}
    replayed = analyze_reachability(
        dataset, binding=_binding(FakeAdapter()), batch_size=1,
        checkpoint_path=cp, tracker=FakeTracker(), stats=stats,
    )
    assert [s.unit_id for s in replayed] == ["b.py:b"]
    assert stats.get("signals_cache_adopted") == 1, stats  # only b carries a signal; a's empty record adopts 0


# ---------------------------------------------------------------------------
# S8 — r3-F1: the stale-base regression (two later batches, distinct keys)
# ---------------------------------------------------------------------------

def test_two_later_batches_cross_signaling_accumulate_in_the_record(tmp_path):
    """S8 (the r3-F1 catch): a target cross-signaled by TWO later batches
    with DISTINCT (kind, confidence) must carry BOTH signals in its
    record — the per-batch flush's in-memory base must REFRESH after its
    own merge, else the second flush re-merges onto the stale pre-flush
    snapshot and the first signal is silently lost (the r3 lane executed
    the regression the r2 remediation introduced: run 1 returned
    [(a, ep, high), (a, ep, medium)] but the record kept only the
    medium; the resume then promoted 0 vs run 1's 1)."""
    cp = str(tmp_path / "llm_reach_checkpoints")
    dataset = {"units": [_make_unit("a.py:a"), _make_unit("b.py:b"),
                         _make_unit("c.py:c")]}
    # batch 1 ([a]): nothing; batch 2 ([b]): a high; batch 3 ([c]): a medium
    canned = [_canned(),
              _canned(_sig("a.py:a", "entry_point", "high")),
              _canned(_sig("a.py:a", "entry_point", "medium"))]
    signals = analyze_reachability(
        dataset, binding=_binding(FakeAdapter(canned)), batch_size=1,
        checkpoint_path=cp, tracker=FakeTracker(),
    )
    assert [(s.unit_id, s.confidence) for s in signals] == [
        ("a.py:a", "high"), ("a.py:a", "medium")], (
        "both cross-batch signals are returned (distinct keys, both real)")

    import os as _os
    with open(_os.path.join(cp, "a.py_a.json")) as fh:
        rec_a = json.load(fh)
    assert [(s["unit_id"], s["confidence"]) for s in rec_a["signals"]] == [
        ("a.py:a", "high"), ("a.py:a", "medium")], (
        "the record must ACCUMULATE across the per-batch flushes — the "
        "in-memory base refreshes after each merge (r3-F1)")

    # and the resume replays BOTH: adopted state equals applied state
    replayed = analyze_reachability(
        dataset, binding=_binding(FakeAdapter()), batch_size=1,
        checkpoint_path=cp, tracker=FakeTracker(),
    )
    assert [(s.unit_id, s.confidence) for s in replayed] == [
        ("a.py:a", "high"), ("a.py:a", "medium")]
