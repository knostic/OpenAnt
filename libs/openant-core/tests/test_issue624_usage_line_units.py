"""#624 — the usage line names what it counts: completions and records.

The per-phase stderr line said "N API calls" while counting TRACKER
RECORDS — and the record unit differed by phase (enhance: one record per
conversation/unit; the verifier: one per finding-conversation; single-shot
helpers: one per completion; the report phase: one aggregate for the whole
phase) — so "Enhance: 1730 API calls" counted UNITS while the run's actual
retained turns were 4,638, and an operator could not know which population
any line carried. One label, three record units.

The fix: every conversation record declares its billed-turn count
(``turns``, REQUIRED when ``usage_details`` is a per-turn list — the
ValueError guard makes a future list-producer fail loudly instead of
silently billing one turn for N); single-completion records default to 1;
the report phase's aggregate carries its completions count; the tracker
sums ``total_turns``; and the line prints BOTH populations:
"N completions (M records), T tokens, $C" — the same unit for every phase.

Two-sided discipline: every row asserts the new text AND the old label's
absence; the conversation row asserts the count AND its structural
identity with the list (``turns == len(usage_details)``) — the report
aggregate deliberately does NOT carry that identity (its merged details
list drops no-detail entries; the completions count is authoritative). Exclusions, pinned as
documentation: SDK-internal retries, raising turns that billed nothing,
KeyboardInterrupt'd turns, and add_prior_usage-injected summary spend all
lie outside both counters — plus the threat-model repo-explorer loop,
which records nothing to the tracker at all (a named follow-up).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # libs/openant-core

import core.tracking as tracking  # noqa: E402
from core.schemas import UsageInfo  # noqa: E402
from utilities.llm_client import get_global_tracker  # noqa: E402

_PRICE = {"input": 1.0, "output": 2.0}


def _record_single(n=1):
    tr = get_global_tracker()
    rec = None
    for _ in range(n):
        rec = tr.record_call("m", 100, 50, pricing=_PRICE)
    return rec


def _record_conversation(turns):
    """One conversation record covering `turns` billed turns (the list
    shape, a None entry for a billed raising turn included)."""
    return get_global_tracker().record_call(
        "m", 100 * turns, 50 * turns, pricing=_PRICE,
        usage_details=[{"x": 1}] * turns, turns=turns)


# --- the record contract -------------------------------------------------------

def test_single_completion_defaults_to_one_turn():
    tracking.reset_tracking()
    rec = _record_single()
    assert rec["turns"] == 1
    assert get_global_tracker().get_totals()["total_turns"] == 1


def test_conversation_record_declares_its_billed_turns():
    tracking.reset_tracking()
    rec = _record_conversation(3)
    assert rec["turns"] == 3
    assert rec["turns"] == len(rec["usage_details"]), (
        "the turn count is structurally the billed-turn list length")
    totals = get_global_tracker().get_totals()
    assert totals["total_turns"] == 3
    assert totals["total_calls"] == 1, (
        "one conversation record, never one per turn — the double-bill guard")


def test_list_without_turns_fails_loudly():
    """The ValueError guard: a future list-passing producer must not
    silently bill one turn for N."""
    tracking.reset_tracking()
    try:
        get_global_tracker().record_call(
            "m", 100, 50, pricing=_PRICE,
            usage_details=[{"x": 1}, {"x": 1}])
    except ValueError as e:
        assert "turns" in str(e)
    else:
        raise AssertionError("the guard must fire for a list without turns")


def test_raise_path_none_entry_is_a_billed_turn():
    """The #609/#616 convention: a raising turn that billed (the [None]
    entry) IS a billed turn — the list length, not the iterations counter
    (which counts the unbilled attempt too)."""
    tracking.reset_tracking()
    details = [{"x": 1}, {"x": 1}, None]  # two completed turns + a billed raise
    rec = get_global_tracker().record_call(
        "m", 100, 50, pricing=_PRICE, usage_details=details, turns=len(details))
    assert rec["turns"] == 3


def test_reset_zeroes_the_turn_counter():
    tracking.reset_tracking()
    _record_conversation(2)
    tracking.reset_tracking()
    assert get_global_tracker().get_totals()["total_turns"] == 0


def test_add_prior_usage_never_injects_turns():
    """Resumed runs: add_prior_usage carries tokens/cost only — turns (like
    calls) are current-process, so the pair stays internally consistent."""
    tracking.reset_tracking()
    tr = get_global_tracker()
    tr.add_prior_usage(100, 50, 0.01)
    totals = tr.get_totals()
    assert totals["total_calls"] == 0 and totals["total_turns"] == 0


# --- the line --------------------------------------------------------------------

def test_the_line_names_both_populations(capsys):
    tracking.reset_tracking()
    _record_single(3)                     # prior phases: 3 completions
    baseline = tracking.get_usage()
    _record_conversation(4)                # this phase: 1 record, 4 turns
    _record_single(1)                     # + 1 single completion
    tracking.log_usage("Enhance", baseline)
    err = capsys.readouterr().err
    assert "Enhance: 5 completions (2 records)" in err, (
        "the phase delta: 4+1 completions in 1+1 records")
    assert "API calls" not in err, "the lying label is gone"
    assert "8 completions" not in err, "not the cumulative total (3+4+1)"


def test_no_baseline_is_cumulative_backcompat(capsys):
    tracking.reset_tracking()
    _record_conversation(3)
    _record_single(2)
    tracking.log_usage("Total")
    err = capsys.readouterr().err
    assert "Total: 5 completions (3 records)" in err


def test_usage_info_carries_total_turns():
    tracking.reset_tracking()
    _record_conversation(3)
    info = tracking.get_usage()
    assert isinstance(info, UsageInfo)
    assert info.total_turns == 3
    d = info.to_dict()
    assert d["total_turns"] == 3


def test_old_totals_shape_defaults_turns_to_zero(monkeypatch):
    """The .get read pattern (#216): a stubbed/old get_totals lacking the
    key reads as the honest zero through the REAL get_usage, never a
    KeyError."""
    import core.tracking as tr_mod  # noqa: PLC0415
    monkeypatch.setattr(
        tr_mod, "get_global_tracker",
        lambda: type("T", (), {"get_totals": staticmethod(lambda: {
            "total_calls": 2, "total_tokens": 10,
            "total_input_tokens": 5, "total_output_tokens": 5,
            "total_cost_usd": 0.0, "cost_incomplete": False,
            "unpriced_models": []})})())
    info = tracking.get_usage()
    assert info.total_turns == 0, "the .get fallback in tracking.get_usage"
    assert info.total_calls == 2


# --- the dynamic-test baseline threading (the #214-in-the-new-field guard) -------

def test_dt_rebuild_is_phase_scoped(capsys):
    """Drive the holder -> refresh -> rebuild shape the DT phase uses."""
    tracking.reset_tracking()
    _record_single(2)                       # prior spend (restored checkpoints)
    snap = tracking.get_usage()
    holder = {"cost_usd": snap.total_cost_usd, "tokens": snap.total_tokens,
              "calls": snap.total_calls, "turns": snap.total_turns}
    _record_single(1)                       # absorbed spend (in production
    tot = get_global_tracker().get_totals()  # the refresh absorbs RESTORED
    # checkpoint spend, never phase-new spend; this REPLICA exercises the
    # rebuild arithmetic — the production path is pinned by the 333 row)
    holder["calls"] = tot.get("total_calls", holder["calls"])
    holder["turns"] = tot.get("total_turns", holder.get("turns", 0))
    rebuilt = UsageInfo(
        total_calls=holder["calls"],
        total_turns=holder.get("turns", 0),
        total_tokens=holder["tokens"],
        total_cost_usd=holder["cost_usd"])
    _record_single(0)
    tracking.log_usage("Dynamic Test", rebuilt)
    err = capsys.readouterr().err
    assert "Dynamic Test: 0 completions (0 records)" in err, (
        "the phase delta excludes the pre-refresh spend")


# --- the report phase's aggregate record ------------------------------------------

def test_merge_usage_carries_the_completions_count():
    from report.generator import _merge_usage  # noqa: PLC0415
    u1 = {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2,
          "cost_usd": 0.0, "usage_details": {"a": 1}}
    u2 = {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2,
          "cost_usd": 0.0}
    merged = _merge_usage([u1, u2])
    assert merged["completions"] == 2, (
        "the aggregate record's turn figure — never silently 1")


def test_reporter_aggregate_record_carries_turns():
    from core.reporter import _usage_to_info  # noqa: PLC0415
    info = _usage_to_info({
        "input_tokens": 2, "output_tokens": 2, "total_tokens": 4,
        "cost_usd": 0.0, "completions": 3})
    assert info.total_calls == 1
    assert info.total_turns == 3, (
        "the aggregate: 1 record covering 3 completions — turns never < calls")