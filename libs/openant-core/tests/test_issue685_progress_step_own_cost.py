"""#685: a STEP-scoped progress cost line must report the step's own spend.

``ProgressReporter._get_cost`` (progress.py:78-83) returns the GLOBAL tracker's
``total_cost_usd`` — the tracker is per-SCAN (``get_global_tracker()`` at
analyzer.py:177/271, enhancer.py:97, verifier.py:274) — and two step-scoped
displays printed it raw:

  * ``finish()``        -> ``[Enhance] Done: 100/100 units in … | cost $X``
  * the periodic summary -> ``[Enhance] --- 50/100 (50.0%) | … | cost $X ---``

so both summed every prior step. The issue's four stress runs show it: the
enhance line reported enhance + app-context, never enhance alone.

This is the un-swept sibling of #214. ``core/tracking.py:37-46`` already states
the contract for the other per-phase stderr lines — "with ``baseline`` … the
line reports THIS PHASE's delta instead of the cumulative run totals" — and
``analyzer.py:849-856`` states its resume half: "The step reports' totals still
include the prior usage (the run-total contract); only the per-phase stderr line
is the delta." ``ProgressReporter`` was missed by both sweeps.

NOT in scope, per the issue's own comment rulings:
  * the per-UNIT line's ``total_cost - _last_cost`` delta, which under
    parallel workers is a smeared attribution rather than that unit's spend
    (comment 3: "a measurement-precision note") — pinned unchanged below;
  * the registry probe's unbilled usage, which #684 owns (comment 1).
"""

import pytest

import core.tracking as tracking
from core.progress import ProgressReporter, _fmt_cost
from core.step_report import step_context
from utilities.llm_client import get_global_tracker

# $1 per million input tokens, nothing for output: one input token is
# exactly $0.000001, so a dollar figure maps to an integer token count.
_PRICE = {"input": 1.0, "output": 0.0}


def _spend(dollars: float) -> None:
    """Record REAL tracker spend of exactly ``dollars`` (no stubbing)."""
    get_global_tracker().record_call(
        "m", round(dollars * 1_000_000), 0, pricing=_PRICE)


def _cost_field(line: str) -> str:
    """The ``cost $X`` token of a Done / summary line."""
    assert "cost " in line, f"no cost field in {line!r}"
    return line.split("cost ")[1].split()[0].rstrip("|-").strip()


# The issue's four independent stress runs: (name, enhance's own, app-context's,
# the scan-cumulative sum the stderr line actually printed).
STRESS = [
    ("click-python",   0.2880, 0.0294, 0.3174),
    ("files-swift",    0.3402, 0.0187, 0.3589),
    ("httprouter-go",  0.2165, 0.0264, 0.2429),
    ("kilo-c",         0.1390, 0.0136, 0.1525),
]


@pytest.mark.parametrize("name,own,prior,cumulative", STRESS)
def test_the_done_line_reports_the_steps_own_cost(capsys, name, own, prior,
                                                  cumulative):
    """The issue's table, run forward: a prior step spends, then Enhance does."""
    tracking.reset_tracking()
    _spend(prior)                                     # the app-context step
    tracker = get_global_tracker()
    progress = ProgressReporter("Enhance", 4, tracker=tracker)  # phase start
    _spend(own)                                       # THIS step's spend
    progress.completed = 4
    progress.finish()

    line = capsys.readouterr().err.strip().splitlines()[-1]
    assert _cost_field(line) == _fmt_cost(own), (
        f"{name}: the Done line must report the step's own "
        f"{_fmt_cost(own)}, got {_cost_field(line)!r} — line: {line!r}")
    assert _fmt_cost(cumulative) not in line, (
        f"{name}: the Done line still prints the scan-cumulative "
        f"{_fmt_cost(cumulative)} (= {_fmt_cost(own)} + {_fmt_cost(prior)})")


def test_the_periodic_summary_reports_the_steps_own_cost(capsys):
    """The second site: report()'s interval summary fed _print_summary the
    same global total, so a step's interval lines ALSO summed prior steps."""
    tracking.reset_tracking()
    _spend(0.0294)
    tracker = get_global_tracker()
    progress = ProgressReporter("Enhance", 3, tracker=tracker,
                                summary_interval=1)
    _spend(0.2880)
    progress.report("u1")

    summaries = [l for l in capsys.readouterr().err.splitlines() if " --- " in l]
    assert summaries, "no periodic summary line was printed"
    assert _cost_field(summaries[-1]) == _fmt_cost(0.2880), (
        f"the interval summary must report the step's own $0.2880, got "
        f"{_cost_field(summaries[-1])!r} — line: {summaries[-1]!r}")
    assert _fmt_cost(0.3174) not in summaries[-1]


def test_the_step_line_agrees_with_the_step_reports_baseline_delta(capsys,
                                                                   tmp_path):
    """Format-independent cross-check against the artifact the issue calls
    already-correct: the Done line's dollars must equal the step report's
    ``cost_usd`` (step_report.py:52 snapshots, :141 subtracts)."""
    tracking.reset_tracking()
    _spend(0.0294)                                    # a prior step
    with step_context("enhance", str(tmp_path)) as report:
        tracker = get_global_tracker()
        progress = ProgressReporter("Enhance", 1, tracker=tracker)
        _spend(0.2880)
        progress.completed = 1
        progress.finish()
        done = capsys.readouterr().err.strip().splitlines()[-1]
    assert _cost_field(done) == _fmt_cost(report.cost_usd), (
        f"the Done line ({_cost_field(done)}) disagrees with the step "
        f"report's own delta (${report.cost_usd:.4f} -> "
        f"{_fmt_cost(report.cost_usd)})")


def test_a_refreshed_phase_baseline_excludes_restored_spend(capsys):
    """The #281 half of the contract (analyzer.py:849-856): a per-phase stderr
    line is the delta, so the checkpoint injection's restored spend must not
    land in it. Replays the real sequence — holder snapshot (enhancer.py:68),
    reporter built (enhancer.py:122), THEN add_prior_usage + the holder refresh
    (context_enhancer.py:799-806), which happens after construction because
    restored_callback fires at :691, before the injection."""
    tracking.reset_tracking()
    holder = {"usage": tracking.get_usage()}          # enhancer.py:68
    tracker = get_global_tracker()
    progress = ProgressReporter("Enhance", 2, tracker=tracker,
                                cost_baseline=holder)  # enhancer.py:122
    tracker.add_prior_usage(0, 0, 0.6000)             # restored checkpoints
    holder["usage"] = tracking.get_usage()            # the #281 refresh
    _spend(0.0300)                                    # the only NEW spend
    progress.mark_restored(1)
    progress.completed = 2
    progress.finish()

    line = capsys.readouterr().err.strip().splitlines()[-1]
    assert _cost_field(line) == _fmt_cost(0.0300), (
        f"the resumed phase line must report only the new $0.0300, got "
        f"{_cost_field(line)!r} — line: {line!r}")
    assert _fmt_cost(0.6300) not in line, (
        "the restored checkpoints' spend is double-counted on the phase line")


def test_the_per_unit_line_keeps_its_last_cost_delta(capsys):
    """Comment 3's ruling, pinned: the per-UNIT line stays ``total_cost -
    _last_cost``. Its smearing under parallel workers is a measurement-precision
    note, NOT this fix — so the fix must leave this line's semantics alone."""
    tracking.reset_tracking()
    tracker = get_global_tracker()
    progress = ProgressReporter("Enhance", 3, tracker=tracker)
    _spend(0.0050)
    progress.report("u1")
    _spend(0.0070)
    progress.report("u2")

    units = [l for l in capsys.readouterr().err.splitlines() if " --- " not in l]
    assert _fmt_cost(0.0050) in units[0], units[0]
    assert _fmt_cost(0.0070) in units[1], units[1]   # the delta, not $0.0120


def test_no_tracker_still_reports_zero(capsys):
    """Precondition guard: the tracker-less path (tests/test_progress_*.py and
    any caller that omits ``tracker``) must stay 0.0 - 0.0 == 0.0, never a
    fabricated baseline (#605's shape)."""
    progress = ProgressReporter("step", 1, tracker=None)
    progress.completed = 1
    progress.finish()
    assert _cost_field(capsys.readouterr().err.strip()) == _fmt_cost(0.0)


def test_finish_is_repeat_call_stable(capsys):
    """analyzer.py calls finish() at FOUR sites (:360, :369, :398, :403 at this
    head -- the #685 diff's own +5 comment moved them from :355/:364/:393/:398)
    on one
    reporter, so the baseline must be immutable: a second call reports the same
    step total, never a second delta that reads $0."""
    tracking.reset_tracking()
    _spend(0.0294)
    tracker = get_global_tracker()
    progress = ProgressReporter("Enhance", 1, tracker=tracker)
    _spend(0.2880)
    progress.completed = 1
    progress.finish()
    progress.finish()
    lines = capsys.readouterr().err.strip().splitlines()
    assert _cost_field(lines[-1]) == _cost_field(lines[-2]) == _fmt_cost(0.2880)


def test_detect_reporter_needs_no_holder_because_of_its_call_order():
    """Why analyzer.py:317 is left alone: its reporter lives in
    ``_run_detection``, which ``run_analysis`` invokes AFTER the #281
    re-snapshot — so its construction-time baseline is already post-injection.
    Pinned as source order the way tests/test_issue281_resume_baseline.py:129
    pins the analyze call order."""
    import inspect
    import core.analyzer as analyzer
    src = inspect.getsource(analyzer)
    inject = src.index("get_global_tracker().add_prior_usage(")
    resnap = src.index("_phase_baseline = tracking.get_usage()", inject)
    call = src.index("_run_detection(", resnap)
    assert inject < resnap < call, (
        "analyzer's #281 re-snapshot must stay between the injection and the "
        "_run_detection call — if it moves, Detect's progress baseline needs "
        "the same mutable holder enhance/verify pass")


def test_enhance_and_verify_actually_pass_the_phase_holder():
    """The plumbing, pinned. Every other test here drives ProgressReporter
    directly, so a dropped ``cost_baseline=`` kwarg at the two call sites
    would be invisible: the step lines would silently fall back to the
    construction snapshot and lose the #281 post-injection refresh. Pinned as
    source the way tests/test_issue281_resume_baseline.py:141-145 pins the
    log_usage call sites."""
    import inspect
    import core.enhancer as enhancer
    import core.verifier as verifier

    for mod, needle in (
        (enhancer, 'ProgressReporter("Enhance", len(units), tracker=tracker,\n'
                   '                                cost_baseline=_phase_baseline)'),
        (verifier, 'ProgressReporter("Verify", findings_input, tracker=tracker,\n'
                   '                                cost_baseline=_phase_baseline)'),
    ):
        src = inspect.getsource(mod)
        assert needle in src, (
            f"{mod.__name__} no longer threads its #281 phase holder into "
            f"ProgressReporter — the step cost line would silently revert to "
            f"the construction snapshot on a resumed run")


def test_a_malformed_cost_baseline_degrades_the_line_and_never_raises(capsys):
    """``finish()`` runs after a step has already paid for its work, so a bad
    holder must fall back to the construction snapshot, not kill the step."""
    tracking.reset_tracking()
    _spend(0.0294)
    tracker = get_global_tracker()
    for bad in (None, {}, {"usage": None}, {"usage": object()}, "not-a-holder"):
        progress = ProgressReporter("Enhance", 1, tracker=tracker,
                                    cost_baseline=bad)
        _spend(0.0100)
        progress.completed = 1
        progress.finish()
        line = capsys.readouterr().err.strip().splitlines()[-1]
        assert _cost_field(line) == _fmt_cost(0.0100), (
            f"holder {bad!r}: expected the construction-snapshot fallback "
            f"{_fmt_cost(0.0100)}, got {_cost_field(line)!r}")


def test_the_delta_is_rounded_like_the_step_reports(capsys, tmp_path):
    """The subtraction's float residue must not survive onto the line: a $0.01
    step delta lands at 0.00999999999999999 and would trip ``_fmt_cost``'s
    $0.01 threshold into the 4-decimal branch. ``step_report.py:141`` rounds
    its own delta to 6 decimals; this line rounds identically, so the two
    figures agree digit for digit."""
    tracking.reset_tracking()
    _spend(0.0294)                                    # a prior step
    with step_context("enhance", str(tmp_path)) as report:
        tracker = get_global_tracker()
        progress = ProgressReporter("Enhance", 1, tracker=tracker)
        assert tracker.get_totals()["total_cost_usd"] - 0.0294 == 0.0, \
            "fixture precondition: the baseline is the prior step's spend"
        _spend(0.0100)
        progress.completed = 1
        assert progress._step_cost() == 0.01, (
            f"the raw subtraction leaked float residue: "
            f"{progress._step_cost()!r}")
        progress.finish()
        line = capsys.readouterr().err.strip().splitlines()[-1]
    assert _cost_field(line) == "$0.01", line
    assert progress._step_cost() == report.cost_usd, (
        f"the Done line's delta {progress._step_cost()!r} and the step "
        f"report's {report.cost_usd!r} must be the same number")


def test_a_negative_delta_is_never_clamped_to_zero(capsys, tmp_path):
    """fable r1 F3 / the surviving M4 ruling: no clamp. The tracker is
    monotonic except ``reset()``, but IF a baseline ever reads higher than
    the running total (a mid-step ``reset_tracking()``, a resumed run whose
    baseline was restored above the live tracker), the step's delta is
    negative and the honest line SHOWS it (``$-0.0100``), never a silent
    ``$0.0000`` — an over-baselined step must stay visible, exactly like
    #214's over-counted phases did. This freezes the M4 mutant
    (``max(0.0, delta)``) as WRONG: it survived every other test."""
    tracking.reset_tracking()
    _spend(0.0200)                                    # a prior step
    with step_context("enhance", str(tmp_path)):
        tracker = get_global_tracker()
        progress = ProgressReporter("Enhance", 1, tracker=tracker)
        assert tracker.get_totals()["total_cost_usd"] - 0.0200 == 0.0, \
            "fixture precondition: the baseline is the prior step's spend"
        tracking.reset_tracking()                     # the mid-step reset
        progress.completed = 1
        progress.finish()
        line = capsys.readouterr().err.strip().splitlines()[-1]
    assert _cost_field(line).startswith("$-"), (
        f"a negative step delta must render visible, never clamped: {line}")
    assert _cost_field(line) != "$0.0000", line
