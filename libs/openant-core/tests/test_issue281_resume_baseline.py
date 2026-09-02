"""Regression tests for issue #281 — resumed runs double-count prior
session usage in the first per-phase usage line.

#214 added per-phase baselines (``_phase_baseline = tracking.get_usage()``
at phase start) so a "Stage 1" line reports the phase's delta. On a
CHECKPOINT-RESUMED run, ``add_prior_usage(...)`` injects the prior
session's tokens/cost into the global tracker AFTER the baseline was
snapshotted — so the printed delta included the injected prior usage:
``Stage 1: 20 API calls, 1,250,000 tokens, $8.25`` where 20 calls account
for ~250k tokens/$0.25 and the extra ~1M/$8 is the restored session.
Calls exclude restored units while tokens/cost included them — internally
inconsistent, and #214's "this phase's delta" contract broken on resume.

Contract locked here: each phase's usage line counts ONLY the current
session's own calls/tokens/cost. The step reports' totals still include
the prior usage (the run-total contract) — only the per-phase stderr
line is the delta. All three restoring phases fixed: analyze (re-snapshot
after injection), verify + enhance (mutable baseline holder refreshed at
the injection site inside verify_batch/enhance_dataset_agentic).
"""

from __future__ import annotations

import io
import sys
import contextlib
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import tracking  # noqa: E402


def _capture_usage_line(prefix="Stage 1", baseline=None):
    """Call log_usage with the GIVEN baseline and return the printed line."""
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        tracking.log_usage(prefix, baseline)
    return buf.getvalue()


def test_analyzer_resume_baseline_excludes_prior(capfd):
    """The #281 shape at the analyzer level: baseline → injection → own
    calls → the line's delta must count ONLY the own calls. The analyzer
    fix re-snapshots _phase_baseline after add_prior_usage; here we verify
    the exact sequence the fixed code performs."""
    tracker = tracking.get_global_tracker()
    tracker.reset()
    baseline = tracking.get_usage()          # #214 snapshot at phase start
    tracker.add_prior_usage(1_000_000, 500_000, 8.00)  # resume injection
    # THE FIX: re-snapshot after the injection (analyzer.py does this now)
    baseline = tracking.get_usage()
    tracker.record_call(model="m", input_tokens=250_000, output_tokens=50_000,
                        pricing={"input": 1.0, "output": 2.0})  # own work
    line = _capture_usage_line("Stage 1", baseline)
    # own work: 250k input + 50k output = 300k total tokens, $0.35
    assert "300,000" in line, f"delta must be the own tokens (got {line!r})"
    assert "1 API calls" in line
    assert "0.3500" in line, f"own cost $0.35 (got {line!r})"
    assert "8." not in line, (
        f"the restored $8 must NOT appear in the phase delta (got {line!r})"
    )


def test_verifier_holder_refreshed_at_injection():
    """The verify path: a mutable baseline holder passed into verify_batch
    is refreshed at the injection site — the final log uses the refreshed
    value, not the pre-injection snapshot."""
    tracker = tracking.get_global_tracker()
    tracker.reset()
    holder = {"usage": tracking.get_usage()}     # runner's :85 snapshot
    # simulate verify_batch's internal sequence: injection + refresh
    tracker.add_prior_usage(400_000, 200_000, 3.00)
    # (finding_verifier.py:684 does exactly this when phase_baseline is not None)
    holder["usage"] = tracking.get_usage()
    tracker.record_call(model="m", input_tokens=100_000, output_tokens=20_000,
                        pricing={"input": 1.0, "output": 2.0})
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        tracking.log_usage("Stage 2", holder["usage"])
    line = buf.getvalue()
    assert "120,000" in line  # 100k input + 20k output
    assert "3." not in line


def test_enhancer_holder_refreshed_at_injection():
    """The enhance path: same holder shape through
    enhance_dataset_agentic's injection site."""
    tracker = tracking.get_global_tracker()
    tracker.reset()
    holder = {"usage": tracking.get_usage()}
    tracker.add_prior_usage(50_000, 10_000, 0.50)
    holder["usage"] = tracking.get_usage()   # context_enhancer.py:684
    tracker.record_call(model="m", input_tokens=30_000, output_tokens=5_000,
                        pricing={"input": 1.0, "output": 2.0})
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        tracking.log_usage("Enhance", holder["usage"])
    line = buf.getvalue()
    assert "35,000" in line  # 30k input + 5k output
    assert "0.5" not in line


def test_analyzer_resnapshot_is_placed_after_injection():
    """Source-placement contract: the analyzer's baseline re-snapshot must
    sit AFTER the add_prior_usage call (the mutation smoke's target —
    simulation tests can't catch a placement regression)."""
    src = Path(__file__).parent.parent / "core" / "analyzer.py"
    text = src.read_text()
    # ORDER-SENSITIVE (wave catch: the old test was order-insensitive —
    # a pre-injection re-snapshot mutation survived it).
    inj = text.find("get_global_tracker().add_prior_usage(")
    assert inj != -1, "injection call present"
    inj_end = text.find("\n", text.find(")", inj))
    resnap = text.find("_phase_baseline = tracking.get_usage()", inj_end)
    assert resnap != -1, (
        "the baseline re-snapshot must FOLLOW the add_prior_usage call "
        "(#281 — without it, resumed Stage 1 lines double-count prior usage)"
    )
    between = text[inj_end:resnap]
    assert "add_prior_usage" not in between, "no second injection between"
    assert between.count("\n") < 12, (
        "re-snapshot should be immediately after the injection, not pages later"
    )
    log_call = text.find('tracking.log_usage("Stage 1", _phase_baseline)', resnap)
    assert log_call != -1, "the Stage 1 log must use the re-snapshotted baseline"


def test_verifier_and_enhancer_holders_wired():
    """Source-placement contract: verify + enhance thread a mutable
    phase_baseline holder into their batch calls, and the injection sites
    refresh it."""
    base = Path(__file__).parent.parent
    vsrc = (base / "core" / "verifier.py").read_text()
    assert '_phase_baseline = {"usage": tracking.get_usage()}' in vsrc
    assert "phase_baseline=_phase_baseline" in vsrc
    assert 'tracking.log_usage("Stage 2", _phase_baseline["usage"])' in vsrc
    esrc = (base / "core" / "enhancer.py").read_text()
    assert '_phase_baseline = {"usage": tracking.get_usage()}' in esrc
    assert "phase_baseline=_phase_baseline" in esrc  # agentic path only
    assert 'tracking.log_usage("Enhance", _phase_baseline["usage"])' in esrc
    fsrc = (base / "utilities" / "finding_verifier.py").read_text()
    assert 'phase_baseline["usage"] = _tracking.get_usage()' in fsrc
    csrc = (base / "utilities" / "context_enhancer.py").read_text()
    assert 'phase_baseline["usage"] = _tracking.get_usage()' in csrc
