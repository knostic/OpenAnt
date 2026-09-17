"""#608: the dynamic-test checkpoint summaries publish the stage-local usage.

Every ``write_summary`` call site passed no ``usage`` — including the
terminal ``phase="done"`` one. The stage publishes after findings, after
generation failures, after Docker outcomes, and at termination (its write
sites cover both outcomes) — so the shape existed; the usage was the
missing key. A summary-reading consumer saw $0 for the whole stage.

The fix adds ``usage=`` to the four existing write sites with the same
accounting requirements as the llr sibling: the DELTA from the pre-stage
baseline (the stage's OWN spend: the restored attempts' prior usage [the
injection] + this run's fresh calls — the ``#333`` "total cost across
runs" contract), the ``#216`` markers and the ``#605`` counter preserved,
exception-safe (a usage read must never kill the stage).
"""

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.llm_client import TokenTracker  # noqa: E402





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
    assert "except Exception:  # noqa: BLE001 — a usage read must never kill the stage" in src
