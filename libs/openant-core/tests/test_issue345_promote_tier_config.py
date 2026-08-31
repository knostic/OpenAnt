"""#345: the entry-point promote set is configurable, and the comment stops lying.

llm-reachability promotes an ``entry_point`` signal to ``is_entry_point = True`` only
when its confidence is in ``_PROMOTE_ENTRY_POINT_AT`` — a deliberate, PR-#50-calibrated
set (the issue is explicit: not a bug). Two defects in the ask's path:

1. the threshold is a module CONSTANT — an operator cannot trade recall for cost per
   run (promote-only bounds the downside: a wrong promotion costs analysis budget on a
   unit that would otherwise be skipped; a missing one silently removes a unit and
   everything reachable only through it — the safe direction for a security scanner is
   more seeding);
2. the comment read "Confidences at or above this threshold promote..." while the code
   is a SET-MEMBERSHIP test — no ordering over high/medium/low exists anywhere in the
   module. It works today because the set has one element; the comment describes
   semantics the code does not implement, a trap for whoever configures it next.

The DEFAULT stays ``{"high"``: the medium-precision audit (48.0%, n=25, 95% CI [30,67])
that would justify widening is from an internal run the issue itself flags as
non-reproducible, and the locked test (test_medium_confidence_does_not_promote)
encodes that choice — changing it needs the second-corpus reproduction the issue
names. ``low`` stays out of the default (0.0% is unambiguous) but is not banned: an
explicit operator choice is logged nowhere as safe, it is the operator's call.

Configurability: OPENANT_PROMOTE_ENTRY_POINT_AT — a comma-separated subset of
high/medium/low, read at apply time (env, not a module constant, so per-run). Invalid
or empty content falls back to the shipped default WITH a stderr warning — a
calibration knob must never crash the scan.
"""
import sys
from pathlib import Path

_CORE = Path(__file__).resolve().parents[1]
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))

from core.llm_reachability import (  # noqa: E402
    ReachabilitySignal,
    apply_signals,
)


def _one_unit_dataset(conf, unit_id="app.py:handler"):
    return {"units": [{"id": unit_id, "is_entry_point": False}]}


def _ep_signal(conf, unit_id="app.py:handler"):
    return [ReachabilitySignal(unit_id, "entry_point", conf, "reads argv and dispatches")]


def test_default_set_is_high_only(monkeypatch):
    """The shipped default: high promotes, medium and low do not (the PR #50
    calibration, pinned through the configurable path)."""
    monkeypatch.delenv("OPENANT_PROMOTE_ENTRY_POINT_AT", raising=False)
    for conf, want in (("high", True), ("medium", False), ("low", False)):
        ds = _one_unit_dataset(conf)
        apply_signals(ds, _ep_signal(conf))
        assert ds["units"][0]["is_entry_point"] is want, conf


def test_operator_widening_to_medium(monkeypatch, capsys):
    """OPENANT_PROMOTE_ENTRY_POINT_AT=high,medium: medium promotes (the
    issue's suggested trade-off made the operator's to make), low still not."""
    monkeypatch.setenv("OPENANT_PROMOTE_ENTRY_POINT_AT", "high,medium")
    ds = _one_unit_dataset("medium")
    apply_signals(ds, _ep_signal("medium"))
    assert ds["units"][0]["is_entry_point"] is True
    ds = _one_unit_dataset("low")
    apply_signals(ds, _ep_signal("low"))
    assert ds["units"][0]["is_entry_point"] is False


def test_explicit_low_is_the_operators_call(monkeypatch):
    """low is not banned — an explicit tier choice is honored (the audit's 0.0%
    is the shipped default's justification, not a hard exclusion)."""
    monkeypatch.setenv("OPENANT_PROMOTE_ENTRY_POINT_AT", "medium, low")
    ds = _one_unit_dataset("low")
    apply_signals(ds, _ep_signal("low"))
    assert ds["units"][0]["is_entry_point"] is True


def test_invalid_value_falls_back_loudly(monkeypatch, capsys):
    """A bad tier list warns on stderr and falls back to the default —
    never crashes the scan, never silently widens."""
    monkeypatch.setenv("OPENANT_PROMOTE_ENTRY_POINT_AT", "hot,high")
    ds = _one_unit_dataset("medium")
    apply_signals(ds, _ep_signal("medium"))
    assert ds["units"][0]["is_entry_point"] is False, (
        "an invalid list must fall back to the {high} default"
    )
    err = capsys.readouterr().err
    assert "OPENANT_PROMOTE_ENTRY_POINT_AT" in err and "falling back" in err


def test_empty_content_falls_back(monkeypatch):
    """Whitespace-only content is not a tier list: default, warned."""
    monkeypatch.setenv("OPENANT_PROMOTE_ENTRY_POINT_AT", " , ")
    ds = _one_unit_dataset("medium")
    apply_signals(ds, _ep_signal("medium"))
    assert ds["units"][0]["is_entry_point"] is False


def test_unset_env_is_silent(monkeypatch, capsys):
    """No env, no warning — the default is not an error condition."""
    monkeypatch.delenv("OPENANT_PROMOTE_ENTRY_POINT_AT", raising=False)
    apply_signals(_one_unit_dataset("high"), _ep_signal("high"))
    assert "OPENANT_PROMOTE_ENTRY_POINT_AT" not in capsys.readouterr().err
