"""Offline unit tests for the efficacy smoke-test scorer's PURE functions.

The scorer's silent-failure modes were the reason it could report a confident
recall number that meant nothing: a missing results file scored as 0.0, an
unrecognised id scored as a false negative. These tests pin the corrected
behaviour — each of those is now a raised SmokeError — WITHOUT a provider, so
they run in the normal free suite. The scan-running half (run_scan/main) is not
exercised here; it costs money and is a canary, not a merge gate.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SCORE = Path(__file__).resolve().parent.parent / "tests" / "efficacy" / "score.py"


def _load():
    spec = importlib.util.spec_from_file_location("efficacy_score", _SCORE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


score = _load()


ORACLE = {
    "units": {
        "src/app_a.py:render_snippet": {"vulnerable": True},
        "src/app_a.py:migrate": {"vulnerable": False},
        "src/app_a.py:download": {"vulnerable": True},
        "src/app_b.py:rotate_logs": {"vulnerable": False},
        "src/app_b.py:get_paste": {"vulnerable": True},
        "src/app_b.py:build_cache_key": {"vulnerable": False},
    }
}
VULN = ["src/app_a.py:render_snippet", "src/app_a.py:download", "src/app_b.py:get_paste"]
CLEAN = ["src/app_a.py:migrate", "src/app_b.py:rotate_logs", "src/app_b.py:build_cache_key"]


def _results(flagged_vuln, flagged_field="finding"):
    """Build a results list where every oracle unit is analysed."""
    out = []
    for uid in VULN + CLEAN:
        out.append({"unit_id": uid, flagged_field: "vulnerable" if uid in flagged_vuln else "safe"})
    return out


# --- unit_key ---

def test_unit_key_strips_language_namespace():
    assert score.unit_key("go::src/a.go:f") == "src/a.go:f"
    assert score.unit_key("src/a.py:f") == "src/a.py:f"


# --- read_results: missing file is an ERROR, not zero ---

def test_read_results_missing_file_raises(tmp_path: Path):
    with pytest.raises(score.SmokeError, match="missing"):
        score.read_results(tmp_path / "nope.json")


def test_read_results_no_results_list_raises(tmp_path: Path):
    p = tmp_path / "results.json"
    p.write_text('{"not_results": []}')
    with pytest.raises(score.SmokeError, match="no 'results' list"):
        score.read_results(p)


# --- index_results: value not truthiness; duplicate id is an error ---

def test_index_flags_by_value_not_truthiness():
    # "safe" is a truthy string; a truthiness check would flag every clean unit.
    flagged, all_ids = score.index_results(_results(VULN), "finding", {"VULNERABLE"})
    assert flagged == set(VULN)
    assert all_ids == set(VULN + CLEAN)


def test_index_duplicate_id_raises():
    dup = _results([]) + [{"unit_id": "src/app_a.py:migrate", "finding": "safe"}]
    with pytest.raises(score.SmokeError, match="duplicate"):
        score.index_results(dup, "finding", {"VULNERABLE"})


# --- evaluate: pass/fail + the two unjudgeable errors ---

def test_evaluate_passes_when_vulns_flagged_and_traps_cleared():
    flagged, all_ids = score.index_results(_results(VULN), "finding", {"VULNERABLE"})
    r = score.evaluate(ORACLE, flagged, all_ids, "stage1")
    assert r["passed"] is True
    assert r["missed_vulns"] == [] and r["false_alarms"] == []


def test_evaluate_fails_on_missed_vuln():
    flagged, all_ids = score.index_results(_results(VULN[:2]), "finding", {"VULNERABLE"})
    r = score.evaluate(ORACLE, flagged, all_ids, "stage1")
    assert r["passed"] is False
    assert r["missed_vulns"] == ["src/app_b.py:get_paste"]


def test_evaluate_fails_on_false_alarm():
    flagged, all_ids = score.index_results(
        _results(VULN + ["src/app_a.py:migrate"]), "finding", {"VULNERABLE"})
    r = score.evaluate(ORACLE, flagged, all_ids, "stage1")
    assert r["passed"] is False
    assert r["false_alarms"] == ["src/app_a.py:migrate"]


def test_evaluate_missing_expected_id_raises_not_scored_as_miss():
    # Only 5 of the 6 units analysed — the 6th is ABSENT, not a false negative.
    partial = [e for e in _results(VULN) if e["unit_id"] != "src/app_b.py:get_paste"]
    flagged, all_ids = score.index_results(partial, "finding", {"VULNERABLE"})
    with pytest.raises(score.SmokeError, match="absent from the results"):
        score.evaluate(ORACLE, flagged, all_ids, "stage1")


def test_evaluate_unknown_flagged_id_raises():
    extra = _results(VULN) + [{"unit_id": "src/app_a.py:__module__", "finding": "vulnerable"}]
    flagged, all_ids = score.index_results(extra, "finding", {"VULNERABLE"})
    with pytest.raises(score.SmokeError, match="oracle does not cover"):
        score.evaluate(ORACLE, flagged, all_ids, "stage1")


def test_evaluate_ignores_extra_unflagged_units():
    # A __module__ unit that is NOT flagged must not error (it is simply extra).
    extra = _results(VULN) + [{"unit_id": "src/app_a.py:__module__", "finding": "safe"}]
    flagged, all_ids = score.index_results(extra, "finding", {"VULNERABLE"})
    r = score.evaluate(ORACLE, flagged, all_ids, "stage1")
    assert r["passed"] is True


# --- verification_effect: the harmful-suppression detector ---

def test_verification_effect_flags_harmful_suppression():
    s1 = set(VULN)
    s2 = set(VULN[:2])  # Stage 2 dropped a TRUE positive
    eff = score.verification_effect(s1, s2, ORACLE)
    assert eff["verdict"].startswith("HARMFUL")
    assert eff["true_positives_suppressed"] == ["src/app_b.py:get_paste"]


def test_verification_effect_improves_precision():
    s1 = set(VULN) | {"src/app_a.py:migrate"}  # Stage 1 over-flagged a trap
    s2 = set(VULN)                              # Stage 2 removed only the FP
    eff = score.verification_effect(s1, s2, ORACLE)
    assert eff["verdict"] == "improves precision"
    assert eff["false_positives_removed"] == ["src/app_a.py:migrate"]
