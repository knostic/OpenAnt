"""Efficacy (end-to-end A/B): a parse-failure ERROR is re-attempted by the
detection retry pass and recovers the unit's true verdict.

Driven with a stubbed LLM (no paid call) through the REAL detection primitives
(core.analyzer._run_detection and _process_unit) and the REAL retry filter
(utilities.rate_limiter.is_retryable_error). The retry pass is reproduced
verbatim from core.analyzer.run_analysis (the retryable_indices comprehension +
_process_unit re-run at run_analysis lines ~532-550); only run_analysis's
checkpoint/registry/dataset-file scaffolding is omitted, none of which the fix
touches.

A/B: the load-bearing line is `retryable_indices == [0]`. On the pristine tree
the parse ERROR carries error=None, so that list is [] and the unit is never
retried (bug). With the fix it is [0], _process_unit re-runs, and the true
verdict VULNERABLE is recovered instead of being permanently masked as ERROR.
"""
import core.analysis_core as ac
import utilities.json_corrector as jc
from core.analyzer import _run_detection, _process_unit
from utilities.rate_limiter import is_retryable_error


def test_parse_failure_recovered_by_retry(monkeypatch):
    calls = {"n": 0}

    def fake_simple_text(binding, prompt, **kwargs):
        calls["n"] += 1
        # Attempt 1: the analyze call AND the JSONCorrector call both return
        # unparseable prose -> permanent ERROR at the parser boundary.
        if calls["n"] <= 2:
            return "Sorry — here is prose analysis with no JSON object at all."
        # Retry attempt: the model now returns well-formed JSON.
        return '{"finding": "vulnerable", "confidence": 90}'

    # Both modules import simple_text into their own namespace.
    monkeypatch.setattr(ac, "simple_text", fake_simple_text)
    monkeypatch.setattr(jc, "simple_text", fake_simple_text)

    units = [{"id": "u1", "code": "def handler(req):\n    return eval(req.body)"}]
    binding = object()  # only stored / passed to the stubbed simple_text

    # --- Stage 1 detection (real) ---
    results, _code_by_route = _run_detection(units, binding, None, None, workers=1)
    assert results[0]["verdict"] == "ERROR"  # first attempt could not be parsed

    # --- Retry pass, reproduced from core.analyzer.run_analysis:~532-550 ---
    retryable_indices = [
        i for i, r in enumerate(results)
        if r and is_retryable_error(r.get("error"))
    ]
    # RED on pristine (error=None -> not retryable -> []); GREEN with the fix.
    assert retryable_indices == [0]
    for i in retryable_indices:
        out = _process_unit(binding, units[i], i, None, None)
        results[i] = out["result"]

    # The malformed first response was retried and the true verdict recovered,
    # instead of being permanently masked as ERROR.
    assert results[0]["verdict"] == "VULNERABLE"
    assert calls["n"] >= 3, "retry pass did not re-attempt the parse failure"
