"""Efficacy (end-to-end A/B): a transient empty-completion ERROR is re-attempted
by the detection retry pass and recovers the unit's true verdict.

Driven with a stubbed LLM (no paid call) through the REAL detection primitives
(_run_detection + _process_unit) and the REAL retry filter (is_retryable_error).
The retry pass is reproduced from core.analyzer.run_analysis (the
retryable_indices comprehension + _process_unit re-run). The load-bearing line is
`retryable_indices == [0]`: pre-fix the empty-completion error string is not
classified retryable, so the unit is never re-attempted (bug); with the fix it
is, so the true verdict is recovered.
"""
import core.analysis_core as ac
import utilities.json_corrector as jc
from core.analyzer import _run_detection, _process_unit
from utilities.rate_limiter import is_retryable_error
from utilities.llm.adapter import LLMResponseError


def test_empty_completion_recovered_by_retry(monkeypatch):
    calls = {"n": 0}

    def fake_simple_text(binding, prompt, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            # Adapter behaviour on a transient empty completion: it RAISES.
            raise LLMResponseError(
                "AnthropicAdapter returned no usable content (empty completion); "
                "the request may have been filtered or the response was malformed")
        return '{"finding": "vulnerable", "confidence": 90}'

    monkeypatch.setattr(ac, "simple_text", fake_simple_text)
    monkeypatch.setattr(jc, "simple_text", fake_simple_text)

    units = [{"id": "u1", "code": "def h(r):\n    return eval(r.body)"}]
    binding = object()

    results, _ = _run_detection(units, binding, None, None, workers=1)
    assert results[0]["verdict"] == "ERROR"  # first attempt raised -> ERROR

    retryable_indices = [
        i for i, r in enumerate(results)
        if r and is_retryable_error(r.get("error"))
    ]
    # RED on base (empty-completion string not retryable -> []); GREEN with fix.
    assert retryable_indices == [0]
    for i in retryable_indices:
        out = _process_unit(binding, units[i], i, None, None)
        results[i] = out["result"]

    assert results[0]["verdict"] == "VULNERABLE"
    assert calls["n"] >= 2, "retry pass did not re-attempt the empty completion"
