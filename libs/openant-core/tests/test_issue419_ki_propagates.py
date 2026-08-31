"""#419: an interrupt during verify or dynamic-test propagates — it is not a
completion.

The #417 interrupt-swallow class persists at two more stages (panel enumeration
during #418's review):

- `finding_verifier.py:952` (sequential): the KeyboardInterrupt handler prints
  'progress saved' and FALLS THROUGH — a SIGINT during verify makes the scan
  continue to the next stage with partially-verified results: the live-run shape
  is the #417 one — the scan completes, success envelope, no exit 130.
- `finding_verifier.py:987` (parallel): `executor.shutdown(...)` then a bare
  `return` — same swallow, parallel path.
- `dynamic_tester/__init__.py:343`: `return results` on KI, and the caller then
  writes DYNAMIC_TEST_RESULTS.md from PARTIAL results — an interrupted run
  presented with a completion artifact.

`core/reporter.py:975` already re-raises (clean); #418 (enhance) and #411
(analyze) fix the other stages. The contract: checkpoints hold the progress
(every completed unit is saved as it completes — that is the resume story), and
the KI itself PROPAGATES so the CLI can exit 130 with an interrupted envelope —
never a success one.
"""
import json
import sys
from pathlib import Path

import pytest

_CORE = Path(__file__).resolve().parents[1]
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))

import utilities.dynamic_tester as dt  # noqa: E402
from utilities.finding_verifier import FindingVerifier  # noqa: E402
from utilities.llm import PhaseBinding  # noqa: E402


class _ToolsAdapter:
    name = "anthropic"
    supports_tools = True

    def validate(self, model):
        pass


def _bare_verifier():
    """A FindingVerifier without the heavy init (the batch methods under test
    only touch _log and _verify_one, both set here/monkeypatched)."""
    v = FindingVerifier.__new__(FindingVerifier)
    v._log = lambda *a, **k: None
    return v


_RESULTS = [{"route_key": "a:f1"}, {"route_key": "a:f2"}, {"route_key": "a:f3"}]


def test_sequential_verify_ki_propagates():
    """SIGINT mid-verify must propagate out of the sequential batch — the
    handler at :952 printed 'progress saved' and fell through (the scan then
    completed with partially-verified results and a success envelope)."""
    v = _bare_verifier()
    n = {"i": 0}

    def fake_verify_one(result, code_by_route):
        n["i"] += 1
        if n["i"] == 2:
            raise KeyboardInterrupt
        return (result["route_key"], "ok", 0.01, "w0", {})

    v._verify_one = fake_verify_one
    with pytest.raises(KeyboardInterrupt):
        v._verify_batch_sequential(list(_RESULTS), {}, None)
    # the completed units before the interrupt were processed (their
    # checkpoint saves are the resume story — not a reason to swallow).
    assert n["i"] == 2


def test_parallel_verify_ki_propagates():
    """The parallel path's handler shut the executor down and returned bare —
    same swallow."""
    v = _bare_verifier()

    def fake_verify_one(result, code_by_route):
        if result["route_key"] == "a:f2":
            raise KeyboardInterrupt
        return (result["route_key"], "ok", 0.01, "w0", {})

    v._verify_one = fake_verify_one
    with pytest.raises(KeyboardInterrupt):
        v._verify_batch_parallel(list(_RESULTS), {}, None, workers=2)


def test_dynamic_test_ki_propagates_not_partial_report(tmp_path):
    """The dynamic-test handler `return results` on KI and the caller then
    wrote DYNAMIC_TEST_RESULTS.md from PARTIAL results — an interrupted run
    presented with a completion artifact. The KI must propagate (the
    checkpoints hold the progress; the envelope must say interrupted)."""
    pipeline = tmp_path / "pipeline_output.json"
    pipeline.write_text(json.dumps({
        "repository": {"name": "t", "language": "python"},
        "application_type": "unknown",
        "findings": [{
            "id": "f1", "name": "X", "short_name": "x", "location": "a.py:1",
            "cwe_id": 79, "stage2_verdict": "confirmed",
            "vulnerable_code": "eval(x)", "attack_vector": "a",
            "steps_to_reproduce": "s", "impact": "i", "suggested_fix": "f",
        }],
    }))

    class _FakeRegistry:
        def get(self, phase):
            return PhaseBinding(phase=phase, adapter=_ToolsAdapter(),
                                model="m", provider_name="anthropic")

    def gen_interrupts(*a, **k):
        raise KeyboardInterrupt

    orig = dt.generate_test
    dt.generate_test = gen_interrupts
    try:
        with pytest.raises(KeyboardInterrupt):
            dt.run_dynamic_tests(
                pipeline_output_path=str(pipeline),
                output_dir=str(tmp_path / "out"),
                checkpoint_path=str(tmp_path / "cp"),
                registry=_FakeRegistry(),
            )
    finally:
        dt.generate_test = orig
    # No partial-results completion artifact from an interrupted run.
    assert not (tmp_path / "out" / "DYNAMIC_TEST_RESULTS.md").exists(), (
        "an interrupted dynamic-test run must not write the completion report "
        "from partial results"
    )
