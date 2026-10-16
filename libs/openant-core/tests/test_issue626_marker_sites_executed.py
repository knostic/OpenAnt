"""#626/PR#661 — the incompleteness markers' EXECUTED site coverage.

Two things live here, both named by the pass-1 review round.

**V1 (astra, MED — F4 PARTIAL).** ``finding_verifier.verify_batch``'s
``_summary_callback`` folded three numeric keys out of each unit's usage
(:883-886) and NEITHER unpriced ID set, while ``_usage_dict`` (:839-848)
read only the restore-loop accumulators. ``verify/_summary.json`` therefore
reported a COMPLETE cost after a FRESH run's unpriced spend — both kinds:
the #216 pricing-absent kind (pre-existing since #216; master has the
identical shape) and the #626 cache kind (the F4 half that #661 was
supposed to close). A resumed run kept the restored ids and silently lost
the fresh ones.

**R1-1 (fable, Significant — a verification gap, not a shipped defect).**
``test_issue626_cache_accounting.py``'s seven-module census asserts
``"unpriced_cache_models" in inspect.getsource(mod)`` — a source-text pin
that every one of those modules now satisfies from a COMMENT. fable's four
isolating mutants (all five ``context_enhancer`` cache folds removed; the
``llm_reachability`` adoption read removed; the ``analyzer`` fresh-run
tracker union removed; the ``agent.py`` error path reverted to one kind)
each SURVIVED the whole plausible test population. The tests below drive
each of those sites for real, so a one-line revert at any of them fails a
test instead of passing a grep.

Every test here drives PRODUCTION entry points (``verify_batch``,
``enhance_dataset_agentic``, ``analyze_reachability``, ``run_analysis``,
``ContextAgent.analyze_unit``) with the repo's established stub patterns —
no monkeypatching of the function under test.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.llm_client import (  # noqa: E402
    TokenTracker,
    reset_global_tracker,
    reset_warning_state,
)

# A model whose INPUT/OUTPUT rates are known but whose CACHE multipliers are
# absent: cache usage on it is the #626 kind (priced model, unpriced cache) —
# never the #216 kind, so the two are distinguishable in every assertion.
_PRICED_NO_CACHE_RATES = {"input": 3.0, "output": 15.0}
_CACHE_DETAILS = {"cache_read_input_tokens": 5_000}


def _read_summary(checkpoint_dir) -> dict:
    return json.loads((Path(checkpoint_dir) / "_summary.json").read_text())


# ===========================================================================
# V1 — verify's FRESH-run summary (finding_verifier.py:883-886)
# ===========================================================================
def _verify_binding():
    from utilities.llm import PhaseBinding

    class _Adapter:
        name = "anthropic"
        supports_tools = True
        pricing = {}

    return PhaseBinding(phase="verify", adapter=_Adapter(), model="m",
                        provider_name="anthropic")


def _drive_verify(tmp_path, seed_checkpoint=None, pricing=_PRICED_NO_CACHE_RATES,
                  usage_details=_CACHE_DETAILS):
    """Drive the REAL verify_batch over one finding whose verification makes
    one real ``record_call``. Returns (summary_dict, tracker)."""
    from core.checkpoint import StepCheckpoint
    from utilities.agentic_enhancer.repository_index import RepositoryIndex
    from utilities.finding_verifier import FindingVerifier, VerificationResult

    class _Scripted(FindingVerifier):
        def verify_result(self, code, finding, attack_vector, reasoning,
                          files_included=None):
            self.tracker.record_call(
                model="new-model", input_tokens=10_000, output_tokens=1_000,
                pricing=pricing, usage_details=usage_details)
            return VerificationResult(agree=True, correct_finding=finding,
                                      explanation="ok", iterations=1,
                                      total_tokens=11_000)

    cp_dir = tmp_path / "verify_checkpoints"
    cp_dir.mkdir()
    if seed_checkpoint is not None:
        (cp_dir / "old.json").write_text(json.dumps(seed_checkpoint))
    cp = StepCheckpoint("Verify", str(tmp_path))
    cp.dir = str(cp_dir)

    tracker = TokenTracker()
    verifier = _Scripted(index=RepositoryIndex({}, repo_path=None),
                         binding=_verify_binding(), tracker=tracker)
    results = [{"route_key": "r1", "finding": "vulnerable",
                "attack_vector": "a", "reasoning": "r"}]
    verifier.verify_batch(results, {"r1": "code"}, workers=1, checkpoint=cp)
    return _read_summary(cp_dir), tracker


def test_verify_fresh_run_summary_carries_the_cache_kind(tmp_path):
    """V1: a FIRST verify run whose only incompleteness is cache-unpriced
    spend must not write a complete-looking verify/_summary.json.

    RED at ea39f7fe: usage == {input_tokens, output_tokens, cost_usd} —
    no cost_incomplete, no unpriced_cache_models — while the tracker's
    own totals name the model."""
    reset_warning_state()
    try:
        summary, tracker = _drive_verify(tmp_path)
    finally:
        reset_warning_state()

    # precondition (non-vacuous): the tracker DID see the cache kind, so a
    # missing marker below is the summary's drop, not a fixture that
    # recorded nothing.
    assert tracker.get_totals()["unpriced_cache_models"] == ["new-model"]

    usage = summary["usage"]
    assert usage["input_tokens"] == 10_000
    assert usage["cost_incomplete"] is True, (
        "verify/_summary.json reported a COMPLETE cost after cache-unpriced "
        "spend — _summary_callback folded the numbers and dropped the "
        "markers (finding_verifier.py:883-886)")
    assert usage["unpriced_cache_models"] == ["new-model"]
    # the #626 kind only: the model's input/output rates were present
    assert "unpriced_models" not in usage


def test_verify_fresh_run_summary_carries_the_pricing_absent_kind(tmp_path):
    """V1, the #216 twin: the SAME drop loses the pricing-absent kind on a
    fresh run (pre-existing since #216 — master's _summary_callback has the
    identical three-key shape). One helper call fixes both kinds."""
    reset_warning_state()
    try:
        summary, tracker = _drive_verify(tmp_path, pricing=None,
                                         usage_details=None)
    finally:
        reset_warning_state()

    assert tracker.get_totals()["unpriced_models"] == ["new-model"]
    usage = summary["usage"]
    assert usage["cost_incomplete"] is True
    assert usage["unpriced_models"] == ["new-model"]
    assert "unpriced_cache_models" not in usage


def test_verify_resumed_summary_keeps_restored_and_adds_fresh(tmp_path):
    """V1, astra's exact shape: a RESUMED verify run must carry BOTH the
    restored ids (the checkpoint's) and this run's fresh ones. RED at
    ea39f7fe: the restored 'm' survives, the fresh 'new-model' vanishes —
    the summary looks authoritative while naming the wrong model set."""
    reset_warning_state()
    seed = {
        "id": "old", "route_key": "old", "finding": "safe",
        "verification": {"agree": True, "correct_finding": "safe"},
        "usage": {"input_tokens": 1, "output_tokens": 1, "cost_usd": 0.001,
                  "cost_incomplete": True, "unpriced_models": ["m"]},
    }
    try:
        summary, _tracker = _drive_verify(tmp_path, seed_checkpoint=seed)
    finally:
        reset_warning_state()

    usage = summary["usage"]
    assert usage["cost_incomplete"] is True
    assert usage["unpriced_models"] == ["m"], "the RESTORED id must survive"
    assert usage["unpriced_cache_models"] == ["new-model"], (
        "the FRESH unit's cache kind was dropped — the restore path folds "
        "both kinds, the per-unit path folded neither")
    # the numbers still reconcile (restored + fresh), unchanged by the fix
    assert usage["input_tokens"] == 10_001


# ===========================================================================
# R1-1 site D — agent.py:378, the error path's agent_state
# (fable's mutant D: `attempt_kinds = unit_unpriced_kinds(self.tracker)`
#  reverted to the old single-kind read. SURVIVED 1677 passing tests.)
# ===========================================================================
class _ScriptedAdapter:
    """One scripted turn, then a raise (the #609 harness shape)."""

    name = "fake"
    supports_tools = True

    def __init__(self, pricing, responses, failure):
        self._pricing = pricing
        self._responses = list(responses)
        self._failure = failure
        self.turn = 0

    @property
    def pricing(self):
        return self._pricing

    def complete(self, *, model, max_tokens, system, tools, messages):
        self.turn += 1
        if self.turn <= len(self._responses):
            return self._responses[self.turn - 1]
        raise self._failure


def _cache_tool_turn():
    from utilities.llm.adapter import CompletionResult, ToolUseBlock

    return CompletionResult(
        content=(ToolUseBlock(id="t1", name="get_static_dependencies", input={}),),
        input_tokens=100, output_tokens=10, stop_reason="tool_use",
        usage_details=dict(_CACHE_DETAILS))


def test_agent_error_state_carries_the_cache_kind():
    """R1-1/D: a failed agent attempt whose billed turn used UNPRICED CACHE
    must name the cache kind on ``agent_state`` — that dict is the ONLY
    carrier of a failed attempt's spend (``agent_metadata`` is absent on
    error), so a kind dropped here is dropped from the enhance summary,
    the per-unit checkpoint and the resume at once.

    RED when agent.py:378 reverts to a single-kind read."""
    from utilities.agentic_enhancer.agent import ContextAgent
    from utilities.agentic_enhancer.repository_index import RepositoryIndex
    from utilities.llm.adapter import LLMConnectionError
    from utilities.llm.registry import PhaseBinding

    reset_warning_state()
    adapter = _ScriptedAdapter({"fake-model": dict(_PRICED_NO_CACHE_RATES)},
                               [_cache_tool_turn()],
                               LLMConnectionError("transport died"))
    tracker = TokenTracker()
    agent = ContextAgent(
        index=RepositoryIndex({}, repo_path=None),
        binding=PhaseBinding(phase="enhance", adapter=adapter,
                             model="fake-model", provider_name="fake"),
        tracker=tracker)
    try:
        with pytest.raises(LLMConnectionError) as excinfo:
            agent.analyze_unit(unit_id="a.py:f", unit_type="function",
                               primary_code="def f(): ...",
                               static_deps=[], static_callers=[])
        state = excinfo.value.agent_state
    finally:
        reset_warning_state()

    # non-vacuous precondition: the attempt WAS billed and the tracker DID
    # see the cache kind
    assert state["input_tokens"] == 100
    assert tracker.get_totals()["unpriced_cache_models"] == ["fake-model"]

    assert state["cost_incomplete"] is True
    assert state["unpriced_cache_models"] == ["fake-model"], (
        "agent.py's error path dropped the #626 cache kind from "
        "agent_state — the only carrier of a failed attempt's spend")
    # the #216 kind is absent (the model's input/output rates were present):
    # the two kinds must not be merged into one list
    assert "unpriced_models" not in state


# ===========================================================================
# R1-1 site C — analyzer.py:858-861, the FRESH-run tracker union in _usage_dict
# (fable's mutant C: drop the cache kind from the tracker union.
#  SURVIVED 362 passing tests across the 17 cost_incomplete files.)
# ===========================================================================
def test_analyze_fresh_run_summary_unions_the_tracker_cache_kind(tmp_path,
                                                                 monkeypatch):
    """R1-1/C: analyze's ``_usage_dict`` consults the GLOBAL tracker, not
    just the resume seed — that is what makes a FIRST analyze run whose only
    incompleteness is cache-unpriced spend write a truthful
    analyze_checkpoints/_summary.json.

    RED when analyzer.py:860-861 drops the cache kind from that union."""
    from core import analyzer
    from utilities.llm import PhaseBinding
    from utilities.llm_client import get_global_tracker

    reset_global_tracker()
    reset_warning_state()

    dataset_path = tmp_path / "dataset.json"
    dataset_path.write_text(json.dumps({"units": [{"id": "a:f", "code": "x=1"}]}))
    output_dir = tmp_path / "out"

    def fake_run_detection(units, binding, json_corrector, app_context,
                           workers, checkpoint=None, summary_callback=None):
        # the real spend this run made: one cache-unpriced call on the
        # GLOBAL tracker (the one analyze's _usage_dict reads)
        get_global_tracker().record_call(
            model="new-model", input_tokens=10_000, output_tokens=1_000,
            pricing=dict(_PRICED_NO_CACHE_RATES),
            usage_details=dict(_CACHE_DETAILS))
        if summary_callback:
            summary_callback("safe", usage={"input_tokens": 10_000,
                                            "output_tokens": 1_000,
                                            "cost_usd": 0.045})
        return ([{"unit_id": "a:f", "finding": "safe", "verdict": "SAFE",
                  "confidence": 90, "vulnerabilities": [], "reasoning": "r"}],
                {u["id"]: "" for u in units})

    class _Adapter:
        name = "anthropic"
        supports_tools = True
        pricing = {}

    class _FakeRegistry:
        def get(self, phase):
            return PhaseBinding(phase=phase, adapter=_Adapter(), model="m",
                                provider_name="anthropic")

    monkeypatch.setattr(analyzer, "_run_detection", fake_run_detection)
    monkeypatch.setattr(analyzer, "_analyze_fingerprint",
                        lambda binding, ctx_sha=None: {"key_digest": "sha256:test"})
    try:
        analyzer.run_analysis(str(dataset_path), str(output_dir),
                              registry=_FakeRegistry(), workers=1)
        # non-vacuous precondition: the run's own tracker saw the cache kind
        assert get_global_tracker().get_totals()["unpriced_cache_models"] == [
            "new-model"]
        summary = _read_summary(output_dir / "analyze_checkpoints")
    finally:
        reset_global_tracker()
        reset_warning_state()

    usage = summary["usage"]
    assert usage["input_tokens"] == 10_000
    assert usage["cost_incomplete"] is True, (
        "analyze/_summary.json reported a COMPLETE cost on a FRESH run whose "
        "spend was cache-unpriced — _usage_dict's tracker union is the only "
        "thing that catches the non-resumed case")
    assert usage["unpriced_cache_models"] == ["new-model"]


# ===========================================================================
# R1-1 site B — llm_reachability.py:678-684, the ADOPTION read
# (fable's mutant B: `unpriced_cache.update(_c)` -> pass. SURVIVED 406
#  passing tests; the #532 FakeTracker records **kw but nothing asserted it.)
# ===========================================================================
class _LLRFakeTracker:
    """The four tracker surfaces llm_reachability touches. ``add_prior_usage``
    takes **kw on purpose: the stage wraps the call in ``except Exception:
    pass``, so a stub that rejects a keyword makes the stage look like it
    injected nothing instead of failing loudly."""

    def __init__(self):
        self.prior_calls: list[dict] = []
        self._current = {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}

    def record_call(self, *, model=None, input_tokens=0, output_tokens=0,
                    pricing=None, usage_details=None):
        self._current["input_tokens"] += input_tokens or 0
        self._current["output_tokens"] += output_tokens or 0
        self._current["cost_usd"] += 0.01

    def start_unit_tracking(self):
        self._current = {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}

    def get_unit_usage(self):
        return dict(self._current)

    def add_prior_usage(self, input_tokens, output_tokens, cost_usd, **kw):
        self.prior_calls.append({"input_tokens": input_tokens,
                                 "output_tokens": output_tokens,
                                 "cost_usd": cost_usd, **kw})


class _LLRFakeAdapter:
    name = "anthropic"
    supports_tools = True

    def __init__(self, responses=None):
        self._responses = list(responses or [])

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        from utilities.llm import CompletionResult, TextBlock

        text = self._responses.pop(0) if self._responses else '{"signals": []}'
        return CompletionResult(content=[TextBlock(text)], input_tokens=10,
                                output_tokens=10, stop_reason="end_turn")

    def validate(self, model):
        pass


def test_llr_adoption_injects_the_cache_kind_as_prior_usage(tmp_path):
    """R1-1/B: ``_share`` has persisted ``unpriced_cache_models`` into the
    per-unit records since F661-2, but the ADOPTION side — the only reader —
    ignored it: write-only persistence. A resumed LLR pass therefore read a
    complete cost after cache-unpriced spend.

    Run 1 writes the records; run 2 adopts them and must hand BOTH kinds to
    ``add_prior_usage``. RED when llm_reachability.py:684 drops the cache
    fold."""
    from core.llm_reachability import analyze_reachability
    from utilities.llm import PhaseBinding

    def _binding(adapter):
        return PhaseBinding(phase="llm_reach", adapter=adapter,
                            model="claude-test", provider_name="anthropic")

    cp = str(tmp_path / "llm_reach_checkpoints")
    dataset = {"units": [{"id": "a:f1", "unit_type": "function",
                          "code": {"primary_code": "pass"}}]}
    canned = json.dumps({"signals": [{"unit_id": "a:f1", "kind": "entry_point",
                                      "confidence": "high",
                                      "reason": "reads argv"}]})

    # --- run 1: a tracker whose unit usage reports BOTH unpriced kinds, so
    # _share persists them onto the per-unit record.
    class _MarkingTracker(_LLRFakeTracker):
        def get_unit_usage(self):
            u = dict(self._current)
            u["cost_incomplete"] = True
            u["unpriced_models"] = ["mystery-model"]
            u["unpriced_cache_models"] = ["new-model"]
            return u

    analyze_reachability(dataset, binding=_binding(_LLRFakeAdapter([canned])),
                         checkpoint_path=cp, tracker=_MarkingTracker())

    # non-vacuous precondition: the record on disk really carries the kind
    record = json.loads((Path(cp) / "a_f1.json").read_text())
    assert record["usage"]["unpriced_cache_models"] == ["new-model"], (
        "fixture broke: _share did not persist the cache kind, so the "
        "adoption assertion below would be vacuous")

    # --- run 2: adopt (no new calls) and inject
    tracker = _LLRFakeTracker()
    analyze_reachability(dataset, binding=_binding(_LLRFakeAdapter()),
                         checkpoint_path=cp, tracker=tracker)

    assert tracker.prior_calls, "adopted records must inject prior usage"
    call = tracker.prior_calls[0]
    assert call["unpriced_models"] == ["mystery-model"]
    assert call["unpriced_cache_models"] == ["new-model"], (
        "the LLR adoption read dropped the #626 cache kind — _share writes "
        "it, nothing read it back (write-only persistence)")


# ===========================================================================
# R1-1 site A — context_enhancer.py, the FIVE cache folds
# (fable's mutant A: all five `_summary_unpriced_cache.update(...)` folds at
#  :782, :928, :942, :1089, :1101 -> pass. SURVIVED the 28-file enhancer
#  population with a FAILED list identical to the clean control.)
#
# The enhance phase has five independent spend sources and the kind had to
# be taught to all five; the tests below drive EACH one, so a single-fold
# revert fails too, not only the all-five mutant.
# ===========================================================================
def _enhance_harness_binding():
    from utilities.llm.registry import PhaseBinding

    class _Adapter:
        name = "fake"
        supports_tools = True
        pricing = {"fake-model": dict(_PRICED_NO_CACHE_RATES)}

    return PhaseBinding(phase="enhance", adapter=_Adapter(),
                        model="fake-model", provider_name="fake")


def _drive_enhance(dataset, checkpoint_dir, enhance, workers=1, tracker=None):
    """Drive the REAL ``enhance_dataset_agentic`` with a stubbed unit
    enhancer. The real ``enhance_unit_with_agent`` is captured BEFORE the
    patch and restored in ``finally`` (the #609 capture-then-patch
    discipline — a self-referential patch has passed vacuously before)."""
    import utilities.context_enhancer as ce

    real = ce.enhance_unit_with_agent
    ce.enhance_unit_with_agent = enhance
    try:
        enhancer = ce.ContextEnhancer(binding=_enhance_harness_binding(),
                                      tracker=tracker)
        analyzer_out = Path(checkpoint_dir).parent / "a.json"
        analyzer_out.write_text(json.dumps({"results": []}))
        enhancer.enhance_dataset_agentic(
            dataset, analyzer_output_path=str(analyzer_out), repo_path=None,
            workers=workers, checkpoint_path=str(checkpoint_dir))
    finally:
        ce.enhance_unit_with_agent = real
    return _read_summary(checkpoint_dir)


def _unit(uid="u1"):
    return {"id": uid, "code": {"primary_code": "x=1"}}


def test_enhance_metadata_cache_kind_reaches_summary(tmp_path):
    """R1-1/A fold 3 (context_enhancer.py:942) — the SUCCESS path: a unit's
    ``agent_metadata`` carries the cache kind and ``_update_summary`` must
    fold it into enhance/_summary.json."""
    reset_warning_state()

    def fake(unit, index, binding, tracker, verbose):
        unit["agent_context"] = {
            "security_classification": "safe",
            "agent_metadata": {"input_tokens": 100, "output_tokens": 10,
                               "cost_usd": 0.03, "cost_incomplete": True,
                               "unpriced_cache_models": ["new-model"]},
        }

    cp_dir = tmp_path / "cp"
    try:
        s = _drive_enhance({"units": [_unit()]}, cp_dir, fake)
    finally:
        reset_warning_state()

    assert s["usage"]["input_tokens"] == 100       # non-vacuous
    assert s["usage"]["cost_incomplete"] is True
    assert s["usage"]["unpriced_cache_models"] == ["new-model"], (
        "the agent_metadata fold dropped the #626 cache kind "
        "(context_enhancer.py:942)")


def test_enhance_error_state_cache_kind_reaches_summary(tmp_path):
    """R1-1/A fold 2 (context_enhancer.py:928) — the ERROR path: the failed
    attempt's spend lives ONLY on ``error.agent_state`` (agent_metadata is
    absent on error), so this fold is the kind's only route to the summary
    on an errored unit."""
    reset_warning_state()

    def fake(unit, index, binding, tracker, verbose):
        err = RuntimeError("enhance exploded")          # NON-retryable
        err.agent_state = {"input_tokens": 100, "output_tokens": 10,
                           "cost_usd": 0.03, "cost_incomplete": True,
                           "unpriced_cache_models": ["new-model"]}
        raise err

    cp_dir = tmp_path / "cp"
    try:
        s = _drive_enhance({"units": [_unit()]}, cp_dir, fake)
    finally:
        reset_warning_state()

    assert s["errors"] == 1                           # non-vacuous
    assert s["usage"]["input_tokens"] == 100
    assert s["usage"]["cost_incomplete"] is True
    assert s["usage"]["unpriced_cache_models"] == ["new-model"], (
        "the error-path agent_state fold dropped the #626 cache kind "
        "(context_enhancer.py:928)")


def test_enhance_retry_folds_cache_kind_from_reerror_and_from_meta(tmp_path):
    """R1-1/A folds 4+5 (context_enhancer.py:1089 the re-errored retry's
    state, :1101 the recovered retry's metadata) — the retry loop is a
    SECOND copy of the fold pair and had its own cache twins.

    uA: errors (retryable) then re-errors with a cache-unpriced attempt ->
        fold :1089 is the only route for 'reerr-model'.
    uB: errors (retryable) then recovers with cache-unpriced metadata ->
        fold :1101 is the only route for 'retry-model'."""
    from utilities.llm.adapter import LLMRateLimitError

    reset_warning_state()
    script = {"uA": ["S", "S2"], "uB": ["S", "M"]}
    seen: dict[str, int] = {}

    def fake(unit, index, binding, tracker, verbose):
        uid = unit["id"]
        n = seen.get(uid, 0)
        seen[uid] = n + 1
        step = script[uid][n]
        if step == "S":          # first attempt: retryable, no markers
            err = LLMRateLimitError("rate limited", retry_after=0)
            err.agent_state = {"input_tokens": 10, "output_tokens": 1,
                               "cost_usd": 0.003}
            raise err
        if step == "S2":         # retry re-errors WITH the cache kind.
            # NON-retryable on purpose: uB recovers in round 1, which keeps
            # the retry loop alive, so a second retryable error would pull
            # uA into round 2 and off the end of its script.
            err = RuntimeError("enhance exploded again")
            err.agent_state = {"input_tokens": 20, "output_tokens": 2,
                               "cost_usd": 0.006, "cost_incomplete": True,
                               "unpriced_cache_models": ["reerr-model"]}
            raise err
        unit["agent_context"] = {   # retry succeeds WITH the cache kind
            "security_classification": "safe",
            "agent_metadata": {"input_tokens": 30, "output_tokens": 3,
                               "cost_usd": 0.009, "cost_incomplete": True,
                               "unpriced_cache_models": ["retry-model"]},
        }

    cp_dir = tmp_path / "cp"
    try:
        s = _drive_enhance({"units": [_unit("uA"), _unit("uB")]}, cp_dir, fake)
    finally:
        reset_warning_state()

    # non-vacuous: every attempt really ran and folded (10+10 + 20 + 30)
    assert seen == {"uA": 2, "uB": 2}
    assert s["usage"]["input_tokens"] == 70
    assert s["usage"]["cost_incomplete"] is True
    assert s["usage"]["unpriced_cache_models"] == ["reerr-model", "retry-model"], (
        "the retry loop's own folds dropped the #626 cache kind — :1089 "
        "(re-errored state) and/or :1101 (recovered metadata)")


def test_enhance_resume_restores_cache_kind_to_summary_and_tracker(tmp_path):
    """R1-1/A fold 1 (context_enhancer.py:782) + the restore CALL (:811-814)
    — run 2 over run 1's checkpoint: the persisted cache kind must reach
    BOTH enhance/_summary.json and the tracker's prior usage (the step
    report's run-total contract)."""
    reset_warning_state()

    # --- run 1: one unit completes, carrying the cache kind
    def fake1(unit, index, binding, tracker, verbose):
        unit["agent_context"] = {
            "security_classification": "safe",
            "agent_metadata": {"input_tokens": 100, "output_tokens": 10,
                               "cost_usd": 0.03, "cost_incomplete": True,
                               "unpriced_cache_models": ["run1-model"]},
        }

    cp_dir = tmp_path / "cp"
    _drive_enhance({"units": [_unit("u1")]}, cp_dir, fake1)

    # non-vacuous precondition: the per-unit checkpoint really persisted it
    from core.checkpoint import id_keyed_checkpoint_map
    cp_file = id_keyed_checkpoint_map(str(cp_dir))["u1"]
    assert json.loads(Path(cp_file).read_text())["usage"][
        "unpriced_cache_models"] == ["run1-model"], (
        "fixture broke: run 1 did not persist the cache kind, so the "
        "restore assertions below would be vacuous")

    # --- run 2: u1 is restored from the checkpoint; u2 is fresh and clean
    class _RecordingTracker(TokenTracker):
        def __init__(self):
            super().__init__()
            self.prior_calls: list[dict] = []

        def add_prior_usage(self, input_tokens, output_tokens, cost_usd, **kw):
            self.prior_calls.append({"input_tokens": input_tokens, **kw})
            return super().add_prior_usage(input_tokens, output_tokens,
                                          cost_usd, **kw)

    def fake2(unit, index, binding, tracker, verbose):
        unit["agent_context"] = {"security_classification": "safe",
                                 "agent_metadata": {"input_tokens": 1,
                                                    "output_tokens": 1,
                                                    "cost_usd": 0.001}}

    tracker = _RecordingTracker()
    try:
        s = _drive_enhance({"units": [_unit("u1"), _unit("u2")]}, cp_dir,
                           fake2, tracker=tracker)
    finally:
        reset_warning_state()

    assert s["usage"]["input_tokens"] == 101          # non-vacuous: 100 + 1
    assert s["usage"]["cost_incomplete"] is True
    assert s["usage"]["unpriced_cache_models"] == ["run1-model"], (
        "the checkpoint-restore fold dropped the #626 cache kind "
        "(context_enhancer.py:782)")
    assert tracker.prior_calls, "the restore must inject prior usage"
    assert tracker.prior_calls[0]["unpriced_cache_models"] == ["run1-model"], (
        "the restore CALL dropped the cache kind — the step report's "
        "run-total would read complete (context_enhancer.py:811-814)")
