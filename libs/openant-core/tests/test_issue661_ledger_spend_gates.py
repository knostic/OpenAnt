"""PR #661 / F661-3 — the LEDGER class: cost-blind write gates and seed
conditions at the five enumerated sites.

THE CLASS. Five "did this phase do work?" conditions each key on input/output
tokens plus the two unpriced MARKER sets, and each guards a body that writes or
accumulates an explicit ``cost_usd`` number:

======  ==========================================  ==============================
site    gate                                        guarded ledger write
======  ==========================================  ==============================
1       ``utilities/context_enhancer.py:809``       ``tracker.add_prior_usage``
2       ``utilities/context_enhancer.py:1032``      ``_prior_spend[...]['cost_usd']``
3       ``utilities/context_enhancer.py:1239``      ``cp_data['usage']``
4       ``core/analyzer.py:865``                    ``add_prior_usage`` (global)
5       ``utilities/finding_verifier.py:867``       ``tracker.add_prior_usage``
======  ==========================================  ==============================

None of the five consults COST. Cache-only spend — a turn billed entirely as a
cache read — arrives at every one of these ledgers as 0 input / 0 output tokens
with a real dollar cost (none of these three modules names a cache token key
anywhere: cache spend reaches them ONLY folded into ``cost_usd``). On a priced
model there is no unpriced marker either, so all four existing disjuncts are
false and the gate decides "no work happened" about a turn that cost money. The
summary — whose folds are UNconditional — reports the dollars anyway, so the
observable shape is a $0.120 summary against a $0.000-or-absent
checkpoint/seed, and the spend is ORPHANED on resume.

Each test below is SITE-ISOLATED: it reaches its own gate without depending on
any other gate in the class (site 1/4/5 hand-seed the checkpoint rather than
producing it through site 3, which would compound two bugs into one failure).

Every test carries a non-vacuous precondition: the summary's $0.120 is asserted
alongside the ledger's $0.000, so a fixture that simply spent nothing cannot
make these pass.

The byte-identity controls are the other half of the contract: a genuinely
no-spend phase must STILL write no usage block and STILL not inject — the
present-only discipline the #626 artifact shape depends on.
"""

from __future__ import annotations

import ast
import json
import math
import os
import sys
from collections import deque
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.llm_client import (  # noqa: E402
    TokenTracker,
    reset_global_tracker,
    reset_warning_state,
)

#: the cache-only turn: all cost, no input/output tokens, priced model (so no
#: unpriced marker of either kind). The shape H5-1 measured.
_CACHE_ONLY_COST = 0.120


def _cost_eq(a: float, b: float) -> bool:
    return math.isclose(a, b, abs_tol=1e-9)


def _read_summary(checkpoint_dir) -> dict:
    return json.loads((Path(checkpoint_dir) / "_summary.json").read_text())


def _read_unit_cp(checkpoint_dir, unit_id: str) -> dict:
    from core.checkpoint import id_keyed_checkpoint_map
    cp_map = id_keyed_checkpoint_map(str(checkpoint_dir))
    return json.loads(Path(cp_map[unit_id]).read_text())


def _enhance_binding():
    from utilities.llm.registry import PhaseBinding

    class _Adapter:
        name = "fake"
        supports_tools = True
        pricing = {"fake-model": {"input": 3.0, "output": 15.0}}

    return PhaseBinding(phase="enhance", adapter=_Adapter(), model="fake-model",
                        provider_name="fake")


def _drive_enhance(dataset, checkpoint_dir, enhance, workers=1, tracker=None):
    """Drive the REAL ``enhance_dataset_agentic`` with a stubbed unit enhancer.

    Capture-then-patch (the #609 harness discipline): the real callable is
    captured BEFORE the patch and restored in ``finally``.
    """
    import utilities.context_enhancer as ce
    real = ce.enhance_unit_with_agent
    tracker = tracker or TokenTracker()
    ce.enhance_unit_with_agent = enhance
    try:
        enhancer = ce.ContextEnhancer(binding=_enhance_binding(), tracker=tracker)
        analyzer_out = Path(checkpoint_dir).parent / "a.json"
        analyzer_out.write_text(json.dumps({"results": []}))
        enhancer.enhance_dataset_agentic(
            dataset, analyzer_output_path=str(analyzer_out), repo_path=None,
            workers=workers, checkpoint_path=str(checkpoint_dir))
        return _read_summary(checkpoint_dir), enhancer.tracker
    finally:
        ce.enhance_unit_with_agent = real


def _seed_unit_checkpoint(cp_dir: Path, uid: str, usage: dict,
                          errored: bool = False) -> None:
    """Hand-write a run-1 unit checkpoint — the resume seed's INPUT.

    Hand-written on purpose: producing it through a real run-1 would route the
    usage block through site 3's gate and compound two sites into one failure.
    """
    cp_dir.mkdir(parents=True, exist_ok=True)
    ctx: dict = {"security_classification": "safe"}
    if errored:
        ctx = {"error": {"type": "RuntimeError", "message": "boom"}}
    (cp_dir / f"{uid}.json").write_text(json.dumps({
        "id": uid, "context_key": "agent_context", "agent_context": ctx,
        "usage": usage,
    }))


def _noop_enhance(unit, index, binding, tracker, verbose):
    """A stub that spends NOTHING — so every dollar observed is restored."""
    unit["agent_context"] = {"security_classification": "safe"}


# ===========================================================================
# SITE 1 — utilities/context_enhancer.py:809, the enhance resume SEED
# ===========================================================================
class TestSite1EnhanceResumeSeed:

    def test_cache_only_prior_spend_is_injected_into_the_tracker(self, tmp_path):
        """A resumed enhance whose restored checkpoint holds cache-only spend
        must inject it: the summary says $0.120, so the tracker must too.

        RED at c68e9df3: the seed condition is
        ``_summary_input_tokens or _summary_output_tokens or _summary_unpriced
        or _summary_unpriced_cache`` — 0 or 0 or empty or empty — so
        ``add_prior_usage`` never runs and the restored $0.120 is orphaned.
        """
        reset_warning_state()
        cp_dir = tmp_path / "cp"
        _seed_unit_checkpoint(cp_dir, "u1", {
            "input_tokens": 0, "output_tokens": 0,
            "cost_usd": _CACHE_ONLY_COST})
        try:
            summary, tracker = _drive_enhance(
                {"units": [{"id": "u1", "code": {"primary_code": "x=1"}}]},
                cp_dir, _noop_enhance)
        finally:
            reset_warning_state()

        # non-vacuous: the SUMMARY saw the dollars (its folds are unguarded)
        assert _cost_eq(summary["usage"]["cost_usd"], _CACHE_ONLY_COST), (
            "fixture check: the resume seed did not even reach the summary")

        assert _cost_eq(tracker.get_totals()["total_cost_usd"],
                        _CACHE_ONLY_COST), (
            "context_enhancer.py:809 — the enhance resume seed reported "
            f"${summary['usage']['cost_usd']:.3f} in enhance/_summary.json but "
            "injected $0.000 into the tracker: the gate keys on tokens only, "
            "so cache-only restored spend is dropped from the run total and "
            "every step report downstream of it.")

    def test_an_unbounded_token_count_does_not_crash_the_resume_seed(
            self, tmp_path):
        """The reachability leg for the predicate's overflow: a resume whose
        run-1 checkpoint carries a JSON integer too large for a float.

        RED at d0637b45: OverflowError out of ``turn_has_spend`` ->
        ``context_enhancer.py:813``, aborting the whole enhance phase. GREEN
        at c68e9df3, which only tested truthiness — so this test is written
        against the behaviour the predicate REPLACED, not against a new idea
        of what it should do.
        """
        reset_warning_state()
        cp_dir = tmp_path / "cp"
        huge = 10 ** 400
        _seed_unit_checkpoint(cp_dir, "u1", {
            "input_tokens": huge, "output_tokens": 0, "cost_usd": 0.25})
        # the count reaches the gate through a real json round-trip
        assert json.loads(
            (cp_dir / "u1.json").read_text())["usage"]["input_tokens"] == huge
        try:
            summary, tracker = _drive_enhance(
                {"units": [{"id": "u1", "code": {"primary_code": "x=1"}}]},
                cp_dir, _noop_enhance)
        finally:
            reset_warning_state()

        assert _cost_eq(summary["usage"]["cost_usd"], 0.25)
        assert _cost_eq(tracker.get_totals()["total_cost_usd"], 0.25), (
            "the resume seed must still inject the restored $0.25 when the "
            "token count is an unbounded integer")
        assert tracker.get_totals()["total_input_tokens"] == huge

    def test_a_genuinely_empty_prior_still_injects_nothing(self, tmp_path):
        """Byte-identity control: an all-zero restored checkpoint is NOT
        spend — the gate must still refuse, or a clean resume grows a
        fabricated $0.00 injection."""
        reset_warning_state()
        cp_dir = tmp_path / "cp"
        _seed_unit_checkpoint(cp_dir, "u1", {
            "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0})
        try:
            _summary, tracker = _drive_enhance(
                {"units": [{"id": "u1", "code": {"primary_code": "x=1"}}]},
                cp_dir, _noop_enhance)
        finally:
            reset_warning_state()
        totals = tracker.get_totals()
        assert totals["total_cost_usd"] == 0.0
        assert totals["total_input_tokens"] == 0
        # get_totals() always STAMPS these two (it is not a present-only
        # artifact dict) — the no-injection shape is False/empty, not absent.
        assert totals["cost_incomplete"] is False
        assert totals["unpriced_models"] == []
        assert totals["total_calls"] == 0


# ===========================================================================
# SITE 2 — utilities/context_enhancer.py:1032, the retry WIPE move
# ===========================================================================
class TestSite2RetryWipeMove:

    def test_cache_only_wiped_attempt_survives_into_the_checkpoint(self, tmp_path):
        """A retryable attempt that spent only cache, then a successful retry:
        the wipe discards the error context, so the about-to-be-wiped attempt's
        spend must move into the prior map or the OVERWRITTEN checkpoint loses
        it.

        RED at c68e9df3: the move is gated on
        ``_wiped_state.get('input_tokens') or ...('output_tokens') or _wiped_u
        or _wiped_c`` — all false for a cache-only attempt — so the checkpoint
        carries the retry's $0.060 while the summary carries $0.180.
        """
        from utilities.llm.adapter import LLMRateLimitError
        reset_warning_state()
        calls: dict = {}

        def fake(unit, index, binding, tracker, verbose):
            n = calls.get(unit["id"], 0)
            calls[unit["id"]] = n + 1
            if n == 0:
                err = LLMRateLimitError("rate limited", retry_after=0)
                err.agent_state = {"input_tokens": 0, "output_tokens": 0,
                                   "cost_usd": _CACHE_ONLY_COST}
                raise err
            unit["agent_context"] = {
                "security_classification": "safe",
                "agent_metadata": {"input_tokens": 200, "output_tokens": 20,
                                   "cost_usd": 0.060},
            }

        cp_dir = tmp_path / "cp"
        try:
            summary, _tracker = _drive_enhance(
                {"units": [{"id": "u1", "code": {"primary_code": "x=1"}}]},
                cp_dir, fake)
        finally:
            reset_warning_state()

        # non-vacuous: the retry really did happen and the summary really did
        # fold both the wiped attempt and the retry
        assert calls["u1"] == 2, "fixture check: the retry did not run"
        assert _cost_eq(summary["usage"]["cost_usd"],
                        _CACHE_ONLY_COST + 0.060)

        cp = _read_unit_cp(cp_dir, "u1")
        assert _cost_eq(cp["usage"]["cost_usd"], _CACHE_ONLY_COST + 0.060), (
            "context_enhancer.py:1032 — the retry wipe dropped the "
            f"cache-only attempt's ${_CACHE_ONLY_COST:.3f}: the summary says "
            f"${summary['usage']['cost_usd']:.3f} and the unit checkpoint says "
            f"${cp['usage']['cost_usd']:.3f}. A run-3 resume reads the "
            "checkpoint, so the attempt is orphaned permanently.")

    def test_a_genuinely_empty_wiped_attempt_moves_nothing(self, tmp_path):
        """Byte-identity control: an attempt with no spend at all must not
        create a prior-map entry (all-zero moves are skipped BY DESIGN —
        the #609 comment at :1026-1027 says so)."""
        from utilities.llm.adapter import LLMRateLimitError
        reset_warning_state()
        calls: dict = {}

        def fake(unit, index, binding, tracker, verbose):
            n = calls.get(unit["id"], 0)
            calls[unit["id"]] = n + 1
            if n == 0:
                err = LLMRateLimitError("rate limited", retry_after=0)
                err.agent_state = {"input_tokens": 0, "output_tokens": 0,
                                   "cost_usd": 0.0}
                raise err
            unit["agent_context"] = {
                "security_classification": "safe",
                "agent_metadata": {"input_tokens": 200, "output_tokens": 20,
                                   "cost_usd": 0.060},
            }

        cp_dir = tmp_path / "cp"
        try:
            _summary, _tracker = _drive_enhance(
                {"units": [{"id": "u1", "code": {"primary_code": "x=1"}}]},
                cp_dir, fake)
        finally:
            reset_warning_state()
        cp = _read_unit_cp(cp_dir, "u1")
        assert _cost_eq(cp["usage"]["cost_usd"], 0.060)
        assert cp["usage"]["input_tokens"] == 200
        # the empty attempt contributed no marker keys either
        assert "unpriced_models" not in cp["usage"] or (
            cp["usage"]["unpriced_models"] == [])


# ===========================================================================
# SITE 3 — utilities/context_enhancer.py:1239, the checkpoint WRITE gate
# ===========================================================================
class TestSite3CheckpointWriteGate:

    def test_cache_only_error_attempt_writes_a_usage_block(self, tmp_path):
        """A unit whose only spend was a cache-billed failed attempt must get
        a usage block in its checkpoint.

        RED at c68e9df3: ``if usage_in or usage_out or usage_unpriced or
        usage_unpriced_cache`` is false, so cp_data has NO 'usage' key at all
        while the summary reports $0.120 — the absent-checkpoint half of the
        H5-1 shape.
        """
        reset_warning_state()

        def fake(unit, index, binding, tracker, verbose):
            err = RuntimeError("enhance exploded")
            err.agent_state = {"input_tokens": 0, "output_tokens": 0,
                               "cost_usd": _CACHE_ONLY_COST}
            raise err

        cp_dir = tmp_path / "cp"
        try:
            summary, _tracker = _drive_enhance(
                {"units": [{"id": "u1", "code": {"primary_code": "x=1"}}]},
                cp_dir, fake)
        finally:
            reset_warning_state()

        # non-vacuous: the summary's unguarded fold saw the dollars
        assert _cost_eq(summary["usage"]["cost_usd"], _CACHE_ONLY_COST)

        cp = _read_unit_cp(cp_dir, "u1")
        assert "usage" in cp, (
            "context_enhancer.py:1239 — the unit checkpoint has NO usage "
            f"block after ${_CACHE_ONLY_COST:.3f} of cache-only spend that "
            "enhance/_summary.json reports in full. The write gate keys on "
            "tokens only; the resume reader sums these blocks, so the spend "
            "is orphaned.")
        assert _cost_eq(cp["usage"]["cost_usd"], _CACHE_ONLY_COST)

    def test_a_no_spend_unit_still_writes_no_usage_block(self, tmp_path):
        """Byte-identity control, the load-bearing one: a unit that genuinely
        spent nothing must still produce the pre-#598 checkpoint shape with NO
        usage key. The present-only discipline extends to the gate."""
        reset_warning_state()
        cp_dir = tmp_path / "cp"
        try:
            _drive_enhance(
                {"units": [{"id": "u1", "code": {"primary_code": "x=1"}}]},
                cp_dir, _noop_enhance)
        finally:
            reset_warning_state()
        cp = _read_unit_cp(cp_dir, "u1")
        assert "usage" not in cp, (
            "a zero-spend unit's checkpoint grew a usage block — the #626 "
            "byte-identity contract for a clean run is broken")


# ===========================================================================
# SITE 4 — core/analyzer.py:865, the analyze resume SEED
# ===========================================================================
class TestSite4AnalyzeResumeSeed:

    @staticmethod
    def _drive(tmp_path, monkeypatch, unit_usage):
        from core import analyzer
        from utilities.llm import PhaseBinding

        dataset_path = tmp_path / "dataset.json"
        dataset_path.write_text(json.dumps(
            {"units": [{"id": "a:f", "code": "x=1"}]}))
        output_dir = tmp_path / "out"
        cp_dir = output_dir / "analyze_checkpoints"
        cp_dir.mkdir(parents=True)
        # the run-1 row: a COMPLETED unit whose spend was cache-only
        (cp_dir / "a_f.json").write_text(json.dumps({
            "id": "a:f", "unit_id": "a:f", "verdict": "SAFE",
            "finding": "safe", "confidence": 90, "vulnerabilities": [],
            "reasoning": "r", "result": {"verdict": "SAFE"},
            "usage": unit_usage,
        }))

        def fake_run_detection(units, binding, json_corrector, app_context,
                               workers, checkpoint=None, summary_callback=None):
            # this run spends NOTHING — every dollar observed is restored
            return ([], {u["id"]: "" for u in units})

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
                            lambda binding, ctx_sha=None: {
                                "key_digest": "sha256:test"})
        analyzer.run_analysis(str(dataset_path), str(output_dir),
                              registry=_FakeRegistry(), workers=1)
        return _read_summary(cp_dir)

    def test_cache_only_prior_spend_is_injected_into_the_global_tracker(
            self, tmp_path, monkeypatch):
        """RED at c68e9df3: analyzer.py:865 keys on tokens and markers only,
        so a resumed analyze whose restored spend was cache-only injects
        nothing and the run total loses the dollars its own summary prints."""
        from utilities.llm_client import get_global_tracker
        reset_global_tracker()
        reset_warning_state()
        try:
            summary = self._drive(tmp_path, monkeypatch, {
                "input_tokens": 0, "output_tokens": 0,
                "cost_usd": _CACHE_ONLY_COST})
            # non-vacuous: the summary restored the dollars
            assert _cost_eq(summary["usage"]["cost_usd"], _CACHE_ONLY_COST), (
                "fixture check: the analyze resume seed read no spend")
            totals = get_global_tracker().get_totals()
        finally:
            reset_global_tracker()
            reset_warning_state()

        assert _cost_eq(totals["total_cost_usd"], _CACHE_ONLY_COST), (
            "core/analyzer.py:865 — analyze/_summary.json reports "
            f"${_CACHE_ONLY_COST:.3f} restored but the global tracker got "
            "$0.000: the seed gate is cost-blind, so every step report for "
            "the rest of the scan under-counts by the restored cache spend.")

    def test_a_genuinely_empty_analyze_seed_injects_nothing(
            self, tmp_path, monkeypatch):
        """Byte-identity control for site 4."""
        from utilities.llm_client import get_global_tracker
        reset_global_tracker()
        reset_warning_state()
        try:
            self._drive(tmp_path, monkeypatch, {
                "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0})
            totals = get_global_tracker().get_totals()
        finally:
            reset_global_tracker()
            reset_warning_state()
        assert totals["total_cost_usd"] == 0.0
        assert totals["cost_incomplete"] is False
        assert totals["unpriced_models"] == []


# ===========================================================================
# SITE 5 — utilities/finding_verifier.py:867, the verify resume SEED
# ===========================================================================
class TestSite5VerifyResumeSeed:

    @staticmethod
    def _drive(tmp_path, seed_usage, spend=True):
        from core.checkpoint import StepCheckpoint
        from utilities.agentic_enhancer.repository_index import RepositoryIndex
        from utilities.finding_verifier import FindingVerifier, VerificationResult
        from utilities.llm import PhaseBinding

        class _Adapter:
            name = "anthropic"
            supports_tools = True
            pricing = {}

        binding = PhaseBinding(phase="verify", adapter=_Adapter(), model="m",
                               provider_name="anthropic")

        class _Scripted(FindingVerifier):
            def verify_result(self, code, finding, attack_vector, reasoning,
                              files_included=None):
                if spend:
                    # this run's OWN spend: 10k in / 1k out at 3/15 per M
                    # = $0.045 exactly (astra's F2 falsifier number)
                    self.tracker.record_call(
                        model="m", input_tokens=10_000, output_tokens=1_000,
                        pricing={"input": 3.0, "output": 15.0})
                return VerificationResult(agree=True, correct_finding=finding,
                                          explanation="ok", iterations=1,
                                          total_tokens=11_000)

        cp_dir = tmp_path / "verify_checkpoints"
        cp_dir.mkdir()
        (cp_dir / "old.json").write_text(json.dumps({
            "id": "old", "route_key": "old", "finding": "safe",
            "verification": {"agree": True, "correct_finding": "safe"},
            "usage": seed_usage,
        }))
        cp = StepCheckpoint("Verify", str(tmp_path))
        cp.dir = str(cp_dir)

        tracker = TokenTracker()
        verifier = _Scripted(index=RepositoryIndex({}, repo_path=None),
                             binding=binding, tracker=tracker)
        results = [{"route_key": "r1", "finding": "vulnerable",
                    "attack_vector": "a", "reasoning": "r"}]
        verifier.verify_batch(results, {"r1": "code"}, workers=1, checkpoint=cp)
        return _read_summary(cp_dir), tracker

    def test_cache_only_prior_spend_is_injected_into_the_tracker(self, tmp_path):
        """RED at c68e9df3: the tracker carries this run's $0.045 ONLY — the
        restored $0.120 never reaches it. This is astra's F2 falsifier shape
        exactly: adding the cost disjunct to this one seed condition restored
        the missing dollars."""
        reset_warning_state()
        try:
            summary, tracker = self._drive(tmp_path, {
                "input_tokens": 0, "output_tokens": 0,
                "cost_usd": _CACHE_ONLY_COST})
        finally:
            reset_warning_state()

        # non-vacuous: the restored dollars DID reach the summary
        assert _cost_eq(summary["usage"]["cost_usd"],
                        _CACHE_ONLY_COST + 0.045), (
            "fixture check: the verify summary did not fold restored + fresh")

        assert _cost_eq(tracker.get_totals()["total_cost_usd"],
                        _CACHE_ONLY_COST + 0.045), (
            "finding_verifier.py:867 — verify/_summary.json reports "
            f"${_CACHE_ONLY_COST + 0.045:.3f} but the tracker carries only "
            "this run's $0.045: the cost-blind seed gate orphaned the "
            "restored cache-only spend.")

    def test_a_genuinely_empty_verify_seed_injects_nothing(self, tmp_path):
        """Byte-identity control for site 5: with an all-zero restored row and
        no fresh spend the tracker must stay empty."""
        reset_warning_state()
        try:
            _summary, tracker = self._drive(tmp_path, {
                "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0},
                spend=False)
        finally:
            reset_warning_state()
        totals = tracker.get_totals()
        assert totals["total_cost_usd"] == 0.0
        assert totals["total_input_tokens"] == 0
        assert totals["cost_incomplete"] is False
        assert totals["unpriced_models"] == []


# ===========================================================================
# The MARKER leg — the existing disjuncts must keep working through the
# shared predicate (a marker-only turn is spend; this is what the four
# original terms bought, and the fix must not trade it away).
# ===========================================================================
class TestTheMarkerLegSurvives:

    def test_a_marker_only_restored_row_still_injects(self, tmp_path):
        """Zero tokens, zero cost, but an unpriced id: still spend (a
        zero-token call whose only trace is the marker — #598's term)."""
        reset_warning_state()
        cp_dir = tmp_path / "cp"
        _seed_unit_checkpoint(cp_dir, "u1", {
            "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0,
            "cost_incomplete": True, "unpriced_models": ["fake/x"]})
        try:
            _summary, tracker = _drive_enhance(
                {"units": [{"id": "u1", "code": {"primary_code": "x=1"}}]},
                cp_dir, _noop_enhance)
        finally:
            reset_warning_state()
        assert tracker.get_totals().get("unpriced_models") == ["fake/x"]

    def test_a_cache_marker_only_restored_row_still_injects(self, tmp_path):
        """The #626 twin kind, same shape."""
        reset_warning_state()
        cp_dir = tmp_path / "cp"
        _seed_unit_checkpoint(cp_dir, "u1", {
            "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0,
            "cost_incomplete": True, "unpriced_cache_models": ["fake/c"]})
        try:
            _summary, tracker = _drive_enhance(
                {"units": [{"id": "u1", "code": {"primary_code": "x=1"}}]},
                cp_dir, _noop_enhance)
        finally:
            reset_warning_state()
        assert tracker.get_totals().get("unpriced_cache_models") == ["fake/c"]


# ===========================================================================
# THE PREDICATE itself — the degeneration edges
# ===========================================================================
class TestTheSpendPredicate:
    """``turn_has_spend`` is the single point of failure for all five gates,
    so its edges are pinned directly: an all-zero dict, a marker-only turn, a
    $0.00-cost-but-cached turn, and the malformed-payload tolerance three of
    the five sites used to get from bare truthiness."""

    def test_an_all_zero_usage_dict_is_not_spend(self):
        from utilities.llm_client import turn_has_spend
        assert turn_has_spend({"input_tokens": 0, "output_tokens": 0,
                               "cost_usd": 0.0}) is False

    def test_an_empty_or_absent_usage_is_not_spend(self):
        from utilities.llm_client import turn_has_spend
        assert turn_has_spend({}) is False
        assert turn_has_spend(None) is False
        assert turn_has_spend() is False

    def test_cache_only_cost_is_spend(self):
        """THE regression: zero tokens, no markers, real dollars."""
        from utilities.llm_client import turn_has_spend
        assert turn_has_spend({"input_tokens": 0, "output_tokens": 0,
                               "cost_usd": 0.120}) is True

    def test_a_sub_cent_cost_is_still_spend(self):
        from utilities.llm_client import turn_has_spend
        assert turn_has_spend({"cost_usd": 1e-9}) is True

    def test_a_marker_only_turn_is_spend_both_kinds(self):
        """A $0.00-cost-but-CACHED turn: the cache was billed on a model with
        no cache multiplier, so the cost is 0 and the only trace is the #626
        marker. Still spend — dropping it loses the incompleteness."""
        from utilities.llm_client import turn_has_spend
        assert turn_has_spend({"unpriced_models": ["m"]}) is True
        assert turn_has_spend({"unpriced_cache_models": ["m"]}) is True
        assert turn_has_spend({"input_tokens": 0, "output_tokens": 0,
                               "cost_usd": 0.0,
                               "unpriced_cache_models": ["m"]}) is True

    def test_tokens_alone_are_still_spend(self):
        """The three original disjuncts are not traded away."""
        from utilities.llm_client import turn_has_spend
        assert turn_has_spend({"input_tokens": 1}) is True
        assert turn_has_spend({"output_tokens": 1}) is True

    def test_keywords_override_the_dict(self):
        from utilities.llm_client import turn_has_spend
        # the dict says nothing happened; the merged accumulator says it did
        assert turn_has_spend({"cost_usd": 0.0}, cost_usd=0.5) is True
        # and the other way: a keyword 0 beats a dict's value
        assert turn_has_spend({"input_tokens": 99}, input_tokens=0) is False

    def test_each_marker_kind_is_resolved_INDEPENDENTLY(self):
        """S9 self-hunt finding: one marker keyword alone must NOT suppress
        the dict read of the OTHER kind.

        Unreachable at today's five sites (the single dict-form call,
        context_enhancer.py:1042, passes both kinds) — but the census pin
        funnels every FUTURE gate through this predicate and only checks that
        it is CALLED, so a half-specified call that silently dropped the other
        marker kind would be exactly the cost-blind defect this round removed,
        reintroduced one kind at a time.
        """
        from utilities.llm_client import turn_has_spend
        # unpriced= given, cache kind must still be read FROM THE DICT
        assert turn_has_spend({"unpriced_cache_models": ["m"]},
                              unpriced=[]) is True
        # and the mirror
        assert turn_has_spend({"unpriced_models": ["m"]},
                              unpriced_cache=[]) is True
        # an explicit empty for BOTH still suppresses both
        assert turn_has_spend({"unpriced_models": ["m"],
                               "unpriced_cache_models": ["m"]},
                              unpriced=[], unpriced_cache=[]) is False

    def test_a_malformed_payload_does_not_raise(self):
        """Three of the five gates tested BARE truthiness before the fix, so a
        legacy payload that read falsy must not start raising inside the gate
        (these run on enhance worker threads)."""
        from utilities.llm_client import turn_has_spend
        assert turn_has_spend({"input_tokens": [], "cost_usd": []}) is False
        assert turn_has_spend({"input_tokens": "abc"}) is True
        assert turn_has_spend({"cost_usd": None, "output_tokens": None}) is False

    def test_an_unbounded_integer_count_is_spend_not_an_OverflowError(self):
        """N1 of the verify wave, on MY OWN round-5 code: a Python int has no
        magnitude limit and a float does, so ``float(10**400)`` raises
        OverflowError — which ``_num`` did not catch.

        This is a ROBUSTNESS REGRESSION, measured as a differential against
        the expression this predicate replaced: at c68e9df3 the enhance resume
        seed was a bare ``_summary_input_tokens or ...`` truthiness test, so
        the same decoded checkpoint restored its $0.25 and the run continued;
        at d0637b45 it raised out of the gate. A corrupt or adversarial
        checkpoint must not be able to abort a resume from inside a predicate
        whose docstring promises it never raises.

        Reachable, not theoretical: JSON integers are unbounded and
        ``context_enhancer.py:777`` accumulates ``cp_usage.get("input_tokens")``
        straight off ``read_json`` into the gate at :813.

        The adjudication, stated because it is a judgement and not a
        derivation: an uncountably large token count is SPEND. Treating it as
        no-spend would orphan the very dollars that accompany it, which is the
        defect this whole round removes.
        """
        from utilities.llm_client import turn_has_spend
        huge = 10 ** 400
        assert turn_has_spend(input_tokens=huge) is True
        assert turn_has_spend(output_tokens=huge) is True
        assert turn_has_spend(cost_usd=huge) is True
        # and through the dict form, the shape a decoded checkpoint arrives in
        assert turn_has_spend({"input_tokens": huge, "output_tokens": 0,
                               "cost_usd": 0.0}) is True
        # a huge NEGATIVE count is still evidence, by the same rule the S9
        # hunt adjudicated for negative/NaN/inf cost
        assert turn_has_spend(input_tokens=-huge) is True

    def test_the_609_stringly_typed_zero_is_still_skipped(self):
        """The differential guard on the N1 fix: the overflow handling must
        not be bought by widening the truthiness fallback. A legacy payload's
        string ``"0"`` is NOT spend — it parses to 0.0 — and that is the
        #609 all-zero skip the round-5 differential measured 52 flips of.

        Unpinned before this round even though the S9 differential relied on
        it; the ``_num`` edit is exactly the edit that could break it.
        """
        from utilities.llm_client import turn_has_spend
        assert turn_has_spend({"input_tokens": "0", "output_tokens": "0",
                               "cost_usd": "0"}) is False
        assert turn_has_spend({"input_tokens": "0.0"}) is False
        # ... while a non-numeric string stays spend (it carries SOMETHING)
        assert turn_has_spend({"input_tokens": "abc"}) is True

    def test_a_non_dict_usage_is_tolerated(self):
        """Every caller also reads legacy checkpoints — ``unpriced_kinds_from``
        makes the same promise."""
        from utilities.llm_client import turn_has_spend
        assert turn_has_spend("not a dict") is False
        assert turn_has_spend(["not", "a", "dict"]) is False

    def test_it_returns_a_real_bool(self):
        """The gates are ``if`` tests; a truthy set leaking out would still
        work but would make the predicate's contract untestable."""
        from utilities.llm_client import turn_has_spend
        assert turn_has_spend({"unpriced_models": ["m"]}) is True
        assert turn_has_spend({"input_tokens": 5}) is True


# ===========================================================================
# THE CENSUS PIN — the ledger class is CLOSED AT 5 and every member routes
# through the one predicate
# ===========================================================================
_REPO_ROOT = PROJECT_ROOT
_SKIP_DIRS = {"tests", ".git", "__pycache__", "node_modules", ".venv",
              "venv", "build", "dist", ".pytest_cache"}

#: every cost-bearing ledger write gate in the tree, keyed by its SINK:
#: (path relative to libs/openant-core, the function that owns it).
_EXPECTED_LEDGER_GATES = {
    ("utilities/context_enhancer.py", "enhance_dataset_agentic"): 2,
    ("utilities/context_enhancer.py", "_save_unit_checkpoint"): 1,
    ("core/analyzer.py", "run_analysis"): 1,
    ("utilities/finding_verifier.py", "verify_batch"): 1,
}

#: the OTHER class, deliberately excluded: F1's accumulated-conversation
#: guards (finding_verifier.py:531, agentic_enhancer/agent.py:367) already
#: consult the CACHE counts via ``turn.billed``, so they are not cost-blind
#: and they are pinned by test_issue626_conversation_error_path_cache.py.
#: The discriminator is mechanical, not a name list: a gate that consults a
#: billed/cache term is not a member of this class.
_CACHE_AWARE_TERMS = ("billed", "cache_read", "cache_write", "cache_creation",
                      "read_total", "write_total")

#: one-slot memo for the census (see the note in _ledger_gates)
_LEDGER_GATE_CACHE: list = []


#: the AST nodes that introduce a NEW namespace -- a binding inside one of
#: these does not belong to the enclosing function's scope
_NESTED_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda,
                       ast.ClassDef)

#: how far a renamed intermediate is chased through local assignments
_INLINE_DEPTH = 6


def _names(node) -> set:
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out.add(n.id)
        elif isinstance(n, ast.Attribute):
            out.add(n.attr)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            out.add(n.value)
    return out


def _own_scope_assigns(node) -> dict:
    """Single-``Name`` assignments belonging to ``node``'s OWN scope.

    THIS IS THE SAME BFS AS ``ast.walk`` -- so which assignment wins the
    ``setdefault`` for a name bound twice in one scope is unchanged -- with
    exactly one difference: it does not cross a nested scope boundary. A
    ``FunctionDef`` / ``AsyncFunctionDef`` / ``Lambda`` / ``ClassDef``
    introduces its own namespace, and admitting its locals here is the scope
    defect described in ``_gates_in_source``.

    The narrowing is deliberate and one-directional: a nested scope's names
    are kept OUT, but an ENCLOSING scope's names are not pulled IN (a closure
    may legally read them). That second half is the pre-existing disclosed
    blind spot in ``_ledger_gates``'s docstring, not something this helper
    changes.
    """
    binds: dict = {}
    # a deque, for the same reason ``ast.walk`` uses one: ``list.pop(0)`` is
    # O(n) per pop, and this runs over every function in the tree inside a CI
    # leg whose timeout-minutes margin this pin has already consumed once.
    queue = deque([node])
    while queue:
        cur = queue.popleft()
        for ch in ast.iter_child_nodes(cur):
            if isinstance(ch, _NESTED_SCOPE_NODES):
                continue          # a different namespace: not these locals
            if (isinstance(ch, ast.Assign) and len(ch.targets) == 1
                    and isinstance(ch.targets[0], ast.Name)):
                binds.setdefault(ch.targets[0].id, ch.value)
            queue.append(ch)
    return binds


def _both_views(node, bindings) -> set:
    """Round-4's rename-defeat guard: resolve a gate's test through its
    enclosing function's single-Name assignments, so ``usage_in`` reads as the
    ``meta.get('input_tokens') + ...`` it actually is.

    The resolution is needed in BOTH directions, which round 4 did not have to
    handle: substitution ALONE also destroys a counter whose initialiser is a
    literal (``_summary_input_tokens = 0`` makes the test read ``0 or 0 or
    ...`` and erases the very name the census keys on). So the raw and
    resolved views are UNIONED -- either view naming a kind counts.

    Computed as a transitive NAME CLOSURE rather than by substituting into a
    copied tree. The two are equivalent here because only the resulting name
    SET is ever consulted, never the rewritten tree -- and the closure needs
    no ``deepcopy`` per node. That is a runtime fix with teeth: the
    substituting version took the windows-latest CI leg (timeout-minutes 15)
    from 9m10s to a 15m13s cancellation.
    """
    out = _names(node)
    frontier, seen = set(out), set()
    for _ in range(_INLINE_DEPTH):
        nxt: set = set()
        for nm in frontier:
            if nm in seen:
                continue
            seen.add(nm)
            repl = bindings.get(nm)
            if repl is not None:
                nxt |= _names(repl)
        nxt -= out
        if not nxt:
            break
        out |= nxt
        frontier = nxt
    return out


def _gates_in_source(rel: str, text: str) -> dict:
    """The census of ONE source: ``{(rel, owning function): [site, ...]}``.

    Split out of :func:`_ledger_gates` so the SCOPING rules below can be
    exercised on a source of the caller's choosing. That is not tidiness: the
    whole-tree assertion cannot see a scope defect the tree does not happen to
    contain today, and this function's innermost-scope promise had one (see
    ``TestTheCensusScopesItsBindingsToTheInnermostFunction``).
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {}
    # INNERMOST-function scoping, both for the sink key and for the inlining
    # bindings. A flat ast.walk leaks a NESTED function's assignments into the
    # enclosing one, and that is not academic in EITHER direction:
    #   * finding_verifier's `_usage_dict` assigns
    #     `usage = {"input_tokens": ..., "cost_usd": ...}`, which turned a bare
    #     `if usage:` presence check into a dict naming both token kinds and
    #     cost — a false sixth member of this class (my own first draft of this
    #     pin reported exactly that, which is how the blind spot was found);
    #   * and the mirror, which the first fix of that blind spot left live: a
    #     nested helper's ZERO-valued local wins the `setdefault` over the
    #     enclosing ledger loop's identically-named, token-derived local, so a
    #     real sixth cost-blind gate reads as `0 or 0` and goes UNSEEN.
    owner, scope = {}, {}

    def _descend(node, fname, binds):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                inner = _own_scope_assigns(child)
                owner[id(child)] = child.name
                scope[id(child)] = inner
                _descend(child, child.name, inner)
            else:
                owner[id(child)] = fname
                scope[id(child)] = binds
                _descend(child, fname, binds)

    # ONE scoping rule for every scope, module included: a two-rule census is
    # how the nested-scope leak survived its own fix comment.
    _descend(tree, "<module>", _own_scope_assigns(tree))
    found: dict = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        binds = scope.get(id(node), {})
        tnames = _both_views(node.test, binds)
        bnames: set = set()
        for st in node.body:
            bnames |= _both_views(st, binds)
        # the guarded body must write/accumulate a cost
        if not any("cost" in n for n in bnames):
            continue
        keys_on_tokens = (any("input_token" in n for n in tnames)
                          and any("output_token" in n for n in tnames))
        uses_predicate = "turn_has_spend" in tnames
        if not (keys_on_tokens or uses_predicate):
            continue
        # F1's cache-aware conversation guards are a DIFFERENT class
        if any(t in n for n in tnames for t in _CACHE_AWARE_TERMS):
            continue
        # a LIST, not an assignment: two gates in ONE function must not
        # collapse to a single key (round 4's mutant M5 found that hole)
        key = (rel, owner.get(id(node), "<module>"))
        found.setdefault(key, []).append({
            "lineno": node.lineno,
            "uses_predicate": uses_predicate,
            "consults_cost": any("cost" in n for n in tnames),
        })
    return found


def _ledger_gates():
    """Sink-keyed AST census: every ``ast.If`` in production Python that gates
    a COST-BEARING ledger write on a per-turn work question.

    AST and not grep, for the reason round 4 learned the hard way: one of the
    five tests names neither token key (``usage_in or usage_out or ...``), so
    a textual census misses it entirely — and that site is the checkpoint
    write gate, the one whose miss orphans spend permanently.

    Membership: the guarded body carries a ``cost``-ish term AND the test
    either (a) names both token kinds, or (b) calls ``turn_has_spend``.
    Cache-aware guards (F1's class) are excluded by the ``billed`` term.

    Two blind spots, both disclosed because both were MEASURED against this
    pin rather than reasoned about:

    * a gate whose condition is computed in a helper CALL (rather than
      lexically in the ``if``) and whose name carries no token or spend term
      is not seen;
    * a file is PRE-FILTERED out unless its text contains "cost" and either
      "token" or "turn_has_spend". That costs this pin nothing by its own
      membership rule (a member's body must name a cost-ish term and its test
      must name both token kinds or call the predicate, so a file lacking
      those words can hold no member) -- but it is a text filter in front of
      an AST census, so it is named here rather than left implicit;
    * a gate whose token source resolves to a LITERAL rather than to a read of
      an ``input_tokens``/``output_tokens`` key is not seen either. A probe
      injecting ``_probe_in = 0; if _probe_in or _probe_out:`` survived this
      pin; the same probe reading ``_probe_usage.get("input_tokens")``
      tripped all three assertions below. Any gate that actually consults a
      real ledger must read those keys from somewhere, which is what makes
      the pin load-bearing in practice — but a gate fed by a renamed
      intermediate assigned OUTSIDE the enclosing function would escape.
    """
    if _LEDGER_GATE_CACHE:
        return _LEDGER_GATE_CACHE[0]
    found: dict = {}
    for dirpath, dirnames, filenames in os.walk(_REPO_ROOT):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if not fn.endswith(".py") or fn.startswith("test_"):
                continue
            path = Path(dirpath) / fn
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            # CHEAP PRE-FILTER, and it costs the pin nothing: membership
            # below requires a "cost"-ish NAME in the guarded body, so a file
            # whose text never says "cost" can hold no member -- and skipping
            # it avoids both the parse and the inlining deepcopies. This is a
            # RUNTIME fix, not a scope change: the windows-latest CI leg has
            # timeout-minutes 15 and three un-memoized full-tree walks with
            # per-node deepcopy took it from 9m10s to a 15m13s cancellation.
            if "cost" not in text:
                continue
            # the same argument for the TEST side: membership requires the
            # test to name both token kinds or to call the predicate, and
            # either way the file's text must contain one of these.
            if "token" not in text and "turn_has_spend" not in text:
                continue
            # as_posix(), not str(): str() yields backslashes on Windows and
            # every key misses _EXPECTED (round 4's windows-latest leg caught
            # exactly that)
            rel = path.relative_to(_REPO_ROOT).as_posix()
            for key, sites in _gates_in_source(rel, text).items():
                found.setdefault(key, []).extend(sites)
    # memoized: three tests below ask the same question of an unchanging
    # tree, and the walk is the whole cost of this file.
    _LEDGER_GATE_CACHE.append(found)
    return found


#: a sixth cost-bearing ledger write gate, cost-blind, whose two token
#: locals are RENAMED intermediates -- so seeing it depends on the census
#: resolving the rename, which is what the scope defect broke.
_SRC_SIXTH_GATE = """
def _ledger_phase(units, sink):
    for _u in units:
        _p_in = _u.get("input_tokens", 0)
        _p_out = _u.get("output_tokens", 0)
        if _p_in or _p_out:
            sink["cost_usd"] = _u.get("cost_usd", 0.0)
"""

#: THE SHADOWED-LOOP SHAPE: the identical gate, plus a nested helper that
#: happens to use the same two local names for a zero-valued purpose.
_SRC_SIXTH_GATE_SHADOWED = """
def _ledger_phase(units, sink):

    def _fmt():
        _p_in = 0
        _p_out = 0
        return "%s/%s" % (_p_in, _p_out)

    for _u in units:
        _p_in = _u.get("input_tokens", 0)
        _p_out = _u.get("output_tokens", 0)
        if _p_in or _p_out:
            sink["cost_usd"] = _u.get("cost_usd", 0.0)
    return _fmt()
"""

#: the sink-key-collision form: a correctly-routed gate AND a shadowed
#: cost-blind one in the SAME function (round 4's mutant-M5 hole, now with
#: the nested helper on top).
_SRC_SECOND_GATE_SHADOWED = """
from utilities.llm_client import turn_has_spend


def verify_batch(units, sink):
    _in = 0
    _out = 0
    _cost = 0.0
    if turn_has_spend(input_tokens=_in, output_tokens=_out, cost_usd=_cost):
        sink["cost_usd"] = _cost

    def _fmt():
        _p_in = 0
        _p_out = 0
        return (_p_in, _p_out)

    for _u in units:
        _p_in = _u.get("input_tokens", 0)
        _p_out = _u.get("output_tokens", 0)
        if _p_in or _p_out:
            sink["extra_cost_usd"] = _u.get("cost_usd", 0.0)
    _fmt()
"""

#: the OTHER direction: a BARE presence check on a name this scope never
#: assigns. finding_verifier's real shape (`_usage_dict` + `if usage:`).
_SRC_BARE_PRESENCE_CHECK = """
def verify_batch(sink):

    def _usage_dict():
        usage = {"input_tokens": 1, "output_tokens": 2, "cost_usd": 0.5}
        return usage

    for usage in (_usage_dict(),):
        if usage:
            sink["cost_usd"] = 1.0
"""

#: ... and its control: the same dict, assigned IN the gate's own scope, IS a
#: member. The scope fix must narrow the inliner, not blind it.
_SRC_IN_SCOPE_DICT = """
def verify_batch(sink):
    usage = {"input_tokens": 1, "output_tokens": 2, "cost_usd": 0.5}
    if usage:
        sink["cost_usd"] = 1.0
"""

#: a gate that lives INSIDE a nested function: it belongs to the nested
#: function, not to its parent.
_SRC_NESTED_GATE = """
def enhance_dataset_agentic(sink):

    def _summary_callback(usage=None):
        _p_in = usage.get("input_tokens", 0)
        _p_out = usage.get("output_tokens", 0)
        if _p_in or _p_out:
            sink["cost_usd"] = usage.get("cost_usd", 0.0)

    return _summary_callback
"""


class TestTheCensusScopesItsBindingsToTheInnermostFunction:
    """The census pin's own scoping promise, pinned — BOTH directions.

    N1 of the non-author verify wave, against MY OWN round-5 code. The census
    promises innermost-function scoping for its inlining bindings and then
    collected them with a flat ``ast.walk``, which crosses INTO nested
    functions. Two failures follow from the one defect, and the whole-tree
    assertions above can see neither, because today's tree happens to contain
    no instance:

    * MASKING — BFS order plus ``setdefault`` means a nested helper's
      zero-valued local WINS over the enclosing ledger loop's identically
      named, token-derived local. The gate's test then resolves to ``0 or 0``,
      the token keys vanish, and a real sixth cost-blind gate is INVISIBLE.
      Measured: the SHADOWED-LOOP forms of mutants M8 and M9 (M8/M9 plus one
      nested helper, nothing else) both SURVIVED at d0637b45 —
      ``found=5 assertions_failed=0`` where the unshadowed originals give
      ``found=6 assertions_failed=3``.
    * PHANTOM — the mirror, and the one the pin's own comment claimed to have
      fixed: a nested helper's usage dict inlines into a BARE presence check
      the enclosing scope never bound, manufacturing a sixth member out of a
      non-member. Measured: ``found=6``, 2 census assertions failed, with no
      cost-blind gate anywhere in the tree.

    These run on synthetic sources rather than on the tree, on purpose: a pin
    whose only input is the tree can only pin what the tree already contains.
    """

    def test_a_nested_helper_must_not_hide_a_real_sixth_gate(self):
        key = ("x.py", "_ledger_phase")
        # fixture check: the gate is detectable AT ALL (the rename resolves)
        control = _gates_in_source("x.py", _SRC_SIXTH_GATE)
        assert list(control) == [key], (
            f"fixture check failed, the plain form is not seen: {control}")

        found = _gates_in_source("x.py", _SRC_SIXTH_GATE_SHADOWED)
        assert list(found) == [key], (
            "a sixth cost-blind ledger write gate became INVISIBLE to this "
            "census because a nested helper in the same function reuses its "
            "two local names for zero-valued work. The bindings used to "
            "resolve a renamed token intermediate must come from the gate's "
            "OWN scope only — a nested function is a different namespace. "
            f"found: {found}")
        assert len(found[key]) == 1, found
        assert found[key][0]["uses_predicate"] is False
        assert found[key][0]["consults_cost"] is False

    def test_a_shadowed_second_gate_in_a_counted_function_still_counts(self):
        """The sink-key-collision direction: the shadowed gate must not hide
        behind its correctly-routed sibling in the same function."""
        key = ("y.py", "verify_batch")
        found = _gates_in_source("y.py", _SRC_SECOND_GATE_SHADOWED)
        assert list(found) == [key], found
        assert len(found[key]) == 2, (
            "two gates in one function must stay two sites; the shadowed "
            f"cost-blind one was dropped: {found}")
        blind = [s for s in found[key] if not s["uses_predicate"]
                 and not s["consults_cost"]]
        assert len(blind) == 1, found

    def test_a_nested_helpers_dict_must_not_fabricate_a_member(self):
        """The PHANTOM direction, with its own control."""
        phantom = _gates_in_source("z.py", _SRC_BARE_PRESENCE_CHECK)
        assert phantom == {}, (
            "a BARE presence check became a member of the cost-bearing "
            "ledger-gate class: the census inlined a NESTED helper's usage "
            "dict into a name the gate's own scope never assigns. That is a "
            "false positive on a real module shape "
            "(finding_verifier.py:855 `_usage_dict` + :904 `if usage:`), and "
            f"it would fail the closure assertions for nothing. found: "
            f"{phantom}")
        # the control: narrowing the scope must not blind the inliner
        in_scope = _gates_in_source("z.py", _SRC_IN_SCOPE_DICT)
        assert list(in_scope) == [("z.py", "verify_batch")], (
            "the same dict, bound in the gate's OWN scope, must still "
            f"resolve — the fix narrows the scope, it does not remove the "
            f"rename resolution: {in_scope}")

    def test_a_gate_inside_a_nested_function_is_keyed_to_that_function(self):
        """The attribution half of the same promise. Green before this fix
        too — it is the regression guard on the sink KEY while the binding
        scope changes underneath it."""
        found = _gates_in_source("w.py", _SRC_NESTED_GATE)
        assert list(found) == [("w.py", "_summary_callback")], found
        assert ("w.py", "enhance_dataset_agentic") not in found


class TestTheLedgerGateClassIsClosed:
    """The population of cost-bearing ledger write gates is CLOSED AT 5, and
    every one of them asks the work question through ``turn_has_spend``.

    This pin exists because the class's SIZE was the thing nobody knew. The
    tokens-only idiom was copied from site to site across #216, #281, #598,
    #609 and #626; four separate rounds fixed cache accounting inside the
    bodies while every one of these gates still decided whether to run the
    body at all using tokens alone. A SIXTH gate — or a sixth copy of the
    cost-blind condition — must fail here, loudly, with the fix named.
    """

    def test_the_population_is_exactly_the_five_known_sinks(self):
        found = _ledger_gates()
        # the keys are POSIX on every platform
        assert all("\\" not in path for path, _ in found), sorted(found)
        counts = {k: len(v) for k, v in found.items()}
        assert counts == _EXPECTED_LEDGER_GATES, (
            "the ledger write-gate census moved.\n"
            f"  expected: {sorted(_EXPECTED_LEDGER_GATES.items())}\n"
            f"  found:    {sorted(counts.items())}\n"
            + str({k: [s["lineno"] for s in v] for k, v in found.items()})
            + "\nA NEW gate deciding whether a cost-bearing ledger write "
              "happens must ask through utilities.llm_client.turn_has_spend "
              "(one predicate, cost included — never a sixth hand-rolled "
              "token-only OR-chain) and then be added here.")
        assert sum(counts.values()) == 5

    def test_every_ledger_gate_routes_through_the_one_predicate(self):
        found = _ledger_gates()
        offenders = [(key, site["lineno"]) for key, sites in found.items()
                     for site in sites if not site["uses_predicate"]]
        assert offenders == [], (
            f"these ledger gates do not use turn_has_spend: {offenders}. "
            "Each re-derives 'did this phase do work?' locally, which is how "
            "the cost term came to be missing at five sites at once.")

    def test_no_cost_bearing_ledger_gate_is_COST_BLIND(self):
        """The closure assertion, stated as the defect rather than the fix: a
        gate that guards a cost-bearing write and consults neither cost nor
        the predicate is the bug this round removed. The population of such
        gates must be EMPTY.

        Stated this way the pin also catches a gate that a future refactor
        renames out of ``_EXPECTED_LEDGER_GATES``'s sink keys.
        """
        found = _ledger_gates()
        blind = [(key, site["lineno"]) for key, sites in found.items()
                 for site in sites
                 if not site["uses_predicate"] and not site["consults_cost"]]
        assert blind == [], (
            f"COST-BLIND ledger write gates found: {blind}. Cache-only spend "
            "reaches these ledgers as 0 input / 0 output tokens with real "
            "dollars, so a token-keyed gate writes no usage block and the "
            "spend is orphaned on resume while the phase summary reports it "
            "in full. Use utilities.llm_client.turn_has_spend.")

    def test_the_predicate_is_imported_at_all_three_modules(self):
        """Source-placement leg: the three modules import the shared
        predicate rather than defining a local copy of it."""
        for rel in ("utilities/context_enhancer.py", "core/analyzer.py",
                    "utilities/finding_verifier.py"):
            # encoding pinned: a locale read on windows-latest is cp1252,
            # and these sources carry non-ASCII (the round-4 CI lesson was
            # exactly this class of host-dependent pin failure).
            text = (_REPO_ROOT / rel).read_text(encoding="utf-8")
            assert "turn_has_spend" in text, rel
            assert "def turn_has_spend" not in text, (
                f"{rel} defines its OWN turn_has_spend — the point of the "
                "shared predicate is that there is exactly one")

    def test_the_f1_guard_class_is_excluded_on_purpose(self):
        """The boundary, asserted so a future reader cannot mistake it for an
        oversight: F1's accumulated-conversation guards consult the CACHE
        counts (``turn.billed``), which is why they are not members of this
        class and are pinned elsewhere."""
        for rel, func in (("utilities/finding_verifier.py", "verify_result"),
                          ("utilities/agentic_enhancer/agent.py",
                           "analyze_unit")):
            text = (_REPO_ROOT / rel).read_text(encoding="utf-8")
            assert "or turn.billed" in text, (
                f"{rel}:{func} no longer consults turn.billed — F1's guard "
                "class changed shape; re-derive the boundary before trusting "
                "this census (that gate would now be cost-blind too).")
            assert (rel, func) not in _EXPECTED_LEDGER_GATES
