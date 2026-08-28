"""Regression tests for issue #293 — two-branch error/else counters count
incomplete work as completed (5 sites).

The pipeline has THREE per-unit outcomes: completed (verdict reached),
incomplete (the loop ran out / the model produced no verdict), and errored.
Five counter sites branched on `error` vs everything-else, so the incomplete
case fell into the `else` and was counted as completed. Runtime proof from
the issue: a verify checkpoint summary reported 175 completed where only 41
verifications actually produced a verdict — a 4.3x over-report; 175 + 48
errors looked internally consistent (== 223 total) while being wrong about
the number that matters.

Contract locked here (the issue's suggested test 4):
- `write_summary` ALWAYS emits completed / incomplete / errors, so
  `completed + incomplete + errors == total_units` is visible and checkable;
- an incomplete unit does NOT increment `completed` — verified end-to-end
  through the REAL verify_batch and enhance_dataset_agentic flows (stubbed
  model calls, real StepCheckpoint summaries on disk);
- an incomplete verification no longer stamps the false "Changed from X to
  X" note (Stage-1 verdict preserved == X);
- the analyzer callback buckets `inconclusive` / `insufficient_context`
  (stable enum findings) as incomplete, not completed — driven through the
  REAL run_analysis closure (stubbed _run_detection) for both fresh and
  resumed (restore-seeded) runs, and enhance's restore seeding likewise.

Deliberately NOT covered here: experiment.py's harness metric
(verifications_incomplete) — harness-only code the issue itself lists "for
completeness, not as a product defect"; driving run_experiment's verify
stage is disproportionate to a 3-line print-metric change.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.checkpoint import StepCheckpoint  # noqa: E402
from utilities.agentic_enhancer.agent import INCOMPLETE_CLASSIFICATION  # noqa: E402
from utilities.finding_verifier import FindingVerifier, VerificationResult  # noqa: E402
from utilities.llm_client import reset_warning_state  # noqa: E402


def _read_summary(checkpoint_dir: Path) -> dict:
    return json.loads((Path(checkpoint_dir) / "_summary.json").read_text())


# ---------------------------------------------------------------------------
# write_summary — the shared emission (all five sites route through this)
# ---------------------------------------------------------------------------
def test_write_summary_emits_all_three_buckets(tmp_path):
    cp = StepCheckpoint("Verify", str(tmp_path))
    cp.write_summary(10, 4, 2, {"api": 2}, phase="done", incomplete=4)
    s = _read_summary(cp.dir)
    assert s["completed"] == 4
    assert s["incomplete"] == 4
    assert s["errors"] == 2
    assert s["completed"] + s["incomplete"] + s["errors"] == s["total_units"]


def test_write_summary_third_bucket_defaults_visible(tmp_path):
    """Pre-#293 callers (dynamic_tester) omit the kwarg — the bucket still
    appears (0), so every _summary.json has the same shape."""
    cp = StepCheckpoint("Analyze", str(tmp_path))
    cp.write_summary(3, 3, 0, {}, phase="done")
    s = _read_summary(cp.dir)
    assert s["incomplete"] == 0
    assert s["completed"] + s["incomplete"] + s["errors"] == s["total_units"]


# ---------------------------------------------------------------------------
# verify_batch — the runtime-proven site, end-to-end with a real checkpoint
# ---------------------------------------------------------------------------
class _ScriptedVerifier(FindingVerifier):
    """verify_result is scripted per route_key: complete / incomplete / raise."""

    SCRIPT = {}

    def verify_result(self, code, finding, attack_vector, reasoning,
                      files_included=None):
        route = getattr(self, "_current_route", "r:complete")
        behavior = self.SCRIPT[route]
        if behavior == "raise":
            raise RuntimeError("api exploded")
        if behavior == "incomplete":
            return VerificationResult(
                agree=False, correct_finding=finding, explanation="Max iterations reached",
                iterations=20, total_tokens=10, incomplete=True)
        return VerificationResult(
            agree=True, correct_finding=finding, explanation="ok",
            iterations=3, total_tokens=10)


def _verify_binding(tmp_path):
    from utilities.agentic_enhancer.repository_index import RepositoryIndex
    from utilities.llm import PhaseBinding

    class _Adapter:
        name = "anthropic"
        supports_tools = True
        pricing = {}

    binding = PhaseBinding(phase="verify", adapter=_Adapter(), model="m",
                           provider_name="anthropic")
    return binding, RepositoryIndex({}, repo_path=None)


def test_verify_batch_three_bucket_summary(tmp_path, monkeypatch):
    reset_warning_state()
    _ScriptedVerifier.SCRIPT = {
        "r:complete": "complete",
        "r:incomplete": "incomplete",
        "r:error": "raise",
    }
    # _verify_one looks the route up in code_by_route; stamp the current
    # route onto the instance via a wrapper around verify_result is not
    # possible (single method) — key the script off the code argument, which
    # verify_batch passes from code_by_route per unit.
    orig = _ScriptedVerifier.verify_result

    def keyed(self, code, finding, attack_vector, reasoning, files_included=None):
        self._current_route = code
        return orig(self, code, finding, attack_vector, reasoning, files_included)

    monkeypatch.setattr(_ScriptedVerifier, "verify_result", keyed)

    results = [
        {"route_key": "r:complete", "finding": "vulnerable",
         "attack_vector": "a", "reasoning": "r"},
        {"route_key": "r:incomplete", "finding": "vulnerable",
         "attack_vector": "a", "reasoning": "r"},
        {"route_key": "r:error", "finding": "vulnerable",
         "attack_vector": "a", "reasoning": "r"},
    ]
    code_by_route = {r["route_key"]: r["route_key"] for r in results}
    binding, index = _verify_binding(tmp_path)
    verifier = _ScriptedVerifier(index=index, binding=binding)

    cp_dir = tmp_path / "verify_checkpoints"
    cp = StepCheckpoint("Verify", str(tmp_path))
    cp.dir = str(cp_dir)
    verifier.verify_batch(results, code_by_route, workers=1, checkpoint=cp)
    reset_warning_state()

    s = _read_summary(cp_dir)
    assert s["phase"] == "done"
    assert s["total_units"] == 3
    assert s["completed"] == 1, "incomplete must not count as completed"
    assert s["incomplete"] == 1
    assert s["errors"] == 1
    assert s["completed"] + s["incomplete"] + s["errors"] == s["total_units"]

    # the incomplete unit keeps its Stage-1 verdict and a truthful note
    inc = results[1]
    assert inc["finding"] == "vulnerable"
    assert "incomplete" in inc.get("verification_note", "").lower()
    assert "Changed from" not in inc.get("verification_note", "")


def test_verify_restore_counts_incomplete_not_completed(tmp_path, monkeypatch):
    """A resumed run restores an INCOMPLETE checkpoint (verdict present) —
    the seeded summary must put it in the third bucket, not completed."""
    reset_warning_state()
    cp_dir = tmp_path / "verify_checkpoints"
    cp_dir.mkdir()
    # pre-existing checkpoint: incomplete verification WITH a verdict
    (cp_dir / "u1.json").write_text(json.dumps({
        "id": "u1",
        "verification": {"incomplete": True, "correct_finding": "vulnerable"},
        "finding": "vulnerable",
    }))
    # and a completed one
    (cp_dir / "u2.json").write_text(json.dumps({
        "id": "u2",
        "verification": {"agree": True, "correct_finding": "safe"},
        "finding": "safe",
    }))

    results = [
        {"route_key": "u1", "finding": "vulnerable", "attack_vector": "a",
         "reasoning": "r"},
        {"route_key": "u2", "finding": "safe", "attack_vector": "a",
         "reasoning": "r"},
    ]
    binding, index = _verify_binding(tmp_path)
    verifier = FindingVerifier(index=index, binding=binding)

    def _no_new_work(self, code, finding, attack_vector, reasoning,
                     files_included=None):
        raise AssertionError("restored units must not be re-verified")

    monkeypatch.setattr(FindingVerifier, "verify_result", _no_new_work)
    cp = StepCheckpoint("Verify", str(tmp_path))
    cp.dir = str(cp_dir)
    verifier.verify_batch(results, {"u1": "c", "u2": "c"}, workers=1,
                          checkpoint=cp)
    reset_warning_state()

    s = _read_summary(cp_dir)
    assert s["total_units"] == 2
    assert s["completed"] == 1
    assert s["incomplete"] == 1
    assert s["errors"] == 0


# ---------------------------------------------------------------------------
# enhance — end-to-end with the real _update_summary closure
# ---------------------------------------------------------------------------
def test_enhance_three_bucket_summary(tmp_path, monkeypatch):
    reset_warning_state()
    import utilities.context_enhancer as ce

    def fake_enhance(unit, index, binding, tracker, verbose):
        cls = unit["_scripted"]
        if cls == "error":
            raise RuntimeError("enhance exploded")
        unit["agent_context"] = {
            "security_classification": cls,
            "agent_metadata": {"input_tokens": 1, "output_tokens": 1,
                               "cost_usd": 0.0},
        }

    monkeypatch.setattr(ce, "enhance_unit_with_agent", fake_enhance)

    from utilities.llm import PhaseBinding

    class _Adapter:
        name = "anthropic"
        supports_tools = True
        pricing = {}

    binding = PhaseBinding(phase="enhance", adapter=_Adapter(), model="m",
                           provider_name="anthropic")
    enhancer = ce.ContextEnhancer(binding=binding)

    analyzer_out = tmp_path / "a.json"
    analyzer_out.write_text(json.dumps({"results": []}))
    dataset = {"units": [
        {"id": "u1", "code": "x=1", "_scripted": "safe"},
        {"id": "u2", "code": "x=1", "_scripted": INCOMPLETE_CLASSIFICATION},
        {"id": "u3", "code": "x=1", "_scripted": "error"},
    ]}
    cp_dir = tmp_path / "enhance_checkpoints"
    enhancer.enhance_dataset_agentic(
        dataset, analyzer_output_path=str(analyzer_out),
        repo_path=None, workers=1, checkpoint_path=str(cp_dir))
    reset_warning_state()

    s = _read_summary(cp_dir)
    assert s["total_units"] == 3
    assert s["completed"] == 1, "INCOMPLETE_CLASSIFICATION is not a completion"
    assert s["incomplete"] == 1
    assert s["errors"] == 1
    assert s["completed"] + s["incomplete"] + s["errors"] == s["total_units"]


# ---------------------------------------------------------------------------
# analyzer — the REAL run_analysis callback + restore loop, driven with a
# stubbed _run_detection that emits the three states through the callback
# run_analysis itself constructs (the closure under test).
# ---------------------------------------------------------------------------
def test_analyzer_run_analysis_three_bucket_summary(tmp_path, monkeypatch):
    reset_warning_state()
    import core.analyzer as analyzer_mod

    dataset_path = tmp_path / "dataset.json"
    dataset_path.write_text(json.dumps({"units": [
        {"id": "a1", "code": "x=1"},
        {"id": "a2", "code": "x=1"},
        {"id": "a3", "code": "x=1"},
    ]}))
    output_dir = tmp_path / "out"

    # #293 adjudication: "inconclusive" is a first-class COMPLETED verdict
    # (verdict_taxonomy FINDING_VERDICT_ORDER; the Stage-1 prompt's enum) —
    # the analyzer has no third state.
    findings_sequence = ["vulnerable", "inconclusive", "error"]

    def fake_run_detection(units, binding, json_corrector, app_context,
                            workers, checkpoint=None, summary_callback=None):
        # emit the three per-unit states through the REAL closure
        for f in findings_sequence:
            summary_callback(f, usage={"input_tokens": 1,
                                       "output_tokens": 1, "cost_usd": 0.0})
        results = [
            {"unit_id": u["id"], "finding": f, "verdict": f.upper(),
             "confidence": 90, "vulnerabilities": [], "reasoning": "r"}
            for u, f in zip(units, findings_sequence)
        ]
        return results, {r["unit_id"]: "code" for r in results}

    monkeypatch.setattr(analyzer_mod, "_run_detection", fake_run_detection)
    monkeypatch.setattr(analyzer_mod, "_analyze_fingerprint",
                        lambda binding: {"key_digest": "sha256:test"})

    from utilities.llm import PhaseBinding

    class _Adapter:
        name = "anthropic"
        supports_tools = True
        pricing = {}

    class _FakeRegistry:
        def get(self, phase):
            return PhaseBinding(phase=phase, adapter=_Adapter(), model="m",
                                provider_name="anthropic")

    analyzer_mod.run_analysis(
        str(dataset_path), str(output_dir),
        registry=_FakeRegistry(), workers=1)
    reset_warning_state()

    s = _read_summary(output_dir / "analyze_checkpoints")
    assert s["phase"] == "done"
    assert s["total_units"] == 3
    assert s["completed"] == 2, "inconclusive IS a completed verdict (taxonomy)"
    assert s["incomplete"] == 0
    assert s["errors"] == 1
    assert s["completed"] + s["incomplete"] + s["errors"] == s["total_units"]


def test_analyzer_restore_counts_inconclusive_completed(tmp_path, monkeypatch):
    """A resumed analyze run seeds its counters from existing checkpoints —
    a restored inconclusive result seeds COMPLETED (taxonomy adjudication:
    inconclusive is a verdict, not a degenerate no-verdict state)."""
    reset_warning_state()
    import core.analyzer as analyzer_mod

    dataset_path = tmp_path / "dataset.json"
    dataset_path.write_text(json.dumps({"units": [
        {"id": "r1", "code": "x=1"},
        {"id": "r2", "code": "x=1"},
    ]}))
    output_dir = tmp_path / "out"
    cp_dir = output_dir / "analyze_checkpoints"
    cp_dir.mkdir(parents=True)
    # pre-existing checkpoints: one completed, one inconclusive
    (cp_dir / "r1.json").write_text(json.dumps({
        "id": "r1", "result": {"finding": "safe", "verdict": "SAFE"},
        "usage": {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0},
    }))
    (cp_dir / "r2.json").write_text(json.dumps({
        "id": "r2", "result": {"finding": "inconclusive",
                               "verdict": "INCONCLUSIVE"},
        "usage": {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0},
    }))

    def fake_run_detection(units, binding, json_corrector, app_context,
                            workers, checkpoint=None, summary_callback=None):
        # both units restored — the callback must NOT fire for them
        return [{"unit_id": u["id"], "finding": "safe", "verdict": "SAFE",
                 "confidence": 90, "vulnerabilities": [], "reasoning": "r"}
                for u in units], {}

    monkeypatch.setattr(analyzer_mod, "_run_detection", fake_run_detection)
    monkeypatch.setattr(analyzer_mod, "_analyze_fingerprint",
                        lambda binding: {"key_digest": "sha256:test"})

    from utilities.llm import PhaseBinding

    class _Adapter:
        name = "anthropic"
        supports_tools = True
        pricing = {}

    class _FakeRegistry:
        def get(self, phase):
            return PhaseBinding(phase=phase, adapter=_Adapter(), model="m",
                                provider_name="anthropic")

    analyzer_mod.run_analysis(
        str(dataset_path), str(output_dir),
        registry=_FakeRegistry(), workers=1)
    reset_warning_state()

    s = _read_summary(cp_dir)
    assert s["total_units"] == 2
    assert s["completed"] == 2, "restored inconclusive counts completed"
    assert s["incomplete"] == 0
    assert s["errors"] == 0


def test_enhance_restore_buckets_incomplete(tmp_path, monkeypatch):
    """A resumed enhance run seeds its counters from restored agent_context
    — a restored INCOMPLETE_CLASSIFICATION unit seeds bucket 3."""
    reset_warning_state()
    import utilities.context_enhancer as ce

    def _no_new_work(unit, index, binding, tracker, verbose):
        raise AssertionError("restored units must not be re-enhanced")

    monkeypatch.setattr(ce, "enhance_unit_with_agent", _no_new_work)

    from utilities.llm import PhaseBinding

    class _Adapter:
        name = "anthropic"
        supports_tools = True
        pricing = {}

    binding = PhaseBinding(phase="enhance", adapter=_Adapter(), model="m",
                           provider_name="anthropic")
    enhancer = ce.ContextEnhancer(binding=binding)

    dataset = {"units": [
        {"id": "e1", "code": "x=1"},
        {"id": "e2", "code": "x=1"},
    ]}
    cp_dir = tmp_path / "enhance_checkpoints"
    cp_dir.mkdir()
    # checkpoint files keyed by id; _load_completed_units counts them
    # completed when agent_context present with no error
    (cp_dir / "e1.json").write_text(json.dumps({
        "id": "e1",
        "agent_context": {"security_classification": "safe"},
    }))
    (cp_dir / "e2.json").write_text(json.dumps({
        "id": "e2",
        "agent_context": {"security_classification":
                          INCOMPLETE_CLASSIFICATION},
    }))

    analyzer_out = tmp_path / "a.json"
    analyzer_out.write_text(json.dumps({"results": []}))
    enhancer.enhance_dataset_agentic(
        dataset, analyzer_output_path=str(analyzer_out),
        repo_path=None, workers=1, checkpoint_path=str(cp_dir))
    reset_warning_state()

    s = _read_summary(cp_dir)
    assert s["total_units"] == 2
    assert s["completed"] == 1
    assert s["incomplete"] == 1, "restored INCOMPLETE seeds bucket 3"
    assert s["errors"] == 0


# ---------------------------------------------------------------------------
# Wave catches (adjudicated): the severity-upgrade fail-safe, status(), the
# enhance retry flip, and units_enhanced.
# ---------------------------------------------------------------------------
def test_incomplete_preserves_severity_upgrade_fail_safe(tmp_path, monkeypatch):
    """FAM-REPORT-2: the self-contradictory-finish path returns
    incomplete=True with correct_finding = the MORE-SEVERE verdict. The
    incomplete branch must propagate it — not propagating silently drops
    the upgraded vuln at the reporter's disclosure filter."""
    reset_warning_state()

    class _UpgradeVerifier(FindingVerifier):
        def verify_result(self, code, finding, attack_vector, reasoning,
                          files_included=None):
            return VerificationResult(
                agree=False, correct_finding="vulnerable",
                explanation="self-contradictory finish",
                iterations=5, total_tokens=10, incomplete=True)

    from utilities.agentic_enhancer.repository_index import RepositoryIndex
    from utilities.llm import PhaseBinding

    class _Adapter:
        name = "anthropic"
        supports_tools = True
        pricing = {}

    binding = PhaseBinding(phase="verify", adapter=_Adapter(), model="m",
                           provider_name="anthropic")
    verifier = _UpgradeVerifier(index=RepositoryIndex({}, repo_path=None),
                                binding=binding)
    result = {"route_key": "r:up", "finding": "safe", "attack_vector": "a",
              "reasoning": "r"}
    out = verifier._verify_one(result, {"r:up": "code"})
    reset_warning_state()
    assert out[1].startswith("incomplete:")
    assert result["finding"] == "vulnerable", (
        "the upgraded (more severe) verdict must propagate on incomplete")
    assert "Changed from" not in result.get("verification_note", "")


def test_status_classifies_three_states(tmp_path):
    """StepCheckpoint.status() — the Go CLI resume path's single source of
    truth — must classify incomplete checkpoints into the third bucket, not
    completed (the issue's 175-of-223 headline number surfaces exactly
    here, in the resume prompt)."""
    from core.checkpoint import StepCheckpoint as SC

    d = tmp_path / "verify_checkpoints"
    d.mkdir()
    (d / "c1.json").write_text(json.dumps({
        "id": "c1",
        "verification": {"agree": True, "correct_finding": "vulnerable"},
        "finding": "vulnerable"}))
    (d / "i1.json").write_text(json.dumps({
        "id": "i1",
        "verification": {"incomplete": True, "correct_finding": "vulnerable"},
        "finding": "vulnerable"}))
    (d / "e1.json").write_text(json.dumps({
        "id": "e1",
        "verification": {"incomplete": True},
        "error": "RuntimeError: api exploded"}))
    st = SC.status(str(d))
    assert st["completed"] == 1
    assert st["incomplete"] == 1
    assert st["errors"] == 1
    assert st["total_files"] == 3


def test_status_enhance_style_incomplete(tmp_path):
    from core.checkpoint import StepCheckpoint as SC

    d = tmp_path / "enhance_checkpoints"
    d.mkdir()
    (d / "h1.json").write_text(json.dumps({
        "id": "h1", "agent_context": {"security_classification": "safe"}}))
    (d / "h2.json").write_text(json.dumps({
        "id": "h2", "agent_context": {"security_classification": "incomplete"}}))
    st = SC.status(str(d))
    assert st["completed"] == 1
    assert st["incomplete"] == 1
    assert st["errors"] == 0


def test_enhance_retry_landing_incomplete_counts_incomplete(tmp_path, monkeypatch):
    """The auto-retry loop: a retried unit that lands on the agent's
    degenerate exit flips its error into the incomplete bucket, not
    completed (wave catch #4)."""
    reset_warning_state()
    import utilities.context_enhancer as ce
    from utilities.llm import LLMRateLimitError

    calls = {"n": 0}

    def flaky_then_incomplete(unit, index, binding, tracker, verbose):
        calls["n"] += 1
        if calls["n"] == 1:
            # rate_limit is retryable on BOTH is_retryable_error branches
            # (this test pins the retry-loop BUCKETING, not #292's
            # empty-completion dict classification)
            raise LLMRateLimitError("rate limited", retry_after=0)
        unit["agent_context"] = {
            "security_classification": INCOMPLETE_CLASSIFICATION,
            "agent_metadata": {"input_tokens": 1, "output_tokens": 1,
                               "cost_usd": 0.0},
        }

    monkeypatch.setattr(ce, "enhance_unit_with_agent", flaky_then_incomplete)

    from utilities.llm import PhaseBinding

    class _Adapter:
        name = "anthropic"
        supports_tools = True
        pricing = {}

    binding = PhaseBinding(phase="enhance", adapter=_Adapter(), model="m",
                           provider_name="anthropic")
    enhancer = ce.ContextEnhancer(binding=binding)

    analyzer_out = tmp_path / "a.json"
    analyzer_out.write_text(json.dumps({"results": []}))
    dataset = {"units": [{"id": "f1", "code": "x=1"}]}
    cp_dir = tmp_path / "enhance_checkpoints"
    enhancer.enhance_dataset_agentic(
        dataset, analyzer_output_path=str(analyzer_out),
        repo_path=None, workers=1, checkpoint_path=str(cp_dir))
    reset_warning_state()

    s = _read_summary(cp_dir)
    assert s["total_units"] == 1
    assert s["completed"] == 0, "retry landing on incomplete is not completed"
    assert s["incomplete"] == 1
    assert s["errors"] == 0, "the error flipped out on successful retry"
    assert calls["n"] == 2, "the retryable error must have been retried"


def test_units_enhanced_excludes_incomplete(tmp_path, monkeypatch):
    """core/enhancer's EnhanceResult.units_enhanced must not count the
    agent's degenerate exits as enhanced (wave catch #5) — driven through
    the REAL enhance_dataset tail with the agentic loop stubbed."""
    import core.enhancer as enh_mod

    def fake_agentic(self, dataset, analyzer_output_path, repo_path=None,
                     batch_size=5, verbose=False, checkpoint_path=None,
                     progress_callback=None, restored_callback=None,
                     workers=10, phase_baseline=None):
        dataset["units"] = [
            {"id": "u1", "agent_context": {"security_classification": "safe"}},
            {"id": "u2", "agent_context": {"security_classification":
                                           INCOMPLETE_CLASSIFICATION}},
            {"id": "u3", "agent_context": {"security_classification": "safe",
                                           "error": {"type": "api"}}},
        ]
        return dataset

    monkeypatch.setattr(
        "utilities.context_enhancer.ContextEnhancer.enhance_dataset_agentic",
        fake_agentic)

    from utilities.llm import PhaseBinding

    class _Adapter:
        name = "anthropic"
        supports_tools = True
        pricing = {}

    class _FakeRegistry:
        def get(self, phase):
            return PhaseBinding(phase=phase, adapter=_Adapter(), model="m",
                                provider_name="anthropic")

    dataset_path = tmp_path / "dataset.json"
    dataset_path.write_text(json.dumps({"units": [
        {"id": "u1", "code": "x"}, {"id": "u2", "code": "x"},
        {"id": "u3", "code": "x"},
    ]}))
    analyzer_out = tmp_path / "a.json"
    analyzer_out.write_text(json.dumps({"results": []}))
    output_path = tmp_path / "enhanced.json"

    result = enh_mod.enhance_dataset(
        str(dataset_path), str(output_path),
        analyzer_output_path=str(analyzer_out), repo_path=str(tmp_path),
        mode="agentic", workers=1, registry=_FakeRegistry())
    assert result.units_enhanced == 1, (
        "1 of 3 units was genuinely enhanced (1 error, 1 incomplete)")
    assert result.error_count == 1
    assert result.classifications.get(INCOMPLETE_CLASSIFICATION) == 1
