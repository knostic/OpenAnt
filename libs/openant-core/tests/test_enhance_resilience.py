"""Regression tests for enhance/analyzer resilience fixes.

Covers four confirmed bugs:

  - is_retryable_error() string branch omits "529" and "overloaded" ->
    Anthropic-overloaded errors never retried on the analyzer detection path
    (which feeds str(e), not a dict).
  - agentic post-loop transient-error retry was a single pass; a unit that
    fails again on the one retry is never re-attempted.
  - single-shot enhance_dataset had no checkpoint/resume, so a --checkpoint path
    was silently dropped and an interrupted run reprocessed every unit.
  - single-shot enhance writes only llm_context
    (no agent_context.security_classification), so --exploitable-only/all
    silently dropped every single-shot unit with no operator signal.

No external network: ContextEnhancer.enhance_unit is monkeypatched.
"""
import os

import pytest

from utilities.rate_limiter import is_retryable_error


@pytest.fixture(autouse=True)
def _anthropic_api_key(monkeypatch):
    """Provide a dummy API key for parity with real runs. No network call is
    made: every test monkeypatches the actual enhancement methods, and the
    ContextEnhancer is handed a fake PhaseBinding whose adapter is never
    exercised, so no SDK client ever issues a request."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-key")


class _FakeAdapter:
    """Minimal LLMAdapter stand-in. Never called: these tests monkeypatch the
    enhancement entry points, so the binding's adapter is inert."""

    name = "anthropic"
    supports_tools = True

    def complete(self, *, model, system, messages, max_tokens, tools=None):  # pragma: no cover
        raise AssertionError("adapter.complete must not be called in these tests")

    def validate(self, model):  # pragma: no cover
        pass


def _fake_binding():
    """Build a PhaseBinding the post-#69 ContextEnhancer requires.

    Mirrors the canonical helper in tests/test_llm_helpers.py: a frozen
    PhaseBinding wrapping a fake adapter, used wherever a real (provider,
    model) binding would otherwise be needed.
    """
    from utilities.llm import PhaseBinding

    return PhaseBinding(
        phase="enhance",
        adapter=_FakeAdapter(),
        model="claude-test",
        provider_name="anthropic",
    )


# --------------------------------------------------------------------------
# 529 / overloaded must be retryable via the string branch.
# --------------------------------------------------------------------------
class TestIsRetryable529:
    def test_529_overloaded_string_is_retryable(self):
        # The exact shape the Anthropic SDK stringifies a 529 into. The
        # analyzer detection path stores str(e), forcing the string branch.
        err = "Error code: 529 - {'type': 'error', 'error': {'type': 'overloaded_error', 'message': 'Overloaded'}}"
        assert is_retryable_error(err) is True

    def test_overloaded_word_alone_is_retryable(self):
        assert is_retryable_error("server overloaded, try again") is True

    def test_existing_5xx_strings_still_retryable(self):
        for code in ("500", "502", "503", "504"):
            assert is_retryable_error(f"Error code: {code} - server error") is True

    def test_client_error_400_still_not_retryable(self):
        # Guard against over-broadening: a 400 must remain non-retryable.
        assert is_retryable_error("Error code: 400 - bad request") is False

    def test_structured_529_dict_still_retryable(self):
        assert is_retryable_error({"type": "api_status", "status_code": 529}) is True


# --------------------------------------------------------------------------
# Shared helpers for the ContextEnhancer-level tests.
# --------------------------------------------------------------------------
def _make_enhancer():
    from utilities.context_enhancer import ContextEnhancer

    return ContextEnhancer(binding=_fake_binding(), tracker=None)


def _dataset(n=3):
    return {"units": [{"id": f"u{i}", "code": f"def f{i}(): pass"} for i in range(n)]}


# --------------------------------------------------------------------------
# agentic retry must be a bounded multi-round loop.
# --------------------------------------------------------------------------
class TestAgenticBoundedRetry:
    def test_unit_failing_on_first_retry_is_retried_again(self, monkeypatch, tmp_path):
        """A transient error that persists for one retry must get another round
        (up to the cap), instead of being abandoned after a single pass."""
        from unittest.mock import MagicMock

        from utilities import context_enhancer as ce

        enh = _make_enhancer()
        # Avoid building a real repository index (no analyzer output / repo).
        fake_index = MagicMock()
        fake_index.get_statistics.return_value = {
            "total_functions": 0, "total_files": 0,
        }
        monkeypatch.setattr(ce, "load_index_from_file", lambda *a, **k: fake_index)

        # attempts[uid] = how many times we've enhanced that unit.
        attempts = {}

        def fake_agent(unit, index, binding, tracker, verbose):
            uid = unit.get("id")
            attempts[uid] = attempts.get(uid, 0) + 1
            # u1 stays transiently-broken for the first 2 attempts, then succeeds.
            if uid == "u1" and attempts[uid] < 3:
                unit["agent_context"] = {
                    "error": {"type": "api_status", "status_code": 529},
                    "security_classification": "neutral",
                    "confidence": 0.0,
                }
            else:
                unit["agent_context"] = {
                    "security_classification": "neutral",
                    "confidence": 0.5,
                }

        monkeypatch.setattr(ce, "enhance_unit_with_agent", fake_agent)

        ds = _dataset(2)
        result = enh.enhance_dataset_agentic(
            dataset=ds,
            analyzer_output_path=None,
            repo_path=None,
            workers=1,
        )

        # With a bounded multi-round retry, u1 is attempted 3 times total
        # (initial + 2 retry rounds) and ends without an error.
        u1 = next(u for u in result["units"] if u["id"] == "u1")
        assert attempts["u1"] >= 3, f"u1 only attempted {attempts['u1']}x (single-pass retry bug)"
        assert not u1.get("agent_context", {}).get("error"), "u1 still errored after bounded retry"


# --------------------------------------------------------------------------
# single-shot enhance must support checkpoint/resume.
# --------------------------------------------------------------------------
class TestSingleShotCheckpoint:
    def test_enhance_dataset_accepts_checkpoint_path(self, monkeypatch, tmp_path):
        """Single-shot enhance_dataset must accept a checkpoint dir and persist
        per-unit results so an interrupted run can resume."""
        from utilities.context_enhancer import ContextEnhancer

        enh = ContextEnhancer(binding=_fake_binding(), tracker=None)

        def fake_enhance_unit(unit, units_by_id):
            unit["llm_context"] = {
                "reasoning": "ok",
                "confidence": 0.9,
                "security_classification": "neutral",
            }
            return unit

        monkeypatch.setattr(enh, "enhance_unit", fake_enhance_unit)

        cp_dir = str(tmp_path / "enhance_checkpoints")
        enh.enhance_dataset(_dataset(3), workers=1, checkpoint_path=cp_dir)

        files = [f for f in os.listdir(cp_dir) if f.endswith(".json")]
        assert len(files) == 3, f"expected 3 per-unit checkpoints, found {files}"

    def test_resume_skips_already_completed_units(self, monkeypatch, tmp_path):
        """On resume, units already checkpointed must not be re-enhanced."""
        from utilities.context_enhancer import ContextEnhancer

        cp_dir = str(tmp_path / "enhance_checkpoints")

        # First run: complete all units.
        enh1 = ContextEnhancer(binding=_fake_binding(), tracker=None)
        monkeypatch.setattr(
            enh1, "enhance_unit",
            lambda unit, by_id: unit.update(
                {"llm_context": {"reasoning": "ok", "confidence": 0.9}}
            ) or unit,
        )
        enh1.enhance_dataset(_dataset(3), workers=1, checkpoint_path=cp_dir)

        # Second run: count how many units get (re-)enhanced.
        enh2 = ContextEnhancer(binding=_fake_binding(), tracker=None)
        seen = []

        def counting_enhance(unit, by_id):
            seen.append(unit.get("id"))
            unit["llm_context"] = {"reasoning": "ok", "confidence": 0.9}
            return unit

        monkeypatch.setattr(enh2, "enhance_unit", counting_enhance)
        enh2.enhance_dataset(_dataset(3), workers=1, checkpoint_path=cp_dir)

        assert seen == [], f"resume re-enhanced units that were already done: {seen}"


# --------------------------------------------------------------------------
# exploitable filter must not silently drop single-shot units.
# --------------------------------------------------------------------------
class TestExploitableFilterSingleShot:
    def test_filter_reads_llm_context_classification_fallback(self):
        """The analyzer exploitable filter must fall back to llm_context's
        security_classification when agent_context is absent (single-shot)."""
        from core.analyzer import _unit_security_classification

        # single-shot unit: classification lives under llm_context
        u = {"id": "x", "llm_context": {"security_classification": "exploitable"}}
        assert _unit_security_classification(u) == "exploitable"

        # agentic unit: classification under agent_context still works
        a = {"id": "y", "agent_context": {"security_classification": "vulnerable_internal"}}
        assert _unit_security_classification(a) == "vulnerable_internal"

        # no classification anywhere
        assert _unit_security_classification({"id": "z"}) is None
