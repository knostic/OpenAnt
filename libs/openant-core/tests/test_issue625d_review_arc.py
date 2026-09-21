"""#625 hardening from the pre-merge review arc: the fatal
thinking-rejection path (a 400 naming thinking must abort the phase,
never become per-unit ERROR rows), the per-step dropped-block DELTAS,
the installed-SDK capability floor, and the verifier/llm-reach
fingerprint folds (deleting either fold previously survived the whole
625 battery while enabling stale cross-policy adoption)."""
import inspect
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import anthropic as _anthropic_sdk  # noqa: E402

from utilities.llm.adapter import (  # noqa: E402
    LLMResponseError,
    Message,
    TextBlock,
    ThinkingPolicyRejectedError,
)
from utilities.llm.registry import PhaseBinding  # noqa: E402

_USER_MSG = [Message(role="user", content=[TextBlock(text="hi")])]


# --- the fatal 400 --------------------------------------------------------


def _adapter_with(thinking, status=400, message="thinking is not supported"):
    """A real AnthropicAdapter whose SDK raises the scripted APIStatusError."""
    import utilities.llm.providers.anthropic as anth

    a = anth.AnthropicAdapter(
        api_key="dummy-key", thinking=thinking)
    exc = _anthropic_sdk.APIStatusError(
        message, response=MagicMock(
            status_code=status,
            headers={"retry-after": "0"},
            request=MagicMock()),
        body=None)
    a._client.messages.create = MagicMock(side_effect=exc)
    return a


def test_rejected_policy_400_is_fatal_not_per_unit():
    a = _adapter_with({"type": "adaptive"})
    try:
        a.complete(model="m", system=None, max_tokens=100,
                   messages=_USER_MSG)
    except ThinkingPolicyRejectedError as e:
        assert "rejected the configured thinking policy" in str(e)
    else:
        raise AssertionError("a thinking-named 400 must be fatal")
    a._client.messages.create.assert_called_once()


def test_rejected_policy_400_with_disabled_policy_is_fatal_too():
    a = _adapter_with({"type": "disabled"})
    try:
        a.complete(model="m", system=None, max_tokens=100,
                   messages=_USER_MSG)
    except ThinkingPolicyRejectedError:
        pass
    else:
        raise AssertionError("disabled rides the request; its rejection "
                             "is equally policy-caused")


def test_unrelated_400_stays_response_error():
    a = _adapter_with({"type": "adaptive"}, message="max_tokens too large")
    try:
        a.complete(model="m", system=None, max_tokens=100,
                   messages=_USER_MSG)
    except ThinkingPolicyRejectedError:
        raise AssertionError("a 400 not naming thinking is NOT policy-fatal")
    except LLMResponseError:
        pass


def test_thinking_named_400_without_policy_stays_response_error():
    a = _adapter_with(None)
    try:
        a.complete(model="m", system=None, max_tokens=100,
                   messages=_USER_MSG)
    except ThinkingPolicyRejectedError:
        raise AssertionError("no configured policy → not policy-fatal")
    except LLMResponseError:
        pass


def test_process_unit_lets_the_rejection_escape():
    """The per-unit catch-all must NOT convert the rejection into an
    ERROR row — the phase handler needs it (the exit-0 green shape)."""
    from core import analyzer as analyzer_mod

    class _Boom:
        name = "fake"

        def complete(self, **kw):
            raise ThinkingPolicyRejectedError("provider said no")

    binding = PhaseBinding(phase="analyze", adapter=_Boom(), model="m",
                           provider_name="p")
    try:
        analyzer_mod._process_unit(
            binding, {"id": "u", "finding": "vulnerable"}, 0,
            MagicMock(), None)
    except ThinkingPolicyRejectedError:
        pass
    else:
        raise AssertionError("the rejection must escape _process_unit")


# --- the per-step dropped-block deltas ------------------------------------


def test_dropped_blocks_are_per_step_deltas(tmp_path):
    from core.step_report import step_context
    from utilities.llm_client import reset_warning_state
    from utilities.llm.providers.anthropic import _count_dropped_block

    reset_warning_state()
    out = str(tmp_path)

    with step_context("one", out, inputs={}) as ctx:
        ctx.summary = {}

    with step_context("two", out, inputs={}) as ctx:
        ctx.summary = {}
        _count_dropped_block("thinking")
        _count_dropped_block("thinking")
        _count_dropped_block("refusal")

    one = json.loads(Path(out, "one.report.json").read_text())
    two = json.loads(Path(out, "two.report.json").read_text())
    assert one["token_usage"].get("dropped_blocks") is None, (
        "a step with no drops carries no key")
    assert two["token_usage"]["dropped_blocks"] == {
        "thinking": 2, "refusal": 1}, (
        "the step carries ONLY its own drops — the run-cumulative "
        "prefix must not leak into later steps")

    with step_context("three", out, inputs={}) as ctx:
        ctx.summary = {}
        _count_dropped_block("thinking")
    with step_context("four", out, inputs={}) as ctx:
        ctx.summary = {}
    four = json.loads(Path(out, "four.report.json").read_text())
    assert four["token_usage"].get("dropped_blocks") is None, (
        "zero-delta steps carry no key even after earlier drops")
    three = json.loads(Path(out, "three.report.json").read_text())
    assert three["token_usage"]["dropped_blocks"] == {"thinking": 1}


# --- the SDK capability floor ---------------------------------------------


def test_installed_sdk_supports_the_thinking_kwarg():
    """The declared floor (pyproject >=0.47.0) exists because the kwarg
    does not exist before it — every call would TypeError per-unit."""
    sig = inspect.signature(
        _anthropic_sdk.Anthropic(api_key="dummy").messages.create)
    assert "thinking" in sig.parameters, (
        f"installed anthropic SDK {_anthropic_sdk.__version__} predates "
        "the thinking kwarg (requires >=0.47.0)")


# --- the verifier / llm-reach fingerprint folds ---------------------------


def _binding(phase, thinking):
    class _A:
        name = "fake"

        def complete(self, **kw):
            raise AssertionError("not called")
    return PhaseBinding(phase=phase, adapter=_A(), model="m",
                        provider_name="p", base_url=None, thinking=thinking)


def test_verifier_fold_present_and_digest_sensitive():
    """The verifier fold is load-bearing: deleting it lets resumed runs
    adopt checkpoints produced under a DIFFERENT policy (executed in the
    review arc: SDK calls 2→0 with stale adoption). The source-presence
    half is what catches that deletion; the digest half pins the
    mechanism."""
    import core.verifier as verifier_mod
    src = inspect.getsource(verifier_mod)
    assert '"thinking": dict(verify_binding.thinking)' in src, (
        "the verify checkpoint fold must stay wired")
    from core.backend_identity import fingerprint_for_binding
    texts = ["t1"]
    d_none = fingerprint_for_binding(
        _binding("verify", None), texts, extra_key={})
    d_set = fingerprint_for_binding(
        _binding("verify", {"type": "disabled"}), texts,
        extra_key={"thinking": {"type": "disabled"}})
    assert d_none["key_digest"] != d_set["key_digest"], (
        "a policy change must invalidate verify checkpoints")


def test_llm_reach_fold_present_and_digest_sensitive():
    import core.llm_reachability as llr_mod
    src = inspect.getsource(llr_mod)
    assert '"thinking": dict(binding.thinking)' in src, (
        "the llm-reach checkpoint fold must stay wired")
    from core.backend_identity import fingerprint_for_binding
    texts = ["t1"]
    d_none = fingerprint_for_binding(
        _binding("llm_reach", None), texts, extra_key={})
    d_set = fingerprint_for_binding(
        _binding("llm_reach", {"type": "adaptive"}), texts,
        extra_key={"thinking": {"type": "adaptive"}})
    assert d_none["key_digest"] != d_set["key_digest"], (
        "a policy change must invalidate llm-reachability checkpoints")
