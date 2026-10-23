import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# module-level imports go adapter-DIRECT (never through utilities/llm/__init__):
# the battery file must COLLECT even at a tree where the __init__'s own
# LLMConfigError import breaks (the class-definition revert) — the deferred
# in-test imports then fail INSIDE the running tests, which is the behavioral
# red the fix-linkage measures (the #646 class-import pattern, extended).
from utilities.llm.adapter import (  # noqa: E402
    LLMAuthError,
    Message,
    TextBlock,
    ToolDef,
)


def _config_error_class():
    """Deferred import of the NEW class: the battery file must COLLECT at
    pristine base (the #696 witness-screen law — the red_gate's overlay runs
    the head's tests on base), so a symbol that does not exist there is
    imported INSIDE the tests: at base the node EXECUTES and fails on the
    ImportError (assertion-equivalent red); at head it resolves."""
    from utilities.llm import LLMConfigError
    return LLMConfigError


# ---------------------------------------------------------------------------
# The issue's executed repro, as the permanent battery: the analyze stage's
# per-unit catch-all converts the designed-abort classes into per-unit ERROR
# rows while the envelope reads success and the CLI exits 0. The llm_reachability
# stage is the parity anchor: LLMAuthError is re-raised BY DESIGN ("Auth
# failures are fatal and recur on every batch — surface them instead of
# burying them as a per-batch 'failed' line").
# ---------------------------------------------------------------------------


def _make_unit(unit_id="u1"):
    return {"id": unit_id, "code": {"primary_code": "x = 1\n"}}


def test_issue696_auth_error_reraises_never_error_row(monkeypatch):
    """An auth failure must abort the phase (the parity anchor), never become
    a per-unit ERROR row while the run reads green."""
    import core.analyzer as A

    def raise_auth(*args, **kwargs):
        raise LLMAuthError("invalid x-api-key")

    monkeypatch.setattr(A, "analyze_unit", raise_auth)
    with pytest.raises(LLMAuthError):
        A._process_unit(None, _make_unit(), 0, None, None)


def test_issue696_thinking_policy_refusal_reraises(monkeypatch):
    """The rejected thinking policy (the thinking+tools refusal) is a config
    error that recurs on every unit — it must abort the phase, never convert
    to per-unit ERROR."""
    import core.analyzer as A

    LLMConfigError = _config_error_class()

    def raise_policy(*args, **kwargs):
        raise LLMConfigError(
            "AnthropicAdapter refuses thinking+tools: thinking blocks must be "
            "preserved on the echoed assistant turn for multi-turn tool "
            "loops, and this adapter's loop echo does not carry them "
            "(iteration 2 would fail after iteration 1 is billed). "
            'Remove `thinking` from the provider entry for tool-using '
            'phases, or set it to {"type": "disabled"}.'
        )

    monkeypatch.setattr(A, "analyze_unit", raise_policy)
    with pytest.raises(LLMConfigError):
        A._process_unit(None, _make_unit(), 0, None, None)


def test_issue696_generic_unit_error_stays_per_unit(monkeypatch):
    """The ordinary per-unit failure stays per-unit (the catch-all's purpose):
    a single unit's model-format hiccup is a recoverable ERROR row."""
    import core.analyzer as A

    def raise_value(*args, **kwargs):
        raise ValueError("one unit's malformed payload")

    monkeypatch.setattr(A, "analyze_unit", raise_value)
    out = A._process_unit(None, _make_unit(), 0, None, None)
    assert out["result"]["verdict"] == "ERROR"
    assert "malformed payload" in out["result"]["error"]


def test_issue696_all_fatal_phase_aborts_not_green(monkeypatch, tmp_path):
    """THE ISSUE'S HEADLINE: a scan in which EVERY unit failed must not be
    indistinguishable from a clean scan. With every unit raising the auth
    error, the phase must abort (raise), never return a results list that
    reads green."""
    import core.analyzer as A

    def raise_auth(*args, **kwargs):
        raise LLMAuthError("invalid x-api-key")

    monkeypatch.setattr(A, "analyze_unit", raise_auth)
    # drive the phase's OWN parallel executor loop (the run_analysis wrapper
    # probes the provider at startup — the #646 validate — which is network
    # and out of scope here; the loop is where a raised unit error must
    # abort the phase rather than collect ERROR rows and read green)
    units = [_make_unit(f"u{i}") for i in range(3)]
    with pytest.raises(LLMAuthError):
        A._run_detection(
            units, binding=None, json_corrector=None, app_context=None, workers=2,
        )


def test_issue696_thinking_budget_preflight():
    """Trigger 3: a thinking budget >= the call's max_tokens must be refused
    BEFORE messages.create (the Anthropic contract: the budget must leave
    room for the response) — as a config error, never a billed failure."""
    from utilities.llm.providers.anthropic import AnthropicAdapter
    LLMConfigError = _config_error_class()

    adapter = AnthropicAdapter(
        api_key="test-key",
        thinking={"type": "enabled", "budget_tokens": 2000},
    )
    with pytest.raises(LLMConfigError, match="budget_tokens"):
        adapter.complete(
            model="claude-3-5-sonnet",
            system=None,
            messages=[Message(role="user", content=[TextBlock("hi")])],
            max_tokens=1000,
        )


def test_issue696_thinking_tools_refusal_is_config_error():
    """The thinking+tools refusal raises the CONFIG class (the discriminator
    the analyze stage keys its abort on), not the per-unit response class."""
    from utilities.llm.providers.anthropic import AnthropicAdapter
    LLMConfigError = _config_error_class()

    adapter = AnthropicAdapter(
        api_key="test-key",
        thinking={"type": "enabled", "budget_tokens": 1024},
    )
    with pytest.raises(LLMConfigError, match="refuses thinking\\+tools"):
        adapter.complete(
            model="claude-3-5-sonnet",
            system=None,
            messages=[Message(role="user", content=[TextBlock("hi")])],
            max_tokens=4096,
            tools=[ToolDef(name="t", description="d", input_schema={})],
        )


def test_issue696_bedrock_budget_preflight():
    """The fable-hunt sibling catch: the bedrock adapter mirrors the
    anthropic budget preflight — budget_tokens >= max_tokens is refused
    up front as a config error, never billed-then-rejected."""
    from utilities.llm.providers.bedrock import BedrockAdapter
    LLMConfigError = _config_error_class()

    adapter = BedrockAdapter(
        _client=object(),  # the region-free stub: the preflight fires first
        thinking={"type": "enabled", "budget_tokens": 2000})
    with pytest.raises(LLMConfigError, match="budget_tokens"):
        adapter.complete(
            model="anthropic.claude-3-5-sonnet",
            system=None,
            messages=[Message(role="user", content=[TextBlock("hi")])],
            max_tokens=1000,
        )


def test_issue696_bedrock_thinking_tools_refusal_is_config_error():
    """The bedrock thinking+tools refusal raises the same config class
    (the designed-abort discriminator), never the per-unit class."""
    from utilities.llm.providers.bedrock import BedrockAdapter
    LLMConfigError = _config_error_class()

    adapter = BedrockAdapter(
        _client=object(),
        thinking={"type": "enabled", "budget_tokens": 1024})
    with pytest.raises(LLMConfigError, match="refuses thinking\\+tools"):
        adapter.complete(
            model="anthropic.claude-3-5-sonnet",
            system=None,
            messages=[Message(role="user", content=[TextBlock("hi")])],
            max_tokens=4096,
            tools=[ToolDef(name="t", description="d", input_schema={})],
        )


def test_issue696_abort_drains_the_pool(monkeypatch):
    """The fable-hunt zombie catch: a designed-abort re-raise must cancel
    the pending units (each a doomed API call against the same bad key) —
    the abort path mirrors the KI arm's shutdown(cancel_futures=True)."""
    import threading
    import core.analyzer as A

    fired = threading.Event()

    class _UnitFuture:
        def result(self):
            raise LLMAuthError("invalid x-api-key")

    class _RecordingExecutor:
        def __init__(self, max_workers=None):
            pass

        def submit(self, fn, *a):
            return _UnitFuture()

        def shutdown(self, wait=False, cancel_futures=False):
            if cancel_futures:
                fired.set()

    monkeypatch.setattr(A, "ThreadPoolExecutor", _RecordingExecutor)
    monkeypatch.setattr(
        A, "as_completed", lambda futures: iter(list(futures)))
    units = [_make_unit(f"u{i}") for i in range(2)]
    with pytest.raises(LLMAuthError):
        A._run_detection(units, binding=None, json_corrector=None,
                         app_context=None, workers=2)
    assert fired.is_set(), "the abort path never cancelled the pool"
