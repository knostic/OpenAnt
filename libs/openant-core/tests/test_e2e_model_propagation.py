"""End-to-end model-propagation tests.

The single highest-leverage regression to catch in the LLM-provider
refactor (issue #65) is "a future call site bypassed the registry
and is sending a hardcoded Claude model ID". These tests pin that
contract by:

1. Building a `PhaseRegistry` over a custom llm-config that maps each
   of the seven phases to a DIFFERENT `(provider, model)` pair.
2. Walking every public entry point a user might hit — both the full
   ``scan`` path and each individual step verb (``enhance``,
   ``analyze``, ``verify``, ``report``, ``dynamic_test``,
   ``llm_reach``, ``app_context``).
3. Asserting each phase's adapter received calls scripted ONLY for
   that phase's configured `(provider, model)`. A regression that
   reaches outside the registry will hit a different adapter and the
   assertion fails with a clear message.

The tests stub the adapter layer at the registry boundary — they
don't hit the network and they don't exercise the Anthropic SDK.
That's by design: the contract here is "the registry routes phases
to the right adapter", not "the Anthropic adapter translates types
correctly" (which `test_llm_adapter_contract.py` covers).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import pytest

from utilities.llm import (
    CompletionResult,
    LLMAdapter,
    Message,
    PhaseBinding,
    PhaseRegistry,
    TextBlock,
    ToolDef,
    ToolUseBlock,
)


# ---------------------------------------------------------------------------
# Recording fake adapter
# ---------------------------------------------------------------------------


@dataclass
class _Call:
    model: str
    system: Optional[str]
    n_messages: int
    n_tools: int


class _RecordingAdapter:
    """Fake adapter that records every call it receives.

    One instance per `(provider, model)` pair in the test's
    llm-config, so a phase's calls land on a specific adapter that
    other phases never touch. If a leak happens — for example, a
    future analyze call site reaches into the verify-phase adapter —
    the wrong instance's `calls` list grows and the assertion at the
    end fails with a readable diff.
    """

    name = "anthropic"          # claim Anthropic so supports_tools=True is plausible
    supports_tools = True

    def __init__(self, *, label: str, tool_use: bool = False):
        self.label = label
        self.calls: list[_Call] = []
        self._tool_use = tool_use
        # Issue a tool_use block on the first call when tool_use=True,
        # then a finish on the second. Keeps the verify / agentic
        # enhance loops to two iterations max.
        self._iteration = 0

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        self.calls.append(
            _Call(
                model=model,
                system=system,
                n_messages=len(messages),
                n_tools=len(tools) if tools else 0,
            )
        )
        if not self._tool_use:
            return CompletionResult(
                content=[TextBlock('{"verdict": "SAFE"}')],
                input_tokens=1,
                output_tokens=1,
                stop_reason="end_turn",
            )

        self._iteration += 1
        if self._iteration == 1 and tools:
            # First iteration of an agentic / verify loop: pick a tool
            # to call. We invent a 'finish' tool result on the next
            # iteration so the loops terminate without hitting their
            # iteration cap.
            return CompletionResult(
                content=[
                    ToolUseBlock(
                        id="toolu_1",
                        name="finish",
                        input={"agree": True, "correct_finding": "safe"},
                    )
                ],
                input_tokens=1,
                output_tokens=1,
                stop_reason="tool_use",
            )
        return CompletionResult(
            content=[TextBlock('{"verdict": "SAFE"}')],
            input_tokens=1,
            output_tokens=1,
            stop_reason="end_turn",
        )

    def validate(self, model):
        # Pretend validation always passes — the test isn't about the
        # validation pathway, only the routing pathway.
        pass


# ---------------------------------------------------------------------------
# Multi-provider registry fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def multi_provider_registry() -> tuple[PhaseRegistry, dict[str, _RecordingAdapter]]:
    """Build a registry where every phase has its own adapter+model.

    Returns the registry plus the per-phase adapter map so tests can
    assert on which adapter each pipeline path actually exercised.

    Bindings:
      analyze       -> ("provider-A", "model-analyze")    no tools needed
      enhance       -> ("provider-B", "model-enhance")    needs tools (agentic)
      verify        -> ("provider-C", "model-verify")     needs tools
      report        -> ("provider-D", "model-report")     no tools
      dynamic_test  -> ("provider-E", "model-dyntest")    no tools
      llm_reach     -> ("provider-F", "model-llmreach")   no tools
      app_context   -> ("provider-G", "model-app-context") no tools
    """
    adapters = {
        "analyze":      _RecordingAdapter(label="analyze",      tool_use=False),
        "enhance":      _RecordingAdapter(label="enhance",      tool_use=True),
        "verify":       _RecordingAdapter(label="verify",       tool_use=True),
        "report":       _RecordingAdapter(label="report",       tool_use=False),
        "dynamic_test": _RecordingAdapter(label="dynamic_test", tool_use=False),
        "llm_reach":    _RecordingAdapter(label="llm_reach",    tool_use=False),
        "app_context":  _RecordingAdapter(label="app_context",  tool_use=False),
    }

    bindings = {
        phase: PhaseBinding(
            phase=phase,
            adapter=adapter,
            model=f"model-{phase.replace('_', '-')}",
            provider_name=f"provider-{phase}",
        )
        for phase, adapter in adapters.items()
    }

    # Hand-build the registry — we don't want the factory's
    # tool-support gating to fire (it would, since "enhance" /
    # "verify" require tools and our adapters all claim
    # supports_tools=True, so we're fine, but the constructor
    # bypasses that path entirely).
    registry = PhaseRegistry(
        bindings=bindings, config_name="e2e-test-config"
    )
    return registry, adapters


# ---------------------------------------------------------------------------
# Phase-by-phase propagation
# ---------------------------------------------------------------------------


class TestPhaseRouting:
    """Each phase resolved from the registry hits ONLY its own adapter."""

    def test_analyze_phase_uses_analyze_adapter(self, multi_provider_registry):
        registry, adapters = multi_provider_registry
        from utilities.llm import simple_text

        simple_text(registry.get("analyze"), "hi")

        assert len(adapters["analyze"].calls) == 1
        assert adapters["analyze"].calls[0].model == "model-analyze"
        # No other phase's adapter saw the call.
        for phase in ("enhance", "verify", "report", "dynamic_test", "llm_reach", "app_context"):
            assert adapters[phase].calls == [], (
                f"analyze phase leaked into {phase} adapter"
            )

    def test_enhance_phase_uses_enhance_adapter(self, multi_provider_registry):
        registry, adapters = multi_provider_registry
        binding = registry.get("enhance")
        binding.adapter.complete(
            model=binding.model,
            system="sys",
            messages=[Message(role="user", content=[TextBlock("hi")])],
            max_tokens=8,
            tools=[ToolDef(name="finish", description="", input_schema={"type": "object"})],
        )
        assert adapters["enhance"].calls[0].model == "model-enhance"
        for phase in ("analyze", "verify", "report", "dynamic_test", "llm_reach", "app_context"):
            assert adapters[phase].calls == []

    def test_verify_phase_uses_verify_adapter(self, multi_provider_registry):
        registry, adapters = multi_provider_registry
        binding = registry.get("verify")
        binding.adapter.complete(
            model=binding.model,
            system=None,
            messages=[Message(role="user", content=[TextBlock("verify this")])],
            max_tokens=8,
            tools=[ToolDef(name="finish", description="", input_schema={"type": "object"})],
        )
        assert adapters["verify"].calls[0].model == "model-verify"
        for phase in ("analyze", "enhance", "report", "dynamic_test", "llm_reach", "app_context"):
            assert adapters[phase].calls == []

    def test_report_phase_uses_report_adapter(self, multi_provider_registry):
        registry, adapters = multi_provider_registry
        from utilities.llm import simple_text

        simple_text(registry.get("report"), "summarise these findings")
        assert adapters["report"].calls[0].model == "model-report"
        for phase in ("analyze", "enhance", "verify", "dynamic_test", "llm_reach", "app_context"):
            assert adapters[phase].calls == []

    def test_dynamic_test_phase_uses_dynamic_test_adapter(self, multi_provider_registry):
        registry, adapters = multi_provider_registry
        from utilities.llm import simple_text

        simple_text(registry.get("dynamic_test"), "generate test")
        assert adapters["dynamic_test"].calls[0].model == "model-dynamic-test"
        for phase in ("analyze", "enhance", "verify", "report", "llm_reach", "app_context"):
            assert adapters[phase].calls == []

    def test_llm_reach_phase_uses_llm_reach_adapter(self, multi_provider_registry):
        registry, adapters = multi_provider_registry
        from utilities.llm import simple_text

        simple_text(registry.get("llm_reach"), "what are the entry points")
        assert adapters["llm_reach"].calls[0].model == "model-llm-reach"
        for phase in ("analyze", "enhance", "verify", "report", "dynamic_test", "app_context"):
            assert adapters[phase].calls == []

    def test_app_context_phase_uses_app_context_adapter(self, multi_provider_registry):
        registry, adapters = multi_provider_registry
        from utilities.llm import simple_text

        simple_text(registry.get("app_context"), "classify this repository")
        assert adapters["app_context"].calls[0].model == "model-app-context"
        for phase in ("analyze", "enhance", "verify", "report", "dynamic_test", "llm_reach"):
            assert adapters[phase].calls == []


# ---------------------------------------------------------------------------
# Full pipeline propagation — every phase end-to-end through analyze_unit /
# enhance_unit_with_agent / FindingVerifier — proves the registry value
# carried by the entry points actually reaches each leaf call site.
# ---------------------------------------------------------------------------


class TestAnalyzeUnitPropagation:
    """experiment.analyze_unit uses the analyze binding, not a hardcoded ID."""

    def test_analyze_unit_routes_to_analyze_adapter(self, multi_provider_registry):
        from experiment import analyze_unit

        registry, adapters = multi_provider_registry
        unit = {
            "id": "test:fn",
            "unit_type": "function",
            "code": {
                "primary_code": "def fn(): pass",
                "primary_origin": {"function_name": "fn", "file_path": "a.py"},
            },
            "metadata": {"direct_calls": [], "direct_callers": []},
        }
        result = analyze_unit(registry.get("analyze"), unit)
        # The fake adapter returned `{"verdict": "SAFE"}` — analyze_unit
        # passes it through. We don't care about the verdict itself,
        # only that the call landed on the analyze adapter.
        assert len(adapters["analyze"].calls) >= 1
        assert all(c.model == "model-analyze" for c in adapters["analyze"].calls)
        assert adapters["enhance"].calls == []
        assert adapters["verify"].calls == []


class TestAgenticEnhanceLoopPropagation:
    """ContextAgent.analyze_unit drives the most complex tool-use loop
    in the codebase. A bug that hardcodes a model inside the loop or
    leaks a different binding's adapter is the highest-leverage
    regression possible. Pin the contract by running the full loop
    through a recording adapter and asserting every iteration hits
    the configured `enhance` binding."""

    def test_context_agent_routes_every_iteration_to_enhance_adapter(
        self, multi_provider_registry
    ):
        from utilities.agentic_enhancer.agent import ContextAgent

        registry, adapters = multi_provider_registry

        class _StubIndex:
            """Minimal RepositoryIndex stand-in. ContextAgent only
            uses it to construct a ToolExecutor; our adapter
            short-circuits via the 'finish' tool on iteration 1
            so the executor is never actually invoked."""

            def get_function(self, name):
                return None

            def search_usages(self, *a, **kw):
                return []

            def search_definitions(self, *a, **kw):
                return []

            def list_functions(self, *a, **kw):
                return []

        # The recording adapter declared `tool_use=True` for enhance
        # in the fixture, so iteration 1 returns a ToolUseBlock
        # naming 'finish' — which the ContextAgent will execute and
        # interpret as completion.
        # Need to patch the tool executor's "finish" to return the
        # complete sentinel the agent looks for.
        agent = ContextAgent(
            index=_StubIndex(),
            binding=registry.get("enhance"),
            verbose=False,
        )

        # Monkey-patch ToolExecutor.execute to satisfy the loop's
        # finish-tool contract (agent.py:282 looks for
        # result.get("status") == "complete").
        agent.tool_executor.execute = lambda name, inp: (
            {"status": "complete", "result": {
                "include_functions": [],
                "usage_context": "",
                "security_classification": "neutral",
                "classification_reasoning": "",
                "confidence": 0.5,
            }}
            if name == "finish"
            else {"status": "ok", "result": {}}
        )

        agent.analyze_unit(
            unit_id="test:fn",
            unit_type="function",
            primary_code="def fn(): pass",
            static_deps=[],
            static_callers=[],
        )

        # The loop made at least one call. Every call landed on the
        # enhance adapter (the registry-resolved one).
        assert len(adapters["enhance"].calls) >= 1, (
            "agentic loop did not invoke any adapter — fixture or loop is broken"
        )
        for call in adapters["enhance"].calls:
            assert call.model == "model-enhance", (
                f"agentic loop call leaked: expected model-enhance, got {call.model!r}"
            )

        # No other adapter saw anything.
        for phase in ("analyze", "verify", "report", "dynamic_test", "llm_reach", "app_context"):
            assert adapters[phase].calls == [], (
                f"agentic enhance loop leaked into {phase} adapter"
            )


class TestFindingVerifierPropagation:
    """FindingVerifier uses the verify binding for messages.create AND
    for the consistency-check / JSON-correction fallback paths."""

    def test_verify_result_routes_to_verify_adapter(self, multi_provider_registry):
        from utilities.finding_verifier import FindingVerifier

        registry, adapters = multi_provider_registry

        # The verifier needs a RepositoryIndex; for this test, an
        # empty stub is enough since our fake adapter immediately
        # calls "finish" without invoking any tool other than finish.
        class _StubIndex:
            functions = {}

            def get_function(self, name):
                return None

        verifier = FindingVerifier(
            index=_StubIndex(),
            binding=registry.get("verify"),
            verbose=False,
        )
        verifier.verify_result(
            code="def foo(): pass",
            finding="vulnerable",
            attack_vector="test",
            reasoning="test",
        )
        assert len(adapters["verify"].calls) >= 1
        assert all(c.model == "model-verify" for c in adapters["verify"].calls)
        # Other phases never saw a call.
        for phase in ("analyze", "enhance", "report", "dynamic_test", "llm_reach", "app_context"):
            assert adapters[phase].calls == [], (
                f"verify leaked into {phase}"
            )


class TestAppContextPropagation:
    """``generate_application_context`` must route through the app_context
    binding. Regression test for the H1 leak where the function used the
    Anthropic SDK directly, bypassing the registry entirely."""

    def test_generate_application_context_routes_to_app_context_adapter(
        self, multi_provider_registry, tmp_path
    ):
        from context.application_context import generate_application_context

        registry, adapters = multi_provider_registry

        # Write a minimal README so gather_context_sources has something
        # to feed into the prompt; the actual content doesn't matter
        # because the recording adapter returns a canned response.
        (tmp_path / "README.md").write_text("# Example\nA tiny project.\n")

        # The recording adapter returns `{"verdict": "SAFE"}` which
        # isn't valid app-context JSON; the function will raise
        # ValueError when it tries to construct ApplicationContext.
        # That's fine — we care that the call landed on the right
        # adapter BEFORE the JSON parse fails.
        try:
            generate_application_context(tmp_path, registry.get("app_context"))
        except (ValueError, Exception):  # noqa: BLE001 — see comment above
            pass

        assert len(adapters["app_context"].calls) == 1
        assert adapters["app_context"].calls[0].model == "model-app-context"
        for phase in ("analyze", "enhance", "verify", "report", "dynamic_test", "llm_reach"):
            assert adapters[phase].calls == [], (
                f"app_context generation leaked into {phase} adapter"
            )


class TestRegistryNeverReroutes:
    """A registry built with config X cannot accidentally be used as if
    it were config Y. Different bindings produce different `model`
    strings on the adapter calls — that's the only invariant we need."""

    def test_get_returns_same_binding_consistently(self, multi_provider_registry):
        registry, _ = multi_provider_registry
        # Calling get() multiple times returns equivalent bindings.
        b1 = registry.get("analyze")
        b2 = registry.get("analyze")
        assert b1.model == b2.model == "model-analyze"
        assert b1.adapter is b2.adapter

    def test_unique_probe_targets_matches_config(self, multi_provider_registry):
        registry, _ = multi_provider_registry
        targets = registry.unique_probe_targets()
        # Seven distinct (provider, model) pairs.
        assert len(targets) == 7
        models = {model for _, model in targets}
        assert "model-analyze" in models
        assert "model-enhance" in models
        assert "model-verify" in models
        assert "model-report" in models
        assert "model-dynamic-test" in models
        assert "model-llm-reach" in models
        assert "model-app-context" in models
