"""Regression tests for degenerate-exit classification in the agentic enhancer.

Bug (agent-degenerate-exit-neutral-drop): when the tool-use loop ended without
a completed ``finish`` tool call — the model emitted a bare ``end_turn``, made
no tool calls, or hit MAX_ITERATIONS — ``analyze_unit`` stamped
``security_classification="neutral"``. "neutral" is a *genuine* verdict ("no
security relevance"), so an analysis that never completed was indistinguishable
from a unit the agent inspected and cleared. Downstream (analyzer's
exploitable-filter, CSV export, experiment reporting) silently bucketed the
dropped unit as a real neutral finding.

The three degenerate exits must carry a DISTINCT classification so the no-op /
error state is recorded, not masqueraded as a neutral verdict.

Pure/deterministic: a stub adapter drives the loop, no network.
"""
from utilities.llm.adapter import CompletionResult, TextBlock, ToolUseBlock
from utilities.agentic_enhancer.agent import ContextAgent, INCOMPLETE_CLASSIFICATION
from utilities.context_enhancer import ContextEnhancer


class _StubIndex:
    def get_function(self, name):
        return None

    def search_usages(self, *a, **kw):
        return []

    def search_definitions(self, *a, **kw):
        return []

    def list_functions(self, *a, **kw):
        return []


class _FakeAdapter:
    name = "fake"
    supports_tools = True

    def __init__(self, results):
        # results: a list consumed one per iteration (last repeats)
        self._results = list(results)

    def complete(self, **kw):
        if len(self._results) > 1:
            return self._results.pop(0)
        return self._results[0]


class _FakeBinding:
    phase = "enhance"
    model = "fake-model"

    def __init__(self, adapter):
        self.adapter = adapter


class _FakeTracker:
    def record_call(self, **kw):
        return {"cost_usd": 0.0}


def _agent(results):
    binding = _FakeBinding(_FakeAdapter(results))
    return ContextAgent(index=_StubIndex(), binding=binding, tracker=_FakeTracker())


def _run(agent):
    return agent.analyze_unit(
        unit_id="test:fn",
        unit_type="function",
        primary_code="def fn():\n    return 1\n",
        static_deps=[],
        static_callers=[],
    )


def test_end_turn_without_finish_is_not_a_neutral_verdict():
    """The anchor path: bare end_turn with no finish tool call."""
    result = _run(_agent([
        CompletionResult(
            content=[TextBlock("I think I'm done.")],
            input_tokens=1, output_tokens=1, stop_reason="end_turn",
        )
    ]))
    assert result.security_classification != "neutral", (
        "degenerate end_turn exit was stamped 'neutral' — indistinguishable "
        "from a genuine no-security-relevance verdict"
    )
    assert result.security_classification == "incomplete"


def test_no_tool_calls_is_not_a_neutral_verdict():
    """Sibling path: model responded but made no tool calls."""
    result = _run(_agent([
        CompletionResult(
            content=[TextBlock("hmm")],
            input_tokens=1, output_tokens=1, stop_reason="tool_use",
        )
    ]))
    assert result.security_classification != "neutral"
    assert result.security_classification == "incomplete"


def test_max_iterations_is_not_a_neutral_verdict():
    """Sibling path: loop exhausts MAX_ITERATIONS without finishing."""
    # Every iteration asks for a non-finish tool, so the loop never completes.
    looping = CompletionResult(
        content=[ToolUseBlock(id="t", name="search_usages", input={})],
        input_tokens=1, output_tokens=1, stop_reason="tool_use",
    )
    agent = _agent([looping])
    agent.tool_executor.execute = lambda name, inp: {"status": "ok", "result": {}}
    result = _run(agent)
    assert result.security_classification != "neutral"
    assert result.security_classification == "incomplete"


def test_incomplete_unit_is_reported_under_incomplete_not_neutral():
    """Reporting residual (FA3): the enhance-phase summary must not mask a
    degenerate-exit unit as a real neutral finding.

    A unit that hit a degenerate exit carries security_classification=
    'incomplete' and has NO 'error' field, so the error-continue guard in
    _compute_agentic_stats does not skip it. Before the fix it fell through the
    classification if/elif chain into the else -> neutral_found bucket (and the
    'neutral' summary key), re-masquerading as neutral on the enhance summary.
    It must instead be tallied under a distinct incomplete_found key.
    """
    units = [
        {  # degenerate exit: incomplete classification, no error field
            "agent_context": {
                "security_classification": INCOMPLETE_CLASSIFICATION,
                "include_functions": [],
                "agent_metadata": {"iterations": 20},
            }
        },
        {  # a genuine neutral verdict, for contrast
            "agent_context": {
                "security_classification": "neutral",
                "include_functions": [],
                "agent_metadata": {"iterations": 3},
            }
        },
    ]
    stats = ContextEnhancer._compute_agentic_stats(units)
    assert stats["incomplete_found"] == 1, (
        "degenerate-exit unit was not tallied under incomplete_found"
    )
    assert stats["neutral_found"] == 1, (
        "only the genuine neutral verdict belongs in neutral_found; the "
        "incomplete unit leaked into it"
    )
