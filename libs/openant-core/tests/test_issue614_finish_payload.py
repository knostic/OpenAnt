"""#614: the completed paid classification survives a post-result assembly
failure — never overwritten with an error dict.

The defect chain: ``agent.py:585`` stores the finished, billed
classification; the assembly loop then dereferenced the model's RAW
``include_functions`` finish input (the finish validator checked field
presence but never element TYPES — a bare string raised
``AttributeError``); and ``context_enhancer.py``'s handler then
REPLACED the stored context with an error dict — destroying the paid
classification and its metadata. The referenced run's 12 raise-class
errors are exactly this shape.

Three fixes:
1. **The validator**: ``include_functions`` must be a list of OBJECTS —
   checked at the finish schema boundary (the root).
2. **Preserve on failure**: agent.py's assembly is wrapped — a raise
   marks ``assembly_error`` INSIDE the stored context (the
   classification, reasoning, confidence, and usage survive; the
   additional code is simply not inlined).
3. **The handler**: context_enhancer distinguishes the two error
   shapes — an assembly_error-marked context is PRESERVED (the
   completed verdict exists); a genuine agent.run() failure (an
   LLM/parse raise with no completed context) still takes the error
   dict. (Reachability, disclosed: agent.py's assembly catch does NOT
   re-raise, so the handler's preserve branch is defense-in-depth for
   a future raise-after-store; the preservation itself is layer 2's.)
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.agentic_enhancer.tools import ToolExecutor  # noqa: E402
from utilities.llm.adapter import (  # noqa: E402
    CompletionResult,
    ToolUseBlock,
)


def _tools():
    """The real finish executor (the _finish validator lives inside)."""
    from tests.test_agent_degenerate_exit import _StubIndex
    return ToolExecutor(_StubIndex())


# ---------------------------------------------------------------------------
# fix 1: the validator rejects malformed elements at the boundary
# ---------------------------------------------------------------------------

def _finish_call(tools, include_functions):
    return tools.execute("finish", {
        "include_functions": include_functions,
        "usage_context": "x",
        "security_classification": "neutral",
        "classification_reasoning": "r",
        "confidence": 0.5,
    })


def test_a_bare_string_element_is_rejected():
    """THE 12 errors' exact shape: a bare string in include_functions —
    rejected at the validator (never reaches the assembly)."""
    out = _finish_call(_tools(), ["not_a_dict"])
    assert "error" in out, out
    assert "objects" in out["error"]
    assert "str" in out["error"]


def test_valid_elements_still_pass():
    out = _finish_call(_tools(), [{"id": "a.py:f"}])
    assert out.get("status") == "complete"


def test_a_non_list_is_rejected():
    out = _finish_call(_tools(), "not_a_list")
    assert "error" in out
    assert "list" in out["error"]


# ---------------------------------------------------------------------------
# fix 2: the assembly preserves the completed classification
# ---------------------------------------------------------------------------

def _finish_block(cls, include_functions):
    return ToolUseBlock(
        id="t1", name="finish",
        input={"include_functions": include_functions,
               "usage_context": "x",
               "security_classification": cls,
               "classification_reasoning": "r",
               "confidence": 0.5})


def test_the_assembly_failure_preserves_the_classification():
    """A valid finish whose include_functions carries an id the index can't
    resolve is a SOFT miss — but the old assembly CRASHED on malformed
    elements (the type now rejected upstream); simulate the historical
    crash shape by poisoning the INDEX lookup instead, and assert the
    completed classification + reasoning + usage SURVIVE with the
    assembly_error marker beside them (never an error dict)."""
    class _PoisonIndex:
        # (the constructor reads binding.adapter — index.adapter is unused)

        def get_function(self, _id):
            raise RuntimeError("index exploded")

    from tests.test_agent_degenerate_exit import _FakeAdapter, _FakeBinding
    # drive via the real ContextAgent with the poison index
    from tests.test_agent_degenerate_exit import _FakeTracker
    from utilities.agentic_enhancer.agent import enhance_unit_with_agent
    unit = {"id": "a.py:f", "unit_type": "function",
            "code": {"primary_code": "def f(): pass"},
            "route": {"file": "a.py", "name": "f"}}
    enhance_unit_with_agent(
        unit,
        _PoisonIndex(),
        _FakeBinding(_FakeAdapter([
            CompletionResult(content=[_finish_block("neutral", [{"id": "a.py:f"}])],
                             input_tokens=5, output_tokens=2,
                             stop_reason="tool_use", usage_details=None)])),
        tracker=_FakeTracker())
    ctx = unit["agent_context"]
    # THE PRESERVE RECEIPT: the classification and reasoning survive
    assert ctx["security_classification"] == "neutral"
    assert ctx["classification_reasoning"] == "r"
    assert ctx.get("error") is None  # never the error dict
    assert ctx["assembly_error"]["exception_class"] == "RuntimeError"



def test_a_validator_regression_still_preserves_the_classification():
    """DEFENSE-IN-DEPTH, driven: monkeypatch _finish to accept the
    historical bare-string payload (the validator regressed) and drive
    the REAL enhance_unit_with_agent — the assembly wrap still catches
    at the historical site (func_info.get on a str) and the completed
    classification survives (the handler never fires: the wrap does not
    re-raise)."""
    from utilities.agentic_enhancer.tools import ToolExecutor
    from tests.test_agent_degenerate_exit import _FakeAdapter, _FakeBinding
    from tests.test_agent_degenerate_exit import _FakeTracker, _StubIndex
    from utilities.agentic_enhancer.agent import enhance_unit_with_agent
    from utilities.llm.adapter import ToolUseBlock

    def _regressed_finish(self, input):
        return {"status": "complete", "result": input}

    # the historical malformed payload: a BARE STRING element
    _bare = ToolUseBlock(id="t1", name="finish", input={
        "include_functions": ["a.py:f"], "usage_context": "ctx",
        "security_classification": "neutral",
        "classification_reasoning": "r", "confidence": 0.5,
    })
    unit = {"id": "a.py:f", "unit_type": "function",
            "language": "python",
            "code": {"primary_code": "def f(): pass"},
            "route": {"file": "a.py", "name": "f"}}
    orig = ToolExecutor._finish
    ToolExecutor._finish = _regressed_finish
    try:
        enhance_unit_with_agent(
            unit, _StubIndex(),
            _FakeBinding(_FakeAdapter([
                CompletionResult(content=[_bare],
                                 input_tokens=5, output_tokens=2,
                                 stop_reason="tool_use",
                                 usage_details=None)])),
            tracker=_FakeTracker())
    finally:
        ToolExecutor._finish = orig
    ctx = unit["agent_context"]
    # the completed, paid classification SURVIVES the assembly raise
    assert ctx["security_classification"] == "neutral"
    assert ctx["assembly_error"]["exception_class"] == "AttributeError"


# ---------------------------------------------------------------------------
# fix 3: the handler distinguishes the two error shapes
# ---------------------------------------------------------------------------

def test_the_handler_preserves_an_assembly_error_context():
    """Source pin: context_enhancer's handler branches on assembly_error —
    the preserved context stays; the bare-run failure still takes the dict."""
    src = (PROJECT_ROOT / "utilities" / "context_enhancer.py").read_text()
    assert 'if _preserved.get("assembly_error"):' in src
    assert 'unit["agent_context"] = _preserved' in src
