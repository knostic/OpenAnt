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


def test_the_handler_preserves_and_reclassifies(monkeypatch, tmp_path):
    """BEHAVIORAL (the source-string pin retired): drive the REAL
    ContextEnhancer.agentic enhance path (the closure's handler) with a
    fake agent entry that stores a completed, assembly_error-marked
    context and THEN raises (the future raise-after-store shape the
    handler branch guards) — the context is preserved and the unit's
    classification is the PRESERVED one (never the error dict)."""
    import utilities.context_enhancer as ce_mod

    def _fake_agent_entry(unit, index, binding, tracker=None,
                          verbose=False, *a, **kw):
        unit["agent_context"] = {
            "security_classification": "security_control",
            "classification_reasoning": "done",
            "confidence": 0.8,
            "assembly_error": {"exception_class": "RuntimeError",
                               "message": "post-store raise"},
        }
        raise RuntimeError("post-store raise")

    monkeypatch.setattr(ce_mod, "enhance_unit_with_agent",
                        _fake_agent_entry)
    # the index loader stub (the handler path never uses it)
    monkeypatch.setattr(ce_mod, "load_index_from_file",
                        lambda *a, **kw: type(
                            "Ix", (), {
                                "get_statistics": lambda s: {
                                    "total_functions": 0,
                                    "total_files": 0}})())

    from types import SimpleNamespace

    class _T:
        def get_totals(self):
            return {"total_calls": 0, "total_input_tokens": 0,
                    "total_output_tokens": 0, "total_tokens": 0,
                    "total_cost_usd": 0.0, "cost_incomplete": False,
                    "unpriced_models": []}
        def get_unit_usage(self):
            return None
        def add_prior_usage(self, *a, **kw):
            pass

    enhancer = ce_mod.ContextEnhancer.__new__(ce_mod.ContextEnhancer)
    enhancer.binding = SimpleNamespace(provider_name="stub", model="m")
    enhancer.tracker = _T()
    enhancer._log = lambda *a, **kw: None

    dataset = {"units": [{"id": "a.py:f", "unit_type": "function",
                          "code": {"primary_code": "def f(): pass"},
                          "route": {"file": "a.py", "name": "f"}}]}
    enhancer.enhance_dataset_agentic(
        dataset, str(tmp_path / "analyzer_output.json"),
        str(tmp_path / "repo"), workers=1)
    out_unit = dataset["units"][0]
    # the PRESERVED context stays (never the error dict) — the
    # classification is the completed one, the marker beside it
    assert out_unit["agent_context"]["security_classification"] \
        == "security_control"
    assert "assembly_error" in out_unit["agent_context"]
    assert "error" not in out_unit["agent_context"]


def test_the_validator_rejects_a_nonstring_id():
    """The schema's id: string — a dict element with a missing/non-string
    id is rejected (the model self-corrects; the index lookup never sees
    an unhashable id)."""
    out = ToolExecutor(None)._finish({
        "include_functions": [{"id": 42}], "usage_context": "ctx",
        "security_classification": "neutral",
        "classification_reasoning": "r", "confidence": 0.5,
    })
    assert "error" in out and "string id" in out["error"]


def test_the_stats_gate_skips_undelivered_context():
    """#614's stats gate: an assembly_error unit is a COMPLETED analysis
    whose code was NOT inlined — units_with_context/functions_added must
    not claim delivery that failed."""
    from utilities.context_enhancer import ContextEnhancer
    units = [
        # delivered: no assembly_error, include_functions present
        {"agent_context": {"security_classification": "neutral",
                           "include_functions": [{"id": "a.py:f"}]}},
        # completed but NOT delivered (the assembly failed)
        {"agent_context": {"security_classification": "security_control",
                           "include_functions": [{"id": "b.py:g"}],
                           "assembly_error": {"exception_class":
                                              "RuntimeError"}}},
    ]
    stats = ContextEnhancer._compute_agentic_stats(units)
    assert stats["units_with_context"] == 1
    assert stats["functions_added"] == 1
    assert stats["security_controls_found"] == 1  # the verdict still counts
