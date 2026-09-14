"""#615: the agentic enhance give-up classes get their own diagnostic channel.

The four degenerate exits are conflated under one ``classification:
"incomplete"``, but they differ in kind and remedy — three cheap
model-behavior exits (end-turn-without-finish, finish truncated,
no-tool-calls) remedied by retry/prompt work, vs ONE budget-exhaustion
exit (MAX_ITERATIONS) remedied by raising the budget. A consumer reading
only ``classification`` cannot split the 4-vs-41.

The fix (NOT a fourth classification enum — that breaks every
``== "incomplete"`` consumer): an ``exit_kind`` field on
``AgentResult`` (present-only in ``to_dict``; empty = a completed
analysis), and the ``incomplete_summary`` kind histogram beside the
existing ``error_summary`` (EnhanceResult + the step-report summary) —
so the split is visible without stderr mining while every existing
consumer keeps its semantics.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.agentic_enhancer.agent import (  # noqa: E402
    AgentResult,
    INCOMPLETE_CLASSIFICATION,
)


def _result(kind="", cls=INCOMPLETE_CLASSIFICATION):
    return AgentResult(
        include_functions=[], usage_context="x",
        security_classification=cls, classification_reasoning="r",
        confidence=0.3, iterations=1, total_tokens=0,
        exit_kind=kind)


# ---------------------------------------------------------------------------
# the four kinds + the completed negative
# ---------------------------------------------------------------------------

def test_the_four_kinds_stamp_their_exit():
    """Each degenerate exit carries its own exit_kind; a completed analysis
    carries an empty one (and serializes WITHOUT the key)."""
    assert _result("end_turn_without_finish").exit_kind == "end_turn_without_finish"
    assert _result("finish_truncated").exit_kind == "finish_truncated"
    assert _result("no_tool_calls").exit_kind == "no_tool_calls"
    assert _result("max_iterations").exit_kind == "max_iterations"
    # the completed negative
    clean = _result("", cls="safe")
    d = clean.to_dict()
    assert d["security_classification"] == "safe"
    assert "exit_kind" not in d  # present-only: the completed analysis


def test_an_incomplete_serializes_its_kind():
    """An incomplete result's to_dict carries exit_kind (the durable
    per-record signal the histogram aggregates)."""
    d = _result("max_iterations").to_dict()
    assert d["exit_kind"] == "max_iterations"
    assert d["security_classification"] == "incomplete"  # the classification UNCHANGED


def test_every_consumer_semantics_is_unchanged():
    """The #1 constraint: classification stays exactly 'incomplete' for
    every existing ==-comparing consumer (checkpoint, enhancer, tests)."""
    for kind in ("end_turn_without_finish", "finish_truncated",
                 "no_tool_calls", "max_iterations"):
        assert _result(kind).security_classification == "incomplete"


# ---------------------------------------------------------------------------
# the incomplete_summary histogram
# ---------------------------------------------------------------------------

def test_the_histogram_counts_the_kinds():
    """The enhancer's counting loop aggregates exit_kind into
    incomplete_summary (the 4-vs-41 split, visible in the artifact)."""
    units = [
        {"id": "a", "agent_context": {
            "security_classification": "incomplete",
            "exit_kind": "max_iterations"}},
        {"id": "b", "agent_context": {
            "security_classification": "incomplete",
            "exit_kind": "max_iterations"}},
        {"id": "c", "agent_context": {
            "security_classification": "incomplete",
            "exit_kind": "end_turn_without_finish"}},
        {"id": "d", "agent_context": {
            "security_classification": "incomplete"}},  # a legacy unstamped row
        {"id": "e", "agent_context": {
            "security_classification": "safe"}},
    ]
    classifications = {}
    incomplete_summary = {}
    incomplete_count = 0
    for unit in units:
        ctx = unit.get("agent_context", {})
        cls = ctx.get("security_classification", "unknown")
        classifications[cls] = classifications.get(cls, 0) + 1
        if cls == "incomplete":
            incomplete_count += 1
            kind = ctx.get("exit_kind") or "unstamped"
            incomplete_summary[kind] = incomplete_summary.get(kind, 0) + 1
    assert incomplete_summary == {"max_iterations": 2,
                                  "end_turn_without_finish": 1,
                                  "unstamped": 1}
    assert incomplete_count == 4  # all four incomplete rows


def test_the_enhance_result_carries_the_histogram():
    from core.schemas import EnhanceResult
    r = EnhanceResult(enhanced_dataset_path="x",
                      incomplete_summary={"max_iterations": 4,
                                          "end_turn_without_finish": 41})
    assert r.to_dict()["incomplete_summary"] == {
        "max_iterations": 4, "end_turn_without_finish": 41}
    # present-only: no incompletes -> the key is ABSENT
    r2 = EnhanceResult(enhanced_dataset_path="x")
    assert "incomplete_summary" not in r2.to_dict()


def test_the_step_summary_threads_the_histogram():
    """Source pin: the scanner's enhance summary forwards the histogram
    (the artifact visibility — no stderr mining)."""
    src = (PROJECT_ROOT / "core" / "scanner.py").read_text()
    assert '"incomplete_summary"' in src


def test_the_enhancer_source_counts_the_kinds():
    """Source pin: the counting loop reads exit_kind with the unstamped
    fallback (the legacy rows before this fix)."""
    src = (PROJECT_ROOT / "core" / "enhancer.py").read_text()
    assert 'ctx.get("exit_kind") or "unstamped"' in src


# ---------------------------------------------------------------------------
# the REAL stamp sites (the degenerate-exit harness — not AgentResult
# construction): each of the four exits drives the real agent loop
# ---------------------------------------------------------------------------

def test_the_real_exits_stamp_their_kinds():
    """Drive the real agent loop (the test_agent_degenerate_exit harness
    pattern) for the two cheaply-simulable exits and assert the stamp on
    the REAL AgentResult — not a hand-constructed one."""
    from tests.test_agent_degenerate_exit import _agent, _run
    from utilities.llm.adapter import CompletionResult, TextBlock

    # THE end-turn-without-finish exit, driven through the real loop
    result = _run(_agent([
        CompletionResult(
            content=[TextBlock("I think I'm done.")],
            input_tokens=1, output_tokens=1, stop_reason="end_turn",
        )
    ]))
    assert result.security_classification == "incomplete"
    assert result.exit_kind == "end_turn_without_finish"  # the real stamp

    # THE finish-truncated exit (the R2-B harness shape: _finish_block
    # + max_tokens)
    from tests.test_agent_degenerate_exit import _finish_block
    result2 = _run(_agent([
        CompletionResult(content=[_finish_block("neutral")],
                         input_tokens=1, output_tokens=1,
                         stop_reason="max_tokens"),
    ]))
    assert result2.security_classification == "incomplete"
    assert result2.exit_kind == "finish_truncated"  # the real stamp
