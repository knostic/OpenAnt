import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


# ---------------------------------------------------------------------------
# #697: the dropped-block diagnostic (#625/#660's per-kind counter, computed
# per call on the CompletionResult) must REACH an operator artifact — the
# step report's token_usage block and the scan aggregate — present-only, so
# a healthy run's artifacts stay byte-identical.
#
# Collection-safe at pristine base (the #696 deferred-import law): every
# module-level import exists at base; the NEW-symbol imports stay inside
# the test bodies, so at base the tests EXECUTE and fail behaviorally.
# ---------------------------------------------------------------------------


def test_issue697_tracker_accumulates_dropped_kinds():
    """The tracker accumulates the per-kind counts across calls."""
    from utilities.llm_client import TokenTracker

    t = TokenTracker()
    t.record_call(model="m", input_tokens=10, output_tokens=5,
                   dropped_block_kinds={"thinking": 2, "redacted_thinking": 1})
    t.record_call(model="m", input_tokens=3, output_tokens=2,
                   dropped_block_kinds={"thinking": 1})
    assert t.get_totals()["dropped_block_kinds"] == {
        "thinking": 3, "redacted_thinking": 1}


def test_issue697_totals_present_only():
    """A clean run's totals keep exactly the pre-#697 shape (byte-identical)."""
    from utilities.llm_client import TokenTracker

    t = TokenTracker()
    t.record_call(model="m", input_tokens=1, output_tokens=1)
    assert "dropped_block_kinds" not in t.get_totals()


def test_issue697_simple_completion_threads_the_diagnostic():
    """simple_completion passes the result's per-kind counts to record_call."""
    from utilities.llm.registry import PhaseBinding
    from utilities.llm_client import reset_global_tracker
    from utilities.llm.adapter import CompletionResult, TextBlock

    class _StubAdapter:
        name = "stub"
        def complete(self, *, model, system, messages, max_tokens,
                     tools=None):
            return CompletionResult(
                content=(TextBlock("ok"),),
                stop_reason="end_turn",
                input_tokens=4,
                output_tokens=2,
                usage_details={},
                dropped_block_kinds={"thinking": 2},
            )

    class _Binding:
        adapter = _StubAdapter()
        model = "stub-model"
        def pricing_get(self, m):  # pragma: no cover
            return None

    from utilities.llm.helpers import simple_completion  # noqa: F401
    reset_global_tracker()
    from utilities.llm_client import get_global_tracker
    binding = PhaseBinding(phase="analyze", adapter=_StubAdapter(),
                           model="stub-model", provider_name="stub")
    from utilities.llm.helpers import simple_completion as _sc
    _sc(binding, "hi", tracker=get_global_tracker())
    totals = get_global_tracker().get_totals()
    assert totals.get("dropped_block_kinds") == {"thinking": 2}


def test_issue697_step_report_carries_delta():
    """THE falsifier: the step report's token_usage carries the per-kind
    DELTA of the blocks dropped during the step."""
    import core.step_report as SR
    from utilities.llm_client import reset_global_tracker, get_global_tracker

    reset_global_tracker()
    get_global_tracker().record_call(
        model="m", input_tokens=1, output_tokens=1,
        dropped_block_kinds={"thinking": 2, "redacted_thinking": 1})

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        with SR.step_context("analyze", td) as report:
            get_global_tracker().record_call(
                model="m", input_tokens=2, output_tokens=1,
                dropped_block_kinds={"thinking": 3})
        assert report.token_usage["dropped_block_kinds"] == {"thinking": 3}
        # the per-kind DELTA, never the run-cumulative total:
        assert report.token_usage["dropped_block_kinds"]["thinking"] == 3


def test_issue697_step_report_clean_run_byte_identical():
    """A step that dropped nothing keeps its token_usage shape exactly."""
    import core.step_report as SR
    from utilities.llm_client import reset_global_tracker

    reset_global_tracker()
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        with SR.step_context("verify", td):
            pass
    # find the report via the context's own artifact? simplest: rebuild one
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        with SR.step_context("verify", td) as report:
            pass
        assert "dropped_block_kinds" not in report.token_usage


def test_issue697_scan_aggregate_sums_kinds():
    """The scan aggregate sums the per-kind counts across the step reports."""
    import core.scanner as SC

    step_reports = [
        {"token_usage": {"input_tokens": 1,
                         "dropped_block_kinds": {"thinking": 2}}},
        {"token_usage": {"input_tokens": 1,
                         "dropped_block_kinds": {"thinking": 1,
                                                 "redacted_thinking": 1}}},
        {"token_usage": {"input_tokens": 1}},  # a clean step contributes nothing
    ]
    assert SC._sum_dropped_block_kinds(step_reports) == {
        "thinking": 3, "redacted_thinking": 1}


def test_issue697_scan_aggregate_clean_scan_present_only():
    """A scan whose steps dropped nothing aggregates to {} (present-only)."""
    import core.scanner as SC

    step_reports = [
        {"token_usage": {"input_tokens": 1, "output_tokens": 1}},
        {"token_usage": {"input_tokens": 2, "output_tokens": 2}},
    ]
    assert SC._sum_dropped_block_kinds(step_reports) == {}

def test_issue697_reset_clears_the_accumulator():
    """llm_client.py@fe220861: reset() re-creates the accumulator — a
    second run's totals never inherit the first run's dropped kinds."""
    from utilities.llm_client import TokenTracker

    t = TokenTracker()
    t.record_call(model="m", input_tokens=1, output_tokens=1,
                  dropped_block_kinds={"thinking": 5})
    t.reset()
    assert t._dropped_block_kinds == {}
    t.record_call(model="m", input_tokens=1, output_tokens=1,
                  dropped_block_kinds={"tool_use": 1})
    assert t.get_totals()["dropped_block_kinds"] == {"tool_use": 1}


def test_issue697_sentinel_carries_end_snapshot_kinds(tmp_path):
    """step_report.py@b6be99ed: the #605 sentinel branch (a FAILED start
    snapshot — the delta is unavailable) carries the end snapshot's
    per-kind counts, the #216 disclosure trade."""
    import core.step_report as SR
    from utilities.llm_client import reset_global_tracker, get_global_tracker

    reset_global_tracker()
    get_global_tracker().record_call(
        model="m", input_tokens=1, output_tokens=1,
        dropped_block_kinds={"thinking": 7})

    real_snapshot = SR._snapshot_usage
    calls = {"n": 0}

    def _failing_then_real():
        calls["n"] += 1
        if calls["n"] == 1:
            return None, None  # the #605 sentinel: the start snapshot failed
        return real_snapshot()

    SR._snapshot_usage = _failing_then_real
    try:
        with SR.step_context("analyze", str(tmp_path)) as report:
            pass
    finally:
        SR._snapshot_usage = real_snapshot
    assert report.token_usage["accounting_error"] is True
    assert report.token_usage["dropped_block_kinds"] == {"thinking": 7}


def test_issue697_aggregate_writes_the_kinds(tmp_path):
    """scanner.py@08c8874c + @2f885ddb: _write_scan_report's token_usage
    carries the summed per-kind counts (the merge call-site + the
    **{} land), present-only."""
    import json as _json
    from core.schemas import ScanResult
    from core.scanner import _write_scan_report

    result = ScanResult(output_dir=str(tmp_path), language="python")
    step_reports = [
        {"step": "analyze", "token_usage": {
            "input_tokens": 1, "output_tokens": 1,
            "dropped_block_kinds": {"thinking": 2}}},
        {"step": "verify", "token_usage": {
            "input_tokens": 1, "output_tokens": 1,
            "dropped_block_kinds": {"thinking": 1, "redacted_thinking": 1}}},
    ]
    path = _write_scan_report(str(tmp_path), result, step_reports,
                              repo_path=str(tmp_path))
    report = _json.loads(_json.dumps(
        _json.loads(Path(path).read_text())))
    assert report["token_usage"]["dropped_block_kinds"] == {
        "thinking": 3, "redacted_thinking": 1}


def test_issue697_aggregate_clean_scan_present_only(tmp_path):
    """scanner.py@2f885ddb: a scan whose steps dropped nothing keeps the
    aggregate token_usage byte-identical (no dropped_block_kinds key)."""
    import json as _json
    from core.schemas import ScanResult
    from core.scanner import _write_scan_report

    result = ScanResult(output_dir=str(tmp_path), language="python")
    step_reports = [
        {"step": "parse", "token_usage": {"input_tokens": 2, "output_tokens": 2}},
    ]
    path = _write_scan_report(str(tmp_path), result, step_reports,
                              repo_path=str(tmp_path))
    report = _json.loads(Path(path).read_text())
    assert "dropped_block_kinds" not in report["token_usage"]


def test_issue697_summary_carries_kinds_present_only():
    """llm_client.py@fe220861: get_summary (the per-call breakdown twin of
    get_totals) carries the same present-only key — the reconciliation
    surfaces agree; a clean run's summary keeps exactly the pre-#697 keys."""
    from utilities.llm_client import TokenTracker

    t = TokenTracker()
    t.record_call(model="m", input_tokens=1, output_tokens=1,
                  dropped_block_kinds={"thinking": 2})
    assert t.get_summary()["dropped_block_kinds"] == {"thinking": 2}

    t2 = TokenTracker()
    t2.record_call(model="m", input_tokens=1, output_tokens=1)
    assert "dropped_block_kinds" not in t2.get_summary()


def test_issue697_non_numeric_counts_skipped():
    """fable-F3: a garbage count is skipped, never coerced to a zero-valued
    key (a present-only dict must not grow from garbage); bool too."""
    from utilities.llm_client import TokenTracker

    t = TokenTracker()
    t.record_call(model="m", input_tokens=1, output_tokens=1,
                  dropped_block_kinds={"x": "3", "y": True, "z": 2.0})
    assert t.get_totals()["dropped_block_kinds"] == {"z": 2}


def test_issue697_verify_leg_threads_the_diagnostic():
    """fable-F1 (the verify half): a verify conversation whose responses
    drop blocks accumulates the per-kind counts onto EVERY exit's record —
    the tracker totals carry them, never a silent zero."""
    from utilities.llm.adapter import (CompletionResult, TextBlock)

    from utilities.finding_verifier import FindingVerifier

    class _Resp(CompletionResult):
        pass

    def _mk(dropped):
        return CompletionResult(
            content=(TextBlock("ok"),),
            stop_reason="end_turn",
            input_tokens=4, output_tokens=2,
            usage_details={},
            dropped_block_kinds=dropped,
        )

    class _StubAdapter:
        name = "stub"
        def complete(self, *, model, system, messages, max_tokens, tools=None):
            return _mk({"thinking": 1, "tool_use": 2})

    class _Binding:
        adapter = _StubAdapter()
        model = "stub-model"
        provider_name = "stub"

    from utilities.llm.registry import PhaseBinding
    from utilities.llm_client import TokenTracker

    binding = PhaseBinding(phase="verify", adapter=_StubAdapter(),
                           model="stub-model", provider_name="stub")
    tracker = TokenTracker()
    fv = FindingVerifier.__new__(FindingVerifier)
    fv.binding = binding
    fv.tracker = tracker
    fv.verbose = False
    fv.retries = 0

    # the text-parse exit: a JSON finish in one turn
    ok_json = '{"agree": true, "correct_finding": "safe", "explanation": "e"}'
    fv._parse_json_from_text = lambda text: {"agree": True, "correct_finding": "safe", "explanation": "e"} if "agree" in text else None
    fv._parse_finish_result = lambda *a, **k: object()
    fv._try_parse_text_response(
        [TextBlock(ok_json)], "vulnerable", 1, 4, 2,
        usage_details=[{}],
        dropped_block_kinds={"thinking": 1},
    )
    assert tracker.get_totals()["dropped_block_kinds"] == {"thinking": 1}


def test_issue697_verify_conversation_loop_carries_kinds():
    """fable-F1 (the verify loop): a verify conversation whose response
    drops blocks carries the per-kind counts onto the loop's OWN record
    (the end_turn degenerate exit) — never a silent zero."""
    from utilities.llm.adapter import CompletionResult, TextBlock
    from utilities.llm.registry import PhaseBinding
    from utilities.llm_client import TokenTracker
    from utilities.finding_verifier import FindingVerifier

    class _StubAdapter:
        name = "stub"
        supports_tools = True

        def complete(self, *, model, system, messages, max_tokens, tools=None):
            return CompletionResult(
                content=(TextBlock("not json"),),
                stop_reason="end_turn",
                input_tokens=4, output_tokens=2,
                usage_details={},
                dropped_block_kinds={"thinking": 2},
            )

    binding = PhaseBinding(phase="verify", adapter=_StubAdapter(),
                           model="stub-model", provider_name="stub")
    tracker = TokenTracker()
    fv = FindingVerifier.__new__(FindingVerifier)
    fv.binding = binding
    fv.tracker = tracker
    fv.verbose = False
    fv.app_context = None
    fv.logger = None
    fv._tool_defs = []
    fv._use_logger = False

    res = fv.verify_result(code="x = 1", finding="vulnerable",
                           attack_vector="av", reasoning="r")
    assert res.agree is False  # the R4-7 fail-safe (no JSON parsed)
    assert tracker.get_totals()["dropped_block_kinds"] == {"thinking": 2}


def test_issue697_enhance_loop_carries_kinds():
    """fable-F1 (the enhance loop): an agentic enhance conversation whose
    response drops blocks carries the per-kind counts onto the loop's exit
    record — never a silent zero."""
    from utilities.llm.adapter import CompletionResult, TextBlock
    from utilities.llm.registry import PhaseBinding
    from utilities.llm_client import TokenTracker
    from utilities.agentic_enhancer.agent import ContextAgent as Agent

    class _StubAdapter:
        name = "stub"
        supports_tools = True

        def complete(self, *, model, system, messages, max_tokens, tools=None):
            return CompletionResult(
                content=(TextBlock("plain text, no finish tool"),),
                stop_reason="end_turn",
                input_tokens=4, output_tokens=2,
                usage_details={},
                dropped_block_kinds={"thinking": 1, "tool_use": 3},
            )

    binding = PhaseBinding(phase="enhance", adapter=_StubAdapter(),
                           model="stub-model", provider_name="stub")
    tracker = TokenTracker()
    ag = Agent.__new__(Agent)
    ag.binding = binding
    ag.tracker = tracker
    ag.verbose = False
    ag.index = None
    ag.entry_points = set()
    ag.reachability = None
    class _NoToolExecutor:
        def set_unit_context(self, *a, **k):
            pass
    ag.tool_executor = _NoToolExecutor()

    res = ag.analyze_unit(unit_id="u1", unit_type="function",
                           primary_code="x = 1", static_deps=[],
                           static_callers=[])
    assert res.exit_kind == "end_turn_without_finish"
    assert tracker.get_totals()["dropped_block_kinds"] == {
        "thinking": 1, "tool_use": 3}


def test_issue697_reachability_summary_carries_kinds():
    """The fable-rejected E-claim replaced by the executed drive: the
    reachability step's _summary_usage closure DOES carry the per-kind
    counts (present-only, run-cumulative from the totals — the same read
    as get_totals/get_summary), driven through the REAL
    analyze_reachability with a write_summary capture (the #603 pattern)."""
    import sys
    import tempfile
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from tests.test_issue532_llr_resume import (
        FakeAdapter, _binding, _canned, _make_unit, _sig,
    )
    from core.checkpoint import StepCheckpoint
    from core.llm_reachability import analyze_reachability
    from utilities.llm_client import TokenTracker

    tracker = TokenTracker()
    tracker.record_call("fake/model", 100, 50,
                        pricing={"input": 2.0, "output": 4.0},
                        dropped_block_kinds={"thinking": 2})

    writes = []
    real_write = StepCheckpoint.write_summary

    def capture(self, **kw):
        writes.append(kw)
        return real_write(self, **kw)

    StepCheckpoint.write_summary = capture
    try:
        cp_dir = tempfile.mkdtemp()
        analyze_reachability(
            {"units": [_make_unit("a:f1")]},
            binding=_binding(FakeAdapter([_canned(_sig("a:f1"))])),
            checkpoint_path=cp_dir, tracker=tracker,
        )
    finally:
        StepCheckpoint.write_summary = real_write

    assert writes
    for w in writes:
        assert w["usage"]["dropped_block_kinds"] == {"thinking": 2}


def test_issue697_agent_raise_path_carries_kinds():
    """fable-F4: the enhance loop's RAISE-path record (the **spread site at
    agent.py:401) rides the per-turn accumulation like every exit — a
    mid-conversation connection error must not vanish the dropped-block
    counts."""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from utilities.llm.adapter import (CompletionResult, ToolUseBlock, LLMConnectionError)
    from utilities.llm.registry import PhaseBinding
    from utilities.llm_client import TokenTracker
    from utilities.agentic_enhancer.agent import ContextAgent

    class _RaisingAdapter:
        name = "stub"
        supports_tools = True
        n = 0

        def complete(self, *, model, system, messages, max_tokens, tools=None):
            _RaisingAdapter.n += 1
            if _RaisingAdapter.n == 1:
                return CompletionResult(
                    content=(ToolUseBlock(id="t1", name="search_code",
                                          input={"query": "x"}),),
                    stop_reason="tool_use",
                    input_tokens=4, output_tokens=2,
                    usage_details={},
                    dropped_block_kinds={"thinking": 1},
                )
            raise LLMConnectionError("mid-conversation drop")

    binding = PhaseBinding(phase="enhance", adapter=_RaisingAdapter(),
                           model="stub-model", provider_name="stub")
    tracker = TokenTracker()
    ag = ContextAgent.__new__(ContextAgent)
    ag.binding = binding
    ag.tracker = tracker
    ag.verbose = False
    ag.index = None
    ag.entry_points = set()
    ag.reachability = None

    class _NoToolExecutor:
        def set_unit_context(self, *a, **k):
            pass
        def execute(self, *a, **k):
            return "ok"
    ag.tool_executor = _NoToolExecutor()

    import pytest as _pytest
    with _pytest.raises(LLMConnectionError):
        ag.analyze_unit(unit_id="u1", unit_type="function",
                        primary_code="x = 1", static_deps=[],
                        static_callers=[])
    assert tracker.get_totals()["dropped_block_kinds"] == {"thinking": 1}
