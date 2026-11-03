"""#699: the five _summary.json writers give ONE answer about the markers.

At ``abd1dcf4`` the five ``_summary.json`` usage-dict builders implemented
THREE different policies for the accounting marker pair, so one
``record_accounting_error()`` tick produced a different artifact answer in
each writer of the same run:

* llm_reachability + dynamic_tester published the counter WITHOUT the flag
  (``{accounting_errors: 1}`` — the tick does not derive
  ``cost_incomplete``, which the tracker bases on the unpriced kinds only);
* context_enhancer published the counter and FORCED the flag (#644 — the
  honoured shape, the lone correct writer);
* analyzer + finding_verifier never published the counter at all (a tick was
  invisible; with unpriced spend the flag went up and the counter stayed
  out — the pair split the OTHER way).

The step report's own wording is the invariant (#605,
``step_report.py:219-222``): an accounting drop is an incomplete-cost
condition — "both markers, never one without the other". #633 stated the
pairing; #644 shipped the honoured shape in one writer.

The fix makes the pairing ONE rule: ``incomplete_markers`` (the PR#661
"ONE implementation" home for the incompleteness kinds — its comment block
literally anticipates "a third kind is a change to two functions") gains
the ``accounting_errors=`` counter kind, and all five writers route through
it. A non-int / non-positive counter is SKIPPED, never coerced (the #697
F3 guard class).

Every test here drives PRODUCTION entry points (``analyze_reachability``,
``run_dynamic_tests``, ``run_analysis``, ``verify_batch``,
``enhance_dataset_agentic``) with the repo's established stub patterns.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.llm_client import (  # noqa: E402
    TokenTracker,
    incomplete_markers,
    record_accounting_error,
    reset_global_tracker,
    reset_warning_state,
)


@pytest.fixture(autouse=True)
def _clean_counter_and_tracker():
    """The #605 counter is PROCESS-GLOBAL and these tests drive the GLOBAL
    tracker — reset both before AND after every test (the repo's convention
    for singleton-touching tests)."""
    reset_global_tracker()
    reset_warning_state()
    yield
    reset_global_tracker()
    reset_warning_state()


def _read_summary(checkpoint_dir) -> dict:
    return json.loads((Path(checkpoint_dir) / "_summary.json").read_text())


def _pair_or_none(usage) -> str:
    """The diagnostic the issue's table shows: which markers a usage dict
    carries, for the assertion messages."""
    flag = "cost_incomplete" in usage
    ctr = "accounting_errors" in usage
    return f"cost_incomplete={'Y' if flag else 'N'} accounting_errors={'Y' if ctr else 'N'}"


# ===========================================================================
# The builder — the ONE rule (#644 shape: counter => flag)
# ===========================================================================
def test_builder_pairs_the_counter_with_the_flag():
    """``incomplete_markers(accounting_errors=1)`` emits BOTH markers — the
    counter implies the flag (an accounting error is an incomplete-cost
    condition even when every model is priced; the step report's
    step_report.py:219-222 wording, now ONE rule for all five writers)."""
    out = incomplete_markers(accounting_errors=1)
    assert out.get("accounting_errors") == 1
    assert out.get("cost_incomplete") is True
    # the pair also rides WITH the unpriced kinds — three kinds, one flag
    out2 = incomplete_markers(["m"], accounting_errors=2)
    assert out2 == {"cost_incomplete": True, "unpriced_models": ["m"],
                    "accounting_errors": 2}


def test_builder_skips_a_non_int_counter():
    """The #697 F3 guard class: a garbage counter is SKIPPED, never coerced
    to a fabricated marker pair (bool excluded — True is not a count)."""
    assert incomplete_markers(accounting_errors="3") == {}
    assert incomplete_markers(accounting_errors=True) == {}
    assert incomplete_markers(accounting_errors=-1) == {}
    assert incomplete_markers(accounting_errors=0) == {}
    assert incomplete_markers(accounting_errors=None) == {}
    # the two unpriced kinds are untouched by a garbage counter
    out = incomplete_markers(["m"], accounting_errors="3")
    assert out == {"cost_incomplete": True, "unpriced_models": ["m"]}


# ===========================================================================
# llm_reachability — the counter-without-flag writer (RED at base)
# ===========================================================================
def _llr_drive(tmp_path, tracker, seed=None):
    """Drive the REAL analyze_reachability with the 532 harness's adapter,
    PRICED (the stock FakeAdapter binds ``claude-test`` with no pricing
    record, so every one of its turns lands in the #216 kind — a marker the
    clean-run controls here must not fire)."""
    from core.llm_reachability import analyze_reachability
    from tests.test_issue532_llr_resume import (
        FakeAdapter, _binding, _canned, _make_unit, _sig,
    )

    class _PricedFakeAdapter(FakeAdapter):
        pricing = {"claude-test": {"input": 2.0, "output": 4.0}}

    if seed:
        seed(tracker)
    import tempfile
    cp_dir = tempfile.mkdtemp(dir=str(tmp_path))
    analyze_reachability(
        {"units": [_make_unit("a:f1")]},
        binding=_binding(_PricedFakeAdapter([_canned(_sig("a:f1"))])),
        checkpoint_path=cp_dir, tracker=tracker,
    )
    return _read_summary(cp_dir)["usage"]


def test_llr_tick_only_summary_carries_both_markers(tmp_path):
    """A tick with every model priced: the llr ``_summary.json`` usage must
    carry the flag AND the counter (base published the counter alone —
    ``{accounting_errors: 1}`` with no ``cost_incomplete``)."""
    record_accounting_error()  # the single tick — the issue's repro
    usage = _llr_drive(tmp_path, TokenTracker())
    assert usage.get("accounting_errors") == 1, _pair_or_none(usage)
    assert usage.get("cost_incomplete") is True, (
        f"llr/_summary.json split the pair after a single accounting tick: "
        f"{_pair_or_none(usage)} — the counter without the flag (the #633 "
        f"pairing invariant, the step report's step_report.py:219-222 "
        f"wording: both markers, never one without the other)")


# ===========================================================================
# dynamic_tester — the counter-without-flag writer (RED at base)
# ===========================================================================
def _dt_registry():
    from utilities.llm import PhaseBinding

    class _Adapter:
        name = "anthropic"
        supports_tools = True
        pricing = {}

    class _Registry:
        def get(self, phase):
            return PhaseBinding(phase=phase, adapter=_Adapter(), model="m",
                                provider_name="anthropic")

    return _Registry()


def _drive_dt(tmp_path, finding=None):
    """Drive the REAL run_dynamic_tests over one finding whose language has
    no Docker template — the run completes with a SKIPPED result, never
    touching Docker or the LLM, and every write_summary fires."""
    from utilities.dynamic_tester import run_dynamic_tests

    out_dir = tmp_path / "dt_out"
    out_dir.mkdir()
    pipeline = tmp_path / "pipeline_output.json"
    pipeline.write_text(json.dumps({
        "repository": {"name": "t", "language": "unknown"},
        "application_type": "web",
        "findings": [finding or {"id": "f1", "stage2_verdict": "vulnerable",
                                 "location": {"file": "f.nolanguage"}}],
    }))
    run_dynamic_tests(str(pipeline), str(out_dir), registry=_dt_registry(),
                      checkpoint_path=str(out_dir / "dt_checkpoints"))
    return _read_summary(out_dir / "dt_checkpoints")


def test_dt_tick_only_summary_carries_both_markers(tmp_path):
    record_accounting_error()  # the single tick
    usage = _drive_dt(tmp_path)["usage"]
    assert usage.get("accounting_errors") == 1, _pair_or_none(usage)
    assert usage.get("cost_incomplete") is True, (
        f"dynamic-test/_summary.json split the pair after a single "
        f"accounting tick: {_pair_or_none(usage)} — the counter without "
        f"the flag")


# ===========================================================================
# analyzer — the never-published-counter writer (RED at base)
# ===========================================================================
def _drive_analyze(tmp_path, monkeypatch, spend=None):
    """The 626 analyzer drive: monkeypatched _run_detection, real
    run_analysis, read analyze_checkpoints/_summary.json."""
    from core import analyzer
    from utilities.llm import PhaseBinding

    dataset_path = tmp_path / "dataset.json"
    dataset_path.write_text(json.dumps({"units": [{"id": "a:f", "code": "x=1"}]}))
    output_dir = tmp_path / "out"

    def fake_run_detection(units, binding, json_corrector, app_context,
                           workers, checkpoint=None, summary_callback=None):
        if spend:
            spend()
        if summary_callback:
            summary_callback("safe", usage={"input_tokens": 10_000,
                                            "output_tokens": 1_000,
                                            "cost_usd": 0.045})
        return ([{"unit_id": "a:f", "finding": "safe", "verdict": "SAFE",
                  "confidence": 90, "vulnerabilities": [], "reasoning": "r"}],
                {u["id"]: "" for u in units})

    class _Adapter:
        name = "anthropic"
        supports_tools = True
        pricing = {}

    class _FakeRegistry:
        def get(self, phase):
            return PhaseBinding(phase=phase, adapter=_Adapter(), model="m",
                                provider_name="anthropic")

    monkeypatch.setattr(analyzer, "_run_detection", fake_run_detection)
    monkeypatch.setattr(analyzer, "_analyze_fingerprint",
                        lambda binding, ctx_sha=None: {"key_digest": "sha256:test"})
    analyzer.run_analysis(str(dataset_path), str(output_dir),
                          registry=_FakeRegistry(), workers=1)
    return _read_summary(output_dir / "analyze_checkpoints")


def _cache_unpriced_spend():
    from tests.test_issue626_marker_sites_executed import (
        _CACHE_DETAILS, _PRICED_NO_CACHE_RATES,
    )
    from utilities.llm_client import get_global_tracker
    get_global_tracker().record_call(
        model="new-model", input_tokens=10_000, output_tokens=1_000,
        pricing=dict(_PRICED_NO_CACHE_RATES),
        usage_details=dict(_CACHE_DETAILS))


def test_analyze_tick_only_summary_carries_both_markers(tmp_path,
                                                        monkeypatch):
    """A tick alone: the analyze ``_summary.json`` usage must carry BOTH
    markers (base published NEITHER — the counter was never consulted)."""
    record_accounting_error()
    usage = _drive_analyze(tmp_path, monkeypatch)["usage"]
    assert usage.get("accounting_errors") == 1, _pair_or_none(usage)
    assert usage.get("cost_incomplete") is True, (
        f"analyze/_summary.json swallowed the accounting tick entirely: "
        f"{_pair_or_none(usage)} — the writer never consulted the counter")


def test_analyze_flag_up_tick_summary_carries_the_counter(tmp_path,
                                                          monkeypatch):
    """The falsifier's other half: with the flag already up (cache-unpriced
    spend) AND a tick, the analyze summary must carry the counter too —
    base raised the flag and dropped the counter (the pair split the other
    way)."""
    record_accounting_error()
    usage = _drive_analyze(tmp_path, monkeypatch,
                           spend=_cache_unpriced_spend)["usage"]
    assert usage.get("cost_incomplete") is True
    assert usage.get("unpriced_cache_models") == ["new-model"]
    assert usage.get("accounting_errors") == 1, (
        f"analyze/_summary.json carried the flag without the counter after "
        f"a tick: {_pair_or_none(usage)} — 'both markers, never one "
        f"without the other'")


# ===========================================================================
# finding_verifier — the never-published-counter writer (RED at base)
# ===========================================================================
def test_verify_tick_only_summary_carries_both_markers(tmp_path):
    from tests.test_issue626_marker_sites_executed import _drive_verify
    record_accounting_error()
    summary, _tracker = _drive_verify(tmp_path)
    usage = summary["usage"]
    assert usage.get("accounting_errors") == 1, _pair_or_none(usage)
    assert usage.get("cost_incomplete") is True, (
        f"verify/_summary.json swallowed the accounting tick entirely: "
        f"{_pair_or_none(usage)} — the writer never consulted the counter")


def test_verify_flag_up_tick_summary_carries_the_counter(tmp_path):
    from tests.test_issue626_marker_sites_executed import _drive_verify
    record_accounting_error()
    # pricing=None: the #216 kind puts the flag up WITHOUT the tick
    summary, _tracker = _drive_verify(tmp_path, pricing=None)
    usage = summary["usage"]
    assert usage.get("cost_incomplete") is True
    assert "new-model" in usage.get("unpriced_models", [])
    assert usage.get("accounting_errors") == 1, (
        f"verify/_summary.json carried the flag without the counter after "
        f"a tick: {_pair_or_none(usage)}")


# ===========================================================================
# context_enhancer — the honoured shape (the control; green at base)
# ===========================================================================
def test_enhance_tick_summary_carries_both_markers(tmp_path):
    """The #644 writer already pairs the markers — this pins the shape the
    fix generalizes, so the shared builder cannot regress the one writer
    that was right."""
    from tests.test_issue626_marker_sites_executed import (
        _drive_enhance, _unit,
    )

    def fake(unit, index, binding, tracker, verbose):
        record_accounting_error()
        unit["llm_context"] = {"confidence": "high", "reasoning": "r"}
        return unit

    cp_dir = tmp_path / "enhance_checkpoints"
    cp_dir.mkdir()
    s = _drive_enhance({"units": [_unit("u1")]}, str(cp_dir), fake)
    usage = s["usage"]
    assert usage.get("accounting_errors") == 1, _pair_or_none(usage)
    assert usage.get("cost_incomplete") is True, _pair_or_none(usage)


# ===========================================================================
# The present-only convention survives (controls; green at base)
# ===========================================================================
def test_llr_clean_run_carries_neither_marker(tmp_path):
    """A healthy run's summary stays byte-identical to pre-#699 — the fix
    must never fabricate a marker pair on clean spend (the #605/#626
    present-only contract)."""
    usage = _llr_drive(tmp_path, TokenTracker())
    assert "cost_incomplete" not in usage, usage
    assert "accounting_errors" not in usage, usage


def test_dt_clean_run_carries_neither_marker(tmp_path):
    usage = _drive_dt(tmp_path)["usage"]
    assert "cost_incomplete" not in usage, usage
    assert "accounting_errors" not in usage, usage


def test_analyze_clean_run_carries_neither_marker(tmp_path, monkeypatch):
    usage = _drive_analyze(tmp_path, monkeypatch)["usage"]
    assert "cost_incomplete" not in usage, usage
    assert "accounting_errors" not in usage, usage


def test_verify_clean_run_carries_neither_marker(tmp_path):
    from tests.test_issue626_marker_sites_executed import _drive_verify
    # fully-priced cache rates + no cache detail: the sole call is complete
    summary, _tracker = _drive_verify(
        tmp_path, pricing={"input": 3.0, "output": 15.0,
                           "cache_read": 0.1, "cache_write": 0.2},
        usage_details={})
    usage = summary["usage"]
    assert "cost_incomplete" not in usage, usage
    assert "accounting_errors" not in usage, usage


# ===========================================================================
# The llr/dt shape quirk: the #216 list is unconditional under the flag
# (the pre-#626 contract these blocks ship — pinned through the fix)
# ===========================================================================
def test_llr_cache_only_keeps_the_unconditional_list_shape(tmp_path):
    """Cache-only incompleteness: the llr block writes ``unpriced_models:
    []`` unconditionally under the flag (the pre-#626 shape contract the
    block documents) — the builder conversion must not drop the empty list."""
    from tests.test_issue626_marker_sites_executed import (
        _CACHE_DETAILS, _PRICED_NO_CACHE_RATES,
    )

    def seed(tracker):
        tracker.record_call("priced/model", 10_000, 1_000,
                            pricing=dict(_PRICED_NO_CACHE_RATES),
                            usage_details=dict(_CACHE_DETAILS))

    usage = _llr_drive(tmp_path, TokenTracker(), seed=seed)
    assert usage.get("cost_incomplete") is True, _pair_or_none(usage)
    assert usage.get("unpriced_cache_models") == ["priced/model"]
    assert usage.get("unpriced_models") == [], (
        f"the pre-#626 shape contract: the #216 list ships unconditionally "
        f"under the flag (a cache-only incompleteness still names the empty "
        f"set) — got {usage}")


def test_dt_cache_only_keeps_the_unconditional_list_shape(tmp_path):
    """The dt sibling's identical quirk: cache-unpriced spend seeds the
    tracker BEFORE the stage baseline — the markers are run-cumulative, the
    deltas stay zero, and the usage block must still name the empty set."""
    _cache_unpriced_spend()
    usage = _drive_dt(tmp_path)["usage"]
    assert usage.get("cost_incomplete") is True, _pair_or_none(usage)
    assert usage.get("unpriced_cache_models") == ["new-model"]
    assert usage.get("unpriced_models") == [], (
        f"the dt block's pre-#626 shape contract: the #216 list ships "
        f"unconditionally under the flag — got {usage}")


# ===========================================================================
# The consolidation pin (AST, never text — a comment must not satisfy it):
# the pairing rule exists ONCE, in the builder; no writer keeps a copy
# ===========================================================================
_FIVE_WRITERS = [
    "core.llm_reachability",
    "utilities.dynamic_tester",
    "core.analyzer",
    "utilities.finding_verifier",
    "utilities.context_enhancer",
]


@pytest.mark.parametrize("module_name", _FIVE_WRITERS)
def test_every_writer_routes_the_counter_through_the_builder(module_name):
    """The issue's own shape demand, as a STRUCTURAL pin: each of the five
    writers builds its usage markers by CALLING ``incomplete_markers`` with
    the ``accounting_errors`` kind, and NONE of them carries a hand-rolled
    copy of the pairing rule (an ``x["accounting_errors"] = ...``
    assignment).

    Why AST and not a regex: the #626 fable round caught a source-text pin
    satisfied from a COMMENT — this pin parses the module and inspects the
    call nodes, so prose cannot satisfy it.

    RED at base for every writer: llr/dt call ``incomplete_markers`` without
    the counter kind (and publish it by hand below); analyze/verify never
    consult the counter at all; enhance hand-rolls the pair instead of
    routing it. This is also the E1/E2 discharge for the enhance
    consolidation hunk (context_enhancer@845cc60d): the hunk is
    behavior-preserving at head BECAUSE the builder already pairs the
    markers — which is the fix's whole point — so its constraint is this
    pin: reverting it re-installs the second copy of the rule and fails
    here."""
    import ast
    import inspect

    # static imports of ALL five prod modules (the screen resolves the
    # loaded symbols to the diff's prod hunks; a dynamic import_module
    # call would test itself)
    import core.analyzer
    import core.llm_reachability
    import utilities.context_enhancer
    import utilities.dynamic_tester
    import utilities.finding_verifier

    mod = {
        "core.llm_reachability": core.llm_reachability,
        "utilities.dynamic_tester": utilities.dynamic_tester,
        "core.analyzer": core.analyzer,
        "utilities.finding_verifier": utilities.finding_verifier,
        "utilities.context_enhancer": utilities.context_enhancer,
    }[module_name]
    tree = ast.parse(inspect.getsource(mod))

    calls_with_kind = []
    hand_copies = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and getattr(node.func, "id", None) == "incomplete_markers"):
            # the third kind arrives positionally (llr/dt pass the totals
            # reads in order) or by keyword (the stage-fold writers) —
            # either routing is the one implementation at work
            kinds = {kw.arg for kw in node.keywords}
            has_kind = ("accounting_errors" in kinds
                        or len(node.args) >= 3)
            if has_kind:
                calls_with_kind.append(node.lineno)
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if (isinstance(tgt, ast.Subscript)
                        and isinstance(tgt.slice, ast.Constant)
                        and tgt.slice.value == "accounting_errors"):
                    hand_copies.append(node.lineno)
    assert calls_with_kind, (
        f"{module_name} builds its usage markers without the builder's "
        f"accounting_errors kind — the pairing rule is not routed through "
        f"the one implementation")
    assert hand_copies == [], (
        f"{module_name} carries a hand-rolled copy of the pairing rule at "
        f"line(s) {hand_copies} — the issue's 'three different answers' "
        f"class; the rule exists once, in incomplete_markers")
