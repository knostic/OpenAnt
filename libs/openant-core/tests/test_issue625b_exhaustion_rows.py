"""The additional #625 rows from the r2 exhaustion pass: the real
unconsumed-warning mirror (with stderr receipts), the gate-ordering pin,
the step-report behavioral folds (both branches), the 4096 shadow pin,
and the counter hygiene."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import utilities.llm.providers.anthropic as anth  # noqa: E402
import utilities.llm.registry as registry_mod  # noqa: E402
from tests.test_issue625_thinking_policy import (  # noqa: E402
    _ALL_PHASES)
from utilities.llm.config import (  # noqa: E402
    ConfigError,
    ConfigFile,
    LLMConfig,
    PhaseRef,
    ProviderConfig,
)


def test_unconsumed_thinking_warning_fires_once(capsys):
    """A provider whose adapter does not declare the thinking kwarg warns
    ONCE per (provider, type) — the #604 unconsumed-knob mirror, with the
    stderr receipts (the r2 catch: the earlier row was vacuous)."""
    import utilities.llm_client as llc  # noqa: PLC0415
    llc.reset_warning_state()
    cf = ConfigFile(llm_providers={
        "g": ProviderConfig(name="g", type="google",
                                    api_key="dummy-key")})
    r = registry_mod.build_adapter(
        cf.llm_providers["g"], thinking={"type": "adaptive"})
    assert r is not None
    err = capsys.readouterr().err
    assert "does not consume it" in err and "google" in err, (
        "the one-time warning must fire")
    # second build: no second warning (the per-(provider,type) set)
    registry_mod.build_adapter(
        cf.llm_providers["g"], thinking={"type": "adaptive"})
    assert "does not consume it" not in capsys.readouterr().err
    # the reset re-arms (the per-scan lifecycle)
    llc.reset_warning_state()
    registry_mod.build_adapter(
        cf.llm_providers["g"], thinking={"type": "adaptive"})
    assert "does not consume it" in capsys.readouterr().err
    llc.reset_warning_state()


def test_gated_phase_on_nonconsuming_provider_raises_without_warning(capsys):
    """The gate fires BEFORE any adapter build — a thinking-configured
    tool phase on a NON-consuming provider raises the ConfigError WITHOUT
    the spurious unconsumed-knob warning first (the ordering pin)."""
    import utilities.llm_client as llc  # noqa: PLC0415
    llc.reset_warning_state()
    cf = ConfigFile(llm_providers={
        "g": ProviderConfig(name="g", type="google",
                                    api_key="dummy-key")})
    phases = {p: PhaseRef(provider="g", model="m") for p in _ALL_PHASES}
    phases["verify"] = PhaseRef(provider="g", model="m",
                                thinking={"type": "adaptive"})
    try:
        registry_mod.build_phase_registry(cf, LLMConfig(name="c", phases=phases))
    except ConfigError as e:
        assert "tool-calling phase" in str(e)
    else:
        raise AssertionError("the gate must fire")
    assert "does not consume it" not in capsys.readouterr().err, (
        "the ConfigError surfaces WITHOUT the spurious warning first")


def test_step_report_success_branch_surfaces_dropped_blocks(tmp_path):
    """The behavioral fold: a dropped block during the step lands in the
    step report's token_usage (the #605 harness shape)."""
    import utilities.llm_client as llc  # noqa: PLC0415
    from core.step_report import step_context  # noqa: PLC0415
    llc.reset_warning_state()
    try:
        with step_context("analyze", str(tmp_path), inputs={}) as ctx:
            ctx.summary = {"ok": True}
            anth._count_dropped_block("refusal")
        report = Path(tmp_path, "analyze.report.json").read_text()
        assert '"dropped_blocks"' in report, (
            "the per-kind count reaches the persisted step report")
        assert '"refusal": 1' in report
    finally:
        llc.reset_warning_state()


def test_step_report_error_branch_surfaces_dropped_blocks(tmp_path, monkeypatch):
    """The error branch rebuilds token_usage wholesale — the counts must
    surface there too (an accounting error and dropped blocks are not
    mutually exclusive; the r2 asymmetry catch)."""
    import utilities.llm_client as llc  # noqa: PLC0415
    from core import step_report as sr  # noqa: PLC0415
    llc.reset_warning_state()

    import core.tracking as tracking_mod  # noqa: PLC0415

    def _poisoned_get_usage():
        raise RuntimeError("boom")
    monkeypatch.setattr(tracking_mod, "get_usage", _poisoned_get_usage)
    try:
        with sr.step_context(
                "analyze", str(tmp_path), inputs={}) as ctx:
            ctx.summary = {"ok": True}
            anth._count_dropped_block("thinking")
        report = Path(tmp_path, "analyze.report.json").read_text()
        assert '"accounting_error": true' in report, (
            "the poisoned snapshot must mark the step errored")
        assert '"dropped_blocks"' in report, (
            "the error branch must not lose the counts")
        assert '"thinking": 1' in report
    finally:
        llc.reset_warning_state()


def test_the_4096_bound_pins_the_real_subcall_caps():
    """The 4096 literal is a hand-kept shadow of the pipeline's smallest
    sub-call cap — pinned to the real constants so drift fails loudly."""
    import utilities.stage1_consistency as s1  # noqa: PLC0415
    import report.html_report as hr  # noqa: PLC0415
    assert 4096 == s1.MAX_TOKENS == hr.MAX_TOKENS, (
        "the parse-time bound must track the real sub-call caps")


def test_totals_flow_row_leaves_no_global_counter_residue():
    """The counter hygiene pin (the r2 LOW): every row that touches the
    process-global counter leaves it clean."""
    import utilities.llm_client as llc  # noqa: PLC0415
    llc.reset_warning_state()
    assert anth.get_dropped_block_counts() == {}
    anth._count_dropped_block("x")
    assert anth.get_dropped_block_counts() == {"x": 1}
    llc.reset_warning_state()
    assert anth.get_dropped_block_counts() == {}