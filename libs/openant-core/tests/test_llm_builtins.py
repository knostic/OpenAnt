"""Pin the shape of ``openant-default`` and the ``report`` CLI dispatch.

This config is the upgrade-safety contract: every existing Anthropic
user relies on it resolving to today's per-phase Claude IDs. Changing
any of these values is a CHANGELOG-worthy event, so the test failure
mode here is "you changed openant-default — was that intentional?".

The second half (``TestReportCliBindingDispatch``) is M2 regression
coverage: ``python -m report summary`` / ``disclosures`` must build a
``report`` :class:`PhaseBinding` and pass it down to the now
binding-required generator functions, instead of crashing with
``TypeError: ... missing 1 required positional argument: 'binding'``.
"""

from __future__ import annotations

import types

import pytest

from utilities.llm import OPENANT_DEFAULT, PHASES, PhaseBinding, get_builtin_default


class TestOpenantDefault:
    def test_name_is_stable(self):
        assert OPENANT_DEFAULT.name == "openant-default"

    def test_covers_every_phase_explicitly(self):
        # Per the user-approved design: every phase listed, no
        # _default fallback. Coverage parity with PHASES means a
        # newly-added phase is immediately reflected in the default.
        assert set(OPENANT_DEFAULT.phases) == set(PHASES)

    def test_every_phase_points_at_anthropic_provider(self):
        # The "anthropic" provider name is special-cased by the
        # registry's fallback synthesis (env-only credentials).
        # Renaming this without updating registry.resolve_provider
        # breaks fresh-install behavior.
        for phase, ref in OPENANT_DEFAULT.phases.items():
            assert ref.provider == "anthropic", (
                f"openant-default phase {phase!r} must use provider 'anthropic' "
                f"so set-api-key and the env-only fallback continue to work"
            )

    def test_historical_model_assignment(self):
        # Pin today's behavior. If Anthropic deprecates one of these
        # IDs, this test breaks loudly and the change is recorded in
        # the CHANGELOG.
        assert OPENANT_DEFAULT.phases["analyze"].model == "claude-opus-4-6"
        assert OPENANT_DEFAULT.phases["verify"].model == "claude-opus-4-6"
        assert OPENANT_DEFAULT.phases["llm_reach"].model == "claude-opus-4-6"
        # report restored to Opus (H1) — matches master's report generator.
        assert OPENANT_DEFAULT.phases["report"].model == "claude-opus-4-6"
        assert OPENANT_DEFAULT.phases["enhance"].model == "claude-sonnet-4-20250514"
        assert OPENANT_DEFAULT.phases["dynamic_test"].model == "claude-sonnet-4-20250514"
        assert OPENANT_DEFAULT.phases["app_context"].model == "claude-sonnet-4-20250514"

    def test_report_phase_defaults_to_opus(self):
        # H1 drift-guard. Master's report/generator.py used
        # MODEL="claude-opus-4-6"; the LLM-provider refactor silently
        # moved the builtin ``report`` default to Sonnet. Restore Opus so
        # the HTML-remediation / summary / disclosure sub-calls keep
        # producing Opus-quality output on a fresh, config-less install.
        # If you intend to change the report default, that is a
        # CHANGELOG-worthy event — update this assertion deliberately.
        assert OPENANT_DEFAULT.phases["report"].model == "claude-opus-4-6"

    def test_accessor_returns_same_object(self):
        # Frozen dataclass, but if a future refactor turns it into a
        # factory function that builds fresh instances, callers
        # comparing by identity break silently. Pin the behavior.
        assert get_builtin_default() is OPENANT_DEFAULT


# ---------------------------------------------------------------------------
# M2 — ``python -m report summary`` / ``disclosures`` binding dispatch
# ---------------------------------------------------------------------------


def _fake_binding() -> PhaseBinding:
    """A throwaway report binding. The generator functions are stubbed,
    so the adapter is never actually called — identity is all we check."""
    return PhaseBinding(
        phase="report",
        adapter=object(),
        model="claude-opus-4-6",
        provider_name="anthropic",
    )


def _patch_registry_build(monkeypatch, binding: PhaseBinding) -> None:
    """Stub the registry-build chain inside ``report.__main__`` so the
    dispatch never touches the filesystem / network. ``registry.get`` hands
    back our fake report binding regardless of phase."""
    import report.__main__ as m

    class _StubRegistry:
        config_name = "stub"

        def get(self, phase):
            assert phase == "report"
            return binding

    monkeypatch.setattr(m, "load_config_file", lambda: object(), raising=False)
    monkeypatch.setattr(m, "resolve_llm_config", lambda cf, name: object(), raising=False)
    monkeypatch.setattr(
        m, "build_phase_registry", lambda cf, cfg: _StubRegistry(), raising=False
    )
    monkeypatch.setattr(m, "probe_registry_or_raise", lambda reg: None, raising=False)


class TestReportCliOldArityWasBroken:
    """Repro: the OLD call arity — invoking the generators positionally
    the way ``__main__`` used to — raises TypeError because ``binding``
    is now required. This is the exact crash M2 fixes."""

    def test_summary_without_binding_raises_type_error(self):
        from report.generator import generate_summary_report

        with pytest.raises(TypeError):
            generate_summary_report({"findings": []})  # missing binding

    def test_disclosure_without_binding_raises_type_error(self):
        from report.generator import generate_disclosure

        with pytest.raises(TypeError):
            generate_disclosure({"short_name": "x"}, "prod/repo")  # missing binding


class TestReportCliBindingDispatch:
    """M2: the ``summary`` / ``disclosures`` command dispatch must build a
    report ``PhaseBinding`` and forward it to the generator functions."""

    def test_cmd_summary_passes_binding(self, monkeypatch, tmp_path):
        import report.__main__ as m

        binding = _fake_binding()
        _patch_registry_build(monkeypatch, binding)

        # Decode + schema-validate are not under test here.
        monkeypatch.setattr(m, "read_json", lambda p: {"findings": []})
        monkeypatch.setattr(m, "validate_pipeline_output", lambda d: None)

        captured = {}

        def _fake_summary(pipeline_data, passed_binding):
            captured["binding"] = passed_binding
            return ("# report", {"cost_usd": 0.0, "total_tokens": 0})

        monkeypatch.setattr(m, "generate_summary_report", _fake_summary)

        args = types.SimpleNamespace(
            input="pipeline_output.json",
            output=str(tmp_path / "SUMMARY.md"),
        )
        m.cmd_summary(args)

        assert isinstance(captured["binding"], PhaseBinding)
        assert captured["binding"] is binding

    def test_cmd_disclosures_passes_binding(self, monkeypatch, tmp_path):
        import report.__main__ as m

        binding = _fake_binding()
        _patch_registry_build(monkeypatch, binding)

        finding = {
            "short_name": "sql injection",
            "stage2_verdict": "confirmed",
        }
        monkeypatch.setattr(
            m, "read_json",
            lambda p: {"repository": {"name": "prod/repo"}, "findings": [finding]},
        )
        monkeypatch.setattr(m, "validate_pipeline_output", lambda d: None)

        captured = {}

        def _fake_disclosure(vuln, product_name, passed_binding):
            captured["binding"] = passed_binding
            captured["product_name"] = product_name
            return ("# disclosure", {"cost_usd": 0.0, "total_tokens": 0})

        monkeypatch.setattr(m, "generate_disclosure", _fake_disclosure)

        args = types.SimpleNamespace(
            input="pipeline_output.json",
            output=str(tmp_path / "disclosures"),
        )
        m.cmd_disclosures(args)

        assert isinstance(captured["binding"], PhaseBinding)
        assert captured["binding"] is binding
        assert captured["product_name"] == "prod/repo"
