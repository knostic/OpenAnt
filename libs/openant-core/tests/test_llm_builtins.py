"""Pin the shape of ``openant-default``.

This config is the upgrade-safety contract: every existing Anthropic
user relies on it resolving to today's per-phase Claude IDs. Changing
any of these values is a CHANGELOG-worthy event, so the test failure
mode here is "you changed openant-default — was that intentional?".
"""

from __future__ import annotations

from utilities.llm import OPENANT_DEFAULT, PHASES, get_builtin_default


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
        assert OPENANT_DEFAULT.phases["enhance"].model == "claude-sonnet-4-20250514"
        assert OPENANT_DEFAULT.phases["report"].model == "claude-sonnet-4-20250514"
        assert OPENANT_DEFAULT.phases["dynamic_test"].model == "claude-sonnet-4-20250514"
        assert OPENANT_DEFAULT.phases["app_context"].model == "claude-sonnet-4-20250514"

    def test_accessor_returns_same_object(self):
        # Frozen dataclass, but if a future refactor turns it into a
        # factory function that builds fresh instances, callers
        # comparing by identity break silently. Pin the behavior.
        assert get_builtin_default() is OPENANT_DEFAULT
