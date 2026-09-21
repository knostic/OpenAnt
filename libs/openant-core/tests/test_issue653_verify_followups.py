"""Regression tests for issue #653 — the three live PR-#652 follow-ups.

Item 1 — the third digest fixture (web_app routing class): #652's digest
helpers cover cli_tool/library (the suppress branch and the untrusted branch).
A web_app with NO untrusted boundaries is the third routing class: its
``_is_untrusted_input_context`` is False (the web_app exclusion) and its
``suppress_local_only`` is True — a degenerate web_app (no untrusted
boundaries) that the descriptor must not call a CLI tool/library.

Item 2 — the standalone-verify stdout lane drops ``attacker_model``:
``verify_step_summary`` (the shared construction) carries it present-only
(schemas.py:387); ``VerifyResult.to_dict`` (the standalone stdout envelope's
source, cli.py's success()) does not — the reader loses the methodology line.

Item 3 — the degenerate web-app class: a web_app with all-trusted boundaries
falls to the ``remote_only`` descriptor whose text calls it "this CLI
tool/library" — wrong for a web application. The boundary condition matters:
``requires_remote_trigger=False`` alone does NOT make the suppress/descriptor
class right (a web_app's remote surface is the browser, not the operator's
own local access).
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from context.application_context import ApplicationContext
from prompts.verification_prompts import (
    _builtin_context_digest_renders,
    _builtin_persona_digest_renders,
    attacker_model_descriptor,
)


def _degenerate_web_app() -> ApplicationContext:
    """The third routing class: a web_app whose boundaries are all trusted."""
    return ApplicationContext(
        application_type="web_app",
        purpose="digest fixture",
        trust_boundaries={"http_body": "trusted", "http_headers": "trusted"},
        requires_remote_trigger=False,
    )


class TestItem1ThirdDigestFixture:
    def test_web_app_digest_fixture_renders_at_base(self):
        """RED at base: neither digest helper covers the web_app class."""
        renders = _builtin_context_digest_renders()
        assert any("web_app" in r or "web application" in r for r in renders), (
            "the third digest fixture (web_app routing class) must render — "
            "a routing change re-routing a web_app is invisible to verify's "
            "checkpoint fold without it")

    def test_web_app_persona_digest_renders_at_base(self):
        renders = _builtin_persona_digest_renders()
        # the web_app fixture's context block renders the literal type
        # (the enum value is the routing discriminator)
        assert any("web_app" in r for r in renders), (
            "the persona digest must cover the web_app routing class")


class TestItem2StdoutAttackerModel:
    def _minimal_verify_result(self, **overrides):
        """A minimally-constructed VerifyResult (the dataclass fields the
        to_dict path reads; attacker_model defaults None)."""
        from core.schemas import VerifyResult
        from datetime import datetime, timezone
        defaults = dict(
            verified_results_path="/tmp/verified.json",
            findings_input=0,
            findings_verified=0,
            agreed=0,
            disagreed=0,
            disagreed_inconclusive=0,
            disagreed_protected=0,
            confirmed_vulnerabilities=0,
            needs_review=0,
            error_count=0,
            units_analyzed_total=0,
        )
        defaults.update(overrides)
        return VerifyResult(**defaults)

    def test_to_dict_carries_attacker_model(self):
        """BEHAVIORAL (the T1 round-1 fix: the source-inspection form was
        vacuous — satisfied by the comment alone): a stamped descriptor
        rides the standalone stdout envelope; the unstamped case omits
        the key (present-only, matching verify_step_summary's truthiness)."""
        stamped = self._minimal_verify_result(
            attacker_model={"kind": "remote_only", "attacker": "..."})
        assert stamped.to_dict()["attacker_model"] == {
            "kind": "remote_only", "attacker": "..."}, (
            "a stamped attacker_model must ride to_dict — the standalone "
            "stdout envelope's methodology line")

    def test_to_dict_omits_attacker_model_when_absent(self):
        unstamped = self._minimal_verify_result()  # attacker_model=None
        assert "attacker_model" not in unstamped.to_dict(), (
            "present-only: the unstamped envelope carries no fabricated key")

    def test_to_dict_truthiness_matches_step_summary(self):
        """F3: to_dict's presence check uses the same truthiness as
        verify_step_summary ({} → omitted, not carried as a fabricated
        empty dict)."""
        empty_stamped = self._minimal_verify_result(attacker_model={})
        assert "attacker_model" not in empty_stamped.to_dict()


class TestItem3DegenerateWebAppDescriptor:
    def test_web_app_descriptor_is_not_a_cli_tool(self):
        """RED at base: the degenerate web_app's descriptor calls it a CLI
        tool/library — wrong for a web application."""
        descriptor = attacker_model_descriptor(_degenerate_web_app())
        assert "CLI" not in descriptor["attacker"], (
            f"a web_app's attacker model must not call it a CLI tool/library; "
            f"got: {descriptor['attacker']!r}")


def test_three_digest_fixtures_not_two():
    """The digest helpers carry THREE routing classes after the fix
    (was: two)."""
    assert len(_builtin_context_digest_renders()) == 3
    assert len(_builtin_persona_digest_renders()) == 4  # 3 user prompts + the web_app system arm


class TestPromptTextsBehavioral:
    """T1 round-2 N2: the three web_app prompt-text branches are PINNED
    behaviorally (the round-1 disease one level up — presence-only tests
    passed with the branches deleted)."""

    def _web(self):
        return ApplicationContext(
            application_type="web_app", purpose="digest fixture",
            trust_boundaries={"http_body": "trusted"},
            requires_remote_trigger=False)

    def _cli(self):
        return ApplicationContext(
            application_type="cli_tool", purpose="digest fixture",
            trust_boundaries={"x": "trusted"},
            requires_remote_trigger=False)

    def test_web_app_user_prompt_says_web_app(self):
        from prompts.verification_prompts import get_verification_prompt
        r = get_verification_prompt(
            code="", finding="", attack_vector="", reasoning="",
            app_context=self._web())
        assert "web application" in r.lower(), "the CRITICAL block must say web application"
        assert "CLI tool" not in r, "the web_app render must not carry the CLI-tool framing"

    def test_web_app_system_prompt_says_web_app(self):
        from prompts.verification_prompts import (
            get_verification_system_prompt, SYSTEM_ARM_REMOTE_ONLY_WEB)
        s = get_verification_system_prompt(self._web())
        assert "web application" in s.lower(), "the system arm must say web application"
        assert "CLI tool" not in s, "the web_app system arm must not carry the CLI framing"
        assert SYSTEM_ARM_REMOTE_ONLY_WEB in s, "the hoisted constant is the arm actually served"

    def test_web_app_persona_is_web(self):
        from prompts.verification_prompts import PERSONA_REMOTE_ONLY_WEB, get_verification_prompt
        r = get_verification_prompt(
            code="", finding="", attack_vector="", reasoning="",
            app_context=self._web())
        assert PERSONA_REMOTE_ONLY_WEB in r, "the web_app persona must be the web constant"
        assert "being the user who runs the application" not in r.lower(), (
            "the CLI persona's 'user who runs the application' rationale is "
            "false for a web app")

    def test_cli_tool_renders_unchanged(self):
        from prompts.verification_prompts import (
            get_verification_prompt, get_verification_system_prompt,
            PERSONA_REMOTE_ONLY, SYSTEM_ARM_REMOTE_ONLY)
        user = get_verification_prompt(
            code="", finding="", attack_vector="", reasoning="",
            app_context=self._cli())
        system = get_verification_system_prompt(self._cli())
        assert "CLI tool" in user, "the cli_tool render keeps the CLI framing"
        assert SYSTEM_ARM_REMOTE_ONLY in system, "the cli_tool system arm keeps the CLI constant"
        assert PERSONA_REMOTE_ONLY in user, "the cli_tool persona keeps the CLI constant"
        assert "web application" not in user.lower(), "the cli_tool render gains no web framing"

    def test_web_app_system_arm_in_fold(self):
        """N1's pin (mutation-hardened after round 3's N4: the presence-only
        form passed with the arm's render deleted): mutating the web_app
        arm's CONSTANT moves the folded texts; mutating the web_app PERSONA
        moves them too."""
        import prompts.verification_prompts as vp
        from core.verifier import _verify_template_texts
        base = [r() for r in _verify_template_texts()]

        arm = vp.SYSTEM_ARM_REMOTE_ONLY_WEB
        try:
            vp.SYSTEM_ARM_REMOTE_ONLY_WEB = arm + "\n# mutated"
            mutated = [r() for r in _verify_template_texts()]
        finally:
            vp.SYSTEM_ARM_REMOTE_ONLY_WEB = arm
        assert mutated != base, (
            "mutating the web_app system arm must move the fold — an arm "
            "invisible to templates_sha is the #621 failure mode")

        persona = vp.PERSONA_REMOTE_ONLY_WEB
        try:
            vp.PERSONA_REMOTE_ONLY_WEB = persona + "\n# mutated"
            mutated2 = [r() for r in _verify_template_texts()]
        finally:
            vp.PERSONA_REMOTE_ONLY_WEB = persona
        assert mutated2 != base, (
            "mutating the web_app persona must move the fold")

        # the arm text itself appears in the renders (not satisfied by the
        # user-prompt render at index 2 — the round-3 escape)
        from prompts.verification_prompts import (
            _builtin_persona_digest_renders, SYSTEM_ARM_REMOTE_ONLY_WEB,
            PERSONA_REMOTE_ONLY_WEB)
        renders = _builtin_persona_digest_renders()
        assert any(SYSTEM_ARM_REMOTE_ONLY_WEB in r for r in renders), (
            "the system arm's own text is in the fold renders")
        assert any(PERSONA_REMOTE_ONLY_WEB in r for r in renders), (
            "the web persona's own text is in the fold renders")
        # the web_app system-prompt render is in the fold: the digest
        # moved from the 2-fixture era (the third fixture + the arm join
        # in the same fold — the #621 contract extended)
        from prompts.verification_prompts import _builtin_persona_digest_renders
        renders = _builtin_persona_digest_renders()
        assert len(renders) == 4, (
            "the persona renders: 3 user prompts + the web_app system prompt "
            "(the fold-visible arm)")
        system_in_renders = any("web application" in r.lower() for r in renders)
        assert system_in_renders, "the web_app system arm is fold-visible"
