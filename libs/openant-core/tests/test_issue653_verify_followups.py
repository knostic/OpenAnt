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
    def test_to_dict_carries_attacker_model(self):
        """RED at base: to_dict omits the attacker_model the step summary
        carries — the standalone-verify stdout lane drops it."""
        from core.schemas import VerifyResult
        import dataclasses
        fields = {f.name for f in dataclasses.fields(VerifyResult)}
        assert "attacker_model" in fields
        # the step summary's construction names it present-only; to_dict must too
        import inspect
        from core.schemas import verify_step_summary
        src = inspect.getsource(verify_step_summary)
        assert "attacker_model" in src
        to_dict_src = inspect.getsource(VerifyResult.to_dict)
        assert "attacker_model" in to_dict_src, (
            "VerifyResult.to_dict (the standalone stdout envelope's source) "
            "must carry attacker_model present-only, like verify_step_summary")


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
    assert len(_builtin_persona_digest_renders()) == 3
