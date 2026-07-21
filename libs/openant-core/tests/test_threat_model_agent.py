"""The agent that WRITES OPENANT.THREATMODEL.md.

This is the last piece of the feature: until now a threat model had to be
hand-authored. The agent surveys the repository and produces the document.

Every test here runs against a fake adapter — zero API calls, zero cost.
"""

import json
from pathlib import Path

from utilities.llm.adapter import CompletionResult, TextBlock, ToolUseBlock

import pytest

from context.threat_model_agent import (
    ThreatModelGenerationError,
    generate_threat_model,
    threat_model_exists,
)

VALID_PAYLOAD = {
    "schema": "openant-threat-model",
    "schema_version": 1,
    "classification": "deployment orchestrator",
    "purpose": "Applies manifests to hosts.",
    "components": [{"name": "parser", "paths": ["pkg/"],
                    "component_type": "data parser", "exposure": "internal"}],
    "attacker_profiles": [{"id": "a1", "position": "adjacent", "description": "d",
                           "capabilities": ["c"], "cannot": ["l"],
                           "entry_via": ["src"], "impact": "i"}],
    "input_sources": {"src": {"trust": "semi_trusted", "description": "d"}},
    "vulnerability_criteria": ["crit"],
    "not_a_vulnerability": [],
    "impact_statement": "impact",
}


class FakeBinding:
    """Minimal PhaseBinding stand-in. No network."""

    def __init__(self, payload=None, supports_tools=True, raises=None):
        self.phase = "app_context"
        self.model = "fake-model"
        self.provider_name = "fake"
        self._payload = payload if payload is not None else VALID_PAYLOAD
        self._raises = raises
        outer = self

        class _Adapter:
            name = "fake"
            supports_tools = False

            def __init__(self):
                self.supports_tools = supports_tools

            # Signature matches utilities.llm.adapter.LLMAdapter.complete EXACTLY:
            # keyword-only, and returning a CompletionResult rather than a str.
            #
            # It used to be `complete(self, *a, **k) -> str`, and that is the single
            # reason a threat-model generator which had never once executed sat
            # behind a green suite: production called `complete(prompt=...)`, which
            # is not a parameter of the real protocol, and a fake looser than the
            # interface it stands in for absorbed the difference. A fake must be at
            # least as strict as the thing it replaces, or it tests the caller's
            # imagination instead of the caller.
            def complete(self, *, model, system, messages, max_tokens, tools=None):
                if outer._raises:
                    raise outer._raises
                # Model BOTH protocol shapes, because production now has two paths
                # and a fake that only knows one would leave the other untested —
                # which is the exact hole that let a never-executing generator sit
                # behind a green suite.
                if tools:
                    # Tool-capable: answer by calling `finish`, as a real model does.
                    return CompletionResult(
                        content=(ToolUseBlock(
                            id="call_1", name="finish", input=dict(outer._payload)),),
                        input_tokens=0, output_tokens=0,
                        stop_reason="tool_use", raw=None,
                    )
                return CompletionResult(
                    content=(TextBlock(text=json.dumps(outer._payload)),),
                    input_tokens=0,
                    output_tokens=0,
                    stop_reason="end_turn",
                    raw=None,
                )

        self.adapter = _Adapter()


@pytest.fixture
def repo(tmp_path):
    src = tmp_path / "repo"
    (src / "pkg").mkdir(parents=True)
    (src / "pkg" / "manifest.py").write_text("def apply(m):\n    pass\n")
    (src / "README.md").write_text("# orchardctl\nApplies manifests.\n")
    return src


class TestGeneration:
    def test_writes_the_file_to_the_repo_root(self, repo):
        path = generate_threat_model(repo, FakeBinding())
        assert path == repo / "OPENANT.THREATMODEL.md"
        assert path.is_file()

    def test_written_file_round_trips_through_the_loader(self, repo):
        """The output must be loadable by the consumer that will read it."""
        from context.threat_model import load_threat_model

        generate_threat_model(repo, FakeBinding())
        ctx = load_threat_model(repo)
        assert ctx is not None
        assert ctx.has_threat_model()
        assert ctx.application_type.startswith("custom:")

    def test_written_file_has_the_human_headings(self, repo):
        path = generate_threat_model(repo, FakeBinding())
        text = path.read_text()
        for heading in ("## Purpose", "## Attacker Profiles",
                        "## What is NOT a Vulnerability"):
            assert heading in text, f"missing {heading}"

    def test_generated_by_provenance_is_recorded(self, repo):
        generate_threat_model(repo, FakeBinding())
        from context.threat_model import parse_threat_model_md

        data = parse_threat_model_md(
            (repo / "OPENANT.THREATMODEL.md").read_text())
        assert data.get("generated_by", {}).get("model") == "fake-model"


class TestExistingFileIsNeverClobbered:
    """A committed threat model may be hand-curated. Never overwrite silently."""

    def test_existing_file_is_not_overwritten(self, repo):
        target = repo / "OPENANT.THREATMODEL.md"
        target.write_text("# hand written, do not lose\n")
        with pytest.raises(ThreatModelGenerationError, match="already exists"):
            generate_threat_model(repo, FakeBinding())
        assert "hand written" in target.read_text()

    def test_force_overwrites_but_backs_up_first(self, repo):
        target = repo / "OPENANT.THREATMODEL.md"
        target.write_text("# hand written\n")
        generate_threat_model(repo, FakeBinding(), force=True)
        assert (repo / "OPENANT.THREATMODEL.md.bak").read_text() == "# hand written\n"
        assert "hand written" not in target.read_text()

    def test_threat_model_exists_helper(self, repo):
        assert not threat_model_exists(repo)
        (repo / "OPENANT.THREATMODEL.md").write_text("x")
        assert threat_model_exists(repo)


class TestInvalidModelOutputIsRejected:
    """The agent's own output goes through the same validator as a human's."""

    def test_schema_invalid_output_raises_and_writes_nothing(self, repo):
        bad = {"schema": "openant-threat-model", "schema_version": 1}
        with pytest.raises(ThreatModelGenerationError):
            generate_threat_model(repo, FakeBinding(payload=bad))
        assert not (repo / "OPENANT.THREATMODEL.md").exists(), (
            "an invalid model was written to the repo"
        )

    def test_non_json_output_raises(self, repo):
        class Garbage(FakeBinding):
            def __init__(self):
                super().__init__()
                self.adapter.complete = lambda *a, **k: "I could not do that."

        with pytest.raises(ThreatModelGenerationError):
            generate_threat_model(repo, Garbage())

    def test_adapter_failure_is_wrapped(self, repo):
        with pytest.raises(ThreatModelGenerationError):
            generate_threat_model(repo, FakeBinding(raises=RuntimeError("boom")))


class TestAdapterWithoutToolSupport:
    def test_falls_back_to_single_shot(self, repo):
        """Not every provider supports tool use; the feature must still work."""
        path = generate_threat_model(repo, FakeBinding(supports_tools=False))
        assert path.is_file()


class TestCLISurface:
    """`openant threat-model` — the user-facing entry point."""

    def test_subcommand_is_registered(self):
        from openant.cli import build_parser

        args = build_parser().parse_args(["threat-model", "/repo"])
        assert args.repo == "/repo"

    def test_flags_exist(self):
        from openant.cli import build_parser

        args = build_parser().parse_args(
            ["threat-model", "/repo", "--force", "--validate-only"])
        assert args.force is True
        assert args.validate_only is True

    def test_validate_only_checks_an_existing_file_without_generating(self, repo, capsys):
        """CI-friendly: verify a committed model parses, spend nothing."""
        from openant.cli import build_parser, cmd_threat_model
        from context.threat_model import render_threat_model_md

        (repo / "OPENANT.THREATMODEL.md").write_text(
            render_threat_model_md(VALID_PAYLOAD))
        args = build_parser().parse_args(
            ["threat-model", str(repo), "--validate-only"])
        assert cmd_threat_model(args) == 0

    def test_validate_only_fails_on_a_malformed_file(self, repo):
        from openant.cli import build_parser, cmd_threat_model

        (repo / "OPENANT.THREATMODEL.md").write_text("# nope\n\nno json\n")
        args = build_parser().parse_args(
            ["threat-model", str(repo), "--validate-only"])
        assert cmd_threat_model(args) == 2

    def test_validate_only_reports_a_missing_file(self, repo):
        from openant.cli import build_parser, cmd_threat_model

        args = build_parser().parse_args(
            ["threat-model", str(repo), "--validate-only"])
        assert cmd_threat_model(args) == 2
