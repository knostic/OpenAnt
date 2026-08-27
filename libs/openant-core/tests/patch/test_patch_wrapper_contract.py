"""Contract tests for the openant-patch integration (core/patch.py + cmd_patch).

These are the tests unique to THIS integration -- not ported from the
standalone Auto Patcher project, which had no notion of "a Go CLI triggered
this and must never get a report indistinguishable from a real one."

Covers the specific safety/scope properties called out in the migration
plan:
  - a run never silently falls back to Auto Patcher's mock mode
  - suggested_fix/rejection_reason never reach the patch engine's input
  - the eligibility gate is an explicit allowlist (fails closed)
  - the envelope contract matches every other openant subcommand
  - the Trust Report is written as an artifact whose content this
    integration never inspects beyond existence

All hermetic: LLM_PROVIDER=mock, no network, no real repo, no Docker.
"""

import json
import os
from unittest import mock

import pytest

from core.patch import (
    PatchStepResult,
    _require_llm_provider,
    check_eligible,
    effective_verdict,
    find_finding_by_id,
    render_vulnerability_markdown,
    run_patch,
)


FIXTURE_FINDING_ELIGIBLE = {
    "id": "F-001",
    "name": "SQL Injection",
    "location": {"file": "app.py", "function": "handle_request"},
    "cwe_id": 89,
    "cwe_name": "SQL Injection",
    "stage1_verdict": "vulnerable",
    "stage2_verdict": "confirmed",
    "description": "User input reaches a raw SQL query unsanitized.",
    "vulnerable_code": "cursor.execute(query)",
    "impact": ["Full database read access"],
    "steps_to_reproduce": ["Send a crafted id"],
    "suggested_fix": "DO-NOT-LEAK-THIS-SUGGESTED-FIX",
    "rejection_reason": "DO-NOT-LEAK-THIS-REJECTION-REASON",
}

FIXTURE_FINDING_REJECTED = {
    **FIXTURE_FINDING_ELIGIBLE,
    "id": "F-002",
    "stage2_verdict": "rejected",
}


def _write_pipeline_output(tmp_path, findings):
    path = tmp_path / "pipeline_output.json"
    path.write_text(json.dumps({"findings": findings}))
    return str(path)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def test_find_finding_by_id_hit():
    f = find_finding_by_id([FIXTURE_FINDING_ELIGIBLE], "F-001")
    assert f["id"] == "F-001"


def test_find_finding_by_id_miss():
    with pytest.raises(ValueError, match="F-999"):
        find_finding_by_id([FIXTURE_FINDING_ELIGIBLE], "F-999")


@pytest.mark.parametrize(
    "stage1,stage2,eligible",
    [
        ("vulnerable", "confirmed", True),
        ("vulnerable", "agreed", True),
        ("vulnerable", "vulnerable", True),
        ("bypassable", "bypassable", True),
        ("vulnerable", "unverified", False),
        ("vulnerable", "error", False),
        ("vulnerable", "rejected", False),
        ("safe", "safe", False),
        ("vulnerable", "protected", False),
        ("vulnerable", "inconclusive", False),
        ("", "", False),
        ("vulnerable", "Confirmed", False),  # case-sensitive: fails closed, not normalized
        ("vulnerable", "quarantined", False),  # unknown future value: fails closed
        ("vulnerable", "", True),  # stage2 empty falls back to eligible stage1
        ("safe", "", False),  # stage2 empty falls back to ineligible stage1
    ],
)
def test_check_eligible_allowlist(stage1, stage2, eligible):
    finding = {"id": "X", "stage1_verdict": stage1, "stage2_verdict": stage2}
    if eligible:
        check_eligible(finding)  # must not raise
    else:
        with pytest.raises(ValueError):
            check_eligible(finding)


def test_effective_verdict_prefers_stage2():
    assert effective_verdict({"stage1_verdict": "vulnerable", "stage2_verdict": "confirmed"}) == "confirmed"


def test_effective_verdict_falls_back_to_stage1_when_stage2_empty():
    assert effective_verdict({"stage1_verdict": "vulnerable", "stage2_verdict": ""}) == "vulnerable"


def test_render_vulnerability_markdown_includes_key_fields():
    rendered = render_vulnerability_markdown(FIXTURE_FINDING_ELIGIBLE)
    for expected in ("F-001", "SQL Injection", "app.py", "handle_request",
                      "CWE-89", "confirmed", "cursor.execute(query)",
                      "Full database read access", "Send a crafted id"):
        assert expected in rendered


def test_render_vulnerability_markdown_never_includes_suggested_fix_or_rejection_reason():
    """Regression guard: OpenAnt's own suggested_fix/rejection_reason must
    never reach the patch engine's input -- they could bias the
    independently-generated candidate patch."""
    rendered = render_vulnerability_markdown(FIXTURE_FINDING_ELIGIBLE)
    assert "DO-NOT-LEAK-THIS-SUGGESTED-FIX" not in rendered
    assert "DO-NOT-LEAK-THIS-REJECTION-REASON" not in rendered


# ---------------------------------------------------------------------------
# F-31 / F-35: impact/steps_to_reproduce may arrive as a string instead of a
# list, and description/vulnerable_code may arrive as a non-string value.
# ---------------------------------------------------------------------------

def test_render_vulnerability_markdown_accepts_string_impact_and_steps():
    """F-31: a string impact/steps_to_reproduce must render as one bullet,
    not one bullet per character."""
    finding = {
        **FIXTURE_FINDING_ELIGIBLE,
        "impact": "Full database read access",
        "steps_to_reproduce": "Send a crafted id",
    }
    rendered = render_vulnerability_markdown(finding)
    assert "- Full database read access" in rendered
    assert "1. Send a crafted id" in rendered
    # the character-by-character bullet regression would produce this
    assert "- F\n- u\n- l\n- l" not in rendered


def test_render_vulnerability_markdown_accepts_list_impact_and_steps():
    """Existing list-shaped inputs keep rendering as before."""
    finding = {
        **FIXTURE_FINDING_ELIGIBLE,
        "impact": ["Full database read access", "Data exfiltration"],
        "steps_to_reproduce": ["Send a crafted id", "Read the response"],
    }
    rendered = render_vulnerability_markdown(finding)
    assert "- Full database read access" in rendered
    assert "- Data exfiltration" in rendered
    assert "1. Send a crafted id" in rendered
    assert "2. Read the response" in rendered


def test_render_vulnerability_markdown_coerces_non_string_description_and_code():
    """F-35: a non-string description/vulnerable_code must not raise."""
    finding = {
        **FIXTURE_FINDING_ELIGIBLE,
        "description": {"summary": "User input reaches a raw SQL query"},
        "vulnerable_code": ["cursor.execute(query)", "conn.commit()"],
    }
    rendered = render_vulnerability_markdown(finding)  # must not raise
    assert "User input reaches a raw SQL query" in rendered
    assert "cursor.execute(query)" in rendered


def test_render_vulnerability_markdown_empty_impact_and_steps_omit_sections():
    """No behavior regression: absent/empty fields still omit their sections."""
    finding = {**FIXTURE_FINDING_ELIGIBLE, "impact": [], "steps_to_reproduce": []}
    rendered = render_vulnerability_markdown(finding)
    assert "## Impact" not in rendered
    assert "## Attack scenario" not in rendered


# ---------------------------------------------------------------------------
# run_patch end-to-end (mock mode)
# ---------------------------------------------------------------------------

def test_run_patch_happy_path(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    po_path = _write_pipeline_output(tmp_path, [FIXTURE_FINDING_ELIGIBLE, FIXTURE_FINDING_REJECTED])

    result = run_patch(po_path, "F-001", str(tmp_path), repo_root=None)

    assert isinstance(result, PatchStepResult)
    assert result.finding_id == "F-001"
    assert os.path.exists(result.vulnerability_path)
    assert os.path.exists(result.trust_report_path)
    assert result.vulnerability_path == str(tmp_path / "patch" / "F-001-vulnerability.md")
    assert result.trust_report_path == str(tmp_path / "patch" / "F-001-trust-report.md")


def test_run_patch_without_repo_root_never_scans_process_cwd(tmp_path, monkeypatch):
    """F-01: this module's own docstring calls these tests "hermetic ...
    no real repo" -- that was only true of the *inputs*. Before the fix,
    repo_root=None made the engine fall back to Path.cwd() and scan
    whatever directory pytest happened to be invoked from (this repo's own
    hundreds of test files), embedding real absolute paths into the
    on-disk Trust Report artifact. Assert that no longer happens."""
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    po_path = _write_pipeline_output(tmp_path, [FIXTURE_FINDING_ELIGIBLE])

    result = run_patch(po_path, "F-001", str(tmp_path), repo_root=None)

    report_text = open(result.trust_report_path, encoding="utf-8").read()
    assert "Not evaluated — no repository root was provided." in report_text
    openant_core_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    assert openant_core_root not in report_text


def test_run_patch_never_leaks_suggested_fix_into_artifact(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    po_path = _write_pipeline_output(tmp_path, [FIXTURE_FINDING_ELIGIBLE])

    result = run_patch(po_path, "F-001", str(tmp_path), repo_root=None)

    vuln_text = open(result.vulnerability_path, encoding="utf-8").read()
    assert "DO-NOT-LEAK-THIS-SUGGESTED-FIX" not in vuln_text
    assert "DO-NOT-LEAK-THIS-REJECTION-REASON" not in vuln_text


def test_run_patch_mock_mode_is_self_disclosing(tmp_path, monkeypatch):
    """The core safety property: a Go-triggered run must never produce a
    mock report indistinguishable from a real one. LLM_PROVIDER=mock is
    allowed, but the resulting Trust Report must say so, loudly."""
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    po_path = _write_pipeline_output(tmp_path, [FIXTURE_FINDING_ELIGIBLE])

    result = run_patch(po_path, "F-001", str(tmp_path), repo_root=None)

    report_text = open(result.trust_report_path, encoding="utf-8").read()
    assert "MOCK MODE" in report_text
    assert "LLM mode | MOCK" in report_text


def test_run_patch_requires_llm_provider(tmp_path, monkeypatch):
    """No credential anywhere for the canonically-resolved provider --
    must fail clearly before any pipeline work. Uses OpenAI so the
    failure is guaranteed at the eager _require_llm_provider() preflight
    (see the module-level comment above for why Anthropic's construction-
    time leniency makes it a worse choice for this specific test)."""
    import utilities.autopatcher.llm_client as llm_client
    from utilities.llm import PHASES, ConfigFile, LLMConfig, PhaseRef

    phases = {p: PhaseRef(provider="openai", model="gpt-test-model") for p in PHASES}
    cf = ConfigFile(default_llm="test-config", llm_configs={"test-config": LLMConfig(name="test-config", phases=phases)})

    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    po_path = _write_pipeline_output(tmp_path, [FIXTURE_FINDING_ELIGIBLE])

    with pytest.raises(RuntimeError, match="No usable credential for provider 'openai'"):
        run_patch(po_path, "F-001", str(tmp_path), repo_root=None)


def test_run_patch_never_leaves_stale_trust_report_after_failed_rerun(tmp_path, monkeypatch):
    """F-39: reusing an output directory after a failed run must never leave
    a stale trust report from an earlier successful run sitting next to a
    freshly-written vulnerability.md."""
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    po_path = _write_pipeline_output(tmp_path, [FIXTURE_FINDING_ELIGIBLE])

    first = run_patch(po_path, "F-001", str(tmp_path), repo_root=None)
    assert os.path.exists(first.trust_report_path)

    import utilities.autopatcher.pipeline as _pipeline_module

    def _boom(**kwargs):
        raise RuntimeError("simulated pipeline failure")

    monkeypatch.setattr(_pipeline_module, "run", _boom)

    with pytest.raises(RuntimeError, match="simulated pipeline failure"):
        run_patch(po_path, "F-001", str(tmp_path), repo_root=None)

    assert not os.path.exists(first.trust_report_path), (
        "a failed rerun must not leave the previous run's trust report behind"
    )
    assert os.path.exists(first.vulnerability_path)


def test_run_patch_rejects_ineligible_finding(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    po_path = _write_pipeline_output(tmp_path, [FIXTURE_FINDING_REJECTED])

    with pytest.raises(ValueError, match="not eligible"):
        run_patch(po_path, "F-002", str(tmp_path), repo_root=None)


def test_run_patch_rejects_unknown_finding(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    po_path = _write_pipeline_output(tmp_path, [FIXTURE_FINDING_ELIGIBLE])

    with pytest.raises(ValueError, match="no finding"):
        run_patch(po_path, "does-not-exist", str(tmp_path), repo_root=None)


def test_run_patch_missing_pipeline_output(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")

    with pytest.raises(FileNotFoundError):
        run_patch(str(tmp_path / "nope.json"), "F-001", str(tmp_path), repo_root=None)


# ---------------------------------------------------------------------------
# _require_llm_provider: the Python-side backstop the Go resolver's
# guarantee relies on. A correctly-resolved interactive run (Go sets
# LLM_PROVIDER in the subprocess env before Python starts) must not trigger
# this at all -- these tests confirm that directly rather than only
# indirectly through run_patch().
#
# _require_llm_provider() now delegates entirely to
# utilities.autopatcher.llm_client.ensure_provider_configured() (the
# authoritative resolver) instead of checking os.environ.get("LLM_PROVIDER")
# directly -- it used to reject a valid config-only run (a real live
# acceptance test: every LLM env var unset, but OpenAnt's config.json has an
# explicit default_llm.analyze binding) before that resolver ever got a
# chance to approve it. These tests cover both the original env-only
# contract and the config-only path, at the exact core.patch boundary.
# ---------------------------------------------------------------------------

def _config_with_valid_analyze_binding():
    """A ConfigFile whose default_llm points at a fully valid, explicitly
    user-authored llm-config -- Anthropic/claude-opus-4-6 analyze binding
    plus a configured credential -- mirroring the exact shape from the
    live acceptance test (default_llm -> llm_configs[..].analyze ->
    {provider, model} -> llm_providers[provider] -> credential)."""
    from utilities.llm import PHASES, ConfigFile, LLMConfig, PhaseRef, ProviderConfig

    filler = PhaseRef(provider="anthropic", model="claude-sonnet-4-6")
    phases = {p: filler for p in PHASES}
    phases["analyze"] = PhaseRef(provider="anthropic", model="claude-opus-4-6")
    llm_config = LLMConfig(name="test-config", phases=phases)
    return ConfigFile(
        default_llm="test-config",
        llm_configs={"test-config": llm_config},
        llm_providers={
            "anthropic": ProviderConfig(name="anthropic", type="anthropic", api_key="configured-test-key"),
        },
    )


def test_require_llm_provider_raises_for_real_provider_value(monkeypatch):
    """LLM_PROVIDER is no longer a supported way to select a real provider
    -- this must fail at the SAME early preflight point it used to
    succeed at, not just deeper inside call_llm()."""
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    with pytest.raises(RuntimeError, match="LLM_PROVIDER"):
        _require_llm_provider()


def test_require_llm_provider_does_not_raise_for_mock(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    _require_llm_provider()  # must not raise


def test_require_llm_provider_does_not_raise_for_config_only_binding(monkeypatch):
    """All LLM env vars unset (LLM_PROVIDER, LLM_MODEL, ANTHROPIC_API_KEY,
    OPENAI_API_KEY), but a valid default_llm.analyze binding -- with a
    configured credential -- exists in OpenAnt's config: _require_llm_provider()
    must resolve AND validate the credential (eagerly building the shared
    adapter) rather than only checking that a provider name resolved, so a
    real, but unconfigured, run still fails before pipeline work rather
    than mid-run. No live Anthropic request is made -- adapter
    construction alone proves the preflight gets out of the way."""
    import utilities.autopatcher.llm_client as llm_client

    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(llm_client, "load_config_file", _config_with_valid_analyze_binding)

    _require_llm_provider()  # must not raise -- config supplies a real credential


def test_require_llm_provider_raises_when_no_credential_available_never_mock(monkeypatch, capsys):
    """A config resolves a provider (as it always does now, via the
    default_llm/openant-default binding), but no credential is available
    anywhere for it -- must fail clearly, before any pipeline work, never
    mock. Uses OpenAI: unlike Anthropic's SDK (which constructs
    successfully with no key and only rejects the request later), OpenAI's
    canonical resolve_provider() raises immediately when no llm_providers
    entry exists, so this failure is guaranteed to surface at THIS eager
    preflight step -- see test_llm_client.py's
    test_anthropic_missing_credential_raises_clearly_never_mock for the
    Anthropic-specific case, which surfaces later, at the first real
    call_llm()."""
    import utilities.autopatcher.llm_client as llm_client
    from utilities.llm import PHASES, ConfigFile, LLMConfig, PhaseRef

    phases = {p: PhaseRef(provider="openai", model="gpt-test-model") for p in PHASES}
    cf = ConfigFile(default_llm="test-config", llm_configs={"test-config": LLMConfig(name="test-config", phases=phases)})

    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)

    with pytest.raises(RuntimeError, match="No usable credential for provider 'openai'"):
        _require_llm_provider()
    assert "mock" not in capsys.readouterr().err.lower()


def test_require_llm_provider_raises_for_invalid_default_llm_reference(monkeypatch):
    """An invalid/dangling default_llm reference (names a config that was
    never defined) must fail clearly -- the SAME ConfigError canonical
    OpenAnt commands raise for the identical broken config -- never
    silently mock, never silently accepted as valid."""
    import utilities.autopatcher.llm_client as llm_client
    from utilities.llm import ConfigError, ConfigFile

    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.setattr(llm_client, "load_config_file", lambda: ConfigFile(default_llm="does-not-exist"))

    with pytest.raises(ConfigError, match="does-not-exist"):
        _require_llm_provider()


def test_run_patch_input_type_and_input_id_default_to_finding(tmp_path, monkeypatch):
    """Regression guard: these fields are additive -- Finding-mode's existing
    PatchStepResult contract must not regress when they were introduced for
    CVE mode."""
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    po_path = _write_pipeline_output(tmp_path, [FIXTURE_FINDING_ELIGIBLE])

    result = run_patch(po_path, "F-001", str(tmp_path), repo_root=None)

    assert result.input_type == "finding"
    assert result.input_id == "F-001"


# ---------------------------------------------------------------------------
# Repository Understanding integration: repo_root normalization and the
# run-scoped investigation directory, mirroring test_run_patch_cve.py's
# equivalent coverage for CVE mode.
# ---------------------------------------------------------------------------

def test_run_patch_repo_root_is_resolved_before_reaching_pipeline_run(tmp_path, monkeypatch):
    """repo_root must be normalized (resolved) once, here at the entry
    point, before InvestigationCase / ground_repository / parsing ever see
    it -- same guarantee as run_patch_cve()."""
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    real_repo = tmp_path / "real_repo"
    real_repo.mkdir()
    link_repo = tmp_path / "link_repo"
    link_repo.symlink_to(real_repo)
    po_path = _write_pipeline_output(tmp_path, [FIXTURE_FINDING_ELIGIBLE])

    import utilities.autopatcher.pipeline as _pipeline_module

    captured = {}
    original_run = _pipeline_module.run

    def _capturing_run(*, vulnerability_text, api_key, repo_root=None, investigation_output_dir=None,
                        budget_controller=None, compare_existing_tests=False, execution_recorder=None):
        captured["repo_root"] = repo_root
        return original_run(
            vulnerability_text=vulnerability_text, api_key=api_key,
            repo_root=repo_root, investigation_output_dir=investigation_output_dir,
            budget_controller=budget_controller, compare_existing_tests=compare_existing_tests,
            execution_recorder=execution_recorder,
        )

    with mock.patch.object(_pipeline_module, "run", side_effect=_capturing_run):
        run_patch(po_path, "F-001", str(tmp_path), repo_root=str(link_repo))

    assert captured["repo_root"] == str(real_repo.resolve())
    assert captured["repo_root"] != str(link_repo)


def test_run_patch_without_repo_root_creates_no_investigation_directory(tmp_path, monkeypatch):
    """Finding mode without a repository must preserve current behavior --
    no InvestigationCase repo_root, no investigation directory created."""
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    po_path = _write_pipeline_output(tmp_path, [FIXTURE_FINDING_ELIGIBLE])

    result = run_patch(po_path, "F-001", str(tmp_path), repo_root=None)

    assert not (tmp_path / "patch" / "F-001-investigation").exists()
    vuln_text_written = open(result.vulnerability_path, encoding="utf-8").read()
    assert vuln_text_written == render_vulnerability_markdown(FIXTURE_FINDING_ELIGIBLE)


def test_run_patch_investigation_directory_created_when_repo_root_given(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    po_path = _write_pipeline_output(tmp_path, [FIXTURE_FINDING_ELIGIBLE])

    run_patch(po_path, "F-001", str(tmp_path), repo_root=str(repo_root))

    expected = tmp_path / "patch" / "F-001-investigation"
    assert expected.is_dir()
    assert not str(expected).startswith(str(repo_root))


# ---------------------------------------------------------------------------
# Full CLI dispatch contract (openant/cli.py's cmd_patch) -- the exact
# envelope shape internal/python.Invoke() parses on the Go side.
# ---------------------------------------------------------------------------

class _Args:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def test_cmd_patch_success_envelope_shape(tmp_path, monkeypatch, capsys):
    from openant.cli import cmd_patch

    monkeypatch.setenv("LLM_PROVIDER", "mock")
    po_path = _write_pipeline_output(tmp_path, [FIXTURE_FINDING_ELIGIBLE])
    args = _Args(pipeline_output=po_path, finding_id="F-001", repo_root=None, output=str(tmp_path / "out"))

    exit_code = cmd_patch(args)

    assert exit_code == 0
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["status"] == "success"
    assert envelope["errors"] == []
    assert envelope["data"]["finding_id"] == "F-001"
    assert os.path.exists(envelope["data"]["trust_report_path"])
    assert os.path.exists(envelope["data"]["vulnerability_path"])


def test_cmd_patch_error_envelope_shape_for_unknown_finding(tmp_path, monkeypatch, capsys):
    from openant.cli import cmd_patch

    monkeypatch.setenv("LLM_PROVIDER", "mock")
    po_path = _write_pipeline_output(tmp_path, [FIXTURE_FINDING_ELIGIBLE])
    args = _Args(pipeline_output=po_path, finding_id="nope", repo_root=None, output=str(tmp_path / "out"))

    exit_code = cmd_patch(args)

    assert exit_code == 2
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["status"] == "error"
    assert envelope["data"] == {}
    assert len(envelope["errors"]) == 1


# ---------------------------------------------------------------------------
# cmd_patch: --cve dispatch, mutual exclusion with --finding-id, and the
# full CVE-mode CLI contract (mocked NVD fetch, no network, no real repo).
# ---------------------------------------------------------------------------

FIXTURE_CVE_FOR_CLI = {
    "id": "CVE-2021-12345",
    "descriptions": [{"lang": "en", "value": "A test vulnerability for CLI-contract coverage."}],
}


def test_cmd_patch_rejects_both_finding_id_and_cve(tmp_path, monkeypatch, capsys):
    from openant.cli import cmd_patch

    monkeypatch.setenv("LLM_PROVIDER", "mock")
    args = _Args(
        pipeline_output=None, finding_id="F-001", cve="CVE-2021-12345",
        repo_root=str(tmp_path), output=str(tmp_path / "out"),
    )

    exit_code = cmd_patch(args)

    assert exit_code == 2
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["status"] == "error"
    assert envelope["data"] == {}
    assert "exactly one" in envelope["errors"][0]


def test_cmd_patch_rejects_neither_finding_id_nor_cve(tmp_path, monkeypatch, capsys):
    from openant.cli import cmd_patch

    monkeypatch.setenv("LLM_PROVIDER", "mock")
    args = _Args(pipeline_output=None, finding_id=None, cve=None, repo_root=None, output=str(tmp_path / "out"))

    exit_code = cmd_patch(args)

    assert exit_code == 2
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["status"] == "error"
    assert "exactly one" in envelope["errors"][0]


def test_cmd_patch_cve_mode_requires_repo_root(tmp_path, monkeypatch, capsys):
    from openant.cli import cmd_patch

    monkeypatch.setenv("LLM_PROVIDER", "mock")
    args = _Args(pipeline_output=None, finding_id=None, cve="CVE-2021-12345", repo_root=None, output=str(tmp_path / "out"))

    exit_code = cmd_patch(args)

    assert exit_code == 2
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["status"] == "error"
    assert "--repo-root" in envelope["errors"][0]


def test_cmd_patch_finding_id_mode_requires_pipeline_output(tmp_path, monkeypatch, capsys):
    from openant.cli import cmd_patch

    monkeypatch.setenv("LLM_PROVIDER", "mock")
    args = _Args(pipeline_output=None, finding_id="F-001", cve=None, repo_root=None, output=str(tmp_path / "out"))

    exit_code = cmd_patch(args)

    assert exit_code == 2
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["status"] == "error"
    assert "pipeline_output" in envelope["errors"][0]


def test_cmd_patch_success_envelope_shape_cve_mode(tmp_path, monkeypatch, capsys):
    from openant.cli import cmd_patch

    monkeypatch.setenv("LLM_PROVIDER", "mock")
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    args = _Args(
        pipeline_output=None, finding_id=None, cve="CVE-2021-12345",
        repo_root=str(repo_root), output=str(tmp_path / "out"),
    )

    with mock.patch("utilities.autopatcher.cve_fetcher.fetch_cve", return_value=FIXTURE_CVE_FOR_CLI):
        exit_code = cmd_patch(args)

    assert exit_code == 0
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["status"] == "success"
    assert envelope["errors"] == []
    assert envelope["data"]["finding_id"] == "CVE-2021-12345"
    assert envelope["data"]["input_type"] == "cve"
    assert envelope["data"]["input_id"] == "CVE-2021-12345"
    assert os.path.exists(envelope["data"]["trust_report_path"])
    assert os.path.exists(envelope["data"]["vulnerability_path"])


def test_cmd_patch_cve_mode_error_envelope_for_unknown_cve(tmp_path, monkeypatch, capsys):
    from openant.cli import cmd_patch
    from utilities.autopatcher.cve_fetcher import CVENotFoundError

    monkeypatch.setenv("LLM_PROVIDER", "mock")
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    args = _Args(
        pipeline_output=None, finding_id=None, cve="CVE-9999-99999",
        repo_root=str(repo_root), output=str(tmp_path / "out"),
    )

    with mock.patch(
        "utilities.autopatcher.cve_fetcher.fetch_cve",
        side_effect=CVENotFoundError("no such CVE"),
    ):
        exit_code = cmd_patch(args)

    assert exit_code == 2
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["status"] == "error"
    assert envelope["data"] == {}
    assert len(envelope["errors"]) == 1
