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

import pytest

from core.patch import (
    PatchStepResult,
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
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    po_path = _write_pipeline_output(tmp_path, [FIXTURE_FINDING_ELIGIBLE])

    with pytest.raises(RuntimeError, match="LLM_PROVIDER"):
        run_patch(po_path, "F-001", str(tmp_path), repo_root=None)


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
