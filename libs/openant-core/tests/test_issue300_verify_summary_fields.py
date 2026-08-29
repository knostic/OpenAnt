"""Regression tests for issue #300 — the standalone `openant verify` step
report omits `needs_review` and `error_count` that the pipeline records.

The pipeline's verify step-report summary (core/scanner.py) carries all
seven counters; the two summary constructions in openant/cli.py (the
chained verify inside `openant analyze --verify`, and standalone
`openant verify`) carried only five — so the command a user runs directly
was strictly less informative, with counters summing far below
`findings_input` and nothing explaining the gap (on the filing run:
needs_review 134 + error_count 48 = 182 of 223 findings, 81.6%).

VerifyResult.to_dict emits both fields — only the step report on disk was
incomplete. Same class as #285, different site; the issue also notes the
dependency: #285's REQUIRED status-derivation key (`error_count` in
ctx.summary) does not exist on the standalone path until this lands.

Contract locked here:
- every verify step-report summary (standalone command, chained analyze
  --verify, pipeline scanner) carries the same SEVEN fields, built by ONE
  shared helper so the sites cannot drift again (the issue's suggestion);
- #285's status derivation has its error_count key on the standalone path.
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.schemas import VerifyResult, verify_step_summary  # noqa: E402

VR = VerifyResult(
    verified_results_path="/tmp/v.json", findings_input=223,
    findings_verified=41, agreed=35, disagreed=6,
    confirmed_vulnerabilities=30, needs_review=134, error_count=48,
)

SEVEN_KEYS = {
    "findings_input", "findings_verified", "agreed", "disagreed",
    "confirmed_vulnerabilities", "needs_review", "error_count",
}


def test_shared_helper_emits_all_seven_fields():
    # #302 (stacked on #300) extends the helper with the three scope keys
    # (units_analyzed_total/downgraded/upgraded); the #300 contract is that
    # these SEVEN are always present — a superset check, not exact-set.
    s = verify_step_summary(VR)
    assert SEVEN_KEYS <= set(s.keys()), s
    assert s["needs_review"] == 134
    assert s["error_count"] == 48
    # The four reconciliation counters are a BOUND, not exact equality: a
    # disagreed-but-still-vulnerable result increments ONLY
    # confirmed_vulnerabilities (verifier.py's else-branch), so
    assert (s["agreed"] + s["disagreed"] + s["needs_review"]
            + s["error_count"]) <= s["findings_input"]


def _stub_run_verification(**kwargs):
    return VR


def test_standalone_verify_step_report_carries_all_fields(tmp_path, monkeypatch):
    """Drive the REAL cmd_verify with run_verification stubbed; the step
    report on disk must carry the seven-field summary."""
    import openant.cli as cli

    monkeypatch.setattr("core.verifier.run_verification",
                        _stub_run_verification, raising=False)
    # cmd_verify imports run_verification inside the function from
    # core.verifier — patch the source module before the local import.
    import core.verifier as verifier_mod
    monkeypatch.setattr(verifier_mod, "run_verification", _stub_run_verification)

    args = types.SimpleNamespace(
        results="r.json", analyzer_output="a.json", output=str(tmp_path),
        app_context=None, repo_path=str(tmp_path), workers=1,
        checkpoint=None, backoff=30, llm_config=None,
    )
    rc = cli.cmd_verify(args)
    assert rc == 1  # confirmed_vulnerabilities=30 > 0 forces rc 1 (cli.py cmd_verify)
    report = json.loads((tmp_path / "verify.report.json").read_text())
    assert SEVEN_KEYS <= set(report["summary"].keys()), report["summary"]
    assert report["summary"]["needs_review"] == 134
    assert report["summary"]["error_count"] == 48


def test_scanner_site_uses_the_shared_helper():
    """The pipeline site (core/scanner.py) builds the same summary through
    the same helper — the anti-drift contract (source-level: both call
    sites reference the shared construction)."""
    import inspect
    import core.scanner as scanner_mod

    src = inspect.getsource(scanner_mod)
    assert "verify_step_summary" in src, (
        "scanner.py must build the verify step summary through the shared "
        "helper so the pipeline and standalone paths cannot drift")
    import openant.cli as cli_mod
    cli_src = inspect.getsource(cli_mod)
    assert cli_src.count("verify_step_summary") >= 2, (
        "both cli.py summary sites must use the shared helper")


def test_error_count_key_present_for_285_status_derivation(tmp_path, monkeypatch):
    """#285's REQUIRED dependency: the standalone step report carries the
    integer error_count the status derivation reads."""
    import core.verifier as verifier_mod
    import openant.cli as cli

    monkeypatch.setattr(verifier_mod, "run_verification", _stub_run_verification)
    args = types.SimpleNamespace(
        results="r.json", analyzer_output="a.json", output=str(tmp_path),
        app_context=None, repo_path=str(tmp_path), workers=1,
        checkpoint=None, backoff=30, llm_config=None,
    )
    cli.cmd_verify(args)
    report = json.loads((tmp_path / "verify.report.json").read_text())
    assert isinstance(report["summary"].get("error_count"), int)
