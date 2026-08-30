"""Regression tests for issue #431 — generate_test RAISING (not returning
None) escapes the #409 error accounting entirely.

The #409 fix (issue #311) covers ``generate_test`` → ``None``: the ERROR
unit file is written and ``_summary.json`` derives its counts from the unit
files. But a raised exception from ``generate_test`` (live-run repro: the
LLM was content-filtered and raised ``LLMResponseError`` after retries) has
no handler — the exception aborts the whole loop, remaining findings are
never attempted, and the on-disk ``_summary.json`` keeps ``errors: 0``, the
exact defect #311 was filed to close. Contract: a raised generation error
records the ERROR unit file, derives the summary counts from the files, and
CONTINUES to the next finding (buckets sum to total).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _pipeline_output(tmp_path, n=2):
    p = tmp_path / "pipeline_output.json"
    p.write_text(json.dumps({
        "repository": {"name": "t", "language": "python"},
        "application_type": "unknown",
        "findings": [
            {"id": f"VULN-{i+1:03d}", "name": "X", "short_name": "x",
             "location": {"file": "a.py", "line": 1},
             "stage1_verdict": "vulnerable", "stage2_verdict": "agreed",
             "cwe_id": 79, "verdict": "vulnerable"}
            for i in range(n)
        ],
    }))
    return str(p)


class _NoopAdapter:
    name = "anthropic"
    supports_tools = True
    def complete(self, **kwargs):  # pragma: no cover - mocked away
        raise AssertionError("should not reach the adapter")
    def validate(self, model):
        pass


class _FakeRegistry:
    def get(self, phase):
        from utilities.llm import PhaseBinding
        return PhaseBinding(phase=phase, adapter=_NoopAdapter(),
                            model="m", provider_name="anthropic")


def test_generate_test_raising_records_error_and_continues(monkeypatch, tmp_path):
    """#431: an exception from generate_test must be recorded as an ERROR
    unit file with counts derived from files, and the loop must CONTINUE
    (the live repro aborted 4/5 findings and wrote errors: 0)."""
    import utilities.dynamic_tester as dt

    calls = {"n": 0}

    def fake_generate_test(finding, repo_info, binding, tracker):
        calls["n"] += 1
        if calls["n"] == 1:
            # live repro shape: the adapter RAISES (content filter) rather
            # than returning None
            raise RuntimeError("OpenRouterAdapter returned an empty completion")
        return {"dockerfile": "FROM python:3.11-slim", "test_script": "print('{}')",
                "test_filename": "t.py", "requirements": "", "requirements_filename": "req.txt",
                "docker_compose": None, "needs_attacker_server": False}

    monkeypatch.setattr(dt, "generate_test", fake_generate_test)
    monkeypatch.setattr(dt, "generate_report", lambda *a, **k: "# report")
    # the second finding generates successfully but Docker execution is
    # stubbed to an ERROR so no container is actually needed
    monkeypatch.setattr(dt, "run_single_container",
                       lambda gen, fid, source_file=None: type("E", (), {
                           "stdout": '{"status": "NOT_REPRODUCED", "details": "ok", "evidence": []}',
                           "stderr": "", "exit_code": 0,
                           "timed_out": False, "build_error": None,
                           "elapsed_seconds": 0.1})())

    out = tmp_path / "out"
    out.mkdir()
    dt.run_dynamic_tests(_pipeline_output(tmp_path), str(out), registry=_FakeRegistry())

    # the ERROR unit file for VULN-001 exists
    ck = out / "dynamic_test_checkpoints" / "VULN-001.json"
    assert ck.exists(), "a RAISED generation error must still write the ERROR unit file"
    d = json.loads(ck.read_text())
    assert d["status"] == "ERROR"
    assert "empty completion" in str(d.get("details", "")) or "RuntimeError" in str(d)

    # the summary derives errors>=1 from the FILES (not 0)
    summary = json.loads((out / "dynamic_test_checkpoints" / "_summary.json").read_text())
    assert summary["errors"] >= 1, (
        f"the raised-generation error must count: errors={summary['errors']} "
        f"(the live repro wrote errors: 0 — the exact #311 defect on the raise route)")

    # CONTINUE: the second finding was attempted (not aborted by finding 1's raise)
    unit_files = [f for f in (out / "dynamic_test_checkpoints").glob("*.json") if f.name != "_summary.json"]
    assert len(unit_files) == 2, f"both findings must record unit files, found: {[f.name for f in unit_files]}"


def test_generate_test_none_still_works(monkeypatch, tmp_path):
    """The #409 (→ None) contract is unchanged by the fix."""
    import utilities.dynamic_tester as dt

    monkeypatch.setattr(dt, "generate_test", lambda *a, **k: None)
    monkeypatch.setattr(dt, "generate_report", lambda *a, **k: "# report")
    out = tmp_path / "out"
    out.mkdir()
    dt.run_dynamic_tests(_pipeline_output(tmp_path, n=1), str(out), registry=_FakeRegistry())
    summary = json.loads((out / "dynamic_test_checkpoints" / "_summary.json").read_text())
    assert summary["errors"] >= 1 and summary["total_units"] == 1
