"""Regression tests for issue #315 — the compose project name drops the
per-run UUID, so `docker compose down` reaches a concurrent run's containers.

The code's own anti-collision mechanism (the run_id UUID prefix at
docker_executor.py:408-409: "UUID prefix prevents collisions between parallel
dynamic-test runs (same finding IDs across scans)") is applied to the image
tag and the network name but NOT the compose project name — two runs testing
the same finding share one compose project, so either teardown (`down
--volumes --remove-orphans` is scoped by `-p <name>`) reaches the other's
containers, and either `up -d` recreates the other's services.

The issue's own corrections lower the severity: the result is a VISIBLE,
retried ERROR ("Container did not produce valid JSON output"), not a silent
false negative — robustness, not correctness. The fix is the suggestion 1
one-liner: the project name carries the same run_id prefix.

Contract locked here:
- the compose project name carries the run_id prefix (f"openant-{run_id}-
  {safe_id}") — identical to what the image tag and network name already
  carry, so the stated invariant holds on ALL three names;
- two runs testing the SAME finding produce DIFFERENT project names;
- the single-container path is unchanged (the image tag already carries it).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.dynamic_tester.docker_executor import compose_project_name  # noqa: E402


def test_compose_project_name_carries_run_id():
    """The invariant the :408 comment states, applied to the project name."""
    assert compose_project_name("a1b2c3d4", "vuln-001") == "openant-a1b2c3d4-vuln-001"


def test_two_runs_same_finding_different_project_names():
    """The parallel-collision case: same finding, two runs, distinct names
    (the teardown scoping the issue demonstrated)."""
    a = compose_project_name("a1b2c3d4", "vuln-001")
    b = compose_project_name("e5f6g7h8", "vuln-001")
    assert a != b


def test_project_name_is_a_valid_docker_reference():
    """The original reason for the safe_id (docker compose names must be
    valid references): run_id is hex (already [a-z0-9]) and safe_id is
    sanitized upstream (docker_executor's own regex) — assert the shape
    holds for the sanitized form."""
    for run_id, finding_id in [("a1b2c3d4", "VULN-001"), ("deadbeef", "XSS in <login>")]:
        safe_id = re.sub(r"[^a-z0-9-]", "-", finding_id.lower()).strip("-_.")
        name = compose_project_name(run_id, safe_id)
        assert re.fullmatch(r"[a-z0-9][a-z0-9_-]*", name), (finding_id, name)  # compose project names forbid dots (review fix)


def test_the_call_site_passes_the_run_id():
    """The wiring contract: run_single_container passes the run_id to the
    compose project name — sourced (the issue's evidence pin)."""
    src = (PROJECT_ROOT / "utilities/dynamic_tester" / "docker_executor.py").read_text()
    assert "_run_compose(work_dir, compose_project_name(run_id, safe_id)" in src, (
        "the call site must pass the run_id-prefixed name")
    assert "result = _run_compose(work_dir, safe_id," not in src, (
        "the bare safe_id pass must be gone")
