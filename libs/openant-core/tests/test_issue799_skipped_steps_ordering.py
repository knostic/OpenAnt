"""#799 — the skipped-steps ORDERING: a late-recorded skip never reaches
pipeline_output.json, so the human summary states a falsehood.

The scanner records the dynamic-test skip one pipeline step AFTER
``build_pipeline_output`` writes the file: Step 6 passes
``skipped_steps=list(result.skipped_steps)`` while the dynamic-test skip is
recorded at Step 7 — so ``pipeline_output.json.pipeline_stats.skipped_steps``
is always ``[]`` on a ``--skip-dynamic-test`` run, ``scan.report.json``
disagrees (``steps_skipped: ["dynamic-test"]``), and the human summary —
generated from the STALE file (report/prompts/summary.txt:50: "iterate
``pipeline_stats.skipped_steps``; if the array is empty, write 'No steps
were skipped.'") — affirmatively states the falsehood in the shipped
deliverable.

The campaign's evidence (SGLang completion run 3, ``--skip-dynamic-test``):
pipeline_output.json → ``skipped_steps: []``; scan.report.json →
``steps_skipped: ["dynamic-test"]``; SUMMARY_REPORT.md → "No steps were
skipped." — the exact three-artifact divergence.

The fix: the dynamic-test DECISION is hoisted BEFORE Step 6's build (every
knowable skip class — not_requested / no_candidates / docker_unavailable —
recorded at its source), and the attempted-run ``failed`` class REBUILDS the
output after the attempt. The report step's own skip stays post-build
(#799's own Not-claimed boundary).

Shapes:

  S1 -- the WITNESS (red at base): the ``not_requested`` class through the
        REAL scan_repository ordering (the _install_minimal_pipeline drive):
        the Step-6 build call must carry dynamic-test in its skipped set —
        at base the call passes [].
  S2 -- the AGREEMENT witness (red at base): the issue's named pin —
        pipeline_output.json.pipeline_stats.skipped_steps ==
        scan.report.json.summary.steps_skipped after a full scan.
  S3 -- the no_candidates class (requested, no findings).
  S4 -- the docker_unavailable class (requested, findings, no docker).
  S5 -- the FAILED class (requested, findings, docker, the run raises): the
        rebuild must land the late skip in the output too.
  S6 -- the falsifier's guard: a run with NO skips writes no falsehood —
        the skipped set is empty exactly when nothing was skipped (no
        cry-wolf: the hoist must not blanket-stamp dynamic-test).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import core.scanner as scanner_mod  # noqa: E402
from tests.test_scanner import _install_minimal_pipeline  # noqa: E402


def _offline_drive(monkeypatch, *, vulnerable=0):
    """The full offline seam: the minimal pipeline + the registry probe
    stub (the probe makes a REAL credential round-trip otherwise)."""
    _install_minimal_pipeline(monkeypatch, vulnerable=vulnerable)
    # the registry probe stub (the same seam tests/test_scanner.py's fixture
    # installs): probe_registry_or_raise makes a REAL credential round-trip
    # otherwise — these drives run fully offline
    import utilities.llm as llm_mod
    monkeypatch.setattr(llm_mod, "probe_registry_or_raise",
                        lambda *a, **k: None, raising=True)


def _recording_build(monkeypatch, calls: list):
    """A build_pipeline_output fake that PERSISTS the skipped-set kwargs it
    was passed — the observable of the Step-6 call's ordering."""
    import core.reporter as reporter

    def _fake_build(*, results_path, output_path, skipped_steps=None,
                    skipped_step_reasons=None, **kwargs):
        calls.append({"skipped_steps": list(skipped_steps or []),
                      "skipped_step_reasons": dict(skipped_step_reasons or {})})
        Path(output_path).write_text(json.dumps({
            "pipeline_stats": {
                "skipped_steps": list(skipped_steps or []),
                "skipped_step_reasons": dict(skipped_step_reasons or {}),
            }}))
        return output_path

    monkeypatch.setattr(reporter, "build_pipeline_output", _fake_build)
    # the scanner imports the symbol at module scope in some paths — patch
    # the scanner's own reference too
    if hasattr(scanner_mod, "build_pipeline_output"):
        monkeypatch.setattr(scanner_mod, "build_pipeline_output", _fake_build)


def _scan(tmp_path, out_name, **overrides):
    kw = dict(repo_path=str(tmp_path), output_dir=str(tmp_path / out_name),
              generate_context=False, enhance=False, verify=False,
              generate_report=False, dynamic_test=False)
    kw.update(overrides)
    return scanner_mod.scan_repository(**kw)


def _pipeline_output(tmp_path, out_name):
    return json.loads((tmp_path / out_name / "pipeline_output.json").read_text())


def _scan_report(tmp_path, out_name):
    return json.loads((tmp_path / out_name / "scan.report.json").read_text())


# ---------------------------------------------------------------------------
# S1 — the not_requested class through the REAL ordering
# ---------------------------------------------------------------------------
def test_the_dynamic_test_skip_reaches_the_pipeline_output(monkeypatch, tmp_path):
    """The falsifier: on a --skip-dynamic-test run, Step 6's build call must
    carry dynamic-test in its skipped set — at base the skip is recorded one
    step LATER and the call passes []."""
    calls: list = []
    _offline_drive(monkeypatch)
    _recording_build(monkeypatch, calls)

    # the REAL scan entry (the prod-bound symbol loaded in the body — the
    # screen's import-bound route): the ordering under test is the
    # scanner's, not the helper's
    scanner_mod.scan_repository(
        repo_path=str(tmp_path), output_dir=str(tmp_path / "out"),
        generate_context=False, enhance=False, verify=False,
        generate_report=False, dynamic_test=False)

    assert len(calls) >= 1, "the Step-6 build never ran"
    po = _pipeline_output(tmp_path, "out")
    skipped = po["pipeline_stats"]["skipped_steps"]
    assert "dynamic-test" in skipped, (
        f"the skip landed only in scan.report.json (the ordering gap): "
        f"the Step-6 call passed {skipped!r}")
    assert po["pipeline_stats"]["skipped_step_reasons"]["dynamic-test"] == \
        "not_requested", po


# ---------------------------------------------------------------------------
# S2 — the agreement pin (the issue's named invariant)
# ---------------------------------------------------------------------------
def test_the_two_artifacts_agree_about_skipped_steps(monkeypatch, tmp_path):
    """The issue's named agreement pin, scoped to the issue's own claim:
    the dynamic-test skip must appear in BOTH machine artifacts after a
    full scan — pipeline_output.json.pipeline_stats.skipped_steps AND
    scan.report.json.summary.steps_skipped — so the human summary (which
    reads the former) cannot state a falsehood the latter contradicts.
    (The REPORT step's own skip is #799's named Not-claimed boundary — the
    same argument may apply to it; this test does not pin it.)"""
    _offline_drive(monkeypatch)
    _recording_build(monkeypatch, [])

    # the REAL scan entry (the prod-bound symbol in the body)
    scanner_mod.scan_repository(
        repo_path=str(tmp_path), output_dir=str(tmp_path / "out"),
        generate_context=False, enhance=False, verify=False,
        generate_report=False, dynamic_test=False)

    po = _pipeline_output(tmp_path, "out")["pipeline_stats"]["skipped_steps"]
    sr = _scan_report(tmp_path, "out")["summary"]["steps_skipped"]
    assert "dynamic-test" in po, (
        f"pipeline_output carries only the pre-build skips: {po!r}")
    assert "dynamic-test" in sr, (
        f"scan.report carries it but pipeline_output does not: {po!r} vs {sr!r}")
    # and the two agree on every step the BUILD could know
    assert set(po) == set(sr) - {"report"}, (
        f"beyond the report step's own late skip (the Not-claimed "
        f"boundary), the artifacts disagree: {po!r} vs {sr!r}")


# ---------------------------------------------------------------------------
# S3 — the no_candidates class (requested, no findings)
# ---------------------------------------------------------------------------
def test_the_no_candidates_skip_reaches_the_pipeline_output(monkeypatch, tmp_path):
    _offline_drive(monkeypatch, vulnerable=0)
    _recording_build(monkeypatch, [])

    _scan(tmp_path, "out", dynamic_test=True)

    po = _pipeline_output(tmp_path, "out")
    assert "dynamic-test" in po["pipeline_stats"]["skipped_steps"], po
    assert po["pipeline_stats"]["skipped_step_reasons"]["dynamic-test"] == \
        "no_candidates", po


# ---------------------------------------------------------------------------
# S4 — the docker_unavailable class (requested, findings, no docker)
# ---------------------------------------------------------------------------
def test_the_docker_missing_skip_reaches_the_pipeline_output(monkeypatch, tmp_path):
    _offline_drive(monkeypatch, vulnerable=1)
    _recording_build(monkeypatch, [])
    monkeypatch.setattr("shutil.which", lambda name: None)

    _scan(tmp_path, "out", dynamic_test=True)

    po = _pipeline_output(tmp_path, "out")
    assert "dynamic-test" in po["pipeline_stats"]["skipped_steps"], po
    assert po["pipeline_stats"]["skipped_step_reasons"]["dynamic-test"] == \
        "docker_unavailable", po


# ---------------------------------------------------------------------------
# S5 — the FAILED class (the attempted run raises): the rebuild
# ---------------------------------------------------------------------------
def test_the_failed_attempt_rebuilds_the_output_with_the_late_skip(monkeypatch, tmp_path):
    """The one class that CANNOT be known before the build: the attempted
    run that raises. The except branch must REBUILD pipeline_output.json
    after recording the skip, or the failed run ships the same stale []."""
    _offline_drive(monkeypatch, vulnerable=1)
    calls: list = []
    _recording_build(monkeypatch, calls)
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/docker")

    def _boom(**kwargs):
        raise RuntimeError("the harness exploded")

    import core.dynamic_tester as dynamic_tester
    monkeypatch.setattr(dynamic_tester, "run_tests", _boom)

    _scan(tmp_path, "out", dynamic_test=True)

    po = _pipeline_output(tmp_path, "out")
    assert "dynamic-test" in po["pipeline_stats"]["skipped_steps"], (
        f"the failed attempt's skip never reached the output: {po!r}")
    assert po["pipeline_stats"]["skipped_step_reasons"]["dynamic-test"] == \
        "failed", po
    # the REBUILD is observable: the builder saw the skip it did not see at
    # Step 6 (at least one later call carries it)
    assert any("dynamic-test" in c["skipped_steps"] for c in calls), (
        f"no rebuild carried the late skip: {[c['skipped_steps'] for c in calls]!r}")


# ---------------------------------------------------------------------------
# S6 — no cry-wolf: a run with nothing skipped writes nothing skipped
# ---------------------------------------------------------------------------
def test_a_full_run_writes_no_false_skips(monkeypatch, tmp_path):
    """The hoist must not blanket-stamp dynamic-test: with the step
    structurally out of the picture (the same minimal drive, the report
    step also off), a scan that skipped ONLY the disabled steps carries
    exactly those — the guard against an over-eager fix."""
    _offline_drive(monkeypatch)
    _recording_build(monkeypatch, [])

    _scan(tmp_path, "out", dynamic_test=False)

    po = _pipeline_output(tmp_path, "out")
    skipped = po["pipeline_stats"]["skipped_steps"]
    # the drive disables context/enhance/verify/report — those skips are
    # REAL; dynamic-test is among them (disabled) — but NOTHING ELSE may
    # appear (no phantom skips)
    allowed = {"app-context", "enhance", "verify", "dynamic-test", "report",
               "llm-reachability"}
    assert set(skipped) <= allowed, skipped


# ---------------------------------------------------------------------------
# S7 — the SUCCESSFUL-RUN guard (the r1-F1 catch): the real no-cry-wolf
# ---------------------------------------------------------------------------
def test_a_successful_dynamic_test_run_skips_nothing(monkeypatch, tmp_path):
    """The r1-F1 catch: the S6 guard allowed 'dynamic-test' in its set, so a
    blanket-stamp mutant (the hoist recording the skip even when the step
    RUNS) survived the whole battery + the scanner family 17/17. This is
    the real guard: the step RUNS (docker present, run_tests succeeds) —
    dynamic-test must appear in NEITHER the result's skipped set NOR the
    built file's skipped set. Green at base too (the guard class), but the
    teeth are the mutant: a blanket stamp fails HERE."""
    _offline_drive(monkeypatch, vulnerable=1)
    calls: list = []
    _recording_build(monkeypatch, calls)
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/docker")

    class _DtResult:
        confirmed = 0
        not_reproduced = 0
        blocked = 0
        inconclusive = 0
        errors = 0
        findings_tested = 1
        results_json_path = "/dev/null"
        results_md_path = "/dev/null"

    import core.dynamic_tester as dynamic_tester
    monkeypatch.setattr(dynamic_tester, "run_tests", lambda **k: _DtResult())

    # the REAL scan entry (the prod-bound symbol in the body)
    res = scanner_mod.scan_repository(
        repo_path=str(tmp_path), output_dir=str(tmp_path / "out"),
        generate_context=False, enhance=False, verify=False,
        generate_report=False, dynamic_test=True)

    assert "dynamic-test" not in res.skipped_steps, (
        f"the step RAN but is stamped skipped: {res.skipped_steps!r}")
    po = _pipeline_output(tmp_path, "out")
    assert "dynamic-test" not in po["pipeline_stats"]["skipped_steps"], (
        f"the built file stamps a step that ran: {po!r}")


# ---------------------------------------------------------------------------
# S8 — the REBUILD-BEST-EFFORT guard (the r1-F3 catch)
# ---------------------------------------------------------------------------
def test_a_failing_rebuild_never_aborts_the_scan(monkeypatch, tmp_path):
    """The r1-F3 catch: the failed-attempt rebuild sat inside the except of
    an OPTIONAL step — a raise there (disk full, a permission flip) would
    re-raise through step_context and ABORT the whole scan. The rebuild is
    best-effort: a WARNING, the Step-6 file stays, the scan completes."""
    _offline_drive(monkeypatch, vulnerable=1)
    calls: list = []

    def _build_once(*, results_path, output_path, **kwargs):
        calls.append(1)
        if len(calls) >= 2:
            raise OSError("disk full on rebuild")
        Path(output_path).write_text(json.dumps({
            "pipeline_stats": {"skipped_steps": list(kwargs.get("skipped_steps") or [])}}))
        return output_path

    import core.reporter as reporter
    monkeypatch.setattr(reporter, "build_pipeline_output", _build_once)
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/docker")

    def _boom(**kwargs):
        raise RuntimeError("the harness exploded")

    import core.dynamic_tester as dynamic_tester
    monkeypatch.setattr(dynamic_tester, "run_tests", _boom)

    # MUST NOT RAISE (the pre-guard head aborted here: OSError through
    # step_context re-raise)
    res = scanner_mod.scan_repository(
        repo_path=str(tmp_path), output_dir=str(tmp_path / "out"),
        generate_context=False, enhance=False, verify=False,
        generate_report=False, dynamic_test=True)

    # the scan completed; the failed class is recorded; the Step-6 file
    # survived with the Step-6 state (never worse than base)
    assert res.skipped_step_reasons["dynamic-test"] == "failed", res.skipped_step_reasons
    po = _pipeline_output(tmp_path, "out")
    assert isinstance(po["pipeline_stats"]["skipped_steps"], list), po
