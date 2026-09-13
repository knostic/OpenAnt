"""#613: the aggregate scan report must record the actual scan target under
``inputs.repo_path`` — not the output directory.

``_write_scan_report`` built the aggregate's ``inputs`` block from
``result.output_dir`` passed through a cwd-substring ``.replace`` — so
``scan.report.json`` claimed the *output directory* was the scanned
repository (``inputs.repo_path: "./out"``), and the substring substitution
could corrupt the value outright (a cwd that is a prefix of a longer
component rewrites the middle of the path; a root cwd renders ``/tmp/out``
as ``.tmp.out``). The per-step reports in the same directory have always
carried the real scan target (the parse step's ``inputs.repo_path``); the
aggregate now records the same value: the caller-threaded target, written
verbatim — one key, one convention.

The writer-level tests would TypeError against the old signature rather
than demonstrate the wrong value, so the plumbing test (a real offline
``scan_repository`` run) carries the honest RED: it reads the artifacts off
disk and fails on pristine code. Fully offline ($0).
"""

import json
import os
from pathlib import Path

import core.scanner as scanner_mod
from core.schemas import AnalysisMetrics, ScanResult
from tests.test_pr69_report_llmconfig_forwarding import _install_minimal_pipeline

# brings the autouse _offline_registry fixture (probe neutered, config resolves)
pytest_plugins = ("tests.test_pr69_report_llmconfig_forwarding",)

_OFFLINE_FLAGS = dict(
    generate_context=False, enhance=False, verify=False,
    generate_report=False, dynamic_test=False,
)


def _result_for(output_dir: Path) -> ScanResult:
    metrics = AnalysisMetrics(total=0, vulnerable=0, bypassable=0, inconclusive=0,
                              protected=0, safe=0, errors=0)
    return ScanResult(output_dir=str(output_dir), units_count=0,
                      language="python", metrics=metrics)


def test_scan_report_records_the_scan_target_not_the_output_dir(
    monkeypatch, tmp_path
):
    """The plumbing proof: the real scan path supplies the target.

    A relative repo sibling of the output dir, resolved from a tmp cwd —
    exercises the caller's normalization (``scan_repository``'s
    ``os.path.abspath``) and the threading into the writer, then asserts the
    artifact on disk (a writer-only test cannot prove the real scanner
    supplies the target). The expectation is derived from the input side
    alone, never from the run's own artifacts. On pristine code the
    aggregate records the *output directory* (cwd-relativized to ``./out``)
    — this is the RED.
    """
    (tmp_path / "repo").mkdir()
    _install_minimal_pipeline(monkeypatch)
    monkeypatch.chdir(tmp_path)
    scanner_mod.scan_repository(
        repo_path="repo", output_dir="out", **_OFFLINE_FLAGS,
    )
    expected = os.path.abspath("repo")
    report = json.loads((tmp_path / "out" / "scan.report.json").read_text())
    assert report["inputs"]["repo_path"] == expected
    # The parse report (same run, the real per-step writer) carries the same
    # value — one key, one convention across the output directory.
    parse = json.loads((tmp_path / "out" / "parse.report.json").read_text())
    assert parse["inputs"]["repo_path"] == expected


def test_writer_records_the_threaded_target_verbatim(monkeypatch, tmp_path):
    """The writer contract: the value is the caller-threaded target, verbatim.

    Defeats the reintroduction of any cwd-based rewriting: the cwd here is a
    prefix of one of the target's components (``repo/`` vs ``repo-archive/``),
    the exact shape that turns a substring ``.replace`` into ``.-archive/src``.
    The target is a real SYMLINK whose resolved location differs from the
    passed path: the exact-string assertion pins the LEXICAL value — a
    ``realpath``-resolving rewrite would record the resolved location and fail.
    """
    out = tmp_path / "out"
    out.mkdir()
    (tmp_path / "repo").mkdir()
    monkeypatch.chdir(tmp_path / "repo")
    # the link is named so BOTH traps hold at once: the cwd (…/repo) is a
    # substring-PREFIX of the target's parent component (repo-archive) — the
    # exact shape that turns a substring ``.replace`` into ``.-archive/src`` —
    # and the lexical path (repo-archive) differs from the resolved one
    # (real-src), so a ``realpath``-resolving rewrite records the wrong value.
    real_src = tmp_path / "real-src"
    real_src.mkdir()
    link_src = tmp_path / "repo-archive"
    link_src.symlink_to(real_src, target_is_directory=True)
    target = str(link_src / "src")
    path = scanner_mod._write_scan_report(
        str(out), _result_for(out), step_reports=[], repo_path=target,
    )
    report = json.loads(Path(path).read_text())
    assert report["inputs"]["repo_path"] == target


def test_writer_keeps_the_target_raw_under_home(monkeypatch, tmp_path):
    """Raw absolute by design — the scan target is never home-relativized.

    ``openant_core_path`` stays scrubbed (it is the tool's INSTALL path,
    incidental disclosure); the scan target is the scan's primary INPUT and
    is recorded exactly like the per-step ``inputs.repo_path`` writers. This
    defeats a future "leak hygiene" pass re-relativizing it (the rationale
    the stale comment falsely claimed today). Coverage boundary:
    ``openant_core_path``'s OWN relativization is not asserted here (under
    a patched HOME it is a no-op on the real install path) — that contract
    lives in test_issue303.
    """
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    out = tmp_path / "out"
    out.mkdir()
    target = str(fake_home / "user" / "repo")
    path = scanner_mod._write_scan_report(
        str(out), _result_for(out), step_reports=[], repo_path=target,
    )
    report = json.loads(Path(path).read_text())
    assert report["inputs"]["repo_path"] == target
    assert not report["inputs"]["repo_path"].startswith("~")
