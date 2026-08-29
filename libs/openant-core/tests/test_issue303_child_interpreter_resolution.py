"""Regression tests for issue #303 — child interpreters spawned mid-scan
resolve through the shared venv's editable `.pth` at spawn time, so a second
session re-pointing the venv mid-scan makes the first scan's later children
import a different checkout than their parent did, silently.

Contract locked here (the issue's suggestions 1+3; 2 is subsumed by 3 — an
explicit PYTHONPATH makes a child unable to resolve elsewhere, deterministically):
- `child_interpreter_env()` prepends the PARENT's resolved openant-core root
  to PYTHONPATH (before site-packages, so it wins over the `.pth` target),
  preserves any existing PYTHONPATH, and returns a COPY of the environment
  (no mutation of os.environ);
- all three child-spawn sites (the per-language parser subprocess, the HTML
  report writer, the CSV export writer) pass that env to subprocess.run;
- `scan.report.json` records the resolved `openant_core_path` — the skew
  becomes detectable after the fact even when prevention fails.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.child_interp import child_interpreter_env, resolved_core_path  # noqa: E402


def test_resolved_core_path_is_this_checkout():
    """The parent's resolved core root is THIS checkout (the module's own
    location), not whatever the venv `.pth` names."""
    assert resolved_core_path() == Path(__file__).resolve().parents[1]


def test_child_env_prepends_core_root(monkeypatch):
    monkeypatch.delenv("PYTHONPATH", raising=False)
    env = child_interpreter_env()
    assert env["PYTHONPATH"] == str(resolved_core_path())


def test_child_env_preserves_existing_pythonpath(monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "/some/existing/path")
    env = child_interpreter_env()
    assert env["PYTHONPATH"].startswith(str(resolved_core_path()))
    assert env["PYTHONPATH"].endswith("/some/existing/path")
    assert env["PYTHONPATH"].count(str(resolved_core_path())) == 1


def test_child_env_is_a_copy_not_mutation(monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "/original")
    env = child_interpreter_env()
    assert env["PYTHONPATH"] != "/original"
    assert os.environ["PYTHONPATH"] == "/original"  # the parent env untouched


def _spawn_capturing(monkeypatch, call):
    """Run `call` with subprocess.run monkeypatched; return captured kwargs."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured.update(kwargs)
        captured["cmd"] = cmd

        class _R:
            returncode = 0
            stdout = ""
            stderr = ""
        return _R()

    monkeypatch.setattr("subprocess.run", fake_run)
    call()
    return captured


def test_parser_subprocess_passes_the_env(tmp_path, monkeypatch):
    """The per-language parser child (the site WITHOUT -P) gets the env."""
    from types import SimpleNamespace
    from core import parser_adapter as pa

    fake_spec = SimpleNamespace(parser_mode="subprocess", bootstrap=None)
    monkeypatch.setattr(pa, "load_registry", lambda: {"python": fake_spec})
    monkeypatch.setattr(pa, "parser_script_path",
                        lambda lang: "/tmp/fake_pipeline.py")

    def call():
        pa._parse_via_subprocess("python", str(tmp_path), str(tmp_path),
                                 "all", True, False)

    captured = _spawn_capturing(monkeypatch, call)
    assert "env" in captured, "the parser subprocess must pass env="
    assert captured["env"]["PYTHONPATH"].startswith(str(resolved_core_path()))


def test_html_report_subprocess_passes_the_env(tmp_path, monkeypatch):
    from core import reporter as rep

    def call():
        rep.generate_html_report(
            str(tmp_path / "r.json"), str(tmp_path / "d.json"),
            str(tmp_path / "out.html"))

    captured = _spawn_capturing(monkeypatch, call)
    assert captured["env"]["PYTHONPATH"].startswith(str(resolved_core_path()))


def test_csv_export_subprocess_passes_the_env(tmp_path, monkeypatch):
    from core import reporter as rep

    def call():
        rep.generate_csv_report(
            str(tmp_path / "r.json"), str(tmp_path / "d.json"),
            str(tmp_path / "out.csv"))

    captured = _spawn_capturing(monkeypatch, call)
    assert captured["env"]["PYTHONPATH"].startswith(str(resolved_core_path()))


def test_scan_report_records_the_resolved_core_path(tmp_path):
    """Suggestion 1: the aggregate report records which checkout produced
    the scan — the skew is detectable after the fact."""
    import json
    from core.scanner import _write_scan_report, ScanResult

    result = ScanResult(output_dir=str(tmp_path))
    result.units_count = 1
    result.language = "python"
    _write_scan_report(str(tmp_path), result, [])
    report = json.loads((tmp_path / "scan.report.json").read_text())
    # leak hygiene: the recorded path is ~-relativized when under the
    # user's home (CI: /home/runner/... -> ~/...), never the raw absolute
    import os as _os
    _raw = str(resolved_core_path())
    _home = _os.path.expanduser("~")
    _expected = "~" + _raw[len(_home):] if _raw.startswith(_home) else _raw
    assert report["summary"]["openant_core_path"] == _expected
