"""Regression lock: the JS and Go parse subprocesses must pass a wall-clock timeout,
so a hung inner Node/Go parser fails cleanly instead of blocking the Python parent forever.

C/Ruby/PHP/Zig already pass timeout=1800; JS and Go did not, so a direct-Python caller of
parse_repository / _parse_javascript / _parse_go had no bound. These tests fail on master
(no timeout) and pass with the fix.
"""
import inspect
import tempfile

from core import parser_adapter


class _FakeCompleted:
    returncode = 0


def _capture_run_calls(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return _FakeCompleted()

    monkeypatch.setattr(parser_adapter.subprocess, "run", fake_run)
    return calls


def _parse_call_timeout(calls, script_name):
    """timeout kwarg of the subprocess.run whose cmd invokes <script_name> (the parse step)."""
    for cmd, kwargs in calls:
        if any(script_name in str(part) for part in cmd):
            return kwargs.get("timeout")
    return "NO-PARSE-CALL"


def test_js_parse_subprocess_has_timeout(monkeypatch):
    calls = _capture_run_calls(monkeypatch)
    d = tempfile.mkdtemp()
    try:
        parser_adapter._parse_javascript(d, d, "reachable")
    except Exception:
        pass  # we only care that the parse subprocess.run received a timeout
    assert _parse_call_timeout(calls, "test_pipeline.py") == 1800


def test_go_parse_subprocess_has_timeout(monkeypatch):
    calls = _capture_run_calls(monkeypatch)
    d = tempfile.mkdtemp()
    try:
        parser_adapter._parse_go(d, d, "reachable")
    except Exception:
        pass
    assert _parse_call_timeout(calls, "test_pipeline.py") == 1800


def test_all_subprocess_parsers_are_uniformly_timed():
    """Every language whose *parse step* runs as a subprocess must carry a timeout — not just
    4 of them. (Python parses in-process, so it is intentionally excluded; the npm-install
    dependency bootstrap in _ensure_js_parser_dependencies is a separate concern, not a parse.)"""
    for lang in ("_parse_javascript", "_parse_go", "_parse_c",
                 "_parse_ruby", "_parse_php", "_parse_zig"):
        src = inspect.getsource(getattr(parser_adapter, lang))
        assert "timeout=" in src, f"{lang} subprocess.run is missing a timeout"
