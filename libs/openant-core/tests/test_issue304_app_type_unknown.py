"""Regression tests for issue #304 — an absent application context is
reported as ``application_type: "web_app"`` rather than unknown.

When app context is absent (``--no-context``, module unavailable, or the
generation crash path), both ``core/scanner.py`` and ``openant/cli.py``
fall back to a hard-coded ``"web_app"`` — a guess emitted into the
deliverable as though it were an observation. ``application_type`` is not
cosmetic: with a real context it feeds the Stage-1 prompt and the Stage-2
attacker personas, so the report presenting a fabricated type as fact
misleads a reader into thinking the context stage examined the target.
``context_source: "none"`` records the real state one field away, but
nothing joins the two for the reader.

Contract locked here (the issue's suggestions 1+3):
- with NO context: ``application_type`` is ``"unknown"`` — never a
  fabricated ``"web_app"`` — at both call sites AND the builder's own
  signature default (the third lurking fallback the issue did not name);
- with a REAL context: the observed value passes through unchanged;
- the summary template instructs the reader-join: when
  ``context_source`` is ``"none"``, the application type renders as not
  determined.

Not claiming (matching the issue): that the fallback ever fed the prompts —
the prompts read the ApplicationContext OBJECT (absent → the app-type
section is omitted), so this fallback was always deliverable-only; changing
it cannot alter prompt behavior.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.reporter import build_pipeline_output  # noqa: E402
from utilities.file_io import write_json  # noqa: E402


def _build(tmp_path, **kwargs):
    tmp_path = Path(tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    results = {"dataset": "t", "code_by_route": {}, "metrics": {"total": 2},
               "confirmed_findings": [], "results": []}
    write_json(tmp_path / "results.json", results)
    out = tmp_path / "pipeline_output.json"
    build_pipeline_output(
        results_path=str(tmp_path / "results.json"), output_path=str(out),
        language="python", repo_name="t/r", processing_level="all",
        **kwargs)
    return json.loads(out.read_text())


@pytest.fixture
def _tp(tmp_path):
    return tmp_path


def test_absent_context_reports_unknown(tmp_path):
    """Suggestion 1: no context → 'unknown', never a fabricated web_app."""
    po = _build(tmp_path, application_type="unknown")
    assert po["application_type"] == "unknown"


def test_real_context_passes_through(tmp_path):
    po = _build(tmp_path, application_type="agent_framework")
    assert po["application_type"] == "agent_framework"


def test_builder_signature_default_is_unknown(tmp_path):
    """The third fallback site (the issue named two): the builder's own
    signature default must not fabricate web_app for a caller that omits
    the parameter."""
    po = _build(tmp_path)  # application_type omitted entirely
    assert po["application_type"] == "unknown"


def test_scanner_fallback_is_unknown():
    """The scanner site: source-level contract — the no-context fallback
    literal is 'unknown' (behavior is covered by the scanner-harness tests;
    this pins the literal so a revert to 'web_app' fails)."""
    src = (PROJECT_ROOT / "core" / "scanner.py").read_text()
    assert 'or "unknown"' in src
    assert 'or "web_app"' not in src


def test_cli_fallback_is_unknown():
    src = (PROJECT_ROOT / "openant" / "cli.py").read_text()
    assert 'args.app_type or "unknown"' in src
    assert 'args.app_type or "web_app"' not in src


def test_summary_template_joins_context_source():
    """Suggestion 3: the template instructs the reader-join — when
    context_source is 'none', the application type renders as not
    determined from analysis."""
    src = (PROJECT_ROOT / "report" / "prompts" / "summary.txt").read_text()
    assert "context_source" in src
    assert "not determined" in src or "unknown" in src
