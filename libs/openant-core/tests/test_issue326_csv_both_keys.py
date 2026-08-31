"""#326: the CSV exporter reads both context keys — agentic is the default mode.

report/csv_export.py read `llm_context` only. In agentic mode — the default on both entry
points — the enhancer writes `agent_context` instead, so `unit_description` (the CSV's
unit-context column) exported empty for every unit of an agentically enhanced dataset.
The two-key fallback handling exactly this split already existed in core/analyzer.py (PR
#133 — the mirror image: that fix's `agent_context`-first fallback was never carried
across, even though the same PR edited this file for something else).

The fix (the issue's suggested reading, with the key-name mapping the issue insists on):
- read `agent_context` first, falling back to `llm_context`;
- `unit_description` maps `agent_context.classification_reasoning` as well as
  `llm_context.reasoning` (the key names differ — a naive two-key fallback would leave the
  column empty in agentic mode);
- `agentic_classification` reads both keys with the analyzer's precedence (agent_context
  first) — this file's half of #321's producer (the single-shot half is #321's own PR).
"""
import csv
import json
import sys
import tempfile
from pathlib import Path

CORE = str(Path(__file__).resolve().parents[2])  # libs/openant-core
if CORE not in sys.path:
    sys.path.insert(0, CORE)

from report.csv_export import export_csv  # noqa: E402


def _run_export(units, results=None):
    with tempfile.TemporaryDirectory() as d:
        exp = Path(d) / "e.json"
        ds = Path(d) / "d.json"
        out = Path(d) / "o.csv"
        exp.write_text(json.dumps({"results": results or [{
            "finding": "vulnerable", "verdict": "VULNERABLE", "reasoning": "r",
            "attack_vector": "av", "route_key": "app.py:f", "cwe_id": 79,
            "cwe_name": "XSS", "verification": {}}], "metrics": {}, "code_by_route": {}}))
        ds.write_text(json.dumps({"units": units}))
        export_csv(str(exp), str(ds), str(out))
        with open(out, newline="") as f:
            rows = list(csv.DictReader(f))
    return rows


_UNIT_AGENTIC = {
    "id": "app.py:f",
    "code": {"primary_code": "def f(): pass"},
    "agent_context": {
        "classification_reasoning": "the agentic-mode unit context",
        "security_classification": "exploitable",
    },
}

_UNIT_SINGLESHOT = {
    "id": "app.py:f",
    "code": {"primary_code": "def f(): pass"},
    "llm_context": {
        "reasoning": "the single-shot unit context",
        "security_classification": "unknown",
    },
}

_UNIT_ERROR_MARKER = {
    "id": "app.py:f",
    "code": {"primary_code": "def f(): pass"},
    "agent_context": {
        "error": {"type": "api_status", "status_code": 529},
        "security_classification": "error",
    },
}


def test_agentic_description_populates():
    """The headline: agentic mode — the default — populates the CSV's
    unit_description with agent_context.classification_reasoning (the issue
    names this mapping as required, not a naive two-key fallback)."""
    rows = _run_export([_UNIT_AGENTIC])
    assert rows[0]["unit_description"] == "the agentic-mode unit context"


def test_single_shot_description_still_populates():
    """The guard: the single-shot path keeps populating from
    llm_context.reasoning."""
    rows = _run_export([_UNIT_SINGLESHOT])
    assert rows[0]["unit_description"] == "the single-shot unit context"


def test_agentic_classification_reads_both_keys():
    """The exporter's half of #321's producer: the classification column
    reads agent_context (agentic) with the llm_context fallback
    (single-shot, post-#321) — the analyzer's precedence."""
    rows = _run_export([_UNIT_AGENTIC])
    assert rows[0]["agentic_classification"] == "exploitable"
    rows2 = _run_export([_UNIT_SINGLESHOT])
    assert rows2[0]["agentic_classification"] == "unknown"


def test_the_error_marker_reaches_the_csv():
    """The issue's additional evidence: the agentic error path writes a
    security_classification="error" marker to agent_context explicitly so the
    CSV shows honestly — but the exporter never read agent_context, so the
    marker vanished (the comment's own purpose was unachieved)."""
    rows = _run_export([_UNIT_ERROR_MARKER])
    assert rows[0]["agentic_classification"] == "error"


def test_both_keys_precedence():
    """The analyzer's precedence: agent_context first when both exist (a
    unit re-enhanced agentically after single-shot)."""
    both = {
        "id": "app.py:f",
        "code": {"primary_code": "def f(): pass"},
        "agent_context": {"classification_reasoning": "the fresh agentic"},
        "llm_context": {"reasoning": "the stale single-shot"},
    }
    rows = _run_export([both])
    assert rows[0]["unit_description"] == "the fresh agentic"
