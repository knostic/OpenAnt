"""#321: single-shot enhance produces the classification its consumers read.

`--exploitable-only` / `--exploitable-all` filter units by `security_classification`;
`analyzer.py:59-74` reads it from BOTH context shapes and its own docstring states the
contract ("single-shot mode must populate `llm_context.security_classification`") — but
the single-shot producer is a fixed six-key literal that drops the field even when the
model volunteers it, and the single-shot prompt never asks for it. After a single-shot
enhance those flags select ZERO units, always — a total false negative on the dataset.

The fix:
- the prompt asks for it (the agentic enum: exploitable / vulnerable_internal /
  security_control / neutral — the same values the filters and the agentic tool schema
  use);
- the result literal threads it — an in-enum value kept verbatim; anything else
  (missing, invalid) becomes the explicit "unknown" (one shape, so the consumer's
  contract is always satisfiable and the enhancer's [Enhance] Classifications counter
  stops reporting a permanent {'unknown': N} for every single-shot run);
- the regression test's hand-built fixture is rebuilt from the real producer's output
  (the issue's suggestion 3 — the old test exercised the reader against an input the
  producer could not generate).
"""
import json
import os
import sys
from pathlib import Path

import pytest

CORE = str(Path(__file__).resolve().parents[2])  # libs/openant-core
if CORE not in sys.path:
    sys.path.insert(0, CORE)

from utilities.context_enhancer import (  # noqa: E402
    ContextEnhancer, get_context_enhancement_prompt,
)
sys.path.insert(0, str(Path(__file__).resolve().parent))  # noqa: E402
from test_enhance_resilience import _fake_binding  # noqa: E402

_ENUM = ("exploitable", "vulnerable_internal", "security_control", "neutral")


def _unit():
    """A realistic unit (the parser's code dict shape)."""
    return {
        "id": "app.py:f",
        "unit_type": "function",
        "code": {
            "primary_code": "def f(x):\n    return eval(x)\n",
            "primary_origin": {"file_path": "app.py", "function_name": "f"},
        },
        "metadata": {"direct_calls": [], "direct_callers": []},
    }


def _stub_enhancer(monkeypatch, reply_json):
    """A real ContextEnhancer with the LLM call stubbed to return reply_json."""
    enh = ContextEnhancer(binding=_fake_binding(), tracker=None)
    monkeypatch.setattr(
        "utilities.context_enhancer.simple_text",
        lambda binding, prompt, **k: json.dumps(reply_json))
    return enh


_VOLUNTEERED = {
    "missing_dependencies": [],
    "additional_callers": [],
    "data_flow": {},
    "imports": [],
    "reasoning": "r",
    "confidence": 0.9,
    # the issue's executed stub: a model that VOLUNTEERS the field — the
    # six-key literal dropped it pre-fix
    "security_classification": "exploitable",
}


def test_volunteered_classification_survives(monkeypatch):
    """The issue's executed repro: even a model that volunteers the field had
    it dropped by the whitelist literal. It must thread through."""
    enh = _stub_enhancer(monkeypatch, _VOLUNTEERED)
    out = enh.enhance_unit(_unit(), {})
    cls = out.get("llm_context", {}).get("security_classification")
    assert cls == "exploitable", f"the volunteered value was dropped: {cls!r}"


def test_every_enum_value_threads(monkeypatch):
    """The agentic enum's four values all thread verbatim."""
    for value in _ENUM:
        reply = dict(_VOLUNTEERED, security_classification=value)
        enh = _stub_enhancer(monkeypatch, reply)
        out = enh.enhance_unit(_unit(), {})
        assert out["llm_context"]["security_classification"] == value


def test_missing_or_invalid_becomes_explicit_unknown(monkeypatch):
    """One shape always: absent or off-enum -> the explicit 'unknown' (the
    key present, so the consumer's contract holds and the [Enhance]
    Classifications counter is honest) — never the pre-fix silent drop."""
    for reply in ({"reasoning": "r"},                       # absent
                  dict(_VOLUNTEERED, security_classification="very-bad")):
        enh = _stub_enhancer(monkeypatch, reply)
        out = enh.enhance_unit(_unit(), {})
        assert out["llm_context"]["security_classification"] == "unknown"


def test_prompt_asks_for_the_classification():
    """The single-shot prompt never requested the field (a grep for it
    returned nothing) — it must ask, with the agentic enum."""
    prompt = get_context_enhancement_prompt(
        function_id="f", function_name="f", function_code="x = 1",
        unit_type="function", class_name=None,
        static_deps=[], static_callers=[], context_functions=[])
    assert "security_classification" in prompt
    for value in _ENUM:
        assert value in prompt


def test_fixture_built_from_the_real_producer(monkeypatch):
    """The issue's suggestion 3: the regression test at
    test_enhance_resilience:283-285 hand-built the unit dict — exercising the
    reader against an input the producer could not generate. Rebuild it from
    the real producer's output."""
    from core.analyzer import _unit_security_classification

    enh = _stub_enhancer(monkeypatch, _VOLUNTEERED)
    produced = enh.enhance_unit(_unit(), {})
    # the real producer's output feeds the real reader — end to end
    assert _unit_security_classification(produced) == "exploitable"


def test_the_filters_now_select_after_singleshot(monkeypatch):
    """The operator-visible consequence: --exploitable-only selects ZERO
    units after a single-shot enhance (always). With the field produced, the
    filter keeps the exploitable unit."""
    enh = _stub_enhancer(monkeypatch, _VOLUNTEERED)
    produced = enh.enhance_unit(_unit(), {})
    from core.analyzer import _unit_security_classification
    kept = [u for u in [produced]
            if _unit_security_classification(u) == "exploitable"]
    assert kept, "the exploitable filter selected zero units"


def test_correction_schema_carries_the_classification():
    """Wave r1 #1: the malformed-reply recovery path repairs into
    _ENHANCE_JSON_SCHEMA — a strictly-schema-following corrector model
    re-emitted the reply WITHOUT the field, and an exploitable unit whose
    reply needed correction was silently excluded (the exact bug class,
    surviving on the correction sub-path)."""
    from utilities.context_enhancer import _ENHANCE_JSON_SCHEMA

    assert "security_classification" in _ENHANCE_JSON_SCHEMA
    for value in _ENUM:
        assert value in _ENHANCE_JSON_SCHEMA


def test_resume_backfills_the_old_six_key_shape():
    """Wave r1 #2: a checkpoint written by a pre-fix run restores verbatim —
    the restored unit still yielded None from the reader (--exploitable-only
    treated it exactly as pre-fix, silently). "One shape ALWAYS" holds across
    resume: the restore backfills the explicit "unknown"."""
    import tempfile
    from utilities.context_enhancer import ContextEnhancer
    from core.checkpoint import save_checkpoint_under_lock
    from core.analyzer import _unit_security_classification

    with tempfile.TemporaryDirectory() as d:
        cp_dir = str(Path(d) / "enhance_checkpoints")
        os.makedirs(cp_dir, exist_ok=True)
        # a PRE-fix checkpoint: the six-key shape, no classification
        save_checkpoint_under_lock(cp_dir, "app.py:f", {
            "id": "app.py:f", "context_key": "llm_context",
            "llm_context": {"reasoning": "old", "confidence": 0.5},
        })
        enh = ContextEnhancer(binding=_fake_binding(), tracker=None)

        def fake_enhance(unit, by_id):
            raise AssertionError("a restored unit must not be re-enhanced")

        enh.enhance_unit = fake_enhance
        ds = {"units": [{"id": "app.py:f", "code": "def f(): pass"}]}
        enh.enhance_dataset(ds, workers=1, checkpoint_path=cp_dir)
        ctx = ds["units"][0]["llm_context"]
        assert ctx.get("security_classification") == "unknown", ctx
        # the reader surfaces "unknown" (its own vocabulary) — never selected
        # by the exploitable filter
        assert _unit_security_classification(ds["units"][0]) == "unknown"


def test_error_path_carries_the_shape():
    """Wave r2 #2: the producer's own error path wrote the keyless shape
    (_get_default_context) — the same shape the commit said can no longer be
    produced. One shape ALWAYS: the error context carries the explicit
    "unknown"."""
    from utilities.context_enhancer import ContextEnhancer

    enh = ContextEnhancer(binding=_fake_binding(), tracker=None)
    ctx = enh._get_default_context({"type": "api_status"})
    assert ctx.get("security_classification") == "unknown", ctx


def test_csv_precedence_matches_the_analyzer():
    """Wave r2 #1: the CSV read llm_context FIRST — now that single-shot
    always holds a truthy value ("unknown" at minimum), llm_context-first
    MASKS agent_context on dual-context units, and the CSV disagrees with
    --exploitable-only (the analyzer prefers agent_context)."""
    import csv
    import tempfile
    from report.csv_export import export_csv

    unit = {"id": "app.py:f",
            "code": {"primary_code": "def f(): pass"},
            # the dual-context shape: agent_context is the analyzer's preferred source
            "agent_context": {"security_classification": "exploitable"},
            "llm_context": {"security_classification": "unknown"}}
    result = {"finding": "vulnerable", "verdict": "VULNERABLE", "reasoning": "r",
              "attack_vector": "av", "route_key": "app.py:f", "cwe_id": 79,
              "cwe_name": "XSS", "verification": {}}
    with tempfile.TemporaryDirectory() as d:
        exp = str(Path(d) / "e.json")
        ds = str(Path(d) / "d.json")
        out = str(Path(d) / "o.csv")
        Path(exp).write_text(json.dumps({"results": [result], "metrics": {}, "code_by_route": {}}))
        Path(ds).write_text(json.dumps({"units": [unit]}))
        export_csv(exp, ds, out)
        with open(out, newline="") as f:
            rows = list(csv.DictReader(f))
    assert rows[0]["agentic_classification"] == "exploitable", rows[0]
