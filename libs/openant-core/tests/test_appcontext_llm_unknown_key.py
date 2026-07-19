"""Regression test for HUNT-sib-appcontext-man-5.

generate_application_context() constructs ``ApplicationContext(**data)`` directly
on JSON parsed from LLM output. An LLM that hallucinates an unknown/extra key
(e.g. ``"threat_actors"``) makes ``**data`` pass an unexpected keyword argument to
the dataclass __init__ -> uncaught TypeError, crashing context generation.

The fix must allowlist-filter the LLM dict to the ApplicationContext dataclass
fields before construction, so unknown keys are dropped rather than crashing.
"""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # libs/openant-core

import json  # noqa: E402

import pytest  # noqa: E402

from context import application_context as appctx  # noqa: E402
from context.application_context import (  # noqa: E402
    ApplicationContext,
    generate_application_context,
    load_context,
)


_LLM_JSON_WITH_HALLUCINATED_KEY = """```json
{
  "application_type": "cli_tool",
  "purpose": "A command-line tool.",
  "intended_behaviors": ["runs commands"],
  "trust_boundaries": {"cli_args": "trusted"},
  "requires_remote_trigger": false,
  "confidence": 0.9,
  "evidence": ["has a CLI entry point"],
  "threat_actors": ["nation-state"],
  "totally_made_up_field": 123
}
```"""


def test_hallucinated_llm_key_does_not_crash(tmp_path, monkeypatch):
    # A repo with at least one context source so gather_context_sources is non-empty.
    (tmp_path / "README.md").write_text("# Demo\nA small CLI tool.\n")

    monkeypatch.setattr(
        appctx, "simple_text", lambda *a, **k: _LLM_JSON_WITH_HALLUCINATED_KEY
    )
    fake_binding = SimpleNamespace(provider_name="fake", model="fake-model")

    # Pre-fix: raises TypeError (unexpected keyword argument 'threat_actors').
    ctx = generate_application_context(
        tmp_path, fake_binding, force_regenerate=True
    )

    assert isinstance(ctx, ApplicationContext)
    assert ctx.application_type == "cli_tool"
    assert ctx.source == "llm"
    # The hallucinated keys must not have been set as attributes.
    assert not hasattr(ctx, "threat_actors")
    assert not hasattr(ctx, "totally_made_up_field")


# --- FA3 same-mechanism residual: MISSING required field -------------------
#
# The allowlist filter closes the UNKNOWN-key crash, but if the LLM OMITS a
# required field (application_type / purpose) then ApplicationContext(**data)
# still raises an uncaught TypeError ("missing required positional argument") —
# the exact crash class the fix set out to kill. generate_application_context
# (untrusted LLM output) must fall back gracefully (return None); load_context
# (a saved/edited file) must raise a clear ValueError, not a raw TypeError.

# Exact repro from the audit finding: valid JSON, omits the required `purpose`.
_LLM_JSON_MISSING_PURPOSE = """```json
{
  "application_type": "cli_tool",
  "confidence": 0.9,
  "threat_actors": ["x"]
}
```"""

_LLM_JSON_EMPTY_OBJECT = """```json
{}
```"""

_LLM_JSON_ONLY_UNKNOWN_KEYS = """```json
{"threat_actors": ["x"], "totally_made_up_field": 123}
```"""


@pytest.mark.parametrize(
    "llm_json",
    [
        _LLM_JSON_MISSING_PURPOSE,
        _LLM_JSON_EMPTY_OBJECT,
        _LLM_JSON_ONLY_UNKNOWN_KEYS,
    ],
)
def test_missing_required_field_does_not_crash(tmp_path, monkeypatch, llm_json):
    (tmp_path / "README.md").write_text("# Demo\nA small CLI tool.\n")
    monkeypatch.setattr(appctx, "simple_text", lambda *a, **k: llm_json)
    fake_binding = SimpleNamespace(provider_name="fake", model="fake-model")

    # Pre-fix: raises TypeError (missing required positional argument 'purpose').
    # Post-fix: graceful fallback to None so callers continue without a context.
    ctx = generate_application_context(
        tmp_path, fake_binding, force_regenerate=True
    )
    assert ctx is None


def test_load_context_missing_required_field_raises_valueerror(tmp_path):
    # A saved/hand-edited context file missing the required `purpose` field.
    bad = tmp_path / "application_context.json"
    bad.write_text(json.dumps({"application_type": "cli_tool", "confidence": 0.9}))

    # Pre-fix: raw TypeError (missing required positional argument 'purpose').
    # Post-fix: a clear ValueError naming the offending file.
    with pytest.raises(ValueError) as excinfo:
        load_context(bad)
    assert str(bad) in str(excinfo.value)
    assert not isinstance(excinfo.value, TypeError)
