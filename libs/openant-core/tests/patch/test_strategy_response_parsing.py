"""PR #763 review: the Final Strategy response parse.

`_parse_json_response`'s prose-prefixed fallback accepted only objects with
the Planner's fingerprint, which the Strategy schema can never match, so one
line of prose before a valid Strategy object dropped the whole response and
with it `target_authority_unresolved=True`. The Strategy call now uses its own
fingerprint; an unparseable response still fails closed (unevaluated, which
the pipeline treats as an invoked-and-failed Strategy).
"""

import json

import pytest

from utilities.autopatcher.pipeline import _strategy_invocation_failure
from utilities.autopatcher.remediation_planner import (
    _has_plan_shape,
    _has_strategy_shape,
    _parse_json_response,
    generate_remediation_strategy,
)


def _strategy_json(unresolved=True, **overrides):
    # exactly the schema prompts/remediation_strategy.md asks for
    body = {
        "extended_mechanism": "shell argument validation",
        "target_files": ["a.py"], "target_symbols": ["handle"],
        "required_edits": ["quote the argument"], "rejected_targets": [],
        "security_invariant": "untrusted input must never reach os.system",
        "insufficient_evidence": [], "target_authority_unresolved": unresolved,
    }
    body.update(overrides)
    return json.dumps(body, indent=2)


_PLANNER_JSON = json.dumps({
    "remediation_mechanism": "m", "target_files": ["a.py"], "target_symbols": ["handle"],
    "security_invariant": "i", "narrower_alternative_decision": "NONE",
})


class _Stub:
    def __init__(self, text):
        self.text = text

    def complete(self, system, user, stage=None):
        return self.text


def _run(tmp_path, response):
    (tmp_path / "a.py").write_text("def handle(req):\n    os.system(req.cmd)\n")
    return generate_remediation_strategy(
        "os.system reached by untrusted input", _Stub(response), tmp_path, None,
        planner_evidence_ctx="## candidate\n- a.py: handle()",
    )


class TestStrategyResponseParsing:
    def test_bare_json(self, tmp_path):
        result = _run(tmp_path, _strategy_json())
        assert result.evaluated is True
        assert result.target_authority_unresolved is True

    @pytest.mark.parametrize("prefix,suffix", [
        ("Here is the strategy:\n", ""),
        ("Here is the strategy (note: `{}` is not used):\n", "\nLet me know if you need more."),
    ], ids=["prose-prefixed", "prose-around-with-brace-noise"])
    def test_prose_wrapped_json_keeps_unresolved_authority(self, tmp_path, prefix, suffix):
        result = _run(tmp_path, prefix + _strategy_json() + suffix)
        assert result.evaluated is True
        assert result.target_authority_unresolved is True

    def test_prose_wrapped_json_keeps_resolved_authority(self, tmp_path):
        result = _run(tmp_path, "Strategy follows.\n" + _strategy_json(unresolved=False))
        assert result.evaluated is True
        assert result.target_authority_unresolved is False

    @pytest.mark.parametrize("response", [
        "Here is the strategy:\n" + _strategy_json()[:-20],  # truncated
        "Here is the strategy:\n" + _strategy_json() + "\nOr alternatively:\n" + _strategy_json(),
        "Here is the plan:\n" + _PLANNER_JSON,  # a Planner object is not a Strategy response
        "I could not determine a strategy.",
    ], ids=["malformed", "ambiguous-two-objects", "planner-shaped", "no-json"])
    def test_unparseable_response_fails_closed(self, tmp_path, response):
        result = _run(tmp_path, response)
        assert result.evaluated is False
        # never mistaken for "Strategy not invoked": the pipeline gate fires
        assert _strategy_invocation_failure("## candidate\n- a.py: handle()", result) is not None


class TestFingerprintsStaySeparate:
    def test_planner_parse_unchanged(self):
        assert _parse_json_response("Here is the plan:\n" + _PLANNER_JSON) == json.loads(_PLANNER_JSON)

    def test_planner_parse_does_not_accept_a_strategy_object(self):
        assert _parse_json_response("Here is the strategy:\n" + _strategy_json()) is None

    def test_shapes_are_disjoint(self):
        assert _has_strategy_shape(json.loads(_strategy_json())) is True
        assert _has_plan_shape(json.loads(_strategy_json())) is False
        assert _has_strategy_shape(json.loads(_PLANNER_JSON)) is False
