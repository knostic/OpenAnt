"""#522: null optionals in a COMPLETE generation are not malformed.

The system prompt declares docker_compose as "string | null" and tells Go
tests NOT to write go.mod — so a model that enumerates the full schema
emits ``"docker_compose": null`` (and, for Go findings, null requirements)
for a complete, valid generation. The old validator rejected any non-str value for those
fields, discarding the generation to the ERROR path (result_collector
records generation-None as status ERROR, un-retried): 18/21 real
sonnet-family generations in the discovery run were dropped this way.

The contract now: the required trio stays strictly str; null optionals
coerce to the canonical absent form "" (what the executor and
DynamicTestResult already default to); non-str non-null optionals stay
rejected (a dict/number is still malformed).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import utilities.dynamic_tester.test_generator as tg  # noqa: E402


_FINDING = {
    "id": "f1", "name": "x", "cwe_id": 22, "cwe_name": "Path Traversal",
    "location": {"file": "a/b.go", "line": 1},
    "stage1_verdict": "vulnerable", "stage2_verdict": "vulnerable",
    "vulnerable_code": "func f() {}", "description": "d", "impact": "i",
    "steps": "s",
}
_REPO = {"name": "r", "language": "go", "application_type": "cli_tool"}

_BASE = {
    "dockerfile": "FROM golang:1.27-alpine\n",
    "test_script": "package main\nfunc main() {}\n",
    "test_filename": "test_exploit.go",
}


def _stub_reply(payload: dict):
    import json
    captured = {}

    def fake_simple_text(binding, prompt, **kw):
        captured["prompt"] = prompt
        return json.dumps(payload)

    return captured, fake_simple_text


def _run_generate(payload):
    captured, fake = _stub_reply(payload)
    orig_st, orig_bp = tg.simple_text, tg._build_finding_prompt
    tg.simple_text = fake
    tg._build_finding_prompt = lambda finding, repo_info: "PROMPT"
    try:
        return tg.generate_test(_FINDING, _REPO, binding=object())
    finally:
        tg.simple_text, tg._build_finding_prompt = orig_st, orig_bp


def _run_regenerate(payload):
    captured, fake = _stub_reply(payload)
    prev = dict(_BASE)  # a clean previous generation; only the REPLY carries the mutation
    orig_st, orig_bp = tg.simple_text, tg._build_finding_prompt
    tg.simple_text = fake
    tg._build_finding_prompt = lambda finding, repo_info: "PROMPT"
    try:
        return tg.regenerate_test(_FINDING, _REPO, prev, "build failed", binding=object())
    finally:
        tg.simple_text, tg._build_finding_prompt = orig_st, orig_bp


import pytest  # noqa: E402


@pytest.mark.parametrize("null_field", [
    "docker_compose", "requirements", "requirements_filename", "__all__"])
def test_generate_accepts_null_optionals(null_field):
    """A complete generation with null optionals is returned, coerced."""
    payload = dict(_BASE)
    if null_field == "__all__":
        payload.update({"docker_compose": None, "requirements": None,
                        "requirements_filename": None})
    else:
        payload[null_field] = None
    out = _run_generate(payload)
    assert out is not None, f"complete generation discarded: {null_field}=null"
    if null_field == "__all__":
        for k in ("docker_compose", "requirements", "requirements_filename"):
            assert out[k] == "", f"{k} must coerce to the absent form ''"
    else:
        assert out[null_field] == ""


@pytest.mark.parametrize("null_field", [
    "docker_compose", "requirements", "requirements_filename", "__all__"])
def test_regenerate_accepts_null_optionals(null_field):
    """The regenerate site accepts and coerces the same shapes."""
    payload = dict(_BASE)
    if null_field == "__all__":
        payload.update({"docker_compose": None, "requirements": None,
                        "requirements_filename": None})
    else:
        payload[null_field] = None
    out = _run_regenerate(payload)
    assert out is not None
    if null_field == "__all__":
        for k in ("docker_compose", "requirements", "requirements_filename"):
            assert out[k] == ""
    else:
        assert out[null_field] == ""


@pytest.mark.parametrize("bad_value", [123, ["x"], {"services": {}}, True])
@pytest.mark.parametrize("field", ["docker_compose", "requirements", "requirements_filename"])
def test_non_null_non_str_optionals_still_rejected(field, bad_value):
    """The belt is not loosened: a dict/list/number optional is malformed."""
    payload = dict(_BASE)
    payload[field] = bad_value
    assert _run_generate(payload) is None
    assert _run_regenerate(payload) is None


@pytest.mark.parametrize("field", ["dockerfile", "test_script", "test_filename"])
@pytest.mark.parametrize("bad_value", [None, 123, ["x"]])
def test_required_trio_stays_strict(field, bad_value):
    """The required trio keeps its strict str validation."""
    payload = dict(_BASE)
    payload[field] = bad_value
    assert _run_generate(payload) is None
    assert _run_regenerate(payload) is None
