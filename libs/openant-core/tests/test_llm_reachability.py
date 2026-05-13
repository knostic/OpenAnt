"""Tests for the LLM reachability review stage (issue #17).

The stage is opt-in and advisory: signals may PROMOTE a unit's
reachability but never demote one that the structural analysis kept.
These tests pin that behavior down with a fully mocked LLM client so they
run without network access or an API key.
"""

from __future__ import annotations

import json
from typing import List

import pytest

from core.llm_reachability import (
    ReachabilitySignal,
    analyze_reachability,
    apply_signals,
    build_prompt,
    parse_response,
    signals_to_json,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


class FakeClient:
    """Minimal stand-in for AnthropicClient.

    Records calls and replays a fixed sequence of canned responses.
    """

    def __init__(self, responses: List[str]):
        self._responses = list(responses)
        self.calls: List[dict] = []

    def analyze_sync(self, prompt: str, max_tokens: int = 4096, model: str = ""):
        self.calls.append(
            {"prompt": prompt, "max_tokens": max_tokens, "model": model}
        )
        if not self._responses:
            return '{"signals": []}'
        return self._responses.pop(0)


def _make_unit(unit_id: str, code: str = "pass", **kw) -> dict:
    unit = {
        "id": unit_id,
        "unit_type": kw.pop("unit_type", "function"),
        "code": {"primary_code": code},
    }
    unit.update(kw)
    return unit


# ---------------------------------------------------------------------------
# parse_response
# ---------------------------------------------------------------------------


class TestParseResponse:
    def test_parses_well_formed_signal(self):
        text = json.dumps(
            {
                "signals": [
                    {
                        "unit_id": "app.py:handler",
                        "kind": "entry_point",
                        "confidence": "high",
                        "reason": "Express handler",
                    }
                ]
            }
        )
        sigs = parse_response(text, valid_unit_ids={"app.py:handler"})
        assert len(sigs) == 1
        assert sigs[0].unit_id == "app.py:handler"
        assert sigs[0].kind == "entry_point"
        assert sigs[0].confidence == "high"
        assert "Express" in sigs[0].reason

    def test_strips_markdown_fences(self):
        text = "```json\n" + json.dumps(
            {"signals": [
                {"unit_id": "x.py:f", "kind": "external_input",
                 "confidence": "medium", "reason": "reads argv"}]}
        ) + "\n```"
        sigs = parse_response(text, valid_unit_ids={"x.py:f"})
        assert len(sigs) == 1
        assert sigs[0].kind == "external_input"

    def test_falls_back_to_first_object(self):
        text = "Sure! Here you go:\n" + json.dumps(
            {"signals": [
                {"unit_id": "a.py:g", "kind": "cross_process",
                 "confidence": "low", "reason": "queue"}]}
        ) + "\nEnd."
        sigs = parse_response(text, valid_unit_ids={"a.py:g"})
        assert len(sigs) == 1

    def test_malformed_json_returns_empty(self):
        errors: List[str] = []
        sigs = parse_response(
            "not json at all",
            valid_unit_ids={"x"},
            on_error=errors.append,
        )
        assert sigs == []
        assert any("malformed" in e for e in errors)

    def test_invalid_kind_skipped(self):
        text = json.dumps(
            {"signals": [
                {"unit_id": "x.py:f", "kind": "garbage",
                 "confidence": "high", "reason": "n/a"}]}
        )
        errors: List[str] = []
        sigs = parse_response(
            text, valid_unit_ids={"x.py:f"}, on_error=errors.append
        )
        assert sigs == []
        assert any("invalid kind" in e for e in errors)

    def test_unknown_unit_id_skipped(self):
        text = json.dumps(
            {"signals": [
                {"unit_id": "ghost.py:f", "kind": "entry_point",
                 "confidence": "high", "reason": "n/a"}]}
        )
        errors: List[str] = []
        sigs = parse_response(
            text, valid_unit_ids={"real.py:f"}, on_error=errors.append
        )
        assert sigs == []

    def test_signals_not_a_list_returns_empty(self):
        text = json.dumps({"signals": "nope"})
        errors: List[str] = []
        sigs = parse_response(text, on_error=errors.append)
        assert sigs == []


# ---------------------------------------------------------------------------
# build_prompt / app_context threading
# ---------------------------------------------------------------------------


class TestBuildPrompt:
    def test_includes_unit_ids_and_code(self):
        units = [_make_unit("app.py:handler", code="def handler(): ...")]
        prompt = build_prompt(units)
        assert "app.py:handler" in prompt
        assert "def handler()" in prompt

    def test_no_app_context_marker(self):
        prompt = build_prompt([_make_unit("a:f")])
        assert "(none provided)" in prompt

    def test_includes_app_context_when_provided(self):
        ctx = {"application_type": "web_app", "framework": "Express"}
        prompt = build_prompt([_make_unit("a:f")], app_context=ctx)
        assert "web_app" in prompt
        assert "Express" in prompt

    def test_truncates_overly_long_code(self):
        big = "x = 1\n" * 5000
        prompt = build_prompt([_make_unit("a:f", code=big)])
        assert "[truncated]" in prompt


# ---------------------------------------------------------------------------
# analyze_reachability — full call with a mocked client
# ---------------------------------------------------------------------------


class TestAnalyzeReachability:
    def test_parses_signals_from_mocked_llm(self):
        dataset = {
            "units": [
                _make_unit("app.py:handler"),
                _make_unit("util.py:helper"),
            ]
        }
        canned = json.dumps(
            {
                "signals": [
                    {
                        "unit_id": "app.py:handler",
                        "kind": "entry_point",
                        "confidence": "high",
                        "reason": "Express handler",
                    },
                    {
                        "unit_id": "util.py:helper",
                        "kind": "external_input",
                        "confidence": "medium",
                        "reason": "reads file",
                    },
                ]
            }
        )
        client = FakeClient([canned])
        signals = analyze_reachability(dataset, client=client)
        assert len(signals) == 2
        assert {s.kind for s in signals} == {"entry_point", "external_input"}
        assert len(client.calls) == 1

    def test_app_context_threaded_into_prompt(self):
        dataset = {"units": [_make_unit("a:f")]}
        client = FakeClient(['{"signals": []}'])
        ctx = {"application_type": "web_app", "framework": "Flask"}
        analyze_reachability(dataset, app_context=ctx, client=client)
        assert "Flask" in client.calls[0]["prompt"]
        assert "web_app" in client.calls[0]["prompt"]

    def test_malformed_response_handled_gracefully(self):
        dataset = {"units": [_make_unit("a:f")]}
        errors: List[str] = []
        client = FakeClient(["this is not JSON"])
        sigs = analyze_reachability(
            dataset, client=client, on_error=errors.append
        )
        assert sigs == []
        assert errors  # at least one error logged

    def test_empty_dataset_returns_empty(self):
        client = FakeClient([])
        sigs = analyze_reachability({"units": []}, client=client)
        assert sigs == []
        assert client.calls == []  # no LLM calls when nothing to review

    def test_batch_size_chunks_units(self):
        dataset = {"units": [_make_unit(f"a:{i}") for i in range(7)]}
        client = FakeClient(['{"signals": []}'] * 5)
        analyze_reachability(dataset, client=client, batch_size=3)
        # 7 units / 3 per batch = 3 calls
        assert len(client.calls) == 3

    def test_non_positive_batch_size_uses_single_batch(self):
        """``batch_size <= 0`` historically tripped a NameError. Guard the
        contract: non-positive size collapses to a single batch covering all
        units (and never raises)."""
        dataset = {"units": [_make_unit(f"a:{i}") for i in range(4)]}
        client = FakeClient(['{"signals": []}'])
        analyze_reachability(dataset, client=client, batch_size=0)
        assert len(client.calls) == 1

    def test_client_exception_does_not_crash(self):
        class Boom:
            def analyze_sync(self, *a, **kw):
                raise RuntimeError("api boom")

        errors: List[str] = []
        sigs = analyze_reachability(
            {"units": [_make_unit("a:f")]},
            client=Boom(),
            on_error=errors.append,
        )
        assert sigs == []
        assert any("api boom" in e for e in errors)


# ---------------------------------------------------------------------------
# apply_signals — promote-only semantics
# ---------------------------------------------------------------------------


class TestApplySignals:
    def test_high_confidence_entry_point_promotes(self):
        dataset = {"units": [_make_unit("a:f", is_entry_point=False)]}
        sigs = [
            ReachabilitySignal("a:f", "entry_point", "high", "framework hook")
        ]
        summary = apply_signals(dataset, sigs)
        assert dataset["units"][0]["is_entry_point"] is True
        assert summary["entry_points_promoted"] == 1
        assert summary["signals_applied"] == 1
        assert summary["units_touched"] == 1

    def test_medium_confidence_does_not_promote(self):
        dataset = {"units": [_make_unit("a:f", is_entry_point=False)]}
        sigs = [
            ReachabilitySignal("a:f", "entry_point", "medium", "maybe")
        ]
        summary = apply_signals(dataset, sigs)
        assert dataset["units"][0]["is_entry_point"] is False
        assert summary["entry_points_promoted"] == 0
        # but the signal is still attached for the reviewer
        assert summary["signals_applied"] == 1

    def test_external_input_does_not_set_entry_point(self):
        dataset = {"units": [_make_unit("a:f", is_entry_point=False)]}
        sigs = [
            ReachabilitySignal("a:f", "external_input", "high", "argv")
        ]
        apply_signals(dataset, sigs)
        # external_input never sets is_entry_point regardless of confidence
        assert dataset["units"][0]["is_entry_point"] is False

    def test_does_not_demote_existing_entry_point(self):
        """Crucial promote-only invariant: a unit the structural pass
        already marked as an entry point must never be unmarked, even if
        the LLM emits no signal (or a low-confidence one) for it."""
        dataset = {"units": [_make_unit("a:f", is_entry_point=True)]}
        # Empty signal list — apply_signals must not flip the flag.
        apply_signals(dataset, [])
        assert dataset["units"][0]["is_entry_point"] is True

        # Even a stray "low" entry_point signal must not flip it back.
        sigs = [ReachabilitySignal("a:f", "entry_point", "low", "weak")]
        apply_signals(dataset, sigs)
        assert dataset["units"][0]["is_entry_point"] is True

    def test_signal_attached_to_unit(self):
        dataset = {"units": [_make_unit("a:f")]}
        sigs = [
            ReachabilitySignal("a:f", "external_input", "medium", "reads stdin")
        ]
        apply_signals(dataset, sigs)
        unit = dataset["units"][0]
        assert "llm_reachability_signals" in unit
        assert len(unit["llm_reachability_signals"]) == 1
        attached = unit["llm_reachability_signals"][0]
        assert attached["kind"] == "external_input"
        assert attached["reason"] == "reads stdin"

    def test_multiple_signals_accumulate_on_same_unit(self):
        dataset = {"units": [_make_unit("a:f")]}
        sigs = [
            ReachabilitySignal("a:f", "external_input", "medium", "argv"),
            ReachabilitySignal("a:f", "cross_process", "low", "queue"),
        ]
        apply_signals(dataset, sigs)
        attached = dataset["units"][0]["llm_reachability_signals"]
        assert len(attached) == 2

    def test_unknown_unit_id_skipped(self):
        dataset = {"units": [_make_unit("a:f")]}
        sigs = [ReachabilitySignal("ghost:x", "entry_point", "high", "n/a")]
        summary = apply_signals(dataset, sigs)
        assert summary["signals_applied"] == 0
        assert summary["entry_points_promoted"] == 0


class TestSerialization:
    def test_signals_to_json_roundtrip(self):
        sigs = [
            ReachabilitySignal("a:f", "entry_point", "high", "r1"),
            ReachabilitySignal("b:g", "external_input", "low", "r2"),
        ]
        out = signals_to_json(sigs)
        assert isinstance(out, list)
        assert all(isinstance(item, dict) for item in out)
        # Round-trips through JSON cleanly.
        json.loads(json.dumps(out))


# ---------------------------------------------------------------------------
# CLI flag plumbing — mock scan_repository to confirm wiring without API
# ---------------------------------------------------------------------------


class TestCliPlumbing:
    """Confirms that the --llm-reachability flag exists in scan --help and
    that, by default (no flag), the LLM reachability path is not invoked.

    These tests exercise the Python CLI directly (no Go binary required), so
    they always run in the basic pytest suite.
    """

    def test_flag_appears_in_scan_help(self, capsys):
        from openant.cli import main

        with pytest.raises(SystemExit):
            import sys
            old = sys.argv
            try:
                sys.argv = ["openant", "scan", "--help"]
                main()
            finally:
                sys.argv = old
        out = capsys.readouterr().out + capsys.readouterr().err
        assert "--llm-reachability" in out

    def test_default_does_not_invoke_llm_reachability(self, monkeypatch, tmp_path):
        """When --llm-reachability is NOT passed, ``analyze_reachability`` in
        the scanner module must not be called.

        We achieve this by monkey-patching ``scan_repository`` to a stub
        that records its kwargs, then driving ``cmd_scan`` through it.
        """
        captured = {}

        from openant import cli as cli_mod

        def fake_scan(**kwargs):
            captured.update(kwargs)
            from core.schemas import ScanResult
            r = ScanResult(output_dir=str(tmp_path))
            return r

        monkeypatch.setattr(
            "core.scanner.scan_repository", fake_scan, raising=True
        )

        # Drive cmd_scan via argparse
        import argparse
        ns = argparse.Namespace(
            repo=str(tmp_path),
            output=str(tmp_path / "out"),
            language="auto",
            level="reachable",
            verify=False,
            no_context=True,
            no_enhance=True,
            enhance_mode="agentic",
            no_report=True,
            dynamic_test=False,
            no_skip_tests=False,
            limit=None,
            model="opus",
            workers=1,
            repo_name=None,
            repo_url=None,
            commit_sha=None,
            backoff=30,
            diff_manifest=None,
            llm_reachability=False,
        )
        rc = cli_mod.cmd_scan(ns)
        # rc 0 or 1 acceptable; we only care about plumbing.
        assert rc in (0, 1)
        assert captured.get("llm_reachability") is False

    def test_flag_passes_through_when_set(self, monkeypatch, tmp_path):
        captured = {}
        from openant import cli as cli_mod

        def fake_scan(**kwargs):
            captured.update(kwargs)
            from core.schemas import ScanResult
            return ScanResult(output_dir=str(tmp_path))

        monkeypatch.setattr(
            "core.scanner.scan_repository", fake_scan, raising=True
        )

        import argparse
        ns = argparse.Namespace(
            repo=str(tmp_path),
            output=str(tmp_path / "out"),
            language="auto",
            level="reachable",
            verify=False,
            no_context=True,
            no_enhance=True,
            enhance_mode="agentic",
            no_report=True,
            dynamic_test=False,
            no_skip_tests=False,
            limit=None,
            model="opus",
            workers=1,
            repo_name=None,
            repo_url=None,
            commit_sha=None,
            backoff=30,
            diff_manifest=None,
            llm_reachability=True,
        )
        cli_mod.cmd_scan(ns)
        assert captured.get("llm_reachability") is True
