"""Regression test for cli-analyze-verify-chain-drops-llm-config.

``cmd_analyze --verify`` chains Stage 1 detection into Stage 2 verification.
The chained ``run_verification`` call must propagate the user's
``--llm-config`` so the verify stage runs with the SAME configured model as
the analyze stage — not the built-in default. This pins that contract.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

from openant.cli import cmd_analyze


def _make_args() -> argparse.Namespace:
    return argparse.Namespace(
        dataset="dataset.json",
        output="/tmp/out_dir_does_not_matter",
        exploitable_all=False,
        exploitable_only=False,
        analyzer_output="analyzer_output.json",
        app_context=None,
        repo_path=None,
        limit=None,
        llm_config="my-custom-config",
        workers=8,
        checkpoint=None,
        backoff=30,
        verify=True,
    )


@contextmanager
def _fake_step_context(*_args, **_kwargs):
    yield MagicMock()


def test_verify_chain_propagates_llm_config():
    args = _make_args()

    analyze_result = MagicMock()
    analyze_result.results_path = "/tmp/out_dir_does_not_matter/results.json"

    verify_result = MagicMock()
    verify_result.confirmed_vulnerabilities = 0
    verify_result.to_dict.return_value = {}

    with patch("core.analyzer.run_analysis", return_value=analyze_result), \
         patch("core.verifier.run_verification", return_value=verify_result) as mock_verify, \
         patch("core.step_report.step_context", _fake_step_context), \
         patch("openant.cli._output_json"):
        cmd_analyze(args)

    assert mock_verify.called, "run_verification was never invoked by --verify chain"
    _, kwargs = mock_verify.call_args
    assert kwargs.get("llm_config_name") == "my-custom-config", (
        "verify chain dropped --llm-config: run_verification was called with "
        f"llm_config_name={kwargs.get('llm_config_name')!r} instead of the "
        "configured 'my-custom-config' (verify would run on the default model)"
    )
