"""PR #69 round-3 review fixes (CLI surface).

* M4 (Python side): the ``report-data`` subparser must register
  ``--llm-config`` so ``cmd_report_data``'s ``getattr(args, "llm_config",
  None)`` actually receives the flag the Go CLI forwards. Without the
  registration the flag was silently dropped and HTML-report remediation
  always fell back to the default llm-config.

The parser is built inline inside ``cli.main()`` and dispatches via
``args.func(args)``. We exercise the real parser by monkeypatching
``sys.argv`` and stubbing the dispatched ``cmd_report_data`` to capture
the parsed namespace — that proves the flag both PARSES and REACHES the
handler as ``args.llm_config``.
"""

from __future__ import annotations

import openant.cli as cli


def _run_cli_capturing_args(monkeypatch, argv):
    """Drive cli.main() with argv, capturing the args handed to cmd_report_data.

    Returns the captured argparse.Namespace. The real handler is replaced
    so no IO / network happens; the value of ``func`` is resolved by the
    parser via ``set_defaults(func=cmd_report_data)``, so this also proves
    report-data dispatches to the right handler.
    """
    captured = {}

    def _fake_report_data(args):
        captured["args"] = args
        return 0

    monkeypatch.setattr(cli, "cmd_report_data", _fake_report_data)
    monkeypatch.setattr("sys.argv", ["openant", *argv])
    rc = cli.main()
    assert rc == 0
    return captured["args"]


def test_report_data_parses_llm_config(monkeypatch):
    args = _run_cli_capturing_args(
        monkeypatch,
        [
            "report-data",
            "results_verified.json",
            "--dataset",
            "dataset.json",
            "--llm-config",
            "my-team-config",
        ],
    )
    # The flag parses into the namespace under llm_config (what
    # cmd_report_data reads via getattr(args, "llm_config", None)).
    assert getattr(args, "llm_config", None) == "my-team-config"


def test_report_data_llm_config_defaults_to_none(monkeypatch):
    # Omitting the flag must leave llm_config present and None (so the
    # downstream resolve_llm_config falls back to default_llm), not absent.
    args = _run_cli_capturing_args(
        monkeypatch,
        ["report-data", "results_verified.json", "--dataset", "dataset.json"],
    )
    assert getattr(args, "llm_config", "MISSING") is None
