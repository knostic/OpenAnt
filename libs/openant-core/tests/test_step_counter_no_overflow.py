"""#219: the step counter must never overflow (e.g. the report step printed as
`[8/7]`).

`_count_steps` (the denominator) counts only steps that RUN, but `_step_label`
incremented the numerator for every emitted line — including the "Skipping ..."
notices for disabled optional steps — so a run with several steps skipped pushed
the numerator past the total. Skips are notices, not performed steps, and must
not consume a step number.

Drives `scan_repository` fully offline (parse/analyze/build/report stubbed,
credential probe neutered via the reused pr69 fixtures) with every optional step
disabled but report on — the exact shape that produced `[8/7]` — and asserts no
`[n/N]` label has n > N. Fully offline ($0).
"""

import re
from pathlib import Path

import core.scanner as scanner_mod
from test_pr69_report_llmconfig_forwarding import _install_minimal_pipeline

# brings the autouse _offline_registry fixture (probe neutered, config resolves)
pytest_plugins = ("test_pr69_report_llmconfig_forwarding",)


def test_step_counter_never_overflows_when_optional_steps_skipped(
    monkeypatch, tmp_path, capsys
):
    _install_minimal_pipeline(monkeypatch)
    import core.reporter as reporter

    monkeypatch.setattr(
        reporter, "generate_summary_report",
        lambda results_path, output_path, llm_config_name=None: Path(
            output_path
        ).write_text("# summary"),
    )
    monkeypatch.setattr(
        reporter, "generate_disclosure_docs",
        lambda results_path, output_dir, llm_config_name=None: Path(
            output_dir
        ).mkdir(parents=True, exist_ok=True),
    )

    scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        generate_context=False,   # -> "Skipping application context"
        enhance=False,            # -> "Skipping enhancement"
        verify=False,             # -> "Skipping verification"
        generate_report=True,
        dynamic_test=False,       # -> "Skipping dynamic test"
        llm_config_name="x",
    )

    err = capsys.readouterr().err
    labels = re.findall(r"\[(\d+)/(\d+)\]", err)
    assert labels, f"no [n/N] step labels captured in stderr:\n{err}"
    overflow = [(n, t) for n, t in labels if int(n) > int(t)]
    assert not overflow, f"step counter overflowed: {overflow} in:\n{err}"
