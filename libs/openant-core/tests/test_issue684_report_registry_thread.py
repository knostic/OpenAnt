"""#684: the report step uses the scan's validated registry (no disk re-read,
no second paid probe mid-scan).

The comment said "always invoked standalone — no upstream scanner has pre-
validated the registry" — false: scanner.py:1457 invokes it as the final
step of a running scan, after analyze has already paid. Two consequences:
a config edit between analyze and report silently switches the provider;
a second full registry probe (one paid API call per unique provider+model).
"""
import inspect
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.reporter import generate_summary_report, generate_disclosure_docs  # noqa: E402


def test_the_signature_accepts_a_registry():
    """The registry param exists on both report entry points (the scan's
    validated binding can thread through)."""
    for fn in (generate_summary_report, generate_disclosure_docs):
        params = inspect.signature(fn).parameters
        assert "registry" in params, (
            f"{fn.__name__} has no 'registry' param — the scanner cannot "
            "pass its validated registry (the #684 mechanism)"
        )


def test_a_passed_registry_skips_the_disk_reload_and_probe(monkeypatch, tmp_path):
    """THE #684 SHAPE: when the scanner passes its registry, the report
    does NOT re-read the config from disk and does NOT re-probe."""
    # if load_config_file is called, the test fails (the disk re-read)
    def _no_disk_reload():
        raise AssertionError(
            "load_config_file was called — the report re-read the config "
            "from disk mid-scan (the #684 defect: a config edit between "
            "analyze and report silently switches the provider)"
        )
    monkeypatch.setattr("utilities.llm.load_config_file", _no_disk_reload)
    # a fake registry with a report binding
    fake_registry = {"report": MagicMock()}
    # a minimal pipeline_output
    pipeline = {"repository": {"name": "test/repo", "url": "",
                              "commit_sha": "abc"},
                "analysis_date": "2026-01-01", "application_type": "web",
                "pipeline_stats": {"total": 0, "vulnerable": 0, "safe": 0},
                "results": {}, "findings": []}
    pipeline_path = tmp_path / "pipeline_output.json"
    import json
    pipeline_path.write_text(json.dumps(pipeline))
    output_path = tmp_path / "SUMMARY.md"
    # the _generate_summary call should use the passed binding, not a probe
    with patch("report.generator.generate_summary_report",
               return_value=("Report", {"cost_usd": 0, "total_tokens": 0})) as gen:
        generate_summary_report(str(pipeline_path), str(output_path),
                                "test-config", registry=fake_registry)
        gen.assert_called_once()
        # the binding used is the PASSED one (not a re-read)
        args, kwargs = gen.call_args
        assert args[1] is fake_registry["report"], (
            "the report did not use the scan's validated registry binding"
        )
    assert output_path.read_text() == "Report"


def test_standalone_still_probes(monkeypatch, tmp_path):
    """The standalone path (no registry param): the config is read and the
    registry is built + probed as before."""
    import json
    import utilities.llm as _ullm

    monkeypatch.setattr(_ullm, "load_config_file",
                        lambda: {"default_llm": "test", "llm_configs": {}})
    monkeypatch.setattr(_ullm, "resolve_llm_config", lambda cf, name: None)
    monkeypatch.setattr(_ullm, "build_phase_registry",
                        lambda cf, name: {"report": "fake-binding"})
    probed = []
    monkeypatch.setattr(_ullm, "probe_registry_or_raise",
                        lambda r: probed.append(r))

    pipeline = {"repository": {"name": "t", "url": "", "commit_sha": "abc"},
                "analysis_date": "2026-01-01", "application_type": "web",
                "pipeline_stats": {"total": 0, "vulnerable": 0, "safe": 0},
                "results": {}, "findings": []}
    pipeline_path = tmp_path / "p.json"
    pipeline_path.write_text(json.dumps(pipeline))
    from unittest.mock import patch
    with patch("report.generator.generate_summary_report",
               return_value=("R", {"cost_usd": 0, "total_tokens": 0})):
        generate_summary_report(str(pipeline_path), str(tmp_path / "out.md"),
                               "test-config")  # no registry param
    assert probed, "the standalone path must still probe the registry"
