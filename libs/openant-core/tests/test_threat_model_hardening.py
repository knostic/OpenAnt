"""Hardening from the sol adversarial review.

The scanned repository authors this file, so it is attacker-controlled input.
Three defects, all of which pass schema validation:

  * Stage 1 was TOLD to check attacker profiles it was never shown.
  * The file was read with symlinks followed and no size cap.
  * A threat model was silently ignored when --no-context was passed.
"""

import os
from pathlib import Path

import pytest

from context.threat_model import ThreatModelValidationError, load_threat_model

VALID = """# TM

```json
{"schema":"openant-threat-model","schema_version":1,
 "classification":"orchestrator","purpose":"p",
 "components":[{"name":"c","paths":["p/"],"component_type":"t","exposure":"internal"}],
 "attacker_profiles":[{"id":"a1","position":"adjacent","description":"d",
   "capabilities":["cap"],"cannot":["lim"],"entry_via":["src"],"impact":"i"}],
 "input_sources":{"src":{"trust":"semi_trusted","description":"d"}},
 "vulnerability_criteria":["crit"],"not_a_vulnerability":[],
 "impact_statement":"impact"}
```
"""


def _threat_model_context():
    """Load the shared fixture without mutating ``sys.path``.

    This was ``sys.path.insert(0, "tests")`` followed by a bare import — twice.
    Two defects in one line. The path is RELATIVE, so the import only resolves
    when pytest is invoked from ``libs/openant-core``; run it from the repository
    root and these tests fail with ModuleNotFoundError while the rest pass, which
    reads as a product regression rather than a harness bug. And the entry is
    never removed, so ``tests/parsers/`` then shadows the real top-level
    ``parsers`` package for the remainder of the process — the suite stayed green
    only because alphabetical collection happened to run the victim first.

    importlib resolves the file directly, relative to THIS file, with no global
    side effect and no ordering dependency.
    """
    import importlib.util

    path = Path(__file__).resolve().parent / "test_threat_model_prompts.py"
    spec = importlib.util.spec_from_file_location("_tm_prompts_fixture", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.threat_model_context


class TestStage1SeesTheAttackerProfiles:
    """The system prompt instructs Stage 1 to check profiles; it must see them."""

    def test_profiles_are_rendered_into_the_stage1_context(self):
        threat_model_context = _threat_model_context()
        from prompts.vulnerability_analysis import format_app_context_for_prompt

        out = format_app_context_for_prompt(threat_model_context())
        assert "manifest_author" in out, (
            "Stage 1 is told 'only flag if a declared attacker profile can "
            "trigger it' but is never shown the profiles"
        )

    def test_capabilities_and_limits_reach_stage1(self):
        threat_model_context = _threat_model_context()
        from prompts.vulnerability_analysis import format_app_context_for_prompt

        out = format_app_context_for_prompt(threat_model_context())
        assert "craft arbitrary manifest YAML" in out
        assert "run commands on the orchestrator" in out


class TestSymlinkAndSizeGuards:
    def test_symlinked_threat_model_is_rejected(self, tmp_path):
        """A repo can ship a symlink pointing anywhere on the host."""
        repo = tmp_path / "repo"; repo.mkdir()
        secret = tmp_path / "outside.md"
        secret.write_text(VALID)
        (repo / "OPENANT.THREATMODEL.md").symlink_to(secret)

        with pytest.raises(ThreatModelValidationError, match="symlink"):
            load_threat_model(repo)

    def test_oversized_threat_model_is_rejected(self, tmp_path):
        repo = tmp_path / "repo"; repo.mkdir()
        (repo / "OPENANT.THREATMODEL.md").write_text("x" * (1024 * 1024 + 1))

        with pytest.raises(ThreatModelValidationError, match="too large"):
            load_threat_model(repo)

    def test_a_normal_file_still_loads(self, tmp_path):
        repo = tmp_path / "repo"; repo.mkdir()
        (repo / "OPENANT.THREATMODEL.md").write_text(VALID)
        assert load_threat_model(repo) is not None

    def test_non_regular_file_is_rejected(self, tmp_path):
        """A FIFO would block the scanner indefinitely."""
        repo = tmp_path / "repo"; repo.mkdir()
        fifo = repo / "OPENANT.THREATMODEL.md"
        try:
            os.mkfifo(fifo)
        except (AttributeError, OSError):
            pytest.skip("mkfifo unavailable on this platform")
        with pytest.raises(ThreatModelValidationError, match="regular file"):
            load_threat_model(repo)


class TestNoContextFlagDoesNotSilentlyIgnoreAThreatModel:
    def test_threat_model_presence_is_reported_even_when_context_is_disabled(
        self, tmp_path, monkeypatch, capsys
    ):
        """--no-context must not silently discard a committed threat model.

        Skipping it is a legitimate operator choice; doing so without saying
        so means the scan runs under a different security model than the repo
        declares, invisibly.
        """
        import core.scanner as scanner_mod
        import utilities.llm as llm_mod
        monkeypatch.setattr(llm_mod, "probe_registry_or_raise", lambda *a, **k: None)

        repo = tmp_path / "repo"; repo.mkdir()
        (repo / "app.py").write_text("def f():\n    pass\n")
        (repo / "OPENANT.THREATMODEL.md").write_text(VALID)

        def fake_parser_for(language):
            def _parse(repo_path, output_dir, processing_level, skip_tests=True,
                       name=None, library_mode=False):
                import json
                d = Path(output_dir); d.mkdir(parents=True, exist_ok=True)
                (d / "dataset.json").write_text(json.dumps(
                    {"units": [{"id": "app.py:f", "code": "x"}], "metadata": {}}))
                from core.schemas import ParseResult
                return ParseResult(dataset_path=str(d / "dataset.json"), units_count=1,
                                   language=language, processing_level=processing_level)
            return _parse
        import core.parser_adapter as pa
        monkeypatch.setattr(pa, "_parser_for", fake_parser_for)

        scanner_mod.scan_repository(
            repo_path=str(repo), output_dir=str(tmp_path / "out"), language="python",
            generate_context=False, generate_report=False, enhance=False,
            verify=False, processing_level="all",
        )
        err = capsys.readouterr().err
        assert "THREATMODEL" in err.upper() or "threat model" in err.lower(), (
            "a committed threat model was discarded with no mention"
        )
