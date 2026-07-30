"""A repo-supplied OPENANT.THREATMODEL.md must actually be used.

Before this, `load_threat_model` had zero production callers: an operator could
write the file, get a completely successful-looking scan, and never learn it
was ignored. The module's own docstring names that silent failure as the thing
it exists to prevent.

Two properties matter, and they pull in opposite directions:
  * ABSENT  -> fall through to the built-in generator (no behaviour change).
  * PRESENT BUT MALFORMED -> abort LOUDLY. It must NOT be swallowed by the
    step's warn-and-continue handler, because degrading to a default web_app
    context silently applies the wrong security model to the whole scan.
"""

import json
from pathlib import Path

import pytest

import core.scanner as scanner_mod

VALID_TM = """# Threat Model: fixture

## Machine-Readable Threat Model

```json
{
  "schema": "openant-threat-model",
  "schema_version": 1,
  "classification": "deployment orchestrator",
  "purpose": "Applies manifests to hosts.",
  "components": [
    {"name": "parser", "paths": ["pkg/"], "component_type": "data parser",
     "exposure": "internal"}
  ],
  "attacker_profiles": [
    {"id": "manifest_author", "position": "adjacent",
     "description": "Dev with commit access, no shell.",
     "capabilities": ["craft manifests"], "cannot": ["run commands"],
     "entry_via": ["manifests"], "impact": "RCE"}
  ],
  "input_sources": {
    "manifests": {"trust": "semi_trusted", "description": "YAML from git"}
  },
  "vulnerability_criteria": ["Manifest escaping the sandbox"],
  "not_a_vulnerability": [],
  "impact_statement": "Deploy-pipeline RCE."
}
```
"""


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    import utilities.llm as llm_mod
    monkeypatch.setattr(llm_mod, "probe_registry_or_raise", lambda *a, **k: None)


@pytest.fixture
def repo(tmp_path):
    src = tmp_path / "repo"
    src.mkdir()
    (src / "app.py").write_text("def handler():\n    pass\n")
    return src


@pytest.fixture
def stub_parse(monkeypatch):
    def fake_parser_for(language):
        def _parse(repo_path, output_dir, processing_level, skip_tests=True,
                   name=None, library_mode=False):
            d = Path(output_dir); d.mkdir(parents=True, exist_ok=True)
            (d / "dataset.json").write_text(json.dumps(
                {"units": [{"id": "app.py:handler", "code": "x"}], "metadata": {}}))
            from core.schemas import ParseResult
            return ParseResult(dataset_path=str(d / "dataset.json"), units_count=1,
                               language=language, processing_level=processing_level)
        return _parse
    import core.parser_adapter as pa
    monkeypatch.setattr(pa, "_parser_for", fake_parser_for)


def run(repo, out, **kw):
    return scanner_mod.scan_repository(
        repo_path=str(repo), output_dir=str(out), language="python",
        generate_report=False, enhance=False, verify=False,
        processing_level="all", **kw,
    )


class TestThreatModelIsUsedWhenPresent:
    def test_a_valid_threat_model_supplies_the_context(self, repo, tmp_path, stub_parse):
        (repo / "OPENANT.THREATMODEL.md").write_text(VALID_TM)
        result = run(repo, tmp_path / "out", generate_context=True)

        assert result.app_context_path, "no context was produced"
        ctx = json.loads(Path(result.app_context_path).read_text())
        assert ctx.get("threat_model_version") == 1, (
            "the repo's threat model was ignored — this is the silent failure "
            "the feature exists to prevent"
        )
        assert ctx["application_type"].startswith("custom:")

    def test_context_source_records_which_path_supplied_it(self, repo, tmp_path,
                                                           stub_parse):
        (repo / "OPENANT.THREATMODEL.md").write_text(VALID_TM)
        result = run(repo, tmp_path / "out", generate_context=True)
        assert result.context_source == "threat_model"

    def test_no_llm_call_is_made_when_a_threat_model_exists(self, repo, tmp_path,
                                                            stub_parse, monkeypatch):
        """A hand-written model must short-circuit generation, not supplement it."""
        calls = []
        monkeypatch.setattr(scanner_mod, "generate_application_context",
                            lambda *a, **k: calls.append(1))
        (repo / "OPENANT.THREATMODEL.md").write_text(VALID_TM)
        run(repo, tmp_path / "out", generate_context=True)
        assert not calls, "generator ran despite a repo-supplied threat model"


class TestMalformedThreatModelFailsLoudly:
    def test_malformed_file_aborts_the_scan(self, repo, tmp_path, stub_parse):
        (repo / "OPENANT.THREATMODEL.md").write_text(
            "# Threat Model\n\n```json\n{\"schema\": \"openant-threat-model\"}\n```\n"
        )
        with pytest.raises(Exception) as exc:
            run(repo, tmp_path / "out", generate_context=True)
        assert "threat" in str(exc.value).lower() or "schema" in str(exc.value).lower()

    def test_malformed_file_is_not_swallowed_into_a_default_context(self, repo,
                                                                    tmp_path, stub_parse):
        """The catch-all must not turn this into a silent web_app scan."""
        (repo / "OPENANT.THREATMODEL.md").write_text("# Threat Model\n\nno json here\n")
        with pytest.raises(Exception):
            run(repo, tmp_path / "out", generate_context=True)


class TestAbsentThreatModelIsUnchanged:
    def test_falls_through_to_the_builtin_generator(self, repo, tmp_path, stub_parse,
                                                    monkeypatch):
        calls = []

        def fake_gen(*a, **k):
            calls.append(1)
            from context.application_context import ApplicationContext
            return ApplicationContext(application_type="cli_tool", purpose="p")

        monkeypatch.setattr(scanner_mod, "generate_application_context", fake_gen)
        result = run(repo, tmp_path / "out", generate_context=True)
        assert calls == [1], "the built-in generator must still run when no file exists"
        assert result.context_source == "generated"

    def test_no_context_flag_still_skips_everything(self, repo, tmp_path, stub_parse):
        (repo / "OPENANT.THREATMODEL.md").write_text(VALID_TM)
        result = run(repo, tmp_path / "out", generate_context=False)
        assert result.app_context_path is None
        assert result.context_source == "none"
