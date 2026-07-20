"""scan_repository must honour a multi-language selection.

Offline: the billed credential probe is neutralised and every LLM stage is
disabled, so these assert orchestration only — which parser calls happen, how
many times, and what the merged result carries.
"""

import json
from pathlib import Path

import pytest

import core.scanner as scanner_mod
from core.scanner import scan_repository


@pytest.fixture(autouse=True)
def _stub_registry_probe(monkeypatch):
    """Neutralise the real 1-token Anthropic credential probe (see test_scanner)."""
    import utilities.llm as llm_mod

    monkeypatch.setattr(
        llm_mod, "probe_registry_or_raise", lambda *a, **k: None, raising=True
    )


@pytest.fixture
def repo(tmp_path):
    src = tmp_path / "repo"
    (src / "web").mkdir(parents=True)
    (src / "app.py").write_text("def handler():\n    pass\n")
    (src / "db.py").write_text("def query():\n    pass\n")
    (src / "web" / "app.js").write_text("function route() {}\n")
    return src


@pytest.fixture
def fake_parsers(monkeypatch):
    """Record which languages were parsed; write a plausible dataset per language."""
    calls = []

    def fake_parser_for(language):
        def _parse(repo_path, output_dir, processing_level, skip_tests=True,
                   name=None, library_mode=False):
            calls.append(language)
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            units = [{"id": f"{language}_f{i}", "code": "x"} for i in range(2)]
            (Path(output_dir) / "dataset.json").write_text(
                json.dumps({"name": "n", "repository": "r", "units": units,
                            "statistics": {}, "metadata": {}})
            )
            (Path(output_dir) / "analyzer_output.json").write_text(
                json.dumps({"functions": {u["id"]: {} for u in units}})
            )
            from core.schemas import ParseResult
            return ParseResult(
                dataset_path=str(Path(output_dir) / "dataset.json"),
                analyzer_output_path=str(Path(output_dir) / "analyzer_output.json"),
                units_count=len(units),
                language=language,
                processing_level=processing_level,
            )
        return _parse

    import core.parser_adapter as pa
    monkeypatch.setattr(pa, "_parser_for", fake_parser_for)
    return calls


def run(repo, out, **kw):
    return scan_repository(
        repo_path=str(repo),
        output_dir=str(out),
        generate_context=False,
        generate_report=False,
        enhance=False,
        verify=False,
        processing_level="all",
        **kw,
    )


class TestMultiLanguageScan:
    def test_every_selected_language_is_parsed(self, repo, tmp_path, fake_parsers):
        run(repo, tmp_path / "out", languages=["python", "javascript"])
        assert sorted(fake_parsers) == ["javascript", "python"]

    def test_merged_dataset_contains_all_languages(self, repo, tmp_path, fake_parsers):
        out = tmp_path / "out"
        run(repo, out, languages=["python", "javascript"])

        merged = json.loads((out / "dataset.json").read_text())
        assert len(merged["units"]) == 4
        assert {u["language"] for u in merged["units"]} == {"python", "javascript"}

    def test_per_language_directories_are_written(self, repo, tmp_path, fake_parsers):
        out = tmp_path / "out"
        run(repo, out, languages=["python", "javascript"])
        assert (out / "python" / "dataset.json").is_file()
        assert (out / "javascript" / "dataset.json").is_file()

    def test_call_graph_index_is_written(self, repo, tmp_path, fake_parsers):
        out = tmp_path / "out"
        run(repo, out, languages=["python", "javascript"])
        assert (out / "call_graphs.json").is_file()

    def test_result_carries_multilanguage_fields(self, repo, tmp_path, fake_parsers):
        result = run(repo, tmp_path / "out", languages=["python", "javascript"])
        assert result.languages == ["python", "javascript"]
        assert result.language_stats == {"python": 2, "javascript": 2}
        assert result.units_count == 4

    def test_scalar_language_stays_the_primary(self, repo, tmp_path, fake_parsers):
        result = run(repo, tmp_path / "out", languages=["python", "javascript"])
        assert result.language == "python", "scalar field must remain the primary"

    def test_app_context_is_generated_once_not_per_language(self, repo, tmp_path,
                                                            fake_parsers, monkeypatch):
        """The merged-dataset design runs post-parse stages once by construction.

        Pinned so a future refactor that reintroduces a per-language loop
        cannot silently multiply per-repo LLM work.
        """
        calls = []
        monkeypatch.setattr(
            scanner_mod, "generate_application_context",
            lambda *a, **k: (calls.append(1), None)[1],
            raising=False,
        )
        scan_repository(
            repo_path=str(repo), output_dir=str(tmp_path / "out"),
            languages=["python", "javascript"],
            generate_context=True, generate_report=False,
            enhance=False, verify=False, processing_level="all",
        )
        assert len(calls) <= 1, f"app-context generated {len(calls)}x for one repo"


class TestSingleLanguageUnchanged:
    def test_no_languages_argument_uses_the_legacy_path(self, repo, tmp_path, fake_parsers):
        """Back-compat: without `languages`, behaviour is byte-identical."""
        out = tmp_path / "out"
        run(repo, out, language="python")

        assert fake_parsers == ["python"]
        assert (out / "dataset.json").is_file()
        assert not (out / "python").exists(), "legacy path must not create subdirs"

    def test_single_element_languages_list_uses_the_legacy_path(self, repo, tmp_path,
                                                               fake_parsers):
        out = tmp_path / "out"
        run(repo, out, languages=["python"])
        assert fake_parsers == ["python"]
        assert not (out / "python").exists()


class TestDegradedRuns:
    def test_one_failing_language_still_produces_a_merged_dataset(self, repo, tmp_path,
                                                                  monkeypatch):
        def fake_parser_for(language):
            def _parse(repo_path, output_dir, processing_level, skip_tests=True,
                       name=None, library_mode=False):
                if language == "javascript":
                    raise RuntimeError("node toolchain missing")
                Path(output_dir).mkdir(parents=True, exist_ok=True)
                (Path(output_dir) / "dataset.json").write_text(
                    json.dumps({"units": [{"id": "p1", "code": "x"}], "metadata": {}})
                )
                from core.schemas import ParseResult
                return ParseResult(
                    dataset_path=str(Path(output_dir) / "dataset.json"),
                    units_count=1, language=language, processing_level=processing_level,
                )
            return _parse

        import core.parser_adapter as pa
        monkeypatch.setattr(pa, "_parser_for", fake_parser_for)

        out = tmp_path / "out"
        result = run(repo, out, languages=["python", "javascript"])

        assert result.units_count == 1
        assert result.degraded, "a failed language must mark the run degraded"
        assert any(e["language"] == "javascript" for e in result.parse_errors)
