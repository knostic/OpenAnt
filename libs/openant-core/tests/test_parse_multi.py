"""Parse fan-out: per-language directories and partial-success semantics.

The load-bearing test here is
``TestCollisionProof::test_each_language_gets_its_own_artifacts``. Every parser
writes the same flat filenames into whatever output_dir it is handed, so
running two languages into one directory leaves exactly one survivor. Two
distinct, populated per-language directories is the proof that hazard is
closed.

Most tests use stub parsers so the suite stays fast and needs no Node/Go
toolchain. The end-to-end test against the real Python and JavaScript parsers
is marked and kept separate.
"""

import json
import os
import subprocess

import pytest

from core import parser_adapter
from core.parser_adapter import parse_repository_multi
from core.schemas import ParseResult

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_multilang_repo")


def _schema_errors(dataset_path) -> list:
    """Run the repo's own dataset schema validator and return its error list.

    Reuses ``validate_dataset_schema.validate_dataset`` — the same checker the
    plan's gate command invokes — rather than reimplementing its rules, so the
    test cannot drift from the tool.
    """
    from validate_dataset_schema import validate_dataset

    errors, _units, _deps = validate_dataset(str(dataset_path))
    return errors

# The full artifact set each parser writes into its output_dir. These names are
# identical across languages, which is precisely the collision hazard.
PARSER_ARTIFACTS = ["dataset.json", "analyzer_output.json"]


def make_stub_parser(units: int = 3, artifacts=PARSER_ARTIFACTS, fail_with=None):
    """Build a fake parser that writes the standard artifacts into output_dir."""

    def _stub(repo_path, output_dir, processing_level, skip_tests=True,
              name=None, library_mode=False):
        if fail_with is not None:
            raise fail_with
        os.makedirs(output_dir, exist_ok=True)
        for artifact in artifacts:
            with open(os.path.join(output_dir, artifact), "w", encoding="utf-8") as f:
                json.dump({"units": [{"id": f"{output_dir}:{i}"} for i in range(units)]}, f)
        return ParseResult(
            dataset_path=os.path.join(output_dir, "dataset.json"),
            analyzer_output_path=os.path.join(output_dir, "analyzer_output.json"),
            units_count=units,
            language=os.path.basename(output_dir),
            processing_level=processing_level,
        )

    return _stub


@pytest.fixture
def stub_parsers(monkeypatch):
    """Route every language to a stub parser keyed by language name."""
    behaviours: dict[str, object] = {}

    def fake_parser_for(language):
        behaviour = behaviours.get(language, make_stub_parser())
        if isinstance(behaviour, BaseException):
            def _raiser(*a, **kw):
                raise behaviour
            return _raiser
        return behaviour

    monkeypatch.setattr(parser_adapter, "_parser_for", fake_parser_for)
    return behaviours


class TestCollisionProof:
    """The reason per-language directories exist."""

    def test_each_language_gets_its_own_artifacts(self, tmp_path, stub_parsers):
        stub_parsers["python"] = make_stub_parser(units=7)
        stub_parsers["go"] = make_stub_parser(units=4)

        outcomes = parse_repository_multi(FIXTURE, str(tmp_path), ["python", "go"])

        assert all(o.ok for o in outcomes)
        for language, expected_units in (("python", 7), ("go", 4)):
            lang_dir = tmp_path / language
            assert lang_dir.is_dir(), f"{language} has no output directory"
            for artifact in PARSER_ARTIFACTS:
                assert (lang_dir / artifact).is_file(), (
                    f"{language}/{artifact} missing — languages collided"
                )
            data = json.loads((lang_dir / "dataset.json").read_text())
            assert len(data["units"]) == expected_units

    def test_neither_language_overwrites_the_other(self, tmp_path, stub_parsers):
        """Distinct unit counts prove both datasets survived independently."""
        stub_parsers["python"] = make_stub_parser(units=7)
        stub_parsers["go"] = make_stub_parser(units=4)

        parse_repository_multi(FIXTURE, str(tmp_path), ["python", "go"])

        py = json.loads((tmp_path / "python" / "dataset.json").read_text())
        go = json.loads((tmp_path / "go" / "dataset.json").read_text())
        assert len(py["units"]) != len(go["units"])
        assert {u["id"] for u in py["units"]}.isdisjoint({u["id"] for u in go["units"]})

    def test_no_dataset_is_written_at_the_run_root(self, tmp_path, stub_parsers):
        """Merging is a later stage; fan-out alone must not write a root dataset."""
        parse_repository_multi(FIXTURE, str(tmp_path), ["python", "go"])
        assert not (tmp_path / "dataset.json").exists()


class TestPartialSuccess:
    def test_one_failure_still_returns_the_survivor(self, tmp_path, stub_parsers):
        stub_parsers["go"] = RuntimeError("go toolchain missing")

        outcomes = parse_repository_multi(FIXTURE, str(tmp_path), ["python", "go"])

        by_lang = {o.language: o for o in outcomes}
        assert by_lang["python"].ok
        assert by_lang["python"].units_count == 3
        assert not by_lang["go"].ok
        assert "go toolchain missing" in by_lang["go"].error
        assert by_lang["go"].error_type == "parser_failed"

    def test_survivor_artifacts_are_intact_after_a_failure(self, tmp_path, stub_parsers):
        stub_parsers["go"] = RuntimeError("boom")
        parse_repository_multi(FIXTURE, str(tmp_path), ["python", "go"])
        assert (tmp_path / "python" / "dataset.json").is_file()

    def test_all_failing_raises_and_aggregates_every_error(self, tmp_path, stub_parsers):
        stub_parsers["python"] = RuntimeError("python broke")
        stub_parsers["go"] = RuntimeError("go broke")

        with pytest.raises(RuntimeError) as exc:
            parse_repository_multi(FIXTURE, str(tmp_path), ["python", "go"])

        message = str(exc.value)
        assert "python broke" in message
        assert "go broke" in message

    def test_single_language_failure_propagates_unchanged(self, tmp_path, stub_parsers):
        """`-l go` on a broken Go parser must fail, not report a clean 0-unit scan.

        This is the back-compat guarantee: asking for exactly one language
        behaves exactly as it did before the fan-out existed.
        """
        stub_parsers["go"] = RuntimeError("go toolchain missing")

        with pytest.raises(RuntimeError, match="go toolchain missing"):
            parse_repository_multi(FIXTURE, str(tmp_path), ["go"])

    def test_strict_mode_aborts_on_first_failure(self, tmp_path, stub_parsers):
        stub_parsers["python"] = RuntimeError("python broke")

        with pytest.raises(RuntimeError, match="python broke"):
            parse_repository_multi(
                FIXTURE, str(tmp_path), ["python", "go"], strict=True
            )
        # Go must never have been attempted.
        assert not (tmp_path / "go").exists()

    def test_degraded_run_is_announced_on_stderr(self, tmp_path, stub_parsers, capsys):
        stub_parsers["go"] = RuntimeError("boom")
        parse_repository_multi(FIXTURE, str(tmp_path), ["python", "go"])
        assert "DEGRADED" in capsys.readouterr().err


class TestErrorClassification:
    @pytest.mark.parametrize("exc,expected", [
        (subprocess.TimeoutExpired(cmd="x", timeout=1), "timeout"),
        (FileNotFoundError("no such binary"), "missing_dependency"),
        (RuntimeError("exit code 1"), "parser_failed"),
        (ValueError("Unsupported language: cobol"), "unsupported_language"),
    ])
    def test_failures_are_classified(self, tmp_path, stub_parsers, exc, expected):
        stub_parsers["go"] = exc
        outcomes = parse_repository_multi(FIXTURE, str(tmp_path), ["python", "go"])
        assert {o.language: o.error_type for o in outcomes}["go"] == expected

    def test_keyboard_interrupt_is_not_swallowed(self, tmp_path, stub_parsers):
        """An interrupt must abort the fan-out, not be logged per language."""
        stub_parsers["python"] = KeyboardInterrupt()
        with pytest.raises(KeyboardInterrupt):
            parse_repository_multi(FIXTURE, str(tmp_path), ["python", "go"])

    def test_memory_error_is_not_swallowed(self, tmp_path, stub_parsers):
        stub_parsers["python"] = MemoryError()
        with pytest.raises(MemoryError):
            parse_repository_multi(FIXTURE, str(tmp_path), ["python", "go"])


class TestOutcomeShape:
    def test_outcomes_are_returned_in_request_order(self, tmp_path, stub_parsers):
        outcomes = parse_repository_multi(
            FIXTURE, str(tmp_path), ["go", "python", "c"]
        )
        assert [o.language for o in outcomes] == ["go", "python", "c"]

    def test_outcome_records_paths_and_duration(self, tmp_path, stub_parsers):
        outcome = parse_repository_multi(FIXTURE, str(tmp_path), ["python"])[0]
        assert outcome.dataset_path.endswith(os.path.join("python", "dataset.json"))
        assert outcome.output_dir == str(tmp_path / "python")
        assert outcome.duration_seconds >= 0

    def test_outcome_is_serialisable(self, tmp_path, stub_parsers):
        outcome = parse_repository_multi(FIXTURE, str(tmp_path), ["python"])[0]
        assert json.loads(json.dumps(outcome.to_dict()))["language"] == "python"

    def test_empty_language_list_is_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="at least one language"):
            parse_repository_multi(FIXTURE, str(tmp_path), [])


class TestFresh:
    def test_fresh_deletes_each_languages_dataset(self, tmp_path, stub_parsers):
        parse_repository_multi(FIXTURE, str(tmp_path), ["python", "go"])
        # Mark both datasets so we can tell whether they were regenerated.
        for language in ("python", "go"):
            (tmp_path / language / "dataset.json").write_text('{"units": [], "stale": true}')

        parse_repository_multi(FIXTURE, str(tmp_path), ["python", "go"], fresh=True)

        for language in ("python", "go"):
            data = json.loads((tmp_path / language / "dataset.json").read_text())
            assert "stale" not in data, f"{language} dataset was not regenerated"

    def test_fresh_on_one_language_does_not_wipe_the_other(self, tmp_path, stub_parsers):
        """Per-language --fresh must stay per-language."""
        parse_repository_multi(FIXTURE, str(tmp_path), ["python", "go"])
        go_before = (tmp_path / "go" / "dataset.json").read_text()

        parse_repository_multi(FIXTURE, str(tmp_path), ["python"], fresh=True)

        assert (tmp_path / "go" / "dataset.json").read_text() == go_before


@pytest.mark.slow
class TestEndToEndRealParsers:
    """The actual walking skeleton, against real parsers. No LLM calls."""

    def test_python_and_javascript_produce_distinct_valid_datasets(self, tmp_path):
        outcomes = parse_repository_multi(
            FIXTURE, str(tmp_path), ["python", "javascript"], processing_level="all"
        )

        by_lang = {o.language: o for o in outcomes}
        assert by_lang["python"].ok, by_lang["python"].error
        assert by_lang["javascript"].ok, by_lang["javascript"].error

        py = json.loads((tmp_path / "python" / "dataset.json").read_text())
        js = json.loads((tmp_path / "javascript" / "dataset.json").read_text())

        assert py["units"], "python parsed no units"
        assert js["units"], "javascript parsed no units"

        # The collision proof: the two datasets describe disjoint files.
        def files(dataset):
            return {u.get("file_path") or u.get("id", "").split(":")[0]
                    for u in dataset["units"]}

        assert files(py).isdisjoint(files(js))
        assert all(f.endswith(".py") for f in files(py) if f)
        assert all(not f.endswith(".py") for f in files(js) if f)

    def test_javascript_dataset_passes_schema_validation(self, tmp_path):
        """The fan-out must emit schema-valid datasets, not merely non-empty ones.

        Asserting "units exist" is weaker than the gate this stage is supposed
        to clear, and the difference is not academic: run against the real
        validator, the python parser's output does NOT pass (see the xfail
        below). Non-emptiness would have reported that as success.
        """
        parse_repository_multi(
            FIXTURE, str(tmp_path), ["javascript"], processing_level="all"
        )
        assert _schema_errors(tmp_path / "javascript" / "dataset.json") == []

    def test_python_dataset_passes_schema_validation(self, tmp_path):
        """Was xfail'd; now passes.

        The original xfail reason was factually wrong: it claimed Python units
        "carry no file boundaries". They always did — with `#` markers, which
        every consumer failed to recognise because they matched `//`
        literally. Fixing the consumers (see core/file_boundary.py) resolved
        both the schema failure and the far more serious prompt-scoping bug
        behind it, so the strict xfail correctly flipped to a pass.
        """
        parse_repository_multi(
            FIXTURE, str(tmp_path), ["python"], processing_level="all"
        )
        assert _schema_errors(tmp_path / "python" / "dataset.json") == []
