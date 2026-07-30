"""Merging per-language parse output into one dataset.

The fan-out writes ``<run>/<lang>/`` directories; this is the step that makes
them a single dataset the (language-agnostic) LLM stages can consume. The
merge is deliberately shallow: union the units, stamp each with its language,
and record per-language provenance. Call graphs are NOT merged — there are no
cross-language edges to resolve, and pretending otherwise would invent them.
"""

import json

import pytest

from core.dataset_merge import (
    merge_analyzer_outputs,
    merge_datasets,
    write_call_graph_index,
)
from core.parser_adapter import LanguageParseOutcome


def write_lang_output(run_dir, language, unit_ids, *, functions=None,
                      call_graph=True, statistics=None):
    """Materialise one language's parser output under <run>/<lang>/."""
    lang_dir = run_dir / language
    lang_dir.mkdir(parents=True, exist_ok=True)

    dataset = {
        "name": "fixture",
        "repository": "/repo",
        "units": [{"id": uid, "code": f"code for {uid}"} for uid in unit_ids],
        "statistics": statistics or {"total_units": len(unit_ids)},
        "metadata": {"generator": f"{language}-parser"},
    }
    (lang_dir / "dataset.json").write_text(json.dumps(dataset))

    analyzer = {"functions": {uid: {"name": uid} for uid in (functions or unit_ids)}}
    (lang_dir / "analyzer_output.json").write_text(json.dumps(analyzer))

    if call_graph:
        (lang_dir / "call_graph.json").write_text(json.dumps({
            "functions": {uid: {} for uid in unit_ids},
            "call_graph": {uid: [] for uid in unit_ids},
            "reverse_call_graph": {},
        }))

    return LanguageParseOutcome(
        language=language,
        ok=True,
        output_dir=str(lang_dir),
        dataset_path=str(lang_dir / "dataset.json"),
        analyzer_output_path=str(lang_dir / "analyzer_output.json"),
        units_count=len(unit_ids),
    )


@pytest.fixture
def two_languages(tmp_path):
    py = write_lang_output(tmp_path, "python", ["app.py:handler", "db.py:query"])
    js = write_lang_output(tmp_path, "javascript", ["web/app.js:route"])
    return tmp_path, [py, js]


class TestMergeDatasets:
    def test_units_from_every_language_are_present(self, two_languages):
        run_dir, outcomes = two_languages
        out = run_dir / "dataset.json"

        stats = merge_datasets(outcomes, str(out))

        merged = json.loads(out.read_text())
        ids = {u["id"] for u in merged["units"]}
        assert ids == {"app.py:handler", "db.py:query", "web/app.js:route"}
        assert stats.total_units == 3
        assert stats.units_per_language == {"python": 2, "javascript": 1}

    def test_every_unit_is_stamped_with_its_language(self, two_languages):
        run_dir, outcomes = two_languages
        out = run_dir / "dataset.json"
        merge_datasets(outcomes, str(out))

        merged = json.loads(out.read_text())
        by_id = {u["id"]: u["language"] for u in merged["units"]}
        assert by_id["app.py:handler"] == "python"
        assert by_id["db.py:query"] == "python"
        assert by_id["web/app.js:route"] == "javascript"

    def test_a_parser_supplied_language_wins_over_the_stamp(self, tmp_path):
        """setdefault, not assignment — if a parser starts emitting it, trust it."""
        lang_dir = tmp_path / "python"
        lang_dir.mkdir()
        (lang_dir / "dataset.json").write_text(json.dumps({
            "units": [{"id": "a.py:f", "language": "python-3.14"}],
            "metadata": {},
        }))
        outcome = LanguageParseOutcome(
            language="python", ok=True, output_dir=str(lang_dir),
            dataset_path=str(lang_dir / "dataset.json"), units_count=1,
        )
        out = tmp_path / "dataset.json"
        merge_datasets([outcome], str(out))

        merged = json.loads(out.read_text())
        assert merged["units"][0]["language"] == "python-3.14"

    def test_metadata_records_languages_and_per_language_detail(self, two_languages):
        run_dir, outcomes = two_languages
        out = run_dir / "dataset.json"
        merge_datasets(outcomes, str(out))

        meta = json.loads(out.read_text())["metadata"]
        assert meta["languages"] == ["python", "javascript"]
        assert meta["per_language"]["python"]["units"] == 2
        assert meta["per_language"]["javascript"]["units"] == 1
        assert "python" in meta["per_language"]["python"]["dataset_path"]

    def test_failed_languages_are_skipped_not_merged(self, tmp_path):
        ok = write_lang_output(tmp_path, "python", ["a.py:f"])
        failed = LanguageParseOutcome(
            language="go", ok=False, output_dir=str(tmp_path / "go"),
            error="toolchain missing", error_type="missing_dependency",
        )
        out = tmp_path / "dataset.json"
        stats = merge_datasets([ok, failed], str(out))

        assert stats.units_per_language == {"python": 1}
        assert "go" not in json.loads(out.read_text())["metadata"]["languages"]

    def test_single_language_merge_is_a_faithful_passthrough(self, tmp_path):
        outcome = write_lang_output(tmp_path, "python", ["a.py:f", "b.py:g"])
        out = tmp_path / "dataset.json"
        merge_datasets([outcome], str(out))

        merged = json.loads(out.read_text())
        assert len(merged["units"]) == 2
        assert merged["name"] == "fixture"
        assert merged["repository"] == "/repo"

    def test_merging_no_successful_languages_raises(self, tmp_path):
        failed = LanguageParseOutcome(
            language="go", ok=False, output_dir=str(tmp_path / "go"), error="boom",
        )
        with pytest.raises(ValueError, match="no successful"):
            merge_datasets([failed], str(tmp_path / "dataset.json"))


class TestMergedStatistics:
    """Statistics must not silently under-report across naming conventions.

    The two parsers disagree on case: Python emits ``total_units``/
    ``units_with_upstream``, JavaScript emits ``totalUnits``/
    ``unitsWithUpstream``. Summing by raw key name produces a dict where
    ``total_units`` holds only Python's count and ``totalUnits`` only
    JavaScript's — each looks authoritative and each is wrong. Nothing in-repo
    reads this field today, which is exactly why a wrong value could sit here
    unnoticed until the first consumer trusts it.
    """

    def test_total_units_is_the_true_merged_total(self, tmp_path):
        py = write_lang_output(
            tmp_path, "python", ["a.py:f", "b.py:g"],
            statistics={"total_units": 2, "units_enhanced": 1},
        )
        js = write_lang_output(
            tmp_path, "javascript", ["c.js:h"],
            statistics={"totalUnits": 1, "unitsWithUpstream": 1},
        )
        out = tmp_path / "dataset.json"
        merge_datasets([py, js], str(out))

        stats = json.loads(out.read_text())["statistics"]
        assert stats["total_units"] == 3, (
            "merged total_units must count every language, not just the one "
            f"using snake_case. Got {stats.get('total_units')} from {stats}"
        )

    def test_incomparable_per_parser_keys_are_not_summed_into_the_aggregate(self, tmp_path):
        """Raw per-parser keys stay per-language; the top level stays honest."""
        py = write_lang_output(
            tmp_path, "python", ["a.py:f"], statistics={"total_units": 1, "avg_upstream": 0.75},
        )
        js = write_lang_output(
            tmp_path, "javascript", ["c.js:h"], statistics={"totalUnits": 1, "byType": {}},
        )
        out = tmp_path / "dataset.json"
        merge_datasets([py, js], str(out))

        merged = json.loads(out.read_text())
        stats = merged["statistics"]
        assert "totalUnits" not in stats, (
            "camelCase parser key leaked into the merged aggregate, where it "
            "reads as a whole-dataset figure but counts one language"
        )
        # The raw per-language numbers remain available, just not conflated.
        per_lang = merged["metadata"]["per_language"]
        assert per_lang["python"]["statistics"]["total_units"] == 1
        assert per_lang["javascript"]["statistics"]["totalUnits"] == 1

    def test_units_per_language_is_recorded_in_statistics(self, tmp_path):
        py = write_lang_output(tmp_path, "python", ["a.py:f", "b.py:g"])
        js = write_lang_output(tmp_path, "javascript", ["c.js:h"])
        out = tmp_path / "dataset.json"
        merge_datasets([py, js], str(out))

        stats = json.loads(out.read_text())["statistics"]
        assert stats["units_per_language"] == {"python": 2, "javascript": 1}


class TestUnitIdCollisions:
    """Path-prefixed ids make collisions impossible today.

    They become possible the moment a language claims an extension another
    already owns, so the merge detects rather than assumes.
    """

    def test_colliding_id_is_namespaced_and_reported(self, tmp_path):
        a = write_lang_output(tmp_path, "c", ["shared.h:init"])
        b = write_lang_output(tmp_path, "zig", ["shared.h:init"])
        out = tmp_path / "dataset.json"

        stats = merge_datasets([a, b], str(out))

        assert stats.id_collisions == ["shared.h:init"]
        ids = {u["id"] for u in json.loads(out.read_text())["units"]}
        # First writer keeps the bare id; the later one is namespaced.
        assert "shared.h:init" in ids
        assert "zig::shared.h:init" in ids

    def test_non_colliding_ids_are_never_namespaced(self, two_languages):
        """Namespacing unconditionally would break diff-filter and dedup."""
        run_dir, outcomes = two_languages
        out = run_dir / "dataset.json"
        merge_datasets(outcomes, str(out))

        ids = {u["id"] for u in json.loads(out.read_text())["units"]}
        assert not any("::" in i for i in ids)


class TestMergeAnalyzerOutputs:
    def test_functions_are_unioned(self, two_languages):
        run_dir, outcomes = two_languages
        out = run_dir / "analyzer_output.json"

        merge_analyzer_outputs(outcomes, str(out))

        merged = json.loads(out.read_text())
        assert set(merged["functions"]) == {
            "app.py:handler", "db.py:query", "web/app.js:route",
        }

    def test_parsers_with_differing_key_sets_both_survive(self, tmp_path):
        """Python emits functions/callGraph; JS adds call_graph/indirect_calls.

        A merge that assumed one schema would silently drop the other's keys.
        """
        for lang, payload in (
            ("python", {"functions": {"a.py:f": {}}, "callGraph": {"a.py:f": []}}),
            ("javascript", {"functions": {"b.js:g": {}},
                            "call_graph": {"b.js:g": []},
                            "indirect_calls": {"b.js:g": []}}),
        ):
            d = tmp_path / lang
            d.mkdir()
            (d / "analyzer_output.json").write_text(json.dumps(payload))

        outcomes = [
            LanguageParseOutcome(
                language=lang, ok=True, output_dir=str(tmp_path / lang),
                analyzer_output_path=str(tmp_path / lang / "analyzer_output.json"),
            )
            for lang in ("python", "javascript")
        ]
        out = tmp_path / "analyzer_output.json"
        merge_analyzer_outputs(outcomes, str(out))

        merged = json.loads(out.read_text())
        assert set(merged["functions"]) == {"a.py:f", "b.js:g"}
        assert "callGraph" in merged
        assert "call_graph" in merged
        assert "indirect_calls" in merged

    def test_scalar_keys_do_not_crash_the_merge(self, tmp_path):
        """`repository` is a string, not a dict — must not be dict-updated."""
        for lang in ("python", "javascript"):
            d = tmp_path / lang
            d.mkdir()
            (d / "analyzer_output.json").write_text(json.dumps({
                "repository": f"/repo/{lang}",
                "functions": {f"{lang}:f": {}},
            }))
        outcomes = [
            LanguageParseOutcome(
                language=lang, ok=True, output_dir=str(tmp_path / lang),
                analyzer_output_path=str(tmp_path / lang / "analyzer_output.json"),
            )
            for lang in ("python", "javascript")
        ]
        out = tmp_path / "analyzer_output.json"
        merge_analyzer_outputs(outcomes, str(out))

        merged = json.loads(out.read_text())
        assert isinstance(merged["repository"], str)
        assert set(merged["functions"]) == {"python:f", "javascript:f"}


class TestCallGraphIndex:
    def test_index_is_built_by_probing_the_filesystem(self, tmp_path):
        """Which parsers persist call_graph.json must NOT be a hardcoded list.

        A stale list in core/scanner.py claimed only Python and Zig do; in fact
        JavaScript does too, and parsers gain the behaviour over time. Probing
        is the only thing that cannot go stale.
        """
        with_cg = write_lang_output(tmp_path, "python", ["a.py:f"], call_graph=True)
        without = write_lang_output(tmp_path, "go", ["b.go:g"], call_graph=False)
        out = tmp_path / "call_graphs.json"

        write_call_graph_index([with_cg, without], str(out))

        index = json.loads(out.read_text())
        assert "python" in index
        assert "go" not in index, "a language with no call_graph.json must be absent"

    def test_index_paths_are_relative_to_the_run_dir(self, tmp_path):
        outcome = write_lang_output(tmp_path, "python", ["a.py:f"])
        out = tmp_path / "call_graphs.json"
        write_call_graph_index([outcome], str(out))

        index = json.loads(out.read_text())
        assert index["python"] == "python/call_graph.json"
        assert (tmp_path / index["python"]).is_file()

    def test_failed_language_is_absent_even_if_stale_file_exists(self, tmp_path):
        stale = write_lang_output(tmp_path, "go", ["b.go:g"], call_graph=True)
        stale.ok = False
        out = tmp_path / "call_graphs.json"
        write_call_graph_index([stale], str(out))

        assert json.loads(out.read_text()) == {}
