"""Post-LLM reachability re-filter must work per language.

With a merged multi-language dataset there is no single ``call_graph.json`` at
the run root — each language persists its own under ``<run>/<lang>/``, indexed
by ``call_graphs.json``. Re-filtering against the run root alone would find
nothing and silently pass every unit downstream at full token cost.

Languages whose parser does NOT persist a call graph pass through unfiltered,
which is the pre-existing behaviour; the point is that a language which DOES
persist one is no longer skipped just because it isn't the primary.
"""

import json


from core.scanner import partition_units_by_language, resolve_call_graph_dirs


class TestResolveCallGraphDirs:
    def test_uses_the_index_when_present(self, tmp_path):
        (tmp_path / "python").mkdir()
        (tmp_path / "python" / "call_graph.json").write_text("{}")
        (tmp_path / "call_graphs.json").write_text(
            json.dumps({"python": "python/call_graph.json"})
        )
        assert resolve_call_graph_dirs(str(tmp_path)) == {
            "python": str(tmp_path / "python")
        }

    def test_multiple_languages_each_get_their_dir(self, tmp_path):
        for lang in ("python", "javascript"):
            (tmp_path / lang).mkdir()
            (tmp_path / lang / "call_graph.json").write_text("{}")
        (tmp_path / "call_graphs.json").write_text(json.dumps({
            "python": "python/call_graph.json",
            "javascript": "javascript/call_graph.json",
        }))
        dirs = resolve_call_graph_dirs(str(tmp_path))
        assert set(dirs) == {"python", "javascript"}

    def test_falls_back_to_the_run_root_for_single_language(self, tmp_path):
        """No index + a root call_graph.json is the legacy single-language layout."""
        (tmp_path / "call_graph.json").write_text("{}")
        assert resolve_call_graph_dirs(str(tmp_path)) == {None: str(tmp_path)}

    def test_returns_empty_when_no_call_graph_exists_anywhere(self, tmp_path):
        assert resolve_call_graph_dirs(str(tmp_path)) == {}

    def test_index_entry_whose_file_is_missing_is_ignored(self, tmp_path):
        """A stale index must not point the filter at a nonexistent graph."""
        (tmp_path / "call_graphs.json").write_text(
            json.dumps({"go": "go/call_graph.json"})
        )
        assert resolve_call_graph_dirs(str(tmp_path)) == {}


class TestPartitionUnitsByLanguage:
    def test_units_split_by_their_language_stamp(self):
        units = [
            {"id": "a", "language": "python"},
            {"id": "b", "language": "javascript"},
            {"id": "c", "language": "python"},
        ]
        parts = partition_units_by_language(units)
        assert [u["id"] for u in parts["python"]] == ["a", "c"]
        assert [u["id"] for u in parts["javascript"]] == ["b"]

    def test_unstamped_units_group_under_none(self):
        """Legacy single-language datasets carry no per-unit language."""
        parts = partition_units_by_language([{"id": "a"}, {"id": "b"}])
        assert set(parts) == {None}
        assert len(parts[None]) == 2

    def test_empty_input(self):
        assert partition_units_by_language([]) == {}

    def test_partition_is_lossless(self):
        units = [
            {"id": "a", "language": "python"},
            {"id": "b"},
            {"id": "c", "language": "go"},
        ]
        parts = partition_units_by_language(units)
        assert sum(len(v) for v in parts.values()) == len(units), "units were lost"


class TestUnfilterableLanguagesPassThrough:
    def test_language_without_a_call_graph_keeps_all_its_units(self, tmp_path):
        """Pre-existing behaviour, now scoped per language rather than per scan."""
        (tmp_path / "python").mkdir()
        (tmp_path / "python" / "call_graph.json").write_text("{}")
        (tmp_path / "call_graphs.json").write_text(
            json.dumps({"python": "python/call_graph.json"})
        )
        dirs = resolve_call_graph_dirs(str(tmp_path))
        assert "go" not in dirs, "go has no graph, so it must not be filtered"
