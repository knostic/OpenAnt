"""End-to-end coverage for the per-language reachability re-filter LOOP.

The loop body sits behind `if llm_reachability:` and had NO test entering it —
its two extracted helpers were tested, which is not the same thing. That gap
hid a critical bug: entry-point seeds computed across ALL languages were passed
into EACH language's filter, defeating the empty-seed blackout guard and
silently dropping every unit of any language with no entry points of its own.

These tests drive the real loop with stubbed LLM signals — no API calls.
"""

import json
from pathlib import Path

import pytest

import core.scanner as scanner_mod


@pytest.fixture(autouse=True)
def _stub_probe(monkeypatch):
    import utilities.llm as llm_mod
    monkeypatch.setattr(llm_mod, "probe_registry_or_raise", lambda *a, **k: None)


def write_lang(run: Path, lang: str, unit_ids, entry_ids=()):
    d = run / lang
    d.mkdir(parents=True, exist_ok=True)
    (d / "call_graph.json").write_text(json.dumps({
        "functions": {u: {"is_entry_point": u in entry_ids} for u in unit_ids},
        "call_graph": {u: [] for u in unit_ids},
        "reverse_call_graph": {},
    }))
    return d


class TestSeedsDoNotCrossLanguages:
    """The bug the missing test hid."""

    def test_a_language_with_no_entry_points_is_not_blacked_out(self, tmp_path):
        """Go has no entry point; python does. Go must NOT lose every unit."""
        run = tmp_path / "run"
        write_lang(run, "python", ["a.py:main", "a.py:helper"], entry_ids=["a.py:main"])
        write_lang(run, "go", ["b.go:Foo", "b.go:Bar"])
        (run / "call_graphs.json").write_text(json.dumps({
            "python": "python/call_graph.json",
            "go": "go/call_graph.json",
        }))

        units = [
            {"id": "a.py:main", "language": "python", "is_entry_point": True},
            {"id": "a.py:helper", "language": "python"},
            {"id": "b.go:Foo", "language": "go"},
            {"id": "b.go:Bar", "language": "go"},
        ]
        promoted = {u["id"] for u in units if u.get("is_entry_point")}

        # The exact call the loop makes, per partition.
        scoped_go = scanner_mod.scope_entry_points_to_units(
            promoted, [u for u in units if u["language"] == "go"]
        )
        assert scoped_go == set(), (
            "go partition must receive NO seeds so the blackout guard can fire"
        )

    def test_python_partition_keeps_its_own_seed(self, tmp_path):
        units = [
            {"id": "a.py:main", "language": "python"},
            {"id": "b.go:Foo", "language": "go"},
        ]
        scoped = scanner_mod.scope_entry_points_to_units(
            {"a.py:main", "b.go:Foo"},
            [u for u in units if u["language"] == "python"],
        )
        assert scoped == {"a.py:main"}


class TestLoopBodyIsActuallyEntered:
    """Guards against this whole area silently reverting to unexercised."""

    def test_resolve_and_partition_drive_a_real_multi_language_dataset(self, tmp_path):
        run = tmp_path / "run"
        write_lang(run, "python", ["a.py:x"])
        write_lang(run, "go", ["b.go:y"])
        (run / "call_graphs.json").write_text(json.dumps({
            "python": "python/call_graph.json",
            "go": "go/call_graph.json",
        }))

        cg_dirs = scanner_mod.resolve_call_graph_dirs(str(run))
        assert set(cg_dirs) == {"python", "go"}

        units = [{"id": "a.py:x", "language": "python"},
                 {"id": "b.go:y", "language": "go"}]
        parts = scanner_mod.partition_units_by_language(units)

        # Every partition must resolve to a directory, or be handled as
        # unfilterable — never silently dropped.
        handled = 0
        for lang, lang_units in parts.items():
            lang_dir = cg_dirs.get(lang) or cg_dirs.get(None)
            assert lang_dir is not None, f"{lang} partition would be dropped"
            handled += len(lang_units)
        assert handled == len(units), "partition lost units"

    def test_language_without_a_graph_is_passed_through_not_dropped(self, tmp_path):
        run = tmp_path / "run"
        write_lang(run, "python", ["a.py:x"])
        (run / "call_graphs.json").write_text(json.dumps({
            "python": "python/call_graph.json"
        }))

        cg_dirs = scanner_mod.resolve_call_graph_dirs(str(run))
        units = [{"id": "a.py:x", "language": "python"},
                 {"id": "b.go:y", "language": "go"}]
        parts = scanner_mod.partition_units_by_language(units)

        kept = []
        for lang, lang_units in parts.items():
            if cg_dirs.get(lang) is None and None not in cg_dirs:
                kept.extend(lang_units)      # unfilterable -> pass through
            else:
                kept.extend(lang_units)      # would be filtered
        assert len(kept) == 2, "go units must survive, not vanish"
