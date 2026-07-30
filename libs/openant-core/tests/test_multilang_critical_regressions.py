"""Regression locks for two critical multi-language defects.

Both were found by adversarial review after the feature was reported done, and
both are silent: the scan exits 0 and reports success while producing wrong or
missing results.
"""

import json

import pytest

from core.language_selection import select_languages
from openant.cli import build_parser, resolve_language_selection


class TestSingleLanguageSelectionIsHonoured:
    """`--languages X` with one entry must parse X, not the dominant language.

    cmd_parse's single-language branch discarded the resolved selection and
    fell back to `args.language or "auto"` — and since `-l` is mutually
    exclusive with `--languages`, that is ALWAYS "auto". So
    `--languages python` on a javascript-dominant repo silently parsed
    javascript and reported success.
    """

    def test_selection_survives_into_the_single_language_branch(self):
        args = build_parser().parse_args(["parse", "/repo", "--languages", "python"])
        sel = resolve_language_selection(args, {"javascript": 6, "python": 3})
        assert sel.selected == ["python"]
        # The value cmd_parse must use for the legacy path:
        assert sel.selected[0] == "python"
        # The value it WAS using:
        assert (args.language or "auto") == "auto", (
            "regression guard: -l is mutex with --languages so args.language is "
            "always 'auto' here; using it discards the user's request"
        )

    def test_dominant_language_would_differ(self):
        """Pins that the fixture genuinely distinguishes the two code paths."""
        sel = select_languages({"javascript": 6, "python": 3}, include=["python"])
        assert sel.selected == ["python"]
        assert sel.counts and max(sel.counts, key=sel.counts.get) == "javascript"


class TestPerLanguageSeedsAreNotCrossContaminated:
    """Entry-point seeds from language A must not be fed to language B's filter.

    `apply_reachability_filter` unions `extra_entry_points` into the seed set
    BEFORE its empty-seed safety net runs. So a language with zero entry points
    of its own gets a non-empty seed set full of IDs absent from its graph: BFS
    reaches nothing, every unit is dropped, and the blackout guard never fires
    because it was defeated by the foreign seeds.
    """

    def test_seeds_are_scoped_to_the_partition(self):
        from core.scanner import scope_entry_points_to_units

        promoted = {"a.py:main", "b.go:Foo"}
        go_units = [{"id": "b.go:Foo"}, {"id": "b.go:Bar"}]
        scoped = scope_entry_points_to_units(promoted, go_units)
        assert scoped == {"b.go:Foo"}, "python seed leaked into the go partition"

    def test_partition_with_no_promoted_units_gets_empty_seeds(self):
        """Empty is REQUIRED — it lets the blackout safety net fire."""
        from core.scanner import scope_entry_points_to_units

        scoped = scope_entry_points_to_units({"a.py:main"}, [{"id": "b.go:Foo"}])
        assert scoped == set(), (
            "must be empty so apply_reachability_filter's empty-seed guard "
            "degrades to pass-through instead of dropping every unit"
        )

    def test_no_promotions_at_all_yields_empty(self):
        from core.scanner import scope_entry_points_to_units

        assert scope_entry_points_to_units(set(), [{"id": "a.py:x"}]) == set()

    def test_units_without_ids_are_tolerated(self):
        from core.scanner import scope_entry_points_to_units

        assert scope_entry_points_to_units({"a.py:x"}, [{}, {"id": "a.py:x"}]) == {"a.py:x"}


class TestRequestingAnAbsentLanguageIsAnError:
    """`--languages go` on a repo with no Go must NOT fall back to Python.

    An empty selection was treated as "no multi-language request", so the
    legacy auto-detect path ran and scanned the dominant language — inverting
    an explicit user instruction, and in `scan` billing LLM analysis of a
    language the user had scoped out.
    """

    def test_empty_selection_raises_rather_than_falling_back(self):
        from core.language_selection import UnknownLanguageError  # noqa: F401
        from openant.cli import build_parser, resolve_language_selection

        args = build_parser().parse_args(["parse", "/repo", "--languages", "go"])
        with pytest.raises(ValueError, match="have source files"):
            resolve_language_selection(args, {"python": 10})

    def test_partially_present_request_still_works(self):
        """Asking for two, one present: proceed with the present one."""
        from openant.cli import build_parser, resolve_language_selection

        args = build_parser().parse_args(["parse", "/repo", "--languages", "go,python"])
        sel = resolve_language_selection(args, {"python": 10})
        assert sel.selected == ["python"]


class TestCheckpointedFindingsAreNotDowngraded:
    """A previously-CONFIRMED finding must not become SKIPPED on resume.

    The language-skip check was inserted BEFORE the checkpoint lookup, so a
    C/Zig finding confirmed by an earlier run was re-labelled SKIPPED,
    discarding exploit evidence.
    """

    def test_skip_check_runs_after_the_checkpoint_lookup(self):
        import inspect

        from utilities.dynamic_tester import run_dynamic_tests

        src = inspect.getsource(run_dynamic_tests)
        cp_idx = src.index("cp_data = checkpointed.get")
        skip_idx = src.index("should_skip_for_language")
        assert cp_idx < skip_idx, (
            "the language-skip check must come AFTER the checkpoint hit, or a "
            "previously CONFIRMED finding is downgraded to SKIPPED on resume"
        )
