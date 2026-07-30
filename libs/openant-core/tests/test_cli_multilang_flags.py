"""CLI surface for multi-language scanning.

Everything before this stage was invisible to users: multi-language worked
through the Python API, but no flag exposed it, so `openant scan` still parsed
exactly one language.

`-l auto` semantics are deliberately UNCHANGED — it still means "the dominant
language, singular". Multi-language is strictly opt-in, so no existing
invocation changes behaviour.
"""

import pytest

from openant.cli import build_parser


def parse(argv):
    return build_parser().parse_args(argv)


class TestBackCompatUnchanged:
    """No existing invocation may change meaning."""

    def test_language_flag_still_accepted(self):
        args = parse(["scan", "/repo", "-l", "python"])
        assert args.language == "python"

    def test_auto_is_still_the_default(self):
        assert parse(["scan", "/repo"]).language == "auto"

    def test_auto_remains_single_language(self):
        """`auto` must NOT silently become multi — that would be a breaking change."""
        args = parse(["scan", "/repo", "-l", "auto"])
        assert args.language == "auto"
        assert args.languages is None
        assert args.all_languages is False

    def test_unknown_language_still_rejected(self):
        with pytest.raises(SystemExit):
            parse(["scan", "/repo", "-l", "cobol"])


class TestNewFlagsExist:
    @pytest.mark.parametrize("command", ["scan", "parse"])
    def test_languages_flag(self, command):
        args = parse([command, "/repo", "--languages", "python,go"])
        assert args.languages == "python,go"

    @pytest.mark.parametrize("command", ["scan", "parse"])
    def test_all_languages_flag(self, command):
        assert parse([command, "/repo", "--all-languages"]).all_languages is True

    @pytest.mark.parametrize("command", ["scan", "parse"])
    def test_threshold_overrides(self, command):
        args = parse([
            command, "/repo", "--all-languages",
            "--min-language-files", "3", "--min-language-share", "0.05",
        ])
        assert args.min_language_files == 3
        assert args.min_language_share == 0.05

    @pytest.mark.parametrize("command", ["scan", "parse"])
    def test_strict_languages_flag(self, command):
        assert parse([command, "/repo", "--strict-languages"]).strict_languages is True

    def test_defaults_match_the_selection_policy(self):
        from core.language_selection import DEFAULT_MIN_FILES, DEFAULT_MIN_SHARE

        args = parse(["scan", "/repo"])
        assert args.min_language_files == DEFAULT_MIN_FILES
        assert args.min_language_share == DEFAULT_MIN_SHARE
        assert args.strict_languages is False


class TestResolution:
    """The flags must resolve to a LanguageSelection consistently."""

    def test_explicit_languages_are_parsed_into_a_list(self):
        from openant.cli import resolve_language_selection

        counts = {"python": 10, "go": 5, "zig": 1}
        sel = resolve_language_selection(
            parse(["scan", "/repo", "--languages", "python,zig"]), counts
        )
        assert sel.selected == ["python", "zig"]

    def test_all_languages_selects_everything(self):
        from openant.cli import resolve_language_selection

        counts = {"python": 5000, "zig": 2}
        sel = resolve_language_selection(
            parse(["scan", "/repo", "--all-languages"]), counts
        )
        assert sel.selected == ["python", "zig"]

    def test_plain_auto_selects_only_the_dominant(self):
        from openant.cli import resolve_language_selection

        counts = {"python": 5000, "zig": 2}
        sel = resolve_language_selection(parse(["scan", "/repo"]), counts)
        assert sel.selected == ["python"]

    def test_explicit_single_language_selects_only_it(self):
        from openant.cli import resolve_language_selection

        counts = {"python": 10, "go": 5}
        sel = resolve_language_selection(
            parse(["scan", "/repo", "-l", "go"]), counts
        )
        assert sel.selected == ["go"]

    def test_whitespace_in_languages_list_is_tolerated(self):
        from openant.cli import resolve_language_selection

        sel = resolve_language_selection(
            parse(["scan", "/repo", "--languages", " python , go "]),
            {"python": 5, "go": 5},
        )
        assert sel.selected == ["go", "python"] or sel.selected == ["python", "go"]


class TestMutualExclusion:
    """`-l <lang>` names one language; the multi flags name a set."""

    def test_explicit_language_with_languages_is_rejected(self):
        from openant.cli import resolve_language_selection

        with pytest.raises(ValueError, match="mutually exclusive"):
            resolve_language_selection(
                parse(["scan", "/repo", "-l", "python", "--languages", "go"]),
                {"python": 5, "go": 5},
            )

    def test_explicit_language_with_all_languages_is_rejected(self):
        from openant.cli import resolve_language_selection

        with pytest.raises(ValueError, match="mutually exclusive"):
            resolve_language_selection(
                parse(["scan", "/repo", "-l", "python", "--all-languages"]),
                {"python": 5, "go": 5},
            )

    def test_auto_with_multi_flags_is_allowed(self):
        """`auto` is the DEFAULT, so combining it with --all-languages is not
        a user contradiction — only an explicit -l <lang> is."""
        from openant.cli import resolve_language_selection

        sel = resolve_language_selection(
            parse(["scan", "/repo", "-l", "auto", "--all-languages"]),
            {"python": 5, "go": 5},
        )
        assert len(sel.selected) == 2
