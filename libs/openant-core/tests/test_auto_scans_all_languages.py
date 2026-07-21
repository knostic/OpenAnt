"""`auto` means every detected language. This is the headline requirement.

The request was: "All languages we currently support should be detected in the repo
and it should scan all of them. **Not just the main one**." That is a statement
about what the tool does by default — an opt-in flag does not satisfy it, which is
why the previous `-l auto` = dominant-language-only behaviour was a requirement
inversion rather than a conservative choice.

These tests pin the default so it cannot quietly revert to opt-in.
"""

from __future__ import annotations

import openant.cli as cli

COUNTS = {"python": 500, "go": 300, "php": 4}


def _selection(argv, counts=COUNTS):
    args = cli.build_parser().parse_args(argv)
    explicit = getattr(args, "language", "auto") not in (None, "auto")
    multi = (args.languages or args.all_languages
             or getattr(args, "multi_language", False))
    if explicit and not multi:
        return None
    return cli.resolve_language_selection(args, counts)


def test_default_selects_every_language_above_threshold(capsys):
    """No flags at all. The case a user who has read no documentation hits."""
    sel = _selection(["parse", "/repo"])
    assert sel is not None, "default fell back to the legacy single-language path"
    assert set(sel.selected) == {"python", "go"}


def test_a_language_dropped_by_threshold_is_reported_loudly(capsys):
    """Thresholds may still exclude, but never silently.

    The user ratified thresholds on condition the exclusions are loud, so a
    coverage gap has to reach the operator. Silent exclusion would recreate the
    original complaint in a subtler form.
    """
    _selection(["parse", "/repo"])
    err = capsys.readouterr().err
    assert "php" in err and "COVERAGE GAP" in err.upper()


def test_all_languages_overrides_the_threshold():
    sel = _selection(["parse", "/repo", "--all-languages"])
    assert set(sel.selected) == {"python", "go", "php"}


def test_explicit_single_language_remains_the_escape_hatch():
    """`-l go` must still mean only go — this is how you opt OUT of the new default."""
    assert _selection(["parse", "/repo", "-l", "go"]) is None


def test_explicit_language_conflicts_with_every_multi_flag():
    """All three multi flags, not just two.

    `--multi-language` was omitted from the exclusivity check while a sibling
    function treated it as a trigger, so `-l go --multi-language` silently dropped
    the flag and then blamed the exclusion on `--languages`, which was never passed.
    """
    import pytest

    for flag in ("--all-languages", "--multi-language"):
        with pytest.raises(ValueError, match="mutually exclusive"):
            _selection(["parse", "/repo", "-l", "go", flag])
    with pytest.raises(ValueError, match="mutually exclusive"):
        _selection(["parse", "/repo", "-l", "go", "--languages", "python"])


def test_single_language_repo_is_unaffected():
    sel = _selection(["parse", "/repo"], {"python": 50})
    assert sel.selected == ["python"]
