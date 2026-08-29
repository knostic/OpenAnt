"""Regression tests for issue #308 — `-l python` and `--languages python`
scan identically, but only `--languages` records the exclusion set; `-l`
emits `excluded_languages: {}`, indistinguishable from "genuinely nothing
was excluded".

The cause: `_select_languages_for` returns None for an explicit `-l`
BEFORE `detect_languages`/`resolve_language_selection` run, so the
exclusion set is never computed — and the populate guard is exactly
`selection is not None`.

Contract locked here (the issue's suggestions 1-4):
- an explicit `-l` still builds a selection (so exclusions are computed
  and reported), with `selected` = the named language only — WHAT GETS
  SCANNED DOES NOT CHANGE (a single-element selection takes the same
  legacy branch);
- `ValueError` from detect/select on the `-l` path (a source-free repo,
  or a requested language with no files) falls back to the current
  behaviour — today's exit codes are preserved;
- the reason string names the flag the user actually typed (`-l`), not
  the `--languages` flag this path never saw (suggestion 3);
- the populate guard fires on the `-l` path too.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from openant.cli import _select_languages_for  # noqa: E402


def _args(lang="python", languages=None, all_languages=False, repo="/repo"):
    class A:
        pass
    a = A()
    a.language = lang
    a.languages = languages
    a.all_languages = all_languages
    a.multi_language = False
    a.repo = repo
    return a


class _FakeAdapter:
    @staticmethod
    def detect_languages(repo):
        # the issue's fixture: 20 py, 12 js, 1 php
        return {"python": 20, "javascript": 12, "php": 1}


def test_explicit_l_builds_a_selection(monkeypatch):
    """Suggestion 1: the -l path computes the exclusion set instead of
    returning None before detection runs."""
    import core.parser_adapter as pa

    monkeypatch.setattr(pa, "detect_languages", _FakeAdapter.detect_languages)

    sel = _select_languages_for(_args())
    assert sel is not None, "the -l path must still build a selection"
    assert sel.selected == ["python"], "WHAT GETS SCANNED DOES NOT CHANGE"
    assert set(sel.excluded) == {"javascript", "php"}


def test_exclusion_reason_names_the_actual_flag(monkeypatch):
    """Suggestion 3: the reason string names -l on this path, not the
    --languages flag the user did not type."""
    import core.parser_adapter as pa

    monkeypatch.setattr(pa, "detect_languages", _FakeAdapter.detect_languages)

    sel = _select_languages_for(_args())
    reasons = set(sel.excluded.values())
    assert reasons == {"not requested via -l"}, reasons


def test_l_path_valueerror_falls_back_to_none(monkeypatch):
    """Suggestion 2: a source-free repo or an empty-for-that-language repo
    raises ValueError on this path — the current exit-0 behaviour is
    preserved by falling back to None."""
    import core.parser_adapter as pa

    def boom(repo):
        raise ValueError("No supported source files found")

    monkeypatch.setattr(pa, "detect_languages", boom)

    assert _select_languages_for(_args()) is None


def test_auto_path_unchanged(monkeypatch):
    """Regression guard: auto still resolves through the full machinery."""
    import core.parser_adapter as pa

    monkeypatch.setattr(pa, "detect_languages", _FakeAdapter.detect_languages)

    sel = _select_languages_for(_args(lang="auto"))
    assert sel is not None
    assert "python" in sel.selected


def test_languages_path_unchanged(monkeypatch):
    """Regression guard: the --languages path keeps its own reason string
    (named after ITS flag)."""
    import core.parser_adapter as pa

    monkeypatch.setattr(pa, "detect_languages", _FakeAdapter.detect_languages)

    sel = _select_languages_for(_args(lang="auto", languages="python"))
    assert sel.selected == ["python"]
    assert set(sel.excluded.values()) == {"not requested via --languages"}


def test_populate_guard_fires_for_explicit_l():
    """The populate site (`if selection is not None`) now receives a
    selection on the -l path — the guard itself is the contract."""
    src = (PROJECT_ROOT / "openant" / "cli.py").read_text()
    assert "if selection is not None and not result.excluded_languages:" in src
