"""#606: the Swift scanner drops the walker's symlink counters, and the
aggregation converts the absence into a false zero.

Two halves, one doctrine (absence ≠ zero, #307):

* the PRODUCER: ``parsers/swift/repository_scanner.py`` rebuilt the
  statistics dict by hand and copied only ``directories_unreadable`` from
  the walker's stats — while rust and zig forward ``symlinks_skipped`` /
  ``symlink_examples`` / ``unreadable_examples``. A Swift scan that refused
  symlinks reported ``symlinks_skipped`` nowhere at all.
* the CONSUMER: ``_collect_coverage``'s any-key presence probe passed on
  the ONE key Swift did emit, then ``stats.get(k, 0)`` summed the absent
  ``symlinks_skipped`` as 0 — manufacturing a false "nothing skipped" with
  Swift absent from ``languages_without_coverage_data``: exactly the
  coercion the function's own docstring forbids.

The fix: the producer mirrors rust/zig (all three keys); the consumer
discloses per-key — each count key's total sums only the languages that
reported it, and the per-key ``languages_without_{key}_data`` lists are
that total's exclusion set (supersets of ``languages_without_coverage_data``:
a fully uninstrumented language is missing every key). A list's ABSENCE
means the total is complete. The example keys stay merge-only (absence of
examples is not a false-zero count); dangling symlinks land in the
unreadable path (the stat-OSError branch), not the symlink count.

The consumer tests hand-write the partial statistics shape because after
the producer fix no live parser reproduces it — the regression guard is for
the NEXT parser that emits one coverage key and not another.

Fully offline ($0).
"""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.scanner import (  # noqa: E402
    _COVERAGE_COUNT_KEYS,
    ScanResult,
    _collect_coverage,
)
from parsers.swift.repository_scanner import RepositoryScanner  # noqa: E402


def _coverage_result(**per_language: str) -> ScanResult:
    langs = list(per_language)
    result = ScanResult(output_dir="/unused", language=langs[0],
                        languages=langs)
    result.per_language = {k: {"output_dir": v} for k, v in per_language.items()}
    return result


def _write_stats(dir_path: Path, statistics: dict) -> Path:
    dir_path.mkdir(parents=True, exist_ok=True)
    (dir_path / "scan_result.json").write_text(
        json.dumps({"statistics": statistics}))
    return dir_path


# ---------------------------------------------------------------------------
# the producer: the Swift scanner's statistics carry the walker's keys
# ---------------------------------------------------------------------------

def test_swift_statistics_carry_the_walker_symlink_keys(tmp_path):
    """A directory AND a file symlink are refused, counted, and exemplified.

    The zig precedent is dir-only — this adds the file shape (one shape
    certified while the other is open is how the class survived #532).
    Counts are exact (``== 2``), not truthiness.
    """
    external = tmp_path / "external_pkg"
    external.mkdir()
    (external / "util.swift").write_text("func f() {}\n")

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "linked_pkg").symlink_to(external, target_is_directory=True)
    (repo / "linked_file.swift").symlink_to(external / "util.swift")

    results = RepositoryScanner(str(repo)).scan()
    stats = results["statistics"]
    assert stats["symlinks_skipped"] == 2
    assert len(stats["symlink_examples"]) == 2
    assert "unreadable_examples" in stats


def test_swift_clean_repository_reports_zero_not_absence(tmp_path):
    """Present-at-0 marks the parser as instrumented — the key is never
    absent on a clean scan (absence is the uninstrumented signal)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "plain.swift").write_text("func g() {}\n")
    stats = RepositoryScanner(str(repo)).scan()["statistics"]
    assert stats["symlinks_skipped"] == 0
    assert stats["symlink_examples"] == []
    assert stats["directories_unreadable"] == 0


# ---------------------------------------------------------------------------
# the consumer: per-key presence disclosure, never a coerced zero
# ---------------------------------------------------------------------------

def test_partial_instrumentation_disclosed_not_summed_as_zero(tmp_path):
    """The Swift-before-fix shape: only ``directories_unreadable`` present.

    The aggregate must disclose the missing ``symlinks_skipped`` per key —
    NOT sum it as a silent 0 — while still counting what the language DID
    report. On pristine code this raises KeyError: the disclosure keys do
    not exist yet. This is the honest RED.
    """
    swift_dir = _write_stats(tmp_path / "swift-out", {
        "directories_unreadable": 1, "symlink_examples": [],
    })
    cov = _collect_coverage(_coverage_result(swift=str(swift_dir)))
    assert cov["languages_without_symlinks_skipped_data"] == ["swift"]
    assert cov["symlinks_skipped"] == 0, (
        "a disclosed zero is acceptable only WITH the list beside it")
    # the partial language is NOT double-listed: it IS instrumented
    assert "swift" not in cov["languages_without_coverage_data"]
    # and what it did report is still counted
    assert cov["directories_unreadable"] == 1
    assert "languages_without_directories_unreadable_data" not in cov


def test_uninstrumented_language_lands_in_every_list(tmp_path):
    """A language with no coverage keys at all: the any-key list AND every
    per-key list (it is missing from every total) — while its sibling's
    reports are unaffected."""
    none_dir = tmp_path / "none-out"
    none_dir.mkdir()
    (none_dir / "scan_result.json").write_text(json.dumps({"statistics": {
        "total_files": 5,  # coverage keys entirely absent
    }}))
    py_dir = _write_stats(tmp_path / "py-out", {
        "symlinks_skipped": 2, "directories_unreadable": 1,
        "symlink_examples": ["a"], "unreadable_examples": [],
    })
    cov = _collect_coverage(_coverage_result(go=str(none_dir), python=str(py_dir)))
    assert cov["languages_without_coverage_data"] == ["go"]
    assert cov["languages_without_symlinks_skipped_data"] == ["go"]
    assert cov["languages_without_directories_unreadable_data"] == ["go"]
    assert cov["symlinks_skipped"] == 2
    assert cov["directories_unreadable"] == 1


def test_fully_instrumented_zero_needs_no_disclosure(tmp_path):
    """All keys present at 0: no per-key lists (their absence means the
    totals are complete) — the trustworthy-zero shape."""
    d = _write_stats(tmp_path / "out", {
        "symlinks_skipped": 0, "directories_unreadable": 0,
        "symlink_examples": [], "unreadable_examples": [],
    })
    cov = _collect_coverage(_coverage_result(python=str(d)))
    assert cov["symlinks_skipped"] == 0
    assert cov["languages_without_coverage_data"] == []
    for k in _COVERAGE_COUNT_KEYS:
        assert f"languages_without_{k}_data" not in cov


def test_mixed_aggregate_sums_only_carrying_languages(tmp_path):
    """The Swift-before-fix partial shape beside a fully-instrumented
    language: each total counts only its carrying languages."""
    py_dir = _write_stats(tmp_path / "py-out", {
        "symlinks_skipped": 2, "directories_unreadable": 7,
    })
    swift_dir = _write_stats(tmp_path / "swift-out", {
        "directories_unreadable": 1,  # the partial shape
    })
    cov = _collect_coverage(_coverage_result(python=str(py_dir), swift=str(swift_dir)))
    assert cov["symlinks_skipped"] == 2  # python's; swift contributes nothing
    assert cov["directories_unreadable"] == 8  # 7 + 1: both reported it
    assert cov["languages_without_symlinks_skipped_data"] == ["swift"]
    assert "languages_without_directories_unreadable_data" not in cov
    assert "swift" not in cov["languages_without_coverage_data"]


# ---------------------------------------------------------------------------
# the template + the drift guards
# ---------------------------------------------------------------------------

def test_summary_template_teaches_the_per_key_disclosure():
    """The LLM-rendered summary must carry the caveat, or the disclosure is
    invisible in the human deliverable (the undisclosed zero reborn)."""
    src = (PROJECT_ROOT / "report" / "prompts" / "summary.txt").read_text()
    assert "languages_without" in src
    assert "unknown, not zero" in src


def test_generated_list_names_cover_the_count_tuple(tmp_path):
    """The drift guard: for EVERY count key in the tuple, a language
    emitting all the OTHERS but not it lands in exactly that key's list.

    If the tuple grows without the disclosure following (the drift class
    this guards), the new key's case fails here — the generator and the
    public contract cannot silently diverge. (The #307 test-skip list is
    a separate hand-written regime and must not collide: a tuple entry
    literally named `coverage` or `test_skip` would — asserted absent.)
    """
    assert "coverage" not in _COVERAGE_COUNT_KEYS
    assert not any(k.startswith("test_") for k in _COVERAGE_COUNT_KEYS)
    # a count key named like an example key would be shadowed by the
    # **examples merge in the emission dict
    from core.scanner import _COVERAGE_EXAMPLE_KEYS
    assert not (set(_COVERAGE_COUNT_KEYS) & set(_COVERAGE_EXAMPLE_KEYS))
    for missing in _COVERAGE_COUNT_KEYS:
        stats = {k: 1 for k in _COVERAGE_COUNT_KEYS if k != missing}
        d = _write_stats(tmp_path / f"out-{missing}", stats)
        cov = _collect_coverage(_coverage_result(python=str(d)))
        assert cov[f"languages_without_{missing}_data"] == ["python"], (
            f"a language missing only {missing!r} must land in exactly that "
            f"key's list; got {cov}")
