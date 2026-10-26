"""#707: a multi-language scan's reachability figures are per-language, not
one language's slice labelled scan-wide.

PR #251's "Scope honesty" disclosed it verbatim: "the merged dataset.json
carries only the first-parsed language's record (dataset_merge spreads
first.metadata); this reads that record and does not yet do full per-language
accounting — deferred to a follow-up." No issue was opened until #707.

The consequence on a two-language scan: ``pipeline_stats.reachable_units`` is
language A's kept count while ``total_units`` spans A+B; the derived
``reachability_reduction_percentage`` describes A's slice while labelled
scan-wide; ``reachability_filter_applied`` reads true from A's record even
when B ran unfiltered.

The fix (the issue's own direction): the merge carries each language's
``reachability_filter`` record into ``metadata.per_language[lang]``; the
reporter's reader sums the kept counts across languages when the per-language
block is present — an UNFILTERED language (no record) contributes its whole
unit count to both sides (its units are all reachable), so the numerator's
language scope always matches the denominator's.

The falsifier (authored at filing): "a two-language scan whose
pipeline_output.json reachability figures are per-language, or whose
reachable_units denominator matches its numerator's language scope."
"""

import json
import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_CORE_ROOT))

import core.dataset_merge as _prod_merge  # noqa: E402
import core.reporter as _prod_reporter  # noqa: E402

assert _prod_merge.merge_datasets is not None  # the prod merge
assert _prod_reporter._load_reachability_metadata is not None  # the prod reader


def _dataset(lang: str, units: int, rf: dict | None) -> dict:
    """A minimal per-language dataset with an optional reachability record."""
    return {
        "name": "repo",
        "units": [
            {"id": f"src_{lang}_{i}.py:fn", "language": lang, "unit_type": "function"}
            for i in range(units)
        ],
        "statistics": {"total_units": units},
        "metadata": ({"reachability_filter": rf} if rf is not None else {}),
    }


def _rf(kept: int, original: int, warning: str = "the A filter record") -> dict:
    return {
        "reachable_units": kept,
        "original_units": original,
        "reduction_percentage": round(100 * (1 - kept / original), 1) if original else 0,
        "warning": warning,
    }


class _Outcome:
    """A minimal successful parse outcome (the merge reads .ok, .language,
    .dataset_path, .output_dir)."""
    def __init__(self, lang: str, dataset_path: str):
        self.ok = True
        self.language = lang
        self.dataset_path = dataset_path
        self.output_dir = ""


def _merge(tmp_path, langs: list[tuple[str, int, dict | None]]):
    """Run the PROD merge over per-language datasets; returns the merged dict."""
    outcomes = []
    for lang, units, rf in langs:
        p = tmp_path / f"ds_{lang}.json"
        p.write_text(json.dumps(_dataset(lang, units, rf)))
        outcomes.append(_Outcome(lang, str(p)))
    out = tmp_path / "merged.json"
    _prod_merge.merge_datasets(outcomes, str(out))
    return json.loads(out.read_text())


# --- the merge half: the per-language records carried ---

def test_the_merge_carries_each_languages_record(tmp_path):
    """The merge no longer drops a language's reachability record: each
    language's dataset record lands under metadata.per_language[lang]."""
    assert hasattr(_prod_merge, "merge_datasets"), "the prod merge is missing"
    merged = _merge(tmp_path, [
        ("python", 10, _rf(4, 10)),
        ("javascript", 6, _rf(3, 6)),
    ])
    pl = merged["metadata"]["per_language"]
    assert pl["python"].get("reachability_filter", {}).get("reachable_units") == 4, (
        f"python's record lost: {pl['python']}")
    assert pl["javascript"].get("reachability_filter", {}).get("reachable_units") == 3, (
        f"javascript's record lost: {pl['javascript']}")


def test_the_merge_keeps_the_legacy_top_level_record(tmp_path):
    """The first language's record still spreads to the top level (the
    single-language readers + old consumers unchanged)."""
    merged = _merge(tmp_path, [("python", 10, _rf(4, 10))])
    assert merged["metadata"]["reachability_filter"]["reachable_units"] == 4


def test_an_unfiltered_language_has_no_record(tmp_path):
    assert hasattr(_prod_merge, "merge_datasets"), "the prod merge is missing"
    merged = _merge(tmp_path, [
        ("python", 10, _rf(4, 10)),
        ("javascript", 6, None),
    ])
    pl = merged["metadata"]["per_language"]
    assert "reachability_filter" not in pl["javascript"], (
        "an unfiltered language must not gain a fabricated record")


# --- the reader half: the sum across languages ---

def _scan_dir(tmp_path, merged: dict) -> str:
    p = tmp_path / "dataset.json"
    p.write_text(json.dumps(merged))
    return str(tmp_path)


def test_the_reader_sums_kept_across_languages(tmp_path):
    """THE #707 falsifier: two languages, both filtered — the scan-wide
    reachable_units is the SUM of the kept counts (7 = 4 + 3), and the
    original_units the sum of the originals (16 = 10 + 6); the reduction
    percentage describes the whole scan."""
    merged = _merge(tmp_path, [
        ("python", 10, _rf(4, 10)),
        ("javascript", 6, _rf(3, 6)),
    ])
    assert hasattr(_prod_reporter, "_load_reachability_metadata"), (
        "the prod reader is missing")
    rf = _prod_reporter._load_reachability_metadata(_scan_dir(tmp_path, merged))
    assert rf is not None
    assert rf["reachable_units"] == 7, f"one language's slice leaked: {rf}"
    assert rf["original_units"] == 16, rf
    assert rf["reduction_percentage"] == round(100 * (1 - 7 / 16), 1), rf
    assert rf.get("per_language") == {"python": 4, "javascript": 3}, (
        f"the per-language decomposition missing: {rf}")


def test_an_unfiltered_language_contributes_its_whole_count(tmp_path):
    """A language with NO record ran unfiltered — its units are all
    reachable: it contributes its unit count to BOTH sides, and the
    scan-wide figures keep numerator == denominator scope."""
    merged = _merge(tmp_path, [
        ("python", 10, _rf(4, 10)),
        ("javascript", 6, None),
    ])
    assert hasattr(_prod_reporter, "_load_reachability_metadata"), (
        "the prod reader is missing")
    rf = _prod_reporter._load_reachability_metadata(_scan_dir(tmp_path, merged))
    assert rf is not None
    assert rf["reachable_units"] == 4 + 6, (
        f"the unfiltered language vanished from the numerator: {rf}")
    assert rf["original_units"] == 10 + 6, rf
    assert rf.get("per_language") == {"python": 4, "javascript": 6}, rf


def test_the_artifact_carries_the_per_language_decomposition(tmp_path):
    """The falsifier's FIRST disjunct: the pipeline_output's reachability
    figures ARE per-language — the scan-wide sums in pipeline_stats plus
    the additive reachability_per_language map naming each language's own
    kept count (the fable-r1 F7 catch: the decomposition previously died
    at the reader, never reaching the artifact)."""
    from utilities.file_io import write_json
    from core.reporter import build_pipeline_output
    assert hasattr(_prod_reporter, "build_pipeline_output"), (
        "the prod build is missing")
    merged = _merge(tmp_path, [
        ("python", 10, _rf(4, 10)),
        ("javascript", 6, _rf(3, 6)),
    ])
    _scan_dir(tmp_path, merged)  # the reader looks for <scan_dir>/dataset.json
    results = {
        "dataset": "repo",
        "code_by_route": {},
        "metrics": {},
        "confirmed_findings": [],
    }
    rp = tmp_path / "results.json"
    write_json(rp, results)
    op = tmp_path / "po.json"
    build_pipeline_output(str(rp), str(op), language="python", repo_name="t/r")
    import json as _json
    data = _json.loads(op.read_text())
    ps = data["pipeline_stats"]
    assert ps["reachable_units"] == 7, ps
    assert ps["original_units"] == 16, ps
    assert ps.get("reachability_per_language") == {"python": 4, "javascript": 3}, (
        f"the decomposition did not reach the artifact: {ps}")


def test_no_fabricated_zeroes_for_keys_no_record_carried(tmp_path):
    """The fable-r1 F1 pin: a key is emitted only when at least one
    language's record CARRIED it — records with prune telemetry but no
    #602 baseline decomposition must not gain fabricated zeros."""
    rf_full = _rf(4, 10)
    rf_full["pruned_orphan_count"] = 2
    merged = _merge(tmp_path, [
        ("python", 10, rf_full),
        ("javascript", 6, _rf(3, 6)),
    ])
    rf = _prod_reporter._load_reachability_metadata(_scan_dir(tmp_path, merged))
    assert rf is not None
    assert rf.get("pruned_orphan_count") == 2, rf
    assert "structural_reachable_units" not in rf, (
        f"a fabricated zero leaked: {rf}")
    assert "units_newly_reachable" not in rf, (
        f"a fabricated zero leaked: {rf}")


def test_both_languages_advisories_forward_with_attribution(tmp_path):
    """The fable-r1 F2 pin: every language's advisory reaches the warnings
    channel, ATTRIBUTED (a first-wins forward re-opened the #323/#520
    misdiagnosis vector for language B)."""
    a = _rf(4, 10, warning="python warned")
    a["blackout_advisory"] = "python's advisory"
    b = _rf(3, 6, warning="javascript warned")
    b["blackout_advisory"] = "javascript's advisory"
    merged = _merge(tmp_path, [("python", 10, a), ("javascript", 6, b)])
    rf = _prod_reporter._load_reachability_metadata(_scan_dir(tmp_path, merged))
    # the advisory key carries the ATTRIBUTED join (both languages, never
    # first-wins); the consumer forwards it standalone into the artifact's
    # reachability_warnings — once, never double-appended (the fable-r2 N2
    # catch folded them into `warning` too, duplicating every advisory)
    assert "python: python's advisory" in (rf.get("blackout_advisory") or ""), rf
    assert "javascript: javascript's advisory" in (rf.get("blackout_advisory") or ""), rf
    assert "python: python's advisory" not in (rf.get("warning") or ""), (
        f"the advisory double-folded into the composite warning: {rf}")


def test_mixed_levels_claim_no_scan_wide_level(tmp_path):
    """The fable-r1 F3 pin: records with DISAGREEING effective levels —
    no single scan-wide level claimed (a warning instead), the scanner's
    own refilter-aggregate precedent."""
    a = _rf(4, 10)
    a["effective_processing_level"] = "reachable"
    b = _rf(3, 6)
    b["effective_processing_level"] = "codeql"
    merged = _merge(tmp_path, [("python", 10, a), ("javascript", 6, b)])
    rf = _prod_reporter._load_reachability_metadata(_scan_dir(tmp_path, merged))
    assert "effective_processing_level" not in rf, (
        f"a mixed-level scan claimed one level: {rf}")
    assert any("Mixed effective processing levels" in str(w)
               for w in (rf.get("warnings") or [])), rf


def test_a_malformed_record_is_named_not_silently_miscounted(tmp_path):
    """The fable-r1 F4 pin: a record without an integer reachable_units —
    the language is NAMED in a warning and treated as unfiltered (its units
    both sides), never denominator-only fabricated pruning."""
    broken = {"original_units": 10}  # no reachable_units
    merged = _merge(tmp_path, [
        ("python", 10, broken),
        ("javascript", 6, _rf(3, 6)),
    ])
    rf = _prod_reporter._load_reachability_metadata(_scan_dir(tmp_path, merged))
    assert rf is not None
    # python's 10 units on BOTH sides (unfiltered), javascript's 3 kept
    assert rf["reachable_units"] == 10 + 3, rf
    assert rf["original_units"] == 10 + 6, rf
    assert any("malformed" in str(w) for w in (rf.get("warnings") or [])), rf


def test_a_top_level_aggregate_outranks_the_parse_time_records(tmp_path):
    """The fable-r1 F6 pin: a top-level record that already carries its own
    per_language block IS the scanner's newer scan-wide aggregate — it wins
    over the merge's parse-time per-language records."""
    merged = _merge(tmp_path, [
        ("python", 10, _rf(4, 10)),
        ("javascript", 6, _rf(3, 6)),
    ])
    # the scanner's post-LLM aggregate stamped on top (newer + scan-wide)
    merged["metadata"]["reachability_filter"] = {
        "reachable_units": 11, "original_units": 16,
        "per_language": {"python": 5, "javascript": 6},
    }
    rf = _prod_reporter._load_reachability_metadata(_scan_dir(tmp_path, merged))
    assert rf is not None and rf["reachable_units"] == 11, (
        f"the stale parse-time sum outranked the newer aggregate: {rf}")


def test_the_fallback_branch_reads_the_top_level_record(tmp_path):
    """The fable-r1 F7(b) pin: a per_language block with NO records (all
    languages unfiltered) + a top-level record — the top-level read (the
    pre-#707 fallback branch, untested until this pin)."""
    merged = _merge(tmp_path, [
        ("python", 10, None),
        ("javascript", 6, None),
    ])
    merged["metadata"]["reachability_filter"] = _rf(9, 16)
    rf = _prod_reporter._load_reachability_metadata(_scan_dir(tmp_path, merged))
    assert rf is not None and rf["reachable_units"] == 9, (
        f"the fallback branch drifted: {rf}")


def test_the_scanner_shape_per_language_projects_kept_ints(tmp_path):
    """The fable-r2 N1 pin: the scanner's refilter aggregate carries
    per_language values as FULL RECORDS — the artifact's
    reachability_per_language contract is {lang: kept-int}, so the reader
    projects the kept counts (never the raw record dicts)."""
    merged = _merge(tmp_path, [
        ("python", 10, _rf(4, 10)),
        ("javascript", 6, _rf(3, 6)),
    ])
    # the scanner's REAL shape: per_language values are records
    merged["metadata"]["reachability_filter"] = {
        "reachable_units": 11, "original_units": 16,
        "per_language": {
            "python": {"reachable_units": 5, "unfilterable": True},
            "javascript": {"reachable_units": 6, "unfilterable": True},
        },
    }
    rf = _prod_reporter._load_reachability_metadata(_scan_dir(tmp_path, merged))
    assert rf is not None
    assert rf["reachable_units"] == 11, rf
    assert rf["per_language"] == {"python": 5, "javascript": 6}, (
        f"the record dicts leaked into the decomposition: {rf['per_language']}")


def test_all_records_malformed_names_the_languages(tmp_path):
    """The fable-r2 N6 pin: EVERY record malformed — no aggregate is
    possible; the languages are NAMED (never a silent discard) and their
    units counted as fully reachable on both sides."""
    # the hand-built shape (the merge's first-spread would put python's
    # malformed record at the top level — the N6 branch fires when the
    # top-level record is ABSENT and only per-language malformed records
    # remain)
    merged = {
        "metadata": {
            "per_language": {
                "python": {"units": 10,
                          "reachability_filter": {"original_units": 10}},
                "javascript": {"units": 6,
                               "reachability_filter": {"original_units": 6}},
            },
        },
    }
    rf = _prod_reporter._load_reachability_metadata(_scan_dir(tmp_path, merged))
    assert rf is not None, "the malformed-only scan silently returned None"
    assert rf["reachable_units"] == 16 and rf["original_units"] == 16, rf
    ws = " ".join(rf.get("warnings") or [])
    assert "python" in ws and "javascript" in ws and "malformed" in ws, rf


def test_the_scanner_path_artifact_carries_the_projected_ints(tmp_path):
    """The astra end-to-end pin (the scanner path): the scanner's refilter
    aggregate — record-dict per_language values + DELIBERATELY CONFLICTING
    parse-time records — through the REAL build_pipeline_output: the
    artifact's reachability_per_language is the PROJECTED kept-ints, the
    scan-wide figures the authoritative sums, and NO record dict leaks."""
    import json as _json
    from utilities.file_io import write_json
    from core.reporter import build_pipeline_output
    merged = _merge(tmp_path, [
        ("python", 10, _rf(4, 10)),
        ("javascript", 6, _rf(3, 6)),
    ])
    # the scanner's newer aggregate, conflicting with the parse-time records
    merged["metadata"]["reachability_filter"] = {
        "reachable_units": 11, "original_units": 16,
        "per_language": {
            "python": {"reachable_units": 5, "unfilterable": True},
            "javascript": {"reachable_units": 6, "unfilterable": True},
        },
    }
    _scan_dir(tmp_path, merged)
    rp = tmp_path / "results.json"
    write_json(rp, {"dataset": "repo", "code_by_route": {}, "metrics": {},
                    "confirmed_findings": []})
    op = tmp_path / "po.json"
    build_pipeline_output(str(rp), str(op), language="python", repo_name="t/r")
    ps = _json.loads(op.read_text())["pipeline_stats"]
    assert ps["reachable_units"] == 11, ps
    assert ps["original_units"] == 16, ps
    assert ps.get("reachability_per_language") == {"python": 5, "javascript": 6}, (
        f"the projected ints did not reach the artifact: {ps}")
    assert all(isinstance(v, int) for v in ps["reachability_per_language"].values()), (
        f"a record dict leaked: {ps}")


def test_language_bs_advisory_reaches_the_artifact_warnings(tmp_path):
    """The astra end-to-end pin (the advisory route): the ONLY advisory on
    language B — through the REAL build_pipeline_output, B's advisory
    reaches the artifact's reachability_warnings, ATTRIBUTED, exactly once
    (never first-wins, never double-appended)."""
    import json as _json
    from utilities.file_io import write_json
    from core.reporter import build_pipeline_output
    b = _rf(3, 6, warning="javascript warned")
    b["blackout_advisory"] = "javascript's advisory"
    merged = _merge(tmp_path, [
        ("python", 10, _rf(4, 10, warning="python warned")),
        ("javascript", 6, b),
    ])
    _scan_dir(tmp_path, merged)
    rp = tmp_path / "results.json"
    write_json(rp, {"dataset": "repo", "code_by_route": {}, "metrics": {},
                    "confirmed_findings": []})
    op = tmp_path / "po.json"
    build_pipeline_output(str(rp), str(op), language="python", repo_name="t/r")
    ws = _json.loads(op.read_text())["pipeline_stats"]["reachability_warnings"]
    joined = " ".join(ws)
    assert "javascript: javascript's advisory" in joined, (
        f"language B's advisory never reached the artifact: {ws}")
    assert joined.count("javascript: javascript's advisory") == 1, (
        f"the advisory double-appended: {ws}")


def test_the_single_language_fallback_reads_the_legacy_record(tmp_path):
    """A single-language dataset (no per_language block, or the block without
    records): today's single-record read, unchanged."""
    merged = _merge(tmp_path, [("python", 10, _rf(4, 10))])
    # the single-language merge has no per_language records — the top-level
    # record is the read
    rf = _prod_reporter._load_reachability_metadata(_scan_dir(tmp_path, merged))
    assert rf is not None and rf["reachable_units"] == 4, rf


def test_the_warnings_forward_from_every_language(tmp_path):
    """The per-language warnings/advisories forward from ALL languages (a
    one-language-only forward would hide the other's degraded filter)."""
    merged = _merge(tmp_path, [
        ("python", 10, _rf(4, 10, warning="python's filter warned")),
        ("javascript", 6, _rf(3, 6, warning="javascript's filter warned")),
    ])
    assert hasattr(_prod_reporter, "_load_reachability_metadata"), (
        "the prod reader is missing")
    rf = _prod_reporter._load_reachability_metadata(_scan_dir(tmp_path, merged))
    ws = rf.get("warnings") or []
    assert "python's filter warned" in ws and "javascript's filter warned" in ws, (
        f"a language's warning dropped: {rf}")


def test_the_applied_flag_means_any_language_filtered(tmp_path):
    """reachability_filter_applied is true when ANY language's record exists
    (and the unfiltered-neighbor nuance is carried as a warning, so the
    reader's consumer can surface the mixed scan)."""
    merged = _merge(tmp_path, [
        ("python", 10, _rf(4, 10)),
        ("javascript", 6, None),
    ])
    rf = _prod_reporter._load_reachability_metadata(_scan_dir(tmp_path, merged))
    assert rf is not None
    assert any("unfiltered" in str(w).lower() for w in (rf.get("warnings") or [])), (
        f"the mixed-scan nuance missing: {rf}")
