"""#623 — the rescue schema asks the calling phase's vocabulary, and the
legacy INSUFFICIENT_CONTEXT value is one answer everywhere.

The JSON rescue schema offered a mismatched 3-value enum
(VULNERABLE|SAFE|INSUFFICIENT_CONTEXT) while the Stage-1 prompt offers
safe|protected|vulnerable|inconclusive — a rescue was a forced choice that
could change meaning (a protected/inconclusive reply forced into wrong
buckets, and a verdict the prompt never asks for). And the legacy
INSUFFICIENT_CONTEXT value hit consumers that disagreed: the summary counted
it completed (#293), resume adopted it as legal (STAGE1_VERDICTS), the
metrics fold counted it ERRORS (#427's catch-all), the recount SILENTLY
DROPPED it, and the displays had no category.

The fix: the schema's enum RENDERS from the shared STAGE1_PROMPT_FINDINGS
constant (a rescue repairs structure, never vocabulary); the legacy value
folds to inconclusive's synonym at every counting/display sink (the metrics
fold, the verify recount, the HTML/cli display reads); the row's own stored
values are NEVER rewritten (provenance; resume adoption unchanged).

RED/GREEN labeling (the honest-evidence rule): the schema change is a
PROMPT-TEXT property — the acceptor already admitted the full vocabulary at
master (STAGE1_VERDICTS + the corrector's mapping), so the rescue-runtime
rows are GUARDs (green at master, regression locks); the RED rows are the
census (the schema/prompt literals) and the counting folds (errors→
inconclusive at the fold; dropped→counted at the recount). The GUARD rows
are INTERLEAVED with the RED rows by topic (not sectioned): the five
base-green rows are the bypassable exclusion, the two rescue-runtime flows,
the #427 negative control, and the resume-adoption guard — every other row
is value-RED at the base. The 13/5 split (18 rows: 13 value-RED,
5 GUARD) is the receipt.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # libs/openant-core

from core.analyzer import _count_verdicts  # noqa: E402
from core.checkpoint import analyze_result_is_error  # noqa: E402
from utilities.json_corrector import (  # noqa: E402
    _VULN_SCHEMA, get_json_extraction_prompt)


def _stage1_prompt_findings():
    """Lazy: the constant is #623's own addition — importing it lazily keeps
    this file COLLECTABLE on the pre-fix base so the RED table is per-test,
    not a collection error."""
    from core.verdict_taxonomy import STAGE1_PROMPT_FINDINGS  # noqa: PLC0415
    return STAGE1_PROMPT_FINDINGS

LEGACY_ROW = {
    "route_key": "a.py:f", "finding": "insufficient_context",
    "verdict": "INSUFFICIENT_CONTEXT",
}


# --- T1 (RED): the prompt/schema census (D3's one-home alignment) -----------

def _schema_verdict_set():
    m = re.search(r'"verdict":\s*(.+)', _VULN_SCHEMA)
    return set(re.findall(r'"([A-Z_]+)"', m.group(1)))


def _prompt_finding_set():
    from prompts.vulnerability_analysis import get_analysis_prompt  # noqa: PLC0415
    text = get_analysis_prompt(code="def f(): pass", language="python")
    m = re.search(r'"finding":\s*(.+)', text)
    return set(re.findall(r'"([a-z_]+)"', m.group(1)))


def test_schema_asks_exactly_the_prompt_vocabulary():
    """The rescue schema's enum == the Stage-1 prompt's finding set
    (uppercased) — the drift this issue was filed over cannot return."""
    findings = _stage1_prompt_findings()
    assert _schema_verdict_set() == {f.upper() for f in findings}, (
        "the rescue schema must ask the calling phase's vocabulary")
    assert "INSUFFICIENT_CONTEXT" not in _schema_verdict_set(), (
        "the legacy value is accepted downstream but never ASKED for")


def test_prompt_offers_exactly_the_shared_constant():
    """The constant is the prompt's own vocabulary — one home, no drift."""
    findings = _stage1_prompt_findings()
    from core.verdict_taxonomy import STAGE1_VERDICTS  # noqa: PLC0415
    assert _prompt_finding_set() == set(findings), (
        "STAGE1_PROMPT_FINDINGS must be exactly the prompt's finding set")
    assert {f.upper() for f in findings} <= set(STAGE1_VERDICTS)


def test_extraction_prompt_embeds_the_aligned_enum():
    prompt = get_json_extraction_prompt("def broken_json(" * 5)
    assert "PROTECTED" in prompt and "INCONCLUSIVE" in prompt, (
        "the extraction prompt must offer the full Stage-1 vocabulary")
    assert "INSUFFICIENT_CONTEXT" not in prompt, (
        "the legacy value must no longer be a rescue CHOICE")


def test_bypassable_is_not_a_stage1_rescue_choice():
    """BYPASSABLE originates in the Stage-2 finish enum, not the Stage-1
    prompt — offering it would let a rescue UPGRADE a reply into a
    verify-only verdict."""
    assert "BYPASSABLE" not in _schema_verdict_set()


# --- T2 (GUARD, green at master): the rescue runtime accepts the vocabulary --

def test_rescued_inconclusive_verdict_flows(tmp_path, monkeypatch):
    """The acceptor path: a rescued INCONCLUSIVE verdict flows to the
    inconclusive bucket. Green at master too (STAGE1_VERDICTS already
    admitted it) — this row is the regression lock for the schema change,
    not its RED. (The corrector's contract is verdict-only out; the finding
    derivation is the analyzer's bridge — the verdict-only counting shape is
    pinned separately below.)"""
    import utilities.json_corrector as jc  # noqa: PLC0415
    monkeypatch.setattr(
        jc, "extract_json_with_llm",
        lambda binding, raw, **kw: {"verdict": "INCONCLUSIVE",
                                    "confidence": 0.4, "reasoning": "r"})
    corrector = jc.JSONCorrector(_fake_binding())
    out = corrector.attempt_correction("not json at all {{{")
    assert out["verdict"] == "INCONCLUSIVE"
    assert out["json_corrected"] is True
    counts = _count_verdicts([out])
    assert counts["inconclusive"] == 1 and counts["errors"] == 0


def test_rescued_protected_verdict_flows(tmp_path, monkeypatch):
    import utilities.json_corrector as jc  # noqa: PLC0415
    monkeypatch.setattr(
        jc, "extract_json_with_llm",
        lambda binding, raw, **kw: {"verdict": "PROTECTED",
                                    "confidence": 0.9, "reasoning": "r"})
    corrector = jc.JSONCorrector(_fake_binding())
    out = corrector.attempt_correction("still not json }}}")
    assert out["verdict"] == "PROTECTED"
    counts = _count_verdicts([out])
    assert counts["protected"] == 1 and counts["errors"] == 0


def _fake_binding():
    from types import SimpleNamespace  # noqa: PLC0415
    return SimpleNamespace(
        phase="analyze", adapter=_NoopAdapter(), model="fake-model",
        provider_name="fake")


class _NoopAdapter:
    name = "fake"
    supports_tools = True
    pricing = {"fake-model": {"input": 1.0, "output": 1.0}}

    def complete(self, **kw):
        raise AssertionError("the extraction is monkeypatched; no LLM call")


# --- T3 (RED): the metrics fold — errors -> inconclusive for the legacy value -

def test_count_verdicts_folds_legacy_value_to_inconclusive():
    counts = _count_verdicts([LEGACY_ROW])
    assert counts["inconclusive"] == 1, (
        "the legacy INSUFFICIENT_CONTEXT value is inconclusive's synonym — "
        "the #427 catch-all counted it ERRORS while #293 counted it completed")
    assert counts["errors"] == 0
    assert sum(counts.values()) == 1


def test_count_verdicts_folds_the_verdict_only_shape():
    """A verdict-only legacy row (the rescue schema's own historical shape —
    no finding key) reaches the same fold via the canonical fallback."""
    counts = _count_verdicts([{"verdict": "INSUFFICIENT_CONTEXT"}])
    assert counts["inconclusive"] == 1
    assert counts["errors"] == 0


def test_count_verdicts_keeps_the_427_garbage_class():
    """The negative control: a genuinely unrecognized verdict still buckets
    as an error — the fold narrows ONLY the legacy synonym, never the #427
    malformed-reply semantics."""
    counts = _count_verdicts([{"verdict": "SAY WHAT"}])
    assert counts["errors"] == 1
    counts = _count_verdicts([{"verdict": None, "finding": None}])
    assert counts["errors"] == 1


def test_count_verdicts_precedence_pin_both_keys_disagree():
    """The documented transient class, pinned consciously (engineer M4): a
    both-keys row {verdict: ERROR, finding: insufficient_context} counts
    inconclusive (the fold is FINDING-FIRST, like the whole counter) while
    resume still retries it (analyze_result_is_error is verdict-first,
    ERROR wins). The retried outcome replaces the row — the disagreement is
    transient by design."""
    row = {"verdict": "ERROR", "finding": "insufficient_context"}
    counts = _count_verdicts([row])
    assert counts["inconclusive"] == 1
    assert analyze_result_is_error(row) is True, (
        "resume retries the row (verdict-first, ERROR wins) — the counting "
        "fold must not change the retry semantics")


# --- T4 (RED): the verify recount — dropped -> counted -----------------------

def test_recount_folds_legacy_value_and_closes_the_partition(tmp_path):
    from core.verifier import _write_verified_results  # noqa: PLC0415
    from utilities.file_io import write_json  # noqa: PLC0415
    path = tmp_path / "results_verified.json"
    experiment = {"metrics": {"total": 1}, "results": [LEGACY_ROW],
                  "code_by_route": {}}
    write_json(path, experiment)
    _write_verified_results(path, experiment, [LEGACY_ROW], [LEGACY_ROW])
    import json  # noqa: PLC0415
    metrics = json.loads(path.read_text())["metrics"]
    assert metrics["inconclusive"] == 1, (
        "the recount previously SILENTLY DROPPED the legacy row — no "
        "bucket matched and the elif caught only ERROR")
    bucket_keys = ("vulnerable", "bypassable", "inconclusive",
                   "protected", "safe", "errors", "needs_review")
    assert sum(metrics[k] for k in bucket_keys) == metrics["total"], (
        "the #284 partition closes for the legacy row")


def test_recount_error_twin_joins_the_partition(tmp_path):
    """The twin fable's map named: a legacy half-stamped finding=='error'
    WITHOUT verdict=='ERROR' was the SAME silent drop at the recount (the
    analyzer's counter has handled exactly this twin since #316/#324)."""
    from core.verifier import _write_verified_results  # noqa: PLC0415
    from utilities.file_io import write_json  # noqa: PLC0415
    import json  # noqa: PLC0415
    row = {"route_key": "b.py:g", "finding": "error"}
    path = tmp_path / "results_verified.json"
    experiment = {"metrics": {"total": 1}, "results": [row],
                  "code_by_route": {}}
    write_json(path, experiment)
    _write_verified_results(path, experiment, [row], [row])
    metrics = json.loads(path.read_text())["metrics"]
    assert metrics["errors"] == 1


# --- T5 (GUARD): resume + summary unchanged ----------------------------------

def test_resume_still_adopts_the_legacy_row():
    """The fold is counting-level ONLY: resume keeps adopting the legacy row
    as a completed legal verdict (the #293 contract, unchanged)."""
    assert analyze_result_is_error(LEGACY_ROW) is False


def test_the_four_consumers_agree_on_the_same_row(tmp_path):
    """The D2/D4 identity shape: ONE fixture row, all consumers asserted —
    resume adopts (legal), the metrics fold counts inconclusive, the recount
    counts inconclusive, and the display reads fold the same way."""
    from core.verifier import _write_verified_results  # noqa: PLC0415
    from report.html_report import _display_verdict  # noqa: PLC0415
    from utilities.file_io import write_json  # noqa: PLC0415
    import json  # noqa: PLC0415

    assert analyze_result_is_error(LEGACY_ROW) is False          # resume
    assert _count_verdicts([LEGACY_ROW])["inconclusive"] == 1     # metrics
    path = tmp_path / "results_verified.json"
    experiment = {"metrics": {"total": 1}, "results": [LEGACY_ROW],
                  "code_by_route": {}}
    write_json(path, experiment)
    _write_verified_results(path, experiment, [LEGACY_ROW], [LEGACY_ROW])
    metrics = json.loads(path.read_text())["metrics"]
    assert metrics["inconclusive"] == 1                          # recount
    assert _display_verdict("insufficient_context") == "inconclusive"  # display
    assert _display_verdict("vulnerable") == "vulnerable"       # identity


def test_display_prepare_folds_the_listing_row():
    """The row-level listing read folds too (html_report's findings[]
    entries) — the whole display is self-consistent with the metrics."""
    from report.html_report import prepare_findings_summary  # noqa: PLC0415
    experiment = {"results": [dict(LEGACY_ROW)],
                  "code_by_route": {}}
    dataset = {"units": []}
    findings = prepare_findings_summary(experiment, dataset)
    assert findings, "the row must appear in the listing"
    assert all(f["verdict"] != "insufficient_context" for f in findings), (
        "the display read folds the legacy value to its synonym")
    assert any(f["verdict"] == "inconclusive" for f in findings)


# --- the finding-first discipline (the #331 net) ------------------------------

def test_fold_is_finding_first_never_the_raw_verdict():
    """The fold applies to the CANONICAL finding-first read — the #331
    stale-finding net is untouched: a row whose finding is the legacy value
    counts by its finding (inconclusive), regardless of the verdict key."""
    row = {"verdict": "vulnerable", "finding": "insufficient_context"}
    counts = _count_verdicts([row])
    assert counts["inconclusive"] == 1
    assert counts["vulnerable"] == 0

# --- the recount-side pins (the panel round's asks) ---------------------------

def test_recount_both_keys_error_shape_flips_to_inconclusive(tmp_path):
    """The both-keys shape {verdict: ERROR, finding: insufficient_context}:
    the recount's fold runs first (finding-first, like the analyzer's
    counter), so the row counts inconclusive while resume still retries it
    (analyze_result_is_error is verdict-first, ERROR wins) — the documented
    transient class, pinned on the recount side (the analyzer side is pinned
    above)."""
    from core.verifier import _write_verified_results  # noqa: PLC0415
    from utilities.file_io import write_json  # noqa: PLC0415
    import json  # noqa: PLC0415
    row = {"verdict": "ERROR", "finding": "insufficient_context"}
    path = tmp_path / "results_verified.json"
    experiment = {"metrics": {"total": 1}, "results": [row],
                  "code_by_route": {}}
    write_json(path, experiment)
    _write_verified_results(path, experiment, [row], [row])
    metrics = json.loads(path.read_text())["metrics"]
    assert metrics["inconclusive"] == 1
    assert analyze_result_is_error(row) is True, "resume retries it"


def test_recount_terminal_else_buckets_garbage_as_errors(tmp_path):
    """The recount's terminal else mirrors _count_verdicts' #427 catch-all:
    an unrecognized non-empty finding is an ERROR in the metrics (never a
    silent drop) — the #284 partition closes for every shape now."""
    from core.verifier import _write_verified_results  # noqa: PLC0415
    from utilities.file_io import write_json  # noqa: PLC0415
    import json  # noqa: PLC0415
    row = {"route_key": "c.py:h", "finding": "SAY WHAT", "verdict": "WEIRD"}
    path = tmp_path / "results_verified.json"
    experiment = {"metrics": {"total": 1}, "results": [row],
                  "code_by_route": {}}
    write_json(path, experiment)
    _write_verified_results(path, experiment, [row], [row])
    metrics = json.loads(path.read_text())["metrics"]
    assert metrics["errors"] == 1
    bucket_keys = ("vulnerable", "bypassable", "inconclusive",
                   "protected", "safe", "errors", "needs_review")
    assert sum(metrics[k] for k in bucket_keys) == metrics["total"]
