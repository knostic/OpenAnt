"""#316 + #324: a Stage-1 verdict every consumer recognizes, or an error.

Two producers escaped the error accounting:

* #316 -- ``_normalize_result``'s string branch mapped an UNRECOGNIZED finding
  string (``"maybe exploitable"``) to an upper-cased passthrough verdict
  (``"MAYBE EXPLOITABLE"``): not a counter bucket, not ``"ERROR"`` (so never
  retried on resume), not in the vulnerable set (so never disclosed). The
  non-string branch ten lines above already chose the opposite direction --
  map to ERROR -- with a comment naming exactly this failure. The JSON
  corrector had two twin synthesis sites (``finding.upper()``,
  ``mapping.get(..., finding.upper())``) feeding the same escape.
* #324 -- a parsed object with NEITHER ``verdict`` NOR ``finding`` (a
  JSON-shaped refusal like ``{"reasoning": ...}``) kept neither key:
  ``_cp_is_error`` adopted it as complete on resume, and ``_count_verdicts``
  counted it in no bucket (the singular ``"error"`` default can never match
  the ``"errors"`` key), so ``units_analyzed`` overstated.

The fix (both issues, one PR -- their sinks are shared): the producers stamp
the one error shape (``verdict="ERROR"``, ``finding="error"``, raw value
preserved under ``raw_finding``), and the four consumer predicates
(``analyzer._cp_is_error``, ``analyzer._count_verdicts``, the two copies in
``checkpoint.py`` -- ``load_ids`` and ``status``) fail closed on the
neither-key shape so legacy checkpoints are re-analyzed, not adopted.

Documented residuals (deliberately NOT changed here):
* an unrecognized VERDICT string (``{"verdict": "SOMETHING_WEIRD"}``) is
  still dropped by ``_count_verdicts`` -- the F13-documented gap.
* ``insufficient_context`` is mapped but has no counter bucket (a
  results-partition question, not a coverage loss -- #293 rules it
  completed).
* legacy checkpoints carrying a PRE-fix garbage verdict (finding present,
  unrecognized) are still adopted; post-fix runs never write that shape.
"""
import json
import sys
from pathlib import Path


CORE = str(Path(__file__).resolve().parents[2])  # libs/openant-core
if CORE not in sys.path:
    sys.path.insert(0, CORE)

from core.analysis_core import _normalize_result, parse_response  # noqa: E402
from core.analyzer import _count_verdicts  # noqa: E402
from core.checkpoint import StepCheckpoint, analyze_result_is_error  # noqa: E402


# ---------------------------------------------------------------------------
# A. producer -- _normalize_result / parse_response
# ---------------------------------------------------------------------------

def test_unrecognized_finding_string_routes_to_error():
    """#316: the upper-case passthrough is gone; the row lands in the error
    accounting (counted, retried on resume) with the raw text preserved."""
    out = _normalize_result({"finding": "maybe exploitable"})
    assert out["verdict"] == "ERROR"
    assert out["finding"] == "error"
    assert out["raw_finding"] == "maybe exploitable"


def test_recognized_findings_still_map():
    """Guard: the six mapped findings map exactly as before -- no ERROR, no
    raw_finding, no finding rewrite."""
    for finding, verdict in [
        ("vulnerable", "VULNERABLE"),
        ("safe", "SAFE"),
        ("protected", "PROTECTED"),
        ("bypassable", "BYPASSABLE"),
        ("inconclusive", "INCONCLUSIVE"),
        ("insufficient_context", "INSUFFICIENT_CONTEXT"),
        ("Vulnerable", "VULNERABLE"),  # casing normalization intact
    ]:
        out = _normalize_result({"finding": finding})
        assert out["verdict"] == verdict, finding
        assert "raw_finding" not in out, finding
        if finding.islower():
            assert out["finding"] == finding
        else:
            assert out["finding"].lower() == finding.lower()


def test_neither_key_stamps_error():
    """#324: a JSON-shaped refusal is not an analysis -- stamp the one error
    shape so every downstream consumer sees it."""
    out = _normalize_result({"reasoning": "cannot determine", "confidence": 0})
    assert out["verdict"] == "ERROR"
    assert out["finding"] == "error"


def test_verdict_present_passthrough_unchanged():
    """Guard: a reply that already carries a CANONICAL verdict keeps it.
    #427 closed the residual this test used to pin ("weird" passing through
    as "WEIRD" — the verdict-key asymmetry where the same garbage-reply class
    failed CLOSED for the finding key and OPEN for the verdict key): an
    unrecognized non-empty verdict now routes to the error accounting with
    the raw preserved (see test_issue427_verdict_whitelist)."""
    assert _normalize_result({"verdict": "SAFE"})["verdict"] == "SAFE"
    assert _normalize_result({"verdict": "INSUFFICIENT_CONTEXT"})["verdict"] == "INSUFFICIENT_CONTEXT"


def test_nonstring_finding_stamps_error_shape():
    """The wrinkle the fix closes: a verdict-only ERROR stamp disagrees with
    the finding-keyed consumers (_summary_callback, _count_verdicts) -- the
    non-string branch stamps BOTH keys, raw preserved."""
    out = _normalize_result({"finding": ["VULNERABLE"]})
    assert out["verdict"] == "ERROR"
    assert out["finding"] == "error"
    assert out["raw_finding"] == ["VULNERABLE"]


def test_parse_response_garbage_finding_is_error_accounted():
    """End-to-end through the real parse: the issue's executed example."""
    out = parse_response('{"finding": "maybe exploitable", "reasoning": "unclear"}')
    assert out["verdict"] == "ERROR"
    assert out["finding"] == "error"


# ---------------------------------------------------------------------------
# B. consumers -- _count_verdicts / _cp_is_error / checkpoint mirrors
# ---------------------------------------------------------------------------

def test_count_verdicts_neither_key_counts_as_error():
    """#324: the neither-key row is partitioned into errors, not dropped."""
    rows = [
        {"finding": "vulnerable", "verdict": "VULNERABLE"},
        {"verdict": "ERROR"},
        {"reasoning": "cannot determine"},  # neither key -- was counted nowhere
    ]
    counts = _count_verdicts(rows)
    assert counts["errors"] == 2
    assert sum(counts.values()) == len(rows)  # the partition closes


def test_count_verdicts_unrecognized_verdict_now_counts_in_errors():
    """#427 (wave r1): the F13-documented gap CLOSED — this pin existed so a
    future fix would update it consciously. An unrecognized VERDICT string
    is a malformed model reply: the error bucket (the partition reconciles,
    and the sink-side analyze_result_is_error agrees so resume retries it)."""
    rows = [{"verdict": "SOMETHING_WEIRD"}]
    counts = _count_verdicts(rows)
    assert counts["errors"] == 1
    assert sum(counts.values()) == 1


def test_count_verdicts_producer_error_shape_counts():
    """The producer's new output shape lands in errors via the verdict arm."""
    rows = [{"finding": "error", "verdict": "ERROR", "raw_finding": "maybe exploitable"}]
    counts = _count_verdicts(rows)
    assert counts["errors"] == 1


def test_cp_is_error_neither_key_retried():
    """#324: a neither-key checkpoint is a malformed reply, not a completed
    unit — re-analyzed, never adopted. Exercises the real module-level
    predicate (hoisted from run() so this is testable, mirroring
    checkpoint.py's copies)."""
    from core.analyzer import _cp_is_error

    assert _cp_is_error({"result": {"reasoning": "cannot determine"}}) is True
    assert _cp_is_error({"result": {"verdict": "VULNERABLE"}}) is False
    # #427 (wave r1): a garbage-verdict row — including the ON-DISK
    # population the pre-fix producer persisted — is RETRIED, never
    # adopted (the sink-side closure; post-fix runs never write the shape).
    assert _cp_is_error(
        {"result": {"finding": "maybe exploitable", "verdict": "MAYBE EXPLOITABLE"}}
    ) is True


def test_null_and_empty_verdicts_are_the_error_shape():
    """Wave finding (bug-hunt): {"verdict": null} is the #324 refusal with
    the key present — it must be treated as no verdict, not adopted as
    complete / crashed on. Pre-fix, _count_verdicts' eager .lower() default
    raised AttributeError AFTER the full Stage-1 spend."""
    # producer: null verdict + valid finding -> the finding is the substance
    out = _normalize_result({"verdict": None, "finding": "vulnerable"})
    assert out["verdict"] == "VULNERABLE"
    # producer: null verdict alone -> the error shape
    out = _normalize_result({"verdict": None, "reasoning": "cannot determine"})
    assert out["verdict"] == "ERROR" and out["finding"] == "error"
    # producer: empty-string verdict -> the error shape
    out = _normalize_result({"verdict": "   "})
    assert out["verdict"] == "ERROR" and out["finding"] == "error"
    # counter: the crash shapes are now partitioned, not raised
    counts = _count_verdicts([
        {"verdict": None, "finding": "vulnerable"},  # counted via finding
        {"verdict": None},                           # was an AttributeError
        {"verdict": ""},                             # was a silent drop
    ])
    assert counts["vulnerable"] == 1
    assert counts["errors"] == 2
    # predicate: not adopted as complete
    from core.analyzer import _cp_is_error

    assert _cp_is_error({"result": {"verdict": None}}) is True


def test_count_verdicts_fallback_shapes_preserved():
    """Guard: the pre-fix partition semantics for ordinary shapes hold."""
    counts = _count_verdicts([
        {"verdict": "SAFE"},             # finding falls back to verdict
        {"finding": "safe"},             # finding direct
        {"verdict": "SOMETHING_WEIRD"},  # #427: the error bucket now
    ])
    assert counts["safe"] == 2
    assert counts["errors"] == 1
    assert sum(counts.values()) == 3


def _write_checkpoint(tmp_path, rows):
    """Write analyze-style checkpoint rows; returns the manager (dir built in)."""
    ck = StepCheckpoint("analyze", str(tmp_path))
    for uid, result in rows:
        ck.save(uid, {"id": uid, "result": result})
    return ck


def test_load_ids_skips_neither_key(tmp_path):
    """Mirror 1: the resume-completed set must not adopt a neither-key row."""
    ck = _write_checkpoint(tmp_path, [
        ("good", {"verdict": "VULNERABLE", "finding": "vulnerable"}),
        ("neither", {"reasoning": "cannot determine"}),
        ("err", {"verdict": "ERROR"}),
    ])
    ids = ck.load_ids(skip_errors=True)
    assert "good" in ids
    assert "err" not in ids
    assert "neither" not in ids  # #324: retried, not adopted


def test_status_counts_neither_key_as_analysis_error(tmp_path):
    """Mirror 2: checkpoint status classifies the neither-key row as an
    analysis error (visible in error accounting, not completed)."""
    ck = _write_checkpoint(tmp_path, [
        ("good", {"verdict": "VULNERABLE", "finding": "vulnerable"}),
        ("neither", {"reasoning": "cannot determine"}),
    ])
    status = StepCheckpoint.status(ck.dir)
    assert status["completed"] == 1
    assert status["errors"] == 1
    assert status["error_breakdown"].get("analysis_error") == 1


def test_load_ids_keeps_non_analyze_phases(tmp_path):
    """Wave finding (all three reviewers): the neither-key arm must be
    scoped to analyze rows — verify/enhance/dynamic-test checkpoints carry
    no "result" key, and load_ids' four-phase contract must hold."""
    # verify shape (finding_verifier.py:931-935)
    ck_v = StepCheckpoint("verify", str(tmp_path / "v"))
    ck_v.save("u1", {"id": "u1", "verification": {"agree": True, "correct_finding": "safe"},
                     "finding": "safe", "verification_note": "n"})
    assert ck_v.load_ids(skip_errors=True) == {"u1"}
    # enhance shape (context_enhancer.py:985-989)
    ck_e = StepCheckpoint("enhance", str(tmp_path / "e"))
    ck_e.save("u2", {"id": "u2", "context_key": "llm_context",
                     "llm_context": {"ok": True}})
    assert ck_e.load_ids(skip_errors=True) == {"u2"}
    # dynamic-test shape (models.py:42-58)
    ck_d = StepCheckpoint("dynamic-test", str(tmp_path / "d"))
    ck_d.save("u3", {"id": "u3", "finding_id": "f1", "status": "SUCCESS"})
    assert ck_d.load_ids(skip_errors=True) == {"u3"}
    # status() agrees on a verify row
    st = StepCheckpoint.status(ck_v.dir)
    assert st["completed"] == 1 and st["errors"] == 0


def test_summary_seed_agrees_with_adoption(tmp_path):
    """Wave round-2 finding (both reviewers, confirmed by execution): the
    seed must count ONLY what adoption keeps. An errored row is re-analyzed
    and its outcome is owned by _summary_callback — seeding it too
    double-counts (completed + errors > total). This drives the REAL
    extracted seed (_seed_summary) over REAL checkpoint files and replays
    the resume arithmetic end to end."""
    from core.analyzer import _seed_summary

    ck = _write_checkpoint(tmp_path, [
        ("good", {"verdict": "SAFE", "finding": "safe"}),
        ("neither", {"reasoning": "cannot determine"}),  # re-analyzed
        ("err", {"verdict": "ERROR", "finding": "error"}),  # re-analyzed
    ])
    existing = ck.load()
    seed = _seed_summary(existing)
    # adoption: only the good row is kept; the other two are re-processed
    adopted = {uid for uid, cp in existing.items()
               if not analyze_result_is_error(cp.get("result") or {})}
    assert adopted == {"good"}
    assert seed["completed"] == 1  # only what adoption keeps
    # resume: the two re-analyzed units' outcomes are counted by the
    # callback (say one succeeds, one errors again)
    completed = seed["completed"] + 1
    errors = 0 + 1
    assert completed + errors == 3  # == total: the invariant holds
    # usage accumulates over ALL rows (the spend happened)
    # (usage seeding is exercised below with a usage-bearing checkpoint)
    ck3 = StepCheckpoint("analyze", str(tmp_path / "s"))
    ck3.save("u", {"id": "u", "result": {"verdict": "SAFE", "finding": "safe"},
                   "usage": {"input_tokens": 10, "output_tokens": 5, "cost_usd": 0.25,
                             "unpriced_models": ["m1"]}})
    seed3 = _seed_summary(ck3.load())
    assert seed3["completed"] == 1
    assert seed3["input_tokens"] == 10 and seed3["output_tokens"] == 5
    assert seed3["cost_usd"] == 0.25
    assert seed3["unpriced_models"] == {"m1"}


def test_analyze_result_is_error_none_and_corrupt_shapes():
    """Wave round-2 (bug-hunt): a hand-edited "result": null must not crash
    the classifier (status() is the Go CLI's checkpoint-status source)."""
    assert analyze_result_is_error(None) is True
    assert analyze_result_is_error({"verdict": "SAFE", "finding": "safe"}) is False


def test_counter_agrees_with_predicate_on_error_finding():
    """Wave round-2 (bug-hunt): a legacy half-stamped row (finding=="error",
    no verdict) — the counter and the predicate must agree it is an error."""
    counts = _count_verdicts([{"finding": "error"}])
    assert counts["errors"] == 1


def test_both_keys_disagreement_residual_pinned():
    """Wave round-2 finding, UPDATED by #427's round (the pin existed for
    this): a row with BOTH keys present but disagreeing
    ({"verdict": "SAFE", "finding": "garbage"}) — the verdict short-circuits
    the finding branch (the producer leaves the disagreement; #331 owns the
    stage-1 producer's co-write), and the finding-first counter now buckets
    the unrecognized finding as an ERROR (the #427 partition closure — the
    row was previously dropped from every bucket). Resume adopts it (the
    VERDICT is canonical — the transient-disagreement semantics in
    analyze_result_is_error's docstring: the retried outcome replaces the
    row only if the verdict is also bad)."""
    out = _normalize_result({"verdict": "SAFE", "finding": "garbage"})
    assert out["verdict"] == "SAFE" and out["finding"] == "garbage"
    counts = _count_verdicts([out])
    assert counts["errors"] == 1  # the unrecognized finding buckets as error
    assert analyze_result_is_error(out) is False  # canonical verdict: adopted


# ---------------------------------------------------------------------------
# C. the JSON corrector's two synthesis sites
# ---------------------------------------------------------------------------

class _ToolAdapter:
    name = "anthropic"
    supports_tools = True

    def complete(self, **kwargs):  # pragma: no cover - never called
        raise AssertionError("adapter.complete must not be called here")

    def validate(self, model):  # pragma: no cover
        pass


def _tool_binding():
    from utilities.llm import PhaseBinding

    return PhaseBinding(
        phase="analyze",
        adapter=_ToolAdapter(),
        model="claude-test",
        provider_name="anthropic",
    )


def _correct(raw_response, extracted, monkeypatch):
    """Run attempt_correction with a stubbed extractor LLM (monkeypatched —
    a bare assignment would leak module state into later tests)."""
    def fake_simple_text(binding, prompt, **kwargs):
        return json.dumps(extracted)

    monkeypatch.setattr(_json_corrector, "simple_text", fake_simple_text)
    return _json_corrector.JSONCorrector(_tool_binding()).attempt_correction(raw_response)


import utilities.json_corrector as _json_corrector  # noqa: E402


def test_corrector_unrecognized_finding_becomes_error(monkeypatch):
    """#316 site (b): the mapping default is ERROR, so a correction that
    recovers only a garbage finding is reported as a FAILED correction."""
    out = _correct("prose with no json", {"finding": "maybe exploitable", "reasoning": "r"}, monkeypatch)
    assert out.get("verdict") == "ERROR"
    assert out.get("json_corrected") is False


def test_corrector_recognized_finding_still_recovers(monkeypatch):
    """Guard: a real recovery still passes its gate."""
    out = _correct("prose with no json", {"finding": "vulnerable", "reasoning": "r"}, monkeypatch)
    assert out.get("verdict") == "VULNERABLE"
    assert out.get("json_corrected") is True


def test_corrector_offenum_correct_finding_becomes_error(monkeypatch):
    """#316 site (a): correct_finding maps through the verify enum; anything
    off-enum is ERROR (rejected), not a synthesized verdict. Pins
    json_corrected=False so the ERROR comes from the new failure gate, not
    the canonical error dict's fall-through."""
    out = _correct("prose with no json", {"agree": False, "correct_finding": "not sure, maybe"}, monkeypatch)
    assert out.get("verdict") == "ERROR"
    assert out.get("json_corrected") is False


def test_corrector_enum_correct_finding_still_recovers(monkeypatch):
    """Guard: the verify-enum values still derive a verdict (site a)."""
    out = _correct("prose with no json", {"agree": False, "correct_finding": "vulnerable"}, monkeypatch)
    assert out.get("verdict") == "VULNERABLE"


# ---------------------------------------------------------------------------
# D. context_corrector's private twin
# ---------------------------------------------------------------------------

def test_context_corrector_unrecognized_finding_routes_to_error():
    """The third _normalize_result copy (the insufficient-context re-analysis
    path) inherits the same treatment."""
    import utilities.context_corrector as _context_corrector

    out = _context_corrector.ContextCorrector._normalize_result({"finding": "maybe exploitable"})
    assert out["verdict"] == "ERROR"


def test_context_corrector_twin_full_mirror():
    """Wave finding (bug-hunt): the twin claims parity with
    analysis_core._normalize_result — pin the FULL contract, not just the
    verdict (co-stamped finding, raw preserved, non-string guard, the
    neither-key arm, null-verdict validity)."""
    import utilities.context_corrector as _context_corrector

    nr = _context_corrector.ContextCorrector._normalize_result
    out = nr({"finding": "maybe exploitable"})
    assert out["verdict"] == "ERROR" and out["finding"] == "error"
    assert out["raw_finding"] == "maybe exploitable"
    # non-string finding: no AttributeError, the error shape
    out = nr({"finding": ["VULNERABLE"]})
    assert out["verdict"] == "ERROR" and out["finding"] == "error"
    assert out["raw_finding"] == ["VULNERABLE"]
    # neither key: the #324 arm exists in the twin too
    out = nr({"reasoning": "cannot determine"})
    assert out["verdict"] == "ERROR" and out["finding"] == "error"
    # null verdict with a valid finding: the finding is the substance
    out = nr({"verdict": None, "finding": "vulnerable"})
    assert out["verdict"] == "VULNERABLE"
    # recognized mapping intact
    assert nr({"finding": "insufficient_context"})["verdict"] == "INSUFFICIENT_CONTEXT"


def test_context_corrector_error_break_stamps_failure(monkeypatch, tmp_path):
    """Wave round-2 finding (both reviewers): the ERROR-gate break must
    stamp the failure on the RETURNED original (every other break in the
    loop does) and preserve the garbage reply — experiment.py reads
    correction_status. Drives the real correct() with the LLM seams
    stubbed."""
    import utilities.context_corrector as cc

    monkeypatch.setattr(
        cc, "parse_missing_context_with_llm", lambda binding, r: "the config loader"
    )
    monkeypatch.setattr(
        cc, "search_files_for_context",
        lambda binding, mc, sf, fi: [{"relative_path": "cfg.py", "content": "x = 1"}],
    )
    # the re-analysis reply carries an unrecognized finding
    monkeypatch.setattr(
        cc, "simple_text", lambda binding, prompt, **k: '{"finding": "not sure, maybe"}'
    )

    class _Tracker:
        def get_totals(self):
            return {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}

    corrector = cc.ContextCorrector(_tool_binding(), str(tmp_path), tracker=_Tracker())
    original = {"verdict": "INSUFFICIENT_CONTEXT", "finding": "insufficient_context",
                "reasoning": "r"}
    out = corrector.attempt_correction(original, "code()", lambda c, f: "prompt")

    # the ORIGINAL is returned (the ERROR re-analysis is not adopted)
    assert out["verdict"] == "INSUFFICIENT_CONTEXT"
    # ...stamped as a failed correction with the garbage reply preserved
    assert out["correction_attempted"] is True
    assert out["correction_status"] == "reanalysis_unrecognized_verdict"
    assert out["raw_finding"] == "not sure, maybe"
    assert corrector.correction_stats["failures"] == 1
    assert corrector.correction_stats["successes"] == 0
