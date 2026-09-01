"""#427: an unrecognized non-empty VERDICT routes to the error accounting.

#426 closed the unrecognized-FINDING case and the absent/null/empty-verdict case — but
an unrecognized non-empty VERDICT string ({"verdict": "SAY WHAT", "finding":
"vulnerable"} — producible by the same untrusted model JSON that produced #316's garbage
findings) still passed through `_normalize_result` unchanged and then FAILED OPEN at
every accounting sink: (a) dropped from all `_count_verdicts` buckets (sum < total
persists); (b) `analyze_result_is_error` -> False -> adopted as complete on resume,
never retried; (c) counted as `completed` by the summary seeding; (d) never in the
disclosure set. The asymmetry: the same garbage-reply class failed CLOSED for the
finding key and OPEN for the verdict key.

The fix mirrors the finding-key fix at the verdict key: a canonical whitelist in the
passthrough branch — known verdicts pass; anything else routes to the error accounting
with the raw value preserved for manual review. The #426 pin test's
`{"verdict": "weird"} == "WEIRD"` line (documented there as "the residual ... #324's
documented gap, unchanged") is updated with this fix — this issue is that gap's closure.
"""
import re
import sys
from pathlib import Path

_CORE = Path(__file__).resolve().parents[1]
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))

from core.analysis_core import _normalize_result  # noqa: E402
from core.verdict_taxonomy import STAGE1_VERDICTS  # noqa: E402
from core.analyzer import _count_verdicts  # noqa: E402


def _is_error(r):
    from core.analyzer import analyze_result_is_error
    return analyze_result_is_error(r)


def test_unrecognized_verdict_routes_to_error():
    """The passthrough escape (no usable finding): `weird` must not land in
    verdict uppercased — it is the same garbage-reply class the finding-key
    fix fails CLOSED on."""
    out = _normalize_result({"verdict": "weird"})
    assert out["verdict"] == "ERROR", out
    assert out["finding"] == "error"
    assert out["raw_verdict"] == "weird", "the raw value stays for manual review"


def test_stripped_verdict_is_stored_stripped():
    """Wave r1 (fable): the check strips; the store must too — a "safe "
    passed the whitelist and was stored unstripped, which the sinks then
    dropped: the exact fail-open, for an input the check classified
    canonical."""
    out = _normalize_result({"verdict": " safe "})
    assert out["verdict"] == "SAFE", out


def test_conformance_the_whitelist_is_the_finding_to_verdict_map():
    """Wave r1 (sonnet): STAGE1_VERDICTS is synchronized with
    analysis_core's own finding_to_verdict map + ERROR — the shared-constant
    pattern the Stage-2 vocabulary already uses
    (test_F3_verdict_taxonomy_shared_constant). A future edit to either
    without the other silently reopens the asymmetry this fix closes."""
    import inspect
    src = inspect.getsource(_normalize_result)
    m = re.search(r"finding_to_verdict = \{(.*?)\}", src, re.S)
    assert m, "the inline map not found"
    vals = set(re.findall(r':\s*"([A-Z_]+)"', m.group(1)))
    assert vals | {"ERROR"} == STAGE1_VERDICTS, (
        f"the whitelist drifted from the map: {STAGE1_VERDICTS - vals - {'ERROR'}} "
        f"or the map gained {vals - STAGE1_VERDICTS}"
    )


def test_unrecognized_verdict_with_valid_finding_keeps_the_finding():
    """Wave r1 (opus) — the finding-kept redesign: the issue's exact row did
    NOT fail open before (the finding-first sinks counted it vulnerable,
    Stage-2 verified it, disclosure kept it), and routing the whole row to
    error EXCLUDED it from all three — a false negative for a row whose
    model reply asserted vulnerable. The garbage verdict is discarded (raw
    preserved); the canonical finding is KEPT."""
    out = _normalize_result({"verdict": "SAY WHAT", "finding": "vulnerable"})
    assert out["finding"] == "vulnerable", (
        "a usable canonical finding is kept — the row keeps its "
        "finding-driven accounting and disclosure"
    )
    assert out["raw_verdict"] == "SAY WHAT"
    assert "raw_finding" not in out
    # an unusable/non-string finding beside the garbage verdict DOES route:
    out2 = _normalize_result({"verdict": "SAY WHAT", "finding": ["vulnerable"]})
    assert out2["verdict"] == "ERROR"
    assert out2["finding"] == "error"
    assert out2["raw_verdict"] == "SAY WHAT"
    assert out2["raw_finding"] == ["vulnerable"], (
        "non-string raws preserved (wave r1 fable)"
    )


def test_canonical_verdicts_pass_unchanged():
    """The whitelist over-blocks nothing: every canonical Stage-1 verdict
    keeps its shape (casing normalized)."""
    for v in ("SAFE", "VULNERABLE", "PROTECTED", "BYPASSABLE", "INCONCLUSIVE",
              "INSUFFICIENT_CONTEXT", "ERROR"):
        out = _normalize_result({"verdict": v.lower()})
        assert out["verdict"] == v, (v, out)
        assert "raw_verdict" not in out


def test_error_shape_reaches_every_sink():
    """The closed sinks for the ERROR-SHAPE row (finding absent/unusable):
    counted in errors (sum reconciles), classified as error (resume does
    NOT adopt it as complete). The disclosure claim corrected (wave r1
    fable): the error shape is DISCLOSURE-ELIGIBLE (error is in
    DISCLOSURE_ELIGIBLE by design — surfaced for manual triage), so the fix
    moves the row from silently-dropped to eligible-as-error."""
    row = _normalize_result({"verdict": "weird"})
    counts = _count_verdicts([dict(row)])
    assert counts["errors"] == 1
    assert sum(v for k, v in counts.items() if k != "errors") == 0
    assert _is_error(row) is True
