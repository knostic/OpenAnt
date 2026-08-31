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
import sys
from pathlib import Path

_CORE = Path(__file__).resolve().parents[1]
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))

from core.analysis_core import _normalize_result  # noqa: E402
from core.analyzer import _count_verdicts  # noqa: E402


def _is_error(r):
    from core.analyzer import analyze_result_is_error
    return analyze_result_is_error(r)


def test_unrecognized_verdict_routes_to_error():
    """The passthrough escape: `weird` must not land in verdict uppercased —
    it is the same garbage-reply class the finding-key fix fails CLOSED on."""
    out = _normalize_result({"verdict": "weird"})
    assert out["verdict"] == "ERROR", out
    assert out["finding"] == "error"
    assert out["raw_verdict"] == "weird", "the raw value stays for manual review"


def test_unrecognized_verdict_with_valid_finding_stamps_both():
    """The issue's exact row: a garbage verdict beside a valid finding — the
    ROW routes to the error accounting; both raws preserved."""
    out = _normalize_result({"verdict": "SAY WHAT", "finding": "vulnerable"})
    assert out["verdict"] == "ERROR"
    assert out["finding"] == "error"
    assert out["raw_verdict"] == "SAY WHAT"
    assert out["raw_finding"] == "vulnerable"


def test_canonical_verdicts_pass_unchanged():
    """The whitelist over-blocks nothing: every canonical Stage-1 verdict
    keeps its shape (casing normalized)."""
    for v in ("SAFE", "VULNERABLE", "PROTECTED", "BYPASSABLE", "INCONCLUSIVE",
              "INSUFFICIENT_CONTEXT", "ERROR"):
        out = _normalize_result({"verdict": v.lower()})
        assert out["verdict"] == v, (v, out)
        assert "raw_verdict" not in out


def test_error_shape_reaches_every_sink():
    """The closed sinks: counted in errors (sum reconciles), classified as
    error (resume does NOT adopt as complete), and never in disclosure."""
    row = _normalize_result({"verdict": "SAY WHAT", "finding": "vulnerable"})
    counts = _count_verdicts([dict(row)])
    assert counts["errors"] == 1
    assert sum(v for k, v in counts.items() if k != "errors") == 0
    assert _is_error(row) is True
