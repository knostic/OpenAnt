"""C2: a hygiene-check internal failure must never surface as integrity
"Clean" / Deploy After Validation, at every layer that used to turn it into
an empty finding list (patch_hygiene.check_patch and
generated_patch_processing.process_generated_patch)."""

from __future__ import annotations

from unittest import mock

from utilities.autopatcher import patch_hygiene
from utilities.autopatcher.generated_patch_processing import process_generated_patch
from utilities.autopatcher.pipeline import _build_recommendation_v1, _compute_trust_signals

_PATCH = (
    "--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,4 @@\n"
    " import os\n+import html\n def f(x):\n-    return x\n+    return html.escape(x)\n"
)
_APPLIES = {"applicable": True, "skipped": False, "error": None, "exit_code": 0, "stderr": ""}
_CHALLENGER = {
    "still_vulnerable": False, "confirmed_defect_count": 0, "plausible_risk_count": 0,
    "validation_gap_count": 0, "verification_status": "VERIFIED_FIXED",
}


def _decide(hygiene):
    signals = _compute_trust_signals(hygiene, _APPLIES, _CHALLENGER, "Good", "low")
    return signals["patch_integrity"]["value"], _build_recommendation_v1(signals)["decision"]


def _boom(*_a, **_k):
    raise RuntimeError("injected")


def test_control_clean_patch_reads_clean_and_deploys():
    assert _decide(patch_hygiene.check_patch(_PATCH)) == ("Clean", "Deploy After Validation")


def test_internal_check_error_never_reads_clean():
    with mock.patch.object(patch_hygiene, "_check_unused_imports", _boom):
        integrity, decision = _decide(patch_hygiene.check_patch(_PATCH))
    assert integrity != "Clean"
    assert decision != "Deploy After Validation"


def test_process_generated_patch_check_patch_raising_fails_closed():
    with mock.patch("utilities.autopatcher.patch_hygiene.check_patch", side_effect=_boom), \
         mock.patch("utilities.autopatcher.patch_applicability.check_applicability", return_value=_APPLIES):
        processed = process_generated_patch(_PATCH, None)
    assert [f["check"] for f in processed.hygiene_findings] == ["hygiene_check_failed"]
    integrity, decision = _decide(processed.hygiene_findings)
    assert integrity != "Clean"
    assert decision != "Deploy After Validation"


def test_process_generated_patch_control_reads_clean():
    with mock.patch("utilities.autopatcher.patch_applicability.check_applicability", return_value=_APPLIES):
        processed = process_generated_patch(_PATCH, None)
    assert processed.hygiene_findings == []


def test_post_strip_recheck_raising_fails_closed(tmp_path):
    """The re-check after strip_empty_hunks used to keep the PRE-strip
    findings on error (describing a different patch); it now fails closed."""
    calls = {"n": 0}

    def _first_ok_then_boom(patch, repo_root=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return []
        raise RuntimeError("injected")

    with mock.patch("utilities.autopatcher.patch_hygiene.check_patch", side_effect=_first_ok_then_boom), \
         mock.patch("utilities.autopatcher.patch_applicability.check_applicability",
                    side_effect=[{"applicable": False, "stderr": "x"}, _APPLIES]), \
         mock.patch("utilities.autopatcher.diff_hunk_repair.strip_empty_hunks", return_value=(_PATCH, 1)):
        processed = process_generated_patch(_PATCH, str(tmp_path), allow_context_reconstruction=False)
    assert processed.empty_hunks_removed == 1
    assert [f["check"] for f in processed.hygiene_findings] == ["hygiene_check_failed"]
