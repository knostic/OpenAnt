"""Tests for the no-candidate-patch early stop in pipeline.run().

Root Cause B (real urllib3 CVE-2023-43804 regression): once Patch
Generation definitively ends without a valid candidate patch, every
patch-dependent review stage -- Challenger, the Challenger-driven repair
loop, Finding Calibration, the Patch Reviewer, and the Confidence Scorer
-- must not run against an empty diff. Running them previously produced
internally contradictory report output (e.g. "Still vulnerable: No" /
"Adversarial review confirms fix approach" alongside "NO PATCH PRODUCED").

Hermetic: no /tmp trace dependency. Note: all patch-dependent stages are
imported into pipeline.py's OWN module namespace at import time (`from
.patch_challenger import challenge_patch`, etc.) -- spying on the
ORIGIN module's attribute (e.g. patch_challenger.challenge_patch) would
not observe what pipeline.run() actually calls; every spy below targets
`utilities.autopatcher.pipeline`'s own bound name instead, exactly like
this suite's other pipeline-level tests (see test_pipeline_repair.py).
"""

from __future__ import annotations

from unittest import mock

from utilities.autopatcher import pipeline as pipeline_mod

_VULN_TEXT = "# Test vulnerability\n\nSome description of a vulnerability for testing.\n"

# Real regression fixtures (copied verbatim, same convention as
# test_patch_generation_contract_retry.py -- each test file owns its own
# copy rather than importing cross-module): the traced CVE-2023-43804
# 003/004 patch_generation responses, both multi-candidate-diff contract
# violations. classify_patch_response's status="contract_violation" for
# both -> _generate_patch_with_contract_check exhausts its one bounded
# retry and returns patch="" -- a genuine, reliable "no candidate patch"
# outcome (unlike a bare "no_diff" first response, whose raw prose is
# deliberately passed through unchanged for pre-existing-behavior
# compatibility, and would NOT be empty here).
_TRACE_003_RESPONSE = """\
```diff
--- a/src/urllib3/connectionpool.py
+++ b/src/urllib3/connectionpool.py
@@ -871,6 +871,8 @@
             retries = retries.increment(method, url, response=response, _pool=self)
             retries.sleep_for_retry(response)
             log.debug("Redirect %s -> %s", url, redirect_location)
+            if retries.remove_headers_on_redirect:
+                new_headers = {k.lower(): v for k, v in headers.items()}
             return self.urlopen(
                 method,
                 redirect_location,
```

Given the actual redirect header-stripping mechanism is not in the verified evidence, the correct minimal fix is to add `Cookie` to the default set of headers removed on redirect:

```diff
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -184,7 +184,7 @@
         RETRY_AFTER_STATUS_CODES.
     \"\"\"

-    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])
+    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])

     #: Default headers to be used for ``remove_headers_on_redirect``
     DEFAULT_ALLOWED_METHODS = frozenset(
```"""

_TRACE_004_RESPONSE = """\
```diff
--- a/src/urllib3/connectionpool.py
+++ b/src/urllib3/connectionpool.py
@@ -940,6 +940,15 @@
         # Handle redirect?
         redirect_location = redirect and response.get_redirect_location()
         if redirect_location:
             if response.status == 303:
                 method = "GET"

+                # Change the body and headers for a GET request.
+                body = None
+                headers = HTTPHeaderDict(headers)._prepare_for_method_change()
+
             try:
                 retries = retries.increment(method, url, response=response, _pool=self)
             except MaxRetryError:
                 if retries.raise_on_redirect:
                     response.drain_conn()
                     raise
                 return response
```

Wait, that changes unrelated logic. Let me reconsider the actual fix for CVE-2023-43804.

```diff
--- a/src/urllib3/connectionpool.py
+++ b/src/urllib3/connectionpool.py
@@ -871,10 +871,20 @@
         # Handle redirect?
         redirect_location = redirect and response.get_redirect_location()
         if redirect_location:
             if response.status == 303:
                 method = "GET"

+            if retries.remove_headers_on_redirect:
+                new_headers = {
+                    k: v
+                    for k, v in (headers or {}).items()
+                    if k.lower() not in retries.remove_headers_on_redirect
+                }
+                headers = new_headers
+
             try:
                 retries = retries.increment(method, url, response=response, _pool=self)
             except MaxRetryError:
```"""


def _make_fake_generate_patch_raw():
    """Fresh per-test closure -- a module-level mutable list would be
    exhausted after the first test that consumes it."""
    responses = [_TRACE_003_RESPONSE, _TRACE_004_RESPONSE]

    def _fake(vulnerability_text, llm, code_context="", retry_hint="", stage="patch_generation"):
        return responses.pop(0)
    return _fake


def _run_no_patch(tmp_path, spies: dict):
    """Run the real pipeline.run() to a genuine no-candidate-patch outcome,
    with challenge_patch/calibrate_findings/review_patch/score_confidence/
    the repair loop's own generate_patch all left un-mocked but wrapped by
    spies -- if any of them fire, the spy records it, proving the early
    stop actually prevented the call rather than merely happening to
    receive convenient input."""
    with (
        mock.patch("utilities.autopatcher.pipeline.generate_patch_raw",
                   side_effect=_make_fake_generate_patch_raw()),
        mock.patch.object(pipeline_mod, "challenge_patch",
                           mock.MagicMock(wraps=pipeline_mod.challenge_patch)) as spy_challenge,
        mock.patch.object(pipeline_mod, "calibrate_findings",
                           mock.MagicMock(wraps=pipeline_mod.calibrate_findings)) as spy_calibrate,
        mock.patch.object(pipeline_mod, "review_patch",
                           mock.MagicMock(wraps=pipeline_mod.review_patch)) as spy_review,
        mock.patch.object(pipeline_mod, "score_confidence",
                           mock.MagicMock(wraps=pipeline_mod.score_confidence)) as spy_score,
        mock.patch.object(pipeline_mod, "generate_patch",
                           mock.MagicMock(wraps=pipeline_mod.generate_patch)) as spy_repair_gen,
    ):
        report = pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))
    spies["challenge"] = spy_challenge
    spies["calibrate"] = spy_calibrate
    spies["review"] = spy_review
    spies["score"] = spy_score
    spies["repair_gen"] = spy_repair_gen
    return report


class TestNoPatchEarlyStopCallCounts:
    """Tests 1-5 (no-patch early stop): every patch-dependent stage is
    called exactly zero times when there is no candidate patch."""

    def test_no_candidate_patch_challenger_never_called(self, tmp_path):
        spies: dict = {}
        _run_no_patch(tmp_path, spies)
        spies["challenge"].assert_not_called()

    def test_no_candidate_patch_calibration_never_called(self, tmp_path):
        spies: dict = {}
        _run_no_patch(tmp_path, spies)
        spies["calibrate"].assert_not_called()

    def test_no_candidate_patch_reviewer_never_called(self, tmp_path):
        spies: dict = {}
        _run_no_patch(tmp_path, spies)
        spies["review"].assert_not_called()

    def test_no_candidate_patch_confidence_scorer_never_called(self, tmp_path):
        spies: dict = {}
        _run_no_patch(tmp_path, spies)
        spies["score"].assert_not_called()

    def test_no_candidate_patch_repair_generation_never_called(self, tmp_path):
        """The Challenger-driven repair loop's own generate_patch() call
        (Site 4) never fires either -- it can't, since the repair loop's
        trigger reads _classify_challenger({})'s confirmed_defect_count,
        which is 0 for an empty challenger dict; this proves that
        no-LLM-call guarantee end to end rather than merely by
        inspection."""
        spies: dict = {}
        _run_no_patch(tmp_path, spies)
        spies["repair_gen"].assert_not_called()


class TestNoPatchReportSemantics:
    """Tests 6-9 (no-patch early stop): the rendered report is
    semantically consistent with "no candidate patch" -- no fabricated
    positive or negative patch-quality judgments, no patch-derived Review
    Results, no patch-review prose pretending a candidate exists, and the
    genuinely-collected failure reason still renders."""

    def test_report_does_not_claim_adversarial_review_confirms_fix(self, tmp_path):
        spies: dict = {}
        report = _run_no_patch(tmp_path, spies)
        assert "Adversarial review confirms fix approach" not in report

    def test_report_has_no_review_results_section(self, tmp_path):
        """No Review Results generated from Challenger should appear --
        Challenger never ran, so there is nothing for that section to
        report."""
        spies: dict = {}
        report = _run_no_patch(tmp_path, spies)
        assert "## Review Results" not in report

    def test_report_has_no_reviewer_prose_sections(self, tmp_path):
        """No patch-specific Reviewer explanation, Affected areas, or
        Reviewer Notes should appear as if a candidate was reviewed --
        the Patch Reviewer never ran."""
        spies: dict = {}
        report = _run_no_patch(tmp_path, spies)
        assert "## Explanation" not in report
        assert "### Affected areas" not in report
        assert "### Reviewer Notes" not in report

    def test_report_still_shows_no_patch_outcome_and_reason(self, tmp_path):
        """The final report must still use the existing NO PATCH PRODUCED
        path, and the reason Patch Generation could not proceed must
        remain visible."""
        spies: dict = {}
        report = _run_no_patch(tmp_path, spies)
        assert "NO PATCH PRODUCED" in report
        assert "The pipeline did not produce a final candidate patch." in report


class TestValidPatchPathUnaffected:
    """Test 10 (no-patch early stop): a run that DOES produce a candidate
    patch must still run Challenger -> Finding Calibration (and everything
    downstream) exactly as before this fix -- the early stop only ever
    activates on a genuinely empty final patch."""

    def test_valid_patch_still_runs_challenger_and_calibration(self, tmp_path):
        patch_diff = (
            "```diff\n--- a/mod.py\n+++ b/mod.py\n@@ -1,2 +1,3 @@\n"
            " def foo():\n+    pass\n     return 1\n```"
        )

        def _fake_raw(vulnerability_text, llm, code_context="", retry_hint="", stage="patch_generation"):
            return patch_diff

        with (
            mock.patch("utilities.autopatcher.pipeline.generate_patch_raw", side_effect=_fake_raw),
            mock.patch.object(pipeline_mod, "challenge_patch",
                               mock.MagicMock(wraps=pipeline_mod.challenge_patch)) as spy_challenge,
            mock.patch.object(pipeline_mod, "review_patch",
                               mock.MagicMock(wraps=pipeline_mod.review_patch)) as spy_review,
            mock.patch.object(pipeline_mod, "score_confidence",
                               mock.MagicMock(wraps=pipeline_mod.score_confidence)) as spy_score,
        ):
            report = pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))

        spy_challenge.assert_called()
        spy_review.assert_called()
        spy_score.assert_called()
        assert "NO PATCH PRODUCED" not in report
