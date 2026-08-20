"""Tests for Patch Generator response-contract enforcement's orchestration
layer (release: response-contract enforcement).

Scope, deliberately narrow:
  - pipeline._generate_patch_with_contract_check: the bounded (at most one
    retry), pure-orchestration decision of whether a contract violation
    warrants a second Patch Generator call. classify_patch_response itself
    (pure, no LLM calls) is tested in test_patch_generator.py.
  - The correction that an invalid response must fail closed BEFORE hunk
    repair, patch hygiene, `git apply --check`, and applicability-aware
    retry — proven against the real pipeline.run() call path, not asserted
    as a property of the orchestration helper alone.

Does not touch repository grounding, evidence acquisition, context-budget
behavior, Planner behavior, Challenger behavior, or recommendation/report
logic — see docs/investigation for the root-cause writeup this change
addresses.
"""

from __future__ import annotations

from unittest import mock

import pytest


# ---------------------------------------------------------------------------
# Real regression fixtures — copied in verbatim from the traced
# CVE-2023-43804 / urllib3 run's 003_patch_generation.response.txt and
# 004_patch_generation.response.txt (no /tmp dependency). Kept identical to
# the copies in test_patch_generator.py; duplicated here rather than
# imported cross-test-module, matching this suite's existing convention of
# each test file owning its own fixtures.
# ---------------------------------------------------------------------------

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
+                # https://datatracker.ietf.org/doc/html/rfc9110#section-15.4.4
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

+            # Strip headers marked as unsafe to forward to the redirected location.
+            # Check remove_headers_on_redirect to avoid a potential network call within
+            # conn.request() where the same headers are sent to another host.
+            retries = retries or self.retries
+            if retries.remove_headers_on_redirect and not is_same_host(
+                redirect_location
+            ):
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
```

The above uses an undefined `is_same_host`. Here is the correct minimal patch:

```diff
--- a/src/urllib3/connectionpool.py
+++ b/src/urllib3/connectionpool.py
@@ -871,6 +871,20 @@
         redirect_location = redirect and response.get_redirect_location()
         if redirect_location:
             if response.status == 303:
                 method = "GET"

+            # Strip headers marked as unsafe to forward to the redirected location.
+            # Check remove_headers_on_redirect to avoid a potential network call within
+            # conn.request() where the same headers are sent to another host.
+            if retries.remove_headers_on_redirect:
+                new_headers = {
+                    k: v
+                    for k, v in (headers or {}).items()
+                    if k.lower() not in retries.remove_headers_on_redirect
+                }
+                redirect_url = urljoin(url, redirect_location)
+                if urlparse(url).netloc != urlparse(redirect_url).netloc:
+                    headers = new_headers
+
             try:
                 retries = retries.increment(method, url, response=response, _pool=self)
             except MaxRetryError:
```"""

_CLEAN_SINGLE_DIFF = """\
```diff
--- a/f.py
+++ b/f.py
@@ -1,1 +1,1 @@
-old
+new
```"""


# ---------------------------------------------------------------------------
# Unit-level orchestration tests: _generate_patch_with_contract_check
# ---------------------------------------------------------------------------

class TestGeneratePatchWithContractCheck:
    def test_valid_response_makes_exactly_one_llm_call(self):
        from utilities.autopatcher.pipeline import _generate_patch_with_contract_check

        llm = mock.MagicMock()
        llm.complete.return_value = _CLEAN_SINGLE_DIFF
        patch, status, calls = _generate_patch_with_contract_check("some vuln", llm)

        assert llm.complete.call_count == 1
        assert status == "valid"
        assert calls == 1
        assert patch.startswith("```diff\n")

    def test_contract_violation_then_valid_makes_exactly_two_calls(self):
        """Second call must be explicitly identifiable as the contract
        retry (distinct `stage`), and only the SECOND response's diff may
        reach the caller — never anything derived from the first,
        rejected response."""
        from utilities.autopatcher.pipeline import _generate_patch_with_contract_check, _CONTRACT_RETRY_STAGE

        llm = mock.MagicMock()
        llm.complete.side_effect = [_TRACE_003_RESPONSE, _CLEAN_SINGLE_DIFF]
        patch, status, calls = _generate_patch_with_contract_check("some vuln", llm)

        assert llm.complete.call_count == 2
        assert calls == 2
        assert status == "valid"
        assert patch == _CLEAN_SINGLE_DIFF
        # Nothing from the rejected first (multi-candidate) response leaks through.
        assert "connectionpool.py" not in patch
        assert "DEFAULT_REMOVE_HEADERS_ON_REDIRECT" not in patch
        # The second call is explicitly traced as a contract retry, not a
        # second ordinary "patch_generation" call indistinguishable from the first.
        second_call_kwargs = llm.complete.call_args_list[1].kwargs
        assert second_call_kwargs.get("stage") == _CONTRACT_RETRY_STAGE == "patch_generation_contract_retry"
        first_call_kwargs = llm.complete.call_args_list[0].kwargs
        assert first_call_kwargs.get("stage") == "patch_generation"

    def test_contract_violation_then_contract_violation_fails_closed(self):
        """Exactly two calls, then fail closed — no candidate diff from
        EITHER invalid response may survive."""
        from utilities.autopatcher.pipeline import _generate_patch_with_contract_check

        llm = mock.MagicMock()
        llm.complete.side_effect = [_TRACE_003_RESPONSE, _TRACE_004_RESPONSE]
        patch, status, calls = _generate_patch_with_contract_check("some vuln", llm)

        assert llm.complete.call_count == 2
        assert calls == 2
        assert status == "contract_violation"
        assert patch == ""

    def test_never_makes_a_third_call(self):
        """Regression guard against ever turning this into a loop: even if
        classify_patch_response somehow kept returning "contract_violation"
        forever, the function itself only ever calls the LLM twice — proven
        by exhausting the mock's side_effect list at exactly 2 items."""
        from utilities.autopatcher.pipeline import _generate_patch_with_contract_check

        llm = mock.MagicMock()
        llm.complete.side_effect = [_TRACE_003_RESPONSE, _TRACE_004_RESPONSE]
        # If the function tried a third call, side_effect would raise
        # StopIteration (unhandled) -- absence of that is itself the proof.
        _generate_patch_with_contract_check("some vuln", llm)
        assert llm.complete.call_count == 2

    def test_no_diff_first_response_is_not_retried(self):
        """"no_diff" must never trigger the bounded retry -- only
        "contract_violation" does."""
        from utilities.autopatcher.pipeline import _generate_patch_with_contract_check

        llm = mock.MagicMock()
        llm.complete.return_value = "I cannot produce an automated patch for this."
        patch, status, calls = _generate_patch_with_contract_check("some vuln", llm)

        assert llm.complete.call_count == 1
        assert calls == 1
        assert status == "no_diff"
        assert patch == "I cannot produce an automated patch for this."

    def test_retry_that_itself_comes_back_no_diff_still_fails_closed_to_empty(self):
        """A contract-violation retry that comes back "no_diff" must NOT
        leak its raw.strip() text into `patch` -- both call sites decide
        "keep original"/"skip validation" partly by checking `patch`
        truthiness, so a non-"valid" retry result must always mean an
        actually-empty patch, not merely a non-"valid" label next to
        leftover prose."""
        from utilities.autopatcher.pipeline import _generate_patch_with_contract_check

        llm = mock.MagicMock()
        llm.complete.side_effect = [_TRACE_003_RESPONSE, "Sorry, I could not determine a fix."]
        patch, status, calls = _generate_patch_with_contract_check("some vuln", llm)

        assert calls == 2
        assert status == "no_diff"
        assert patch == ""  # not "Sorry, I could not determine a fix."


# ---------------------------------------------------------------------------
# Pipeline-level: invalid responses must fail closed BEFORE hunk repair,
# hygiene, git apply --check, and applicability-aware retry.
# ---------------------------------------------------------------------------

_VULN_TEXT = "# Test vulnerability\n\nSome description of a vulnerability for testing.\n"


class TestInvalidResponseNeverReachesValidationMachinery:
    def test_site1_contract_violation_exhausted_skips_repair_hygiene_applicability(self, tmp_path, monkeypatch):
        """Site 1 (initial generation): both the first response and the one
        bounded contract retry violate the contract (the real traced 003/004
        shapes) -- repair_hunk_headers, check_patch, and check_applicability
        must never be called at all, not merely called on "" harmlessly."""
        from utilities.autopatcher import pipeline as pipeline_mod
        from utilities.autopatcher import patch_applicability, diff_hunk_repair, patch_hygiene

        raw_responses = [_TRACE_003_RESPONSE, _TRACE_004_RESPONSE]

        def _fake_generate_patch_raw(vulnerability_text, llm, code_context="", retry_hint="", stage="patch_generation"):
            return raw_responses.pop(0)

        applicability_spy = mock.MagicMock(wraps=patch_applicability.check_applicability)
        repair_spy = mock.MagicMock(wraps=diff_hunk_repair.repair_hunk_headers)
        hygiene_spy = mock.MagicMock(wraps=patch_hygiene.check_patch)

        with mock.patch("utilities.autopatcher.pipeline.generate_patch_raw", side_effect=_fake_generate_patch_raw), \
             mock.patch.object(patch_applicability, "check_applicability", applicability_spy), \
             mock.patch.object(diff_hunk_repair, "repair_hunk_headers", repair_spy), \
             mock.patch.object(patch_hygiene, "check_patch", hygiene_spy):
            report = pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))

        assert not raw_responses, "expected both canned responses to be consumed (2 LLM calls)"
        applicability_spy.assert_not_called()
        repair_spy.assert_not_called()
        hygiene_spy.assert_not_called()
        assert "NO PATCH PRODUCED" in report

    def test_site2_regeneration_contract_violation_never_reaches_applicability(self, tmp_path, monkeypatch):
        """Site 2 (applicability-aware retry): the ORIGINAL patch is
        syntactically valid but fails `git apply` (real content mismatch),
        triggering the existing retry path. The regeneration response AND
        its own bounded contract retry both violate the contract. Must
        behave like "the applicability retry failed to produce a usable
        replacement" -- never like "here is an empty/invalid patch to
        validate" -- and must not trigger a second applicability-aware
        retry."""
        import subprocess

        from utilities.autopatcher import pipeline as pipeline_mod
        from utilities.autopatcher import patch_applicability

        subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
        target = tmp_path / "mod.py"
        target.write_text("def foo():\n    return 1\n", encoding="utf-8")

        # A syntactically valid single diff whose context lines do not match
        # the real file content above -- git apply must fail on it.
        original_patch = (
            "```diff\n"
            "--- a/mod.py\n"
            "+++ b/mod.py\n"
            "@@ -1,2 +1,2 @@\n"
            " def foo():\n"
            "-    return 999\n"
            "+    return 2\n"
            "```"
        )

        raw_responses = [original_patch, _TRACE_003_RESPONSE, _TRACE_004_RESPONSE]

        def _fake_generate_patch_raw(vulnerability_text, llm, code_context="", retry_hint="", stage="patch_generation"):
            return raw_responses.pop(0)

        applicability_calls: list[str] = []
        _real_check_applicability = patch_applicability.check_applicability

        def _applicability_spy(patch, repo_root):
            applicability_calls.append(patch)
            return _real_check_applicability(patch, repo_root)

        with mock.patch("utilities.autopatcher.pipeline.generate_patch_raw", side_effect=_fake_generate_patch_raw), \
             mock.patch.object(patch_applicability, "check_applicability", side_effect=_applicability_spy):
            report = pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))

        assert not raw_responses, "expected all three canned responses to be consumed (3 LLM calls)"
        # check_applicability was called for the original patch (and
        # possibly again by deterministic context reconstruction on that
        # SAME original patch) -- but never for either invalid regenerated
        # candidate response.
        for call_patch in applicability_calls:
            assert "connectionpool.py" not in call_patch
            assert "_prepare_for_method_change" not in call_patch
            assert "DEFAULT_REMOVE_HEADERS_ON_REDIRECT" not in call_patch
        assert applicability_calls, "check_applicability should have been called at least once, for the original patch"

        # Original retry-failure semantics preserved: the report still
        # reflects the ORIGINAL (still-inapplicable) patch, not an empty one.
        assert "return 2" in report
        assert "NO PATCH PRODUCED" not in report

    def test_normal_applicability_failure_and_retry_still_works(self, tmp_path):
        """Regression guard: an ordinary applicability failure followed by
        a VALID regenerated patch must behave exactly as before this
        change -- retry succeeds, the new patch is adopted."""
        import subprocess

        from utilities.autopatcher import pipeline as pipeline_mod

        subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
        target = tmp_path / "mod.py"
        target.write_text("def foo():\n    return 1\n", encoding="utf-8")

        original_patch = (
            "```diff\n"
            "--- a/mod.py\n"
            "+++ b/mod.py\n"
            "@@ -1,2 +1,2 @@\n"
            " def foo():\n"
            "-    return 999\n"
            "+    return 2\n"
            "```"
        )
        regenerated_patch = (
            "```diff\n"
            "--- a/mod.py\n"
            "+++ b/mod.py\n"
            "@@ -1,2 +1,2 @@\n"
            " def foo():\n"
            "-    return 1\n"
            "+    return 2\n"
            "```"
        )
        raw_responses = [original_patch, regenerated_patch]

        def _fake_generate_patch_raw(vulnerability_text, llm, code_context="", retry_hint="", stage="patch_generation"):
            return raw_responses.pop(0)

        with mock.patch("utilities.autopatcher.pipeline.generate_patch_raw", side_effect=_fake_generate_patch_raw):
            report = pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))

        assert not raw_responses
        assert "return 1" in report  # the successful regenerated diff, unchanged behavior
        assert "NO PATCH PRODUCED" not in report
