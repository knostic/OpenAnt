"""Unit tests for patch_generator._extract_diff_block and generate_patch."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_CLEAN_DIFF = """\
```diff
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -187,7 +187,7 @@
-    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])
+    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])
```"""

_PROSE_PREAMBLE = """\
The vulnerability is in retry.py. Here is the minimal fix:

```diff
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -187,7 +187,7 @@
-    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])
+    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])
```

Let me know if you need a more defensive approach."""

_TWO_ALTERNATIVES = """\
Option A — minimal fix:

```diff
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -187,7 +187,7 @@
-    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])
+    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])
```

Option B — more defensive:

```diff
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -187,7 +187,7 @@
-    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])
+    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization", "X-Csrf-Token"])
```"""

_MULTI_FILE_DIFF = """\
```diff
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -187,7 +187,7 @@
-    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])
+    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])
--- a/src/urllib3/connectionpool.py
+++ b/src/urllib3/connectionpool.py
@@ -1,3 +1,4 @@
+# Cookie stripping is handled via DEFAULT_REMOVE_HEADERS_ON_REDIRECT.
```"""

_PATCH_TAG = """\
```patch
--- a/src/utils.py
+++ b/src/utils.py
@@ -1,1 +1,1 @@
-old_line()
+new_line()
```"""

_UDIFF_TAG = """\
```udiff
--- a/src/utils.py
+++ b/src/utils.py
@@ -1,1 +1,1 @@
-old_line()
+new_line()
```"""

_NO_DIFF_BLOCK = "The vulnerability requires manual intervention. No automated patch is possible."

_WINDOWS_ENDINGS = "```diff\r\n--- a/foo.py\r\n+++ b/foo.py\r\n@@ -1 +1 @@\r\n-old\r\n+new\r\n```"

# F-29 regression fixtures: a diff body that itself contains a nested
# Markdown fence must not be truncated at the inner fence.

_NESTED_FENCE_DIFF = """\
```diff
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -10,4 +10,9 @@ Some intro text
 ## Usage

+```bash
+openant patch --check
+```
+
+See docs for more.
diff --git a/lib/auth.py b/lib/auth.py
--- a/lib/auth.py
+++ b/lib/auth.py
@@ -50,7 +50,7 @@ def verify_token(token):
-    if token == expected:
+    if hmac.compare_digest(token, expected):
         return True
```"""

_QUAD_FENCE_DIFF = """\
````diff
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1,2 +1,5 @@
 # Title
+```bash
+echo hello
+```
````"""

_TILDE_FENCE_DIFF = """\
~~~diff
--- a/src/utils.py
+++ b/src/utils.py
@@ -1,1 +1,1 @@
-old_line()
+new_line()
~~~"""

# Context lines (unchanged, single leading space) reproducing a fence from
# the patched file's own content -- must not be mistaken for the outer
# fence's closer, since a genuine closer is never diff-prefixed.
_CONTEXT_LINE_FENCE_DIFF = """\
```diff
--- a/README.md
+++ b/README.md
@@ -10,7 +10,7 @@ Some intro
 ## Usage

 ```bash
 echo hi
 ```

-See docs.
+See documentation.
```"""

# Recognised opener, real applicable-looking hunk content, but the fence is
# never closed -- e.g. the model's response was cut off mid-generation.
_UNCLOSED_FENCE_DIFF = (
    "```diff\n"
    "--- a/auth.py\n"
    "+++ b/auth.py\n"
    "@@ -1,2 +1,2 @@\n"
    " def authenticate(u, p):\n"
    "-    return True\n"
    "+    return check_credentials(u, p)\n"
)

# The first ```diff opener is never closed, but a second, independently
# well-formed ```diff block follows later in the same response. The first
# block must be treated as malformed on its own -- neither merged with the
# second block's content nor skipped in favour of it.
_UNCLOSED_FIRST_THEN_VALID_SECOND_DIFF = (
    "```diff\n"
    "--- a/first.py\n"
    "+++ b/first.py\n"
    "@@ -1,1 +1,1 @@\n"
    "-old_first\n"
    "+new_first\n"
    "\n"
    "Some trailing prose, still inside the unclosed first block.\n"
    "\n"
    "```diff\n"
    "--- a/second.py\n"
    "+++ b/second.py\n"
    "@@ -1,1 +1,1 @@\n"
    "-old_second\n"
    "+new_second\n"
    "```\n"
)

# --- Full-contract-enforcement fixtures (release: response-contract
# enforcement -- prose before/after a single otherwise-valid block is now a
# contract violation, not silently stripped) ---

_PROSE_BEFORE_ONLY = """\
The vulnerability is in retry.py. Here is the minimal fix:

```diff
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -187,7 +187,7 @@
-    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])
+    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])
```"""

_PROSE_AFTER_ONLY = """\
```diff
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -187,7 +187,7 @@
-    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])
+    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])
```

Let me know if you need a more defensive approach."""

_THREE_ALTERNATIVES = """\
Option A — minimal fix:

```diff
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -187,7 +187,7 @@
-    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])
+    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])
```

Option B — more defensive:

```diff
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -187,7 +187,7 @@
-    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])
+    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization", "X-Csrf-Token"])
```

Wait, let me reconsider — option C:

```diff
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -187,7 +187,7 @@
-    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])
+    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization", "Set-Cookie"])
```"""

# Whitespace-only before/after the fence (blank lines, trailing newline) must
# remain valid -- "surrounding whitespace is allowed" is explicit in the
# response contract.
_WHITESPACE_ONLY_SURROUNDING_DIFF = (
    "\n\n"
    "```diff\n"
    "--- a/f.py\n"
    "+++ b/f.py\n"
    "@@ -1,1 +1,1 @@\n"
    "-old\n"
    "+new\n"
    "```"
    "\n   \n"
)

# --- Real regression fixtures: the CVE-2023-43804 / urllib3 traced run
# (see docs/investigation for the full root-cause writeup). Copied in
# verbatim from the traced run's 003_patch_generation.response.txt and
# 004_patch_generation.response.txt so the test suite has no dependency on
# /tmp. Both are genuine LLM output: the model itself produced the correct
# Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT fix in each case, as a LATER
# block than the one that used to be silently selected -- these fixtures
# exist to prove the parser never selects any candidate from either
# response, not to assert which candidate "should" win.

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


# ---------------------------------------------------------------------------
# Tests for _extract_diff_block
# ---------------------------------------------------------------------------

class TestExtractDiffBlock:
    def test_clean_diff_preserved(self):
        from utilities.autopatcher.patch_generator import _extract_diff_block
        result = _extract_diff_block(_CLEAN_DIFF)
        assert result.startswith("```diff\n")
        assert result.strip().endswith("```")
        assert "DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in result

    def test_prose_preamble_and_postamble_is_now_a_contract_violation(self):
        """Release: response-contract enforcement. _PROSE_PREAMBLE has real
        prose on both sides of an otherwise-valid single diff — previously
        silently stripped, now correctly a contract violation (the prompt
        contract requires "no prose... before or after the block")."""
        from utilities.autopatcher.patch_generator import _extract_diff_block
        result = _extract_diff_block(_PROSE_PREAMBLE)
        assert result == ""

    def test_two_diff_alternatives_is_contract_violation(self):
        """Release: response-contract enforcement. This used to assert the
        first of two alternatives was silently returned — that was the
        actual bug (see the traced urllib3 CVE-2023-43804 regression). A
        multi-candidate response must now be rejected outright, never
        resolved by picking one."""
        from utilities.autopatcher.patch_generator import _extract_diff_block
        result = _extract_diff_block(_TWO_ALTERNATIVES)
        assert result == ""

    def test_multi_file_diff_preserved(self):
        from utilities.autopatcher.patch_generator import _extract_diff_block
        result = _extract_diff_block(_MULTI_FILE_DIFF)
        assert "retry.py" in result
        assert "connectionpool.py" in result

    def test_patch_tag_normalised_to_diff(self):
        from utilities.autopatcher.patch_generator import _extract_diff_block
        result = _extract_diff_block(_PATCH_TAG)
        assert result.startswith("```diff\n")
        assert "+new_line()" in result

    def test_udiff_tag_normalised_to_diff(self):
        from utilities.autopatcher.patch_generator import _extract_diff_block
        result = _extract_diff_block(_UDIFF_TAG)
        assert result.startswith("```diff\n")
        assert "+new_line()" in result

    def test_no_fenced_block_returns_raw_stripped(self):
        from utilities.autopatcher.patch_generator import _extract_diff_block
        result = _extract_diff_block(_NO_DIFF_BLOCK)
        assert result == _NO_DIFF_BLOCK.strip()

    def test_empty_string_returns_empty(self):
        from utilities.autopatcher.patch_generator import _extract_diff_block
        assert _extract_diff_block("") == ""

    def test_windows_line_endings_accepted(self):
        from utilities.autopatcher.patch_generator import _extract_diff_block
        result = _extract_diff_block(_WINDOWS_ENDINGS)
        assert result.startswith("```diff\n")
        assert "+new" in result

    def test_valid_single_diff_always_starts_with_diff_fence(self):
        """_PROSE_PREAMBLE and _TWO_ALTERNATIVES removed from this list —
        release: response-contract enforcement — neither classifies as
        "valid" anymore (see test_prose_preamble_and_postamble_is_now_a_
        contract_violation / test_two_diff_alternatives_is_contract_violation)."""
        from utilities.autopatcher.patch_generator import _extract_diff_block
        for raw in (_CLEAN_DIFF, _PATCH_TAG, _WHITESPACE_ONLY_SURROUNDING_DIFF):
            result = _extract_diff_block(raw)
            assert result.startswith("```diff\n"), f"Failed for input starting: {raw[:40]!r}"


# ---------------------------------------------------------------------------
# classify_patch_response — full response-contract enforcement.
#
# Required cases A-I from the release plan: exactly one fenced diff block,
# no prose before, no prose after, no alternatives; surrounding whitespace
# allowed; malformed/no-diff keep their pre-existing, separately-tested
# semantics (see TestExtractDiffBlock / TestExtractDiffBlockNestedFences
# above, unchanged).
# ---------------------------------------------------------------------------

class TestClassifyPatchResponse:
    def test_a_one_valid_diff_only(self):
        from utilities.autopatcher.patch_generator import classify_patch_response
        result = classify_patch_response(_CLEAN_DIFF)
        assert result.status == "valid"
        assert result.block_count == 1
        assert result.diff.startswith("```diff\n")
        assert "DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in result.diff

    def test_b_prose_before_one_diff_is_contract_violation(self):
        from utilities.autopatcher.patch_generator import classify_patch_response
        result = classify_patch_response(_PROSE_BEFORE_ONLY)
        assert result.status == "contract_violation"
        assert result.block_count == 1
        assert result.diff == ""

    def test_c_prose_after_one_diff_is_contract_violation(self):
        from utilities.autopatcher.patch_generator import classify_patch_response
        result = classify_patch_response(_PROSE_AFTER_ONLY)
        assert result.status == "contract_violation"
        assert result.block_count == 1
        assert result.diff == ""

    def test_d_two_complete_diff_blocks_is_contract_violation(self):
        from utilities.autopatcher.patch_generator import classify_patch_response
        result = classify_patch_response(_TWO_ALTERNATIVES)
        assert result.status == "contract_violation"
        assert result.block_count == 2
        assert result.diff == ""

    def test_e_three_complete_diff_blocks_is_contract_violation(self):
        from utilities.autopatcher.patch_generator import classify_patch_response
        result = classify_patch_response(_THREE_ALTERNATIVES)
        assert result.status == "contract_violation"
        assert result.block_count == 3
        assert result.diff == ""

    def test_f_malformed_nested_fence_is_malformed_not_contract_violation(self):
        """Malformed/truncated structured output is a distinct state from
        "contract violation" — it was never eligible for the bounded retry
        (see _generate_patch_with_contract_check) and keeps its
        pre-existing, separately-tested "" fail-closed behavior."""
        from utilities.autopatcher.patch_generator import classify_patch_response
        result = classify_patch_response(_UNCLOSED_FIRST_THEN_VALID_SECOND_DIFF)
        assert result.status == "malformed_fence"
        assert result.block_count == 0
        assert result.diff == ""

    def test_g_no_diff_preserves_its_own_distinct_state(self):
        """"no_diff" (the model wrote plain prose, no fence at all) is
        deliberately NOT a "contract_violation" and is never retried by
        _generate_patch_with_contract_check — it may be an honest "no
        automated patch is possible" answer, and retrying it as if it were
        a formatting problem risks pressuring a fabricated diff out of a
        model that had nothing to add. Behavior (raw.strip() passthrough)
        is byte-identical to before this change."""
        from utilities.autopatcher.patch_generator import classify_patch_response
        result = classify_patch_response(_NO_DIFF_BLOCK)
        assert result.status == "no_diff"
        assert result.block_count == 0
        assert result.diff == _NO_DIFF_BLOCK.strip()

    def test_h_real_trace_003_is_contract_violation_not_first_block(self):
        """The actual CVE-2023-43804 / urllib3 traced regression, call 1.
        The model's SECOND block is the correct Retry fix — this asserts
        only that the response is rejected outright, never that a
        particular candidate "should" win."""
        from utilities.autopatcher.patch_generator import classify_patch_response
        result = classify_patch_response(_TRACE_003_RESPONSE)
        assert result.status == "contract_violation"
        assert result.block_count == 2
        assert result.diff == ""

    def test_i_real_trace_004_is_contract_violation_not_first_block(self):
        """Same traced regression, call 2 (the applicability-aware retry
        response) — three candidates including one the model itself
        disavows ("Wait, that changes unrelated logic..."). Must still be
        rejected outright, never resolved to any one of the three."""
        from utilities.autopatcher.patch_generator import classify_patch_response
        result = classify_patch_response(_TRACE_004_RESPONSE)
        assert result.status == "contract_violation"
        assert result.block_count == 3
        assert result.diff == ""

    def test_whitespace_only_surrounding_a_single_diff_is_valid(self):
        """Explicit requirement: surrounding whitespace (blank lines,
        trailing newline) must remain valid — only non-whitespace prose is
        a violation."""
        from utilities.autopatcher.patch_generator import classify_patch_response
        result = classify_patch_response(_WHITESPACE_ONLY_SURROUNDING_DIFF)
        assert result.status == "valid"
        assert result.block_count == 1

    def test_multi_file_single_block_diff_remains_valid(self):
        """A single fence containing multiple --- a/ / +++ b/ file
        sections is still exactly ONE fenced block — must not be confused
        with "multiple diff blocks"."""
        from utilities.autopatcher.patch_generator import classify_patch_response
        result = classify_patch_response(_MULTI_FILE_DIFF)
        assert result.status == "valid"
        assert result.block_count == 1

    def test_empty_response_is_no_diff(self):
        from utilities.autopatcher.patch_generator import classify_patch_response
        result = classify_patch_response("")
        assert result.status == "no_diff"
        assert result.diff == ""


# ---------------------------------------------------------------------------
# F-29 regression: nested/embedded fences must not truncate the diff
# ---------------------------------------------------------------------------

class TestExtractDiffBlockNestedFences:
    def test_nested_markdown_fence_does_not_truncate_diff(self):
        from utilities.autopatcher.patch_generator import _extract_diff_block
        result = _extract_diff_block(_NESTED_FENCE_DIFF)
        assert result.count("```diff") == 1
        assert "openant patch --check" in result
        # The security-relevant change after the inner fenced block must survive.
        assert "lib/auth.py" in result
        assert "hmac.compare_digest(token, expected)" in result

    def test_quad_backtick_outer_fence_survives_triple_backtick_content(self):
        from utilities.autopatcher.patch_generator import _extract_diff_block
        result = _extract_diff_block(_QUAD_FENCE_DIFF)
        assert result.startswith("```diff\n")
        assert "echo hello" in result
        assert "README.md" in result

    def test_tilde_fenced_diff_normalised_to_diff(self):
        from utilities.autopatcher.patch_generator import _extract_diff_block
        result = _extract_diff_block(_TILDE_FENCE_DIFF)
        assert result.startswith("```diff\n")
        assert "+new_line()" in result
        assert "~~~" not in result

    def test_context_line_fence_not_mistaken_for_closer(self):
        """A single-space-prefixed context line reproducing a bare fence
        (as unified-diff grammar requires for unchanged content) must not
        be mistaken for the outer fence's closer."""
        from utilities.autopatcher.patch_generator import _extract_diff_block
        result = _extract_diff_block(_CONTEXT_LINE_FENCE_DIFF)
        assert result.count("```diff") == 1
        assert "-See docs." in result
        assert "+See documentation." in result

    def test_unclosed_recognised_fence_returns_empty_string(self):
        """A recognised opener with no matching closer is malformed
        structured output -- it must not be returned as partial content or
        silently repackaged as a complete-looking diff."""
        from utilities.autopatcher.patch_generator import _extract_diff_block
        result = _extract_diff_block(_UNCLOSED_FENCE_DIFF)
        assert result == ""

    def test_unclosed_first_block_not_merged_with_valid_second_block(self):
        """An unclosed first opener followed by an independently
        well-formed second block must not be merged or skipped past -- the
        first block is malformed on its own, so the whole extraction fails
        closed (""), regardless of the second block's validity."""
        from utilities.autopatcher.patch_generator import _extract_diff_block
        result = _extract_diff_block(_UNCLOSED_FIRST_THEN_VALID_SECOND_DIFF)
        assert result == ""


# ---------------------------------------------------------------------------
# Integration: generate_patch extracts clean output from messy LLM response
# ---------------------------------------------------------------------------

class TestGeneratePatchExtraction:
    def test_messy_response_with_prose_is_contract_violation(self):
        """Release: response-contract enforcement. Prose before AND after
        the single diff block used to be silently stripped — this is now a
        contract violation. generate_patch() makes exactly one LLM call and
        never retries internally (see pipeline.py's
        _generate_patch_with_contract_check for the bounded retry that
        lives one level up), so this must return "" outright, not a
        cleaned-up diff."""
        from utilities.autopatcher.patch_generator import generate_patch
        messy = (
            "I'll fix this by adding Cookie to the frozenset:\n\n"
            "```diff\n"
            "--- a/src/urllib3/util/retry.py\n"
            "+++ b/src/urllib3/util/retry.py\n"
            "@@ -187,7 +187,7 @@\n"
            '-    DEFAULT_REMOVE = frozenset(["Authorization"])\n'
            '+    DEFAULT_REMOVE = frozenset(["Cookie", "Authorization"])\n'
            "```\n\n"
            "Alternatively you could also strip X-Csrf-Token."
        )
        llm = mock.MagicMock()
        llm.complete.return_value = messy
        result = generate_patch("some vuln", llm)
        assert result == ""
        assert llm.complete.call_count == 1

    def test_fallback_when_no_fenced_block(self):
        from utilities.autopatcher.patch_generator import generate_patch
        plain = "No automated patch available for this vulnerability."
        llm = mock.MagicMock()
        llm.complete.return_value = plain
        result = generate_patch("some vuln", llm)
        assert result == plain.strip()


# ---------------------------------------------------------------------------
# F-29 integration regression: an unclosed recognised fence must not become
# an applicable patch after the real downstream repair/hygiene/applicability
# chain runs on it -- proven against the actual pipeline code, not asserted
# as a property of the extractor's output alone.
# ---------------------------------------------------------------------------

class TestUnclosedFenceCannotBecomeApplicable:
    def test_unclosed_fence_never_reaches_applicable_true(self, tmp_path):
        from utilities.autopatcher.patch_generator import _extract_diff_block
        from utilities.autopatcher.diff_hunk_repair import repair_hunk_headers
        from utilities.autopatcher.patch_hygiene import check_patch
        from utilities.autopatcher.patch_applicability import check_applicability

        (tmp_path / ".git").mkdir()

        # Same fence-open-but-never-closed input as the unit test above, run
        # through the real downstream chain in the same order pipeline.py
        # uses: repair -> hygiene -> applicability.
        patch = _extract_diff_block(_UNCLOSED_FENCE_DIFF)
        patch, _repair_meta = repair_hunk_headers(patch)
        check_patch(patch)  # hygiene is best-effort; must not raise
        result = check_applicability(patch, tmp_path)

        assert result["applicable"] is not True
        assert result["skipped"] is True
        assert "empty" in (result["skipped_reason"] or "").lower()

    def test_unclosed_first_block_with_valid_second_block_never_reaches_applicable_true(self, tmp_path):
        """An unclosed first opener followed by an independently
        well-formed second block must not, via the real downstream chain,
        end up applicable=True with either block's content -- and it must
        not merge the two into some other syntactically-valid patch either."""
        from utilities.autopatcher.patch_generator import _extract_diff_block
        from utilities.autopatcher.diff_hunk_repair import repair_hunk_headers
        from utilities.autopatcher.patch_hygiene import check_patch
        from utilities.autopatcher.patch_applicability import check_applicability

        (tmp_path / ".git").mkdir()

        patch = _extract_diff_block(_UNCLOSED_FIRST_THEN_VALID_SECOND_DIFF)
        patch, _repair_meta = repair_hunk_headers(patch)
        check_patch(patch)  # hygiene is best-effort; must not raise
        result = check_applicability(patch, tmp_path)

        assert result["applicable"] is not True
        assert result["skipped"] is True
        assert "empty" in (result["skipped_reason"] or "").lower()


# ---------------------------------------------------------------------------
# AUTOPATCHER_DEBUG prompt dump
# ---------------------------------------------------------------------------

class TestDebugDump:
    def test_debug_file_written_when_env_set(self, tmp_path, monkeypatch):
        from utilities.autopatcher.patch_generator import generate_patch

        monkeypatch.setenv("AUTOPATCHER_DEBUG", "1")
        # Redirect debug output to tmp_path
        monkeypatch.chdir(tmp_path)

        llm = mock.MagicMock()
        llm.complete.return_value = "```diff\n--- a/f.py\n+++ b/f.py\n```"

        generate_patch("SQL injection in auth.py", llm, code_context="def auth(): pass")

        debug_dir = tmp_path / "reports" / "debug"
        assert debug_dir.exists(), "reports/debug/ must be created"
        files = list(debug_dir.glob("prompt_*.txt"))
        assert len(files) == 1, f"Expected one debug file, found {files}"
        content = files[0].read_text()
        assert "SQL injection" in content
        assert "def auth(): pass" in content

    def test_no_debug_file_when_env_unset(self, tmp_path, monkeypatch):
        from utilities.autopatcher.patch_generator import generate_patch

        monkeypatch.delenv("AUTOPATCHER_DEBUG", raising=False)
        monkeypatch.chdir(tmp_path)

        llm = mock.MagicMock()
        llm.complete.return_value = "```diff\n--- a/f.py\n+++ b/f.py\n```"

        generate_patch("some vuln", llm)

        debug_dir = tmp_path / "reports" / "debug"
        assert not debug_dir.exists(), "No debug directory should be created without the env var"

    def test_debug_file_does_not_contain_api_key(self, tmp_path, monkeypatch):
        from utilities.autopatcher.patch_generator import generate_patch

        monkeypatch.setenv("AUTOPATCHER_DEBUG", "1")
        monkeypatch.chdir(tmp_path)

        llm = mock.MagicMock()
        llm.complete.return_value = "```diff\n--- a/f.py\n+++ b/f.py\n```"

        generate_patch("vuln text", llm, code_context="some code")

        debug_dir = tmp_path / "reports" / "debug"
        files = list(debug_dir.glob("prompt_*.txt"))
        assert files
        content = files[0].read_text()
        # user_message contains only vuln text + code context, never the API key
        assert "sk-" not in content
        assert "OPENAI_API_KEY" not in content


# ---------------------------------------------------------------------------
# retry_hint parameter
# ---------------------------------------------------------------------------

class TestRetryHint:
    def test_retry_hint_appended_to_user_message(self):
        from utilities.autopatcher.patch_generator import generate_patch

        llm = mock.MagicMock()
        llm.complete.return_value = "```diff\n--- a/f.py\n+++ b/f.py\n```"

        generate_patch(
            "some vuln",
            llm,
            code_context="def foo(): pass",
            retry_hint="Please fix the context lines.",
        )

        _system, user_message = llm.complete.call_args[0]
        assert "## Retry instruction" in user_message
        assert "Please fix the context lines." in user_message

    def test_no_retry_section_when_hint_empty(self):
        from utilities.autopatcher.patch_generator import generate_patch

        llm = mock.MagicMock()
        llm.complete.return_value = "```diff\n--- a/f.py\n+++ b/f.py\n```"

        generate_patch("some vuln", llm, code_context="def foo(): pass")

        _system, user_message = llm.complete.call_args[0]
        assert "## Retry instruction" not in user_message


# ---------------------------------------------------------------------------
# Base prompt content — no repository-specific contamination
# ---------------------------------------------------------------------------

class TestPromptGeneratorMarkdownIsGeneric:
    """The base system prompt is sent verbatim to every patch-generation
    call, for every target repository. It must never contain terms specific
    to one repository (e.g. GitPython internals leaked into the universal
    template) -- those are hard errors for a completely unrelated repo like
    urllib3, not real patch-generation rules."""

    # Exact, proven-leaked terms only -- not a broad denylist of every
    # benchmark repo name, and not generic words (`HEAD`, `file`, `git`,
    # `repository`, `path`) that would produce fragile false positives.
    _LEAKED_GITPYTHON_TERMS = [
        "for_git_dir",
        "repo.common_dir",
        "ORIG_HEAD",
        "FETCH_HEAD",
        "MERGE_HEAD",
        "LockedFD",
        "assure_directory_exists",
    ]

    def _prompt_text(self) -> str:
        from utilities.autopatcher.patch_generator import _PROMPT_PATH
        return _PROMPT_PATH.read_text(encoding="utf-8")

    def test_no_gitpython_specific_terms_in_base_prompt(self):
        prompt = self._prompt_text()
        leaked = [term for term in self._LEAKED_GITPYTHON_TERMS if term in prompt]
        assert leaked == [], f"repository-specific terms leaked into the universal prompt: {leaked}"

    def test_prompt_still_requires_a_unified_diff(self):
        prompt = self._prompt_text()
        assert "unified diff" in prompt.lower()

    def test_prompt_still_references_repository_code_context(self):
        prompt = self._prompt_text()
        assert "repository code context" in prompt.lower()

    def test_prompt_still_discourages_unrelated_changes(self):
        prompt = self._prompt_text()
        assert "unrelated" in prompt.lower()

    def test_prompt_still_honors_an_authoritative_patch_plan(self):
        prompt = self._prompt_text()
        assert "Patch Plan" in prompt
        assert "authoritative" in prompt.lower()
