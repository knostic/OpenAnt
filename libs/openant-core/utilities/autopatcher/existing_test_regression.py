"""Existing Test Comparison.

Answers one question, using deterministic evidence only:

    Does the repository's existing test suite have any NEW failures after
    the candidate patch that were not present before it?

This is a factual delta, not a judgment call. A newly failing test may be an
unintended regression, an expected/intended behavior change, a stale test,
a test that needs updating alongside the patch, or another intentional
consequence -- this module deliberately does not decide which. It reports
the deterministic before/after delta; a human decides what that delta means.

Architecture: repository evidence -> ONE bounded LLM Test Plan Discovery
call (test_plan_discovery.py) -> an immutable, validated TestExecutionPlan
(test_plan_validation.py) -> the SAME plan executed against an isolated,
unpatched copy (baseline) and an isolated copy with the FINAL candidate
patch applied (patched), via a generic executor (test_executors.py) ->
deterministic JUnit/TAP/runner-summary/exit-code comparison. A baseline does not need to
be green; a pre-existing failure is never attributed to the patch. JUnit
and TAP are both normalized into the SAME per-test result shape
(result_parsers.ParsedTestCounts) before reaching this module's own
comparator (compare_runs) -- there is no separate TAP-specific comparison
path, and no result-format-specific branch anywhere below
_to_test_run_result.

Scope (explicit product decision, matching the precedent set by
source_verification.py's Evidence Sufficiency Gate): this module produces
a signal and a report section only. It is deliberately NOT read by
pipeline._build_recommendation_v1 -- Recommendation Policy is unchanged by
this feature's presence. Feeding a detected new failure back into
repair/Challenger is explicitly out of scope for this slice.

This module contains NO tool-specific knowledge (no mention of pytest,
npm, go test, tox, etc.) -- that knowledge lives only in a
TestExecutionPlan's field VALUES, produced by test_plan_discovery.py from
repository evidence, never in this module's code.

Naming note: this module's filename, and a handful of internal identifiers
that reference it by name in other modules' docstrings/comments (e.g.
``existing_test_regression.py``), were deliberately NOT renamed alongside
the public API below -- see the project's regression-terminology cleanup
notes. Renaming a module's file path churns every importer for a purely
cosmetic gain; the externally visible names (the class, the status
constants, the functions) are what actually communicate the "comparison,
not verdict" semantics, and those are what changed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .patch_applicability import apply_patch
from .patch_workspace import temporary_repo_copy
from .result_parsers import parse_result
from .test_execution_models import TestExecutionPlan, TestExecutionResult
from .test_executors import (
    DEFAULT_RUN_TIMEOUT,
    DEFAULT_SETUP_TIMEOUT,
    is_runtime_supported,
    select_executor,
)
from .test_plan_discovery import discover_test_plan

STATUS_PASS = "PASS"
STATUS_NEW_FAILURES_DETECTED = "NEW_FAILURES_DETECTED"
STATUS_PRE_EXISTING_FAILURES_ONLY = "PRE_EXISTING_FAILURES_ONLY"
STATUS_NOT_VERIFIED = "NOT_VERIFIED"
STATUS_TEST_EXECUTION_ERROR = "TEST_EXECUTION_ERROR"

_MAX_EXCERPT_CHARS = 4_000
_EXCERPT_HEAD_CHARS = _MAX_EXCERPT_CHARS // 2
_EXCERPT_TAIL_CHARS = _MAX_EXCERPT_CHARS - _EXCERPT_HEAD_CHARS


def preflight_test_comparison_environment():
    """Cheap, deterministic readiness check for the executor Existing
    Test Comparison would use -- WITHOUT running Test Plan Discovery,
    evidence acquisition, or any workspace/Docker build/run work. Returns
    a ``test_execution_models.ExecutorPreflightResult``.

    Exposed as a public, standalone entry point so ``core.patch`` can
    call it BEFORE the Auto Patcher pipeline (repository grounding,
    Repository Understanding, remediation planning, patch generation --
    all of it) ever starts, when ``--compare-existing-tests`` was
    explicitly requested -- see
    ``core.patch._require_test_comparison_environment``. This is
    intentionally the exact same check
    ``evaluate_existing_test_comparison`` performs again, later, on its
    own (defense-in-depth for direct internal callers, future executor
    changes, and environment drift between this early check and actual
    execution) -- calling ``docker info`` twice on a successful run is an
    accepted, deliberately-not-cached tradeoff; see that function's own
    preflight comment for why simple ownership wins over avoiding the
    second probe.
    """
    return select_executor("docker").preflight()


def _excerpt(text: "str | None") -> str:
    """Bound `text` to _MAX_EXCERPT_CHARS TOTAL, keeping both the
    beginning AND the end -- never head-only. Many tools' actionable
    summary (pytest's final pass/fail counts and failure list included)
    is printed at the END of a long run, not the start; a head-only
    excerpt discards exactly that content. This makes no assumption about
    ANY specific tool's output format -- it is a fixed, generic
    head+tail/omit-the-middle shape applied identically regardless of
    what produced `text`.

    Operates on the executor's full, untruncated capture (see
    test_executors.py -- this is now the ONLY truncation point in the
    whole pipeline), so the tail this keeps is the REAL tail of the
    stream, not the tail of some earlier, unrelated size cut.

    Below the total budget, `text` is returned byte-for-byte unchanged."""
    text = text or ""
    if len(text) <= _MAX_EXCERPT_CHARS:
        return text
    head = text[:_EXCERPT_HEAD_CHARS]
    tail = text[-_EXCERPT_TAIL_CHARS:]
    omitted = len(text) - _EXCERPT_HEAD_CHARS - _EXCERPT_TAIL_CHARS
    return f"{head}\n[… {omitted} character(s) omitted from the middle …]\n{tail}"


# ---------------------------------------------------------------------------
# Runner-summary counts -- a fallback evidence tier for the wrapper-command
# class of test entry point (nox/tox/Make/etc.), where no structured
# junit/tap report exists at all. Deterministic and generic: it recognizes
# generic OUTCOME WORDS immediately adjacent to a number on a SINGLE line,
# never any specific runner's exact phrasing or name -- consistent with
# this module's "no tool-specific knowledge" rule (see module docstring).
#
# Validated empirically against the real urllib3 CVE-2023-43804 capture
# (recovered the true 103->104 failed / 1639->1638 passed / 563 skipped
# delta cleanly, with zero competing candidates) and stress-tested against
# warning prose, progress lines, exception text, timing/percentage noise,
# and a synthetic multi-session capture (correctly failed closed on all of
# them) -- see the architecture investigation this implements.
#
# Deliberately NOT attempted, per that investigation's own conclusions:
#   - multi-line summary stitching (single-line candidates only)
#   - a "Tests run: N" tolerance for Maven/Surefire's real phrasing (its
#     label and number are separated by an extra word -- accepting that
#     would mean special-casing that exact phrase)
#   - deriving a PASSED count from a TOTAL count by subtraction
# All three would add either runner-specific knowledge or a first
# arithmetic-inference step this feature has never needed anywhere else.
# ---------------------------------------------------------------------------

_SUMMARY_TAIL_LINES = 300

# FAILED and ERRORED are kept as separate buckets, not merged as synonyms.
# pytest itself reports them separately when both occur ("1 failed, 1
# error, 8 passed"), and Maven/Surefire's "Failures: N, Errors: M" is a
# real, non-synonymous convention -- merging them (tried during
# investigation) caused Maven's own legitimate shape to be rejected as
# "conflicting counts for one bucket."
_SUMMARY_BUCKETS = {
    "FAILED":  r'fail(?:s|ed|ure|ures)?',
    "ERRORED": r'error(?:s|ed)?',
    "PASSED":  r'pass(?:es|ed)?|success(?:es)?',
    "SKIPPED": r'skip(?:s|ped)?|xfail(?:ed)?|ignored',
    "TOTAL":   r'tests?',
}
_SUMMARY_LABEL_ALT = "|".join(f"(?P<{name}>{pattern})" for name, pattern in _SUMMARY_BUCKETS.items())

# "103 failed", "1639 passed" -- a count immediately followed by a label.
_NUM_THEN_LABEL_RE = re.compile(
    rf'(?<![\d.])(?P<count>\d{{1,7}})\s+(?:{_SUMMARY_LABEL_ALT})\b', re.IGNORECASE,
)
# "Failures: 3", "Tests: 100" -- a label immediately followed by its own
# count, with only whitespace or a single colon in between. Deliberately
# strict: an earlier, looser version of this pattern let a label "reach
# across" a comma into an UNRELATED clause's own number (e.g. "failed,
# 1639 passed" was misread as failed=1639) -- no intervening punctuation
# or extra words are allowed between a label and its number.
_LABEL_THEN_NUM_RE = re.compile(
    rf'\b(?:{_SUMMARY_LABEL_ALT})\b(?:\s*:\s*|\s+)(?P<count>\d{{1,7}})(?!\d)', re.IGNORECASE,
)

_SUMMARY_FAIL_SIDE = frozenset({"FAILED", "ERRORED"})
_SUMMARY_RESOLUTION_SIDE = frozenset({"PASSED", "TOTAL"})

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')


def _summary_bucket_of(match: "re.Match") -> "str | None":
    for name in _SUMMARY_BUCKETS:
        if match.group(name):
            return name
    return None


def _extract_summary_pairs(line: str) -> "dict[str, int] | None":
    """(bucket -> count) for ONE already-normalized line, or None if the
    same bucket would receive two DIFFERENT values on this line -- fails
    closed on ambiguity rather than picking one."""
    found: "dict[str, int]" = {}
    for regex in (_NUM_THEN_LABEL_RE, _LABEL_THEN_NUM_RE):
        for m in regex.finditer(line):
            bucket = _summary_bucket_of(m)
            count = int(m.group("count"))
            if bucket in found and found[bucket] != count:
                return None
            found[bucket] = count
    return found


def _is_plausible_summary(pairs: "dict[str, int] | None") -> bool:
    """A candidate must report at least two distinct outcome categories
    AND span both a fail-side bucket (failed/errored) and a resolution-
    side bucket (passed/total). This is what tells an actual test-run
    summary line apart from incidental prose that happens to mention two
    failure-domain words together (e.g. an unrelated warning about "3
    errors, 4 failures" from an upstream service, which has no
    resolution-side count at all) -- a real, adversarial case this
    rejected during investigation."""
    if not pairs or len(pairs) < 2:
        return False
    return bool(_SUMMARY_FAIL_SIDE & pairs.keys()) and bool(_SUMMARY_RESOLUTION_SIDE & pairs.keys())


def _find_runner_summary(stdout: "str | None") -> "dict[str, int] | None":
    """Scan the true TAIL of `stdout` (bounded, and kept near the END of
    execution, where a final summary conventionally lives -- never the
    whole stream) for exactly ONE plausible aggregate-count candidate
    line. Returns that candidate's (bucket -> count) mapping, or None if
    zero or more than one plausible candidate was found. Never guesses
    among multiple candidates, never merges or aggregates them -- a
    multi-session/multi-interpreter wrapper producing more than one real
    summary line in the same stream is exactly the ambiguous case this
    must decline, not silently resolve."""
    if not stdout:
        return None
    lines = stdout.splitlines()[-_SUMMARY_TAIL_LINES:]
    candidates: "list[dict[str, int]]" = []
    for raw_line in lines:
        line = _ANSI_RE.sub('', raw_line)
        line = re.sub(r'\s+', ' ', line.strip())
        if not line:
            continue
        pairs = _extract_summary_pairs(line)
        if _is_plausible_summary(pairs):
            candidates.append(pairs)
    if len(candidates) != 1:
        return None
    return candidates[0]


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

@dataclass
class TestRunResult:
    """One side (baseline or patched) of an Existing Test Comparison run.

    ``status`` describes THIS run's own execution outcome -- distinct from
    ``ExistingTestComparisonResult.status``, the two-sided comparison's
    outcome:
        COMPLETED     -- the test command ran to completion and produced
                         at least exit-code-level evidence.
        SETUP_FAILED  -- setup_commands and/or the image build failed or
                         timed out (an environment problem, not a test
                         result).
        TIMED_OUT     -- the container did not finish within the run budget.
        UNPARSEABLE   -- the run completed but produced no usable evidence
                         at all (no exit code, and declared junit output
                         was empty/malformed with nothing to fall back to).
        NOT_ATTEMPTED -- this side was never run (e.g. baseline already
                         unusable, so the patched side was skipped, or the
                         candidate patch failed to apply).

    ``evidence_level`` describes how granular the comparison evidence is:
        OK              -- per-test IDs available (junit, full parse).
        COUNTS_ONLY     -- only aggregate pass/fail/skip/error counts
                           (junit, suite-level-only parse).
        RUNNER_SUMMARY_COUNTS -- aggregate counts parsed from the test
                           command's own final summary line via generic
                           outcome-word/number adjacency, attempted only
                           when no structured junit/tap report was
                           available at all (see _find_runner_summary).
                           Weaker than COUNTS_ONLY -- a real structured
                           report format is still stronger evidence than
                           deterministically-parsed free text.
        EXIT_CODE_ONLY  -- only the process exit code (result_strategy
                           "exit_code", or "junit"/"tap" declared but
                           unavailable/unparseable and no runner-summary
                           candidate found either -- see
                           _to_test_run_result).
        UNAVAILABLE     -- no usable evidence at all.
    """
    __test__ = False  # not a pytest test class -- name collides with pytest's Test* discovery

    command: "tuple[str, ...]"
    status: str
    exit_code: "int | None"
    duration_seconds: float
    passed: "int | None"
    failed: "int | None"
    skipped: "int | None"
    errors: "int | None"
    failed_test_ids: "list[str] | None"
    stdout_excerpt: str
    stderr_excerpt: str
    timed_out: bool
    evidence_level: str
    reason: "str | None" = None

    @property
    def total(self) -> "int | None":
        if self.passed is None:
            return None
        return (self.passed or 0) + (self.failed or 0) + (self.skipped or 0) + (self.errors or 0)


def _not_attempted(command: "tuple[str, ...]", reason: str) -> TestRunResult:
    return TestRunResult(
        command=command, status="NOT_ATTEMPTED", exit_code=None, duration_seconds=0.0,
        passed=None, failed=None, skipped=None, errors=None, failed_test_ids=None,
        stdout_excerpt="", stderr_excerpt="", timed_out=False,
        evidence_level="UNAVAILABLE", reason=reason,
    )


@dataclass
class ExistingTestComparisonResult:
    """Baseline-vs-patched comparison outcome. ``reason`` is always a
    populated, human-readable sentence -- the report renders it verbatim
    for every non-comparison status.

    ``status`` reports a factual delta (did a previously-passing test now
    fail?), never a judgment about whether that delta is good or bad --
    see the module docstring."""
    status: str
    command: "tuple[str, ...] | None"
    baseline: "TestRunResult | None"
    patched: "TestRunResult | None"
    newly_failing_tests: "list[str]" = field(default_factory=list)
    pre_existing_failures: "list[str]" = field(default_factory=list)
    newly_passing_tests: "list[str]" = field(default_factory=list)
    reason: str = ""
    plan: "TestExecutionPlan | None" = None  # provenance for the report (§ render below)


def not_verified_result(reason: str, command: "tuple[str, ...] | None" = None,
                         baseline: "TestRunResult | None" = None,
                         plan: "TestExecutionPlan | None" = None) -> ExistingTestComparisonResult:
    """Public constructor for a NOT_VERIFIED result -- used both internally
    and by pipeline.py for its own pre-flight skip checks, so every "we
    didn't run this" path produces the exact same shape."""
    return ExistingTestComparisonResult(
        status=STATUS_NOT_VERIFIED, command=command, baseline=baseline, patched=None, reason=reason, plan=plan,
    )


# Backwards-compatible private alias for this module's own internal call sites.
_not_verified = not_verified_result


def _not_started(detail: str) -> ExistingTestComparisonResult:
    """NOT_VERIFIED specifically for an environment-preflight failure --
    i.e. Existing Test Comparison never even started (no evidence
    acquisition, no LLM call, no workspace/Docker work), as opposed to
    having started and then being unable to interpret a result. The "did
    not start" framing composes with render_existing_test_comparison's
    existing "Existing tests could not be compared because {reason}"
    wrapper to read as an environment prerequisite failure, not a
    test-result judgement -- no separate report-rendering change needed
    for that distinction."""
    return _not_verified(f"test comparison did not start: {detail}")


def test_execution_error_result(reason: str,
                                 baseline: "TestRunResult | None" = None,
                                 patched: "TestRunResult | None" = None,
                                 command: "tuple[str, ...] | None" = None,
                                 plan: "TestExecutionPlan | None" = None) -> ExistingTestComparisonResult:
    """Public constructor for a TEST_EXECUTION_ERROR result -- for an
    unexpected crash in OUR OWN execution path (harness/setup problem),
    distinct from NOT_VERIFIED (a known, anticipated "can't verify this"
    case)."""
    return ExistingTestComparisonResult(
        status=STATUS_TEST_EXECUTION_ERROR, command=command, baseline=baseline, patched=patched,
        reason=reason, plan=plan,
    )


# Structured (per-test) result strategies -> their raw text source and a
# display label used only in the fallback/failure `reason` strings below.
# "exit_code" is deliberately absent -- it has no structured source at
# all, and is handled by the plain fallthrough branch after this one.
_STRUCTURED_RESULT_LABELS = {"junit": "JUnit", "tap": "TAP"}


def _structured_source_text(plan: TestExecutionPlan, raw: TestExecutionResult) -> "str | None":
    """Where a structured-result strategy's raw text actually comes from.
    JUnit reads the report file content the executor already extracted
    into ``raw.result_output`` (from ``result_output_path``). TAP has no
    separate report file -- test_plan_validation.py requires
    ``result_output_path`` be null for it -- so it is read directly from
    the test command's own normal captured stdout (see
    test_plan_discovery.py's "TAP RESULT SOURCE" policy and
    tap_parser.py's module docstring).

    ``raw.stdout`` here is the executor's FULL, untruncated capture, not
    a bounded excerpt -- test_executors.py performs no truncation of its
    own; _excerpt() below is the one and only place output gets bounded,
    and it is applied separately, only when building the report-facing
    TestRunResult, never to the text a structured-result parser reads.
    This is what lets TAP (like JUnit already did) see the complete
    stream regardless of its size."""
    if plan.result_strategy == "junit":
        return raw.result_output
    if plan.result_strategy == "tap":
        return raw.stdout
    return None


def _build_evidence_from_exit_code(
    plan: TestExecutionPlan, raw: TestExecutionResult, *, unavailable_reason: "str | None",
) -> TestRunResult:
    """Common tail for _to_test_run_result whenever no structured
    (junit/tap) per-test evidence is available and raw.exit_code IS
    present: try the generic runner-summary-counts fallback before
    settling for bare exit-code evidence. `unavailable_reason`, when
    given, is the declared-but-unavailable explanation for a junit/tap
    plan that fell through to this point; None for a plain exit_code
    plan -- preserved verbatim as the EXIT_CODE_ONLY reason when no
    runner-summary candidate is found, exactly as before this fallback
    existed."""
    summary = _find_runner_summary(raw.stdout)
    if summary is not None:
        return TestRunResult(
            command=plan.test_command, status="COMPLETED", exit_code=raw.exit_code,
            duration_seconds=raw.duration_seconds,
            passed=summary.get("PASSED"), failed=summary.get("FAILED"),
            skipped=summary.get("SKIPPED"), errors=summary.get("ERRORED"),
            failed_test_ids=None, stdout_excerpt=_excerpt(raw.stdout), stderr_excerpt=_excerpt(raw.stderr),
            timed_out=False, evidence_level="RUNNER_SUMMARY_COUNTS", reason=None,
        )
    return TestRunResult(
        command=plan.test_command, status="COMPLETED", exit_code=raw.exit_code,
        duration_seconds=raw.duration_seconds, passed=None, failed=None, skipped=None, errors=None,
        failed_test_ids=None, stdout_excerpt=_excerpt(raw.stdout), stderr_excerpt=_excerpt(raw.stderr),
        timed_out=False, evidence_level="EXIT_CODE_ONLY", reason=unavailable_reason,
    )


def _to_test_run_result(plan: TestExecutionPlan, raw: TestExecutionResult) -> TestRunResult:
    if raw.setup_failed:
        return TestRunResult(
            command=plan.test_command, status="SETUP_FAILED", exit_code=None,
            duration_seconds=raw.duration_seconds, passed=None, failed=None, skipped=None, errors=None,
            failed_test_ids=None, stdout_excerpt=_excerpt(raw.stdout), stderr_excerpt=_excerpt(raw.stderr),
            timed_out=raw.timed_out, evidence_level="UNAVAILABLE",
            reason=f"Setup/build failed: {_excerpt(raw.setup_error)}",
        )
    if raw.timed_out:
        return TestRunResult(
            command=plan.test_command, status="TIMED_OUT", exit_code=None,
            duration_seconds=raw.duration_seconds, passed=None, failed=None, skipped=None, errors=None,
            failed_test_ids=None, stdout_excerpt=_excerpt(raw.stdout), stderr_excerpt=_excerpt(raw.stderr),
            timed_out=True, evidence_level="UNAVAILABLE",
            reason="test run did not complete within the time budget",
        )

    if plan.result_strategy in _STRUCTURED_RESULT_LABELS:
        label = _STRUCTURED_RESULT_LABELS[plan.result_strategy]
        parsed = parse_result(plan.result_strategy, _structured_source_text(plan, raw))
        if parsed is not None:
            total = parsed.passed + parsed.failed + parsed.skipped + parsed.errors
            if total > 0:
                return TestRunResult(
                    command=plan.test_command, status="COMPLETED", exit_code=raw.exit_code,
                    duration_seconds=raw.duration_seconds, passed=parsed.passed, failed=parsed.failed,
                    skipped=parsed.skipped, errors=parsed.errors, failed_test_ids=parsed.failed_test_ids,
                    stdout_excerpt=_excerpt(raw.stdout), stderr_excerpt=_excerpt(raw.stderr),
                    timed_out=False, evidence_level=("OK" if parsed.mode == "full" else "COUNTS_ONLY"),
                    reason=None,
                )
        # Structured output was declared but is unavailable/unparseable/
        # empty (for TAP this also covers a parser that fails closed on
        # malformed/truncated/ambiguous input -- see tap_parser.parse_tap)
        # -- try the generic runner-summary-counts fallback before
        # settling for bare exit-code evidence; a real exit code is still
        # real, if coarser, evidence either way. The SAME fallback serves
        # both junit and tap -- see the module docstring's "reuse the same
        # comparator abstraction".
        if raw.exit_code is not None:
            return _build_evidence_from_exit_code(
                plan, raw,
                unavailable_reason=(
                    f"{label} output was declared but unavailable/unparseable; "
                    "falling back to exit-code evidence"
                ),
            )
        return TestRunResult(
            command=plan.test_command, status="UNPARSEABLE", exit_code=raw.exit_code,
            duration_seconds=raw.duration_seconds, passed=None, failed=None, skipped=None, errors=None,
            failed_test_ids=None, stdout_excerpt=_excerpt(raw.stdout), stderr_excerpt=_excerpt(raw.stderr),
            timed_out=False, evidence_level="UNAVAILABLE",
            reason=f"no usable {label} or exit-code evidence was produced",
        )

    # result_strategy == "exit_code"
    if raw.exit_code is None:
        return TestRunResult(
            command=plan.test_command, status="UNPARSEABLE", exit_code=None,
            duration_seconds=raw.duration_seconds, passed=None, failed=None, skipped=None, errors=None,
            failed_test_ids=None, stdout_excerpt=_excerpt(raw.stdout), stderr_excerpt=_excerpt(raw.stderr),
            timed_out=False, evidence_level="UNAVAILABLE",
            reason="no exit code was captured",
        )
    return _build_evidence_from_exit_code(plan, raw, unavailable_reason=None)


# ---------------------------------------------------------------------------
# Comparison -- deterministic; every fallback is conservative by design.
#
# This algorithm reports a FACTUAL DELTA, never a judgment: it does not
# infer whether a newly-failing test is an unintended regression, an
# expected/intended behavior change, a stale test, or something else --
# only that a test which passed on the baseline failed on the patched run
# (or vice versa). See the module docstring.
# ---------------------------------------------------------------------------

_EVIDENCE_LEVEL_RANK = {
    "UNAVAILABLE": 0, "EXIT_CODE_ONLY": 1, "RUNNER_SUMMARY_COUNTS": 2, "COUNTS_ONLY": 3, "OK": 4,
}


def _populated_count_buckets(r: TestRunResult) -> "frozenset[str]":
    """Which of TestRunResult's own count fields this side's evidence
    actually populated -- used only to decide whether baseline and
    patched RUNNER_SUMMARY_COUNTS candidates are comparable at all (they
    must expose the identical set; anything else -- e.g. one side's
    summary line omitting a zero-count category the other side's line
    happens to include -- is a reporting-shape mismatch, not something
    safe to paper over by assuming the missing one means zero)."""
    fields = {"passed": r.passed, "failed": r.failed, "skipped": r.skipped, "errors": r.errors}
    return frozenset(name for name, value in fields.items() if value is not None)


def _compare_exit_code_only(command, baseline: TestRunResult, patched: TestRunResult) -> ExistingTestComparisonResult:
    b_ok = baseline.exit_code == 0
    p_ok = patched.exit_code == 0
    if b_ok and p_ok:
        return ExistingTestComparisonResult(
            status=STATUS_PASS, command=command, baseline=baseline, patched=patched,
            reason="Both baseline and patched exited 0 (exit-code-only evidence).",
        )
    if b_ok and not p_ok:
        return ExistingTestComparisonResult(
            status=STATUS_NEW_FAILURES_DETECTED, command=command, baseline=baseline, patched=patched,
            reason=(
                "Baseline exited 0 but patched exited non-zero under the identical command; "
                "this is command-level (exit-code-only) evidence -- individual newly-failing "
                "tests are not available."
            ),
        )
    if not b_ok and not p_ok:
        return ExistingTestComparisonResult(
            status=STATUS_NOT_VERIFIED, command=command, baseline=baseline, patched=patched,
            reason=(
                "Both baseline and patched exited non-zero; exit-code-only evidence cannot "
                "distinguish a new failure from a pre-existing failure."
            ),
        )
    # not b_ok and p_ok
    return ExistingTestComparisonResult(
        status=STATUS_PASS, command=command, baseline=baseline, patched=patched,
        reason="Patched exited 0 (exit-code-only evidence) -- no failures remain, whatever failed before.",
    )


def _compare_by_aggregate_counts(
    command, baseline: TestRunResult, patched: TestRunResult, *, new_failure_note: str,
) -> ExistingTestComparisonResult:
    """Shared count-based comparison for COUNTS_ONLY and
    RUNNER_SUMMARY_COUNTS -- both reduce to the identical question ('did
    the aggregate bad-count go up'); only the evidence-tier-appropriate
    caveat in the NEW_FAILURES_DETECTED reason differs, so a reader never
    mistakes a heuristic aggregate delta for structured per-test proof."""
    b_bad = (baseline.failed or 0) + (baseline.errors or 0)
    p_bad = (patched.failed or 0) + (patched.errors or 0)
    if p_bad > b_bad:
        return ExistingTestComparisonResult(
            status=STATUS_NEW_FAILURES_DETECTED, command=command, baseline=baseline, patched=patched,
            reason=(
                f"Failure/error count increased from {b_bad} to {p_bad}; individual "
                f"newly-failing tests could not be identified ({new_failure_note}) -- "
                "count-based evidence only."
            ),
        )
    if p_bad > 0:
        return ExistingTestComparisonResult(
            status=STATUS_PRE_EXISTING_FAILURES_ONLY, command=command, baseline=baseline, patched=patched,
            reason=(
                f"{p_bad} failure(s)/error(s), not more than baseline ({b_bad}); "
                "count-based comparison only; no new failures indicated."
            ),
        )
    return ExistingTestComparisonResult(
        status=STATUS_PASS, command=command, baseline=baseline, patched=patched,
        reason="No failures in either run (count-based comparison only).",
    )


def compare_runs(
    command: "tuple[str, ...]", baseline: TestRunResult, patched: TestRunResult,
) -> ExistingTestComparisonResult:
    """Compare two COMPLETED runs of the identical command/plan. Callers
    must have already ruled out timeout/setup failures on either side --
    this function only implements the comparison algorithm itself.

    Uses the WEAKER of the two sides' evidence levels for both -- e.g. if
    baseline has full per-test IDs but patched only has an exit code, the
    comparison is exit-code-only for both, never a partial/asymmetric
    claim."""
    b_rank = _EVIDENCE_LEVEL_RANK.get(baseline.evidence_level, 0)
    p_rank = _EVIDENCE_LEVEL_RANK.get(patched.evidence_level, 0)
    effective_rank = min(b_rank, p_rank)

    if effective_rank == 0:
        return ExistingTestComparisonResult(
            status=STATUS_NOT_VERIFIED, command=command, baseline=baseline, patched=patched,
            reason="Baseline and patched test output could not be compared reliably.",
        )

    if effective_rank == 1:
        return _compare_exit_code_only(command, baseline, patched)

    if effective_rank == 2:
        # RUNNER_SUMMARY_COUNTS -- deterministic aggregate counts parsed
        # from the final runner-summary line, never structured per-test
        # output. Baseline and patched must additionally expose the
        # IDENTICAL set of populated count buckets before being treated
        # as comparable at all; any mismatch falls back to plain
        # exit-code comparison rather than guessing which side's shape is
        # "right".
        if _populated_count_buckets(baseline) != _populated_count_buckets(patched):
            return _compare_exit_code_only(command, baseline, patched)
        return _compare_by_aggregate_counts(
            command, baseline, patched,
            new_failure_note="evidence is deterministic aggregate runner-summary counts, not structured per-test output",
        )

    if effective_rank == 3:
        return _compare_by_aggregate_counts(
            command, baseline, patched, new_failure_note="structured per-test IDs were unavailable",
        )

    # effective_rank == 4 -- full per-test-ID evidence on both sides
    b_ids = set(baseline.failed_test_ids or [])
    p_ids = set(patched.failed_test_ids or [])
    newly_failing = sorted(p_ids - b_ids)
    pre_existing = sorted(p_ids & b_ids)
    newly_passing = sorted(b_ids - p_ids)

    if newly_failing:
        status, reason = STATUS_NEW_FAILURES_DETECTED, f"{len(newly_failing)} test(s) newly failing after the patch."
    elif p_ids:
        status, reason = STATUS_PRE_EXISTING_FAILURES_ONLY, (
            f"{len(p_ids)} pre-existing failure(s); no new failures after the patch."
        )
    else:
        status, reason = STATUS_PASS, "No failures in either the baseline or the patched run."

    return ExistingTestComparisonResult(
        status=status, command=command, baseline=baseline, patched=patched,
        newly_failing_tests=newly_failing, pre_existing_failures=pre_existing,
        newly_passing_tests=newly_passing, reason=reason,
    )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def _baseline_unusable_reason(baseline: TestRunResult) -> str:
    if baseline.status == "SETUP_FAILED":
        return f"Baseline test environment could not be established: {baseline.reason}"
    if baseline.status == "TIMED_OUT":
        return "Baseline test run timed out; no trustworthy baseline could be established."
    return f"Baseline test output could not be interpreted: {baseline.reason or baseline.status}"


def discover_test_plan_for_comparison(
    repo_root: "Path | str", patch: str, llm,
) -> "tuple[TestExecutionPlan | None, ExistingTestComparisonResult | None, object | None]":
    """The DISCOVERY half of what used to be one fused
    evaluate_existing_test_comparison() call (extracted so a caller --
    pipeline.run(), for canonical Stage-10/Stage-11 StageExecution
    recording -- can record test-plan discovery and existing-test
    comparison as separate, truthful executions; see
    evaluate_existing_test_comparison_with_plan() for the other half).

    Returns ``(plan, None, executor)`` when a TestExecutionPlan was
    discovered, or ``(None, early_result, None)`` when comparison must
    stop before (or at) discovery -- ``early_result`` is EXACTLY the
    ExistingTestComparisonResult evaluate_existing_test_comparison() would
    have returned at that same point, unchanged: identical reasons,
    identical NOT_VERIFIED/TEST_EXECUTION_ERROR shapes.

    ``executor``: the SAME already-preflighted executor instance this
    function itself just selected, returned so a caller that goes on to
    run evaluate_existing_test_comparison_with_plan() can pass it straight
    through (``executor=``) and skip a second, redundant ``.preflight()``
    call -- preserving the original function's "exactly one preflight
    call" behavior even when discovery and comparison are invoked as two
    separate steps. ``None`` whenever no executor was successfully
    preflighted (every early-stop case above).

    Environment preflight (fail-fast, BEFORE any LLM/Docker cost): cheap,
    deterministic checks -- candidate patch present, repo_root is a real
    directory, and the selected executor's own ``.preflight()`` -- all run
    before gather_test_plan_evidence/discover_test_plan is ever called.
    This is the fix for a real observed failure mode: Test Plan Discovery
    spending an LLM call and then execution failing anyway because the
    Docker daemon was not running.

    Never raises: any unexpected internal failure degrades to a
    TEST_EXECUTION_ERROR result, same as evaluate_existing_test_comparison
    itself.
    """
    try:
        repo_root = Path(repo_root)

        if not patch or not patch.strip():
            return None, _not_started("no candidate patch was provided"), None
        if not repo_root.is_dir():
            return None, _not_started(f"repository root does not exist or is not a directory: {repo_root}"), None

        executor = select_executor("docker")
        preflight = executor.preflight()
        if not preflight.ready:
            return None, _not_started(preflight.reason), None

        plan = discover_test_plan(repo_root, llm)
        if plan is None:
            return None, _not_verified(
                "no reliable test execution plan could be discovered for this repository"
            ), executor
        return plan, None, executor
    except Exception as exc:  # noqa: BLE001 -- never let this feature crash the pipeline
        return None, ExistingTestComparisonResult(
            status=STATUS_TEST_EXECUTION_ERROR, command=None, baseline=None, patched=None,
            reason=f"Existing Test Comparison failed unexpectedly: {type(exc).__name__}: {exc}",
        ), None


def evaluate_existing_test_comparison_with_plan(
    repo_root: "Path | str",
    patch: str,
    plan: TestExecutionPlan,
    setup_timeout: int = DEFAULT_SETUP_TIMEOUT,
    run_timeout: int = DEFAULT_RUN_TIMEOUT,
    executor: object = None,
) -> ExistingTestComparisonResult:
    """The COMPARISON half of what used to be one fused
    evaluate_existing_test_comparison() call: given an ALREADY-discovered
    ``plan`` (see discover_test_plan_for_comparison()), run the baseline
    and patched executions and compare them. Never mutates ``repo_root``.
    Never re-discovers a plan -- there is no code path here capable of
    calling discover_test_plan(). Never raises.

    ``executor``: optional, an already-selected-and-preflighted executor
    (as returned by discover_test_plan_for_comparison()) -- when given,
    reused as-is with NO second ``.preflight()`` call, preserving the
    original fused function's "exactly one preflight call" behavior. When
    omitted (``None``, e.g. a caller that only ever wants the comparison
    half and hasn't already preflighted one itself), this function selects
    and preflights its own, same as before this module's discovery/
    comparison split.

    Fail-fast ordering (same as evaluate_existing_test_comparison(), minus
    the discovery step, which the caller already did):
      1. environment preflight (executor readiness, skipped if `executor`
         was already given ready) -- zero Docker build either way
      2. runtime-support check (no Docker work if unsupported)
      3. baseline run -- patched side is skipped entirely if unusable
      4. patched run (final candidate patch applied, same plan)
      5. comparison
    """
    try:
        repo_root = Path(repo_root)

        if executor is None:
            executor = select_executor("docker")
            preflight = executor.preflight()
            if not preflight.ready:
                return _not_started(preflight.reason)

        if not is_runtime_supported(plan.runtime_family):
            return _not_verified(
                f"runtime not supported yet: {plan.runtime_family!r}",
                command=plan.test_command, plan=plan,
            )

        baseline = _run_side(repo_root, plan, executor, patch=None,
                              setup_timeout=setup_timeout, run_timeout=run_timeout)
        if baseline.status != "COMPLETED":
            return ExistingTestComparisonResult(
                status=STATUS_NOT_VERIFIED, command=plan.test_command, baseline=baseline, patched=None,
                reason=_baseline_unusable_reason(baseline), plan=plan,
            )

        patched, apply_error = _run_side_with_patch(
            repo_root, plan, executor, patch, setup_timeout=setup_timeout, run_timeout=run_timeout,
        )
        if apply_error is not None:
            return ExistingTestComparisonResult(
                status=STATUS_TEST_EXECUTION_ERROR, command=plan.test_command, baseline=baseline, patched=None,
                reason=apply_error, plan=plan,
            )

        if patched.status == "TIMED_OUT":
            result = ExistingTestComparisonResult(
                status=STATUS_TEST_EXECUTION_ERROR, command=plan.test_command, baseline=baseline, patched=patched,
                reason=(
                    "Patched test run timed out after a usable baseline "
                    f"({baseline.passed} passed, {baseline.failed} failed); "
                    "the test comparison could not be completed."
                ),
                plan=plan,
            )
            return result
        if patched.status == "SETUP_FAILED":
            return ExistingTestComparisonResult(
                status=STATUS_TEST_EXECUTION_ERROR, command=plan.test_command, baseline=baseline, patched=patched,
                reason=(
                    "Setup/build failed for the patched workspace after a usable baseline: "
                    f"{patched.reason}. The test comparison could not be completed."
                ),
                plan=plan,
            )
        if patched.evidence_level == "UNAVAILABLE":
            return ExistingTestComparisonResult(
                status=STATUS_NOT_VERIFIED, command=plan.test_command, baseline=baseline, patched=patched,
                reason=(
                    f"Patched test output could not be interpreted: {patched.reason}. "
                    "The test comparison could not be completed."
                ),
                plan=plan,
            )

        result = compare_runs(plan.test_command, baseline, patched)
        result.plan = plan
        return result

    except Exception as exc:  # noqa: BLE001 -- never let this feature crash the pipeline
        return ExistingTestComparisonResult(
            status=STATUS_TEST_EXECUTION_ERROR, command=None, baseline=None, patched=None,
            reason=f"Existing Test Comparison failed unexpectedly: {type(exc).__name__}: {exc}",
        )


def evaluate_existing_test_comparison(
    repo_root: "Path | str",
    patch: str,
    llm,
    setup_timeout: int = DEFAULT_SETUP_TIMEOUT,
    run_timeout: int = DEFAULT_RUN_TIMEOUT,
) -> ExistingTestComparisonResult:
    """Run Existing Test Comparison for ``patch`` against ``repo_root``,
    exactly as before this module's discovery/comparison split -- this is
    now a thin composition of discover_test_plan_for_comparison() +
    evaluate_existing_test_comparison_with_plan(), preserved unchanged for
    any caller that wants the whole thing in one call (every caller
    before this split, and any non-pipeline caller). See those two
    functions' own docstrings for the fail-fast ordering and Same-plan
    invariant (Test Plan Discovery runs EXACTLY ONCE, reused unmodified
    for both the baseline and patched runs) -- both still hold exactly as
    documented; this wrapper adds no new behavior.

    pipeline.run() itself does NOT call this wrapper -- it calls the two
    halves directly, so Stage 10 (test_analysis_and_plan) and Stage 11
    (existing_test_comparison) can be recorded as separate, truthful
    StageExecutions.
    """
    plan, early_result, executor = discover_test_plan_for_comparison(repo_root, patch, llm)
    if early_result is not None:
        return early_result
    return evaluate_existing_test_comparison_with_plan(
        repo_root, patch, plan, setup_timeout=setup_timeout, run_timeout=run_timeout, executor=executor,
    )


def _run_side(repo_root, plan, executor, patch: "str | None", setup_timeout, run_timeout) -> TestRunResult:
    """Run one side (baseline when patch is None) inside its own
    disposable workspace copy. The copy -- and everything written into
    it, including the generated Dockerfile -- is destroyed on exit
    regardless of outcome."""
    with temporary_repo_copy(repo_root) as workspace_root:
        if patch is not None:
            apply_patch(patch, workspace_root)  # caller already checked .applied
        raw = executor.run(plan, workspace_root, setup_timeout=setup_timeout, run_timeout=run_timeout)
    return _to_test_run_result(plan, raw)


def _run_side_with_patch(
    repo_root, plan, executor, patch: str, setup_timeout, run_timeout,
) -> "tuple[TestRunResult, str | None]":
    """Same as ``_run_side`` for the patched side, but checks
    ``apply_patch``'s own result first -- a failed apply is a harness
    problem (TEST_EXECUTION_ERROR), not a test result."""
    with temporary_repo_copy(repo_root) as workspace_root:
        apply_result = apply_patch(patch, workspace_root)
        if not apply_result.applied:
            return (
                _not_attempted(plan.test_command, "candidate patch did not apply to the isolated patched workspace"),
                (
                    "Candidate patch did not apply to the isolated patched workspace: "
                    f"{apply_result.error or apply_result.error_kind or 'apply rejected'}"
                ),
            )
        raw = executor.run(plan, workspace_root, setup_timeout=setup_timeout, run_timeout=run_timeout)
    return _to_test_run_result(plan, raw), None


# ---------------------------------------------------------------------------
# Trust signal + report rendering
# ---------------------------------------------------------------------------

_ICONS = {
    STATUS_PASS: "✅",
    STATUS_NEW_FAILURES_DETECTED: "❌",
    STATUS_PRE_EXISTING_FAILURES_ONLY: "✅",
    STATUS_NOT_VERIFIED: "?",
    STATUS_TEST_EXECUTION_ERROR: "?",
}

_LABELS = {
    STATUS_PASS: "Pass",
    STATUS_NEW_FAILURES_DETECTED: "New Failures Detected",
    STATUS_PRE_EXISTING_FAILURES_ONLY: "Pre-Existing Failures Only",
    STATUS_NOT_VERIFIED: "Not Verified",
    STATUS_TEST_EXECUTION_ERROR: "Test Execution Error",
}

_NOT_REQUESTED_NOTES = (
    "Existing Test Comparison was not requested for this run "
    "(opt-in; see --compare-existing-tests)."
)


def classify_existing_test_comparison_signal(result: "ExistingTestComparisonResult | None") -> dict:
    """Trust-signal-shaped {"value", "label", "notes"} for `result` --
    mirrors source_verification.classify_source_verification's shape.

    OBSERVABILITY ONLY in this slice: never read by
    pipeline._build_recommendation_v1. `result is None` covers BOTH "the
    --compare-existing-tests flag was off" and "a hand-built PipelineResult
    from before this signal existed" -- both fall back to the same
    NOT_VERIFIED value; only the notes text distinguishes "not requested"
    from "attempted but inconclusive."""
    if result is None:
        return {"value": STATUS_NOT_VERIFIED, "label": f"{_ICONS[STATUS_NOT_VERIFIED]} Not Verified",
                "notes": _NOT_REQUESTED_NOTES}
    icon = _ICONS.get(result.status, "?")
    label_text = _LABELS.get(result.status, result.status)
    return {"value": result.status, "label": f"{icon} {label_text}", "notes": result.reason}


def _run_summary_line(label: str, r: "TestRunResult | None") -> str:
    if r is None:
        return f"- {label}: not run"
    if r.evidence_level == "UNAVAILABLE":
        return f"- {label}: {r.reason or r.status}"
    if r.evidence_level == "EXIT_CODE_ONLY":
        return f"- {label}: exit code {r.exit_code} (exit-code-only evidence)"
    passed = r.passed if r.passed is not None else "?"
    failed = r.failed if r.failed is not None else "?"
    extra = f", {r.errors} errored" if r.errors else ""
    return f"- {label}: {passed} passed, {failed} failed{extra}"


def _plural(n: int, singular: str, plural: "str | None" = None) -> str:
    if n == 1:
        return singular
    return plural if plural is not None else f"{singular}s"


_MAX_LISTED_TESTS = 20


def render_existing_test_comparison(result: "ExistingTestComparisonResult | None") -> str:
    """Render the ``## Existing Test Comparison`` report section.

    Always returns a complete section -- "not requested" and "not
    verified" are themselves meaningful, deterministic states. Output is
    bounded: raw process stdout/stderr is never dumped here, only counts,
    exit codes, and (capped) test names. Includes light provenance
    (discovered command + how it was executed) but never chain-of-thought.

    Wording throughout is deliberately factual ("new failure", never
    "regression") -- see the module docstring: this feature reports a
    deterministic before/after delta and leaves the judgment of whether
    that delta is an unintended regression, an expected behavior change,
    or something else entirely to a human reviewer.
    """
    lines = [
        "---\n",
        "## Existing Test Comparison\n",
        (
            "*Runs the repository's own tests once against the unpatched "
            "repository and once against the candidate patch, in "
            "Docker-isolated disposable copies, using the identical "
            "discovered test plan both times, and compares results. A "
            "pre-existing failure is never reported as caused by this "
            "patch. A new failure means a test that passed on the "
            "baseline failed after the patch; OpenAnt does not determine "
            "whether that behavior change is intended.*\n"
        ),
    ]

    if result is None:
        lines.append(f"? Not requested\n\n{_NOT_REQUESTED_NOTES}\n")
        return "\n".join(lines) + "\n"

    if result.plan is not None:
        lines.append(
            f"- Test plan: discovered from repository evidence "
            f"({', '.join(result.plan.evidence)})\n"
            f"- Command: `{' '.join(result.command or result.plan.test_command)}`\n"
            "- Execution: Docker\n"
        )

    if result.status == STATUS_NOT_VERIFIED:
        lines.append(f"? Not verified\n\nExisting tests could not be compared because {result.reason}\n")
        return "\n".join(lines) + "\n"

    if result.status == STATUS_TEST_EXECUTION_ERROR:
        lines.append(f"? Execution error — the test comparison could not be completed\n\n{result.reason}\n")
        if result.baseline is not None:
            lines.append(_run_summary_line("Baseline", result.baseline) + "\n")
        return "\n".join(lines) + "\n"

    if result.status == STATUS_PASS:
        lines.append("✅ No new failures in the existing test suite\n")
    elif result.status == STATUS_PRE_EXISTING_FAILURES_ONLY:
        lines.append(
            f"✅ No new failures — {len(result.pre_existing_failures)} pre-existing "
            "failure(s) unaffected by this patch\n"
        )
    else:  # STATUS_NEW_FAILURES_DETECTED
        n = len(result.newly_failing_tests)
        if n:
            lines.append(f"❌ {n} new {_plural(n, 'failure')} after the candidate patch\n\n")
            lines.append(
                f"{n} existing {_plural(n, 'test')} that passed on the baseline "
                "failed after applying the candidate patch.\n"
            )
        else:
            # No named test IDs at this evidence tier (COUNTS_ONLY or
            # RUNNER_SUMMARY_COUNTS) -- surface the evidence-tier-specific
            # caveat from `reason` explicitly (it already says, e.g.,
            # "individual newly-failing tests could not be identified...
            # count-based evidence only") rather than the bare status
            # line alone, so a reader can never mistake an aggregate-
            # count delta for a proven, specific new failure.
            lines.append("❌ The patched test run showed worse aggregate results.\n\n")
            if result.reason:
                lines.append(f"{result.reason}\n")

    lines.append(_run_summary_line("Baseline", result.baseline) + "\n")
    lines.append(_run_summary_line("Patched", result.patched) + "\n")

    if result.status == STATUS_NEW_FAILURES_DETECTED and result.newly_failing_tests:
        lines.append("\n**Newly failing:**\n")
        for name in result.newly_failing_tests[:_MAX_LISTED_TESTS]:
            lines.append(f"- {name}\n")
        remaining = len(result.newly_failing_tests) - _MAX_LISTED_TESTS
        if remaining > 0:
            lines.append(f"- … {remaining} more\n")
    if result.pre_existing_failures:
        lines.append(f"\nPre-existing failures: {len(result.pre_existing_failures)}\n\n")
        lines.append(
            "These are failures that were already present on the baseline and therefore "
            "cannot be attributed to the candidate patch.\n"
        )

    return "\n".join(lines) + "\n"
