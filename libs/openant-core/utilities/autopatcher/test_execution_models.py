"""Generic data model for Existing Test Comparison's test-execution
architecture.

Three shapes, none of which know anything about pytest, npm, go test, tox,
or any other specific tool:

    TestExecutionPlan     -- what to run (argv commands + a few closed,
                              constrained environment hints), proposed by
                              Test Plan Discovery (test_plan_discovery.py)
                              from repository evidence and validated
                              (test_plan_validation.py) before ever being
                              executed.
    TestExecutionResult    -- what happened when an executor
                              (test_executors.py) actually ran a plan once,
                              inside one disposable workspace.
    PlanValidationResult   -- the deterministic validation verdict for a
                              candidate plan, before execution.

Any tool-specific knowledge lives only in the *values* placed into a
plan's fields (by evidence/the LLM), never in the shape of these types.
"""

from __future__ import annotations

from dataclasses import dataclass

# Runtime families OpenAnt recognizes as WELL-FORMED values for
# TestExecutionPlan.runtime_family. This is a well-formedness set, not a
# support/capability set -- whether a given family is actually executable
# this release is a separate, executor-owned policy decision (see
# test_executors.APPROVED_IMAGES). Recognizing "rust"/"jvm" as legitimate
# values now means adding real support later is a policy-map change, not
# a schema change.
KNOWN_RUNTIME_FAMILIES = frozenset({"python", "node", "go", "rust", "jvm"})

VALID_RESULT_STRATEGIES = frozenset({"junit", "tap", "exit_code"})

# "high"/"medium"/"low" are the only values the LLM is ever asked to
# self-report (see test_plan_discovery._SYSTEM_PROMPT's schema block --
# unchanged by this set). "unknown" is never offered to the model; it is
# an internal normalization value test_plan_discovery.py substitutes when
# the model's response omitted confidence entirely, supplied the wrong
# JSON type, or used an unrecognized string -- confidence is advisory
# provenance, not an execution-critical field, so a malformed or missing
# self-report must not by itself discard an otherwise valid,
# deterministically validated plan. See that module's docstring for the
# full metadata-vs-execution-critical policy.
VALID_CONFIDENCE_LEVELS = frozenset({"high", "medium", "low", "unknown"})

# The only writable-in-the-container path prefix result_output_path may
# resolve under. This is a CONTAINER-internal path constraint, not a host
# filesystem constraint -- see test_plan_validation.py.
APPROVED_RESULT_OUTPUT_PREFIX = "/tmp/"


@dataclass(frozen=True)
class TestExecutionPlan:
    """An immutable, structured proposal for how to prepare and run a
    repository's existing tests. Produced once per Existing Test
    Comparison run (see test_plan_discovery.discover_test_plan)
    and reused, unmodified, for both the baseline and patched execution --
    see existing_test_regression.py's same-plan invariant.

    Deliberately absent from this schema: ``cwd`` (every command always
    runs from the workspace root inside the container -- no monorepo
    subdirectory support in this release) and ``env`` (a plan can never
    mutate environment variables; only the executor controls the
    container's environment). Their absence is itself the safeguard --
    there is no field to validate away because the capability was never
    given a field.
    """
    __test__ = False  # not a pytest test class -- name collides with pytest's Test* discovery

    setup_commands: "tuple[tuple[str, ...], ...]"
    test_command: "tuple[str, ...]"
    result_strategy: str                    # "junit" | "tap" | "exit_code"
    result_output_path: "str | None"        # required iff result_strategy == "junit"; must be
                                             # None for "tap" (read from captured stdout, not a
                                             # file -- see result_parsers.parse_tap) and for
                                             # "exit_code"
    runtime_family: "str | None"            # describes the EXECUTION ENVIRONMENT, never the test tool
    runtime_version_hint: "str | None"      # provenance only; never selects the image directly
    evidence: "tuple[str, ...]"             # repo-relative paths that justified this plan
    reasoning_summary: str                  # short provenance note, never a reasoning trace
    confidence: str                         # "high" | "medium" | "low" | "unknown" (normalized
                                             # when the model's self-report was missing/malformed)
    source: str = "llm"                     # "llm" this release; "manual" reserved for a future,
                                             # explicit repository-declared override -- not built yet


@dataclass
class TestExecutionResult:
    """Generic, executor-agnostic raw output of ONE run of a plan's
    test_command (after setup_commands) inside ONE disposable workspace.

    Neither DockerTestExecutor nor any future LocalTestExecutor is
    permitted to add tool-specific fields here -- anything a specific
    tool/format needs is derived downstream, deterministically, by
    result_parsers.py from ``result_output``.
    """
    __test__ = False  # not a pytest test class -- name collides with pytest's Test* discovery

    ran: bool
    exit_code: "int | None"
    timed_out: bool
    setup_failed: bool     # setup_commands and/or the image build failed
    setup_error: str
    stdout: str
    stderr: str
    result_output: "str | None"   # raw text captured from result_output_path, if any
    duration_seconds: float
    executor: str           # "docker" | "local" -- which executor produced this


@dataclass(frozen=True)
class PlanValidationResult:
    valid: bool
    plan: "TestExecutionPlan | None"   # the plan, unchanged, only when valid
    reason: "str | None"


@dataclass(frozen=True)
class ExecutorPreflightResult:
    """Generic executor-readiness verdict. Checked exactly ONCE, before any
    evidence acquisition or LLM Test Plan Discovery call (see
    existing_test_regression.py's environment-preflight step) -- the whole
    point is to fail fast, before spending an LLM token or building a
    disposable workspace, when the selected executor can't actually run
    anything.

    ``status`` is a free-form, executor-defined string (Docker's is
    CLI_MISSING/DAEMON_UNREACHABLE/DAEMON_UNUSABLE/TIMEOUT/ERROR/OK; a
    future LocalExecutor may use a different vocabulary) -- this model
    only standardizes the shape every executor's preflight returns, not a
    shared status enum across executors.
    """
    ready: bool
    reason: "str | None"
    status: str = "OK"
