"""Deterministic, fail-closed validation for a candidate TestExecutionPlan.

This is the boundary between "the LLM proposed this" and "OpenAnt will
execute this." It applies IDENTICALLY regardless of a plan's ``source`` --
a deterministically-built plan gets no special trust either, since a
failure here would indicate a bug in our own code, not an attack, and is
still worth catching.

This module does NOT try to statically prove a package-manager command
"safe" -- that's not achievable in general (see docstrings in
test_executors.py for the actual containment story). It makes the
execution *contract* explicit and rejects anything clearly malformed or
structurally unsafe:

  - argv arrays only (enforced by type, not just checked)
  - bounded command count and bounded per-command size
  - no shell metacharacters in any token (defense in depth -- shell=True
    is never used anywhere in this feature, but a token containing ``;``
    or a backtick has no legitimate reason to appear in an argv array
    either)
  - only a small, fixed set of recognized binaries may start a command
  - result_output_path, when present, must resolve under the one
    container-internal writable prefix the executor actually mounts
    (``/tmp/``) -- this is a CONTAINER path constraint, not a host
    filesystem constraint. Repository-relative paths elsewhere in a
    command's arguments (e.g. ``tests/unit/test_x.py``) or other absolute
    CONTAINER paths (e.g. ``--junitxml=/tmp/x.xml``) are perfectly valid
    and are not rejected -- there is no "deny absolute paths" rule here.
  - evidence must be non-empty
  - runtime_family, if set, must be a recognized (not necessarily
    SUPPORTED -- see test_executors.APPROVED_IMAGES) value
  - runtime_version_hint, if malformed, is silently dropped (informational
    only) rather than failing the whole plan
  - when result_strategy is "junit", test_command must actually reference
    result_output_path somewhere in its own tokens -- a plan cannot claim
    structured output it never actually requested from the command it's
    about to run. This is a simple substring consistency check, not a CLI
    parser for any specific runner's flag syntax -- see validate_plan's
    body for exactly what it checks.

Deliberately NOT re-checked here because the schema itself makes them
impossible: no ``cwd``/``env`` fields exist on TestExecutionPlan at all;
resource limits and timeouts are executor/caller parameters, never plan
fields; there is no field anywhere in the schema for a Docker image
string.
"""

from __future__ import annotations

import re

from .test_execution_models import (
    APPROVED_RESULT_OUTPUT_PREFIX,
    KNOWN_RUNTIME_FAMILIES,
    VALID_CONFIDENCE_LEVELS,
    VALID_RESULT_STRATEGIES,
    PlanValidationResult,
    TestExecutionPlan,
)

MAX_SETUP_COMMANDS = 4
MAX_TOKENS_PER_COMMAND = 12
MAX_COMMAND_CHARS = 500

# A small, fixed, reviewed set of binaries a command's first token may be.
# Broader than what this release can actually EXECUTE (see
# test_executors.APPROVED_IMAGES) -- this is a well-formedness gate, not a
# capability gate; a structurally valid command for an unsupported runtime
# still fails later, for a different, more precise reason (see
# test_executors.is_runtime_supported).
ALLOWED_COMMAND_BINARIES = frozenset({
    "python", "python3", "pip", "pip3", "uv", "poetry", "tox", "nox",
    "npm", "yarn", "pnpm", "node",
    "go",
    "cargo",
    "mvn", "gradle", "./gradlew",
    "make",
})

_SHELL_METACHAR_RE = re.compile(r"[;|&`$<>\n]")
_VERSION_HINT_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,20}$")


def _invalid(reason: str) -> PlanValidationResult:
    return PlanValidationResult(valid=False, plan=None, reason=reason)


def _valid_command_shape(argv, label: str) -> "str | None":
    """Returns an error string, or None if argv is a well-formed,
    bounded, safe-looking argv tuple."""
    if not isinstance(argv, tuple) or not argv:
        return f"{label} must be a non-empty argv tuple"
    if len(argv) > MAX_TOKENS_PER_COMMAND:
        return f"{label} has too many tokens ({len(argv)} > {MAX_TOKENS_PER_COMMAND})"
    if sum(len(t) for t in argv) > MAX_COMMAND_CHARS:
        return f"{label} exceeds the total character bound ({MAX_COMMAND_CHARS})"
    for token in argv:
        if not isinstance(token, str) or not token:
            return f"{label} contains a non-string or empty token"
        if _SHELL_METACHAR_RE.search(token):
            return f"{label} token contains a disallowed shell metacharacter: {token!r}"
    if argv[0] not in ALLOWED_COMMAND_BINARIES:
        return f"{label} starts with an unrecognized binary: {argv[0]!r}"
    return None


def validate_plan(plan: TestExecutionPlan) -> PlanValidationResult:
    """Validate a candidate plan. Never raises -- any unexpected shape is
    a rejection, not a crash."""
    try:
        if len(plan.setup_commands) > MAX_SETUP_COMMANDS:
            return _invalid(
                f"too many setup_commands ({len(plan.setup_commands)} > {MAX_SETUP_COMMANDS})"
            )
        for i, cmd in enumerate(plan.setup_commands):
            err = _valid_command_shape(cmd, f"setup_commands[{i}]")
            if err:
                return _invalid(err)

        err = _valid_command_shape(plan.test_command, "test_command")
        if err:
            return _invalid(err)

        if plan.result_strategy not in VALID_RESULT_STRATEGIES:
            return _invalid(f"unrecognized result_strategy: {plan.result_strategy!r}")

        if plan.result_strategy == "junit":
            if not plan.result_output_path:
                return _invalid("result_strategy is 'junit' but result_output_path is empty")
            if not plan.result_output_path.startswith(APPROVED_RESULT_OUTPUT_PREFIX):
                return _invalid(
                    "result_output_path must resolve under the approved "
                    f"container-internal writable prefix {APPROVED_RESULT_OUTPUT_PREFIX!r}, "
                    f"got {plan.result_output_path!r}"
                )
            if _SHELL_METACHAR_RE.search(plan.result_output_path) or ".." in plan.result_output_path:
                return _invalid(f"result_output_path is malformed: {plan.result_output_path!r}")
            # Consistency check, not a CLI parser: confirm the command
            # actually references the declared output path SOMEWHERE in
            # its own tokens (e.g. "--junitxml=/tmp/x.xml" as one token,
            # or a flag/value pair split across two tokens). This does
            # NOT hard-code `--junitxml` or understand any runner's
            # syntax -- it only catches a plan that claims "junit" while
            # never actually requesting it from the command it's about to
            # run.
            if not any(plan.result_output_path in token for token in plan.test_command):
                return _invalid(
                    "result_strategy is 'junit' but test_command does not reference "
                    f"result_output_path ({plan.result_output_path!r}) anywhere"
                )
        else:  # "exit_code"
            if plan.result_output_path:
                return _invalid("result_strategy is 'exit_code' but result_output_path was set")

        if plan.runtime_family is not None and plan.runtime_family not in KNOWN_RUNTIME_FAMILIES:
            return _invalid(f"unrecognized runtime_family: {plan.runtime_family!r}")

        if not plan.evidence:
            return _invalid("evidence must be non-empty")

        if plan.confidence not in VALID_CONFIDENCE_LEVELS:
            return _invalid(f"unrecognized confidence: {plan.confidence!r}")

        # runtime_version_hint is informational only -- sanitize rather
        # than reject the whole plan over a cosmetic field.
        version_hint = plan.runtime_version_hint
        if version_hint is not None and not _VERSION_HINT_RE.match(version_hint):
            plan = TestExecutionPlan(
                setup_commands=plan.setup_commands, test_command=plan.test_command,
                result_strategy=plan.result_strategy, result_output_path=plan.result_output_path,
                runtime_family=plan.runtime_family, runtime_version_hint=None,
                evidence=plan.evidence, reasoning_summary=plan.reasoning_summary,
                confidence=plan.confidence, source=plan.source,
            )

        return PlanValidationResult(valid=True, plan=plan, reason=None)

    except Exception as exc:  # noqa: BLE001 -- never let a malformed plan crash discovery
        return _invalid(f"plan validation failed unexpectedly: {type(exc).__name__}: {exc}")
