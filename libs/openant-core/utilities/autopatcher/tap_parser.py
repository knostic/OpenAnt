"""A deterministic, conservative parser for the Test Anything Protocol
(TAP) -- a result FORMAT, not an ecosystem or language. TAP is emitted by
many unrelated producers (Node's built-in test runner, Perl's original
`prove`, Rust's `libtest`-based harnesses via a TAP flag, and plenty of
bespoke harnesses), so this module knows nothing about any of them: it
consumes plain TAP text and produces the SAME normalized
``result_parsers.ParsedTestCounts`` shape ``parse_junit_xml`` already
produces, so existing_test_regression.py's comparator needs no
TAP-specific branch at all -- see result_parsers.parse_result's dispatch.

Scope, deliberately the SMALLEST parser that handles the TAP constructs
Existing Test Comparison actually needs (per-test pass/fail identity for
baseline-vs-patched diffing), not the full TAP14 specification:

  - flat "ok"/"not ok" test lines (TAP12/TAP13's core, and the overwhelming
    majority of real TAP output)
  - "# SKIP"/"# TODO" directives on a test line, treated as skipped
    (neither a pass nor a failure) -- a deliberate simplification of
    TODO's slightly richer spec meaning (see _parse_test_line's docstring)
  - ONE level of "# Subtest: NAME" nesting (TAP14's documented nested-test
    convention, and the exact shape Node's built-in test runner emits) --
    a subtest's own child lines are the real per-test identities; its
    trailing rollup line (the parent-level "ok"/"not ok N - NAME" line
    that summarizes the whole subtest) is NOT counted as a second,
    independent failure on top of its children -- see
    _drain_open_subtest. Nesting deeper than one level is conservatively
    treated as unsupported (fail closed), not guessed at.
  - YAML diagnostic blocks (``---`` ... ``...``) are skipped as opaque
    text, never mined for fake test identities.
  - "TAP version N" / "1..N" plan lines are structural markers, never
    test lines.
  - a comment line that ISN'T "# Subtest: ..." is a free-form diagnostic
    and is always ignored -- it can never become a test identity.

Fail-closed, not best-effort: malformed, truncated, or ambiguous input
returns ``None`` (see ``parse_tap``'s docstring) rather than guessing at a
"probably fine" interpretation -- a caller that gets ``None`` back must
treat this exactly like JUnit's parse failure (NOT_VERIFIED, never a
silent "no new failures").

Real-world grounding: this module's test suite includes fixtures captured
directly from minimist's own `tap` v0.4.13 test harness (via its `--tap`
flag) -- see tests/patch/test_tap_parser.py::TestExactMinimistCapturedOutput.
That real capture exposes a genuine, disclosed limitation of generic TAP
parsing: node-tap 0.4.x renders each test file's own inner stream as
"#"-prefixed comment lines (including its own inner "TAP version 13"),
but emits both the file's real per-assertion "ok"/"not ok" lines AND its
own file-level rollup line ("ok N - test/foo.js") at the SAME top-level
indentation, with no "# Subtest:" marker or indentation connecting them.
A generic, spec-faithful parser has no principled way to tell those apart
-- both are, per the bare TAP spec, equally valid top-level results -- so
this parser counts the rollup line as its own leaf result too, alongside
the real assertions it summarizes. This is a disclosed OVER-counting
artifact (a real failure can end up reported under two identities), never
an under-counting one (a real failure is never hidden by it). This module
deliberately does NOT add a minimist/node-tap-specific heuristic to
collapse it -- doing so would be exactly the ecosystem-specific logic
this feature must not have. The generically-supported nesting constructs
above ("# Subtest: NAME" and its matching rollup) remain fully collapsed,
correctly, as documented; only a producer using NEITHER recognized
construct falls back to this flat, disclosed-limitation behavior. The
separate "more than one top-level TAP version declaration" rejection
(see ``parse_tap``) is a real, distinct malformation this parser does
still reject -- it does not describe minimist's shape, which has exactly
one.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .result_parsers import ParsedTestCounts

_TAP_VERSION_RE = re.compile(r"^TAP version\s+\d+\s*$")
_PLAN_RE = re.compile(r"^\d+\.\.\d+\s*$")
_SUBTEST_RE = re.compile(r"^#\s*Subtest:\s*(.*)$", re.IGNORECASE)
_YAML_OPEN_RE = re.compile(r"^-{3}\s*$")
_YAML_CLOSE_RE = re.compile(r"^\.{3}\s*$")
_TEST_LINE_RE = re.compile(r"^(?P<not>not\s+)?ok\b(?:\s+(?P<num>\d+))?(?P<rest>.*)$")
_DIRECTIVE_RE = re.compile(r"#\s*(SKIP|TODO)\b", re.IGNORECASE)

# Deterministic, conservative bound -- TAP is a text protocol with no
# inherent size limit; without this a pathological input could make this
# parser do unbounded work. Well-behaved test output for any real
# repository is orders of magnitude smaller than this.
_MAX_LINES = 200_000


def _leading_spaces(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _parse_test_line(content: str) -> "tuple[str, str] | None":
    """Parse one TAP test line's body (with leading/trailing whitespace
    already stripped). Returns (description, status) where status is
    "pass" | "fail" | "skip", or None if `content` isn't a test line at
    all.

    Simplification, stated explicitly: TAP's directive spec distinguishes
    SKIP (never ran) from TODO (ran, expected to fail) -- a *passing*
    TODO technically signals "this can be un-TODO'd now." Existing Test
    Comparison only needs a stable pass/fail/skip partition to diff
    baseline vs. patched, so both directives are folded into "skip" here:
    neither contributes to failed_test_ids, which is exactly the
    property this feature depends on (a skipped/TODO'd test is never
    reported as a newly-introduced failure).
    """
    match = _TEST_LINE_RE.match(content)
    if match is None:
        return None
    not_ok = match.group("not") is not None
    rest = match.group("rest") or ""

    directive_match = _DIRECTIVE_RE.search(rest)
    skipped = directive_match is not None
    if skipped:
        rest = rest[: directive_match.start()]

    description = rest.strip()
    if description.startswith("-"):
        description = description[1:].strip()

    if not description:
        num = match.group("num")
        description = f"test {num}" if num else "(unnamed test)"

    if skipped:
        status = "skip"
    elif not_ok:
        status = "fail"
    else:
        status = "pass"
    return description, status


def parse_tap(text: "str | None") -> "ParsedTestCounts | None":
    """Parse a TAP text stream into ``result_parsers.ParsedTestCounts``.
    Returns ``None`` -- never raises, never guesses -- when the text is
    missing/empty, contains more than one top-level "TAP version"
    declaration (an ambiguous/concatenated stream -- see module
    docstring), opens a "# Subtest:"/YAML block it never closes
    (truncated), nests a "# Subtest:" more than one level deep
    (unsupported), or contains no recognizable TAP structure at all.

    A caller receiving ``None`` must treat it exactly like a JUnit parse
    failure: fail closed (NOT_VERIFIED), never assume "no failures."
    """
    if text is None or not text.strip():
        return None

    lines = text.splitlines()
    if len(lines) > _MAX_LINES:
        return None

    top_level: "list[tuple[str, str]]" = []  # (id, status)
    open_subtest: "dict | None" = None  # {"name": str, "indent": int, "children": list}
    in_yaml_block = False
    top_version_seen = False
    saw_any_structure = False

    for raw_line in lines:
        line = raw_line.rstrip("\r\n")
        indent = _leading_spaces(line)
        content = line.strip()

        if in_yaml_block:
            if _YAML_CLOSE_RE.match(content):
                in_yaml_block = False
            continue  # opaque diagnostic text -- never mined for test identities

        if content == "":
            continue

        if _YAML_OPEN_RE.match(content):
            in_yaml_block = True
            continue

        if _TAP_VERSION_RE.match(content):
            saw_any_structure = True
            if indent == 0:
                if top_version_seen:
                    return None  # ambiguous/concatenated stream -- fail closed
                top_version_seen = True
            continue

        if _PLAN_RE.match(content):
            saw_any_structure = True
            continue

        subtest_match = _SUBTEST_RE.match(content)
        if subtest_match:
            if open_subtest is not None:
                return None  # nested deeper than one level -- unsupported, fail closed
            open_subtest = {
                "name": subtest_match.group(1).strip() or "subtest",
                "indent": indent,
                "children": [],
            }
            saw_any_structure = True
            continue

        if content.startswith("#"):
            continue  # free-form diagnostic comment -- never a test identity

        parsed = _parse_test_line(content)
        if parsed is None:
            continue  # stray non-TAP output line (e.g. print()/console.log noise) -- ignored

        saw_any_structure = True
        description, status = parsed
        if open_subtest is not None and indent > open_subtest["indent"]:
            open_subtest["children"].append((description, status))
            continue

        if open_subtest is not None:
            # This line is at or above the subtest's own indent -- it is
            # the subtest's ROLLUP line, not a new top-level test.
            _drain_open_subtest(top_level, open_subtest, rollup_status=status)
            open_subtest = None
            continue

        top_level.append((description, status))

    if in_yaml_block:
        return None  # truncated -- a YAML diagnostic block was never closed
    if open_subtest is not None:
        return None  # truncated -- a subtest was opened but never rolled up
    if not saw_any_structure:
        return None  # nothing recognizable as TAP at all

    from .result_parsers import ParsedTestCounts  # local import -- avoid a cycle at module load

    passed = sum(1 for _, s in top_level if s == "pass")
    failed = sum(1 for _, s in top_level if s == "fail")
    skipped = sum(1 for _, s in top_level if s == "skip")
    failed_ids = [tid for tid, s in top_level if s == "fail"]
    return ParsedTestCounts(
        passed=passed, failed=failed, skipped=skipped, errors=0,
        failed_test_ids=failed_ids, mode="full",
    )


def _drain_open_subtest(top_level: "list[tuple[str, str]]", open_subtest: dict, rollup_status: str) -> None:
    """Fold a closed subtest's recorded children into `top_level`,
    preferring the CHILDREN's own identities/statuses over the subtest's
    own rollup line -- this is the "do not double-count a parent summary
    on top of its child failure" rule (see module docstring). Each
    child's id is qualified with the subtest's name for a stable,
    hierarchical identity ("group > child"). If the subtest had no
    recorded children at all (e.g. an empty subtest, or one whose only
    content was diagnostics), the rollup line itself is the best
    available identity and is used as a single leaf result instead."""
    name = open_subtest["name"]
    children = open_subtest["children"]
    if children:
        for child_id, status in children:
            top_level.append((f"{name} > {child_id}", status))
    else:
        top_level.append((name, rollup_status))
