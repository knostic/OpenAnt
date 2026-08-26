"""Test Plan Discovery: the ONLY place an LLM is consulted about how a
repository's existing tests should be prepared and run.

Flow: gather bounded, deterministic evidence (test_evidence_acquisition.py)
-> exactly ONE LLM call proposing a structured TestExecutionPlan -> strict
deterministic parsing -> deterministic validation
(test_plan_validation.py). The LLM never executes anything, never sees
test output, and never decides pass/fail or comparison status -- that is
entirely existing_test_regression.py's job, downstream of this module.

No retries in this release: any parse/validation/confidence/provenance
failure is treated as "no plan discovered," never a second attempt.

Metadata vs. execution-critical fields: ``setup_commands``, ``test_command``,
``result_strategy``, ``result_output_path``, ``runtime_family``, and
``evidence`` are execution-critical -- a response that omits one, or whose
value is the wrong shape, gives OpenAnt nothing safe to execute, so it is
rejected outright (see ``_REQUIRED_KEYS`` and the strict per-field checks
below). ``confidence``, ``reasoning_summary``, and ``runtime_version_hint``
are advisory provenance/metadata only -- never consulted by
test_plan_validation.py's execution-safety checks, never rendered as if
they were verified fact. A response that simply omits one of these three
must not, by itself, discard an otherwise valid, deterministically
validated plan: each is normalized to a safe default (``confidence`` ->
"unknown", ``reasoning_summary`` -> "", ``runtime_version_hint`` -> None)
rather than causing rejection. A malformed *value* for
``reasoning_summary``/``runtime_version_hint`` (present, but the wrong
JSON type) is still rejected, unchanged from before -- only their
*absence* is now tolerated. ``confidence`` is treated more leniently even
than that: a malformed type or an unrecognized string both normalize to
"unknown" too, rather than rejecting the plan, since confidence is never
part of the execution-safety boundary either way (see "Confidence
semantics" below).

Confidence still goes missing more often than it should: real runs
(including a minimist stage replay) have shown the model omitting
``confidence`` from an otherwise well-formed response, even though the
schema block above states it. Mentioning a field once in a long prompt is
evidently not enough repetition to reliably survive to the end of the
response, so ``_SYSTEM_PROMPT`` ends with a short, mandatory "every schema
key, and confidence is one of high/medium/low" checklist placed
immediately before the repository evidence is shown -- the last thing the
model reads before generating. This is a prompt-only reliability nudge:
the ``"unknown"`` fallback above is unchanged and remains the real
safeguard, and no retry is added merely because confidence was omitted
(see "No retries" above) -- a second omission after the checklist is
still just "unknown," not a failure.

Confidence semantics: the actual execution trust boundary is entirely
deterministic -- structured argv, test_plan_validation.py's checks,
test_executors.is_runtime_supported's runtime policy, result-path
validation, Docker containment, and running the one immutable plan
unmodified for both baseline and patched. LLM self-reported confidence
never overrides or substitutes for any of that; it is provenance, not a
security boundary. The one place confidence still affects control flow is
discover_test_plan's explicit, deliberate rejection of a plan the model
*itself* reported as "low" -- kept because building and running a Docker
workspace for both baseline and patched is not free, and there is no
reason to spend that cost on a plan the model has already told us it
doesn't trust. This is a cost/reliability heuristic, not a safety gate --
deterministic validation still runs first and is what actually decides
executability for every other confidence value, including the new
"unknown" (missing/malformed self-report), which is intentionally treated
as neutral rather than as "low."

Provenance: every path the model cites in ``evidence`` must be an EXACT
member of the same EvidenceBundle's ``citable_identifiers`` that was used
to build the prompt -- never fuzzy-matched, never assumed. A response
citing a file it was never shown is rejected outright, the same as a
malformed response.

Structured vs. exit-code result preference: the model is asked to prefer
``result_strategy="junit"`` or ``"tap"`` over ``"exit_code"`` whenever it
can confidently identify, respectively, a specific well-known test
runner's own built-in structured-output flag, or a test entry point whose
completely unmodified, normal invocation already emits raw TAP -- purely
because per-test evidence lets the downstream comparator
(existing_test_regression.py) tell a NEW failure apart from a
PRE-EXISTING one even when the baseline wasn't fully green, which a bare
exit code can never do. This is a preference expressed in the prompt only
-- no new field beyond the "tap" enum value, no new architecture, no
framework-specific code anywhere in this module or downstream (TAP is a
result FORMAT emitted by many unrelated ecosystems, not a Node-specific
addition -- see tap_parser.py). ``test_plan_validation.validate_plan``
additionally rejects any "junit" plan whose ``test_command`` doesn't
actually reference the declared ``result_output_path``, and any "tap"
plan that sets a ``result_output_path`` at all (see that module), so a
plan can never claim structured output it didn't really request.

TAP's evidence bar is deliberately narrower than junit's, not equal to
it: a real minimist inspection (test_plan_discovery evidence shows
package.json's ``scripts.test`` as ``"tap test/*.js"``) confirmed that a
script/library NAMED "tap" does not, by itself, mean the repository's
normal, unmodified invocation emits raw TAP -- the `tap` v0.4.x CLI's own
DEFAULT output (with no added flag) is a human-readable per-file summary,
not TAP at all; real TAP requires an added `--tap` flag or `TAP=1`
environment variable this feature is not permitted to add (no command
rewrite, no ``env`` field on ``TestExecutionPlan`` at all). The prompt
therefore requires evidence of the UNMODIFIED entry point's own default
behavior, never a name/dependency-based guess -- see the "tap" bullet
below.

Repository-grounding (evidence-first discovery): the prompt requires the
model to DISCOVER how a repository already declares its own tests should
be run, never to INVENT a plausible-looking equivalent. A real minimist
run exposed the failure mode this guards against: repository evidence
plainly showed ``package.json``'s ``scripts.test`` as ``"tap
test/*.js"``, and the model still returned ``["npx", "tap",
"test/*.js"]`` -- reconstructing the wrapper's internals instead of
preserving the repository-owned entry point (``["npm", "test"]``). This
is a prompt-only fix (no schema/architecture change, no framework
provider, no ecosystem-specific branch anywhere in this module or
downstream): the model is told to prefer an evidenced repository-owned
entry point (a package-manager script, Makefile target, repository test
script, or a command CI/docs directly show) over any command it
constructs itself, and to fail closed (low confidence, no plan) rather
than guess when the evidence doesn't support a reliable choice. This
does NOT interact with the structured-result preference above: adding a
reporting-only flag to an already-evidenced command is still fine; only
*replacing* the evidenced command with a reconstructed one is not.
``test_plan_validation.ALLOWED_COMMAND_BINARIES`` is deliberately
unchanged by this fix -- ``npx`` was never added to it, and still isn't;
this is fixed at discovery, not by widening what the deterministic
validator will accept.

Setup-command grounding (repository-grounded EXECUTABILITY, not just
command wording): the fix above preserves the right ENTRY POINT
(``["npm", "test"]``) but a real minimist run still returned
``setup_commands=[]`` for it -- and ``npm test`` fails with ``sh: tap:
command not found`` (exit 127) in a fresh container, because
package.json's own ``devDependencies`` declare ``tap``/``tape``/
``covert``, none of which exist until installed. Two things were wrong,
both fixed together, neither a framework provider:
(1) ``test_evidence_acquisition._package_json_relevant_fields`` used to
extract only ``scripts``/``engines`` from package.json, deliberately
omitting ``dependencies``/``devDependencies``/``packageManager`` --
the model was never SHOWN the evidence it would have needed to ground an
install step, no matter how the prompt was worded; it now extracts those
too (still bounded by the same per-file byte cap every other config file
already goes through). (2) The prompt's setup rule only recognized
lockfiles/CI/docs as sufficient setup evidence, treating a dependency
manifest's own declaration of the entry point's invoked tool as
insufficient by itself -- it now explicitly is sufficient: if the
repository's own manifest declares the entry-point tool as a project
dependency, and nothing shows it already materialized, that is
repository-grounded setup, not invention (see the "setup_commands" rule
below, and its "WEAK / SPECULATIVE" vs. "STRONGLY IMPLIED
REPOSITORY-OWNED" distinction). This does not lower the bar for weak
setup guesses (e.g. "Python files exist -> pip install -r
requirements.txt" with no such file shown) -- it only stops discarding
evidence the model WAS shown. A lockfile still governs INSTALL MODE only
("npm ci" vs "npm install"), never whether to install at all -- its
absence must not be read as "skip setup."
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .test_evidence_acquisition import gather_test_plan_evidence
from .test_execution_models import (
    VALID_CONFIDENCE_LEVELS,
    VALID_RESULT_STRATEGIES,
    TestExecutionPlan,
)
from .test_plan_validation import validate_plan

# Execution-critical: the response must explicitly include every one of
# these keys (a value may still be null where the schema allows it, e.g.
# result_output_path or runtime_family) -- without them there is nothing
# safe to execute, so a response missing any one is rejected outright.
# Deliberately EXCLUDES confidence/reasoning_summary/runtime_version_hint
# -- see the module docstring's "Metadata vs. execution-critical fields".
_REQUIRED_KEYS = (
    "setup_commands", "test_command", "result_strategy", "result_output_path",
    "runtime_family", "evidence",
)

# Deterministic, conservative output bounds -- not semantic truncation, just
# a hard cap so an LLM-authored provenance field can never grow without
# bound. reasoning_summary is truncated (it is display-only, prose, and
# losing its tail is harmless); an evidence list that is too long or
# contains an overlong entry is instead REJECTED outright (a well-behaved
# response never needs anywhere near this many citations, so hitting the
# cap is itself a signal something is wrong with the response).
_MAX_REASONING_SUMMARY_CHARS = 500
_MAX_EVIDENCE_ENTRIES = 20
_MAX_EVIDENCE_ENTRY_CHARS = 200

# Bounded, internal diagnostic strings only (see discover_test_plan's
# rejection_reason parameter) -- never surfaced verbatim in the
# user-facing trust report, and never grown into a general logging
# system.
_MAX_REJECTION_REASON_CHARS = 300

_SYSTEM_PROMPT = """\
You are the Test Plan Discovery step of OpenAnt's Auto Patcher. Your ONLY \
job is to propose how THIS repository's existing test suite should be \
prepared and executed, based solely on the repository evidence given to \
you below.

You do not execute anything. You will never see test output. You are not \
judging whether tests pass or fail, and you must never claim that they do.

Respond with EXACTLY one JSON object, no prose before or after it, no \
markdown code fences, matching this schema:

{
  "setup_commands": [[<argv tokens>], ...],
  "test_command": [<argv tokens>],
  "result_strategy": "junit" | "tap" | "exit_code",
  "result_output_path": "<absolute path under /tmp/, or null>",
  "runtime_family": "python" | "node" | "go" | "rust" | "jvm" | null,
  "runtime_version_hint": "<short version string, or null>",
  "evidence": ["<repo-relative file path>", ...],
  "reasoning_summary": "<one or two short sentences>",
  "confidence": "high" | "medium" | "low"
}

Rules:
- setup_commands: 0 to 4 commands, run in order, before test_command.
- Every command is an argv array (separate string tokens) -- never a single
  shell string, and never include shell operators such as ; | & > < or
  backticks.
- YOUR JOB IS DISCOVERY, NOT INVENTION. You are not being asked "what is a
  plausible way to run this repository's tests" -- you are being asked "how
  does THIS repository, by its own evidence, expect its tests to be run."
  Every material part of test_command and setup_commands must be supported
  by repository evidence, or be a narrowly-allowed reporting-only addition
  (see the result_strategy rules below). If you cannot ground a command in
  the evidence you were shown, do not invent one -- see "When evidence is
  insufficient" below. The bias is: NO PLAN IS BETTER THAN A GUESSED PLAN.
- PRESERVE REPOSITORY-OWNED ENTRY POINTS -- do not reconstruct what is
  inside them. Follow this order:
    1. Search the evidence for an explicit, repository-owned test entry
       point: a package-manager script (e.g. package.json's
       scripts.test), a Makefile/justfile target, a repository test
       script (e.g. ./scripts/test.sh), a tox/nox session, a build-system
       test target, or a command CI/contributor documentation directly
       shows being run.
    2. If one exists, USE IT AS-IS -- e.g. package.json declares
       scripts.test = "tap test/*.js" -> use ["npm", "test"], never
       ["npx", "tap", "test/*.js"]; a Makefile "test:" target -> use
       ["make", "test"], never the commands written inside that target;
       a documented ./scripts/test.sh -> use that script, never its
       internal commands; CI running "go test ./..." -> that raw command
       IS itself repository evidence and using it directly is correct
       (see "When a direct command is appropriate" below).
    3. Do NOT open up a wrapper/script/target and run what's inside it
       instead. A repository's own entry point may carry environment
       setup, working-directory assumptions, lifecycle hooks, or
       selection logic that isn't visible from its contents alone -- the
       reasoning pattern "the repository runs X through wrapper Y,
       therefore I can just run X directly" is NOT safe and is
       explicitly prohibited. Evidenced wrapper/script/target always
       outranks an inferred command extracted from it.
    4. Only construct a command yourself when the repository genuinely
       does NOT provide a sufficiently evidenced entry point -- and even
       then, every token you add must trace back to something the
       evidence actually shows (e.g. a runner name mentioned in CI or
       docs), never general ecosystem knowledge about what's "common."
    5. When a direct command is appropriate: if CI or documentation
       itself directly shows the raw invocation (e.g. CI runs
       "pytest tests/", or docs say "cargo test --workspace"), that
       command already IS the repository's own evidence -- using it
       directly is correct and is NOT the reconstruction problem above.
       The distinction is not "wrapper vs. direct command" -- it is
       "evidenced command vs. an unevidenced one you built yourself."
- Reconcile evidence rather than assuming a fixed priority. CI workflow
  commands, documented developer/test instructions, package-manager
  scripts, Makefile/build-system targets, tox/nox configuration,
  repository test scripts, language-native project config, and
  contributor documentation can all be authoritative -- there is no
  universal rule that one of these always outranks another. When
  multiple sources agree, say so and let it raise your confidence. When
  they conflict (e.g. package.json's own "test" script looks stale but
  CI actually runs "npm run test:ci", or CONTRIBUTING.md documents a
  different current workflow), use the evidence itself to judge which
  path is current/canonical, and say briefly why in reasoning_summary.
  If you cannot resolve the conflict reliably from the evidence given,
  do not guess -- treat this the same as insufficient evidence.
- The package manager is itself something to ground, not assume. Do not
  convert every package.json "scripts.test" into "npm test" by default.
  Look for evidence of WHICH package manager this repository actually
  uses -- a lockfile (package-lock.json/npm-shrinkwrap.json -> npm,
  yarn.lock -> yarn, pnpm-lock.yaml -> pnpm), package.json's own
  "packageManager" field, CI commands, or documented instructions. Use
  whichever manager that evidence establishes (e.g. yarn.lock present ->
  ["yarn", "test"]; pnpm-lock.yaml present -> ["pnpm", "test"]). Do not
  pick a different package manager merely from general ecosystem
  familiarity when the evidence doesn't support it. When package.json
  exists but NONE of those signals distinguish a specific manager (no
  lockfile of any kind, no "packageManager" field, no CI, no docs), "npm"
  is the one choice that adds no further, unevidenced assumption -- it
  ships with Node itself, unlike yarn/pnpm, which nothing in the evidence
  suggests are even available. This is the absence-of-contrary-evidence
  default for the one manager that needs no separate installation to
  exist, not the "general ecosystem familiarity" guess this rule
  otherwise prohibits.
- setup_commands follow the identical evidence discipline as
  test_command -- but "no CI/install step was shown" is NOT the same
  claim as "nothing needs installing." Work through, in order: (1) what
  repository-owned test entry point will run; (2) what tool(s) that
  entry point itself invokes; (3) does the repository's OWN dependency
  manifest (package.json's dependencies/devDependencies, a
  requirements/Pipfile/pyproject dependency list, a Cargo.toml/go.mod,
  etc.) declare that tool as a project dependency; (4) will a fresh,
  disposable checkout already contain it (a package manager's install
  target -- node_modules, a virtualenv, target/ -- will NOT; a file
  committed to the repository would). If the entry point invokes a tool
  the repository's OWN manifest declares as a dependency, and nothing
  suggests it is already materialized, INCLUDE the setup command that
  installs it, using the SAME package manager you established for the
  test entry point above -- this is making the repository's own declared
  interface executable, not inventing a plausible-looking convention
  (see "WEAK / SPECULATIVE SETUP" vs. "STRONGLY IMPLIED REPOSITORY-OWNED
  SETUP" for the exact line: guessing a command such as "pip install -r
  requirements.txt" merely because Python files exist, with no such file
  shown, is still prohibited; declining to install a dependency the
  manifest itself names, that the entry point itself needs, is not
  caution -- it is discarding evidence you were given). Do NOT default to
  a "common for this language" install command such as "npm install",
  "npm ci", "pip install -r requirements.txt", "poetry install", or
  "bundle install" merely because it's typical, with no dependency
  manifest behind it -- that remains prohibited.
    * A lockfile changes HOW you install, never WHETHER you install:
      package-lock.json/npm-shrinkwrap.json justifies a deterministic
      mode ("npm ci"); its ABSENCE does not mean skip setup -- it means
      use the non-lockfile mode instead ("npm install"). Never propose
      "npm ci" (or another manager's lockfile-only install mode) without
      that exact lockfile actually present, and never invent or assume
      one that isn't.
    * These are examples of the principle, not a table to pattern-match:
      a package-manager project whose test entry point invokes a
      devDependency-declared CLI; a Python project whose evidenced test
      command runs a tool its own requirements/pyproject dependency list
      declares; a Rust/Go/JVM project where repository evidence
      establishes its own preparation command. The rule is
      repository-declared-dependency executability, not a per-ecosystem
      lookup table.
  If no dependency manifest declares the invoked tool, or the evidence is
  ambiguous/contradictory about setup, prefer 0 setup_commands (or low
  confidence if the test command cannot run at all without one) over
  inventing an environment.
- Command provenance is required, not optional: reasoning_summary must be
  able to answer, briefly, "why is THIS setup command supported by the
  repository" and "why is THIS test entry point supported by the
  repository" -- name the evidence, don't just assert the command. For
  example: "package.json defines scripts.test; package-lock.json
  establishes npm as the package manager; the repository-owned entry
  point is `npm test`. The inner tap invocation is intentionally not
  reconstructed."
- When evidence is insufficient -- to determine a reliable command, to
  choose a package manager, to resolve conflicting sources, or for any
  other material part of the plan -- do not guess. Set confidence to
  "low" (see below) rather than filling the gap with an inferred
  "equivalent." Uncertainty must never be converted into invention.
- The result_strategy rules below are about REPORTING, layered ON TOP of
  the repository-grounded command above -- never a license to rewrite it.
  Repository-owned execution semantics + safe reporting instrumentation is
  allowed; LLM-reconstructed execution semantics is not, no matter how the
  result is reported. Prefer structured, per-test result output over a
  bare exit code whenever you can do so SAFELY and CONFIDENTLY, without
  changing which tests run.
  Per-test evidence lets OpenAnt tell a newly-introduced failure apart from
  one that already existed before the patch, even when the suite was not
  fully passing beforehand -- a bare exit code cannot make that distinction,
  so it is a weaker result even when it is the safe, correct choice.
- Use result_strategy = "junit" ONLY when ALL of the following hold:
    * the repository evidence clearly identifies a SPECIFIC, well-known
      test runner (e.g. pytest) -- not a guess, not "probably", not
      inferred from an unrelated hint;
    * you know, with confidence, that EXACT runner's own standard,
      built-in flag for emitting a JUnit XML report (e.g. pytest's
      `--junitxml=<path>`) -- never a third-party plugin/reporter that
      might not be installed, and never a flag you are not certain
      exists for that runner;
    * adding that flag changes ONLY how results are reported -- it does
      not add, remove, filter, or otherwise change which tests are
      selected, does not change pass/fail semantics, and requires no
      dependency beyond what the runner itself already provides;
    * result_output_path is an absolute path under /tmp/ (e.g.
      /tmp/openant-result.xml), and test_command's own tokens actually
      contain that exact path somewhere (e.g. as
      `--junitxml=/tmp/openant-result.xml`) -- a plan that claims "junit"
      without its command actually referencing the declared path will be
      rejected.
  Example: repository evidence clearly shows pytest is used (e.g.
  pyproject.toml's [tool.pytest.ini_options], a noxfile.py invoking
  pytest, and/or CI running pytest) -- you may take the pytest invocation
  that same evidence establishes and append
  `--junitxml=/tmp/openant-result.xml` to it unchanged otherwise, with
  result_strategy = "junit" and result_output_path =
  "/tmp/openant-result.xml".
- Use result_strategy = "tap" ONLY when repository evidence clearly shows
  that the repository-owned test entry point's NORMAL invocation --
  completely unchanged, no added flag, no added environment variable --
  itself emits raw TAP text (lines like "ok 1 - ..."/"not ok 2 - ...").
  Do NOT infer "tap" merely because a script/command name CONTAINS "tap"
  or "tape", or because a TAP-capable library is a declared dependency --
  many such tools print a human-readable summary by default and only
  emit real TAP with an added flag or environment variable, and you may
  never add one (the entry point runs exactly as evidenced -- see above).
  Sufficient evidence looks like: CI/docs directly showing raw "ok"/"not
  ok" lines coming from THIS unmodified command, or the evidenced runner
  being one you know, with confidence, emits TAP as its own unconditional
  default (e.g. Node's built-in `node --test`). result_output_path must
  be null for "tap" -- there is no report file; unlike junit, the TAP
  text is read directly from the command's own normal output. When in
  doubt, this is exactly the same "do not guess" situation as junit
  below -- use "exit_code" instead.
- If you are not fully confident in a SPECIFIC runner's own built-in
  structured-output flag or a genuinely-unprompted TAP stream, use
  result_strategy = "exit_code" and leave result_output_path null. This is
  the correct, safe choice for a custom or bespoke command (e.g. `make
  test`, `./scripts/test.sh`) -- do NOT invent a result converter, and do
  NOT wrap, replace, or second-guess the repository's own evidenced
  command just to obtain structured output. The repository's normal test
  invocation is authoritative; when in doubt, choose "exit_code" rather
  than guess.
- Whether proposing "junit", "tap", or "exit_code", you must NEVER add,
  and a structured-output result must never require:
    * a speculative or unfamiliar runner flag you are not certain exists;
    * a third-party reporter/plugin flag that may need a package the
      repository has not itself declared;
    * any change to which tests are selected -- no new paths, filters,
      keyword expressions, or markers beyond what the repository's own
      evidenced command already specifies;
    * parallelization/xdist changes, retries, or fail-fast flags;
    * a coverage wrapper, UNLESS the repository's own evidenced command
      already uses one, in which case leave it exactly as evidenced;
    * a custom result converter or post-processing step.
  If getting structured output would require any of the above, use
  "exit_code" instead -- never trade test-selection fidelity for a
  richer result.
- runtime_family describes the EXECUTION ENVIRONMENT (interpreter/toolchain)
  the commands need, NOT which test tool is used. For example, a Python
  repository whose tests are run via `make test` still has runtime_family
  "python", not "make" -- "make" is not a runtime family.
- runtime_version_hint is optional provenance only (e.g. from a
  .python-version, package.json engines field, or go.mod). Do not guess a
  version the repository does not evidence.
- Never propose a Docker image, base image, or any container identifier --
  runtime_family and runtime_version_hint are the only environment signals
  you may give; OpenAnt chooses the actual execution image.
- evidence must list every file (by the exact path shown above) that
  justified your plan. Do not cite a file you were not shown.
- If the evidence does not give you enough to propose a reliable plan, set
  confidence to "low" and briefly say why in reasoning_summary -- do not
  guess a plan you are not confident in.
- reasoning_summary is a short provenance note (a sentence or two), not a
  chain of reasoning. When you choose "junit", state why plainly, e.g.:
  "Repository evidence identifies pytest; JUnit XML output is enabled only
  to capture per-test results and does not change test selection." When
  preserving a repository-owned entry point, name the evidence, e.g.:
  "package.json defines scripts.test; package-lock.json establishes npm;
  the repository-owned entry point `npm test` is used as-is rather than
  reconstructing the tap invocation inside it."

Before returning, verify that your JSON object contains every schema key:
    setup_commands
    test_command
    result_strategy
    result_output_path
    runtime_family
    runtime_version_hint
    evidence
    reasoning_summary
    confidence
confidence MUST be present and MUST be exactly one of: "high", "medium",
"low". Do not omit it.
"""

_FENCE_RE = re.compile(r"^```[a-zA-Z]*\n|\n```\s*$")


def _strip_fences(text: str) -> str:
    return _FENCE_RE.sub("", text.strip())


def _as_tuple_of_str(value) -> "tuple[str, ...] | None":
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        return None
    return tuple(value)


def _as_tuple_of_command_tuples(value) -> "tuple[tuple[str, ...], ...] | None":
    if not isinstance(value, list):
        return None
    out = []
    for item in value:
        t = _as_tuple_of_str(item)
        if t is None:
            return None
        out.append(t)
    return tuple(out)


def _parse_response(raw: str) -> "tuple[dict | None, str | None]":
    """Strict, deterministic parse. Any missing execution-critical key,
    wrong type, or unparseable JSON returns (None, reason) -- never a
    partially-trusted plan. ``confidence``/``reasoning_summary``/
    ``runtime_version_hint`` are advisory metadata: their outright
    ABSENCE normalizes to a safe default instead of rejecting the whole
    response (see the module docstring's "Metadata vs. execution-critical
    fields"); a malformed *value* (present, wrong JSON type) is still
    rejected for reasoning_summary/runtime_version_hint exactly as
    before, while confidence normalizes even a malformed or unrecognized
    value to "unknown" rather than rejecting (see "Confidence
    semantics").

    The returned reason string is a bounded, internal diagnostic for
    traced/debug runs only -- see discover_test_plan's rejection_reason
    parameter. It is never surfaced verbatim in the user-facing trust
    report."""
    try:
        data = json.loads(_strip_fences(raw))
    except (json.JSONDecodeError, TypeError):
        return None, "LLM response was not valid JSON"
    if not isinstance(data, dict):
        return None, "LLM response JSON was not an object"
    missing = [key for key in _REQUIRED_KEYS if key not in data]
    if missing:
        return None, f"LLM response missing required field(s): {', '.join(missing)}"

    setup_commands = _as_tuple_of_command_tuples(data["setup_commands"])
    if setup_commands is None:
        return None, "setup_commands was not a list of argv-token lists"
    test_command = _as_tuple_of_str(data["test_command"])
    if test_command is None:
        return None, "test_command was not a list of string tokens"
    evidence = _as_tuple_of_str(data["evidence"])
    if evidence is None:
        return None, "evidence was not a list of strings"
    if len(evidence) > _MAX_EVIDENCE_ENTRIES or any(len(e) > _MAX_EVIDENCE_ENTRY_CHARS for e in evidence):
        return None, "evidence list exceeded the bounded entry count/length"

    result_strategy = data["result_strategy"]
    if result_strategy not in VALID_RESULT_STRATEGIES:
        return None, f"unrecognized result_strategy: {result_strategy!r}"

    result_output_path = data["result_output_path"]
    if result_output_path is not None and not isinstance(result_output_path, str):
        return None, "result_output_path was neither a string nor null"
    runtime_family = data["runtime_family"]
    if runtime_family is not None and not isinstance(runtime_family, str):
        return None, "runtime_family was neither a string nor null"

    # --- advisory metadata: absence normalizes, malformed VALUES for
    # reasoning_summary/runtime_version_hint still reject (unchanged from
    # before); confidence is normalized even when malformed -- see module
    # docstring.
    runtime_version_hint = data.get("runtime_version_hint")
    if runtime_version_hint is not None and not isinstance(runtime_version_hint, str):
        return None, "runtime_version_hint was neither a string nor null"
    reasoning_summary = data.get("reasoning_summary", "")
    if not isinstance(reasoning_summary, str):
        return None, "reasoning_summary was not a string"
    reasoning_summary = reasoning_summary[:_MAX_REASONING_SUMMARY_CHARS]
    confidence = data.get("confidence")
    # isinstance-guard BEFORE the membership check: an unhashable
    # malformed value (e.g. a list/dict, not just an int or an
    # unrecognized string) must normalize to "unknown" too, never raise --
    # `x in <frozenset>` itself requires hashing x, so checking membership
    # first would crash on exactly the malformed input this is supposed to
    # tolerate.
    if not isinstance(confidence, str) or confidence not in VALID_CONFIDENCE_LEVELS:
        confidence = "unknown"

    return {
        "setup_commands": setup_commands, "test_command": test_command,
        "result_strategy": result_strategy, "result_output_path": result_output_path,
        "runtime_family": runtime_family, "runtime_version_hint": runtime_version_hint,
        "evidence": evidence, "reasoning_summary": reasoning_summary, "confidence": confidence,
    }, None


def discover_test_plan(
    repo_root: "Path | str", llm, *, rejection_reason: "list[str] | None" = None,
) -> "TestExecutionPlan | None":
    """Discover a TestExecutionPlan for repo_root using exactly one bounded
    LLM call. Returns None (never a fabricated plan) when: there is no
    evidence to reason from, the LLM call itself raises, the response
    can't be parsed, the model deliberately self-reports low confidence,
    evidence citations don't check out, or the resulting plan fails
    deterministic validation. Callers must treat None identically to
    NOT_VERIFIED.

    ``rejection_reason``: optional, opt-in, additive-only. When a caller
    passes a list, exactly one bounded, internal diagnostic string is
    appended to it if (and only if) this call returns None -- letting
    traced/debug tooling distinguish *why* (malformed JSON, missing
    execution-critical field, deterministic validation failure,
    unsupported runtime, low-confidence policy rejection, ...) without
    that reason ever needing to appear in the user-facing trust report.
    Passing nothing (the default) is a zero-behavior-change no-op,
    identical to this function's prior signature.
    """
    def _reject(reason: str) -> None:
        if rejection_reason is not None:
            rejection_reason.append(reason[:_MAX_REJECTION_REASON_CHARS])
        return None

    repo_root = Path(repo_root)
    evidence = gather_test_plan_evidence(repo_root)
    if evidence.is_empty:
        return _reject("no repository evidence found to reason from")

    user_message = (
        "Repository evidence follows. Use ONLY this evidence -- do not assume "
        "anything about the repository beyond what is shown.\n\n" + evidence.to_prompt_text()
    )

    try:
        raw = llm.complete(_SYSTEM_PROMPT, user_message, stage="test_plan_discovery")
    except Exception as exc:  # noqa: BLE001 -- an LLM-layer failure is a discovery failure, not a crash
        return _reject(f"LLM call failed: {type(exc).__name__}")

    candidate, parse_reason = _parse_response(raw)
    if candidate is None:
        return _reject(parse_reason or "LLM response failed schema parsing")
    if candidate["confidence"] == "low":
        # The model ITSELF deliberately reported low confidence -- kept
        # distinct from "unknown" (missing/malformed self-report, treated
        # as neutral, see module docstring) -- don't spend a Docker build
        # on a plan the model has already told us it doesn't trust.
        return _reject("model self-reported low confidence")

    # Provenance enforcement: every cited evidence path must be one we
    # actually showed the model -- exact match only, never fuzzy. This is
    # deterministic (checked against the SAME EvidenceBundle used to build
    # the prompt above, not re-derived), so a hallucinated citation (e.g.
    # "tox.ini" when no tox.ini was ever supplied) is rejected outright
    # rather than silently trusted because *some* evidence was non-empty.
    if not set(candidate["evidence"]) <= evidence.citable_identifiers:
        return _reject("evidence citation not found among what was actually shown to the model")

    try:
        plan = TestExecutionPlan(source="llm", **candidate)
    except Exception as exc:  # noqa: BLE001
        return _reject(f"TestExecutionPlan construction failed: {type(exc).__name__}")

    result = validate_plan(plan)
    if not result.valid:
        return _reject(f"deterministic plan validation failed: {result.reason}")
    return result.plan
