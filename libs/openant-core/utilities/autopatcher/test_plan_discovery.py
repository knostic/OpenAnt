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
``result_strategy``, ``result_output_path``, ``runtime_family``,
``evidence``, and ``confidence`` are all part of the required response
CONTRACT -- a response that omits one, or whose value is the wrong shape
(or, for confidence, any value other than "high"/"medium"/"low"), gives
OpenAnt nothing safe to execute or accept, so it is rejected outright (see
``_REQUIRED_KEYS`` and the strict per-field checks below). Only
``reasoning_summary`` and ``runtime_version_hint`` are advisory
provenance/metadata -- never consulted by test_plan_validation.py's
execution-safety checks, never rendered as if they were verified fact. A
response that simply omits one of these two must not, by itself, discard
an otherwise valid, deterministically validated plan: each is normalized
to a safe default (``reasoning_summary`` -> "", ``runtime_version_hint`` ->
None) rather than causing rejection -- a malformed *value* (present, but
the wrong JSON type) is still rejected, unchanged. Confidence is
deliberately NOT given this same absence-tolerant treatment, even though
it is equally advisory in what it's USED for (see "Confidence semantics"
below) -- see "Confidence contract enforcement" for why.

Confidence contract enforcement: a real urllib3 replay showed the model
omitting ``confidence`` from an otherwise well-formed response, and an
earlier version of this module silently normalized that to an internal
"unknown" placeholder and still accepted the plan -- persisting a
confidence value the LLM never actually returned, out of the three values
the schema declares as the only legal ones. That is now rejected outright,
the same "no plan discovered" path every other execution-critical failure
already takes (see ``_parse_response``) -- no retry is added merely
because confidence was omitted (see "No retries" above); a second omission
is just as much a rejection as the first. ``_SYSTEM_PROMPT`` still ends
with a short, mandatory "every schema key, and confidence is one of
high/medium/low" checklist placed immediately before the repository
evidence is shown -- the last thing the model reads before generating --
as a prompt-only reliability nudge to reduce how often this rejection
fires at all, but the rejection itself, not a silent substitute value, is
what actually enforces the contract now.

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
executability for "high" and "medium" alike. (test_execution_models.
VALID_CONFIDENCE_LEVELS separately still includes "unknown" -- that is a
*structural* validity set for ANY TestExecutionPlan object, including one
reconstructed from a prior run's persisted artifact during replay, where
an old, pre-this-fix "unknown" value may legitimately already exist on
disk; it has no bearing on what a FRESH LLM response is allowed to
contain, which is this module's own, narrower
``_VALID_LLM_CONFIDENCE_LEVELS``.)

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

Parameterized-command grounding (evidenced template != evidenced concrete
value): a real urllib3 replay showed the model taking a CI-evidenced,
matrix-parameterized invocation (a shell expansion resolving to
"test-$PYTHON_VERSION", the version coming from a CI matrix dimension
OpenAnt's own environment has no visibility into) and instantiating it
into a specific, unevidenced concrete command ("test-3.12") -- which then
ran against a runtime that specific value didn't actually have available,
silently producing no real test execution at all (see
existing_test_regression.py's execution-validity handling for the other
half of this fix). This is a prompt-only fix, deliberately not a CI-
expression interpreter or templating framework (see the "PARAMETERIZED
VALUES" rule below): repository evidence establishing that a
parameterized command exists is not evidence for any ONE value of that
parameter, and the model must not guess one -- exactly the same
"no plan is better than a guessed plan" principle already governing every
other part of this prompt, just for a category (matrix/environment-
variable/template placeholders) that hadn't been called out explicitly
before. Deterministic validation cannot reliably catch this after the
fact once the model has already produced a syntactically clean, concrete
value with no residual template syntax left in it -- this is why the fix
is at the discovery/prompt boundary, not a new validation rule.

Evidence-backed repository-owned commands: a real GitPython
CVE-2026-44243 regression-suite run showed a valid, well-evidenced plan
whose setup_commands included "./init-tests-after-clone.sh" -- a real
script GitPython's own CI directly invokes, exactly the repository-owned
entry point this prompt's own "PRESERVE REPOSITORY-OWNED ENTRY POINTS"
rule already tells the model to preserve -- rejected outright by
test_plan_validation's static ALLOWED_COMMAND_BINARIES, which has no
notion of a repository-owned file at all. This is fixed at discovery,
not by adding the exact path to a static allowlist (the next
differently-named repository script would hit the identical wall) and
not by a filename/path heuristic (a repository controls its own
filenames -- that is not a meaningful security boundary): see
test_plan_command_provenance.resolve_repository_owned_commands, called
by discover_test_plan below, which trusts a "./"-prefixed command token
for exactly one call only when it is BOTH a real, contained repository
file AND grounded in the repository test/setup evidence actually shown
to the model -- never a static entry, never a name-based guess.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .test_evidence_acquisition import gather_test_plan_evidence
from .test_execution_models import (
    VALID_RESULT_STRATEGIES,
    TestExecutionPlan,
)
from .test_plan_command_provenance import resolve_repository_owned_commands
from .test_plan_validation import validate_plan

# Execution-critical: the response must explicitly include every one of
# these keys (a value may still be null where the schema allows it, e.g.
# result_output_path or runtime_family) -- without them there is nothing
# safe to execute (or, for confidence, nothing safe to ACCEPT -- see
# "confidence is part of the response CONTRACT" below), so a response
# missing any one is rejected outright. Deliberately EXCLUDES
# reasoning_summary/runtime_version_hint -- see the module docstring's
# "Metadata vs. execution-critical fields".
_REQUIRED_KEYS = (
    "setup_commands", "test_command", "result_strategy", "result_output_path",
    "runtime_family", "evidence", "confidence",
)

# LLM call tags -- mirrors patch_generator.py/pipeline.py's own
# "patch_generation" / "patch_generation_contract_retry" pair exactly (see
# stage_registry.STAGE_OWNED_LLM_TAGS[TEST_ANALYSIS_AND_PLAN], which must
# own both). The retry tag is used for AT MOST one additional call per
# discover_test_plan() invocation -- see that function's own bounded
# contract-repair retry.
_DISCOVERY_STAGE = "test_plan_discovery"
_CONTRACT_REPAIR_RETRY_STAGE = "test_plan_discovery_contract_retry"

_CONTRACT_REPAIR_RETRY_HEADER = "\n\n## Contract violation in your previous response\n\n"
_CONTRACT_REPAIR_RETRY_HINT = """\
Your previous response violated the required output contract: {violation}

Respond again with a complete, corrected JSON object satisfying the exact \
same schema as before -- every required key present, "confidence" one of \
"high"/"medium"/"low", "result_strategy" one of "junit"/"tap"/"exit_code". \
Return the WHOLE object again, fully valid this time -- do not return only \
the corrected piece. No prose, no markdown fences."""

# The ONLY values the declared LLM-facing schema permits for confidence
# (see _SYSTEM_PROMPT's schema block). Deliberately NOT
# test_execution_models.VALID_CONFIDENCE_LEVELS, which additionally
# contains "unknown" -- that frozenset validates ANY TestExecutionPlan
# structurally, including one reconstructed from a PRIOR run's persisted
# artifact during replay (where an old, pre-this-fix "unknown" value may
# still legitimately exist on disk and must not make replay itself
# crash). This narrower set is the response CONTRACT boundary for a
# FRESH LLM response: it is never lenient about "unknown" or anything
# else outside the three declared values -- see _parse_response.
_VALID_LLM_CONFIDENCE_LEVELS = frozenset({"high", "medium", "low"})

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
  "test_command": [<argv tokens>] | [] (empty ONLY together with confidence "low" --
                  see "INSUFFICIENT EVIDENCE" below),
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
    6. PARAMETERIZED VALUES: an evidenced command may itself contain a
       placeholder your OWN environment does not resolve -- a shell
       expansion (``${VAR}``, ``${VAR:-default}``), a CI matrix
       expression (e.g. ``${{ matrix.python-version }}``), a template
       substitution, a version placeholder, or any other build-matrix
       dimension. Repository evidence establishing that a PARAMETERIZED
       command exists is NOT, by itself, evidence for any ONE concrete
       value of that parameter -- you have no visibility into which
       matrix entry, environment variable, or default OpenAnt's own
       execution environment would actually supply, and CI matrix
       possibilities are not a grounded runtime fact about that
       environment. Do NOT instantiate a placeholder into a specific
       concrete value (e.g. turning ``test-$PYTHON_VERSION`` into
       ``test-3.12``) unless repository evidence AND OpenAnt's execution
       environment TOGETHER establish that exact value -- which, for a
       CI-matrix-driven placeholder, they essentially never will. This is
       exactly as unsafe as inventing a command from nothing: a
       plausible-looking concrete value is still a guess. Instead, prefer
       a DIFFERENT repository-owned entry point that avoids the
       placeholder entirely, if the evidence establishes one (e.g. a
       plain, non-parameterized session/target with the same purpose).
       A wrapper/session tool that itself declares and owns expansion of
       a parameterized session is exactly this kind of plain,
       non-parameterized entry point -- e.g. nox's own
       ``@nox.session(python=[...])`` decorator naming a base session
       (``test``) that nox itself selects/expands among its declared
       variants at invocation time. When repository evidence shows a
       session/environment declared this way, invoking the wrapper with
       that bare, repository-declared name (e.g. ``nox -s test``) uses a
       repository-owned entry point exactly as declared -- it is NOT the
       same act as instantiating a CI-computed, matrix-substituted value
       (e.g. ``test-3.12``), which remains forbidden above. The
       distinction is not "wrapper vs. direct" -- it is whether the exact
       name used is itself present in the repository's own declaration,
       or whether it was constructed by substituting a value the
       repository never wrote down. This applies to any wrapper/session
       tool with the same shape (e.g. tox environments), not only nox.
       If none of this establishes a safe entry point, treat this exactly
       like INSUFFICIENT EVIDENCE below: do not guess a value, and if no
       command can be honestly grounded at all, use an empty test_command
       with confidence "low" -- see that rule for the exact mechanism. A
       literal, UNRESOLVED placeholder left in test_command instead (e.g.
       the raw text ``${VAR}`` or ``${{ matrix.foo }}``) is likewise never
       acceptable -- it is neither a real, executable argv token, nor the
       explicit "no plan" signal; use the empty array, not a leftover
       fragment of the unresolved expression.
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
- INSUFFICIENT EVIDENCE: when evidence is insufficient -- to determine a
  reliable command, to choose a package manager, to resolve conflicting
  sources, to ground a parameterized value (see PARAMETERIZED VALUES
  above), or for any other material part of the plan -- do not guess.
  Set confidence to "low" rather than filling the gap with an inferred
  "equivalent." Uncertainty must never be converted into invention. If
  the result is that NO command can be honestly grounded at all -- not
  even a non-parameterized fallback -- set test_command to an empty
  array `[]` (and setup_commands to `[]` too; there is nothing to
  install for a command that doesn't exist) TOGETHER WITH confidence
  "low". This is the correct, sanctioned way to report "no executable
  plan" -- explain briefly in reasoning_summary why no command could be
  grounded. Do NOT leave an unresolved placeholder or partial expression
  in test_command instead (e.g. the literal text of a shell/CI variable
  you couldn't resolve) -- that is neither a real command nor the
  explicit "no plan" signal; use the empty array. An empty test_command
  is ONLY valid together with confidence "low" -- a "medium"/"high"
  confidence response must always have a real, non-empty, executable
  command.
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
- Before settling on result_strategy = "exit_code", re-check one thing
  specifically: does the evidence you were shown include a directly-
  evidenced invocation (CI, documentation, or a repository test script
  showing the raw command) of a SPECIFIC, well-known test runner you are
  confident has its own built-in structured-output flag -- even if a
  wrapper/session tool (e.g. nox/tox) is ALSO present in the evidence for
  a different purpose? If so, prefer proposing "junit"/"tap" on that
  directly-evidenced invocation over "exit_code", exactly as the
  result_strategy rules above describe. Only fall back to "exit_code"
  once you have actually considered this -- not by default.

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


def _find_balanced_json_objects(text: str) -> "list[str]":
    """Find every top-level, brace-balanced ``{...}`` substring in
    `text`, respecting JSON string-literal syntax (a ``{``/``}`` inside a
    quoted string value, e.g. inside reasoning_summary prose, never
    confuses the depth count). Purely syntactic bracket-matching -- no
    JSON parsing, no semantic interpretation, no repair -- so a returned
    substring is only a CANDIDATE; the caller still runs it through
    ``json.loads`` and only trusts it if that succeeds on its own."""
    objects: "list[str]" = []
    depth = 0
    start = None
    in_string = False
    escaped = False
    for i, ch in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth > 0:
            depth -= 1
            if depth == 0 and start is not None:
                objects.append(text[start:i + 1])
                start = None
    return objects


def _load_response_json(raw: str) -> "tuple[object, str | None]":
    """Parse `raw` as JSON, tolerating harmless surrounding prose --
    formatting tolerance only, never semantic repair.

    Strategy, strictly in this order:
      1. Prefer the whole (fence-stripped) response parsing as JSON on
         its own -- unchanged from before this function existed. This is
         the only path taken for a well-formed response.
      2. Only if that fails: look for every top-level, brace-balanced
         ``{...}`` substring (see _find_balanced_json_objects) and keep
         exactly the ones that ALSO parse as valid JSON on their own.
         If precisely ONE does, that is the extracted object -- e.g. one
         prose sentence before and/or after an otherwise well-formed
         JSON object, despite the prompt explicitly saying not to add
         one, is recovered this way. If ZERO or MORE THAN ONE substring
         parses successfully, this still rejects, exactly as strict
         parsing already would -- never guesses among competing
         candidates, never repairs a malformed one.

    Returns (parsed_value, None) on success -- `parsed_value` may be any
    JSON type; the caller (``_parse_response``) still checks it is a
    dict, unchanged. Returns (None, reason) on failure."""
    stripped = _strip_fences(raw)
    try:
        return json.loads(stripped), None
    except (json.JSONDecodeError, TypeError):
        pass

    candidates = []
    for substring in _find_balanced_json_objects(stripped):
        try:
            candidates.append(json.loads(substring))
        except (json.JSONDecodeError, TypeError):
            continue  # not valid JSON on its own -- e.g. a stray "{" in prose

    if len(candidates) == 1:
        return candidates[0], None
    if len(candidates) > 1:
        return None, "LLM response contained more than one candidate JSON object; expected exactly one"
    return None, "LLM response was not valid JSON"


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


def _parse_response(raw: str) -> "tuple[dict | None, str | None, bool]":
    """Strict, deterministic parse. Any missing required key, wrong type,
    or unparseable JSON returns (None, reason, repairable) -- never a
    partially-trusted plan.

    ``repairable`` (the third element) is True for EXACTLY three narrow,
    mechanical output-CONTRACT violations in an otherwise syntactically
    valid JSON object -- missing required schema key(s), an invalid
    ``result_strategy`` value, or a missing/invalid ``confidence`` value
    -- see discover_test_plan's own single bounded contract-repair retry.
    False for every other rejection below (unparseable JSON, wrong field
    types, evidence-bound violations, malformed advisory fields): those
    are not narrow omissions a "you forgot one thing" reminder can fix,
    and are never retried. Cross-field semantic checks (e.g. empty
    test_command paired with a non-"low" confidence) live in
    discover_test_plan, not here, and are DELIBERATELY NOT marked
    repairable in this slice -- our production evidence justifies
    repairing schema completeness/enum-contract failures, not retrying
    semantic contradictions. Meaningless (always False) on the success
    path, where `candidate` is not None.

    JSON extraction (formatting tolerance only, never semantic repair):
    the prompt says "Respond with EXACTLY one JSON object, no prose
    before or after it" -- a real urllib3 replay showed the model
    otherwise producing an execution-critical-valid plan but prefacing it
    with one explanatory prose sentence anyway, which made the whole
    response fail strict ``json.loads`` and rejected an otherwise-good
    plan. ``_load_response_json`` still prefers the whole response
    parsing as JSON on its own (unchanged, and the only path taken for a
    well-formed response); only when that fails does it look for exactly
    one brace-balanced substring that parses as valid JSON by itself.
    Zero such substrings, or more than one (never guessed among), both
    still reject -- see that function's own docstring. Everything below
    this point -- required-key/type/enum checks, confidence, evidence
    provenance -- is completely UNCHANGED by this: it operates on
    whatever dict was obtained, exactly as before, whether that came from
    the whole response or an extracted substring.

    ``reasoning_summary``/``runtime_version_hint`` are
    advisory metadata ONLY: their outright ABSENCE normalizes to a safe
    default instead of rejecting the whole response (see the module
    docstring's "Metadata vs. execution-critical fields"); a malformed
    *value* (present, wrong JSON type) is still rejected for either,
    unchanged.

    ``confidence`` is NOT treated this leniently, despite also being
    advisory (never part of the execution-safety boundary -- see
    "Confidence semantics" below): it is part of the declared response
    CONTRACT (the schema block states exactly three valid values, and the
    prompt repeats "confidence MUST be present"), so a response that
    omits it, or supplies anything other than "high"/"medium"/"low", is
    REJECTED here -- never silently normalized to an out-of-schema
    placeholder like "unknown" and then treated as an accepted plan. A
    prior version of this function normalized a missing/malformed
    confidence to "unknown" and still accepted the plan; a real urllib3
    replay showed the model omitting confidence from an otherwise
    well-formed response, and that response being SILENTLY ACCEPTED with
    a fabricated value the LLM never actually returned. A LATER real
    urllib3 replay showed this exact rejection firing on an otherwise
    fully correct, well-evidenced plan -- this is now `repairable=True`:
    discover_test_plan gets exactly one bounded chance to ask the SAME
    model to resend a complete, corrected object; OpenAnt itself still
    never synthesizes the missing value (see "No retries" above, now
    narrowed to "no MORE than one retry, and only for this narrow
    contract-completeness shape").

    The returned reason string is a bounded, internal diagnostic for
    traced/debug runs only -- see discover_test_plan's rejection_reason
    parameter. It is never surfaced verbatim in the user-facing trust
    report."""
    def _fail(reason: str, *, repairable: bool = False) -> "tuple[None, str, bool]":
        return None, reason, repairable

    data, json_reason = _load_response_json(raw)
    if json_reason is not None:
        return _fail(json_reason)
    if not isinstance(data, dict):
        return _fail("LLM response JSON was not an object")
    missing = [key for key in _REQUIRED_KEYS if key not in data]
    if missing:
        return _fail(f"LLM response missing required field(s): {', '.join(missing)}", repairable=True)

    setup_commands = _as_tuple_of_command_tuples(data["setup_commands"])
    if setup_commands is None:
        return _fail("setup_commands was not a list of argv-token lists")
    # `[]` is intentionally ACCEPTED here (_as_tuple_of_str allows an
    # empty list through) -- it is the correct SHAPE for both "a real,
    # zero-argument command" (never actually valid, see
    # test_plan_validation._valid_command_shape's own non-empty check)
    # and, more importantly, the model's explicit "no executable plan"
    # signal (see _SYSTEM_PROMPT's "INSUFFICIENT EVIDENCE" rule).
    # discover_test_plan (not here) is what enforces that an empty
    # command is valid ONLY alongside confidence "low", and rejects it
    # BEFORE ever constructing a TestExecutionPlan -- do not move that
    # enforcement here, it needs `candidate["confidence"]`, which isn't
    # parsed yet at this point in the function.
    test_command = _as_tuple_of_str(data["test_command"])
    if test_command is None:
        return _fail("test_command was not a list of string tokens")
    evidence = _as_tuple_of_str(data["evidence"])
    if evidence is None:
        return _fail("evidence was not a list of strings")
    if len(evidence) > _MAX_EVIDENCE_ENTRIES or any(len(e) > _MAX_EVIDENCE_ENTRY_CHARS for e in evidence):
        return _fail("evidence list exceeded the bounded entry count/length")

    # Enum-contract violation -- one of the three narrow, repairable
    # shapes (see this function's own docstring).
    result_strategy = data["result_strategy"]
    if result_strategy not in VALID_RESULT_STRATEGIES:
        return _fail(f"unrecognized result_strategy: {result_strategy!r}", repairable=True)

    result_output_path = data["result_output_path"]
    if result_output_path is not None and not isinstance(result_output_path, str):
        return _fail("result_output_path was neither a string nor null")
    runtime_family = data["runtime_family"]
    if runtime_family is not None and not isinstance(runtime_family, str):
        return _fail("runtime_family was neither a string nor null")

    # Part of the response CONTRACT, not advisory metadata (see this
    # function's own docstring) -- missing or invalid confidence rejects
    # the whole response, exactly like an unrecognized result_strategy
    # above. isinstance-guard BEFORE the membership check: an unhashable
    # value (e.g. a list/dict) must still be rejected cleanly, never
    # raise -- `x in <frozenset>` itself requires hashing x. One of the
    # three narrow, repairable contract shapes (see this function's own
    # docstring) -- a MISSING confidence key is already caught above by
    # the required-keys check; this branch additionally catches a
    # PRESENT-but-invalid value (wrong type, or not one of the three).
    confidence = data["confidence"]
    if not isinstance(confidence, str) or confidence not in _VALID_LLM_CONFIDENCE_LEVELS:
        return _fail(f"confidence must be exactly one of 'high'/'medium'/'low', got {confidence!r}", repairable=True)

    # --- advisory metadata: absence normalizes, malformed VALUES still
    # reject (unchanged from before).
    runtime_version_hint = data.get("runtime_version_hint")
    if runtime_version_hint is not None and not isinstance(runtime_version_hint, str):
        return _fail("runtime_version_hint was neither a string nor null")
    reasoning_summary = data.get("reasoning_summary", "")
    if not isinstance(reasoning_summary, str):
        return _fail("reasoning_summary was not a string")
    reasoning_summary = reasoning_summary[:_MAX_REASONING_SUMMARY_CHARS]

    return {
        "setup_commands": setup_commands, "test_command": test_command,
        "result_strategy": result_strategy, "result_output_path": result_output_path,
        "runtime_family": runtime_family, "runtime_version_hint": runtime_version_hint,
        "evidence": evidence, "reasoning_summary": reasoning_summary, "confidence": confidence,
    }, None, False


def discover_test_plan(
    repo_root: "Path | str", llm, *, rejection_reason: "list[str] | None" = None,
) -> "TestExecutionPlan | None":
    """Discover a TestExecutionPlan for repo_root using AT MOST TWO bounded
    LLM calls -- the second (see _CONTRACT_REPAIR_RETRY_STAGE) fires ONLY
    when the first response's failure is one of the three narrow,
    mechanical contract-completeness shapes _parse_response marks
    `repairable=True` (missing required key(s), an invalid
    `result_strategy`, or a missing/invalid `confidence`) -- never for
    unparseable JSON, wrong field types, evidence-bound violations,
    evidence-provenance hallucination, deterministic validation
    (test_plan_validation) failure, or a cross-field semantic
    inconsistency (e.g. empty test_command with a non-"low" confidence).
    A second failure, of any kind, is never retried again -- exactly one
    retry, ever, per call. OpenAnt never synthesizes the missing/invalid
    value itself; the retry only ever asks the SAME model to resend a
    complete, corrected object (see _CONTRACT_REPAIR_RETRY_HINT).

    Returns None (never a fabricated plan) when: there is no evidence to
    reason from, the LLM call itself raises, the response (after the one
    contract-repair retry, if it fired) still can't be parsed, the model
    EXPLICITLY reports insufficient evidence (an empty test_command +
    confidence "low" -- see _SYSTEM_PROMPT's "INSUFFICIENT EVIDENCE"
    rule), the model deliberately self-reports low confidence on an
    otherwise-populated command, evidence citations don't check out, or
    the resulting plan fails deterministic validation. Callers must treat
    None identically to NOT_VERIFIED.

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
        raw = llm.complete(_SYSTEM_PROMPT, user_message, stage=_DISCOVERY_STAGE)
    except Exception as exc:  # noqa: BLE001 -- an LLM-layer failure is a discovery failure, not a crash
        return _reject(f"LLM call failed: {type(exc).__name__}")

    candidate, parse_reason, repairable = _parse_response(raw)

    # Bounded contract-repair retry -- exactly one, and ONLY for the three
    # narrow, mechanical contract-completeness shapes _parse_response
    # marks repairable (see this function's own docstring). Never invoked
    # a second time: the retry response's own `repairable` flag is
    # discarded below, so a second failure -- of any kind, including the
    # exact same one again -- falls straight through to the existing
    # rejection path, unchanged.
    if candidate is None and repairable:
        retry_message = user_message + _CONTRACT_REPAIR_RETRY_HEADER + _CONTRACT_REPAIR_RETRY_HINT.format(
            violation=parse_reason,
        )
        try:
            retry_raw = llm.complete(_SYSTEM_PROMPT, retry_message, stage=_CONTRACT_REPAIR_RETRY_STAGE)
        except Exception as exc:  # noqa: BLE001
            return _reject(f"contract-repair retry LLM call failed: {type(exc).__name__}")
        candidate, parse_reason, _ = _parse_response(retry_raw)

    if candidate is None:
        return _reject(parse_reason or "LLM response failed schema parsing")

    if not candidate["test_command"]:
        # An empty test_command is the model's explicit, structurally
        # valid way to report "repository evidence is insufficient to
        # produce an executable test plan" (see _SYSTEM_PROMPT's
        # "INSUFFICIENT EVIDENCE" rule) -- checked, and rejected, BEFORE
        # ever constructing a TestExecutionPlan: an empty command was
        # never executable to begin with, so there is nothing to build or
        # validate. This closes a real contract inconsistency a urllib3
        # replay exposed: the prompt already told the model never to
        # instantiate or leave an unresolved CI-matrix placeholder in
        # test_command, but gave it no OTHER way to populate a
        # nominally-required field when no command could be honestly
        # grounded at all -- so it left the unresolved placeholder in
        # place anyway (rejected today only because confidence also
        # happened to be "low", or because test_plan_validation's
        # shell-metacharacter check happened to catch the literal
        # placeholder syntax -- both incidental, not an explicit
        # contract). An empty command is valid ONLY alongside the
        # model's own "low" confidence self-report -- a "medium"/"high"
        # response must always have a real, executable command.
        if candidate["confidence"] != "low":
            return _reject(
                "test_command was empty but confidence was not 'low' -- an "
                "executable plan requires a real, non-empty command, or "
                "confidence must be 'low' to signal insufficient evidence"
            )
        return _reject("model reported insufficient evidence: no executable command could be grounded")

    if candidate["confidence"] == "low":
        # The model ITSELF deliberately reported low confidence on an
        # otherwise-populated command -- kept distinct from "unknown"
        # (missing/malformed self-report, treated as neutral, see module
        # docstring) -- don't spend a Docker build on a plan the model
        # has already told us it doesn't trust.
        return _reject("model self-reported low confidence")

    # Provenance enforcement: every cited evidence path must be one we
    # actually showed the model -- exact match only, never fuzzy. This is
    # deterministic (checked against the SAME EvidenceBundle used to build
    # the prompt above, not re-derived), so a hallucinated citation (e.g.
    # "tox.ini" when no tox.ini was ever supplied) is rejected outright
    # rather than silently trusted because *some* evidence was non-empty.
    if not set(candidate["evidence"]) <= evidence.citable_identifiers:
        return _reject("evidence citation not found among what was actually shown to the model")

    # Evidence-backed repository-owned commands (real GitPython CVE-2026-44243
    # regression-suite finding: a valid, well-evidenced plan's setup_commands
    # included "./init-tests-after-clone.sh", a real CI-evidenced repository
    # script -- rejected outright by validate_plan's static
    # ALLOWED_COMMAND_BINARIES, which has no notion of a repository-owned
    # entry point at all). Examines every "./"-prefixed argv[0] across
    # setup_commands + test_command; each must be a real, contained
    # repository file (see test_plan_command_provenance) AND grounded in the
    # repository test/setup evidence actually shown -- never a static
    # allowlist entry, never a filename/path heuristic. Any non-"./"-prefixed
    # token is untouched here and continues to be governed solely by
    # validate_plan's existing static allowlist, unchanged.
    trusted_repo_commands, provenance_reason = resolve_repository_owned_commands(
        candidate["setup_commands"] + (candidate["test_command"],), repo_root, evidence,
    )
    if provenance_reason is not None:
        return _reject(provenance_reason)

    try:
        plan = TestExecutionPlan(source="llm", **candidate)
    except Exception as exc:  # noqa: BLE001
        return _reject(f"TestExecutionPlan construction failed: {type(exc).__name__}")

    result = validate_plan(plan, extra_allowed_first_tokens=trusted_repo_commands)
    if not result.valid:
        return _reject(f"deterministic plan validation failed: {result.reason}")
    return result.plan
