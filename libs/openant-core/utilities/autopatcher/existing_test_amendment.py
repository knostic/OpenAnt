"""Existing Test Amendment -- a narrow, bounded feedback mechanism from
Existing Test Comparison (S11, existing_test_regression.py) back into the
candidate patch, for exactly one case: a legitimate, intentional behavior
change made by the production patch leaves an existing test asserting the
OLD behavior.

Architecture (see the architecture-inspection findings this module
implements): S11 itself stays a pure, factual comparator and is NEVER
mutated by this module -- it is called by a pipeline.py-level orchestrator
BEFORE this module runs (producing R1), and again AFTER this module
produces an amended patch (producing R2). This module only decides whether
an amendment is justified and, if so, produces it; it never re-implements
or second-guesses S11's comparison algorithm.

Gate philosophy (fail-closed at every step, exactly one bounded attempt,
never a loop):

  1. Deterministic necessary preconditions (see attempt_existing_test_
     amendment's own gate) -- most runs never reach the LLM call at all.
  2. Deterministic per-test-id -> repository-file GROUNDING (see
     ground_newly_failing_tests) -- an id that cannot be resolved to a
     real file under repo_root, with no path traversal, is simply excluded
     from the candidate set; it is never guessed at, and its shape is
     never generalized beyond pytest's own "path::rest" node-id
     convention (the one identifier shape this repository's own runner-
     summary extraction already relies on -- see existing_test_regression.
     py's _pytest_node_id_from_summary_line).
  3. ONE bounded LLM call (see attempt_existing_test_amendment) that must
     establish a DIRECT CONTRADICTION between the grounded test source and
     the patch's own stated intent -- never "does this look stale?" -- and
     may return a diff touching ONLY the grounded test file(s).
  4. PRE-SCOPE validation (see _validate_amendment_diff) of the LLM's RAW
     diff -- files subset of grounded newly-failing test files, disjoint
     from the production patch's own files, no unsafe/traversal paths --
     BEFORE any repository-aware repair or content relocation ever runs.
     A malformed or out-of-scope response is rejected here, cheaply, with
     zero repo access.
  5. The SAME shared, generic generated-diff processing primitive S4/S6
     use for their own LLM-generated diffs (see
     generated_patch_processing.process_generated_patch) --
     repair_hunk_headers, hygiene, check_applicability, and (like S4's own
     primary path) conditional context reconstruction. This module owns
     NO local hunk-header/relocation/context-reconstruction logic of its
     own -- see that module's own docstring for why one shared mechanical
     policy owner matters.
  6. POST-SCOPE validation -- the SAME check as step 4, re-run on the
     processor's OUTPUT, proving repair/relocation did not widen or
     change the target file set (defense in depth: repair_hunk_headers's
     own contract already guarantees this by construction, but it is
     verified here, never merely assumed).
  7. Deterministic, fence-safe composition with the untouched production
     patch (see _compose_amended_patch) -- markdown-fence stripping reuses
     diff_hunk_repair.strip_markdown_fences, never a bespoke parser here.
  8. An explicit semantic_delta equality check (see
     _production_patch_semantic_delta_preserved) proving the production
     patch's own hunks are byte-for-byte semantically unchanged by
     composition -- the only permitted difference between the original,
     standalone production patch and its "production part" inside the
     combined patch is the removal of a surrounding markdown fence.
  9. A final check_applicability(combined_patch, repo_root) -- the sole
     acceptance gate. Hygiene findings from step 5 are recorded on
     AmendmentOutcome purely for observability; they never reject an
     amendment on their own (see AmendmentOutcome.hygiene_findings).

Every failure mode collapses to the SAME outcome: no amendment, the
original candidate patch is returned byte-for-byte untouched, and the
caller keeps R1. This module never raises for a decision it cannot
confidently make -- see AmendmentOutcome.status.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .diff_parsing import parse_diff, semantic_delta
from .existing_test_regression import (
    STATUS_NEW_FAILURES_DETECTED,
    STATUS_PASS,
    STATUS_PRE_EXISTING_FAILURES_ONLY,
    ExistingTestComparisonResult,
    evaluate_existing_test_comparison_with_plan,
)
from .patch_applicability import check_applicability
from .test_executors import DEFAULT_RUN_TIMEOUT, DEFAULT_SETUP_TIMEOUT

_PROMPT_PATH = Path(__file__).parent / "prompts" / "existing_test_amendment.md"

_AMENDMENT_LLM_TAG = "existing_test_amendment"

# Bounded, like every other LLM-input cap in this pipeline (see
# existing_test_regression._DISTILLATION_INPUT_CAP) -- a per-file cap on
# how much of a grounded test file's source is sent to the LLM. Existing
# test files are ordinarily small; a pathological file is truncated
# (never rejected outright -- the LLM is instructed to fail closed to
# NO_AMENDMENT_JUSTIFIED itself when it cannot see enough of the file to
# be sure).
_MAX_SOURCE_CHARS_PER_FILE = 20_000

_FENCE_RE = re.compile(r"^```[a-zA-Z]*\n|\n```\s*$")

_STATUS_NOT_ATTEMPTED = "not_attempted"
_STATUS_NO_AMENDMENT_JUSTIFIED = "no_amendment_justified"
_STATUS_UNRESOLVED = "unresolved"
_STATUS_REJECTED_INVALID_SCOPE = "rejected_invalid_scope"
_STATUS_REJECTED_INAPPLICABLE = "rejected_inapplicable"
_STATUS_AMENDED = "amended"


@dataclass
class AmendmentOutcome:
    """The result of one attempt_existing_test_amendment() call.

    ``status``:
      not_attempted           -- a necessary precondition was missing (no
                                  security invariant, nothing groundable,
                                  etc.); no LLM call was made.
      no_amendment_justified  -- the LLM call ran and explicitly declined
                                  (no direct contradiction established, or
                                  the fix would require touching more than
                                  the grounded test file(s)).
      unresolved              -- the LLM call itself failed, or its
                                  response was malformed/ambiguous; treated
                                  identically to no_amendment_justified by
                                  every caller, kept separate only for
                                  observability.
      rejected_invalid_scope  -- the LLM said AMENDMENT_JUSTIFIED and
                                  returned a diff, but it failed the
                                  deterministic scope/disjointness check.
      rejected_inapplicable   -- scope was valid, but the concatenated
                                  (original + amendment) patch did not
                                  apply cleanly.
      amended                 -- every check passed; ``amended_patch`` is
                                  the original patch with the grounded
                                  test-file diff appended, verified
                                  applicable.

    Only ``amended`` carries a non-None ``amended_patch``. The caller
    (pipeline.py) is responsible for re-running S11 against it and for the
    accept/reject decision based on THAT rerun's result -- this dataclass
    only reports whether a candidate amendment was produced, never whether
    it actually fixed anything.

    ``hygiene_findings``: whatever generated_patch_processing.
    process_generated_patch's own check_patch pass found in the amendment
    diff -- OBSERVABILITY ONLY. This module has no hygiene-based
    rejection policy of its own and must never invent one: mechanical
    applicability remains the sole acceptance gate. Empty whenever the
    LLM call never reached the shared processor (every status before
    scope validation passes).
    """
    status: str
    reason: str = ""
    amended_patch: "str | None" = None
    grounded_files: "tuple[str, ...]" = ()
    ungrounded_ids: "tuple[str, ...]" = ()
    hygiene_findings: tuple = ()


def _ground_node_id_to_file(node_id: str, repo_root: Path) -> "str | None":
    """Deterministically resolve ONE pytest-style node id's file prefix
    (the part before the first '::') to an existing repository-relative
    file under repo_root. Returns the repo-relative, forward-slash path on
    success; None if the id has no '::' at all (not this one recognized
    shape -- never guessed at for any other identifier convention, see
    module docstring), the resulting path would escape repo_root (path
    traversal), or the resolved path is not an existing file.

    This is the SAME node-id convention existing_test_regression.py's own
    runner-summary extraction already relies on (see
    _pytest_node_id_from_summary_line) -- not a new assumption about test
    identifier shapes, a reuse of an already-accepted one."""
    if not isinstance(node_id, str) or "::" not in node_id:
        return None
    rel_path = node_id.split("::", 1)[0].strip()
    if not rel_path or rel_path.startswith(("/", "\\")):
        return None
    if ".." in Path(rel_path).parts:
        return None
    root = Path(repo_root).resolve()
    candidate = (root / rel_path)
    try:
        candidate = candidate.resolve()
        candidate.relative_to(root)
    except (OSError, ValueError):
        return None
    if not candidate.is_file():
        return None
    return rel_path.replace("\\", "/")


def ground_newly_failing_tests(
    newly_failing_tests: "list[str]", repo_root: "Path | str",
) -> "tuple[dict[str, str], list[str]]":
    """Ground every entry in `newly_failing_tests` to an existing
    repository file, deterministically. Returns (grounded, ungrounded):
    ``grounded`` maps node id -> repo-relative file path for every id that
    resolved; ``ungrounded`` lists every id that did not (never silently
    dropped -- callers must treat an ungrounded id as still-failing
    evidence the rerun will surface if it isn't otherwise addressed)."""
    root = Path(repo_root)
    grounded: "dict[str, str]" = {}
    ungrounded: "list[str]" = []
    for node_id in newly_failing_tests:
        file_path = _ground_node_id_to_file(node_id, root)
        if file_path is None:
            ungrounded.append(node_id)
        else:
            grounded[node_id] = file_path
    return grounded, ungrounded


def _read_source_capped(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    if len(text) > _MAX_SOURCE_CHARS_PER_FILE:
        text = text[:_MAX_SOURCE_CHARS_PER_FILE] + "\n[... truncated ...]\n"
    return text


def _build_amendment_prompt(
    patch: str, security_invariant: str, grounded: "dict[str, str]",
    failure_diagnostics: "dict[str, str] | None", repo_root: Path,
) -> str:
    diagnostics = failure_diagnostics or {}
    parts = [
        "## Production patch (context only -- never modify or reproduce this)\n\n",
        patch.strip() + "\n\n",
        "## Stated security invariant / remediation intent\n\n",
        (security_invariant.strip() or "(none provided)") + "\n\n",
        "## Newly-failing test(s) with grounded source\n\n",
    ]
    seen_files: "set[str]" = set()
    for node_id, file_path in grounded.items():
        parts.append(f"### Test id: {node_id}\n")
        parts.append(f"File: {file_path}\n")
        diag = diagnostics.get(node_id)
        if diag:
            parts.append(f"Captured failure diagnostic (additive evidence only): {diag}\n")
        if file_path not in seen_files:
            seen_files.add(file_path)
            source = _read_source_capped(Path(repo_root) / file_path)
            parts.append(f"\n```\n{source}\n```\n\n")
        else:
            parts.append("(source already shown above for another test id in this same file)\n\n")
    return "".join(parts)


def _parse_amendment_response(raw: "str | None") -> "tuple[str, str, str | None]":
    """Strict, deterministic parse of the amendment LLM's JSON response.
    Returns (decision, reason, diff) where decision is always one of
    "AMENDMENT_JUSTIFIED" / "NO_AMENDMENT_JUSTIFIED" / "unresolved" (the
    last one meaning the response itself could not be trusted at all --
    never raises, never invents a diff)."""
    try:
        text = (raw or "").strip()
        text = _FENCE_RE.sub("", text)
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return "unresolved", "amendment response was not valid JSON", None
    if not isinstance(data, dict):
        return "unresolved", "amendment response JSON was not an object", None

    decision = data.get("decision")
    reason = data.get("reason")
    reason = reason.strip() if isinstance(reason, str) else ""

    if decision not in ("AMENDMENT_JUSTIFIED", "NO_AMENDMENT_JUSTIFIED"):
        return "unresolved", reason or "amendment response had an unrecognized decision", None

    if decision == "NO_AMENDMENT_JUSTIFIED":
        return decision, reason or "no direct contradiction was established", None

    diff = data.get("diff")
    if not isinstance(diff, str) or not diff.strip():
        return "unresolved", "amendment response declared AMENDMENT_JUSTIFIED but supplied no diff", None
    # .strip() trims incidental outer whitespace/blank lines, but a well-
    # formed unified diff's own last body line must still end in "\n" --
    # stripping it away entirely corrupts downstream line-based processing
    # (diff_hunk_repair.reconstruct_hunk_context splices new context lines
    # onto what it assumes is already a complete, newline-terminated last
    # line; without the "\n" this produces a malformed merged line). One
    # canonical trailing newline is restored unconditionally here, exactly
    # like check_applicability's own raw_diff-completion already does for
    # the whole-string case -- never ambiguous about "how many blank lines
    # were there before", always exactly one.
    return decision, reason, diff.strip() + "\n"


def _is_safe_repo_relative_path(path: str) -> bool:
    """No absolute path, no path-traversal component, no out-of-repo
    target -- the exact same shape-safety rule _ground_node_id_to_file
    already applies to a node id's own file prefix, applied here to a
    diff's OWN claimed file path(s). Checked independently of (not merely
    implied by) the grounded_files subset check in
    _validate_amendment_diff below, so an unsafe path shape is always
    caught explicitly, even if some future change ever populated
    grounded_files less strictly."""
    if not path or path.startswith(("/", "\\")):
        return False
    if ".." in Path(path).parts:
        return False
    return True


def _validate_amendment_diff(
    diff: str, original_patch_files: "set[str]", grounded_files: "set[str]",
) -> "str | None":
    """Deterministic scope check -- see module docstring's PRE-SCOPE/
    POST-SCOPE steps. Called TWICE by attempt_existing_test_amendment:
    once on the LLM's raw diff, before any repository-aware repair/
    relocation ever runs, and once more on generated_patch_processing.
    process_generated_patch's OUTPUT, to prove repair did not widen or
    change the target file set. Returns None when `diff` is acceptable;
    otherwise a short, human-readable rejection reason. Never repairs,
    never asks for a retry -- the caller treats any non-None return as a
    terminal rejection for this one bounded attempt."""
    try:
        amendment_files, _ = parse_diff(diff)
    except Exception as exc:  # noqa: BLE001 -- an unparseable diff is a rejection, not a crash
        return f"amendment diff could not be parsed: {type(exc).__name__}"
    if not amendment_files:
        return "amendment diff touched no recognizable files"
    unsafe = [f for f in amendment_files if not _is_safe_repo_relative_path(f)]
    if unsafe:
        return f"amendment diff claimed unsafe/non-repository-relative path(s): {unsafe}"
    amendment_file_set = set(amendment_files)
    if not amendment_file_set.issubset(grounded_files):
        extra = sorted(amendment_file_set - grounded_files)
        return f"amendment diff touched file(s) outside the grounded newly-failing test file(s): {extra}"
    overlap = amendment_file_set & original_patch_files
    if overlap:
        return f"amendment diff touched file(s) already present in the production patch: {sorted(overlap)}"
    return None


def _production_patch_semantic_delta_preserved(
    original_patch: str, combined_patch: str, original_patch_files: "set[str]",
) -> bool:
    """The 'production patch untouched' invariant, precisely stated:
    composition necessarily strips the production patch's own surrounding
    markdown fence (see _compose_amended_patch), so the invariant is NOT
    byte-for-byte equality of the whole string -- it is that every
    production file's own semantic_delta (its exact, ordered sequence of
    added/removed lines -- diff_parsing.semantic_delta) inside the
    combined patch is IDENTICAL to what it was in the original, standalone
    production patch. Removing only a surrounding fence is the one
    allowed difference. A mismatch here would mean the production hunks
    were somehow regenerated, relocated, repaired, or otherwise
    semantically altered by this path -- which must never happen -- so
    this is verified explicitly, never merely assumed from how
    composition happens to be implemented today."""
    try:
        from .diff_hunk_repair import strip_markdown_fences
        original_delta = semantic_delta(strip_markdown_fences(original_patch))
        combined_delta = semantic_delta(combined_patch)
    except Exception:  # noqa: BLE001 -- cannot prove preservation -> treat as NOT preserved, fail closed
        return False
    return all(combined_delta.get(f) == original_delta.get(f) for f in original_patch_files)


def _compose_amended_patch(production_patch: str, amendment_diff: str) -> str:
    """Deterministic, fence-safe composition -- the ONLY place this
    module concatenates two diff fragments. Reuses diff_hunk_repair.
    strip_markdown_fences (no bespoke markdown parsing here) on BOTH
    sides: the production patch is always fence-wrapped in production
    (see patch_generator.classify_patch_response's "valid" branch), and
    the amendment diff may or may not be, depending on whether
    generated_patch_processing.process_generated_patch's own
    repair_hunk_headers pass round-tripped an incidental fence. Stripping
    both unconditionally (a no-op for an already-fence-free string) is
    what prevents a stray fence marker from ending up embedded in the
    MIDDLE of the combined text -- the exact real defect this function
    exists to prevent (neither check_applicability's nor
    diff_hunk_repair's own fence-stripping looks past the first/last line
    of the string each is given, so a fence buried mid-string, from naive
    string concatenation, was previously invisible to both)."""
    from .diff_hunk_repair import strip_markdown_fences
    production_body = strip_markdown_fences(production_patch)
    amendment_body = strip_markdown_fences(amendment_diff)
    return production_body.rstrip("\n") + "\n" + amendment_body.strip("\n") + "\n"


def attempt_existing_test_amendment(
    *, repo_root: "Path | str", patch: str, newly_failing_tests: "list[str]",
    security_invariant: "str | None", failure_diagnostics: "dict[str, str] | None" = None,
    llm: object,
) -> AmendmentOutcome:
    """The single entry point. Callers (pipeline.py) must have already
    established that S11's first comparison (R1) concluded
    NEW_FAILURES_DETECTED with a non-empty, deterministic
    `newly_failing_tests`; this function performs every remaining gate
    itself and never raises.

    `failure_diagnostics` is OPTIONAL, additive evidence only (e.g.
    TestRunResult.failure_diagnostics, when a structured JUnit/TAP parse
    happened to capture it) -- its absence must never by itself block an
    otherwise-justified amendment; see the real urllib3 case this feature
    was built from, where deterministic per-test IDs were available but
    failure_diagnostics was null.

    Never mutates `repo_root` or `patch`. Makes at most ONE LLM call."""
    repo_root = Path(repo_root)

    security_invariant = (security_invariant or "").strip()
    if not security_invariant:
        return AmendmentOutcome(
            status=_STATUS_NOT_ATTEMPTED,
            reason="no stated security invariant / remediation intent is available to ground a conflict judgment against",
        )
    if not newly_failing_tests:
        return AmendmentOutcome(status=_STATUS_NOT_ATTEMPTED, reason="no newly-failing tests to consider")

    grounded, ungrounded = ground_newly_failing_tests(newly_failing_tests, repo_root)
    if not grounded:
        return AmendmentOutcome(
            status=_STATUS_NOT_ATTEMPTED,
            reason="no newly-failing test id could be grounded to an existing repository file",
            ungrounded_ids=tuple(ungrounded),
        )

    try:
        original_patch_files, _ = parse_diff(patch)
    except Exception as exc:  # noqa: BLE001
        return AmendmentOutcome(
            status=_STATUS_NOT_ATTEMPTED,
            reason=f"could not parse the production patch to establish its own file set: {type(exc).__name__}",
        )

    user_message = _build_amendment_prompt(patch, security_invariant, grounded, failure_diagnostics, repo_root)
    try:
        system_prompt = _PROMPT_PATH.read_text(encoding="utf-8")
        raw = llm.complete(system_prompt, user_message, stage=_AMENDMENT_LLM_TAG)
    except Exception as exc:  # noqa: BLE001 -- an LLM-layer failure degrades to unresolved, never crashes the pipeline
        return AmendmentOutcome(
            status=_STATUS_UNRESOLVED, reason=f"amendment LLM call failed: {type(exc).__name__}",
            grounded_files=tuple(sorted(set(grounded.values()))), ungrounded_ids=tuple(ungrounded),
        )

    decision, reason, diff = _parse_amendment_response(raw)
    grounded_file_set = set(grounded.values())
    if decision != "AMENDMENT_JUSTIFIED":
        status = _STATUS_NO_AMENDMENT_JUSTIFIED if decision == "NO_AMENDMENT_JUSTIFIED" else _STATUS_UNRESOLVED
        return AmendmentOutcome(
            status=status, reason=reason,
            grounded_files=tuple(sorted(grounded_file_set)), ungrounded_ids=tuple(ungrounded),
        )

    original_patch_file_set = set(original_patch_files)

    # PRE-SCOPE VALIDATION -- on the LLM's RAW diff, before any
    # repository-aware repair/relocation ever runs (see module docstring).
    pre_scope_error = _validate_amendment_diff(diff, original_patch_file_set, grounded_file_set)
    if pre_scope_error is not None:
        return AmendmentOutcome(
            status=_STATUS_REJECTED_INVALID_SCOPE, reason=f"pre-repair scope check failed: {pre_scope_error}",
            grounded_files=tuple(sorted(grounded_file_set)), ungrounded_ids=tuple(ungrounded),
        )

    # Shared generated-diff mechanics -- the SAME primitive S4/S6 use for
    # their own LLM-generated diffs (see generated_patch_processing.py's
    # module docstring). allow_context_reconstruction=True: like S4's own
    # primary generation path, a test-file amendment benefits from this --
    # the LLM was given the exact current source, so any context-thinness
    # is more likely a formatting quirk than a semantic problem.
    from .generated_patch_processing import process_generated_patch
    processed = process_generated_patch(diff, repo_root, allow_context_reconstruction=True)
    diff = processed.patch
    hygiene_findings = tuple(processed.hygiene_findings)

    # POST-SCOPE VALIDATION -- the SAME check, re-run on the processor's
    # OUTPUT, proving repair/relocation did not widen or change the
    # target set. repair_hunk_headers's own contract already guarantees
    # this by construction (see its module docstring); verified here
    # regardless, never merely assumed.
    post_scope_error = _validate_amendment_diff(diff, original_patch_file_set, grounded_file_set)
    if post_scope_error is not None:
        return AmendmentOutcome(
            status=_STATUS_REJECTED_INVALID_SCOPE, reason=f"post-repair scope check failed: {post_scope_error}",
            grounded_files=tuple(sorted(grounded_file_set)), ungrounded_ids=tuple(ungrounded),
            hygiene_findings=hygiene_findings,
        )

    # The amendment must stand on its own before composition is even
    # attempted -- it targets a file the production patch never touches,
    # so its own applicability can never depend on the production patch.
    if processed.applicability_result.get("applicable") is not True:
        return AmendmentOutcome(
            status=_STATUS_REJECTED_INAPPLICABLE,
            reason=(
                "amendment diff did not apply cleanly on its own, even after shared repair/context "
                f"reconstruction: {processed.applicability_result.get('stderr') or processed.applicability_result.get('error') or 'unknown error'}"
            ),
            grounded_files=tuple(sorted(grounded_file_set)), ungrounded_ids=tuple(ungrounded),
            hygiene_findings=hygiene_findings,
        )

    # Deterministic, fence-safe composition (see _compose_amended_patch) --
    # never regenerates, relocates, repairs, or otherwise touches the
    # production patch's own hunks.
    combined_patch = _compose_amended_patch(patch, diff)

    if not _production_patch_semantic_delta_preserved(patch, combined_patch, original_patch_file_set):
        return AmendmentOutcome(
            status=_STATUS_REJECTED_INVALID_SCOPE,
            reason="composition would have altered the production patch's own semantic content -- rejected",
            grounded_files=tuple(sorted(grounded_file_set)), ungrounded_ids=tuple(ungrounded),
            hygiene_findings=hygiene_findings,
        )

    applicability = check_applicability(combined_patch, repo_root)
    if applicability.get("applicable") is not True:
        return AmendmentOutcome(
            status=_STATUS_REJECTED_INAPPLICABLE,
            reason=f"amended patch did not apply cleanly: {applicability.get('stderr') or applicability.get('error') or 'unknown error'}",
            grounded_files=tuple(sorted(grounded_file_set)), ungrounded_ids=tuple(ungrounded),
            hygiene_findings=hygiene_findings,
        )

    return AmendmentOutcome(
        status=_STATUS_AMENDED, reason=reason, amended_patch=combined_patch,
        grounded_files=tuple(sorted(grounded_file_set)), ungrounded_ids=tuple(ungrounded),
        hygiene_findings=hygiene_findings,
    )


# ---------------------------------------------------------------------------
# Rerun orchestration -- the ONE shared executor both pipeline.py (production)
# and replay_engine.py (Stage 11 replay) call, so both share exactly the same
# bounded-loop implementation. This is the ONLY place S11's pure comparator
# (evaluate_existing_test_comparison_with_plan) is ever called more than
# once for a single candidate -- that function itself is never modified or
# given awareness of amendment; it is called, unchanged, up to twice.
# ---------------------------------------------------------------------------

@dataclass
class AmendmentRerunOutcome:
    """The full outcome of one bounded existing-test-amendment cycle.

    ``result`` is the CANONICAL ExistingTestComparisonResult callers must
    treat as ground truth: R2 (the rerun) when an amendment was accepted,
    R1 (the original, untouched comparison) otherwise -- exactly one of
    the two, never a merge of both.

    ``patch`` is the authoritative candidate callers must use downstream:
    the amended patch when accepted, the original `patch` argument
    otherwise (returned byte-for-byte unchanged -- see
    _validate_amendment_diff/attempt_existing_test_amendment).

    ``amendment`` is always present (status "not_attempted" covers every
    case where the gate never reached the LLM call at all -- see
    attempt_existing_test_amendment) -- observability, never re-derived
    by callers.

    ``pre_amendment_result`` is R1, populated only when an amendment was
    actually attempted (whether or not it was ultimately accepted) -- lets
    a caller show what changed without re-running anything."""
    result: ExistingTestComparisonResult
    patch: str
    amendment: AmendmentOutcome
    accepted: bool
    pre_amendment_result: "ExistingTestComparisonResult | None" = None


def evaluate_existing_test_comparison_with_amendment(
    repo_root: "Path | str", patch: str, plan, *,
    security_invariant: "str | None",
    setup_timeout: int = DEFAULT_SETUP_TIMEOUT, run_timeout: int = DEFAULT_RUN_TIMEOUT,
    executor: object = None, llm: object = None,
) -> AmendmentRerunOutcome:
    """Run S11's existing comparator once (R1); if, and only if, it
    reports NEW_FAILURES_DETECTED with a non-empty, deterministic
    `newly_failing_tests`, attempt EXACTLY ONE bounded Existing Test
    Amendment (see attempt_existing_test_amendment); if an amendment is
    produced, run the SAME comparator a second time (R2) against the
    amended patch, using the SAME plan/executor. Accepts the amendment
    (`accepted=True`, `result=R2`, `patch=amended`) only when R2 is PASS
    or PRE_EXISTING_FAILURES_ONLY -- any remaining or new
    `newly_failing_tests` in R2 rejects the amendment outright and
    restores the original, untouched `patch`/R1. No iteration: at most two
    calls to the comparator, at most one LLM amendment call, ever, per
    invocation of this function.

    `llm=None` (matching evaluate_existing_test_comparison_with_plan's own
    convention): the amendment step is never attempted -- there is no
    provider to make its one bounded call with -- exactly as distillation
    already treats `llm=None` as "never attempted", not as an error.

    Rerun cost, by deliberate minimal-risk design choice (not yet
    optimized): R2 reruns evaluate_existing_test_comparison_with_plan()
    UNCHANGED, including its own baseline execution -- the baseline is
    identical to R1's (the amendment never touches production files), so
    this repeats one Docker run that a future optimization could instead
    cache/reuse from R1. Deliberately not done in this first
    implementation to avoid a second, riskier refactor (threading a
    precomputed baseline through evaluate_existing_test_comparison_with_
    plan's contract) alongside this feature's own new risk surface."""
    r1 = evaluate_existing_test_comparison_with_plan(
        repo_root, patch, plan, setup_timeout=setup_timeout, run_timeout=run_timeout,
        executor=executor, llm=llm,
    )
    if r1.status != STATUS_NEW_FAILURES_DETECTED or not r1.newly_failing_tests:
        return AmendmentRerunOutcome(
            result=r1, patch=patch, accepted=False,
            amendment=AmendmentOutcome(
                status=_STATUS_NOT_ATTEMPTED,
                reason="S11 comparison did not report deterministic newly-failing test identity",
            ),
        )
    if llm is None:
        return AmendmentRerunOutcome(
            result=r1, patch=patch, accepted=False,
            amendment=AmendmentOutcome(status=_STATUS_NOT_ATTEMPTED, reason="no LLM provider was given"),
        )

    failure_diagnostics = (r1.patched.failure_diagnostics or None) if r1.patched is not None else None
    amendment = attempt_existing_test_amendment(
        repo_root=repo_root, patch=patch, newly_failing_tests=r1.newly_failing_tests,
        security_invariant=security_invariant, failure_diagnostics=failure_diagnostics, llm=llm,
    )
    if amendment.status != _STATUS_AMENDED:
        return AmendmentRerunOutcome(result=r1, patch=patch, accepted=False, amendment=amendment, pre_amendment_result=r1)

    r2 = evaluate_existing_test_comparison_with_plan(
        repo_root, amendment.amended_patch, plan, setup_timeout=setup_timeout, run_timeout=run_timeout,
        executor=executor, llm=llm,
    )
    if r2.status in (STATUS_PASS, STATUS_PRE_EXISTING_FAILURES_ONLY):
        return AmendmentRerunOutcome(
            result=r2, patch=amendment.amended_patch, accepted=True, amendment=amendment, pre_amendment_result=r1,
        )
    # Rejected: R2 still shows a newly-failing test (the amendment didn't
    # fix it, or introduced/left a different one) -- restore the original,
    # untouched patch and keep R1 as canonical. Exactly one attempt; no
    # retry, no second amendment call.
    return AmendmentRerunOutcome(result=r1, patch=patch, accepted=False, amendment=amendment, pre_amendment_result=r1)
