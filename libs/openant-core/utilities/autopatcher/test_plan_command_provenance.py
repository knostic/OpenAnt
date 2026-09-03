"""Evidence-backed repository-owned command provenance for Test Plan
Discovery's deterministic validation boundary.

Real GitPython (CVE-2026-44243) regression-suite finding: the LLM
produced a valid, well-evidenced plan whose setup_commands included
``./init-tests-after-clone.sh`` -- a real script GitPython's own CI
directly invokes to prepare the repository for tests, exactly the kind
of repository-owned entry point test_plan_discovery.py's own
_SYSTEM_PROMPT already tells the model to preserve (see its "PRESERVE
REPOSITORY-OWNED ENTRY POINTS" rule, which explicitly names "a
repository test script (e.g. ./scripts/test.sh)" as a valid example).
test_plan_validation.ALLOWED_COMMAND_BINARIES rejected it outright as an
"unrecognized binary" -- it is a small, fixed, reviewed set of EXTERNAL
tool names and structurally has no notion of "the repository's own file,
trusted because the repository's own evidence says so."

This module is that second, narrower trust path -- NOT a static
allowlist entry (the next differently-named repository script would hit
the identical wall) and NOT a "the filename/path contains test"
heuristic (a repository controls its own filenames; that is not a
meaningful security boundary; see the module's own adversarial test
coverage for a script that is named like a test script but never
evidenced). A repository-relative command token is trusted for exactly
ONE discover_test_plan() call, never globally, when it passes BOTH of
two independent, mandatory checks:

  (a) FILESYSTEM SAFETY: it is a real, contained, regular file strictly
      inside repo_root (see _resolve_contained_file) -- symlink escapes,
      traversal, absolute paths, and nonexistent targets are all
      rejected here.
  (b) COMMAND-LEVEL EVIDENCE PROVENANCE: the literal path string was
      actually present in the CONTENT the model was shown -- not merely
      "some evidenced file exists," and not merely "the model cited a
      real filename in its evidence list" (see _content_evidence_text
      and the module docstring's own file-level-vs-command-level
      distinction). Existence in the repository's bare directory
      listing or lockfile-name list is deliberately NOT sufficient
      grounding -- those only prove existence, never test-workflow
      intent; only present_config_files/ci_snippets/readme_excerpt
      content counts.

Neither check alone is sufficient: evidence TEXT alone is trivially
gameable (a README could "evidence" any arbitrary string by naming it
in prose); the filesystem check anchors what gets approved to a real
file that is already part of the exact same repository checkout already
being fed into the same Docker sandbox (see test_executors.py's own
security model) -- it adds no capability beyond what every already-
allowlisted wrapper tool (npm/make/tox/pip) already grants via its own
repository-defined scripts/targets/hooks.

Deliberately scoped to repository-RELATIVE paths beginning with "./"
only -- this single requirement is what keeps a bare word (e.g.
"curl", "run-tests") from ever entering this code path at all (it falls
straight through to test_plan_validation's existing, unchanged
unrecognized-binary rejection), and what keeps absolute paths and
"../"-prefixed parent-traversal attempts out without any extra logic
(neither shape starts with "./"). Bare, non-path runner binaries (e.g.
"jest", "vitest") are a DIFFERENT, weaker trust question -- a bare word
has no independent filesystem identity to anchor a check the way a real
repository-relative file does -- and are deliberately NOT handled here;
see this module's own tests for what stays out of scope.

Consumed by test_plan_discovery.discover_test_plan only, at the one
place repo_root and the EXACT EvidenceBundle shown to the model are
both already in scope -- never by test_plan_validation.validate_plan
directly, which stays a pure, source-agnostic function of a plan's own
fields (see that module's docstring); this module instead produces a
small, precomputed set of per-call-trusted first tokens that
discover_test_plan passes into validate_plan via its
`extra_allowed_first_tokens` parameter.
"""

from __future__ import annotations

from pathlib import Path

from .test_evidence_acquisition import EvidenceBundle

_REPO_RELATIVE_PREFIX = "./"


def _looks_repo_relative(token: str) -> bool:
    return token.startswith(_REPO_RELATIVE_PREFIX)


def _content_evidence_text(evidence: EvidenceBundle) -> str:
    """Concatenates ONLY the content-bearing evidence actually shown to
    the model -- present_config_files/ci_snippets content, plus the
    readme_excerpt. Deliberately EXCLUDES directory_listing and
    present_lockfiles (bare names only prove existence, never
    test-workflow intent -- see module docstring)."""
    parts = [content for _, content in evidence.present_config_files]
    parts.extend(content for _, content in evidence.ci_snippets)
    if evidence.readme_excerpt:
        parts.append(evidence.readme_excerpt)
    return "\n".join(parts)


def _resolve_contained_file(token: str, repo_root: Path) -> "Path | str":
    """Returns the resolved Path if `token` (a "./"-prefixed relative
    reference) names a real, regular file strictly contained within
    repo_root -- or a bounded error string otherwise. Resolution follows
    symlinks (Path.resolve), so a symlink whose real target escapes
    repo_root is caught by the containment check below, not merely a
    literal ".." scan (kept anyway, as cheap defense-in-depth, before
    ever touching the filesystem)."""
    relative_part = token[len(_REPO_RELATIVE_PREFIX):]
    if not relative_part:
        return "token has no path after './'"
    if ".." in Path(relative_part).parts:
        return "token contains a '..' path segment"

    repo_root_resolved = repo_root.resolve()
    candidate = (repo_root / relative_part).resolve()

    if not candidate.is_relative_to(repo_root_resolved):
        return "resolved path escapes repo_root"
    if not candidate.exists():
        return "target does not exist"
    if not candidate.is_file():
        return "target is not a regular file"
    return candidate


def resolve_repository_owned_commands(
    commands: "tuple[tuple[str, ...], ...]", repo_root: "Path | str", evidence: EvidenceBundle,
) -> "tuple[frozenset[str], str | None]":
    """Examines the first token of every command in `commands` (each a
    setup_commands entry or the test_command). Tokens that don't start
    with "./" are left completely untouched -- they are not this
    module's concern; test_plan_validation's existing static
    ALLOWED_COMMAND_BINARIES check governs them unchanged.

    For every "./"-prefixed token, both the filesystem-safety and
    command-level-evidence-provenance checks (see module docstring) must
    pass, or the WHOLE candidate is rejected outright -- fail-closed,
    exactly like every other discover_test_plan rejection path -- with a
    specific, bounded reason. Never partially trusts a plan: any
    repository-owned token failing either check means the returned
    trusted set is discarded (empty) and a rejection reason is returned
    instead.

    Returns (trusted_first_tokens, rejection_reason). When
    rejection_reason is not None, the caller must reject the candidate
    before ever constructing a TestExecutionPlan -- exactly the same
    contract discover_test_plan's own evidence-citation check already
    follows. When rejection_reason is None, `trusted_first_tokens` is
    the exact set of literal "./"-prefixed strings that passed both
    checks in THIS call, to be passed into
    test_plan_validation.validate_plan's own
    `extra_allowed_first_tokens` parameter -- never persisted, never
    reused across a different discover_test_plan call or a different
    repository."""
    repo_root = Path(repo_root)
    content_text = _content_evidence_text(evidence)
    trusted: "set[str]" = set()

    for command in commands:
        if not command:
            continue
        token = command[0]
        if not _looks_repo_relative(token):
            continue
        if token in trusted:
            continue

        resolved = _resolve_contained_file(token, repo_root)
        if isinstance(resolved, str):
            return frozenset(), f"repository-owned command {token!r} rejected: {resolved}"

        relative_part = token[len(_REPO_RELATIVE_PREFIX):]
        if relative_part not in content_text:
            return frozenset(), (
                f"repository-owned command {token!r} is not grounded in the repository "
                "test/setup evidence actually shown (config file content, CI workflow "
                "content, or README excerpt) -- merely existing in the repository, or "
                "appearing only in the bare directory listing, is not sufficient"
            )
        trusted.add(token)

    return frozenset(trusted), None
