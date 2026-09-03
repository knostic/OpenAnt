"""Generic, deterministic post-processing for an already-generated unified
diff -- the ONE shared mechanical pipeline every LLM-generated diff in
Auto Patcher passes through, regardless of WHY it was generated.

Extracted from three previously independent, copy-pasted call sites in
pipeline.py (S4's primary/final settle path, S4's applicability-aware
retry, and S6's Challenger-driven repair loop) plus S11's Existing Test
Amendment path -- all four called the identical
``repair_hunk_headers -> check_patch -> check_applicability`` triplet
(optionally followed by ``reconstruct_hunk_context`` + a re-check), in the
same order, each independently fail-soft. This module is that one policy
owner: it decides HOW an LLM-generated diff is mechanically normalized,
repaired, linted, and applicability-checked -- never WHY a diff was
generated, never WHETHER its content is a good fix, never anything
vulnerability/remediation/test-semantic.

Deliberately excluded (stays with each caller, never migrated here):
  - vulnerability-text regeneration / contract-violation retry (S4)
  - Edit Readiness / Patch Target Conformance / Post-Patch Recovery (S4) --
    this needs a RepairResult BEFORE its own conformance gate decides
    whether to accept a regenerated patch at all, a sequencing this
    module's single bundled call cannot express without absorbing that
    gate's own semantics; see pipeline.py's Post-Patch-Recovery block,
    which continues to call diff_hunk_repair.repair_hunk_headers directly.
  - Challenger re-challenge / finding calibration (S6)
  - Existing Test Amendment's own scope/disjointness gate and LLM
    judgment (S11) -- this module has no concept of "grounded test
    files" or "production patch", only "a diff and a repo_root".

No I/O, no printing: this module is a pure function over (patch, repo_root)
-> ProcessedPatch. Every caller keeps making its OWN diagnostic prints from
the returned fields, exactly as each already did before this extraction --
this module changes WHERE the mechanics live, never what gets printed or
when.
"""

from __future__ import annotations

from dataclasses import dataclass

# diff_hunk_repair.RepairResult/ContextExpansionResult (plain dataclasses)
# and repair_hunk_headers itself are never mocked anywhere in this
# codebase's tests -- safe to import at module level. check_applicability/
# check_patch/reconstruct_hunk_context are each imported LAZILY, inside
# process_generated_patch() itself, NOT here: every existing test suite in
# this codebase mocks them via
# mock.patch("utilities.autopatcher.<module>.<function>", ...) -- string-
# based patching of the ATTRIBUTE on their OWNING module. A module-level
# `from .patch_applicability import check_applicability` here would bind a
# SEPARATE name in THIS module's namespace that such a mock never touches
# (see diff_hunk_repair.py's own module docstring, which documents this
# exact hazard for the same function). Importing lazily guarantees a fresh,
# correctly-mockable lookup on every call, exactly like every other consumer
# of these functions already does.
from .diff_hunk_repair import ContextExpansionResult, RepairResult, repair_hunk_headers


@dataclass
class ProcessedPatch:
    """The result of running one already-generated diff through the shared
    mechanical pipeline. Every field mirrors what a caller already computed
    inline before this extraction -- nothing new is invented.

    ``hygiene_findings`` is returned for the caller's own observability/
    reporting use ONLY -- this module never rejects or alters `patch`
    based on hygiene findings, and no caller may newly start doing so
    based on this module's existence (see existing_test_amendment.py's
    own docstring on this point). Mechanical applicability remains the
    sole acceptance gate for every caller.

    ``context_expansion`` is None whenever context reconstruction was
    disabled (`allow_context_reconstruction=False`) or never attempted
    (the patch was already applicable, or reconstruction wasn't
    requested) -- never a fabricated "not attempted" sentinel distinct
    from "genuinely didn't run".
    """
    patch: str
    repair_result: RepairResult
    hygiene_findings: list
    applicability_result: dict
    context_expansion: "ContextExpansionResult | None" = None


def process_generated_patch(
    raw_patch: str, repo_root: "object | None", *, allow_context_reconstruction: bool = True,
) -> ProcessedPatch:
    """Run `raw_patch` through the shared mechanical pipeline:

        repair_hunk_headers
        check_patch (hygiene)
        check_applicability
        [if still inapplicable and allow_context_reconstruction and repo_root:
            reconstruct_hunk_context, then re-check_applicability]

    Every step already fails soft on its own (repair_hunk_headers and
    check_patch never raise by their own contract; check_applicability
    degrades to a skipped/{"applicable": None, ...} dict on any
    unexpected condition) -- this function adds one more layer of
    defensive try/except around each step purely to match every existing
    call site's own belt-and-suspenders style, never because any of these
    functions are actually expected to raise.

    Idempotent by construction: calling this a second time on an
    already-repaired, already-applicable patch is a safe no-op (repair_
    hunk_headers recomputes identical values from identical body content;
    the fixed point is reached in one pass) -- this is what lets S4's
    final settle path reuse this same function even though, in current
    production code, the patch it hands in may already have been repaired
    once upstream (by S4's own first-pass repair or by Post-Patch
    Recovery's regeneration-time repair, neither of which this function
    replaces or duplicates -- see module docstring)."""
    try:
        patch, repair_result = repair_hunk_headers(raw_patch, repo_root=repo_root)
    except Exception:  # noqa: BLE001 -- repair_hunk_headers already fails soft; this is defensive only
        patch, repair_result = raw_patch, RepairResult()

    try:
        from .patch_hygiene import check_patch
        hygiene_findings = check_patch(patch)
    except Exception:  # noqa: BLE001
        hygiene_findings = []

    try:
        from .patch_applicability import check_applicability
        applicability_result = check_applicability(patch, repo_root)
    except Exception:  # noqa: BLE001
        applicability_result = {
            "applicable": None, "skipped": False, "skipped_reason": None,
            "error": "applicability check failed unexpectedly",
            "exit_code": None, "stderr": "",
        }

    context_expansion = None
    if allow_context_reconstruction and applicability_result.get("applicable") is False and repo_root:
        try:
            from .diff_hunk_repair import reconstruct_hunk_context
            from .patch_applicability import check_applicability as _check_applicability_for_expansion
            reconstructed_patch, context_expansion = reconstruct_hunk_context(patch, repo_root)
            if context_expansion.succeeded:
                patch = reconstructed_patch
                applicability_result = _check_applicability_for_expansion(patch, repo_root)
        except Exception:  # noqa: BLE001
            context_expansion = None

    return ProcessedPatch(
        patch=patch, repair_result=repair_result, hygiene_findings=hygiene_findings,
        applicability_result=applicability_result, context_expansion=context_expansion,
    )
