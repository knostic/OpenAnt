"""
Context enhancement wrapper.

Wraps utilities/context_enhancer.py, providing a path-based interface
for both agentic and single-shot enhancement modes.

Checkpoints are always enabled for agentic mode. Per-unit progress is saved
to ``{output_dir}/enhance_checkpoints/`` so interrupted runs can resume
automatically. Checkpoints are preserved alongside results (see the scanner's enhance step).
"""

import os
import sys

from core.schemas import EnhanceResult
from core import tracking
from core.progress import ProgressReporter
from utilities.rate_limiter import configure_rate_limiter
from utilities.file_io import read_json, write_json
from utilities.llm import (
    PhaseRegistry,
    build_phase_registry,
    load_config_file,
    resolve_llm_config,
)


# #739: the --limit selection order. The raw head-slice took
# ``dataset.units[:N]`` in FILE-WALK order — a limited run silently measured
# whichever files the parser visited first (the campaign's --limit 3 on
# OpenBao selected three api/auth/approle CLIENT-SDK files while the 90
# http_handler units — the server attack surface — began at index 18). The
# priority available BEFORE enhancement is the structural one: the seeded
# entry points (``is_entry_point``, stamped by the reachability filter /
# the LLM-reachability promotions) and the call-graph edges
# (``metadata.direct_calls``) — so the selection is a multi-source BFS
# from the entry points (depth 0 = the seeds, depth 1 = their direct
# callees, ...) with the ORIGINAL file-walk order as the per-depth
# tiebreak (deterministic: the same dataset + limit always selects the
# same units — the reproducibility contract a head-slice gave for free
# and a priority sort must not lose).
LIMIT_MODE_ENTRY_PATH = "entry-path-bfs"
LIMIT_MODE_FILE_ORDER = "file-order-head-slice"
# #739 fix round: a ``--limit N`` with N >= len(units) selects NOTHING --
# ``select_units_for_limit`` early-returns the units unreordered and unsliced. The
# first cut still stamped ``entry-path-bfs`` there, so the artifact claimed a
# priority selection that never ran: verbatim the failure this change exists to
# remove ("the mode is printed so a limited run never reads as a priority-based
# sample when it is not"). A third value names that state, rather than reusing the
# empty string -- empty already MEANS "no limit ran", and a non-binding limit DID
# run, so collapsing the two would lose the distinction an operator needs.
LIMIT_MODE_NOT_BINDING = "no-selection-all-units-under-limit"


def limit_selection_mode(units) -> str:
    """#739: the selection mode a --limit run used — the reportable label
    for the issue's shape-2 ask. ``entry-path-bfs`` when the dataset
    carries at least one seeded entry point (the BFS has a source);
    ``file-order-head-slice`` when it does not (the order is UNCHANGED
    file-walk order and the output must say so, never read as a
    priority-based sample)."""
    for u in units:
        if (isinstance(u, dict) and u.get("is_entry_point")
                and isinstance(u.get("id"), str) and u.get("id")):
            return LIMIT_MODE_ENTRY_PATH
    return LIMIT_MODE_FILE_ORDER


def limit_mode_for(units, limit) -> str:
    """#739 fix round: THE ONE DERIVATION of the REPORTED selection mode.

    ``limit_selection_mode`` answers a different question -- "does this dataset
    carry a BFS source?" -- and is still the predicate ``select_units_for_limit``
    branches on. What the REPORT needs is "what did the selection actually do",
    and those diverge in exactly one place: a limit that does not bind. Deriving
    the label here, from the same (units, limit) pair the selection sees, is what
    stops the stamp and the selection from disagreeing again."""
    if not limit:
        return ""
    if len(units) <= limit:
        return LIMIT_MODE_NOT_BINDING
    return limit_selection_mode(units)


def select_units_for_limit(units, limit):
    """#739: the priority-ordered selection — entry-path BFS depth first,
    original file order within a depth, then the slice.

    Units NOT reachable from any entry point sort after every reachable
    unit (they keep their relative file order). Non-dict rows (the fa15
    trust-boundary class) and rows without ids pass through in place,
    never crash the sort. A falsy ``limit`` or an empty seed set returns
    the units UNREORDERED (the #213 diff-selected population contract is
    the caller's; this function only orders)."""
    if not limit or len(units) <= limit:
        return units
    if limit_selection_mode(units) == LIMIT_MODE_FILE_ORDER:
        # no seeded entry points: nothing to BFS from — the file order
        # stands (still sliced: the limit binds), and the caller's label
        # (limit_selection_mode) says so.
        return units[:limit]

    # The depth map: multi-source BFS from every is_entry_point unit over
    # the callee edges (metadata.direct_calls). Malformed rows/edges are
    # skipped, never raised (the fa15 shape; the selection degrades to
    # file order for the row, not for the run). The id index is built
    # ONCE — the OpenBao-scale corpus (13,944 units) must not re-scan the
    # list per frontier node.
    by_id: dict = {}
    for u in units:
        if (isinstance(u, dict) and isinstance(u.get("id"), str)
                and u.get("id")):
            by_id.setdefault(u["id"], u)
    depth: dict = {}
    frontier = [u.get("id") for u in units
                if (isinstance(u, dict) and u.get("is_entry_point")
                    and isinstance(u.get("id"), str) and u.get("id"))]
    for _id in frontier:
        depth[_id] = 0
    while frontier:
        next_frontier = []
        for _id in frontier:
            meta = by_id.get(_id, {}).get("metadata")
            calls = meta.get("direct_calls") if isinstance(meta, dict) else None
            if not isinstance(calls, list):
                continue
            for callee in calls:
                if (isinstance(callee, str) and callee in by_id
                        and callee not in depth):
                    depth[callee] = depth[_id] + 1
                    next_frontier.append(callee)
        frontier = next_frontier

    # unreachable units sort last, keeping their relative order among
    # themselves; the enumerate index is the per-depth tiebreak.
    order = sorted(
        enumerate(units),
        key=lambda pair: (
            depth.get(pair[1].get("id")) if isinstance(pair[1], dict)
            and isinstance(pair[1].get("id"), str)
            and pair[1].get("id") in depth else float("inf"),
            pair[0],
        ),
    )
    selected = [u for _, u in order][:limit]
    return selected


def enhance_dataset(
    dataset_path: str,
    output_path: str,
    analyzer_output_path: str | None = None,
    repo_path: str | None = None,
    mode: str = "agentic",
    checkpoint_path: str | None = None,
    registry: PhaseRegistry | None = None,
    llm_config_name: str | None = None,
    workers: int = 8,
    backoff_seconds: int = 30,
    limit: int | None = None,
) -> EnhanceResult:
    """Enhance a parsed dataset with security context.

    Args:
        dataset_path: Path to dataset.json from the parse step.
        output_path: Path to write the enhanced dataset.
        analyzer_output_path: Path to analyzer_output.json (required for agentic mode).
        repo_path: Path to the repository (required for agentic mode).
        mode: "agentic" (thorough, tool-use) or "single-shot" (fast, cheaper).
        checkpoint_path: Path to save/resume checkpoint (both modes).
            If None, auto-derived from output_path.
        registry: Pre-built PhaseRegistry. Scanners pass theirs;
            standalone callers leave this None and a registry is
            constructed from ``llm_config_name``.
        llm_config_name: Name of the llm-config when ``registry`` is
            None. ``None`` falls through to the active config.
        workers: Number of parallel workers (default: 8).
        backoff_seconds: Seconds to wait on rate limit before retry (default: 30).
        limit: Max number of units to enhance (None = all). Mirrors `analyze --limit`.

    Returns:
        EnhanceResult with output path, stats, and usage.
    """
    # #214: snapshot cumulative usage at phase start so the "Enhance" summary
    # below reports this phase's delta, not the prior phases' total.
    # #281: MUTABLE holder — the enhance path's checkpoint-restore injects
    # prior usage into the tracker AFTER this snapshot; the injection site
    # refreshes the holder (see verifier's identical shape).
    _phase_baseline = {"usage": tracking.get_usage()}
    # Configure global rate limiter
    configure_rate_limiter(backoff_seconds=float(backoff_seconds))

    # Resolve the enhance-phase binding from the registry.
    # Standalone-invocation path validates upfront (same pattern as
    # run_analysis); scanner-driven calls trust the scanner's probe.
    if registry is None:
        from utilities.llm import probe_registry_or_raise

        cf = load_config_file()
        registry = build_phase_registry(cf, resolve_llm_config(cf, llm_config_name))
        probe_registry_or_raise(registry)
    binding = registry.get("enhance")
    print(f"[Enhance] Mode: {mode}", file=sys.stderr)
    print(f"[Enhance] Provider: {binding.provider_name}, Model: {binding.model}", file=sys.stderr)

    # Auto-derive checkpoint path for BOTH modes so single-shot also resumes
    # after an interrupt / cost-cap instead of reprocessing every unit
    # Single-shot is the cheap, high-volume mode, so wasted
    # re-enhancement there is the most costly to lose.
    if checkpoint_path is None:
        output_dir = os.path.dirname(os.path.abspath(output_path))
        checkpoint_path = os.path.join(output_dir, "enhance_checkpoints")

    # Import here to avoid heavy imports at module load
    from utilities.llm_client import get_global_tracker
    from utilities.context_enhancer import ContextEnhancer

    tracker = get_global_tracker()
    enhancer = ContextEnhancer(binding=binding, tracker=tracker)

    # Load dataset
    print(f"[Enhance] Loading dataset: {dataset_path}", file=sys.stderr)
    dataset = read_json(dataset_path)
    units = dataset.get("units", [])
    # #213: apply --limit to the INTENDED population, not the raw head. When
    # diff-mode annotated the dataset (diff_selected markers), analyze's own
    # order is filter-then-limit (analyzer.py:523-557); a raw head-slice here
    # would slice ALPHABETICALLY first and silently drop diff-selected units
    # outside the head — the run would enhance/analyze ~0 units and exit
    # clean (a false-coverage regression glm-5.3 caught in review). Match
    # analyze's population semantics EXACTLY, including its key-presence
    # predicate (analyzer.py:523): a diff that selected ZERO units still
    # counts as annotated — filtering to 0 beats spending the limit on
    # unrelated units (sonnet confirm-round catch).
    if any("diff_selected" in u for u in units if isinstance(u, dict)):
        units = [u for u in units if isinstance(u, dict) and u.get("diff_selected")]
    # #739: the selection mode a --limit run used, stamped over the
    # population the slice ACTUALLY selected from (the #213 diff-selected
    # subset when diff-mode annotated the dataset — the label must never
    # describe the unfiltered corpus; the T1-r1 F1 catch). Threaded to the
    # EnhanceResult below.
    _limit_mode = ""
    if limit:
        # the selection is the entry-path BFS priority first, the
        # file-order head-slice only when no entry point is seeded — and
        # the mode is printed so a limited run never reads as a
        # priority-based sample when it is not.
        _limit_mode = limit_mode_for(units, limit)
        units = select_units_for_limit(units, limit)
        dataset["units"] = units  # so the agentic/single-shot paths enhance only these
        print(f"[Enhance] Limit {limit}: selection mode {_limit_mode}",
              file=sys.stderr)
    print(f"[Enhance] Units to enhance: {len(units)}", file=sys.stderr)

    # Set up progress reporter
    # #685: the Done/summary cost lines report THIS step's spend, read
    # against the same mutable holder the "Enhance" log_usage line uses —
    # so the #281 refresh at the checkpoint-injection site covers them too.
    progress = ProgressReporter("Enhance", len(units), tracker=tracker,
                                cost_baseline=_phase_baseline)

    def _on_unit_done(unit_id: str, classification: str, unit_elapsed: float):
        progress.report(
            unit_label=unit_id,
            detail=classification,
            unit_elapsed=unit_elapsed,
        )

    def _on_restored(count: int):
        # #218: rebase BOTH the counter and the session baseline, else the
        # restored units dilute the per-unit rate (Enhance/Verify learn the
        # restored count here, not via the `completed=` constructor arg).
        progress.mark_restored(count)

    # Run enhancement
    if mode == "agentic":
        if not analyzer_output_path:
            raise ValueError("Agentic mode requires --analyzer-output")

        enhanced = enhancer.enhance_dataset_agentic(
            dataset=dataset,
            analyzer_output_path=analyzer_output_path,
            repo_path=repo_path,
            checkpoint_path=checkpoint_path,
            progress_callback=_on_unit_done,
            restored_callback=_on_restored,
            workers=workers,
            phase_baseline=_phase_baseline,
        )
    elif mode == "single-shot":
        # NOTE: single-shot enhance performs NO add_prior_usage injection
        # (no checkpoint restore on this path) — its baseline was already
        # correct pre-#281; no holder threading needed (wave catch: threading
        # it anyway was dead code).
        enhanced = enhancer.enhance_dataset(
            dataset,
            progress_callback=_on_unit_done,
            workers=workers,
            checkpoint_path=checkpoint_path,
            restored_callback=_on_restored,
        )
    else:
        raise ValueError(f"Unknown enhancement mode: {mode}. Use 'agentic' or 'single-shot'.")

    progress.finish()

    # Compute classification distribution and error summary FIRST (before cleanup decision)
    classifications = {}
    error_count = 0
    error_summary = {}
    # #615: the degenerate-exit kind histogram (exit_kind's aggregate)
    incomplete_summary = {}
    context_key = "agent_context" if mode == "agentic" else "llm_context"

    incomplete_count = 0
    for unit in enhanced.get("units", []):
        ctx = unit.get(context_key, {})
        if ctx.get("error"):
            error_count += 1
            err = ctx["error"]
            if isinstance(err, dict):
                err_type = err.get("type", "unknown")
            else:
                err_type = "legacy_string"
            error_summary[err_type] = error_summary.get(err_type, 0) + 1
            continue
        cls = ctx.get("security_classification", "unknown")
        classifications[cls] = classifications.get(cls, 0) + 1
        # #293: the agent's degenerate exit is not a successful enhance
        if cls == "incomplete":
            incomplete_count += 1
            # #615: WHICH degenerate exit — the four exits differ in kind
            # and remedy (budget exhaustion vs cheap model behavior).
            kind = ctx.get("exit_kind") or "unstamped"
            incomplete_summary[kind] = incomplete_summary.get(kind, 0) + 1

    # Checkpoints are preserved as a permanent artifact alongside results.
    # Final summary (phase="done") is written by context_enhancer.

    # Write enhanced dataset
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    write_json(output_path, enhanced)
    print(f"[Enhance] Enhanced dataset: {output_path}", file=sys.stderr)
    print(f"[Enhance] Classifications: {classifications}", file=sys.stderr)
    if error_count:
        print(f"[Enhance] Errors: {error_count} ({error_summary})", file=sys.stderr)

    tracking.log_usage("Enhance", _phase_baseline["usage"])

    usage = tracking.get_usage()

    return EnhanceResult(
        enhanced_dataset_path=output_path,
        units_enhanced=len(units) - error_count - incomplete_count,
        error_count=error_count,
        error_summary=error_summary,
        classifications=classifications,
        # #611: the identity's own fields
        incomplete_count=incomplete_count,
        total_units=len(units),
        # #615: the kind histogram (the empty dict serializes without the
        # key via to_dict's present-only gate)
        incomplete_summary=incomplete_summary,
        # #802: the kept-set delta the resume paths hold at their
        # stale-restored intersections (present-only; None on a fresh run
        # or when nothing dropped).
        resume_delta=getattr(enhancer, "_resume_delta", None),
        # #739: the stamped selection mode (empty = no limit ran)
        limit_mode=_limit_mode,
        usage=usage,
    )
