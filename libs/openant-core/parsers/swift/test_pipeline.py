#!/usr/bin/env python3
"""
Swift Parser Pipeline Orchestrator

Entry point for parsing Swift repositories. Wires together the 4-stage pipeline:
1. Repository Scanner
2. Function Extractor
3. Call Graph Builder
4. Unit Generator

Usage:
    python test_pipeline.py <repo_path> \
        --output <dir> \
        --processing-level <all|reachable|codeql|exploitable> \
        --skip-tests \
        --name <dataset_name>
"""

import argparse
import sys
from pathlib import Path

# Put openant-core on sys.path BEFORE importing `utilities`/`parsers` — otherwise a
# direct `python parsers/swift/test_pipeline.py` invocation (the documented usage)
# crashes at import time. It only worked because parser_adapter runs this with
# cwd=openant-core, which masked the ordering bug (the Zig sibling has it too).
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utilities.file_io import write_json  # noqa: E402
from utilities.prune_telemetry import compute_prune_telemetry  # noqa: E402
from parsers.swift.repository_scanner import RepositoryScanner  # noqa: E402
from parsers.swift.function_extractor import FunctionExtractor  # noqa: E402
from parsers.swift.call_graph_builder import CallGraphBuilder  # noqa: E402
from parsers.swift.unit_generator import UnitGenerator  # noqa: E402


def main():
    parser = argparse.ArgumentParser(
        description="Parse Swift repositories for vulnerability analysis"
    )
    parser.add_argument("repo_path", help="Path to the Swift repository")
    parser.add_argument("--output", "-o", required=True, help="Output directory for results")
    parser.add_argument(
        "--processing-level",
        choices=["all", "reachable", "codeql", "exploitable"],
        default="all",
        help="Processing level for filtering functions",
    )
    parser.add_argument("--skip-tests", action="store_true", help="Skip test files and functions")
    parser.add_argument("--name", help="Dataset name (defaults to repo directory name)")
    parser.add_argument(
        "--library-mode",
        action="store_true",
        help="Seed the exported public API as entry points (for libraries/frameworks with no main/route/CLI)",
    )
    parser.add_argument("--dependency-depth", type=int, default=3, help="Maximum depth for dependency resolution")

    args = parser.parse_args()

    repo_path = Path(args.repo_path).resolve()
    output_dir = Path(args.output).resolve()

    if not repo_path.exists():
        print(f"Error: Repository path does not exist: {repo_path}", file=sys.stderr)
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[Swift Parser] Parsing repository: {repo_path}", file=sys.stderr)
    print(f"[Swift Parser] Output directory: {output_dir}", file=sys.stderr)
    print(f"[Swift Parser] Processing level: {args.processing_level}", file=sys.stderr)
    print(f"[Swift Parser] Skip tests: {args.skip_tests}", file=sys.stderr)

    try:
        # Stage 1: Repository Scanner
        print("[Swift Parser] Stage 1: Scanning repository...", file=sys.stderr)
        scanner = RepositoryScanner(str(repo_path), skip_tests=args.skip_tests)
        scan_results = scanner.scan()
        scanner.save_results(str(output_dir / "scan_results.json"), scan_results)
        print(f"  Found {scan_results['statistics']['total_files']} Swift files", file=sys.stderr)

        if scan_results["statistics"]["total_files"] == 0:
            print("[Swift Parser] No Swift files found in repository", file=sys.stderr)
            empty_dataset = {
                "name": args.name or repo_path.name,
                "repository": str(repo_path),
                "units": [],
                "statistics": {"total_units": 0, "by_type": {}},
                "metadata": {"generator": "swift_unit_generator.py"},
            }
            write_json(output_dir / "dataset.json", empty_dataset)
            write_json(output_dir / "analyzer_output.json", {"repository": str(repo_path), "functions": {}})
            return 0

        # Stage 2: Function Extractor
        print("[Swift Parser] Stage 2: Extracting functions...", file=sys.stderr)
        extractor = FunctionExtractor(str(repo_path), scan_results)
        extractor_output = extractor.extract()
        print(f"  Extracted {extractor_output['statistics']['total_functions']} functions", file=sys.stderr)
        print(f"  Extracted {extractor_output['statistics']['total_classes']} types", file=sys.stderr)

        # Stage 3: Call Graph Builder
        print("[Swift Parser] Stage 3: Building call graph...", file=sys.stderr)
        call_graph_builder = CallGraphBuilder(extractor_output)
        call_graph_output = call_graph_builder.build()
        call_graph_builder.save_results(str(output_dir / "call_graph.json"), call_graph_output)
        stats = call_graph_output["statistics"]
        print(f"  Built graph with {stats['total_edges']} edges", file=sys.stderr)
        _warn_under_connection(stats)

        # Apply processing level filters
        if args.processing_level != "all":
            call_graph_output = apply_processing_filter(
                call_graph_output, args.processing_level, str(repo_path),
                output_dir=str(output_dir), library_mode=args.library_mode,
            )
            print(f"  After {args.processing_level} filter: {len(call_graph_output['functions'])} functions", file=sys.stderr)

        # Stage 4: Unit Generator
        print("[Swift Parser] Stage 4: Generating analysis units...", file=sys.stderr)
        generator = UnitGenerator(call_graph_output, str(repo_path), dependency_depth=args.dependency_depth)
        dataset, analyzer_output = generator.generate(name=args.name)
        # B3: surface the reachability-filter record (prune telemetry + invariant) in
        # dataset metadata — parity with js/go/c/ruby/php, which all write this block.
        _rf = call_graph_output.get("_reachability_filter")
        if _rf is not None:
            dataset.setdefault("metadata", {})["reachability_filter"] = _rf
        generator.save_results(str(output_dir), dataset, analyzer_output)
        print(f"  Generated {dataset['statistics']['total_units']} units", file=sys.stderr)

        print("[Swift Parser] Pipeline complete!", file=sys.stderr)
        return 0

    except Exception as e:
        print(f"[Swift Parser] Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return 1


def _warn_under_connection(stats: dict) -> None:
    """Advisory silent-under-connection guard (Sol: "N4 is not enough").

    The repo-wide keep-all net only fires on a ZERO entry-point seed. A call
    graph that extracted many functions but resolved almost no edges (e.g. an AST
    node-name mismatch broke call extraction) would still have a valid seed, so
    reachability keeps only the seed + its ~nothing and silently prunes the repo.
    Surface that shape loudly; it never changes results.
    """
    funcs = stats.get("total_functions", 0)
    call_sites = stats.get("total_call_sites", 0)
    resolved = stats.get("resolved_edges", 0)
    isolated_ratio = stats.get("isolated_ratio", 0)
    reparse_errors = stats.get("reparse_error_bodies", 0)
    if reparse_errors:
        print(f"  [Warning] {reparse_errors} unit bodies reparsed with syntax errors "
              f"during call extraction (some out-edges may be missing).", file=sys.stderr)
    if funcs >= 50 and call_sites >= funcs and resolved == 0:
        print(f"  [Warning] {funcs} functions with {call_sites} call sites resolved "
              f"ZERO edges — call resolution looks broken (silent under-connection). "
              f"Reachability will prune almost everything.", file=sys.stderr)
    elif funcs >= 100 and isolated_ratio >= 0.9:
        print(f"  [Warning] {isolated_ratio*100:.0f}% of functions are isolated (no "
              f"caller/callee) — call resolution may be under-connecting.", file=sys.stderr)


def apply_processing_filter(call_graph_output: dict, level: str, repo_path: str,
                            output_dir: str = None, library_mode: bool = False) -> dict:
    if level in ("reachable", "codeql", "exploitable"):
        return apply_reachability_filter(call_graph_output, repo_path,
                                         output_dir=output_dir, library_mode=library_mode)
    return call_graph_output


def apply_reachability_filter(call_graph_output: dict, repo_path: str,
                              output_dir: str = None, library_mode: bool = False) -> dict:
    """Filter to functions reachable from entry points.

    Uses the real EntryPointDetector / ReachabilityAnalyzer contract, matching
    core/parser_adapter.apply_reachability_filter and the C/Go/PHP/Ruby/Zig
    sibling pipelines, incl. the N4 empty-seed keep-all net.

    B3: when ``output_dir`` is provided, emits the per-unit prune telemetry +
    forward-asymmetry invariant + pruned_units.json sidecar via the SHARED helper
    (utilities.prune_telemetry.compute_prune_telemetry), and stashes the reachability-filter
    record on ``result["_reachability_filter"]`` for main() to merge into dataset
    metadata. ADDITIVE only — never changes which functions survive. ``output_dir`` is
    optional so the existing 3-arg callers (tests/parsers/swift/test_empty_seed_keep_all)
    keep working; without it the sidecar is skipped but the record is still stashed.
    """
    try:
        from utilities.agentic_enhancer.entry_point_detector import (
            EntryPointDetector, blackout_warning, library_seed_ids,
        )
        from utilities.agentic_enhancer.reachability_analyzer import ReachabilityAnalyzer
    except ImportError:
        print("  Warning: Reachability analyzer not available, skipping filter", file=sys.stderr)
        return call_graph_output

    functions = call_graph_output.get("functions", {})
    call_graph = call_graph_output.get("call_graph", {})
    reverse_call_graph = call_graph_output.get("reverse_call_graph", {})

    detector = EntryPointDetector(functions, call_graph)
    entry_points = detector.detect_entry_points()

    if library_mode:
        entry_points = entry_points | library_seed_ids(functions)

    analyzer = ReachabilityAnalyzer(
        functions=functions,
        reverse_call_graph=reverse_call_graph,
        entry_points=entry_points,
    )
    reachable = analyzer.get_all_reachable()

    # N4: empty-seed safety-net — no entry points => keep all + warn, never a
    # silent 0-unit blackout (the dominant failure for library/framework targets).
    if not entry_points and functions:
        print("  [Warning] No entry points detected — keeping all units unfiltered "
              "to avoid a silent blackout.", file=sys.stderr)
        reachable = set(functions.keys())

    filtered_functions = {fid: finfo for fid, finfo in functions.items() if fid in reachable}
    result = call_graph_output.copy()
    result["functions"] = filtered_functions
    result["call_graph"] = {
        k: [v for v in vs if v in reachable]
        for k, vs in call_graph.items() if k in reachable
    }
    result["reverse_call_graph"] = {
        k: [v for v in vs if v in reachable]
        for k, vs in reverse_call_graph.items() if k in reachable
    }

    _blackout = blackout_warning(detector.entry_point_details, len(functions),
                                 len(filtered_functions), library_mode=library_mode)
    if _blackout:
        print(f"  [Warning] {_blackout}", file=sys.stderr)

    # B3: per-unit prune telemetry via the shared utilities.prune_telemetry helper. Best-effort — a telemetry
    # failure must NEVER fail a Swift scan (main()'s bare except turns any raise into rc=1).
    try:
        original_count = len(functions)
        reduction_pct = (round((1 - len(filtered_functions) / original_count) * 100, 1)
                         if original_count > 0 else 0)
        rf = {
            "original_units": original_count,
            "entry_points": len(entry_points),
            "reachable_units": len(filtered_functions),
            "filtered_out": original_count - len(filtered_functions),
            "reduction_percentage": reduction_pct,
        }
        if not entry_points:
            # N4 empty-seed keep-all: mirror core's REDUCED schema (no pruned_* keys, no
            # sidecar) — reachable filtering was not really applied. Contract pinned for
            # core by test_reachability_prune_telemetry::test_empty_entrypoints_passthrough.
            # Match core's int 0 exactly (core hardcodes 0 on this branch, not round()=0.0).
            rf["reduction_percentage"] = 0
            rf["warning"] = ("No entry points detected — kept all units unfiltered to "
                             "avoid a silent blackout; reachable filtering was NOT applied.")
        else:
            # Feed the UN-pruned graphs (`call_graph`/`reverse_call_graph`), NOT
            # `result[...]`: a pruned graph forces the asymmetry invariant to a
            # manufactured 0. Highest-risk line in this change.
            pruned_ids = sorted(set(functions) - set(filtered_functions))
            # #301: third return value = the orphan-rate advisory (its own
            # key, never the reserved warning slot; core parity).
            _extra, _asym_warning, _orphan_advisory = compute_prune_telemetry(
                reachable, pruned_ids, call_graph, reverse_call_graph, output_dir)
            rf.update(_extra)
            if _asym_warning:
                rf["warning"] = _asym_warning
            if _blackout:            # blackout warning takes precedence (core parity)
                rf["warning"] = _blackout
            if _orphan_advisory:
                rf["orphan_advisory"] = _orphan_advisory
                print(f"  [Advisory] {_orphan_advisory}", file=sys.stderr)
        result["_reachability_filter"] = rf
    except Exception as _e:          # telemetry is advisory; never break the scan
        print(f"  [Warning] prune telemetry skipped: {_e}", file=sys.stderr)

    return result


if __name__ == "__main__":
    sys.exit(main())
