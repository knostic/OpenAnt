#!/usr/bin/env python3
"""
Rust Parser Pipeline Orchestrator

Entry point for parsing Rust repositories. Wires together the 4-stage pipeline:
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

# Add parent directories to path for imports. This MUST run before importing
# anything from `utilities` / `parsers`, which live under that root and are not
# otherwise on sys.path when this script is invoked directly (the way
# parser_adapter runs it: cwd=core root, no PYTHONPATH).
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utilities.file_io import write_json
from parsers.rust.repository_scanner import RepositoryScanner
from parsers.rust.function_extractor import FunctionExtractor
from parsers.rust.call_graph_builder import CallGraphBuilder
from parsers.rust.unit_generator import UnitGenerator


def main():
    parser = argparse.ArgumentParser(
        description="Parse Rust repositories for vulnerability analysis"
    )
    parser.add_argument("repo_path", help="Path to the Rust repository")
    parser.add_argument(
        "--output", "-o", required=True, help="Output directory for results"
    )
    parser.add_argument(
        "--processing-level",
        choices=["all", "reachable", "codeql", "exploitable"],
        default="all",
        help="Processing level for filtering functions",
    )
    parser.add_argument(
        "--skip-tests", action="store_true", help="Skip test files and functions"
    )
    parser.add_argument("--name", help="Dataset name (defaults to repo directory name)")
    parser.add_argument(
        "--library-mode",
        action="store_true",
        help="Seed the exported public API as entry points (for libraries with no main/route/CLI)",
    )
    parser.add_argument(
        "--dependency-depth",
        type=int,
        default=3,
        help="Maximum depth for dependency resolution",
    )

    args = parser.parse_args()

    repo_path = Path(args.repo_path).resolve()
    output_dir = Path(args.output).resolve()

    if not repo_path.exists():
        print(f"Error: Repository path does not exist: {repo_path}", file=sys.stderr)
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[Rust Parser] Parsing repository: {repo_path}", file=sys.stderr)
    print(f"[Rust Parser] Output directory: {output_dir}", file=sys.stderr)
    print(f"[Rust Parser] Processing level: {args.processing_level}", file=sys.stderr)
    print(f"[Rust Parser] Skip tests: {args.skip_tests}", file=sys.stderr)

    try:
        # Stage 1: Repository Scanner
        print("[Rust Parser] Stage 1: Scanning repository...", file=sys.stderr)
        scanner = RepositoryScanner(
            str(repo_path),
            skip_tests=args.skip_tests,
        )
        scan_results = scanner.scan()
        scanner.save_results(str(output_dir / "scan_results.json"), scan_results)
        print(
            f"  Found {scan_results['statistics']['total_files']} Rust files",
            file=sys.stderr,
        )

        if scan_results["statistics"]["total_files"] == 0:
            print("[Rust Parser] No Rust files found in repository", file=sys.stderr)
            empty_dataset = {
                "name": args.name or repo_path.name,
                "repository": str(repo_path),
                "units": [],
                "statistics": {"total_units": 0, "by_type": {}},
                "metadata": {"generator": "rust_unit_generator.py"},
            }
            write_json(output_dir / "dataset.json", empty_dataset)
            write_json(
                output_dir / "analyzer_output.json",
                {"repository": str(repo_path), "functions": {}},
            )
            return 0

        # Stage 2: Function Extractor
        print("[Rust Parser] Stage 2: Extracting functions...", file=sys.stderr)
        extractor = FunctionExtractor(str(repo_path), scan_results, skip_tests=args.skip_tests)
        extractor_output = extractor.extract()
        print(
            f"  Extracted {extractor_output['statistics']['total_functions']} functions",
            file=sys.stderr,
        )
        print(
            f"  Extracted {extractor_output['statistics']['total_classes']} structs/enums/traits",
            file=sys.stderr,
        )

        # Stage 3: Call Graph Builder
        print("[Rust Parser] Stage 3: Building call graph...", file=sys.stderr)
        call_graph_builder = CallGraphBuilder(extractor_output)
        call_graph_output = call_graph_builder.build()
        call_graph_builder.save_results(
            str(output_dir / "call_graph.json"), call_graph_output
        )
        print(
            f"  Built graph with {call_graph_output['statistics']['total_edges']} edges",
            file=sys.stderr,
        )

        # Apply processing level filters
        if args.processing_level != "all":
            call_graph_output = apply_processing_filter(
                call_graph_output, args.processing_level, str(repo_path),
                library_mode=args.library_mode,
            )
            print(
                f"  After {args.processing_level} filter: {len(call_graph_output['functions'])} functions",
                file=sys.stderr,
            )

        # Stage 4: Unit Generator
        print("[Rust Parser] Stage 4: Generating analysis units...", file=sys.stderr)
        generator = UnitGenerator(
            call_graph_output,
            str(repo_path),
            dependency_depth=args.dependency_depth,
        )
        dataset, analyzer_output = generator.generate(name=args.name)
        generator.save_results(str(output_dir), dataset, analyzer_output)
        print(
            f"  Generated {dataset['statistics']['total_units']} units",
            file=sys.stderr,
        )

        print("[Rust Parser] Pipeline complete!", file=sys.stderr)
        return 0

    except Exception as e:
        print(f"[Rust Parser] Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return 1


def apply_processing_filter(
    call_graph_output: dict, level: str, repo_path: str, library_mode: bool = False
) -> dict:
    """
    Apply processing level filters to reduce the function set.

    Levels:
    - all: No filtering (already handled)
    - reachable: Filter to functions reachable from entry points
    - codeql: Filter to reachable + CodeQL-flagged functions
    - exploitable: Filter to reachable + CodeQL + LLM-classified exploitable
    """
    if level == "reachable":
        return apply_reachability_filter(call_graph_output, repo_path, library_mode=library_mode)
    elif level == "codeql":
        filtered = apply_reachability_filter(call_graph_output, repo_path, library_mode=library_mode)
        return filtered
    elif level == "exploitable":
        filtered = apply_reachability_filter(call_graph_output, repo_path, library_mode=library_mode)
        return filtered
    return call_graph_output


def apply_reachability_filter(call_graph_output: dict, repo_path: str,
                              library_mode: bool = False) -> dict:
    """Filter to functions reachable from entry points.

    Uses the shared EntryPointDetector / ReachabilityAnalyzer contract (see
    the Zig/PHP/Ruby/C parser pipelines for the identical shape).
    """
    try:
        from utilities.agentic_enhancer.entry_point_detector import EntryPointDetector, blackout_warning, library_seed_ids
        from utilities.agentic_enhancer.reachability_analyzer import ReachabilityAnalyzer
    except ImportError:
        print(
            "  Warning: Reachability analyzer not available, skipping filter",
            file=sys.stderr,
        )
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

    if not entry_points and functions:
        print("  [Warning] No entry points detected — keeping all units unfiltered "
              "to avoid a silent blackout.", file=sys.stderr)
        reachable = set(functions.keys())

    filtered_functions = {
        fid: finfo for fid, finfo in functions.items() if fid in reachable
    }

    result = call_graph_output.copy()
    result["functions"] = filtered_functions

    result["call_graph"] = {
        k: [v for v in vs if v in reachable]
        for k, vs in call_graph.items()
        if k in reachable
    }
    result["reverse_call_graph"] = {
        k: [v for v in vs if v in reachable]
        for k, vs in reverse_call_graph.items()
        if k in reachable
    }

    _blackout = blackout_warning(detector.entry_point_details, len(functions),
                                 len(filtered_functions), library_mode=library_mode)
    if _blackout:
        print(f"  [Warning] {_blackout}", file=sys.stderr)

    return result


if __name__ == "__main__":
    sys.exit(main())
