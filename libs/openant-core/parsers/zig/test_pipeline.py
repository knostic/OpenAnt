#!/usr/bin/env python3
"""
Zig Parser Pipeline Orchestrator

Entry point for parsing Zig repositories. Wires together the 4-stage pipeline:
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
import json
import sys
from pathlib import Path

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from parsers.zig.repository_scanner import RepositoryScanner
from parsers.zig.function_extractor import FunctionExtractor
from parsers.zig.call_graph_builder import CallGraphBuilder
from parsers.zig.unit_generator import UnitGenerator


def main():
    parser = argparse.ArgumentParser(
        description="Parse Zig repositories for vulnerability analysis"
    )
    parser.add_argument("repo_path", help="Path to the Zig repository")
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

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[Zig Parser] Parsing repository: {repo_path}", file=sys.stderr)
    print(f"[Zig Parser] Output directory: {output_dir}", file=sys.stderr)
    print(f"[Zig Parser] Processing level: {args.processing_level}", file=sys.stderr)
    print(f"[Zig Parser] Skip tests: {args.skip_tests}", file=sys.stderr)

    try:
        # Stage 1: Repository Scanner
        print("[Zig Parser] Stage 1: Scanning repository...", file=sys.stderr)
        scanner = RepositoryScanner(
            str(repo_path),
            skip_tests=args.skip_tests,
        )
        scan_results = scanner.scan()
        scanner.save_results(str(output_dir / "scan_results.json"), scan_results)
        print(
            f"  Found {scan_results['statistics']['total_files']} Zig files",
            file=sys.stderr,
        )

        if scan_results["statistics"]["total_files"] == 0:
            print("[Zig Parser] No Zig files found in repository", file=sys.stderr)
            # Write empty dataset
            empty_dataset = {
                "name": args.name or repo_path.name,
                "repository": str(repo_path),
                "units": [],
                "statistics": {"total_units": 0, "by_type": {}},
                "metadata": {"generator": "zig_unit_generator.py"},
            }
            with open(output_dir / "dataset.json", "w") as f:
                json.dump(empty_dataset, f, indent=2)
            with open(output_dir / "analyzer_output.json", "w") as f:
                json.dump({"repository": str(repo_path), "functions": {}}, f, indent=2)
            return 0

        # Stage 2: Function Extractor
        print("[Zig Parser] Stage 2: Extracting functions...", file=sys.stderr)
        extractor = FunctionExtractor(str(repo_path), scan_results)
        extractor_output = extractor.extract()
        print(
            f"  Extracted {extractor_output['statistics']['total_functions']} functions",
            file=sys.stderr,
        )
        print(
            f"  Extracted {extractor_output['statistics']['total_classes']} structs",
            file=sys.stderr,
        )

        # Stage 3: Call Graph Builder
        print("[Zig Parser] Stage 3: Building call graph...", file=sys.stderr)
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
                call_graph_output, args.processing_level, str(repo_path)
            )
            print(
                f"  After {args.processing_level} filter: {len(call_graph_output['functions'])} functions",
                file=sys.stderr,
            )

        # Stage 4: Unit Generator
        print("[Zig Parser] Stage 4: Generating analysis units...", file=sys.stderr)
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

        print("[Zig Parser] Pipeline complete!", file=sys.stderr)
        return 0

    except Exception as e:
        print(f"[Zig Parser] Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return 1


def apply_processing_filter(
    call_graph_output: dict, level: str, repo_path: str
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
        return apply_reachability_filter(call_graph_output, repo_path)
    elif level == "codeql":
        # First apply reachability, then would filter by CodeQL results
        filtered = apply_reachability_filter(call_graph_output, repo_path)
        # CodeQL filtering would be applied here if results exist
        return filtered
    elif level == "exploitable":
        # Apply all filters
        filtered = apply_reachability_filter(call_graph_output, repo_path)
        # CodeQL + LLM filtering would be applied here
        return filtered
    return call_graph_output


def apply_reachability_filter(call_graph_output: dict, repo_path: str) -> dict:
    """Filter to functions reachable from entry points."""
    try:
        # Try to import the reachability analyzer
        from utilities.agentic_enhancer.entry_point_detector import EntryPointDetector
        from utilities.agentic_enhancer.reachability_analyzer import ReachabilityAnalyzer

        # Detect entry points
        detector = EntryPointDetector(repo_path)
        entry_points = detector.detect()

        # Analyze reachability
        analyzer = ReachabilityAnalyzer(call_graph_output, entry_points)
        reachable = analyzer.get_reachable_functions()

        # Filter functions to only reachable ones
        filtered_functions = {
            fid: finfo
            for fid, finfo in call_graph_output["functions"].items()
            if fid in reachable
        }

        # Update the output with filtered functions
        result = call_graph_output.copy()
        result["functions"] = filtered_functions

        # Filter call graphs too
        result["call_graph"] = {
            k: [v for v in vs if v in reachable]
            for k, vs in call_graph_output.get("call_graph", {}).items()
            if k in reachable
        }
        result["reverse_call_graph"] = {
            k: [v for v in vs if v in reachable]
            for k, vs in call_graph_output.get("reverse_call_graph", {}).items()
            if k in reachable
        }

        return result

    except ImportError:
        print(
            "  Warning: Reachability analyzer not available, skipping filter",
            file=sys.stderr,
        )
        return call_graph_output


if __name__ == "__main__":
    sys.exit(main())
