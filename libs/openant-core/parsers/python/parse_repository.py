#!/usr/bin/env python3
"""
Python Repository Parser - Main Orchestrator

This is the primary entry point for parsing Python repositories into
datasets for OpenAnt's vulnerability analysis. It orchestrates a
4-stage pipeline:

Pipeline Stages:
    1. Repository Scanner  - Find all Python files in the repository
    2. Function Extractor  - Extract functions, classes, and module-level code
    3. Call Graph Builder  - Build bidirectional call graphs (who calls whom)
    4. Unit Generator      - Create self-contained analysis units with dependencies

Output Files:
    - dataset.json: Analysis units compatible with experiment.py
    - analyzer_output.json: Function index for Stage 2 verification tools

Key Features:
    - Module-level code extraction (critical for Streamlit/script vulnerabilities)
    - Bidirectional call graph analysis
    - Configurable dependency resolution depth
    - Stage 2 verification support via analyzer_output.json

Usage:
    # Basic: parse and output to stdout
    python parse_repository.py /path/to/repo

    # With output files
    python parse_repository.py /path/to/repo \\
        --output dataset.json \\
        --analyzer-output analyzer_output.json

    # With debugging intermediates
    python parse_repository.py /path/to/repo \\
        --output dataset.json \\
        --intermediates /tmp/debug

See Also:
    - PARSER_PIPELINE.md: Human-readable documentation
    - PARSER_UPGRADE_PLAN.md: Technical reference for Claude
    - datasets/DATASET_FORMAT.md: Output schema documentation
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from repository_scanner import RepositoryScanner
from function_extractor import FunctionExtractor
from call_graph_builder import CallGraphBuilder
from unit_generator import UnitGenerator
from utilities.file_io import read_json, write_json, open_utf8


def generate_analyzer_output(extractor_result: dict) -> dict:
    """
    Generate analyzer_output.json format for Stage 2 verification.

    This format is compatible with OpenAnt's RepositoryIndex class,
    enabling the Stage 2 verifier to search function usages, definitions,
    and explore the codebase.

    Args:
        extractor_result: Output from FunctionExtractor

    Returns:
        Dict in analyzer_output.json format:
        {
            "functions": {
                "file.py:func_name": {
                    "name": "func_name",
                    "code": "...",
                    "isExported": true,
                    "unitType": "function",
                    "startLine": 3,
                    "endLine": 5,
                    "className": "ClassName"  // optional
                }
            }
        }
    """
    functions = {}

    for func_id, func_data in extractor_result.get('functions', {}).items():
        functions[func_id] = {
            "name": func_data.get("name", ""),
            "code": func_data.get("code", ""),
            "isExported": True,  # Python doesn't have explicit exports
            "unitType": func_data.get("unit_type", "function"),
            "startLine": func_data.get("start_line", 0),
            "endLine": func_data.get("end_line", 0),
        }

        # Add className for methods
        class_name = func_data.get("class_name")
        if class_name:
            functions[func_id]["className"] = class_name

    return {"functions": functions}


def parse_repository(repo_path: str, options: dict = None) -> tuple:
    """
    Parse a Python repository and generate analysis units.

    Args:
        repo_path: Path to the repository
        options: Optional configuration
            - max_depth: Dependency resolution depth (default: 3)
            - dataset_name: Name for the dataset
            - skip_tests: Whether to skip test files
            - output_intermediates: Whether to save intermediate files

    Returns:
        Tuple of (dataset, analyzer_output):
            - dataset: Dictionary compatible with OpenAnt experiment.py
            - analyzer_output: Dictionary compatible with RepositoryIndex (Stage 2)
    """
    options = options or {}
    max_depth = options.get('max_depth', 3)
    dataset_name = options.get('dataset_name', Path(repo_path).name)
    skip_tests = options.get('skip_tests', False)
    output_dir = options.get('output_dir')

    print(f"=" * 60, file=sys.stderr)
    print(f"PYTHON REPOSITORY PARSER", file=sys.stderr)
    print(f"Repository: {repo_path}", file=sys.stderr)
    print(f"=" * 60, file=sys.stderr)

    # Phase 1: Scan repository
    print(f"\n[Phase 1] Scanning repository for Python files...", file=sys.stderr)
    scanner = RepositoryScanner(repo_path, {'skip_tests': skip_tests})
    scan_result = scanner.scan()
    print(f"  Found {scan_result['statistics']['total_files']} Python files", file=sys.stderr)
    print(f"  Total size: {scan_result['statistics']['total_size_bytes']:,} bytes", file=sys.stderr)

    if output_dir:
        scan_file = Path(output_dir) / 'scan_result.json'
        write_json(scan_file, scan_result)
        print(f"  Saved: {scan_file}", file=sys.stderr)

    # Phase 2: Extract functions
    print(f"\n[Phase 2] Extracting functions and classes...", file=sys.stderr)
    extractor = FunctionExtractor(repo_path)
    extractor_result = extractor.extract_from_scan(scan_result)
    print(f"  Total functions: {extractor_result['statistics']['total_functions']}", file=sys.stderr)
    print(f"    Standalone: {extractor_result['statistics']['standalone_functions']}", file=sys.stderr)
    print(f"    Methods: {extractor_result['statistics']['total_methods']}", file=sys.stderr)
    print(f"    Module-level: {extractor_result['statistics']['module_level_units']}", file=sys.stderr)
    print(f"  Total classes: {extractor_result['statistics']['total_classes']}", file=sys.stderr)

    if output_dir:
        extract_file = Path(output_dir) / 'functions.json'
        write_json(extract_file, extractor_result)
        print(f"  Saved: {extract_file}", file=sys.stderr)

    # Phase 3: Build call graph
    print(f"\n[Phase 3] Building call graph...", file=sys.stderr)
    builder = CallGraphBuilder(extractor_result, {'max_depth': max_depth})
    builder.build_call_graph()
    call_graph_result = builder.export()
    stats = call_graph_result['statistics']
    print(f"  Total edges: {stats['total_edges']}", file=sys.stderr)
    print(f"  Avg out-degree: {stats['avg_out_degree']}", file=sys.stderr)
    print(f"  Max out-degree: {stats['max_out_degree']}", file=sys.stderr)
    print(f"  Isolated functions: {stats['isolated_functions']}", file=sys.stderr)

    if output_dir:
        graph_file = Path(output_dir) / 'call_graph.json'
        write_json(graph_file, call_graph_result)
        print(f"  Saved: {graph_file}", file=sys.stderr)

    # Phase 4: Generate units
    print(f"\n[Phase 4] Generating analysis units...", file=sys.stderr)
    generator = UnitGenerator(call_graph_result, {
        'max_depth': max_depth,
        'dataset_name': dataset_name,
    })
    dataset = generator.generate_units()
    stats = dataset['statistics']
    print(f"  Total units: {stats['total_units']}", file=sys.stderr)
    print(f"  Enhanced units: {stats['units_enhanced']}", file=sys.stderr)
    print(f"  With upstream deps: {stats['units_with_upstream']}", file=sys.stderr)
    print(f"  With downstream callers: {stats['units_with_downstream']}", file=sys.stderr)

    # Summary by type
    print(f"\n  By type:", file=sys.stderr)
    for unit_type, count in sorted(stats['by_type'].items()):
        print(f"    {unit_type}: {count}", file=sys.stderr)

    # Generate analyzer output for Stage 2 verification
    analyzer_output = generate_analyzer_output(extractor_result)
    print(f"\n[Stage 2 Support] Generated analyzer output: {len(analyzer_output['functions'])} functions", file=sys.stderr)

    if output_dir:
        analyzer_file = Path(output_dir) / 'analyzer_output.json'
        write_json(analyzer_file, analyzer_output)
        print(f"  Saved: {analyzer_file}", file=sys.stderr)

    print(f"\n" + "=" * 60, file=sys.stderr)
    print(f"PARSING COMPLETE", file=sys.stderr)
    print(f"=" * 60, file=sys.stderr)

    return dataset, analyzer_output


def main():
    """Command line interface."""
    parser = argparse.ArgumentParser(
        description='Parse a Python repository and generate analysis units',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python parse_repository.py /path/to/repo
  python parse_repository.py /path/to/repo --output dataset.json
  python parse_repository.py /path/to/repo --output dataset.json --analyzer-output analyzer_output.json
  python parse_repository.py /path/to/repo --depth 2 --name my_dataset
  python parse_repository.py /path/to/repo --intermediates /tmp/parsing
        '''
    )

    parser.add_argument('repo_path', help='Path to the repository')
    parser.add_argument('--output', '-o', help='Output file for dataset (default: stdout)')
    parser.add_argument('--analyzer-output', '-a',
                        help='Output file for analyzer_output.json (Stage 2 verification support)')
    parser.add_argument('--depth', '-d', type=int, default=3,
                        help='Max dependency resolution depth (default: 3)')
    parser.add_argument('--name', '-n', help='Dataset name (default: derived from repo path)')
    parser.add_argument('--skip-tests', action='store_true', help='Skip test files')
    parser.add_argument('--intermediates', help='Directory to save intermediate files')

    args = parser.parse_args()

    try:
        options = {
            'max_depth': args.depth,
            'skip_tests': args.skip_tests,
        }
        if args.name:
            options['dataset_name'] = args.name
        if args.intermediates:
            options['output_dir'] = args.intermediates
            Path(args.intermediates).mkdir(parents=True, exist_ok=True)

        dataset, analyzer_output = parse_repository(args.repo_path, options)

        # Save dataset
        dataset_json = json.dumps(dataset, indent=2)
        if args.output:
            with open_utf8(args.output, 'w') as f:
                f.write(dataset_json)
            print(f"\nDataset written to: {args.output}", file=sys.stderr)
        else:
            print(dataset_json)

        # Save analyzer output if requested
        if args.analyzer_output:
            write_json(args.analyzer_output, analyzer_output)
            print(f"Analyzer output written to: {args.analyzer_output}", file=sys.stderr)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
