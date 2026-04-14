#!/usr/bin/env python3
"""
Unit Generator for Ruby Codebases

Creates self-contained analysis units for ALL functions extracted from a repository.
Each unit includes:
- Primary code (the function itself)
- Upstream dependencies (functions this calls)
- Downstream callers (functions that call this)
- Assembled enhanced code with file boundaries

This is Phase 4 of the Ruby parser - dataset generation.

Usage:
    python unit_generator.py <call_graph.json> [--output <file>] [--depth <N>]

Output (JSON):
    {
        "name": "dataset_name",
        "repository": "/path/to/repo",
        "units": [ ... ],
        "statistics": { ... }
    }
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set


# File boundary marker for enhanced code (Ruby uses # comments)
FILE_BOUNDARY = '\n\n# ========== File Boundary ==========\n\n'


class UnitGenerator:
    """
    Generate self-contained analysis units from call graph data.

    This is Stage 4 (final stage) of the Ruby parser pipeline.
    """

    def __init__(self, call_graph_data: Dict, options: Optional[Dict] = None):
        options = options or {}

        self.functions = call_graph_data.get('functions', {})
        self.classes = call_graph_data.get('classes', {})
        self.call_graph = call_graph_data.get('call_graph', {})
        self.reverse_call_graph = call_graph_data.get('reverse_call_graph', {})
        self.repo_path = call_graph_data.get('repository', '')

        self.max_depth = options.get('max_depth', 3)
        self.dataset_name = options.get('dataset_name', Path(self.repo_path).name if self.repo_path else 'dataset')

        self.units: List[Dict] = []
        self.statistics = {
            'total_units': 0,
            'by_type': {},
            'units_with_upstream': 0,
            'units_with_downstream': 0,
            'units_enhanced': 0,
            'avg_upstream': 0,
            'avg_downstream': 0,
        }

    def get_dependencies(self, func_id: str, depth: Optional[int] = None) -> List[str]:
        """Get all dependencies (callees) for a function up to max depth."""
        max_d = depth if depth is not None else self.max_depth
        dependencies = []
        visited = {func_id}
        queue = [(func_id, 0)]

        while queue:
            current_id, current_depth = queue.pop(0)

            if current_depth >= max_d:
                continue

            calls = self.call_graph.get(current_id, [])
            for called_id in calls:
                if called_id not in visited:
                    visited.add(called_id)
                    dependencies.append(called_id)
                    queue.append((called_id, current_depth + 1))

        return dependencies

    def get_callers(self, func_id: str, depth: Optional[int] = None) -> List[str]:
        """Get all callers for a function up to max depth."""
        max_d = depth if depth is not None else self.max_depth
        callers = []
        visited = {func_id}
        queue = [(func_id, 0)]

        while queue:
            current_id, current_depth = queue.pop(0)

            if current_depth >= max_d:
                continue

            caller_ids = self.reverse_call_graph.get(current_id, [])
            for caller_id in caller_ids:
                if caller_id not in visited:
                    visited.add(caller_id)
                    callers.append(caller_id)
                    queue.append((caller_id, current_depth + 1))

        return callers

    def assemble_enhanced_code(self, func_data: Dict,
                                upstream_deps: List[Dict],
                                downstream_callers: List[Dict]) -> str:
        """Assemble enhanced code with all dependencies using file boundary markers."""
        parts = []
        included_code: Set[str] = set()

        # Add primary code first
        primary_code = func_data.get('code', '')
        parts.append(primary_code)
        included_code.add(primary_code)

        # Add upstream dependencies (functions this calls)
        for dep in upstream_deps:
            dep_code = dep.get('code', '')
            if dep_code and dep_code not in included_code:
                parts.append(dep_code)
                included_code.add(dep_code)

        # Add downstream callers (functions that call this)
        for caller in downstream_callers:
            caller_code = caller.get('code', '')
            if caller_code and caller_code not in included_code:
                parts.append(caller_code)
                included_code.add(caller_code)

        return FILE_BOUNDARY.join(parts)

    def collect_files_included(self, primary_file: str,
                                upstream_deps: List[Dict],
                                downstream_callers: List[Dict]) -> List[str]:
        """Collect unique file paths from primary and all dependencies."""
        files: Set[str] = {primary_file}

        for dep in upstream_deps:
            file_path = dep.get('file_path', '')
            if file_path:
                files.add(file_path)

        for caller in downstream_callers:
            file_path = caller.get('file_path', '')
            if file_path:
                files.add(file_path)

        return sorted(list(files))

    def create_unit(self, func_id: str, func_data: Dict) -> Dict:
        """Create a single analysis unit with full context."""
        file_path = func_data.get('file_path', '')
        func_name = func_data.get('name', '')
        class_name = func_data.get('class_name')
        module_name = func_data.get('module_name')
        unit_type = func_data.get('unit_type', 'function')

        # Get upstream dependencies (functions this calls)
        upstream_ids = self.get_dependencies(func_id)
        upstream_deps = []
        for dep_id in upstream_ids:
            dep_func = self.functions.get(dep_id, {})
            if dep_func:
                upstream_deps.append({
                    'id': dep_id,
                    'name': dep_func.get('name'),
                    'code': dep_func.get('code', ''),
                    'file_path': dep_func.get('file_path', ''),
                    'unit_type': dep_func.get('unit_type', 'function'),
                    'class_name': dep_func.get('class_name'),
                })

        # Get downstream callers (functions that call this)
        caller_ids = self.get_callers(func_id)
        downstream_callers = []
        for caller_id in caller_ids:
            caller_func = self.functions.get(caller_id, {})
            if caller_func:
                downstream_callers.append({
                    'id': caller_id,
                    'name': caller_func.get('name'),
                    'code': caller_func.get('code', ''),
                    'file_path': caller_func.get('file_path', ''),
                    'unit_type': caller_func.get('unit_type', 'function'),
                    'class_name': caller_func.get('class_name'),
                })

        # Assemble enhanced code
        enhanced_code = self.assemble_enhanced_code(func_data, upstream_deps, downstream_callers)
        files_included = self.collect_files_included(file_path, upstream_deps, downstream_callers)
        has_deps_inlined = len(upstream_deps) > 0 or len(downstream_callers) > 0

        # Get direct calls/callers (depth 1 only)
        direct_calls = self.call_graph.get(func_id, [])
        direct_callers = self.reverse_call_graph.get(func_id, [])

        # Build the unit
        unit = {
            'id': func_id,
            'unit_type': unit_type,
            'code': {
                'primary_code': enhanced_code,
                'primary_origin': {
                    'file_path': file_path,
                    'start_line': func_data.get('start_line'),
                    'end_line': func_data.get('end_line'),
                    'function_name': func_name,
                    'class_name': class_name,
                    'deps_inlined': has_deps_inlined,
                    'files_included': files_included,
                    'original_length': len(func_data.get('code', '')),
                    'enhanced_length': len(enhanced_code),
                },
                'dependencies': [],
                'dependency_metadata': {
                    'depth': self.max_depth,
                    'total_upstream': len(upstream_deps),
                    'total_downstream': len(downstream_callers),
                    'direct_calls': len(direct_calls),
                    'direct_callers': len(direct_callers),
                }
            },
            'ground_truth': {
                'status': 'UNKNOWN',
                'vulnerability_types': [],
                'issues': [],
                'annotation_source': None,
                'annotation_key': None,
                'notes': None,
            },
            'metadata': {
                'is_singleton': func_data.get('is_singleton', False),
                'module_name': module_name,
                'parameters': func_data.get('parameters', []),
                'generator': 'ruby_unit_generator.py',
                'direct_calls': direct_calls,
                'direct_callers': direct_callers,
            }
        }

        return unit

    def update_statistics(self, unit: Dict) -> None:
        """Update statistics for a unit."""
        self.statistics['total_units'] += 1

        unit_type = unit.get('unit_type', 'function')
        self.statistics['by_type'][unit_type] = self.statistics['by_type'].get(unit_type, 0) + 1

        dep_meta = unit.get('code', {}).get('dependency_metadata', {})
        if dep_meta.get('total_upstream', 0) > 0:
            self.statistics['units_with_upstream'] += 1
        if dep_meta.get('total_downstream', 0) > 0:
            self.statistics['units_with_downstream'] += 1
        if unit.get('code', {}).get('primary_origin', {}).get('deps_inlined', False):
            self.statistics['units_enhanced'] += 1

    def generate_units(self) -> Dict:
        """Generate analysis units for all functions."""
        total_upstream = 0
        total_downstream = 0

        for func_id, func_data in self.functions.items():
            unit = self.create_unit(func_id, func_data)
            self.units.append(unit)
            self.update_statistics(unit)

            dep_meta = unit.get('code', {}).get('dependency_metadata', {})
            total_upstream += dep_meta.get('total_upstream', 0)
            total_downstream += dep_meta.get('total_downstream', 0)

        # Calculate averages
        if self.statistics['total_units'] > 0:
            self.statistics['avg_upstream'] = round(total_upstream / self.statistics['total_units'], 2)
            self.statistics['avg_downstream'] = round(total_downstream / self.statistics['total_units'], 2)

        return {
            'name': self.dataset_name,
            'repository': self.repo_path,
            'units': self.units,
            'statistics': self.statistics,
            'metadata': {
                'generator': 'ruby_unit_generator.py',
                'generated_at': datetime.now().isoformat(),
                'dependency_depth': self.max_depth,
            }
        }

    def generate_analyzer_output(self) -> Dict:
        """Generate analyzer_output.json with camelCase fields for compatibility."""
        functions = {}
        for func_id, func_data in self.functions.items():
            functions[func_id] = {
                'name': func_data.get('name', ''),
                'unitType': func_data.get('unit_type', 'function'),
                'code': func_data.get('code', ''),
                'filePath': func_data.get('file_path', ''),
                'startLine': func_data.get('start_line', 0),
                'endLine': func_data.get('end_line', 0),
                'isSingleton': func_data.get('is_singleton', False),
                'isExported': True,  # Ruby doesn't have explicit exports
                'moduleName': func_data.get('module_name'),
                'parameters': func_data.get('parameters', []),
                'className': func_data.get('class_name'),
            }

        return {
            'repository': self.repo_path,
            'functions': functions,
            'call_graph': self.call_graph,
            'reverse_call_graph': self.reverse_call_graph,
        }


def main():
    """Command line interface."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Generate analysis units from Ruby call graph data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python unit_generator.py call_graph.json
  python unit_generator.py call_graph.json --output dataset.json
  python unit_generator.py call_graph.json --depth 2 --name my_dataset
        '''
    )

    parser.add_argument('input_file', help='Call graph JSON file')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--analyzer-output', help='Path for analyzer_output.json')
    parser.add_argument('--depth', '-d', type=int, default=3,
                        help='Max dependency resolution depth (default: 3)')
    parser.add_argument('--name', '-n', help='Dataset name (default: derived from repo path)')

    args = parser.parse_args()

    try:
        with open(args.input_file) as f:
            call_graph_data = json.load(f)

        options = {
            'max_depth': args.depth,
        }
        if args.name:
            options['dataset_name'] = args.name

        print(f"Processing {len(call_graph_data.get('functions', {}))} functions...", file=sys.stderr)
        print(f"Dependency resolution depth: {args.depth}", file=sys.stderr)

        generator = UnitGenerator(call_graph_data, options)
        result = generator.generate_units()

        stats = result['statistics']
        print(f"\nDataset generated:", file=sys.stderr)
        print(f"  Total units: {stats['total_units']}", file=sys.stderr)
        print(f"  Units with upstream deps: {stats['units_with_upstream']}", file=sys.stderr)
        print(f"  Units with downstream callers: {stats['units_with_downstream']}", file=sys.stderr)
        print(f"  Enhanced units: {stats['units_enhanced']}", file=sys.stderr)
        print(f"  Avg upstream deps: {stats['avg_upstream']}", file=sys.stderr)
        print(f"  Avg downstream callers: {stats['avg_downstream']}", file=sys.stderr)
        print(f"\nBy type:", file=sys.stderr)
        for unit_type, count in sorted(stats['by_type'].items()):
            print(f"  {unit_type}: {count}", file=sys.stderr)

        output = json.dumps(result, indent=2)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"\nOutput written to: {args.output}", file=sys.stderr)
        else:
            print(output)

        # Write analyzer output if requested
        if args.analyzer_output:
            analyzer = generator.generate_analyzer_output()
            with open(args.analyzer_output, 'w') as f:
                json.dump(analyzer, f, indent=2)
            print(f"Analyzer output written to: {args.analyzer_output}", file=sys.stderr)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
