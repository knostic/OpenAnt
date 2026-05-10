#!/usr/bin/env python3
"""
Function Extractor for Ruby Codebases

Extracts ALL functions and class methods from Ruby source files using tree-sitter.
This is Phase 2 of the Ruby parser - function inventory.

Usage:
    python function_extractor.py <repo_path> [--output <file>] [--scan-file <scan.json>]

Output (JSON):
    {
        "repository": "/path/to/repo",
        "extraction_time": "2025-12-30T...",
        "functions": {
            "file.rb:ClassName.method_name": {
                "name": "method_name",
                "qualified_name": "ClassName.method_name",
                "file_path": "file.rb",
                "start_line": 10,
                "end_line": 25,
                "code": "def method_name(...)\\n  ...\\nend",
                "class_name": "ClassName",
                "module_name": "ModuleName",
                "parameters": ["param1", "param2"],
                "is_singleton": false,
                "unit_type": "method"
            }
        },
        "classes": { ... },
        "imports": { ... },
        "statistics": { ... }
    }
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import tree_sitter_ruby as ts_ruby
from tree_sitter import Language, Parser
from utilities.file_io import read_json, write_json, open_utf8


RUBY_LANGUAGE = Language(ts_ruby.language())


class FunctionExtractor:
    """
    Extract all functions and classes from Ruby source files using tree-sitter.

    This is Stage 2 of the Ruby parser pipeline.
    """

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()
        self.functions: Dict[str, Dict] = {}
        self.classes: Dict[str, Dict] = {}
        self.imports: Dict[str, Dict[str, str]] = {}

        self.parser = Parser(RUBY_LANGUAGE)

        self.file_cache: Dict[str, bytes] = {}

        self.stats = {
            'total_functions': 0,
            'total_classes': 0,
            'total_methods': 0,
            'standalone_functions': 0,
            'singleton_methods': 0,
            'files_processed': 0,
            'files_with_errors': 0,
            'by_type': {},
        }

    def read_file(self, file_path: Path) -> bytes:
        """Read and cache file contents as bytes (tree-sitter needs bytes)."""
        path_str = str(file_path)
        if path_str not in self.file_cache:
            try:
                self.file_cache[path_str] = file_path.read_bytes()
            except Exception as e:
                print(f"Warning: Cannot read {file_path}: {e}", file=sys.stderr)
                self.file_cache[path_str] = b""
        return self.file_cache[path_str]

    def _node_text(self, node, source: bytes) -> str:
        """Extract text from a tree-sitter node."""
        return source[node.start_byte:node.end_byte].decode('utf-8', errors='replace')

    def _get_method_name(self, node, source: bytes) -> Optional[str]:
        """Extract method name from a method or singleton_method node."""
        name_node = node.child_by_field_name('name')
        if name_node:
            return self._node_text(name_node, source)
        # Fallback: search for identifier child
        for child in node.children:
            if child.type == 'identifier':
                return self._node_text(child, source)
        return None

    def _get_parameters(self, node, source: bytes) -> List[str]:
        """Extract parameters from a method node."""
        params = []
        params_node = node.child_by_field_name('parameters')
        if params_node is None:
            # Look for method_parameters child
            for child in node.children:
                if child.type == 'method_parameters':
                    params_node = child
                    break

        if params_node is None:
            return params

        for child in params_node.children:
            if child.type in ('identifier', 'optional_parameter', 'splat_parameter',
                              'hash_splat_parameter', 'block_parameter',
                              'keyword_parameter', 'destructured_parameter'):
                param_text = self._node_text(child, source)
                params.append(param_text)

        return params

    def _classify_function(self, func_name: str, class_name: Optional[str],
                           module_name: Optional[str], is_singleton: bool,
                           file_path: str) -> str:
        """Classify a function by its type/purpose."""
        path_lower = file_path.lower()

        if func_name == 'initialize':
            return 'constructor'

        if is_singleton:
            return 'singleton_method'

        # Callbacks
        if func_name.startswith(('before_', 'after_', 'around_')):
            return 'callback'

        # Controller actions (route handlers)
        if class_name and 'controller' in (class_name.lower() if class_name else ''):
            return 'route_handler'
        if 'controllers' in path_lower:
            if class_name:
                return 'route_handler'

        # Inside a class
        if class_name:
            if func_name.startswith('_'):
                return 'private_method'
            return 'method'

        # Inside a module only (no class)
        if module_name and not class_name:
            return 'module_method'

        # Test functions
        if func_name.startswith('test_') or 'test' in path_lower or 'spec' in path_lower:
            return 'test'

        # Top-level
        return 'function'

    def _extract_imports(self, tree, source: bytes) -> Dict[str, str]:
        """Extract require/require_relative/include/extend/prepend from a file."""
        imports = {}
        stack = [tree.root_node]

        while stack:
            node = stack.pop()

            if node.type == 'call':
                # Check for require, require_relative, include, extend, prepend
                method_node = None
                for child in node.children:
                    if child.type == 'identifier':
                        method_node = child
                        break

                if method_node:
                    method_name = self._node_text(method_node, source)
                    if method_name in ('require', 'require_relative', 'include',
                                       'extend', 'prepend'):
                        # Extract the argument
                        arg_list = None
                        for child in node.children:
                            if child.type == 'argument_list':
                                arg_list = child
                                break

                        if arg_list:
                            for arg_child in arg_list.children:
                                if arg_child.type == 'string':
                                    # Extract string content
                                    for sc in arg_child.children:
                                        if sc.type == 'string_content':
                                            val = self._node_text(sc, source)
                                            imports[val] = method_name
                                            break
                                elif arg_child.type in ('constant', 'scope_resolution'):
                                    val = self._node_text(arg_child, source)
                                    imports[val] = method_name

            stack.extend(reversed(node.children))

        return imports

    def _extract_functions_from_tree(self, tree, source: bytes, file_path: Path,
                                     relative_path: str) -> None:
        """Extract all method definitions from a parsed tree."""
        # Stack-based traversal: (node, class_name, module_name)
        stack = [(tree.root_node, None, None)]

        while stack:
            node, class_name, module_name = stack.pop()

            if node.type == 'method':
                self._process_method_node(
                    node, source, relative_path, class_name, module_name,
                    is_singleton=False
                )

            elif node.type == 'singleton_method':
                self._process_method_node(
                    node, source, relative_path, class_name, module_name,
                    is_singleton=True
                )

            elif node.type == 'class':
                # Extract class name
                name_node = node.child_by_field_name('name')
                new_class_name = self._node_text(name_node, source) if name_node else None

                # Extract superclass
                superclass = None
                sup_node = node.child_by_field_name('superclass')
                if sup_node:
                    # Skip the '<' token
                    for child in sup_node.children:
                        if child.type != '<':
                            superclass = self._node_text(child, source)
                            break

                if new_class_name:
                    class_id = f"{relative_path}:{new_class_name}"
                    body_node = node.child_by_field_name('body')
                    methods = []
                    if body_node:
                        for child in body_node.children:
                            if child.type == 'method':
                                mname = self._get_method_name(child, source)
                                if mname:
                                    methods.append(mname)
                            elif child.type == 'singleton_method':
                                mname = self._get_method_name(child, source)
                                if mname:
                                    methods.append(f"self.{mname}")

                    self.classes[class_id] = {
                        'name': new_class_name,
                        'file_path': relative_path,
                        'start_line': node.start_point[0] + 1,
                        'end_line': node.end_point[0] + 1,
                        'methods': methods,
                        'superclass': superclass,
                        'module_name': module_name,
                    }
                    self.stats['total_classes'] += 1

                # Recurse into class body with updated class_name
                body_node = node.child_by_field_name('body')
                if body_node:
                    for child in reversed(body_node.children):
                        stack.append((child, new_class_name, module_name))
                continue  # Don't walk children again

            elif node.type == 'module':
                # Extract module name
                name_node = None
                for child in node.children:
                    if child.type == 'constant':
                        name_node = child
                        break
                new_module_name = self._node_text(name_node, source) if name_node else module_name

                # Recurse into module body
                body_node = node.child_by_field_name('body')
                if body_node is None:
                    # Try finding body_statement child
                    for child in node.children:
                        if child.type == 'body_statement':
                            body_node = child
                            break

                if body_node:
                    for child in reversed(body_node.children):
                        stack.append((child, class_name, new_module_name))
                continue  # Don't walk children again

            else:
                for child in reversed(node.children):
                    stack.append((child, class_name, module_name))

    def _process_method_node(self, node, source: bytes, relative_path: str,
                              class_name: Optional[str], module_name: Optional[str],
                              is_singleton: bool) -> None:
        """Process a single method or singleton_method node."""
        name = self._get_method_name(node, source)
        if not name:
            return

        code = self._node_text(node, source)
        start_line = node.start_point[0] + 1  # tree-sitter is 0-indexed
        end_line = node.end_point[0] + 1
        parameters = self._get_parameters(node, source)

        unit_type = self._classify_function(
            name, class_name, module_name, is_singleton, relative_path
        )

        # Build qualified name and function ID
        if class_name:
            qualified_name = f"{class_name}.{name}"
        elif module_name:
            qualified_name = f"{module_name}.{name}"
        else:
            qualified_name = name

        func_id = f"{relative_path}:{qualified_name}"

        func_data = {
            'name': name,
            'qualified_name': qualified_name,
            'file_path': relative_path,
            'start_line': start_line,
            'end_line': end_line,
            'code': code,
            'class_name': class_name,
            'module_name': module_name,
            'parameters': parameters,
            'is_singleton': is_singleton,
            'unit_type': unit_type,
        }

        self.functions[func_id] = func_data
        self.stats['total_functions'] += 1

        if class_name:
            self.stats['total_methods'] += 1
        else:
            self.stats['standalone_functions'] += 1

        if is_singleton:
            self.stats['singleton_methods'] += 1

        self.stats['by_type'][unit_type] = self.stats['by_type'].get(unit_type, 0) + 1

    def process_file(self, file_path: Path) -> None:
        """Process a single Ruby file."""
        source = self.read_file(file_path)
        if not source:
            self.stats['files_with_errors'] += 1
            return

        relative_path = str(file_path.relative_to(self.repo_path))

        try:
            tree = self.parser.parse(source)
        except Exception as e:
            print(f"Parse error in {file_path}: {e}", file=sys.stderr)
            self.stats['files_with_errors'] += 1
            return

        self.stats['files_processed'] += 1

        # Extract imports
        self.imports[relative_path] = self._extract_imports(tree, source)

        # Extract functions
        self._extract_functions_from_tree(tree, source, file_path, relative_path)

    def extract_from_scan(self, scan_result: Dict) -> Dict:
        """Extract functions from files listed in a scan result."""
        for file_info in scan_result.get('files', []):
            file_path = self.repo_path / file_info['path']
            self.process_file(file_path)

        return self.export()

    def extract_all(self, files: Optional[List[str]] = None) -> Dict:
        """Extract functions from all Ruby files or a specific list."""
        if files:
            for file_rel_path in files:
                file_path = self.repo_path / file_rel_path
                if file_path.exists():
                    self.process_file(file_path)
        else:
            for ext in ('.rb', '.rake'):
                for file_path in self.repo_path.rglob(f'*{ext}'):
                    path_str = str(file_path)
                    if any(excl in path_str for excl in ['.git', 'vendor', '.bundle', 'tmp', 'node_modules']):
                        continue
                    self.process_file(file_path)

        return self.export()

    def export(self) -> Dict:
        """Export extraction results."""
        return {
            'repository': str(self.repo_path),
            'extraction_time': datetime.now().isoformat(),
            'functions': self.functions,
            'classes': self.classes,
            'imports': self.imports,
            'statistics': self.stats,
        }


def main():
    """Command line interface."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Extract all functions and classes from a Ruby repository',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python function_extractor.py /path/to/repo
  python function_extractor.py /path/to/repo --output functions.json
  python function_extractor.py /path/to/repo --scan-file scan_results.json
        '''
    )

    parser.add_argument('repo_path', help='Path to the repository')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--scan-file', help='Use file list from repository scanner output')

    args = parser.parse_args()

    try:
        extractor = FunctionExtractor(args.repo_path)

        if args.scan_file:
            scan_result = read_json(args.scan_file)
            result = extractor.extract_from_scan(scan_result)
        else:
            result = extractor.extract_all()

        output = json.dumps(result, indent=2)

        if args.output:
            with open_utf8(args.output, 'w') as f:
                f.write(output)
            print(f"Extraction complete. Results written to: {args.output}", file=sys.stderr)
            print(f"Total functions: {result['statistics']['total_functions']}", file=sys.stderr)
            print(f"  Standalone: {result['statistics']['standalone_functions']}", file=sys.stderr)
            print(f"  Methods: {result['statistics']['total_methods']}", file=sys.stderr)
            print(f"  Singleton methods: {result['statistics']['singleton_methods']}", file=sys.stderr)
            print(f"Total classes: {result['statistics']['total_classes']}", file=sys.stderr)
            print(f"Files processed: {result['statistics']['files_processed']}", file=sys.stderr)
            if result['statistics']['files_with_errors'] > 0:
                print(f"Files with errors: {result['statistics']['files_with_errors']}", file=sys.stderr)
            print(f"By type:", file=sys.stderr)
            for unit_type, count in sorted(result['statistics']['by_type'].items()):
                print(f"  {unit_type}: {count}", file=sys.stderr)
        else:
            print(output)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
