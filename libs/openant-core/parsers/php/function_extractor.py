#!/usr/bin/env python3
"""
Function Extractor for PHP Codebases

Extracts ALL functions and class methods from PHP source files using tree-sitter.
This is Phase 2 of the PHP parser - function inventory.

Usage:
    python function_extractor.py <repo_path> [--output <file>] [--scan-file <scan.json>]

Output (JSON):
    {
        "repository": "/path/to/repo",
        "extraction_time": "2025-12-30T...",
        "functions": {
            "file.php:ClassName.method_name": {
                "name": "method_name",
                "qualified_name": "ClassName.method_name",
                "file_path": "file.php",
                "start_line": 10,
                "end_line": 25,
                "code": "public function method_name(...)\\n{ ... }",
                "class_name": "ClassName",
                "namespace_name": "App\\Controllers",
                "parameters": ["$param1", "$param2"],
                "is_static": false,
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

import tree_sitter_php as ts_php
from tree_sitter import Language, Parser
from utilities.file_io import read_json, write_json, open_utf8


PHP_LANGUAGE = Language(ts_php.language_php())

# PHP magic methods (besides __construct which is classified as constructor)
PHP_MAGIC_METHODS = {
    '__destruct', '__call', '__callStatic', '__get', '__set', '__isset',
    '__unset', '__sleep', '__wakeup', '__serialize', '__unserialize',
    '__toString', '__invoke', '__set_state', '__clone', '__debugInfo',
}


class FunctionExtractor:
    """
    Extract all functions and classes from PHP source files using tree-sitter.

    This is Stage 2 of the PHP parser pipeline.
    """

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()
        self.functions: Dict[str, Dict] = {}
        self.classes: Dict[str, Dict] = {}
        self.imports: Dict[str, Dict[str, str]] = {}

        self.parser = Parser(PHP_LANGUAGE)

        self.file_cache: Dict[str, bytes] = {}

        self.stats = {
            'total_functions': 0,
            'total_classes': 0,
            'total_methods': 0,
            'standalone_functions': 0,
            'static_methods': 0,
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

    def _get_function_name(self, node, source: bytes) -> Optional[str]:
        """Extract function/method name from a function_definition or method_declaration node."""
        name_node = node.child_by_field_name('name')
        if name_node:
            return self._node_text(name_node, source)
        # Fallback: search for name child
        for child in node.children:
            if child.type == 'name':
                return self._node_text(child, source)
        return None

    def _get_parameters(self, node, source: bytes) -> List[str]:
        """Extract parameters from a function/method node."""
        params = []
        params_node = node.child_by_field_name('parameters')
        if params_node is None:
            # Look for formal_parameters child
            for child in node.children:
                if child.type == 'formal_parameters':
                    params_node = child
                    break

        if params_node is None:
            return params

        for child in params_node.children:
            if child.type in ('simple_parameter', 'variadic_parameter',
                              'property_promotion_parameter'):
                param_text = self._node_text(child, source)
                params.append(param_text)

        return params

    def _is_static_method(self, node, source: bytes) -> bool:
        """Check if a method_declaration has a static modifier."""
        for child in node.children:
            if child.type == 'static_modifier':
                return True
        return False

    def _get_visibility(self, node, source: bytes) -> Optional[str]:
        """Extract visibility modifier from a method_declaration node."""
        for child in node.children:
            if child.type == 'visibility_modifier':
                return self._node_text(child, source)
        return None

    def _classify_function(self, func_name: str, class_name: Optional[str],
                           namespace_name: Optional[str], is_static: bool,
                           file_path: str) -> str:
        """Classify a function by its type/purpose."""
        path_lower = file_path.lower()

        # Constructor
        if func_name == '__construct':
            return 'constructor'

        # Magic methods
        if func_name in PHP_MAGIC_METHODS:
            return 'magic_method'

        # Static methods
        if is_static:
            return 'static_method'

        # Controller actions (route handlers)
        if class_name and 'controller' in class_name.lower():
            return 'route_handler'
        if 'controllers' in path_lower or 'controller' in path_lower:
            if class_name:
                return 'route_handler'

        # Inside a class
        if class_name:
            if func_name.startswith('_'):
                return 'private_method'
            return 'method'

        # Private top-level functions (convention)
        if func_name.startswith('_'):
            return 'private_function'

        # Test functions
        if func_name.startswith('test') or 'test' in path_lower or 'spec' in path_lower:
            return 'test'

        # Top-level function
        return 'function'

    def _extract_imports(self, tree, source: bytes) -> Dict[str, str]:
        """Extract use declarations, namespace definitions, and include/require from a file."""
        imports = {}
        stack = [tree.root_node]

        while stack:
            node = stack.pop()

            if node.type == 'use_declaration':
                # Extract the full use statement value
                import_text = self._node_text(node, source)
                # Clean up: remove 'use ' prefix and trailing ';'
                cleaned = import_text.strip()
                if cleaned.startswith('use '):
                    cleaned = cleaned[4:]
                cleaned = cleaned.rstrip(';').strip()
                imports[cleaned] = 'use'

            elif node.type == 'namespace_definition':
                # Extract namespace name
                name_node = node.child_by_field_name('name')
                if name_node:
                    ns_name = self._node_text(name_node, source)
                    imports[ns_name] = 'namespace'

            elif node.type in ('include_expression', 'require_expression',
                               'include_once_expression', 'require_once_expression'):
                # Extract the included/required file path
                arg_text = self._node_text(node, source)
                # Extract the type (include, require, etc.)
                import_type = node.type.replace('_expression', '')
                imports[arg_text] = import_type

            stack.extend(reversed(node.children))

        return imports

    def _extract_functions_from_tree(self, tree, source: bytes, file_path: Path,
                                     relative_path: str) -> None:
        """Extract all function/method definitions from a parsed tree."""
        # Stack-based traversal: (node, class_name, namespace_name)
        stack = [(tree.root_node, None, None)]

        while stack:
            node, class_name, namespace_name = stack.pop()

            if node.type == 'function_definition':
                self._process_function_node(
                    node, source, relative_path, class_name, namespace_name,
                    is_static=False
                )

            elif node.type == 'method_declaration':
                is_static = self._is_static_method(node, source)
                self._process_function_node(
                    node, source, relative_path, class_name, namespace_name,
                    is_static=is_static
                )

            elif node.type == 'class_declaration':
                # Extract class name
                name_node = node.child_by_field_name('name')
                new_class_name = self._node_text(name_node, source) if name_node else None

                # Extract superclass (extends)
                superclass = None
                for child in node.children:
                    if child.type == 'base_clause':
                        for base_child in child.children:
                            if base_child.type == 'name' or base_child.type == 'qualified_name':
                                superclass = self._node_text(base_child, source)
                                break
                        break

                # Extract interfaces (implements)
                interfaces = []
                for child in node.children:
                    if child.type == 'class_interface_clause':
                        for iface_child in child.children:
                            if iface_child.type in ('name', 'qualified_name'):
                                interfaces.append(self._node_text(iface_child, source))
                        break

                if new_class_name:
                    class_id = f"{relative_path}:{new_class_name}"
                    methods = []
                    # Find declaration_list (class body)
                    body_node = node.child_by_field_name('body')
                    if body_node is None:
                        for child in node.children:
                            if child.type == 'declaration_list':
                                body_node = child
                                break

                    if body_node:
                        for child in body_node.children:
                            if child.type == 'method_declaration':
                                mname = self._get_function_name(child, source)
                                if mname:
                                    if self._is_static_method(child, source):
                                        methods.append(f"static:{mname}")
                                    else:
                                        methods.append(mname)

                    self.classes[class_id] = {
                        'name': new_class_name,
                        'file_path': relative_path,
                        'start_line': node.start_point[0] + 1,
                        'end_line': node.end_point[0] + 1,
                        'methods': methods,
                        'superclass': superclass,
                        'interfaces': interfaces,
                        'namespace_name': namespace_name,
                    }
                    self.stats['total_classes'] += 1

                # Recurse into class body with updated class_name
                if body_node:
                    for child in reversed(body_node.children):
                        stack.append((child, new_class_name, namespace_name))
                continue  # Don't walk children again

            elif node.type == 'interface_declaration':
                # Extract interface name
                name_node = node.child_by_field_name('name')
                new_iface_name = self._node_text(name_node, source) if name_node else None

                if new_iface_name:
                    class_id = f"{relative_path}:{new_iface_name}"
                    methods = []
                    body_node = node.child_by_field_name('body')
                    if body_node is None:
                        for child in node.children:
                            if child.type == 'declaration_list':
                                body_node = child
                                break

                    if body_node:
                        for child in body_node.children:
                            if child.type == 'method_declaration':
                                mname = self._get_function_name(child, source)
                                if mname:
                                    methods.append(mname)

                    self.classes[class_id] = {
                        'name': new_iface_name,
                        'file_path': relative_path,
                        'start_line': node.start_point[0] + 1,
                        'end_line': node.end_point[0] + 1,
                        'methods': methods,
                        'superclass': None,
                        'interfaces': [],
                        'namespace_name': namespace_name,
                    }
                    self.stats['total_classes'] += 1

                if body_node:
                    for child in reversed(body_node.children):
                        stack.append((child, new_iface_name, namespace_name))
                continue

            elif node.type == 'trait_declaration':
                # Extract trait name
                name_node = node.child_by_field_name('name')
                new_trait_name = self._node_text(name_node, source) if name_node else None

                if new_trait_name:
                    class_id = f"{relative_path}:{new_trait_name}"
                    methods = []
                    body_node = node.child_by_field_name('body')
                    if body_node is None:
                        for child in node.children:
                            if child.type == 'declaration_list':
                                body_node = child
                                break

                    if body_node:
                        for child in body_node.children:
                            if child.type == 'method_declaration':
                                mname = self._get_function_name(child, source)
                                if mname:
                                    methods.append(mname)

                    self.classes[class_id] = {
                        'name': new_trait_name,
                        'file_path': relative_path,
                        'start_line': node.start_point[0] + 1,
                        'end_line': node.end_point[0] + 1,
                        'methods': methods,
                        'superclass': None,
                        'interfaces': [],
                        'namespace_name': namespace_name,
                    }
                    self.stats['total_classes'] += 1

                if body_node:
                    for child in reversed(body_node.children):
                        stack.append((child, new_trait_name, namespace_name))
                continue

            elif node.type == 'namespace_definition':
                # Extract namespace name
                name_node = node.child_by_field_name('name')
                new_namespace_name = self._node_text(name_node, source) if name_node else namespace_name

                # Recurse into namespace body
                body_node = node.child_by_field_name('body')
                if body_node is None:
                    # Namespace without braces covers rest of file; recurse children directly
                    for child in reversed(node.children):
                        if child.type not in ('namespace', 'name', ';'):
                            stack.append((child, class_name, new_namespace_name))
                else:
                    for child in reversed(body_node.children):
                        stack.append((child, class_name, new_namespace_name))
                continue  # Don't walk children again

            else:
                for child in reversed(node.children):
                    stack.append((child, class_name, namespace_name))

    def _process_function_node(self, node, source: bytes, relative_path: str,
                                class_name: Optional[str], namespace_name: Optional[str],
                                is_static: bool) -> None:
        """Process a single function_definition or method_declaration node."""
        name = self._get_function_name(node, source)
        if not name:
            return

        code = self._node_text(node, source)
        start_line = node.start_point[0] + 1  # tree-sitter is 0-indexed
        end_line = node.end_point[0] + 1
        parameters = self._get_parameters(node, source)

        unit_type = self._classify_function(
            name, class_name, namespace_name, is_static, relative_path
        )

        # Build qualified name and function ID
        if class_name:
            qualified_name = f"{class_name}.{name}"
        elif namespace_name:
            qualified_name = f"{namespace_name}\\{name}"
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
            'namespace_name': namespace_name,
            'parameters': parameters,
            'is_static': is_static,
            'unit_type': unit_type,
        }

        self.functions[func_id] = func_data
        self.stats['total_functions'] += 1

        if class_name:
            self.stats['total_methods'] += 1
        else:
            self.stats['standalone_functions'] += 1

        if is_static:
            self.stats['static_methods'] += 1

        self.stats['by_type'][unit_type] = self.stats['by_type'].get(unit_type, 0) + 1

    def process_file(self, file_path: Path) -> None:
        """Process a single PHP file."""
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
        """Extract functions from all PHP files or a specific list."""
        if files:
            for file_rel_path in files:
                file_path = self.repo_path / file_rel_path
                if file_path.exists():
                    self.process_file(file_path)
        else:
            for ext in ('.php', '.phtml'):
                for file_path in self.repo_path.rglob(f'*{ext}'):
                    path_str = str(file_path)
                    if any(excl in path_str for excl in ['.git', 'vendor', 'node_modules', 'tmp', '.cache']):
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
        description='Extract all functions and classes from a PHP repository',
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
            print(f"  Static methods: {result['statistics']['static_methods']}", file=sys.stderr)
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
