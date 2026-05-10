#!/usr/bin/env python3
"""
Call Graph Builder for PHP Codebases

Builds bidirectional call graphs from extracted function data:
- Forward graph: function -> functions it calls
- Reverse graph: function -> functions that call it

This is Phase 3 of the PHP parser - dependency resolution.

Usage:
    python call_graph_builder.py <extractor_output.json> [--output <file>] [--depth <N>]

Output (JSON):
    {
        "functions": {...},
        "call_graph": {
            "file.php:func1": ["file.php:func2", "other.php:func3"],
            ...
        },
        "reverse_call_graph": {
            "file.php:func2": ["file.php:func1"],
            ...
        },
        "statistics": {
            "total_edges": 500,
            "avg_out_degree": 2.5,
            "max_out_degree": 15,
            "isolated_functions": 20
        }
    }
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

import tree_sitter_php as ts_php
from tree_sitter import Language, Parser
from utilities.file_io import read_json, write_json, open_utf8


PHP_LANGUAGE = Language(ts_php.language_php())

# PHP builtins and common functions to filter out
PHP_BUILTINS = {
    'echo', 'print', 'print_r', 'var_dump', 'var_export',
    'die', 'exit', 'isset', 'unset', 'empty',
    'array', 'list', 'count', 'sizeof', 'strlen', 'substr',
    'strpos', 'str_replace', 'trim', 'ltrim', 'rtrim',
    'strtolower', 'strtoupper', 'ucfirst', 'lcfirst', 'ucwords',
    'explode', 'implode', 'join',
    'array_push', 'array_pop', 'array_shift', 'array_unshift',
    'array_merge', 'array_keys', 'array_values', 'array_map',
    'array_filter', 'array_reduce', 'array_unique', 'array_reverse',
    'array_slice', 'array_splice', 'in_array', 'array_search',
    'array_key_exists', 'sort', 'asort', 'ksort', 'usort',
    'rsort', 'arsort', 'krsort',
    'is_array', 'is_string', 'is_int', 'is_integer', 'is_numeric',
    'is_bool', 'is_null', 'is_object', 'is_callable',
    'intval', 'floatval', 'strval', 'boolval', 'settype', 'gettype',
    'class_exists', 'method_exists', 'property_exists', 'function_exists',
    'get_class', 'get_parent_class', 'is_a', 'instanceof',
    'json_encode', 'json_decode', 'serialize', 'unserialize',
    'date', 'time', 'strtotime', 'mktime',
    'sprintf', 'printf', 'number_format',
    'abs', 'ceil', 'floor', 'round', 'min', 'max',
    'rand', 'mt_rand', 'array_rand',
    'file_get_contents', 'file_put_contents', 'file_exists',
    'is_file', 'is_dir', 'mkdir', 'rmdir', 'unlink', 'rename',
    'copy', 'move_uploaded_file', 'pathinfo', 'basename', 'dirname',
    'realpath', 'glob',
    'header', 'setcookie', 'session_start', 'session_destroy',
    'htmlspecialchars', 'htmlentities', 'strip_tags',
    'addslashes', 'stripslashes', 'nl2br',
    'urlencode', 'urldecode', 'rawurlencode', 'rawurldecode',
    'base64_encode', 'base64_decode',
    'md5', 'sha1', 'hash', 'password_hash', 'password_verify',
    'preg_match', 'preg_match_all', 'preg_replace', 'preg_split',
    'trigger_error', 'throw',
    'compact', 'extract', 'defined', 'define', 'constant',
    'array_walk', 'array_combine', 'array_flip', 'array_fill',
    'array_chunk', 'array_column', 'array_pad',
    'array_intersect', 'array_diff', 'range',
    'call_user_func', 'call_user_func_array',
}

# PHP keywords to skip in regex fallback
PHP_KEYWORDS = {
    'if', 'else', 'elseif', 'while', 'for', 'foreach',
    'switch', 'case', 'break', 'continue', 'return',
    'try', 'catch', 'finally', 'throw', 'new',
    'class', 'function', 'interface', 'trait',
    'namespace', 'use', 'require', 'require_once',
    'include', 'include_once', 'echo', 'print',
}


class CallGraphBuilder:
    """
    Build bidirectional call graphs from extracted PHP function data.

    This is Stage 3 of the PHP parser pipeline.
    """

    def __init__(self, extractor_output: Dict, options: Optional[Dict] = None):
        options = options or {}

        self.functions = extractor_output.get('functions', {})
        self.classes = extractor_output.get('classes', {})
        self.imports = extractor_output.get('imports', {})
        self.repo_path = extractor_output.get('repository', '')

        self.max_depth = options.get('max_depth', 3)

        # Call graphs
        self.call_graph: Dict[str, List[str]] = {}
        self.reverse_call_graph: Dict[str, List[str]] = {}

        # Indexes for faster lookup
        self.functions_by_name: Dict[str, List[str]] = {}
        self.functions_by_file: Dict[str, List[str]] = {}
        self.methods_by_class: Dict[str, List[str]] = {}

        self._build_indexes()

        # Parser for re-parsing function bodies
        self.php_parser = Parser(PHP_LANGUAGE)

    def _build_indexes(self) -> None:
        """Build lookup indexes for faster resolution."""
        for func_id, func_data in self.functions.items():
            name = func_data.get('name', '')
            if name:
                if name not in self.functions_by_name:
                    self.functions_by_name[name] = []
                self.functions_by_name[name].append(func_id)

            file_path = func_data.get('file_path', '')
            if file_path:
                if file_path not in self.functions_by_file:
                    self.functions_by_file[file_path] = []
                self.functions_by_file[file_path].append(func_id)

            class_name = func_data.get('class_name')
            if class_name:
                class_key = f"{file_path}:{class_name}"
                if class_key not in self.methods_by_class:
                    self.methods_by_class[class_key] = []
                self.methods_by_class[class_key].append(func_id)

    def _is_builtin(self, name: str) -> bool:
        """Check if name is a PHP builtin or common function."""
        return name in PHP_BUILTINS

    def _extract_calls_from_code(self, code: str, caller_id: str) -> Set[str]:
        """Extract function call references from code using tree-sitter."""
        calls = set()
        caller_file = caller_id.split(':')[0]
        caller_func = self.functions.get(caller_id, {})
        caller_class = caller_func.get('class_name')

        code_bytes = code.encode('utf-8', errors='replace')
        try:
            tree = self.php_parser.parse(code_bytes)
        except Exception:
            return self._extract_calls_regex(code, caller_id)

        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type in ('function_call_expression', 'member_call_expression',
                             'scoped_call_expression'):
                resolved = self._resolve_call_node(node, code_bytes, caller_file, caller_class)
                if resolved:
                    calls.add(resolved)
            stack.extend(reversed(node.children))

        return calls

    def _resolve_call_node(self, node, source: bytes, caller_file: str,
                           caller_class: Optional[str]) -> Optional[str]:
        """Resolve a tree-sitter call node to a function ID."""
        if node.type == 'function_call_expression':
            return self._resolve_function_call(node, source, caller_file, caller_class)
        elif node.type == 'member_call_expression':
            return self._resolve_member_call(node, source, caller_file, caller_class)
        elif node.type == 'scoped_call_expression':
            return self._resolve_scoped_call(node, source, caller_file, caller_class)
        return None

    def _resolve_function_call(self, node, source: bytes, caller_file: str,
                                caller_class: Optional[str]) -> Optional[str]:
        """Resolve a simple function call like func()."""
        func_name = None

        for child in node.children:
            if child.type in ('name', 'identifier'):
                func_name = source[child.start_byte:child.end_byte].decode('utf-8', errors='replace')
                break
            elif child.type == 'qualified_name':
                func_name = source[child.start_byte:child.end_byte].decode('utf-8', errors='replace')
                # Use just the last segment for resolution
                if '\\' in func_name:
                    func_name = func_name.rsplit('\\', 1)[-1]
                break

        if not func_name:
            return None

        if self._is_builtin(func_name):
            return None

        return self._resolve_simple_call(func_name, caller_file, caller_class)

    def _resolve_member_call(self, node, source: bytes, caller_file: str,
                              caller_class: Optional[str]) -> Optional[str]:
        """Resolve a member call like $obj->method()."""
        method_name = None
        receiver = None

        for child in node.children:
            if child.type == 'name':
                method_name = source[child.start_byte:child.end_byte].decode('utf-8', errors='replace')
            elif child.type in ('->', 'arguments'):
                continue
            elif child.type == 'variable_name':
                receiver = source[child.start_byte:child.end_byte].decode('utf-8', errors='replace')

        if not method_name:
            return None

        if self._is_builtin(method_name):
            return None

        # $this->method() - same class
        if receiver == '$this' and caller_class:
            return self._resolve_self_call(method_name, caller_file, caller_class)

        return None

    def _resolve_scoped_call(self, node, source: bytes, caller_file: str,
                              caller_class: Optional[str]) -> Optional[str]:
        """Resolve a scoped call like ClassName::method()."""
        method_name = None
        scope = None

        for child in node.children:
            if child.type == 'name' and scope is not None:
                method_name = source[child.start_byte:child.end_byte].decode('utf-8', errors='replace')
            elif child.type in ('name', 'qualified_name') and scope is None:
                scope = source[child.start_byte:child.end_byte].decode('utf-8', errors='replace')
                if '\\' in scope:
                    scope = scope.rsplit('\\', 1)[-1]
            elif child.type == '::':
                continue

        if not method_name or not scope:
            return None

        if self._is_builtin(method_name):
            return None

        # self::method() or static::method() - same class
        if scope in ('self', 'static', 'parent') and caller_class:
            return self._resolve_self_call(method_name, caller_file, caller_class)

        # ClassName::method()
        return self._resolve_class_call(scope, method_name, caller_file)

    def _resolve_simple_call(self, func_name: str, caller_file: str,
                             caller_class: Optional[str]) -> Optional[str]:
        """Resolve a simple function call to a function ID."""
        # 1. Check same class first (implicit $this)
        if caller_class:
            result = self._resolve_self_call(func_name, caller_file, caller_class)
            if result:
                return result

        # 2. Check same file
        same_file_funcs = self.functions_by_file.get(caller_file, [])
        for func_id in same_file_funcs:
            func_data = self.functions.get(func_id, {})
            if func_data.get('name') == func_name and not func_data.get('class_name'):
                return func_id

        # 3. Check use/require-resolved files
        file_imports = self.imports.get(caller_file, {})
        for import_name, import_type in file_imports.items():
            if import_type in ('require', 'require_once', 'include', 'include_once', 'use'):
                # Try matching import path to file
                for file_path in self.functions_by_file:
                    if file_path.endswith(f"{import_name}.php") or import_name in file_path:
                        file_funcs = self.functions_by_file[file_path]
                        for func_id in file_funcs:
                            func_data = self.functions.get(func_id, {})
                            if func_data.get('name') == func_name:
                                return func_id

        # 4. Unique name match across files
        candidates = self.functions_by_name.get(func_name, [])
        candidates = [c for c in candidates if not self.functions.get(c, {}).get('class_name')]
        if len(candidates) == 1:
            return candidates[0]

        return None

    def _resolve_self_call(self, method_name: str, caller_file: str,
                           caller_class: str) -> Optional[str]:
        """Resolve a $this->method() or self::method() call within a class."""
        class_key = f"{caller_file}:{caller_class}"
        class_methods = self.methods_by_class.get(class_key, [])

        for func_id in class_methods:
            func_data = self.functions.get(func_id, {})
            if func_data.get('name') == method_name:
                return func_id

        return None

    def _resolve_class_call(self, class_name: str, method_name: str,
                            caller_file: str) -> Optional[str]:
        """Resolve a ClassName::method() call."""
        # Check same file first
        class_key = f"{caller_file}:{class_name}"
        if class_key in self.methods_by_class:
            for func_id in self.methods_by_class[class_key]:
                func_data = self.functions.get(func_id, {})
                if func_data.get('name') == method_name:
                    return func_id

        # Check all files for the class
        for key, func_ids in self.methods_by_class.items():
            if key.endswith(f":{class_name}"):
                for func_id in func_ids:
                    func_data = self.functions.get(func_id, {})
                    if func_data.get('name') == method_name:
                        return func_id

        return None

    def _extract_calls_regex(self, code: str, caller_id: str) -> Set[str]:
        """Fallback regex-based call extraction for unparseable code."""
        calls = set()
        caller_file = caller_id.split(':')[0]

        # Match function calls: name(
        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*[\(]'
        for match in re.finditer(pattern, code):
            func_name = match.group(1)
            # Skip PHP keywords
            if func_name in PHP_KEYWORDS:
                continue
            if not self._is_builtin(func_name):
                resolved = self._resolve_simple_call(func_name, caller_file, None)
                if resolved:
                    calls.add(resolved)

        return calls

    def build_call_graph(self) -> None:
        """Build the complete call graph for all functions."""
        for func_id, func_data in self.functions.items():
            code = func_data.get('code', '')
            if not code:
                self.call_graph[func_id] = []
                continue

            calls = self._extract_calls_from_code(code, func_id)

            # Filter to valid function IDs (must exist, not self-calls)
            valid_calls = [c for c in calls if c in self.functions and c != func_id]
            self.call_graph[func_id] = valid_calls

            # Build reverse graph
            for called_id in valid_calls:
                if called_id not in self.reverse_call_graph:
                    self.reverse_call_graph[called_id] = []
                if func_id not in self.reverse_call_graph[called_id]:
                    self.reverse_call_graph[called_id].append(func_id)

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

    def get_statistics(self) -> Dict:
        """Calculate call graph statistics."""
        total_edges = sum(len(calls) for calls in self.call_graph.values())
        num_funcs = len(self.functions)

        out_degrees = [len(self.call_graph.get(f, [])) for f in self.functions]
        in_degrees = [len(self.reverse_call_graph.get(f, [])) for f in self.functions]

        isolated = sum(1 for f in self.functions
                       if len(self.call_graph.get(f, [])) == 0
                       and len(self.reverse_call_graph.get(f, [])) == 0)

        return {
            'total_functions': num_funcs,
            'total_edges': total_edges,
            'avg_out_degree': round(total_edges / num_funcs, 2) if num_funcs > 0 else 0,
            'avg_in_degree': round(total_edges / num_funcs, 2) if num_funcs > 0 else 0,
            'max_out_degree': max(out_degrees) if out_degrees else 0,
            'max_in_degree': max(in_degrees) if in_degrees else 0,
            'isolated_functions': isolated,
        }

    def export(self) -> Dict:
        """Export the call graph data."""
        return {
            'repository': self.repo_path,
            'functions': self.functions,
            'classes': self.classes,
            'imports': self.imports,
            'call_graph': self.call_graph,
            'reverse_call_graph': self.reverse_call_graph,
            'statistics': self.get_statistics(),
        }


def main():
    """Command line interface."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Build call graphs from extracted PHP function data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python call_graph_builder.py functions.json
  python call_graph_builder.py functions.json --output call_graph.json
  python call_graph_builder.py functions.json --depth 5
        '''
    )

    parser.add_argument('input_file', help='Function extractor output JSON file')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--depth', '-d', type=int, default=3,
                        help='Max dependency resolution depth (default: 3)')

    args = parser.parse_args()

    try:
        extractor_output = read_json(args.input_file)
        print(f"Processing {len(extractor_output.get('functions', {}))} functions...", file=sys.stderr)

        builder = CallGraphBuilder(extractor_output, {'max_depth': args.depth})
        builder.build_call_graph()

        result = builder.export()
        stats = result['statistics']

        print(f"Call graph built:", file=sys.stderr)
        print(f"  Total functions: {stats['total_functions']}", file=sys.stderr)
        print(f"  Total edges: {stats['total_edges']}", file=sys.stderr)
        print(f"  Avg out-degree: {stats['avg_out_degree']}", file=sys.stderr)
        print(f"  Max out-degree: {stats['max_out_degree']}", file=sys.stderr)
        print(f"  Isolated functions: {stats['isolated_functions']}", file=sys.stderr)

        output = json.dumps(result, indent=2)

        if args.output:
            with open_utf8(args.output, 'w') as f:
                f.write(output)
            print(f"Output written to: {args.output}", file=sys.stderr)
        else:
            print(output)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
