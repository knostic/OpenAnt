#!/usr/bin/env python3
"""
Call Graph Builder for Python Codebases

Builds bidirectional call graphs from extracted function data:
- Forward graph: function → functions it calls
- Reverse graph: function → functions that call it

This is Phase 3 of the Python parser - dependency resolution.

Usage:
    python call_graph_builder.py <extractor_output.json> [--output <file>] [--depth <N>]

Output (JSON):
    {
        "functions": {...},  # From extractor, enhanced
        "call_graph": {
            "file.py:func1": ["file.py:func2", "other.py:func3"],
            ...
        },
        "reverse_call_graph": {
            "file.py:func2": ["file.py:func1"],
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

import ast
import json
import re
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from utilities.file_io import read_json, write_json, open_utf8


class CallGraphBuilder:
    """
    Build bidirectional call graphs from extracted Python function data.

    This is Stage 3 of the Python parser pipeline. It analyzes function bodies
    to determine which functions call which, creating two complementary graphs:

    1. Forward call graph (call_graph):
       Maps each function to the functions it calls.
       Example: {'file.py:main': ['file.py:helper', 'utils.py:validate']}

    2. Reverse call graph (reverse_call_graph):
       Maps each function to the functions that call it.
       Example: {'utils.py:validate': ['file.py:main', 'app.py:run']}

    Call Resolution Strategy:
    The builder resolves function calls in this priority order:
    1. Same-file functions (most reliable)
    2. Imported modules/functions (uses import tracking from extractor)
    3. Class methods for self.method() calls
    4. Name-based matching across files (fallback, less reliable)

    Skipped Calls:
    - Python builtins (print, len, range, etc.)
    - Common object methods (append, strip, get, etc.)
    - Standard library functions

    Usage:
        builder = CallGraphBuilder(extractor_output)
        builder.build_call_graph()
        result = builder.export()
        # Use result['call_graph'] and result['reverse_call_graph']

    Attributes:
        call_graph: Forward graph (func_id → [called_func_ids])
        reverse_call_graph: Reverse graph (func_id → [caller_func_ids])
        functions_by_name: Index for name-based lookup
        functions_by_file: Index for file-based lookup
        methods_by_class: Index for class method lookup
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

    def _build_indexes(self) -> None:
        """Build lookup indexes for faster resolution."""
        for func_id, func_data in self.functions.items():
            # Index by simple name
            name = func_data.get('name', '')
            if name:
                if name not in self.functions_by_name:
                    self.functions_by_name[name] = []
                self.functions_by_name[name].append(func_id)

            # Index by file path
            file_path = func_data.get('file_path', '')
            if file_path:
                if file_path not in self.functions_by_file:
                    self.functions_by_file[file_path] = []
                self.functions_by_file[file_path].append(func_id)

            # Index methods by class
            class_name = func_data.get('class_name')
            if class_name:
                class_key = f"{file_path}:{class_name}"
                if class_key not in self.methods_by_class:
                    self.methods_by_class[class_key] = []
                self.methods_by_class[class_key].append(func_id)

    def _is_builtin(self, name: str) -> bool:
        """Check if name is a Python builtin or standard library function."""
        builtins = {
            # Builtin functions
            'print', 'len', 'range', 'str', 'int', 'float', 'bool', 'list', 'dict',
            'set', 'tuple', 'type', 'isinstance', 'issubclass', 'hasattr', 'getattr',
            'setattr', 'delattr', 'callable', 'super', 'next', 'iter', 'enumerate',
            'zip', 'map', 'filter', 'sorted', 'reversed', 'min', 'max', 'sum', 'abs',
            'round', 'pow', 'divmod', 'hex', 'oct', 'bin', 'ord', 'chr', 'ascii',
            'repr', 'format', 'hash', 'id', 'input', 'open', 'eval', 'exec', 'compile',
            'globals', 'locals', 'vars', 'dir', 'help', 'exit', 'quit',
            'staticmethod', 'classmethod', 'property', 'object', 'Exception',
            'BaseException', 'ValueError', 'TypeError', 'KeyError', 'IndexError',
            'AttributeError', 'RuntimeError', 'StopIteration', 'NotImplementedError',

            # Common standard library
            'json', 'os', 'sys', 're', 'datetime', 'time', 'math', 'random',
            'collections', 'itertools', 'functools', 'operator', 'copy',
            'pickle', 'shelve', 'sqlite3', 'csv', 'io', 'pathlib', 'shutil',
            'subprocess', 'threading', 'multiprocessing', 'asyncio', 'socket',
            'http', 'urllib', 'email', 'html', 'xml', 'logging', 'unittest',
            'typing', 'dataclasses', 'contextlib', 'abc', 'inspect', 'traceback',
        }
        return name in builtins

    def _is_common_method(self, method_name: str) -> bool:
        """Check if method name is a common object method unlikely to be custom."""
        common_methods = {
            # String methods
            'strip', 'split', 'join', 'replace', 'lower', 'upper', 'format',
            'startswith', 'endswith', 'find', 'index', 'count', 'encode', 'decode',
            # List/dict methods
            'append', 'extend', 'insert', 'remove', 'pop', 'clear', 'copy',
            'keys', 'values', 'items', 'get', 'update', 'setdefault',
            # Common patterns
            'close', 'read', 'write', 'seek', 'flush', 'readline', 'readlines',
            'send', 'recv', 'connect', 'bind', 'listen', 'accept',
            # Iteration
            '__iter__', '__next__', '__enter__', '__exit__',
        }
        return method_name in common_methods

    def _extract_calls_from_code(self, code: str, caller_id: str) -> Set[str]:
        """Extract function call references from code using AST."""
        calls = set()
        caller_file = caller_id.split(':')[0]
        caller_func = self.functions.get(caller_id, {})
        caller_class = caller_func.get('class_name')

        try:
            tree = ast.parse(textwrap.dedent(code))
        except SyntaxError:
            # Fall back to regex-based extraction
            return self._extract_calls_regex(code, caller_id)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                resolved = self._resolve_call_node(node, caller_file, caller_class)
                if resolved:
                    calls.add(resolved)

        return calls

    def _resolve_call_node(self, node: ast.Call, caller_file: str, caller_class: Optional[str]) -> Optional[str]:
        """Resolve an AST Call node to a function ID."""
        func = node.func

        # Simple function call: func_name(...)
        if isinstance(func, ast.Name):
            func_name = func.id
            if self._is_builtin(func_name):
                return None
            return self._resolve_simple_call(func_name, caller_file)

        # Method call: obj.method(...)
        elif isinstance(func, ast.Attribute):
            method_name = func.attr
            obj = func.value

            # self.method(...) - same class
            if isinstance(obj, ast.Name) and obj.id == 'self':
                if caller_class:
                    return self._resolve_self_call(method_name, caller_file, caller_class)
                return None

            # cls.method(...) - classmethod
            if isinstance(obj, ast.Name) and obj.id == 'cls':
                if caller_class:
                    return self._resolve_self_call(method_name, caller_file, caller_class)
                return None

            # super().method(...)
            if isinstance(obj, ast.Call) and isinstance(obj.func, ast.Name) and obj.func.id == 'super':
                # Would need to resolve parent class - skip for now
                return None

            # module.func(...) or object.method(...)
            if isinstance(obj, ast.Name):
                obj_name = obj.id
                return self._resolve_module_call(obj_name, method_name, caller_file)

            # Chained calls: obj.method1().method2(...)
            # Skip common methods
            if self._is_common_method(method_name):
                return None

        return None

    def _resolve_simple_call(self, func_name: str, caller_file: str) -> Optional[str]:
        """Resolve a simple function call to a function ID."""
        # 1. Check same file first
        same_file_funcs = self.functions_by_file.get(caller_file, [])
        for func_id in same_file_funcs:
            func_data = self.functions.get(func_id, {})
            if func_data.get('name') == func_name and not func_data.get('class_name'):
                return func_id

        # 2. Check imports and resolve
        file_imports = self.imports.get(caller_file, {})
        if func_name in file_imports:
            import_path = file_imports[func_name]
            # Try to find the function in the codebase
            return self._resolve_import(import_path, func_name, caller_file)

        # 3. Check by simple name across files (single match only)
        candidates = self.functions_by_name.get(func_name, [])
        # Filter to non-method functions
        candidates = [c for c in candidates if not self.functions.get(c, {}).get('class_name')]
        if len(candidates) == 1:
            return candidates[0]

        return None

    def _resolve_self_call(self, method_name: str, caller_file: str, caller_class: str) -> Optional[str]:
        """Resolve a self.method() call within a class."""
        class_key = f"{caller_file}:{caller_class}"
        class_methods = self.methods_by_class.get(class_key, [])

        for func_id in class_methods:
            func_data = self.functions.get(func_id, {})
            if func_data.get('name') == method_name:
                return func_id

        return None

    def _resolve_module_call(self, obj_name: str, method_name: str, caller_file: str) -> Optional[str]:
        """Resolve a module.function() or object.method() call."""
        # Skip builtin modules
        if self._is_builtin(obj_name):
            return None

        # Check if obj_name is an imported module/class
        file_imports = self.imports.get(caller_file, {})
        if obj_name in file_imports:
            import_path = file_imports[obj_name]
            # Try to resolve the method in the imported module/class
            return self._resolve_import(import_path, method_name, caller_file)

        # Check if obj_name is a class in the same file
        class_key = f"{caller_file}:{obj_name}"
        if class_key in self.methods_by_class:
            class_methods = self.methods_by_class[class_key]
            for func_id in class_methods:
                func_data = self.functions.get(func_id, {})
                if func_data.get('name') == method_name:
                    return func_id

        return None

    def _resolve_import(self, import_path: str, func_name: str, caller_file: str) -> Optional[str]:
        """Resolve an imported function to a function ID."""
        # import_path might be "module.submodule.function" or "module.ClassName"
        parts = import_path.split('.')

        # Try to find a matching file and function
        # Strategy 1: Look for file matching module path
        for i in range(len(parts), 0, -1):
            potential_file = '/'.join(parts[:i]) + '.py'
            remaining = parts[i:]

            if potential_file in self.functions_by_file:
                # Found a matching file
                file_funcs = self.functions_by_file[potential_file]

                # Look for the function
                target_name = func_name
                if remaining:
                    # It's a class method: ClassName.method
                    class_name = remaining[0] if remaining else None
                    if class_name:
                        target_id = f"{potential_file}:{class_name}.{func_name}"
                        if target_id in self.functions:
                            return target_id

                # Look for standalone function
                target_id = f"{potential_file}:{target_name}"
                if target_id in self.functions:
                    return target_id

        # Strategy 2: Check if import_path itself is a function
        for func_id in self.functions:
            func_data = self.functions[func_id]
            if func_data.get('name') == parts[-1]:
                # Check if file path matches module path
                file_path = func_data.get('file_path', '')
                module_path = file_path.replace('/', '.').replace('.py', '')
                expected_module = '.'.join(parts[:-1])
                if module_path.endswith(expected_module) or expected_module.endswith(module_path):
                    return func_id

        return None

    def _extract_calls_regex(self, code: str, caller_id: str) -> Set[str]:
        """Fallback regex-based call extraction for unparseable code."""
        calls = set()
        caller_file = caller_id.split(':')[0]

        # Match function calls: name(
        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        for match in re.finditer(pattern, code):
            func_name = match.group(1)
            if not self._is_builtin(func_name):
                resolved = self._resolve_simple_call(func_name, caller_file)
                if resolved:
                    calls.add(resolved)

        return calls

    def build_call_graph(self) -> None:
        """
        Build the complete call graph for all functions.

        This is the main entry point for call graph construction. It iterates
        through all extracted functions, analyzes their code to find function
        calls, and builds both forward and reverse graphs.

        The forward graph (call_graph) answers: "What functions does X call?"
        The reverse graph (reverse_call_graph) answers: "What functions call X?"

        Both graphs are essential for security analysis:
        - Forward: Track data flow from entry points to sinks
        - Reverse: Find all paths that reach a vulnerable function
        """
        for func_id, func_data in self.functions.items():
            code = func_data.get('code', '')
            if not code:
                self.call_graph[func_id] = []
                continue

            # Extract all function calls from this function's code
            calls = self._extract_calls_from_code(code, func_id)

            # Filter to valid function IDs (must exist in our codebase, not self-calls)
            valid_calls = [c for c in calls if c in self.functions and c != func_id]
            self.call_graph[func_id] = valid_calls

            # Build reverse graph: for each called function, record this caller
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
        description='Build call graphs from extracted Python function data',
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
