#!/usr/bin/env python3
"""
Call Graph Builder for C/C++ Codebases

Builds bidirectional call graphs from extracted function data:
- Forward graph: function -> functions it calls
- Reverse graph: function -> functions that call it

This is Phase 3 of the C/C++ parser - dependency resolution.

Usage:
    python call_graph_builder.py <extractor_output.json> [--output <file>] [--depth <N>]

Output (JSON):
    {
        "functions": {...},
        "call_graph": {
            "file.c:func1": ["file.c:func2", "other.c:func3"],
            ...
        },
        "reverse_call_graph": {
            "file.c:func2": ["file.c:func1"],
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

import tree_sitter_c as tsc
import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser
from utilities.file_io import read_json, write_json, open_utf8


C_LANGUAGE = Language(tsc.language())
CPP_LANGUAGE = Language(tscpp.language())

C_EXTENSIONS = {'.c', '.h'}
CPP_EXTENSIONS = {'.cpp', '.hpp', '.cc', '.cxx', '.hxx', '.hh'}

# Standard C library functions to filter out
STDLIB_FUNCTIONS = {
    # Memory
    'malloc', 'calloc', 'realloc', 'free',
    # I/O
    'printf', 'fprintf', 'sprintf', 'snprintf', 'vprintf', 'vfprintf',
    'vsprintf', 'vsnprintf', 'scanf', 'fscanf', 'sscanf',
    'fopen', 'fclose', 'fread', 'fwrite', 'fgets', 'fputs',
    'fseek', 'ftell', 'rewind', 'fflush', 'feof', 'ferror',
    'puts', 'getchar', 'putchar', 'getc', 'putc', 'ungetc',
    'perror',
    # String
    'memcpy', 'memset', 'memmove', 'memcmp', 'memchr',
    'strlen', 'strcmp', 'strncmp', 'strcpy', 'strncpy',
    'strcat', 'strncat', 'strstr', 'strchr', 'strrchr',
    'strtok', 'strerror', 'strdup', 'strndup',
    # Conversion
    'atoi', 'atol', 'atof', 'strtol', 'strtoul', 'strtoll',
    'strtoull', 'strtod', 'strtof',
    # General
    'exit', 'abort', '_exit', 'atexit',
    'qsort', 'bsearch', 'abs', 'labs',
    'getenv', 'setenv', 'system',
    # Assert
    'assert',
    # Operators / keywords that look like calls
    'sizeof', 'offsetof', 'typeof', 'alignof',
    '__builtin_expect', '__builtin_unreachable',
    # va_args
    'va_start', 'va_end', 'va_arg', 'va_copy',
    # POSIX
    'close', 'read', 'write', 'open', 'lseek',
    'mmap', 'munmap', 'mprotect',
    'socket', 'bind', 'listen', 'accept', 'connect',
    'send', 'recv', 'sendto', 'recvfrom',
    'select', 'poll', 'epoll_create', 'epoll_ctl', 'epoll_wait',
    'fork', 'exec', 'execve', 'execvp', 'waitpid',
    'pthread_create', 'pthread_join', 'pthread_mutex_lock', 'pthread_mutex_unlock',
    'signal', 'sigaction',
    # C++ standard
    'std', 'move', 'forward', 'make_shared', 'make_unique',
    'static_cast', 'dynamic_cast', 'reinterpret_cast', 'const_cast',
    'new', 'delete',
}


class CallGraphBuilder:
    """
    Build bidirectional call graphs from extracted C/C++ function data.

    This is Stage 3 of the C/C++ parser pipeline.
    """

    def __init__(self, extractor_output: Dict, options: Optional[Dict] = None):
        options = options or {}

        self.functions = extractor_output.get('functions', {})
        self.includes = extractor_output.get('includes', {})
        self.macros = extractor_output.get('macros', {})
        self.macro_aliases = extractor_output.get('macro_aliases', {})
        self.prototypes = extractor_output.get('prototypes', {})
        self.repo_path = extractor_output.get('repository', '')

        self.max_depth = options.get('max_depth', 3)

        # Call graphs
        self.call_graph: Dict[str, List[str]] = {}
        self.reverse_call_graph: Dict[str, List[str]] = {}

        # Indexes for faster lookup
        self.functions_by_name: Dict[str, List[str]] = {}
        self.functions_by_file: Dict[str, List[str]] = {}

        # Include map: file -> set of included header files
        self.include_map: Dict[str, Set[str]] = {}

        self._build_indexes()

        # Parsers for re-parsing function bodies
        self.c_parser = Parser(C_LANGUAGE)
        self.cpp_parser = Parser(CPP_LANGUAGE)

    def _build_indexes(self) -> None:
        """Build lookup indexes for faster resolution."""
        for func_id, func_data in self.functions.items():
            name = func_data.get('name', '')
            if name:
                # Use the base name (without namespace/class prefix)
                base_name = name.split('::')[-1] if '::' in name else name
                if base_name not in self.functions_by_name:
                    self.functions_by_name[base_name] = []
                self.functions_by_name[base_name].append(func_id)
                # Also index by full name if different
                if name != base_name:
                    if name not in self.functions_by_name:
                        self.functions_by_name[name] = []
                    self.functions_by_name[name].append(func_id)

            file_path = func_data.get('file_path', '')
            if file_path:
                if file_path not in self.functions_by_file:
                    self.functions_by_file[file_path] = []
                self.functions_by_file[file_path].append(func_id)

        # Build include map
        for file_path, inc_list in self.includes.items():
            self.include_map[file_path] = set()
            for inc in inc_list:
                # Match included header to files in repo
                for other_file in self.functions_by_file:
                    if other_file.endswith(inc) or other_file.endswith('/' + inc):
                        self.include_map[file_path].add(other_file)

    def _is_stdlib(self, name: str) -> bool:
        """Check if name is a standard library function."""
        return name in STDLIB_FUNCTIONS

    def _get_parser_for_file(self, file_path: str) -> Parser:
        ext = Path(file_path).suffix.lower()
        if ext in CPP_EXTENSIONS:
            return self.cpp_parser
        return self.c_parser

    def _extract_calls_from_code(self, code: str, caller_id: str) -> Set[str]:
        """Extract function call references from code using tree-sitter."""
        calls = set()
        caller_file = caller_id.split(':')[0]
        func_data = self.functions.get(caller_id, {})
        file_path = func_data.get('file_path', caller_file)

        parser = self._get_parser_for_file(file_path)

        # Wrap in a dummy function if needed for parsing
        code_bytes = code.encode('utf-8', errors='replace')
        try:
            tree = parser.parse(code_bytes)
        except Exception:
            return self._extract_calls_regex(code, caller_id)

        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type == 'call_expression':
                func_node = node.child_by_field_name('function')
                if func_node:
                    call_name = self._extract_call_name(func_node, code_bytes)
                    if call_name:
                        resolved = self._resolve_call(call_name, caller_file)
                        if resolved:
                            calls.add(resolved)
            stack.extend(reversed(node.children))
        return calls

    def _extract_call_name(self, node, source: bytes) -> Optional[str]:
        """Extract the function name from a call_expression's function child."""
        text = source[node.start_byte:node.end_byte].decode('utf-8', errors='replace')

        if node.type == 'identifier':
            return text

        if node.type == 'field_expression':
            # obj->method or obj.method - extract the field name
            field = node.child_by_field_name('field')
            if field:
                return source[field.start_byte:field.end_byte].decode('utf-8', errors='replace')

        if node.type == 'qualified_identifier':
            return text

        if node.type == 'template_function':
            name_node = node.child_by_field_name('name')
            if name_node:
                return source[name_node.start_byte:name_node.end_byte].decode('utf-8', errors='replace')

        if node.type == 'parenthesized_expression':
            # Function pointer call: (*func_ptr)(args)
            return None

        return text if text.isidentifier() else None

    def _resolve_call(self, call_name: str, caller_file: str) -> Optional[str]:
        """Resolve a function call name to a function ID."""
        if self._is_stdlib(call_name):
            return None

        # Check for macro aliases
        resolved_name = self.macro_aliases.get(call_name, call_name)
        if resolved_name != call_name:
            # Try resolving the aliased name instead
            result = self._resolve_call(resolved_name, caller_file)
            if result:
                return result

        # 1. Same-file functions
        same_file_funcs = self.functions_by_file.get(caller_file, [])
        for func_id in same_file_funcs:
            func_data = self.functions.get(func_id, {})
            fname = func_data.get('name', '')
            base_name = fname.split('::')[-1] if '::' in fname else fname
            if base_name == call_name:
                return func_id

        # 2. Functions in included headers
        included_files = self.include_map.get(caller_file, set())
        for inc_file in included_files:
            file_funcs = self.functions_by_file.get(inc_file, [])
            for func_id in file_funcs:
                func_data = self.functions.get(func_id, {})
                fname = func_data.get('name', '')
                base_name = fname.split('::')[-1] if '::' in fname else fname
                if base_name == call_name:
                    return func_id

        # 3. Unique name match across entire repo
        candidates = self.functions_by_name.get(call_name, [])
        if len(candidates) == 1:
            return candidates[0]

        # 4. If prototype exists, try to find the definition
        if call_name in self.prototypes:
            proto = self.prototypes[call_name]
            # Look for a definition (non-header)
            for func_id in candidates:
                func_data = self.functions.get(func_id, {})
                fp = func_data.get('file_path', '')
                ext = Path(fp).suffix.lower()
                if ext in {'.c', '.cpp', '.cc', '.cxx'}:
                    return func_id

        return None

    def _extract_calls_regex(self, code: str, caller_id: str) -> Set[str]:
        """Fallback regex-based call extraction."""
        calls = set()
        caller_file = caller_id.split(':')[0]

        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        for match in re.finditer(pattern, code):
            func_name = match.group(1)
            # Skip C keywords that look like function calls
            if func_name in ('if', 'while', 'for', 'switch', 'return', 'sizeof',
                             'typeof', 'alignof', 'offsetof', 'case', 'else'):
                continue
            if not self._is_stdlib(func_name):
                resolved = self._resolve_call(func_name, caller_file)
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
            'includes': self.includes,
            'macros': self.macros,
            'macro_aliases': self.macro_aliases,
            'prototypes': self.prototypes,
            'call_graph': self.call_graph,
            'reverse_call_graph': self.reverse_call_graph,
            'statistics': self.get_statistics(),
        }


def main():
    """Command line interface."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Build call graphs from extracted C/C++ function data',
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
