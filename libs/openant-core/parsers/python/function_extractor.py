#!/usr/bin/env python3
"""
Function Extractor for Python Codebases

Extracts ALL functions and class methods from Python source files using AST.
This is Phase 2 of the Python parser - function inventory.

Usage:
    python function_extractor.py <repo_path> [--output <file>] [--scan-file <scan.json>]

Output (JSON):
    {
        "repository": "/path/to/repo",
        "extraction_time": "2025-12-30T...",
        "functions": {
            "file.py:function_name": {
                "name": "function_name",
                "qualified_name": "module.function_name",
                "file_path": "file.py",
                "start_line": 10,
                "end_line": 25,
                "code": "def function_name(...):\\n    ...",
                "class_name": null,
                "decorators": ["@decorator"],
                "is_async": false,
                "parameters": ["param1", "param2"],
                "docstring": "Function docstring...",
                "unit_type": "function"
            }
        },
        "classes": {
            "file.py:ClassName": {
                "name": "ClassName",
                "file_path": "file.py",
                "start_line": 5,
                "end_line": 50,
                "methods": ["method1", "method2"],
                "bases": ["BaseClass"],
                "decorators": []
            }
        },
        "imports": {
            "file.py": {
                "os": "os",
                "Path": "pathlib.Path",
                "json": "json"
            }
        },
        "statistics": {
            "total_functions": 150,
            "total_classes": 25,
            "total_methods": 100,
            "by_type": {...},
            "files_processed": 50,
            "files_with_errors": 2
        }
    }
"""

import ast
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from utilities.file_io import read_json, write_json, open_utf8


class FunctionExtractor:
    """
    Extract all functions and classes from Python source files using AST.

    This is Stage 2 of the Python parser pipeline. It parses each Python file
    and extracts:
    - Standalone functions (top-level def statements)
    - Class definitions and their methods
    - Module-level code (executable code outside functions/classes)

    The module-level extraction is CRITICAL for detecting vulnerabilities in:
    - Streamlit apps (code runs at module level)
    - Scripts with global initialization
    - Configuration files with dynamic evaluation

    Key features:
    - Uses Python's AST for reliable parsing
    - Extracts decorators, parameters, docstrings
    - Classifies functions by type (route_handler, constructor, etc.)
    - Creates synthetic __module__ units for module-level code

    Usage:
        extractor = FunctionExtractor('/path/to/repo')
        result = extractor.extract_all()  # Process all .py files
        # OR
        result = extractor.extract_from_scan(scan_result)  # Use scanner output

    Attributes:
        repo_path: Absolute path to the repository root
        functions: Dict mapping func_id to function metadata
        classes: Dict mapping class_id to class metadata
        imports: Dict mapping file_path to import statements
    """

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()
        self.functions: Dict[str, Dict] = {}
        self.classes: Dict[str, Dict] = {}
        self.imports: Dict[str, Dict[str, str]] = {}

        # File cache
        self.file_cache: Dict[str, str] = {}

        # Statistics
        self.stats = {
            'total_functions': 0,
            'total_classes': 0,
            'total_methods': 0,
            'standalone_functions': 0,
            'module_level_units': 0,
            'async_functions': 0,
            'files_processed': 0,
            'files_with_errors': 0,
            'by_type': {},
        }

    def read_file(self, file_path: Path) -> str:
        """Read and cache file contents."""
        path_str = str(file_path)
        if path_str not in self.file_cache:
            try:
                self.file_cache[path_str] = file_path.read_text(encoding='utf-8', errors='replace')
            except Exception as e:
                print(f"Warning: Cannot read {file_path}: {e}", file=sys.stderr)
                self.file_cache[path_str] = ""
        return self.file_cache[path_str]

    def get_source_segment(self, content: str, node: ast.AST) -> str:
        """Extract source code for an AST node."""
        lines = content.split('\n')

        # Get line range
        start_line = node.lineno - 1  # 0-indexed
        end_line = getattr(node, 'end_lineno', start_line + 1)

        # Include decorators if present
        if hasattr(node, 'decorator_list') and node.decorator_list:
            first_decorator_line = min(d.lineno for d in node.decorator_list) - 1
            start_line = min(start_line, first_decorator_line)

        # Extract lines
        source_lines = lines[start_line:end_line]
        return '\n'.join(source_lines)

    def extract_decorators(self, node: ast.AST) -> List[str]:
        """Extract decorator names from a function or class."""
        decorators = []
        if hasattr(node, 'decorator_list'):
            for dec in node.decorator_list:
                if isinstance(dec, ast.Name):
                    decorators.append(f"@{dec.id}")
                elif isinstance(dec, ast.Attribute):
                    decorators.append(f"@{self._get_attribute_string(dec)}")
                elif isinstance(dec, ast.Call):
                    if isinstance(dec.func, ast.Name):
                        decorators.append(f"@{dec.func.id}(...)")
                    elif isinstance(dec.func, ast.Attribute):
                        decorators.append(f"@{self._get_attribute_string(dec.func)}(...)")
        return decorators

    def extract_parameters(self, node: ast.FunctionDef) -> List[str]:
        """Extract parameter names from a function definition."""
        params = []
        args = node.args

        # Positional args
        for arg in args.args:
            params.append(arg.arg)

        # *args
        if args.vararg:
            params.append(f"*{args.vararg.arg}")

        # Keyword-only args
        for arg in args.kwonlyargs:
            params.append(arg.arg)

        # **kwargs
        if args.kwarg:
            params.append(f"**{args.kwarg.arg}")

        return params

    def get_docstring(self, node: ast.AST) -> Optional[str]:
        """Extract docstring from a function or class."""
        return ast.get_docstring(node)

    def classify_function(self, func_name: str, decorators: List[str],
                          class_name: Optional[str], file_path: str) -> str:
        """Classify a function by its type/purpose."""
        dec_str = ' '.join(decorators).lower()
        path_lower = file_path.lower()

        # Route handlers
        if '@app.route' in dec_str or '@router.' in dec_str or '@blueprint.' in dec_str:
            return 'route_handler'
        if '@get' in dec_str or '@post' in dec_str or '@put' in dec_str or '@delete' in dec_str:
            return 'route_handler'

        # Django views
        if 'views' in path_lower and class_name is None:
            return 'view_function'

        # Class methods
        if class_name:
            if func_name == '__init__':
                return 'constructor'
            if func_name.startswith('__') and func_name.endswith('__'):
                return 'dunder_method'
            if '@property' in dec_str:
                return 'property'
            if '@staticmethod' in dec_str:
                return 'static_method'
            if '@classmethod' in dec_str:
                return 'class_method'
            return 'method'

        # Middleware/decorators
        if 'middleware' in func_name.lower() or 'middleware' in path_lower:
            return 'middleware'

        # Test functions
        if func_name.startswith('test_') or 'test' in path_lower:
            return 'test'

        # Utility functions
        if func_name.startswith('_') and not func_name.startswith('__'):
            return 'private_function'

        return 'function'

    def _get_attribute_string(self, node: ast.Attribute) -> str:
        """Get full attribute string (e.g., 'module.submodule.attr')."""
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        parts.reverse()
        return '.'.join(parts)

    def extract_imports(self, tree: ast.AST, file_path: str) -> Dict[str, str]:
        """Extract all imports from a file."""
        imports = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name
                    imports[name] = alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ''
                for alias in node.names:
                    name = alias.asname or alias.name
                    full_path = f"{module}.{alias.name}" if module else alias.name
                    imports[name] = full_path

        return imports

    def process_function(self, node: ast.FunctionDef, file_path: str,
                         content: str, class_name: Optional[str] = None) -> Dict:
        """Process a function definition and extract metadata."""
        func_name = node.name
        qualified_name = f"{class_name}.{func_name}" if class_name else func_name

        # Generate unique ID
        relative_path = str(Path(file_path).relative_to(self.repo_path))
        func_id = f"{relative_path}:{qualified_name}"

        # Extract metadata
        decorators = self.extract_decorators(node)
        parameters = self.extract_parameters(node)
        docstring = self.get_docstring(node)
        code = self.get_source_segment(content, node)
        is_async = isinstance(node, ast.AsyncFunctionDef)
        unit_type = self.classify_function(func_name, decorators, class_name, relative_path)

        func_data = {
            'name': func_name,
            'qualified_name': qualified_name,
            'file_path': relative_path,
            'start_line': node.lineno,
            'end_line': getattr(node, 'end_lineno', node.lineno),
            'code': code,
            'class_name': class_name,
            'decorators': decorators,
            'is_async': is_async,
            'parameters': parameters,
            'docstring': docstring[:500] if docstring else None,  # Truncate long docstrings
            'unit_type': unit_type,
        }

        return func_id, func_data

    def process_class(self, node: ast.ClassDef, file_path: str, content: str) -> Tuple[str, Dict, List[Tuple]]:
        """Process a class definition and extract metadata."""
        class_name = node.name
        relative_path = str(Path(file_path).relative_to(self.repo_path))
        class_id = f"{relative_path}:{class_name}"

        # Extract base classes
        bases = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                bases.append(base.id)
            elif isinstance(base, ast.Attribute):
                bases.append(self._get_attribute_string(base))

        decorators = self.extract_decorators(node)

        # Collect methods
        methods = []
        method_funcs = []
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                methods.append(item.name)
                method_funcs.append(item)

        class_data = {
            'name': class_name,
            'file_path': relative_path,
            'start_line': node.lineno,
            'end_line': getattr(node, 'end_lineno', node.lineno),
            'methods': methods,
            'bases': bases,
            'decorators': decorators,
            'docstring': self.get_docstring(node),
        }

        return class_id, class_data, [(m, class_name) for m in method_funcs]

    def extract_module_level_code(self, tree: ast.AST, content: str,
                                    file_path: Path) -> Optional[Tuple[str, Dict]]:
        """
        Extract module-level code that is not inside functions or classes.

        This is a CRITICAL function for vulnerability detection. Many Python
        applications (especially Streamlit, scripts, and CLI tools) have
        significant executable code at module level that would otherwise
        be missed by function-only extraction.

        Example of vulnerable module-level code this captures:
            # In a Streamlit app:
            user_input = st.text_input("Enter expression")
            result = eval(user_input)  # RCE vulnerability at module level!

        The function works by:
        1. Identifying which lines are covered by functions/classes
        2. Collecting all uncovered lines (module-level code)
        3. Filtering to only executable code (not just imports/comments)
        4. Creating a synthetic __module__ unit

        Args:
            tree: Parsed AST of the file
            content: Raw file content as string
            file_path: Path to the source file

        Returns:
            tuple: (func_id, func_data) where func_id is "file.py:__module__"
                   and func_data contains the extracted code and metadata.
                   Returns None if no significant module-level code found.

        Note:
            The unit_type for module-level code is 'module_level' and the
            function name is '__module__' (synthetic identifier).
        """
        lines = content.split('\n')
        total_lines = len(lines)

        # Track which lines are covered by functions/classes
        covered_lines: Set[int] = set()

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                start_line = node.lineno
                end_line = getattr(node, 'end_lineno', start_line)

                # Include decorators
                if hasattr(node, 'decorator_list') and node.decorator_list:
                    first_decorator = min(d.lineno for d in node.decorator_list)
                    start_line = min(start_line, first_decorator)

                for line_num in range(start_line, end_line + 1):
                    covered_lines.add(line_num)

        # Collect uncovered lines (module-level code)
        module_level_lines = []
        for line_num in range(1, total_lines + 1):  # 1-indexed like AST
            if line_num not in covered_lines:
                module_level_lines.append((line_num, lines[line_num - 1]))

        # Filter out empty lines and pure comments at the start
        # but keep all code including imports
        significant_lines = []
        for line_num, line in module_level_lines:
            stripped = line.strip()
            # Keep all non-empty lines (imports, assignments, calls, etc.)
            if stripped and not stripped.startswith('#'):
                significant_lines.append((line_num, line))
            elif stripped.startswith('#') and significant_lines:
                # Keep comments that appear after code (inline documentation)
                significant_lines.append((line_num, line))

        # Skip if no significant module-level code
        if not significant_lines:
            return None

        # Check if there's actual executable code (not just imports)
        has_executable_code = False
        for _, line in significant_lines:
            stripped = line.strip()
            # Skip pure import lines
            if stripped.startswith('import ') or stripped.startswith('from '):
                continue
            # Skip docstrings
            if stripped.startswith('"""') or stripped.startswith("'''"):
                continue
            # Found executable code
            if stripped:
                has_executable_code = True
                break

        if not has_executable_code:
            return None

        # Build module-level code string
        # Include ALL module-level code for complete context
        module_code_lines = []
        for line_num, line in module_level_lines:
            module_code_lines.append(line)

        module_code = '\n'.join(module_code_lines)

        # Remove leading/trailing empty lines but preserve internal structure
        module_code = module_code.strip()

        if not module_code:
            return None

        relative_path = str(file_path.relative_to(self.repo_path))
        func_id = f"{relative_path}:__module__"

        # Determine start and end lines
        start_line = significant_lines[0][0] if significant_lines else 1
        end_line = significant_lines[-1][0] if significant_lines else total_lines

        func_data = {
            'name': '__module__',
            'qualified_name': '__module__',
            'file_path': relative_path,
            'start_line': start_line,
            'end_line': end_line,
            'code': module_code,
            'class_name': None,
            'decorators': [],
            'is_async': False,
            'parameters': [],
            'docstring': None,
            'unit_type': 'module_level',
            'is_module_level': True,
        }

        return func_id, func_data

    def process_file(self, file_path: Path) -> None:
        """Process a single Python file."""
        content = self.read_file(file_path)
        if not content:
            self.stats['files_with_errors'] += 1
            return

        try:
            tree = ast.parse(content)
        except SyntaxError as e:
            print(f"Syntax error in {file_path}: {e}", file=sys.stderr)
            self.stats['files_with_errors'] += 1
            return

        self.stats['files_processed'] += 1
        relative_path = str(file_path.relative_to(self.repo_path))

        # Extract imports
        self.imports[relative_path] = self.extract_imports(tree, relative_path)

        # Process top-level functions and classes
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_id, func_data = self.process_function(node, file_path, content)
                self.functions[func_id] = func_data
                self.stats['total_functions'] += 1
                self.stats['standalone_functions'] += 1
                if func_data['is_async']:
                    self.stats['async_functions'] += 1

                # Track by type
                unit_type = func_data['unit_type']
                self.stats['by_type'][unit_type] = self.stats['by_type'].get(unit_type, 0) + 1

            elif isinstance(node, ast.ClassDef):
                class_id, class_data, method_nodes = self.process_class(node, file_path, content)
                self.classes[class_id] = class_data
                self.stats['total_classes'] += 1

                # Process methods
                for method_node, class_name in method_nodes:
                    func_id, func_data = self.process_function(method_node, file_path, content, class_name)
                    self.functions[func_id] = func_data
                    self.stats['total_functions'] += 1
                    self.stats['total_methods'] += 1
                    if func_data['is_async']:
                        self.stats['async_functions'] += 1

                    # Track by type
                    unit_type = func_data['unit_type']
                    self.stats['by_type'][unit_type] = self.stats['by_type'].get(unit_type, 0) + 1

        # Extract module-level code
        module_result = self.extract_module_level_code(tree, content, file_path)
        if module_result:
            func_id, func_data = module_result
            self.functions[func_id] = func_data
            self.stats['total_functions'] += 1
            self.stats['module_level_units'] += 1
            self.stats['by_type']['module_level'] = self.stats['by_type'].get('module_level', 0) + 1

    def extract_from_scan(self, scan_result: Dict) -> Dict:
        """Extract functions from files listed in a scan result."""
        for file_info in scan_result.get('files', []):
            file_path = self.repo_path / file_info['path']
            self.process_file(file_path)

        return self.export()

    def extract_all(self, files: Optional[List[str]] = None) -> Dict:
        """Extract functions from all Python files or a specific list."""
        if files:
            for file_rel_path in files:
                file_path = self.repo_path / file_rel_path
                if file_path.exists():
                    self.process_file(file_path)
        else:
            # Scan all .py files
            for file_path in self.repo_path.rglob('*.py'):
                # Skip common exclude patterns
                path_str = str(file_path)
                if any(excl in path_str for excl in ['__pycache__', '.git', 'venv', '.venv', 'node_modules']):
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
        description='Extract all functions and classes from a Python repository',
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
            print(f"  Module-level: {result['statistics']['module_level_units']}", file=sys.stderr)
            print(f"  Async: {result['statistics']['async_functions']}", file=sys.stderr)
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
