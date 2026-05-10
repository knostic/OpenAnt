#!/usr/bin/env python3
"""
Python Dataset Enhancer

Enhances parsed Python routes with additional context by following
function calls and gathering related code.
"""

import ast
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from utilities.file_io import read_json, write_json, open_utf8


class PythonDependencyResolver:
    """Resolve and collect Python code dependencies."""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.file_cache: Dict[str, str] = {}
        self.ast_cache: Dict[str, ast.AST] = {}
        self.import_map: Dict[str, Dict[str, str]] = {}  # file -> {name -> module}

    def _read_file(self, file_path: Path) -> str:
        """Read and cache file contents."""
        path_str = str(file_path)
        if path_str not in self.file_cache:
            try:
                with open_utf8(file_path, errors="replace") as _f:
                    self.file_cache[path_str] = _f.read()
            except Exception as e:
                self.file_cache[path_str] = ""
        return self.file_cache[path_str]

    def _get_ast(self, file_path: Path) -> Optional[ast.AST]:
        """Parse and cache AST for a file."""
        path_str = str(file_path)
        if path_str not in self.ast_cache:
            content = self._read_file(file_path)
            if content:
                try:
                    self.ast_cache[path_str] = ast.parse(content)
                except SyntaxError:
                    self.ast_cache[path_str] = None
            else:
                self.ast_cache[path_str] = None
        return self.ast_cache[path_str]

    def _build_import_map(self, file_path: Path):
        """Build a map of imports for a file."""
        path_str = str(file_path)
        if path_str in self.import_map:
            return

        self.import_map[path_str] = {}
        tree = self._get_ast(file_path)
        if not tree:
            return

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name
                    self.import_map[path_str][name] = alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ''
                for alias in node.names:
                    name = alias.asname or alias.name
                    full_path = f"{module}.{alias.name}" if module else alias.name
                    self.import_map[path_str][name] = full_path

    def _resolve_module_path(self, module_name: str, from_file: Path) -> Optional[Path]:
        """Resolve a module name to a file path."""
        parts = module_name.split('.')

        # Try relative import from same directory
        base_dir = from_file.parent
        for i in range(len(parts)):
            candidate = base_dir / '/'.join(parts[:i+1])
            if candidate.with_suffix('.py').exists():
                return candidate.with_suffix('.py')
            if (candidate / '__init__.py').exists():
                return candidate / '__init__.py'

        # Try from repo root
        for i in range(len(parts)):
            candidate = self.repo_path / '/'.join(parts[:i+1])
            if candidate.with_suffix('.py').exists():
                return candidate.with_suffix('.py')
            if (candidate / '__init__.py').exists():
                return candidate / '__init__.py'

        return None

    def _get_function_source(self, file_path: Path, func_name: str) -> Tuple[str, int, int]:
        """Extract function source code from a file."""
        content = self._read_file(file_path)
        if not content:
            return "", 0, 0

        tree = self._get_ast(file_path)
        if not tree:
            return "", 0, 0

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == func_name:
                lines = content.split('\n')
                start = node.lineno - 1
                end = node.end_lineno if hasattr(node, 'end_lineno') else start + 10

                # Include decorators
                if node.decorator_list:
                    first_decorator = min(d.lineno for d in node.decorator_list)
                    start = first_decorator - 1

                func_lines = lines[start:end]
                return '\n'.join(func_lines), start + 1, end

            # Also check class methods
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and item.name == func_name:
                        lines = content.split('\n')
                        start = item.lineno - 1
                        end = item.end_lineno if hasattr(item, 'end_lineno') else start + 10

                        if item.decorator_list:
                            first_decorator = min(d.lineno for d in item.decorator_list)
                            start = first_decorator - 1

                        func_lines = lines[start:end]
                        return '\n'.join(func_lines), start + 1, end

        return "", 0, 0

    def _extract_called_functions(self, code: str) -> Set[str]:
        """Extract function names called in the code."""
        called = set()
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        called.add(node.func.id)
                    elif isinstance(node.func, ast.Attribute):
                        # Get the full attribute chain
                        parts = []
                        current = node.func
                        while isinstance(current, ast.Attribute):
                            parts.append(current.attr)
                            current = current.value
                        if isinstance(current, ast.Name):
                            parts.append(current.id)
                        parts.reverse()
                        called.add('.'.join(parts))
        except SyntaxError:
            pass
        return called

    def resolve_dependencies(self, file_path: Path, code: str, max_depth: int = 3) -> List[Dict]:
        """Resolve code dependencies recursively."""
        dependencies = []
        visited = set()
        self._build_import_map(file_path)

        def resolve_recursive(current_file: Path, current_code: str, depth: int):
            if depth > max_depth:
                return

            called = self._extract_called_functions(current_code)

            for func_ref in called:
                if func_ref in visited:
                    continue
                visited.add(func_ref)

                # Try to resolve the function
                parts = func_ref.split('.')

                # Check if it's an imported module
                first_part = parts[0]
                import_map = self.import_map.get(str(current_file), {})

                if first_part in import_map:
                    module_name = import_map[first_part]
                    resolved_path = self._resolve_module_path(module_name, current_file)

                    if resolved_path:
                        # Get the function from the resolved module
                        func_name = parts[-1] if len(parts) > 1 else first_part
                        dep_code, start, end = self._get_function_source(resolved_path, func_name)

                        if dep_code:
                            dependencies.append({
                                "code": dep_code,
                                "origin": {
                                    "file_path": str(resolved_path.relative_to(self.repo_path)),
                                    "start_line": start,
                                    "end_line": end,
                                    "function_name": func_name
                                }
                            })
                            resolve_recursive(resolved_path, dep_code, depth + 1)

                # Try same file
                if len(parts) == 1:
                    dep_code, start, end = self._get_function_source(current_file, func_ref)
                    if dep_code and func_ref not in visited:
                        dependencies.append({
                            "code": dep_code,
                            "origin": {
                                "file_path": str(current_file.relative_to(self.repo_path)),
                                "start_line": start,
                                "end_line": end,
                                "function_name": func_ref
                            }
                        })
                        visited.add(func_ref)
                        resolve_recursive(current_file, dep_code, depth + 1)

        resolve_recursive(file_path, code, 0)
        return dependencies


def enhance_dataset(dataset_path: str, repo_path: str, output_path: str = None):
    """Enhance a dataset with resolved dependencies."""
    dataset = read_json(dataset_path)
    resolver = PythonDependencyResolver(repo_path)

    enhanced_units = []
    for unit in dataset.get('units', []):
        primary_code = unit.get('code', {}).get('primary_code', '')
        origin = unit.get('code', {}).get('primary_origin', {})
        file_path_str = origin.get('file_path', '')

        if file_path_str:
            file_path = Path(repo_path) / file_path_str
            dependencies = resolver.resolve_dependencies(file_path, primary_code)

            # Update unit with dependencies
            unit['code']['dependencies'] = dependencies

            # Create combined code with dependencies
            files_included = [file_path_str]
            combined_code = f"# File: {file_path_str}\n{primary_code}"

            for dep in dependencies:
                dep_file = dep['origin'].get('file_path', '')
                if dep_file and dep_file not in files_included:
                    files_included.append(dep_file)
                    combined_code += f"\n\n# File: {dep_file}\n{dep['code']}"

            unit['code']['primary_origin']['files_included'] = files_included
            unit['code']['combined_code'] = combined_code

        enhanced_units.append(unit)

    dataset['units'] = enhanced_units
    dataset['enhanced'] = True

    if output_path:
        write_json(output_path, dataset)
        print(f"Enhanced dataset written to {output_path}")
    else:
        print(json.dumps(dataset, indent=2))

    print(f"Enhanced {len(enhanced_units)} units")


def main():
    """Command line interface."""
    if len(sys.argv) < 3:
        print("Usage: python dataset_enhancer.py <dataset_path> <repo_path> [output_path]")
        sys.exit(1)

    dataset_path = sys.argv[1]
    repo_path = sys.argv[2]
    output_path = sys.argv[3] if len(sys.argv) > 3 else None

    enhance_dataset(dataset_path, repo_path, output_path)


if __name__ == "__main__":
    main()
