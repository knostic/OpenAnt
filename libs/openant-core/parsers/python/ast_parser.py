#!/usr/bin/env python3
"""
Python AST Parser for Web Application Routes

Parses Python web application frameworks to extract route definitions:
- Django: urls.py with path() mappings
- Flask: @app.route() and blueprint decorators
- aiohttp: add_route() calls

Outputs dataset.json in the same format as the JavaScript parser.
"""

import ast
import json
import os
from utilities.file_io import open_utf8
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from utilities.file_io import read_json, write_json, open_utf8


class PythonRouteParser:
    """Parse Python web frameworks to extract routes and handlers."""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.routes: List[Dict] = []
        self.file_cache: Dict[str, str] = {}
        self.function_cache: Dict[str, Dict] = {}
        self.framework = None

    def detect_framework(self) -> str:
        """Detect which Python web framework is being used."""
        files = list(self.repo_path.rglob("*.py"))

        for f in files:
            try:
                with open_utf8(f, errors="replace") as _f:
                    content = _f.read()
                if "from django" in content or "django.urls" in content:
                    return "django"
                if "from flask" in content or "Flask(" in content:
                    return "flask"
                if "from aiohttp" in content or "aiohttp.web" in content:
                    return "aiohttp"
            except Exception:
                continue

        return "unknown"

    def parse(self) -> Dict:
        """Main entry point - parse the repository."""
        self.framework = self.detect_framework()
        print(f"Detected framework: {self.framework}")

        if self.framework == "django":
            self._parse_django()
        elif self.framework == "flask":
            self._parse_flask()
        elif self.framework == "aiohttp":
            self._parse_aiohttp()
        else:
            print(f"Warning: Unknown framework, trying all parsers")
            self._parse_django()
            self._parse_flask()
            self._parse_aiohttp()

        return {
            "name": self.repo_path.name,
            "repository_path": str(self.repo_path),
            "framework": self.framework,
            "units": self.routes
        }

    def _read_file(self, file_path: Path) -> str:
        """Read and cache file contents."""
        path_str = str(file_path)
        if path_str not in self.file_cache:
            try:
                with open_utf8(file_path, errors="replace") as _f:
                    self.file_cache[path_str] = _f.read()
            except Exception as e:
                print(f"Error reading {file_path}: {e}")
                self.file_cache[path_str] = ""
        return self.file_cache[path_str]

    def _get_function_source(self, file_path: Path, func_name: str) -> Tuple[str, int, int]:
        """Extract function source code from a file."""
        content = self._read_file(file_path)
        if not content:
            return "", 0, 0

        try:
            tree = ast.parse(content)
        except SyntaxError:
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

        return "", 0, 0

    def _get_file_source(self, file_path: Path) -> str:
        """Get entire file source."""
        return self._read_file(file_path)

    def _create_unit(self, method: str, path: str, handler: str,
                     code: str, file_path: Path, start_line: int, end_line: int,
                     middleware: List[str] = None) -> Dict:
        """Create a dataset unit in the standard format."""
        route_id = f"{method}:{path}"

        return {
            "id": route_id,
            "code": {
                "primary_code": code,
                "primary_origin": {
                    "file_path": str(file_path.relative_to(self.repo_path)),
                    "start_line": start_line,
                    "end_line": end_line,
                    "function_name": handler,
                    "class_name": None
                },
                "dependencies": [],
                "dependency_metadata": {}
            },
            "route": {
                "method": method,
                "path": path,
                "handler": handler,
                "middleware": middleware or []
            },
            "ground_truth": {
                "status": "unknown",
                "vulnerability_types": [],
                "issues": [],
                "annotation_source": "unknown",
                "annotation_key": route_id,
                "notes": ""
            },
            "metadata": {
                "parser": "python_ast_parser.py",
                "framework": self.framework,
                "route_file": str(file_path.relative_to(self.repo_path)),
                "route_line": start_line
            }
        }

    # ==================== Django Parser ====================

    def _parse_django(self):
        """Parse Django urls.py files."""
        urls_files = list(self.repo_path.rglob("urls.py"))

        for urls_file in urls_files:
            self._parse_django_urls(urls_file)

    def _parse_django_urls(self, urls_file: Path):
        """Parse a Django urls.py file."""
        content = self._read_file(urls_file)
        if not content:
            return

        # Find the views module import
        views_module = self._find_django_views_module(urls_file, content)

        # Parse path() and url() calls
        try:
            tree = ast.parse(content)
        except SyntaxError as e:
            print(f"Syntax error in {urls_file}: {e}")
            return

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node)
                if func_name in ('path', 're_path', 'url'):
                    self._extract_django_route(node, urls_file, views_module)

    def _find_django_views_module(self, urls_file: Path, content: str) -> Optional[Path]:
        """Find the views.py module referenced in urls.py."""
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return None

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module and 'views' in node.module:
                    # Try to find the views file
                    base_dir = urls_file.parent
                    parts = node.module.split('.')
                    views_path = base_dir / '/'.join(parts[:-1]) / f"{parts[-1]}.py" if len(parts) > 1 else base_dir / f"{node.module}.py"
                    if views_path.exists():
                        return views_path

                    # Try relative path
                    views_path = base_dir / "views.py"
                    if views_path.exists():
                        return views_path

        return None

    def _extract_django_route(self, node: ast.Call, urls_file: Path, views_module: Optional[Path]):
        """Extract route info from a Django path() call."""
        if len(node.args) < 2:
            return

        # Get path pattern
        path_arg = node.args[0]
        path = self._get_string_value(path_arg)
        if path is None:
            return

        # Normalize path
        if not path.startswith('/'):
            path = '/' + path

        # Get view function
        view_arg = node.args[1]
        handler = self._get_call_name(view_arg) or self._get_attribute_string(view_arg)
        if not handler:
            return

        # Get the handler source
        code = ""
        start_line = node.lineno
        end_line = node.lineno

        if views_module and '.' in handler:
            # views.function_name format
            func_name = handler.split('.')[-1]
            code, start_line, end_line = self._get_function_source(views_module, func_name)
            if not code:
                code = self._get_file_source(views_module)
                start_line = 1
                end_line = code.count('\n') + 1

        # Django typically handles all methods in one view
        methods = ['GET', 'POST']

        for method in methods:
            unit = self._create_unit(
                method=method,
                path=path,
                handler=handler,
                code=code or f"# Handler: {handler}",
                file_path=views_module or urls_file,
                start_line=start_line,
                end_line=end_line
            )
            self.routes.append(unit)

    # ==================== Flask Parser ====================

    def _parse_flask(self):
        """Parse Flask route decorators."""
        py_files = list(self.repo_path.rglob("*.py"))

        for py_file in py_files:
            self._parse_flask_file(py_file)

    def _parse_flask_file(self, file_path: Path):
        """Parse a Flask file for route decorators."""
        content = self._read_file(file_path)
        if not content:
            return

        try:
            tree = ast.parse(content)
        except SyntaxError as e:
            print(f"Syntax error in {file_path}: {e}")
            return

        # Find route decorators
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                route_info = self._extract_flask_route_decorator(node)
                if route_info:
                    path, methods = route_info

                    # Get function source
                    lines = content.split('\n')
                    start = node.lineno - 1
                    end = node.end_lineno if hasattr(node, 'end_lineno') else start + 20

                    # Include decorators
                    if node.decorator_list:
                        first_decorator = min(d.lineno for d in node.decorator_list)
                        start = first_decorator - 1

                    func_code = '\n'.join(lines[start:end])

                    for method in methods:
                        unit = self._create_unit(
                            method=method,
                            path=path,
                            handler=node.name,
                            code=func_code,
                            file_path=file_path,
                            start_line=start + 1,
                            end_line=end
                        )
                        self.routes.append(unit)

    def _extract_flask_route_decorator(self, func_node: ast.FunctionDef) -> Optional[Tuple[str, List[str]]]:
        """Extract route path and methods from Flask decorators."""
        for decorator in func_node.decorator_list:
            if isinstance(decorator, ast.Call):
                dec_name = self._get_attribute_string(decorator.func)
                if dec_name and 'route' in dec_name:
                    # Get path
                    path = None
                    if decorator.args:
                        path = self._get_string_value(decorator.args[0])

                    # Get methods
                    methods = ['GET']  # Default
                    for kw in decorator.keywords:
                        if kw.arg == 'methods':
                            if isinstance(kw.value, ast.List):
                                methods = [self._get_string_value(m) for m in kw.value.elts if self._get_string_value(m)]

                    if path:
                        return path, methods

            elif isinstance(decorator, ast.Attribute):
                # @app.get('/path') style
                attr_name = decorator.attr
                if attr_name in ('get', 'post', 'put', 'delete', 'patch'):
                    # Need to check parent for path
                    pass

        return None

    # ==================== aiohttp Parser ====================

    def _parse_aiohttp(self):
        """Parse aiohttp route definitions."""
        py_files = list(self.repo_path.rglob("*.py"))

        for py_file in py_files:
            self._parse_aiohttp_file(py_file)

    def _parse_aiohttp_file(self, file_path: Path):
        """Parse an aiohttp file for add_route calls."""
        content = self._read_file(file_path)
        if not content:
            return

        try:
            tree = ast.parse(content)
        except SyntaxError as e:
            print(f"Syntax error in {file_path}: {e}")
            return

        # Find views module in same directory
        views_file = file_path.parent / "views.py"

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = self._get_attribute_string(node.func)
                if call_name and 'add_route' in call_name:
                    self._extract_aiohttp_route(node, file_path, views_file)

    def _extract_aiohttp_route(self, node: ast.Call, routes_file: Path, views_file: Path):
        """Extract route info from aiohttp add_route() call."""
        if len(node.args) < 3:
            return

        # Get method
        method = self._get_string_value(node.args[0])
        if not method:
            return

        # Get path
        path = self._get_string_value(node.args[1])
        if not path:
            return

        # Get handler
        handler = self._get_attribute_string(node.args[2])
        if not handler:
            return

        # Get handler source
        code = ""
        start_line = node.lineno
        end_line = node.lineno

        if views_file.exists():
            func_name = handler.split('.')[-1] if '.' in handler else handler
            code, start_line, end_line = self._get_function_source(views_file, func_name)
            if not code:
                code = self._get_file_source(views_file)
                start_line = 1
                end_line = code.count('\n') + 1

        unit = self._create_unit(
            method=method,
            path=path,
            handler=handler,
            code=code or f"# Handler: {handler}",
            file_path=views_file if views_file.exists() else routes_file,
            start_line=start_line,
            end_line=end_line
        )
        self.routes.append(unit)

    # ==================== Utility Methods ====================

    def _get_string_value(self, node) -> Optional[str]:
        """Extract string value from an AST node."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Str):  # Python < 3.8
            return node.s
        return None

    def _get_call_name(self, node) -> Optional[str]:
        """Get the name of a function call."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{self._get_call_name(node.value)}.{node.attr}"
        if isinstance(node, ast.Call):
            return self._get_call_name(node.func)
        return None

    def _get_attribute_string(self, node) -> Optional[str]:
        """Get full attribute string (e.g., 'views.handler')."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._get_attribute_string(node.value)
            if base:
                return f"{base}.{node.attr}"
            return node.attr
        return None


def main():
    """Command line interface."""
    if len(sys.argv) < 2:
        print("Usage: python ast_parser.py <repository_path> [output_file]")
        sys.exit(1)

    repo_path = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    parser = PythonRouteParser(repo_path)
    result = parser.parse()

    if output_file:
        write_json(output_file, result)
        print(f"Output written to {output_file}")
    else:
        print(json.dumps(result, indent=2))

    print(f"\nParsed {len(result['units'])} routes")


if __name__ == "__main__":
    main()
