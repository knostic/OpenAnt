"""
Repository Index

Builds a searchable index of functions from TypeScript analyzer output.
Enables fast lookup by function name, file path, and pattern matching.

The index is used by Stage 2 verification to enable the model to explore
the codebase - searching for function usages, definitions, and callers.

Classes:
    RepositoryIndex: Main searchable index with functions, by_name, by_file lookups

Functions:
    load_index_from_file: Load index from analyzer_output.json file
"""

import re
from pathlib import Path
from typing import Optional

from utilities.file_io import read_json


class RepositoryIndex:
    """
    Searchable index of all functions in a repository.
    Built from TypeScriptAnalyzer output.
    """

    def __init__(self, analyzer_output: dict, repo_path: str = None):
        """
        Initialize the index from analyzer output.

        Args:
            analyzer_output: Output from typescript_analyzer.js
            repo_path: Repository root path (for file reading)
        """
        self.repo_path = Path(repo_path) if repo_path else None
        self.functions = {}  # function_id -> function_data
        self.by_name = {}    # function_name -> [function_ids]
        self.by_file = {}    # file_path -> [function_ids]

        self._build_index(analyzer_output)

    def _build_index(self, analyzer_output: dict):
        """Build the searchable index from analyzer output."""
        functions = analyzer_output.get("functions", {})

        for func_id, func_data in functions.items():
            # Store full function data
            self.functions[func_id] = func_data

            # Index by function name
            func_name = func_data.get("name", "")
            if func_name:
                if func_name not in self.by_name:
                    self.by_name[func_name] = []
                self.by_name[func_name].append(func_id)

            # Index by file path (extract from func_id)
            # func_id format: "file/path.ts:functionName" or "file/path.ts:ClassName.methodName"
            colon_idx = func_id.rfind(":")
            if colon_idx > 0:
                file_path = func_id[:colon_idx]
                if file_path not in self.by_file:
                    self.by_file[file_path] = []
                self.by_file[file_path].append(func_id)

    def get_function(self, func_id: str) -> Optional[dict]:
        """
        Get function data by ID.

        Args:
            func_id: Function identifier (file:functionName)

        Returns:
            Function data dict or None if not found
        """
        return self.functions.get(func_id)

    def get_function_code(self, func_id: str) -> Optional[str]:
        """
        Get function code by ID.

        Args:
            func_id: Function identifier

        Returns:
            Function source code or None if not found
        """
        func = self.functions.get(func_id)
        return func.get("code") if func else None

    def search_by_name(self, name: str, exact: bool = False) -> list[dict]:
        """
        Search functions by name.

        Args:
            name: Function name to search for
            exact: If True, require exact match. If False, allow partial/pattern match.

        Returns:
            List of matching functions with their IDs
        """
        results = []

        if exact:
            # Exact match
            func_ids = self.by_name.get(name, [])
            for func_id in func_ids:
                func = self.functions[func_id]
                results.append({
                    "id": func_id,
                    "name": func.get("name"),
                    "code": func.get("code"),
                    "startLine": func.get("startLine"),
                    "endLine": func.get("endLine"),
                    "unitType": func.get("unitType"),
                    "className": func.get("className")
                })
        else:
            # Pattern match (case-insensitive)
            pattern = re.compile(re.escape(name), re.IGNORECASE)
            for func_id, func in self.functions.items():
                func_name = func.get("name", "")
                if pattern.search(func_name):
                    results.append({
                        "id": func_id,
                        "name": func.get("name"),
                        "code": func.get("code"),
                        "startLine": func.get("startLine"),
                        "endLine": func.get("endLine"),
                        "unitType": func.get("unitType"),
                        "className": func.get("className")
                    })

        return results

    def search_usages(self, function_name: str) -> list[dict]:
        """
        Search for usages of a function across the codebase.

        Args:
            function_name: Name of the function to find usages of

        Returns:
            List of functions that call the target function
        """
        results = []

        # Patterns to match function calls
        patterns = [
            re.compile(rf'\b{re.escape(function_name)}\s*\('),  # functionName(
            re.compile(rf'\.{re.escape(function_name)}\s*\('),   # .functionName(
            re.compile(rf'\bthis\.{re.escape(function_name)}\s*\('),  # this.functionName(
        ]

        for func_id, func in self.functions.items():
            code = func.get("code", "")
            for pattern in patterns:
                if pattern.search(code):
                    # Extract the matching line(s)
                    matches = []
                    for i, line in enumerate(code.split('\n')):
                        if pattern.search(line):
                            matches.append({
                                "line_offset": i,
                                "content": line.strip()
                            })

                    results.append({
                        "id": func_id,
                        "name": func.get("name"),
                        "file": func_id.rsplit(":", 1)[0] if ":" in func_id else "",
                        "matches": matches[:3]  # Limit to 3 matches per function
                    })
                    break  # Don't double-count same function

        return results

    def search_definitions(self, function_name: str) -> list[dict]:
        """
        Search for function definitions by name.

        Args:
            function_name: Name of the function to find

        Returns:
            List of function definitions
        """
        return self.search_by_name(function_name, exact=True)

    def list_functions_in_file(self, file_path: str) -> list[dict]:
        """
        List all functions in a file.

        Args:
            file_path: Path to the file (relative to repo root)

        Returns:
            List of functions in the file
        """
        func_ids = self.by_file.get(file_path, [])
        results = []

        for func_id in func_ids:
            func = self.functions[func_id]
            results.append({
                "id": func_id,
                "name": func.get("name"),
                "startLine": func.get("startLine"),
                "endLine": func.get("endLine"),
                "unitType": func.get("unitType"),
                "className": func.get("className")
            })

        return results

    def read_file_section(self, file_path: str, start_line: int, end_line: int) -> Optional[str]:
        """
        Read a section of a file.

        Args:
            file_path: Path to file (relative to repo root)
            start_line: Start line (1-indexed)
            end_line: End line (1-indexed, inclusive)

        Returns:
            File content or None if file not found
        """
        if not self.repo_path:
            return None

        full_path = self.repo_path / file_path
        if not full_path.exists():
            return None

        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            # Convert to 0-indexed
            start_idx = max(0, start_line - 1)
            end_idx = min(len(lines), end_line)

            return ''.join(lines[start_idx:end_idx])
        except Exception:
            return None

    def get_all_function_ids(self) -> list[str]:
        """
        Get list of all function IDs.

        Returns:
            List of function IDs
        """
        return list(self.functions.keys())

    def get_statistics(self) -> dict:
        """
        Get index statistics.

        Returns:
            Dict with counts and summary
        """
        return {
            "total_functions": len(self.functions),
            "total_files": len(self.by_file),
            "unique_names": len(self.by_name),
            "functions_per_file": {
                file: len(funcs) for file, funcs in self.by_file.items()
            }
        }


def load_index_from_file(analyzer_output_path: str, repo_path: str = None) -> RepositoryIndex:
    """
    Load repository index from analyzer output file.

    Args:
        analyzer_output_path: Path to analyzer_output.json
        repo_path: Repository root path

    Returns:
        RepositoryIndex instance
    """
    analyzer_output = read_json(analyzer_output_path)

    return RepositoryIndex(analyzer_output, repo_path)
