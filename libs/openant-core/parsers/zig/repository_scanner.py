"""
Stage 1: Repository Scanner for Zig

Enumerates all Zig source files in a repository.
"""

import os
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional


class RepositoryScanner:
    """Scans a repository for Zig source files."""

    # Directories to exclude from scanning
    EXCLUDE_DIRS = {
        ".git",
        "vendor",
        "node_modules",
        "zig-cache",
        "zig-out",
        ".zig-cache",
        "__pycache__",
        ".venv",
        "venv",
        "build",
        "dist",
        "target",
    }

    # Test directory patterns to skip when skip_tests is True
    TEST_PATTERNS = {"test", "tests", "spec", "specs", "_test", "test_"}

    def __init__(
        self,
        repo_path: str,
        skip_tests: bool = True,
        exclude_patterns: Optional[List[str]] = None,
    ):
        self.repo_path = Path(repo_path).resolve()
        self.skip_tests = skip_tests
        self.exclude_patterns = exclude_patterns or []

    def scan(self) -> Dict[str, Any]:
        """
        Scan the repository for Zig files.

        Returns scan_results.json structure:
        {
            "repository": "/path/to/repo",
            "scan_time": "2025-01-15T10:30:00",
            "files": [{"path": "src/main.zig", "size": 1234}, ...],
            "statistics": {...}
        }
        """
        files = []
        directories_scanned = 0
        directories_excluded = 0

        for root, dirs, filenames in os.walk(self.repo_path):
            # Filter out excluded directories
            original_dirs = dirs.copy()
            dirs[:] = [
                d
                for d in dirs
                if d not in self.EXCLUDE_DIRS
                and not self._matches_exclude_pattern(d)
                and not (self.skip_tests and self._is_test_directory(d))
            ]
            directories_excluded += len(original_dirs) - len(dirs)
            directories_scanned += 1

            for filename in filenames:
                if not filename.endswith(".zig"):
                    continue

                file_path = Path(root) / filename
                relative_path = file_path.relative_to(self.repo_path)

                # Skip test files if requested
                if self.skip_tests and self._is_test_file(str(relative_path)):
                    continue

                try:
                    size = file_path.stat().st_size
                except OSError:
                    size = 0

                files.append({"path": str(relative_path), "size": size})

        total_size = sum(f["size"] for f in files)

        return {
            "repository": str(self.repo_path),
            "scan_time": datetime.now().isoformat(),
            "files": files,
            "statistics": {
                "total_files": len(files),
                "total_size_bytes": total_size,
                "directories_scanned": directories_scanned,
                "directories_excluded": directories_excluded,
            },
        }

    def _matches_exclude_pattern(self, name: str) -> bool:
        """Check if a name matches any exclude pattern."""
        for pattern in self.exclude_patterns:
            if pattern in name:
                return True
        return False

    def _is_test_directory(self, dirname: str) -> bool:
        """Check if a directory name indicates test code."""
        dirname_lower = dirname.lower()
        return any(pattern in dirname_lower for pattern in self.TEST_PATTERNS)

    def _is_test_file(self, filepath: str) -> bool:
        """Check if a file path indicates test code."""
        filepath_lower = filepath.lower()
        # Check for test in path components
        parts = Path(filepath_lower).parts
        for part in parts:
            if any(pattern in part for pattern in self.TEST_PATTERNS):
                return True
        # Check for _test.zig suffix
        if filepath_lower.endswith("_test.zig"):
            return True
        return False

    def save_results(self, output_path: str, results: Dict[str, Any]) -> None:
        """Save scan results to a JSON file."""
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
