"""
Stage 1: Repository Scanner for Zig

Enumerates all Zig source files in a repository.
"""

import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from utilities.file_io import write_json


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

    # Test directory names (matched as whole path components, not substrings).
    TEST_DIRS = {"test", "tests", "spec", "specs"}

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
        """Check if a directory name indicates test code.

        Matches whole directory names exactly (``test``/``tests``/``spec``/
        ``specs``) so that real dirs whose name merely *contains* a test token
        as a substring (``latest_dir``, ``inspector``) are NOT excluded.
        """
        return dirname.lower() in self.TEST_DIRS

    def _is_test_file(self, filepath: str) -> bool:
        """Check if a file path indicates test code.

        Anchored to path components / basename conventions so that real sources
        whose name merely *contains* a test token as a substring (``latest.zig``,
        ``contest.zig``, ``attestation.zig``, ``inspector/foo.zig``) are NOT
        skipped. A path is a test iff a directory component is exactly a test
        dir OR the basename follows a test convention (``test_*``,
        ``*_test.zig``, ``*_spec.zig``).
        """
        filepath_lower = filepath.lower()
        parts = Path(filepath_lower).parts
        # Directory-component match (exact, not substring).
        for part in parts[:-1]:
            if part in self.TEST_DIRS:
                return True
        basename = parts[-1] if parts else filepath_lower
        if basename.startswith("test_"):
            return True
        if basename.endswith("_test.zig") or basename.endswith("_spec.zig"):
            return True
        return False

    def save_results(self, output_path: str, results: Dict[str, Any]) -> None:
        """Save scan results to a JSON file."""
        write_json(output_path, results)
