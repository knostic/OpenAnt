"""
Stage 1: Repository Scanner for Zig

Enumerates all Zig source files in a repository.
"""

import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from utilities.file_io import write_json
from utilities.path_filters import should_exclude_directory


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

    # Native Zig test conventions. Directory names are matched as whole path
    # segments; filenames are matched by anchored stem prefix/suffix. Matching
    # bare "test"/"spec" as a substring (the prior behaviour) misclassified
    # ordinary names like ``latest``/``contest``/``fastest.zig`` as tests.
    TEST_DIR_NAMES = {"test", "tests", "spec", "specs"}
    TEST_FILE_PREFIXES = ("test_", "spec_")
    TEST_FILE_SUFFIXES = ("_test.zig", "_spec.zig")

    def __init__(
        self,
        repo_path: str,
        skip_tests: bool = False,
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

        # followlinks=True so .zig files reachable ONLY through a symlinked
        # directory are still scanned (matches the iterdir()+is_dir() behaviour
        # of the other four language scanners). Following symlinks needs a guard
        # against two hazards, applied by pruning directory symlinks from `dirs`
        # (os.walk descends whatever remains in `dirs`):
        #   1. Alias duplication / canonical loss: a symlink pointing back INSIDE
        #      the repo names a real directory that os.walk already reaches on its
        #      canonical (non-symlink) path. Descending the alias would emit files
        #      under the symlink path and, worse, could suppress the real path
        #      entirely. We always drop the alias and keep the canonical visit.
        #   2. External symlink loops: a symlink pointing OUTSIDE the repo whose
        #      real target we have already descended (a self-referential loop)
        #      would recurse forever; an inode guard prevents re-descending it.
        seen_real_dirs: set = set()
        repo_real = os.path.realpath(self.repo_path)
        for root, dirs, filenames in os.walk(self.repo_path, followlinks=True):
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

            # Cycle / alias guard on the surviving directory symlinks.
            kept = []
            for d in dirs:
                full = os.path.join(root, d)
                if os.path.islink(full):
                    real = os.path.realpath(full)
                    # In-repo alias: the real directory is walked canonically,
                    # so never descend the symlink (prefer the canonical path).
                    if real == repo_real or real.startswith(repo_real + os.sep):
                        continue
                    # External target: guard against symlink loops by inode.
                    try:
                        st = os.stat(full)
                        real_key = (st.st_dev, st.st_ino)
                    except OSError:
                        continue
                    if real_key in seen_real_dirs:
                        continue
                    seen_real_dirs.add(real_key)
                kept.append(d)
            dirs[:] = kept

            directories_scanned += 1

            for filename in filenames:
                # Case-insensitive: filesystems (macOS/Windows) and users may
                # spell the extension .ZIG/.Zig; skipping those silently loses files.
                if not filename.lower().endswith(".zig"):
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
        """Check if a name matches any exclude pattern (whole-segment match)."""
        return should_exclude_directory(name, self.exclude_patterns)

    def _is_test_directory(self, dirname: str) -> bool:
        """Check if a directory name indicates test code.

        Exact (whole-name) match so that ``latest``/``contest``/``attestation``
        are not misclassified as test directories.
        """
        return dirname.lower() in self.TEST_DIR_NAMES

    def _is_test_file(self, filepath: str) -> bool:
        """Check if a file path indicates test code.

        A file is a test iff one of its directory components is a test
        directory, or its filename is anchored (stem prefix ``test_``/``spec_``
        or suffix ``_test.zig``/``_spec.zig``). Anchoring stops ordinary names
        like ``src/fastest.zig``/``src/latest/main.zig`` from matching.
        """
        p = Path(filepath.lower())
        if any(part in self.TEST_DIR_NAMES for part in p.parts[:-1]):
            return True
        name = p.name
        if name.startswith(self.TEST_FILE_PREFIXES):
            return True
        if name.endswith(self.TEST_FILE_SUFFIXES):
            return True
        return False

    def save_results(self, output_path: str, results: Dict[str, Any]) -> None:
        """Save scan results to a JSON file."""
        write_json(output_path, results)
