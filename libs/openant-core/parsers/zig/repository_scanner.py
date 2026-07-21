"""
Stage 1: Repository Scanner for Zig

Enumerates all Zig source files in a repository.
"""

import os
from core.repo_walk import walk_repository
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
        # Traversal delegated to core/repo_walk.py. The previous implementation
        # used os.walk(followlinks=True) with an inode set that deduped only
        # REPEAT visits, so an external directory symlink was descended the first
        # time — `escape -> /` walked the host filesystem into the dataset. Both a
        # grep-based audit census and a token-matching parity test scored this
        # scanner "guarded"; only executing it against a hostile fixture found the
        # hole. It also never recorded unreadable directories, so a subtree it
        # could not enter vanished from a scan that reported success.
        stats: dict = {}

        def _on_file(entry, relative_path: str) -> None:
            # Case-insensitive: filesystems (macOS/Windows) and users may spell the
            # extension .ZIG/.Zig; skipping those silently loses files.
            if not entry.name.lower().endswith(".zig"):
                return
            if self.skip_tests and self._is_test_file(relative_path):
                return
            try:
                size = entry.stat().st_size
            except OSError:
                size = 0
            files.append({"path": relative_path, "size": size})

        def _should_exclude(name: str) -> bool:
            return (name in self.EXCLUDE_DIRS
                    or self._matches_exclude_pattern(name)
                    or (self.skip_tests and self._is_test_directory(name)))

        walk_repository(
            self.repo_path,
            should_exclude_directory=_should_exclude,
            on_file=_on_file,
            stats=stats,
        )
        directories_scanned = stats.get("directories_scanned", 0)
        directories_excluded = stats.get("directories_excluded", 0)
        self.walk_stats = stats

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
                # Surfaced into the RESULT, not just stderr. A directory the
                # scanner could not enter is code it never analysed, and CI
                # discards stderr — so a gap that lives only in a warning is a
                # gap nobody sees.
                "directories_unreadable": stats.get("directories_unreadable", 0),
                "unreadable_examples": stats.get("unreadable_examples", []),
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
