"""
Stage 1: Repository Scanner for Rust

Enumerates all Rust source files in a repository.
"""

from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from core.repo_walk import walk_repository
from utilities.file_io import write_json
from utilities.path_filters import should_exclude_directory


class RepositoryScanner:
    """Scans a repository for Rust source files."""

    # Directories to exclude from scanning. Beyond the shared VCS/dep dirs,
    # this covers Cargo's build output (`target/`) and vendored-dependency
    # trees (`vendor/`, populated by `cargo vendor`).
    EXCLUDE_DIRS = {
        ".git",
        "vendor",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "build",
        "dist",
        "target",  # cargo build output
    }

    # Native Rust test conventions. Directory names are matched as whole path
    # segments; filenames are matched by anchored stem prefix/suffix. Matching a
    # bare "test" as a substring would misclassify ordinary names like
    # ``latest.rs``/``contest.rs``/``fastest.rs``. The dominant Cargo convention
    # is a top-level `tests/` directory holding integration tests; unit tests
    # overwhelmingly live INLINE in `#[cfg(test)] mod tests { ... }` blocks
    # within ordinary source files, which this file-level scan cannot see —
    # that case is handled at extraction time (see function_extractor.py),
    # not here.
    TEST_DIR_NAMES = {"test", "tests"}
    TEST_FILE_PREFIXES = ("test_",)
    TEST_FILE_SUFFIXES = ("_test.rs", "_tests.rs")

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
        Scan the repository for Rust files.

        Returns scan_results.json structure:
        {
            "repository": "/path/to/repo",
            "scan_time": "2025-01-15T10:30:00",
            "files": [{"path": "src/main.rs", "size": 1234}, ...],
            "statistics": {...}
        }
        """
        files: List[Dict[str, Any]] = []
        stats: dict = {}

        def _should_exclude(name: str) -> bool:
            return (
                name in self.EXCLUDE_DIRS
                or self._matches_exclude_pattern(name)
                or (self.skip_tests and self._is_test_directory(name))
            )

        def _on_file(entry, relative_path: str) -> None:
            # Case-insensitive: filesystems (macOS/Windows) and users may spell
            # the extension .RS/.Rs; skipping those silently loses files.
            if not entry.name.lower().endswith(".rs"):
                return
            if self.skip_tests and self._is_test_file(relative_path):
                return
            try:
                size = entry.stat().st_size
            except OSError:
                size = 0
            files.append({"path": relative_path, "size": size})

        # Traversal delegated to the shared core/repo_walk.py: an iterative
        # walk that refuses symlinks (no exfiltration via a `vendor -> /`
        # alias) and records unreadable/excluded subtrees in `stats` rather
        # than silently dropping them.
        walk_repository(
            self.repo_path,
            should_exclude_directory=_should_exclude,
            on_file=_on_file,
            stats=stats,
        )

        total_size = sum(f["size"] for f in files)

        return {
            "repository": str(self.repo_path),
            "scan_time": datetime.now().isoformat(),
            "files": files,
            "statistics": {
                "total_files": len(files),
                "total_size_bytes": total_size,
                "directories_scanned": stats.get("directories_scanned", 0),
                "directories_excluded": stats.get("directories_excluded", 0),
                "directories_unreadable": stats.get("directories_unreadable", 0),
                "unreadable_examples": stats.get("unreadable_examples", []),
                "symlinks_skipped": stats.get("symlinks_skipped", 0),
                "symlink_examples": stats.get("symlink_examples", []),
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
        directory (Cargo integration-test convention: top-level ``tests/``),
        or its filename is anchored (stem prefix ``test_`` or suffix
        ``_test.rs``/``_tests.rs``). Anchoring stops ordinary names like
        ``src/fastest.rs``/``src/latest/main.rs`` from matching.
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
