"""
Stage 1: Repository Scanner for Swift

Enumerates all Swift source files in a repository.
"""

from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from core.repo_walk import walk_repository
from utilities.file_io import write_json
from utilities.path_filters import should_exclude_directory


class RepositoryScanner:
    """Scans a repository for Swift source files."""

    # Directories to exclude from scanning. Beyond the shared VCS/dep dirs, this
    # covers the Swift/Xcode build-output trees whose contents are generated, not
    # source: SwiftPM's `.build`, Xcode `DerivedData`/`xcuserdata`, CocoaPods
    # `Pods`, Carthage `Carthage`, and the `.swiftpm` metadata dir.
    EXCLUDE_DIRS = {
        ".git",
        "vendor",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "build",
        "dist",
        "target",
        # Swift / Xcode build + dependency output (generated, not source)
        ".build",
        ".swiftpm",
        "DerivedData",
        "xcuserdata",
        "Pods",
        "Carthage",
    }

    # Native Swift test conventions. Directory names are matched as whole path
    # segments; filenames are matched by anchored stem prefix/suffix. Matching a
    # bare "test"/"spec" as a substring (the naive behaviour) would misclassify
    # ordinary names like ``latest``/``contest``/``fastest.swift`` as tests. The
    # dominant Swift/XCTest conventions are a ``Tests``/``UITests`` directory and a
    # ``FooTests.swift`` / ``FooTest.swift`` / ``FooSpec.swift`` filename.
    TEST_DIR_NAMES = {"test", "tests", "spec", "specs", "uitests", "unittests"}
    TEST_FILE_PREFIXES = ("test_", "spec_")
    # Underscore-anchored suffixes are matched case-INSENSITIVELY (the `_` is the
    # word boundary). The dominant XCTest convention `FooTests.swift` has NO
    # underscore, so it is matched case-SENSITIVELY on the CamelCase boundary:
    # matching a bare lowercase "test.swift" would wrongly flag ``latest.swift``
    # (the exact 'anchoring beats substring' hazard). `Greatest.swift` (lowercase
    # t) does not match `Test.swift`; `ContrastTest.swift` does.
    TEST_FILE_SUFFIXES_CI = ("_test.swift", "_tests.swift", "_spec.swift", "_specs.swift")
    TEST_FILE_SUFFIXES_CS = ("Tests.swift", "Test.swift", "Spec.swift", "Specs.swift")

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
        Scan the repository for Swift files.

        Returns scan_results.json structure:
        {
            "repository": "/path/to/repo",
            "scan_time": "2025-01-15T10:30:00",
            "files": [{"path": "Sources/App/main.swift", "size": 1234}, ...],
            "statistics": {...}
        }
        """
        files: List[Dict[str, Any]] = []
        stats: dict = {}

        # Directory pruning: shared VCS/dep dirs + Swift/Xcode build output +
        # (optionally) test directories. Given a bare directory name.
        def _should_exclude(name: str) -> bool:
            return (
                name in self.EXCLUDE_DIRS
                or self._matches_exclude_pattern(name)
                or (self.skip_tests and self._is_test_directory(name))
            )

        # Called per regular file with a forward-slash (POSIX) relative path, so
        # unit IDs are stable across OSes.
        def _on_file(entry, relative_path: str) -> None:
            # Case-insensitive: filesystems (macOS/Windows) and users may spell
            # the extension .SWIFT/.Swift; skipping those silently loses files.
            if not entry.name.lower().endswith(".swift"):
                return
            if self.skip_tests and self._is_test_file(relative_path):
                return
            try:
                size = entry.stat().st_size
            except OSError:
                size = 0
            files.append({"path": relative_path, "size": size})

        # Traversal delegated to the shared core/repo_walk.py: an explicit
        # iterator stack that records unreadable/too-deep subtrees in `stats`
        # rather than silently dropping them (os.walk vanishes a path past
        # PATH_MAX), and bounds symlink cycles. Matches the other parsers.
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

        A file is a test iff one of its directory components is a test directory,
        or its filename is anchored (stem prefix ``test_``/``spec_`` or suffix
        ``Tests.swift``/``Test.swift``/``Spec.swift`` — matched case-insensitively).
        Anchoring stops ordinary names like ``Sources/fastest.swift`` or
        ``latest/main.swift`` from matching, while still catching the dominant
        XCTest ``FooTests.swift`` convention (which has no underscore).
        """
        p = Path(filepath)
        # Directory components: whole-segment, case-insensitive.
        if any(part.lower() in self.TEST_DIR_NAMES for part in p.parts[:-1]):
            return True
        name = p.name
        name_lower = name.lower()
        if name_lower.startswith(self.TEST_FILE_PREFIXES):
            return True
        if name_lower.endswith(self.TEST_FILE_SUFFIXES_CI):  # underscore-anchored, CI
            return True
        if name.endswith(self.TEST_FILE_SUFFIXES_CS):  # CamelCase XCTest, case-sensitive
            return True
        return False

    def save_results(self, output_path: str, results: Dict[str, Any]) -> None:
        """Save scan results to a JSON file."""
        write_json(output_path, results)
