#!/usr/bin/env python3
"""
Repository Scanner for Ruby Codebases

Enumerates ALL Ruby source files in a repository for complete coverage.
This is Phase 1 of the Ruby parser - file discovery.

Usage:
    python repository_scanner.py <repo_path> [--output <file>] [--exclude <patterns>]

Output (JSON):
    {
        "repository": "/path/to/repo",
        "scan_time": "2025-12-30T...",
        "files": [
            { "path": "relative/path/to/file.rb", "size": 1234 }
        ],
        "statistics": {
            "total_files": 150,
            "total_size_bytes": 500000,
            "directories_scanned": 25,
            "directories_excluded": 10
        }
    }
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
from utilities.file_io import read_json, write_json, open_utf8
from core.repo_walk import walk_repository


class RepositoryScanner:
    """
    Scan a repository for all Ruby source files.

    This is Stage 1 of the Ruby parser pipeline. It walks the directory tree,
    identifies Ruby source files, and collects metadata about each file.

    Key features:
    - Excludes common non-source directories (vendor, .bundle, .git, etc.)
    - Optionally skips test files (test_*, *_test.rb, *_spec.rb, test/, spec/)
    - Collects file size statistics for monitoring

    Usage:
        scanner = RepositoryScanner('/path/to/repo')
        result = scanner.scan()
        # result['files'] contains list of {path, size} dicts

    Attributes:
        repo_path: Absolute path to the repository root
        exclude_patterns: Set of directory names to skip
        source_extensions: Set of file extensions to include (default: {'.rb', '.rake'})
        skip_tests: Whether to exclude test files
    """

    def __init__(self, repo_path: str, options: Optional[Dict] = None):
        self.repo_path = Path(repo_path).resolve()
        options = options or {}

        # Default exclude patterns
        self.exclude_patterns: Set[str] = set(options.get('exclude_patterns', [
            '.git',
            'vendor',
            '.bundle',
            'tmp',
            'log',
            'coverage',
            'build',
            'dist',
            'pkg',
            'node_modules',
            '.cache',
            'doc',
            'docs',
        ]))

        # Source file extensions
        self.source_extensions: Set[str] = set(options.get('source_extensions', [
            '.rb',
            '.rake',
        ]))

        # Skip test files by default (can be overridden)
        self.skip_tests = options.get('skip_tests', False)
        # Native Ruby test conventions (Minitest/RSpec). Directory names match
        # whole path segments; filename rules are anchored to the basename so
        # that ordinary sources like ``latest_release.rb``/``contest/foo.rb``
        # are NOT misclassified as tests (an unanchored substring scan would).
        self.test_dir_names = {'test', 'tests', 'spec'}
        self.test_file_prefixes = ('test_',)
        self.test_file_suffixes = ('_test.rb', '_spec.rb')

        self.stats = {
            'total_files': 0,
            'total_size_bytes': 0,
            'directories_scanned': 0,
            'directories_excluded': 0,
            'test_files_skipped': 0,
            # Directories whose contents could not be read (permission/OS error);
            # every file under them is silently dropped, so surface the count in
            # the structured result — not only on stderr — for consumers.
            'directories_read_failed': 0,
        }

        self.files: List[Dict] = []

        # Cycle guard: (st_dev, st_ino) of every directory already descended
        # into, so a symlink loop back to an ancestor does not cause infinite
        # recursion / duplicate scanning.
        self._visited_dirs: Set = set()

    def should_exclude_directory(self, dir_name: str) -> bool:
        """Check if a directory should be excluded."""
        # Exact match
        if dir_name in self.exclude_patterns:
            return True
        if dir_name.startswith('.'):
            # Exclude hidden directories
            return True
        return False

    def is_source_file(self, file_name: str) -> bool:
        """Check if a file is a Ruby source file."""
        ext = os.path.splitext(file_name)[1].lower()
        return ext in self.source_extensions

    def is_test_file(self, relative_path: str) -> bool:
        """Check if a file is a test file.

        Matches on path *components* and *anchored* filename rules rather than
        unanchored substrings, so non-test files whose name merely contains a
        token (``latest_release.rb``, ``contest/foo.rb``) are not skipped.
        """
        p = Path(relative_path)
        if any(part.lower() in self.test_dir_names for part in p.parts[:-1]):
            return True
        name_lower = p.name.lower()
        if name_lower.startswith(self.test_file_prefixes):
            return True
        if name_lower.endswith(self.test_file_suffixes):
            return True
        return False

    def scan_directory(self, dir_path: Path, relative_path: str = '') -> None:
        """Walk the tree via the shared walker.

        Traversal used to be implemented here, and independently in three sibling
        scanners. Each had to be fixed separately for symlink escape, deep nesting
        and stat-error handling, and each time at least one was missed. The walk now
        lives in ``core/repo_walk.py``; this method keeps only the parts that are
        genuinely language-specific: which files count as source, which count as
        tests, and what a record looks like.
        """
        def _on_file(entry: Path, entry_relative: str) -> None:
            if not self.is_source_file(entry.name):
                return
            if self.skip_tests and self.is_test_file(entry_relative):
                self.stats['test_files_skipped'] += 1
                return
            try:
                file_size = entry.stat().st_size
            except OSError:
                file_size = 0
            record = {'path': entry_relative, 'size': file_size}
            self.files.append(record)
            self.stats['total_files'] += 1
            self.stats['total_size_bytes'] += file_size

        walk_repository(
            dir_path,
            should_exclude_directory=self.should_exclude_directory,
            on_file=_on_file,
            stats=self.stats,
        )

    def scan(self) -> Dict:
        """Execute the repository scan and return results."""
        if not self.repo_path.exists():
            raise FileNotFoundError(f"Repository path does not exist: {self.repo_path}")

        if not self.repo_path.is_dir():
            raise NotADirectoryError(f"Repository path is not a directory: {self.repo_path}")

        self.files = []
        self._visited_dirs = set()
        self.stats = {
            'total_files': 0,
            'total_size_bytes': 0,
            'directories_scanned': 0,
            'directories_excluded': 0,
            'test_files_skipped': 0,
            'directories_read_failed': 0,
        }

        self.scan_directory(self.repo_path)

        # Sort files by path for consistent output
        self.files.sort(key=lambda f: f['path'])

        return {
            'repository': str(self.repo_path),
            'scan_time': datetime.now().isoformat(),
            'files': self.files,
            'statistics': self.stats,
        }


def main():
    """Command line interface."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Scan a Ruby repository for source files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python repository_scanner.py /path/to/repo
  python repository_scanner.py /path/to/repo --output scan_results.json
  python repository_scanner.py /path/to/repo --exclude "custom_dir,another_dir"
  python repository_scanner.py /path/to/repo --skip-tests
        '''
    )

    parser.add_argument('repo_path', help='Path to the repository to scan')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--exclude', help='Comma-separated additional exclude patterns')
    parser.add_argument('--skip-tests', action='store_true', help='Skip test files')

    args = parser.parse_args()

    # Build options
    options = {}
    if args.exclude:
        additional_excludes = [p.strip() for p in args.exclude.split(',')]
        default_excludes = [
            '.git', 'vendor', '.bundle', 'tmp', 'log', 'coverage',
            'build', 'dist', 'pkg', 'node_modules', '.cache', 'doc', 'docs',
        ]
        options['exclude_patterns'] = default_excludes + additional_excludes

    options['skip_tests'] = args.skip_tests

    try:
        scanner = RepositoryScanner(args.repo_path, options)
        result = scanner.scan()

        output = json.dumps(result, indent=2)

        if args.output:
            with open_utf8(args.output, 'w') as f:
                f.write(output)
            print(f"Scan complete. Results written to: {args.output}", file=sys.stderr)
            print(f"Total files found: {result['statistics']['total_files']}", file=sys.stderr)
            print(f"Total size: {result['statistics']['total_size_bytes']:,} bytes", file=sys.stderr)
            print(f"Directories scanned: {result['statistics']['directories_scanned']}", file=sys.stderr)
            print(f"Directories excluded: {result['statistics']['directories_excluded']}", file=sys.stderr)
            if args.skip_tests:
                print(f"Test files skipped: {result['statistics']['test_files_skipped']}", file=sys.stderr)
        else:
            print(output)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
