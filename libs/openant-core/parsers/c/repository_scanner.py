#!/usr/bin/env python3
"""
Repository Scanner for C/C++ Codebases

Enumerates ALL C/C++ source files in a repository for complete coverage.
This is Phase 1 of the C/C++ parser - file discovery.

Usage:
    python repository_scanner.py <repo_path> [--output <file>] [--exclude <patterns>]

Output (JSON):
    {
        "repository": "/path/to/repo",
        "scan_time": "2025-12-30T...",
        "files": [
            { "path": "relative/path/to/file.c", "size": 1234, "extension": ".c" }
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


class RepositoryScanner:
    """
    Scan a repository for all C/C++ source files.

    This is Stage 1 of the C/C++ parser pipeline.
    """

    def __init__(self, repo_path: str, options: Optional[Dict] = None):
        self.repo_path = Path(repo_path).resolve()
        options = options or {}

        self.exclude_patterns: Set[str] = set(options.get('exclude_patterns', [
            '.git',
            '.svn',
            '.hg',
            'node_modules',
            '__pycache__',
            'build',
            'CMakeFiles',
            'third_party',
            'external',
            'vendor',
            'test',
            'tests',
            'testdata',
            'fuzz',
            'doc',
            'docs',
            'demos',
            'examples',
            'man',
            'dist',
            'bin',
            '.cache',
        ]))

        self.source_extensions: Set[str] = set(options.get('source_extensions', [
            '.c', '.h', '.cpp', '.hpp', '.cc', '.cxx', '.hxx', '.hh',
        ]))

        self.skip_tests = options.get('skip_tests', False)
        self.test_patterns = {'test/', 'tests/', 'fuzz/', '_test.c', '_test.cpp', 'test_'}

        self.stats = {
            'total_files': 0,
            'total_size_bytes': 0,
            'directories_scanned': 0,
            'directories_excluded': 0,
            'test_files_skipped': 0,
        }

        self.files: List[Dict] = []

    def should_exclude_directory(self, dir_name: str) -> bool:
        """Check if a directory should be excluded."""
        if dir_name in self.exclude_patterns:
            return True
        if dir_name.startswith('.') or dir_name.startswith('_'):
            return True
        if dir_name.startswith('cmake-build-'):
            return True
        return False

    def is_source_file(self, file_name: str) -> bool:
        """Check if a file is a C/C++ source file."""
        ext = os.path.splitext(file_name)[1].lower()
        return ext in self.source_extensions

    def is_test_file(self, relative_path: str) -> bool:
        """Check if a file is a test file."""
        path_lower = relative_path.lower()
        for pattern in self.test_patterns:
            if pattern in path_lower:
                return True
        return False

    def scan_directory(self, dir_path: Path, relative_path: str = '') -> None:
        """Recursively scan a directory."""
        self.stats['directories_scanned'] += 1

        try:
            entries = list(dir_path.iterdir())
        except PermissionError:
            print(f"Warning: Cannot read directory {dir_path}: Permission denied", file=sys.stderr)
            return
        except Exception as e:
            print(f"Warning: Cannot read directory {dir_path}: {e}", file=sys.stderr)
            return

        for entry in sorted(entries, key=lambda e: e.name):
            entry_relative = os.path.join(relative_path, entry.name) if relative_path else entry.name

            if entry.is_dir():
                if self.should_exclude_directory(entry.name):
                    self.stats['directories_excluded'] += 1
                    continue
                self.scan_directory(entry, entry_relative)

            elif entry.is_file():
                if not self.is_source_file(entry.name):
                    continue

                if self.skip_tests and self.is_test_file(entry_relative):
                    self.stats['test_files_skipped'] += 1
                    continue

                try:
                    file_size = entry.stat().st_size
                except Exception:
                    file_size = 0

                ext = os.path.splitext(entry.name)[1].lower()

                self.files.append({
                    'path': entry_relative,
                    'size': file_size,
                    'extension': ext,
                })

                self.stats['total_files'] += 1
                self.stats['total_size_bytes'] += file_size

    def scan(self) -> Dict:
        """Execute the repository scan and return results."""
        if not self.repo_path.exists():
            raise FileNotFoundError(f"Repository path does not exist: {self.repo_path}")

        if not self.repo_path.is_dir():
            raise NotADirectoryError(f"Repository path is not a directory: {self.repo_path}")

        self.files = []
        self.stats = {
            'total_files': 0,
            'total_size_bytes': 0,
            'directories_scanned': 0,
            'directories_excluded': 0,
            'test_files_skipped': 0,
        }

        self.scan_directory(self.repo_path)

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
        description='Scan a C/C++ repository for source files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python repository_scanner.py /path/to/repo
  python repository_scanner.py /path/to/repo --output scan_results.json
  python repository_scanner.py /path/to/repo --skip-tests
        '''
    )

    parser.add_argument('repo_path', help='Path to the repository to scan')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--exclude', help='Comma-separated additional exclude patterns')
    parser.add_argument('--skip-tests', action='store_true', help='Skip test files')

    args = parser.parse_args()

    options = {}
    if args.exclude:
        additional_excludes = [p.strip() for p in args.exclude.split(',')]
        default_excludes = [
            '.git', '.svn', '.hg', 'node_modules', '__pycache__',
            'build', 'CMakeFiles', 'third_party', 'external', 'vendor',
            'test', 'tests', 'testdata', 'fuzz', 'doc', 'docs',
            'demos', 'examples', 'man', 'dist', 'bin', '.cache',
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
