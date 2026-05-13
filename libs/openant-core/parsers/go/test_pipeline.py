#!/usr/bin/env python3
"""
Go Parser Pipeline Test Script

Tests the Go parser pipeline components:
1. go_parser scan - Enumerates source files
2. go_parser extract - Extracts functions with unit type classification
3. go_parser callgraph - Builds bidirectional call graphs
4. go_parser generate - Creates OpenAnt dataset format
5. CodeQL (optional) - Static analysis pre-filter
6. ContextEnhancer (optional) - LLM enhancement using Claude Sonnet

Usage:
    python test_pipeline.py <repo_path> [--output <dir>] [--llm] [--agentic] [--processing-level LEVEL]

Processing Levels (cumulative filtering):
    Level 1: all         - Process all units (no filtering)
    Level 2: reachable   - Process only units reachable from entry points
    Level 3: codeql      - Process only reachable + CodeQL-flagged units
    Level 4: exploitable - Process only reachable + CodeQL-flagged + exploitable units

Example:
    # Static analysis only
    python test_pipeline.py /path/to/repo --output /tmp/output

    # With agentic LLM enhancement
    python test_pipeline.py /path/to/repo --output /tmp/output --llm --agentic

    # CodeQL pre-filter + agentic classification
    python test_pipeline.py /path/to/repo --output /tmp/output --llm --agentic --processing-level codeql

    # Maximum cost savings: only exploitable units
    python test_pipeline.py /path/to/repo --output /tmp/output --llm --agentic --processing-level exploitable
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Set

# Add parent directories to path so utilities can be found when run as a subprocess
_parser_dir = Path(__file__).parent
_core_root = _parser_dir.parent.parent
if str(_core_root) not in sys.path:
    sys.path.insert(0, str(_core_root))

from utilities.file_io import open_utf8, read_json, run_utf8, write_json


def _stdout_supports_unicode() -> bool:
    """Return True if sys.stdout can emit the symbols we use for status.

    Returns False when stdout is piped or redirected (common in CI) and
    the encoding cannot be determined — this degrades output to plain ASCII
    rather than raising UnicodeEncodeError at runtime.
    """
    encoding = getattr(sys.stdout, "encoding", None)
    if not encoding:
        return False
    try:
        # Probe with the actual symbols we emit. This catches cp1252 and
        # other limited code pages without us having to enumerate them.
        "✓✗→".encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


_UNICODE_OK = _stdout_supports_unicode()
SYM_OK = "✓" if _UNICODE_OK else "OK"
SYM_FAIL = "✗" if _UNICODE_OK else "FAIL"
SYM_ARROW = "→" if _UNICODE_OK else "->"

# Add parent directory to path for utilities import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from utilities.context_enhancer import ContextEnhancer
from utilities.agentic_enhancer import EntryPointDetector, ReachabilityAnalyzer


class ProcessingLevel(Enum):
    """
    Processing level determines which units are processed.
    Levels are cumulative - each level includes filters from previous levels.
    """
    ALL = "all"                    # Level 1: Process all units (no filtering)
    REACHABLE = "reachable"        # Level 2: Filter to reachable from entry points
    CODEQL = "codeql"              # Level 3: Filter to reachable + CodeQL-flagged
    EXPLOITABLE = "exploitable"    # Level 4: Filter to reachable + CodeQL-flagged + exploitable


class GoPipelineTest:
    def __init__(
        self,
        repo_path: str,
        output_dir: str = None,
        enable_llm: bool = False,
        agentic: bool = False,
        processing_level: ProcessingLevel = ProcessingLevel.ALL,
        skip_tests: bool = False,
        depth: int = 3,
        name: str = None
    ):
        self.repo_path = os.path.abspath(repo_path)
        self.output_dir = output_dir or os.path.join(os.path.dirname(__file__), 'test_output')
        self.parser_dir = os.path.dirname(os.path.abspath(__file__))
        self.enable_llm = enable_llm
        self.agentic = agentic
        self.processing_level = processing_level
        self.skip_tests = skip_tests
        self.depth = depth
        self.dataset_name = name

        # Go parser binary location
        self.go_parser = os.path.join(self.parser_dir, 'go_parser', 'go_parser')

        # Pipeline artifacts
        self.scan_results_file = None
        self.analyzer_output_file = None
        self.dataset_file = None

        # Reachability data (populated if processing_level >= REACHABLE)
        self.entry_points: Set[str] = set()
        self.reachable_units: Set[str] = set()

        # CodeQL data (populated if processing_level >= CODEQL)
        self.codeql_flagged_units: Set[str] = set()
        self.codeql_findings: list = []

        # Results
        self.results = {
            'repository': self.repo_path,
            'test_time': datetime.now().isoformat(),
            'processing_level': processing_level.value,
            'stages': {}
        }

    def setup(self):
        """Create output directory and build Go parser if needed."""
        os.makedirs(self.output_dir, exist_ok=True)
        print(f"Output directory: {self.output_dir}")

        # Check if Go parser binary exists, build if not
        if not os.path.exists(self.go_parser):
            print("Building Go parser...")
            go_parser_dir = os.path.join(self.parser_dir, 'go_parser')
            result = run_utf8(
                ['go', 'build', '-o', 'go_parser', '.'],
                cwd=go_parser_dir,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                print(f"Error building Go parser: {result.stderr}")
                return False
            print("  Go parser built successfully")

        print()
        return True

    def run_stage(self, name: str, command: list, output_file: str) -> dict:
        """Run a pipeline stage and capture results."""
        print(f"=" * 60)
        print(f"STAGE: {name}")
        print(f"=" * 60)
        print(f"Command: {' '.join(command)}")
        print()

        start_time = datetime.now()

        try:
            result = run_utf8(
                command,
                capture_output=True,
                text=True,
                cwd=self.parser_dir
            )

            elapsed = (datetime.now() - start_time).total_seconds()

            stage_result = {
                'success': result.returncode == 0,
                'elapsed_seconds': elapsed,
                'output_file': output_file if result.returncode == 0 else None,
                'stdout': result.stdout,
                'stderr': result.stderr
            }

            if result.returncode == 0:
                print(f"{SYM_OK} Success ({elapsed:.2f}s)")
                print()
                # Print stderr (often contains summary info)
                if result.stderr:
                    for line in result.stderr.strip().split('\n'):
                        print(f"  {line}")
                print()

                # Load and summarize output
                if os.path.exists(output_file):
                    data = read_json(output_file)
                    stage_result['summary'] = self._summarize_output(name, data)
            else:
                print(f"{SYM_FAIL} Failed (exit code {result.returncode})")
                print()
                if result.stderr:
                    print("STDERR:")
                    print(result.stderr)
                if result.stdout:
                    print("STDOUT:")
                    print(result.stdout[:500])

            return stage_result

        except Exception as e:
            elapsed = (datetime.now() - start_time).total_seconds()
            print(f"{SYM_FAIL} Error: {e}")
            return {
                'success': False,
                'elapsed_seconds': elapsed,
                'error': str(e)
            }

    def _summarize_output(self, stage: str, data: dict) -> dict:
        """Extract summary statistics from stage output."""
        if stage == 'go_scan':
            stats = data.get('statistics', {})
            return {
                'total_files': stats.get('total_files', stats.get('totalFiles', 0)),
                'total_size_bytes': stats.get('total_size_bytes', stats.get('totalSizeBytes', 0))
            }
        elif stage == 'go_extract':
            functions = data.get('functions', {})

            # Count by unit type
            by_type = {}
            for func in functions.values():
                unit_type = func.get('unit_type', func.get('unitType', 'unknown'))
                by_type[unit_type] = by_type.get(unit_type, 0) + 1

            return {
                'total_functions': len(functions),
                'by_unit_type': by_type
            }
        elif stage == 'go_all' or stage == 'go_generate':
            stats = data.get('statistics', {})
            call_graph_stats = stats.get('call_graph', stats.get('callGraph', {}))

            return {
                'total_units': stats.get('total_units', stats.get('totalUnits', 0)),
                'by_type': stats.get('by_type', stats.get('byType', {})),
                'call_graph_edges': call_graph_stats.get('total_edges', call_graph_stats.get('totalEdges', 0)),
                'avg_out_degree': call_graph_stats.get('avg_out_degree', call_graph_stats.get('avgOutDegree', 0))
            }
        return {}

    def run_go_parser_all(self) -> bool:
        """Run go_parser all command to execute full pipeline."""
        self.dataset_file = os.path.join(self.output_dir, 'dataset.json')
        self.analyzer_output_file = os.path.join(self.output_dir, 'analyzer_output.json')

        # Build command with flags BEFORE positional argument
        command = [self.go_parser, 'all', '--output', self.dataset_file]
        if self.skip_tests:
            command.append('--skip-tests')
        if self.depth != 3:
            command.extend(['--depth', str(self.depth)])
        command.extend(['--analyzer-output', self.analyzer_output_file])
        command.append(self.repo_path)

        result = self.run_stage('go_all', command, self.dataset_file)

        # Post-process: apply dataset name if specified (Go binary doesn't support --name)
        if result.get('success', False) and self.dataset_name and os.path.exists(self.dataset_file):
            try:
                dataset = read_json(self.dataset_file)
                dataset['name'] = self.dataset_name
                write_json(self.dataset_file, dataset)
            except Exception as e:
                print(f"Warning: Could not apply dataset name: {e}")

        self.results['stages']['go_parser'] = result

        # Write call_graph.json immediately after parsing so the post-LLM
        # reachability re-filter can use it regardless of processing_level.
        # Go's analyzer_output.json has functions; the call graph edges live
        # in each unit's metadata.direct_calls / direct_callers.
        if (
            result.get('success', False)
            and self.analyzer_output_file and os.path.exists(self.analyzer_output_file)
            and self.dataset_file and os.path.exists(self.dataset_file)
        ):
            try:
                analyzer = read_json(self.analyzer_output_file)
                dataset_for_cg = read_json(self.dataset_file)

                raw_functions = analyzer.get("functions", {})
                # Normalise to the camelCase shape EntryPointDetector expects.
                normalized_functions = {
                    func_id: {
                        'name': fd.get('name', ''),
                        'unitType': fd.get('unit_type', fd.get('unitType', 'function')),
                        'code': fd.get('code', ''),
                        'filePath': fd.get('file_path', fd.get('filePath', '')),
                        'startLine': fd.get('start_line', fd.get('startLine', 0)),
                        'endLine': fd.get('end_line', fd.get('endLine', 0)),
                        'package': fd.get('package', ''),
                        'receiver': fd.get('receiver', ''),
                        'isExported': fd.get('is_exported', fd.get('isExported', False)),
                    }
                    for func_id, fd in raw_functions.items()
                }

                call_graph: dict = {}
                reverse_call_graph: dict = {}
                for unit in dataset_for_cg.get('units', []):
                    unit_id = unit.get('id')
                    metadata = unit.get('metadata', {})
                    direct_calls = metadata.get('direct_calls', metadata.get('directCalls', []))
                    direct_callers = metadata.get('direct_callers', metadata.get('directCallers', []))
                    if direct_calls:
                        call_graph[unit_id] = direct_calls
                    if direct_callers:
                        reverse_call_graph[unit_id] = direct_callers

                call_graph_file = os.path.join(self.output_dir, 'call_graph.json')
                write_json(call_graph_file, {
                    "functions": normalized_functions,
                    "call_graph": call_graph,
                    "reverse_call_graph": reverse_call_graph,
                })
            except (OSError, json.JSONDecodeError, KeyError) as e:
                print(f"Warning: could not write call_graph.json: {e}")

        return result.get('success', False)

    def apply_reachability_filter(self) -> bool:
        """
        Filter dataset to only include units reachable from entry points.

        This is Stage 3.5 - applied after go_parser if processing_level >= REACHABLE.
        Uses static analysis to identify entry points and trace reachability via call graph.

        Returns:
            True if filtering succeeded, False otherwise
        """
        if not self.analyzer_output_file or not os.path.exists(self.analyzer_output_file):
            print("No analyzer output for reachability filtering")
            return False

        if not self.dataset_file or not os.path.exists(self.dataset_file):
            print("No dataset to filter")
            return False

        print("=" * 60)
        print("STAGE: reachability_filter (static analysis)")
        print("=" * 60)
        print()

        start_time = datetime.now()

        try:
            # Load analyzer output for call graph
            analyzer = read_json(self.analyzer_output_file)

            functions = analyzer.get("functions", {})

            # Convert to expected format for EntryPointDetector
            # Go parser uses snake_case, EntryPointDetector expects camelCase
            normalized_functions = {}
            for func_id, func_data in functions.items():
                normalized_functions[func_id] = {
                    'name': func_data.get('name', ''),
                    'unitType': func_data.get('unit_type', func_data.get('unitType', 'function')),
                    'code': func_data.get('code', ''),
                    'filePath': func_data.get('file_path', func_data.get('filePath', '')),
                    'startLine': func_data.get('start_line', func_data.get('startLine', 0)),
                    'endLine': func_data.get('end_line', func_data.get('endLine', 0)),
                    'package': func_data.get('package', ''),
                    'receiver': func_data.get('receiver', ''),
                    'isExported': func_data.get('is_exported', func_data.get('isExported', False)),
                }

            # Load call graph from dataset (go_parser puts it in statistics)
            dataset = read_json(self.dataset_file)

            # Build call graph from unit metadata
            call_graph = {}
            reverse_call_graph = {}
            for unit in dataset.get('units', []):
                unit_id = unit.get('id')
                metadata = unit.get('metadata', {})
                direct_calls = metadata.get('direct_calls', metadata.get('directCalls', []))
                direct_callers = metadata.get('direct_callers', metadata.get('directCallers', []))

                if direct_calls:
                    call_graph[unit_id] = direct_calls
                if direct_callers:
                    reverse_call_graph[unit_id] = direct_callers

            # Detect entry points
            detector = EntryPointDetector(normalized_functions, call_graph)
            self.entry_points = detector.detect_entry_points()

            # Build reachability analyzer
            reachability = ReachabilityAnalyzer(
                functions=normalized_functions,
                reverse_call_graph=reverse_call_graph,
                entry_points=self.entry_points
            )
            self.reachable_units = reachability.get_all_reachable()

            units = dataset.get("units", [])
            original_count = len(units)

            # Filter to reachable units and stamp reachability tags
            filtered_units = []
            for u in units:
                unit_id = u.get("id", "")
                if unit_id in self.reachable_units:
                    u["reachable"] = True
                    u["is_entry_point"] = unit_id in self.entry_points
                    if unit_id in self.entry_points:
                        u["entry_point_reason"] = detector.get_entry_point_reason(unit_id)
                    filtered_units.append(u)

            # Update dataset
            dataset["units"] = filtered_units
            dataset["metadata"] = dataset.get("metadata", {})
            dataset["metadata"]["reachability_filter"] = {
                "original_units": original_count,
                "entry_points": len(self.entry_points),
                "reachable_units": len(filtered_units),
                "filtered_out": original_count - len(filtered_units),
                "reduction_percentage": round((1 - len(filtered_units) / original_count) * 100, 1) if original_count > 0 else 0
            }

            # Write filtered dataset
            write_json(self.dataset_file, dataset)

            elapsed = (datetime.now() - start_time).total_seconds()

            summary = {
                'original_units': original_count,
                'entry_points': len(self.entry_points),
                'reachable_units': len(filtered_units),
                'reduction_percentage': dataset["metadata"]["reachability_filter"]["reduction_percentage"]
            }

            result = {
                'success': True,
                'elapsed_seconds': elapsed,
                'output_file': self.dataset_file,
                'summary': summary
            }

            print(f"{SYM_OK} Success ({elapsed:.2f}s)")
            print(f"  Entry points detected: {len(self.entry_points)}")
            print(f"  Units: {original_count} {SYM_ARROW} {len(filtered_units)} ({summary['reduction_percentage']}% reduction)")
            print()

            self.results['stages']['reachability_filter'] = result
            return True

        except Exception as e:
            elapsed = (datetime.now() - start_time).total_seconds()
            print(f"{SYM_FAIL} Error: {e}")
            import traceback
            traceback.print_exc()
            result = {
                'success': False,
                'elapsed_seconds': elapsed,
                'error': str(e)
            }
            self.results['stages']['reachability_filter'] = result
            return False

    def run_codeql_analysis(self) -> bool:
        """
        Run CodeQL analysis on the repository.

        This is Stage 3.6 - runs CodeQL to identify potentially vulnerable code.
        Creates a CodeQL database, runs security queries, and parses SARIF output.

        Returns:
            True if analysis succeeded, False otherwise
        """
        print("=" * 60)
        print("STAGE: codeql_analysis")
        print("=" * 60)
        print()

        start_time = datetime.now()

        # Go language for CodeQL
        language = "go"
        print(f"Language: {language}")

        codeql_db_path = os.path.join(self.output_dir, 'codeql-db')
        sarif_output = os.path.join(self.output_dir, 'codeql-results.sarif')

        try:
            # Step 1: Create CodeQL database
            print("Creating CodeQL database...")
            create_db_cmd = [
                'codeql', 'database', 'create',
                codeql_db_path,
                f'--language={language}',
                f'--source-root={self.repo_path}',
                '--overwrite'
            ]

            result = run_utf8(
                create_db_cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )

            if result.returncode != 0:
                print(f"{SYM_FAIL} CodeQL database creation failed")
                print(f"  stderr: {result.stderr[:500] if result.stderr else 'none'}")
                elapsed = (datetime.now() - start_time).total_seconds()
                self.results['stages']['codeql_analysis'] = {
                    'success': False,
                    'elapsed_seconds': elapsed,
                    'error': 'Database creation failed',
                    'stderr': result.stderr
                }
                return False

            print("  Database created successfully")

            # Step 2: Run security queries
            print("Running security queries...")
            analyze_cmd = [
                'codeql', 'database', 'analyze',
                codeql_db_path,
                '--format=sarif-latest',
                f'--output={sarif_output}',
                f'codeql/{language}-queries:codeql-suites/{language}-security-extended.qls'
            ]

            result = run_utf8(
                analyze_cmd,
                capture_output=True,
                text=True,
                timeout=1800  # 30 minute timeout
            )

            if result.returncode != 0:
                print(f"{SYM_FAIL} CodeQL analysis failed")
                print(f"  stderr: {result.stderr[:500] if result.stderr else 'none'}")
                elapsed = (datetime.now() - start_time).total_seconds()
                self.results['stages']['codeql_analysis'] = {
                    'success': False,
                    'elapsed_seconds': elapsed,
                    'error': 'Analysis failed',
                    'stderr': result.stderr
                }
                return False

            print("  Analysis completed")

            # Step 3: Parse SARIF output
            print("Parsing results...")
            if not os.path.exists(sarif_output):
                print(f"{SYM_FAIL} SARIF output not found")
                elapsed = (datetime.now() - start_time).total_seconds()
                self.results['stages']['codeql_analysis'] = {
                    'success': False,
                    'elapsed_seconds': elapsed,
                    'error': 'SARIF output not found'
                }
                return False

            sarif_data = read_json(sarif_output)

            # Extract findings and map to file:line
            self.codeql_findings = []

            for run in sarif_data.get('runs', []):
                for result in run.get('results', []):
                    rule_id = result.get('ruleId', 'unknown')
                    message = result.get('message', {}).get('text', '')
                    level = result.get('level', 'warning')

                    for location in result.get('locations', []):
                        physical = location.get('physicalLocation', {})
                        artifact = physical.get('artifactLocation', {})
                        uri = artifact.get('uri', '')
                        region = physical.get('region', {})
                        start_line = region.get('startLine', 0)
                        end_line = region.get('endLine', start_line)

                        finding = {
                            'rule_id': rule_id,
                            'message': message,
                            'level': level,
                            'file': uri,
                            'start_line': start_line,
                            'end_line': end_line
                        }
                        self.codeql_findings.append(finding)

            elapsed = (datetime.now() - start_time).total_seconds()

            summary = {
                'total_findings': len(self.codeql_findings),
                'unique_files': len(set(f['file'] for f in self.codeql_findings)),
                'by_level': {},
                'by_rule': {}
            }

            for finding in self.codeql_findings:
                level = finding['level']
                rule = finding['rule_id']
                summary['by_level'][level] = summary['by_level'].get(level, 0) + 1
                summary['by_rule'][rule] = summary['by_rule'].get(rule, 0) + 1

            result_data = {
                'success': True,
                'elapsed_seconds': elapsed,
                'output_file': sarif_output,
                'summary': summary
            }

            print(f"{SYM_OK} Success ({elapsed:.2f}s)")
            print(f"  Total findings: {len(self.codeql_findings)}")
            print(f"  Unique files: {summary['unique_files']}")
            if summary['by_level']:
                print(f"  By level: {summary['by_level']}")
            print()

            self.results['stages']['codeql_analysis'] = result_data
            return True

        except FileNotFoundError:
            elapsed = (datetime.now() - start_time).total_seconds()
            print(f"{SYM_FAIL} CodeQL not found. Please install CodeQL CLI.")
            print("  See: https://docs.github.com/en/code-security/codeql-cli")
            self.results['stages']['codeql_analysis'] = {
                'success': False,
                'elapsed_seconds': elapsed,
                'error': 'CodeQL CLI not installed'
            }
            return False

        except subprocess.TimeoutExpired:
            elapsed = (datetime.now() - start_time).total_seconds()
            print(f"{SYM_FAIL} CodeQL analysis timed out")
            self.results['stages']['codeql_analysis'] = {
                'success': False,
                'elapsed_seconds': elapsed,
                'error': 'Timeout'
            }
            return False

        except Exception as e:
            elapsed = (datetime.now() - start_time).total_seconds()
            print(f"{SYM_FAIL} Error: {e}")
            import traceback
            traceback.print_exc()
            self.results['stages']['codeql_analysis'] = {
                'success': False,
                'elapsed_seconds': elapsed,
                'error': str(e)
            }
            return False

    def apply_codeql_filter(self) -> bool:
        """
        Filter dataset to only include units flagged by CodeQL.

        This is Stage 3.7 - applied after CodeQL analysis if processing_level >= CODEQL.
        Maps CodeQL findings (file:line) to function units based on line ranges.

        Returns:
            True if filtering succeeded, False otherwise
        """
        if not self.dataset_file or not os.path.exists(self.dataset_file):
            print("No dataset to filter")
            return False

        if not self.codeql_findings:
            print("No CodeQL findings to filter by")
            return False

        print("=" * 60)
        print("STAGE: codeql_filter")
        print("=" * 60)
        print()

        start_time = datetime.now()

        try:
            # Load dataset to get function line ranges
            dataset = read_json(self.dataset_file)

            # Build mapping of file -> [(start_line, end_line, func_id)]
            file_functions = {}
            for unit in dataset.get('units', []):
                unit_id = unit.get('id', '')
                origin = unit.get('code', {}).get('primary_origin', unit.get('code', {}).get('primaryOrigin', {}))
                file_path = origin.get('file_path', origin.get('filePath', ''))
                start_line = origin.get('start_line', origin.get('startLine', 0))
                end_line = origin.get('end_line', origin.get('endLine', start_line))

                if file_path:
                    if file_path not in file_functions:
                        file_functions[file_path] = []
                    file_functions[file_path].append((start_line, end_line, unit_id))

            # Map CodeQL findings to function units
            for finding in self.codeql_findings:
                file_uri = finding['file']
                finding_start = finding['start_line']
                finding_end = finding['end_line']

                # Try to match file path (CodeQL uses relative URIs)
                matched_file = None
                for file_path in file_functions.keys():
                    if file_path.endswith(file_uri) or file_uri.endswith(file_path) or file_path == file_uri:
                        matched_file = file_path
                        break

                if matched_file:
                    # Find functions that contain this finding
                    for start, end, func_id in file_functions[matched_file]:
                        if start <= finding_start <= end or start <= finding_end <= end:
                            self.codeql_flagged_units.add(func_id)

            units = dataset.get("units", [])
            original_count = len(units)

            # Filter to CodeQL-flagged units
            filtered_units = [u for u in units if u.get("id") in self.codeql_flagged_units]

            # Update dataset
            dataset["units"] = filtered_units
            dataset["metadata"] = dataset.get("metadata", {})
            dataset["metadata"]["codeql_filter"] = {
                "original_units": original_count,
                "codeql_findings": len(self.codeql_findings),
                "flagged_units": len(self.codeql_flagged_units),
                "filtered_units": len(filtered_units),
                "filtered_out": original_count - len(filtered_units),
                "reduction_percentage": round((1 - len(filtered_units) / original_count) * 100, 1) if original_count > 0 else 0
            }

            # Write filtered dataset
            write_json(self.dataset_file, dataset)

            elapsed = (datetime.now() - start_time).total_seconds()

            summary = {
                'original_units': original_count,
                'codeql_findings': len(self.codeql_findings),
                'flagged_units': len(self.codeql_flagged_units),
                'filtered_units': len(filtered_units),
                'reduction_percentage': dataset["metadata"]["codeql_filter"]["reduction_percentage"]
            }

            result = {
                'success': True,
                'elapsed_seconds': elapsed,
                'output_file': self.dataset_file,
                'summary': summary
            }

            print(f"{SYM_OK} Success ({elapsed:.2f}s)")
            print(f"  CodeQL findings: {len(self.codeql_findings)}")
            print(f"  Flagged function units: {len(self.codeql_flagged_units)}")
            print(f"  Units: {original_count} {SYM_ARROW} {len(filtered_units)} ({summary['reduction_percentage']}% reduction)")
            print()

            self.results['stages']['codeql_filter'] = result
            return True

        except Exception as e:
            elapsed = (datetime.now() - start_time).total_seconds()
            print(f"{SYM_FAIL} Error: {e}")
            import traceback
            traceback.print_exc()
            result = {
                'success': False,
                'elapsed_seconds': elapsed,
                'error': str(e)
            }
            self.results['stages']['codeql_filter'] = result
            return False

    def run_context_enhancer(self) -> bool:
        """Stage 4 (optional): Enhance dataset with LLM context."""
        if not self.dataset_file or not os.path.exists(self.dataset_file):
            print("No dataset to enhance")
            return False

        mode = "agentic" if self.agentic else "single-shot"
        print("=" * 60)
        print(f"STAGE: context_enhancer (Python, {mode} mode)")
        print("=" * 60)
        print()

        start_time = datetime.now()

        try:
            # Load dataset
            dataset = read_json(self.dataset_file)

            # Enhance with LLM
            enhancer = ContextEnhancer()

            if self.agentic:
                # Agentic mode - iterative tool use
                enhanced = enhancer.enhance_dataset_agentic(
                    dataset,
                    analyzer_output_path=self.analyzer_output_file,
                    repo_path=self.repo_path,
                    batch_size=5,
                    verbose=False
                )
                # Get agentic stats for summary
                agentic_stats = enhanced.get('metadata', {}).get('agentic_stats', {})
                summary = {
                    'mode': 'agentic',
                    'units_processed': agentic_stats.get('units_processed', 0),
                    'units_with_context': agentic_stats.get('units_with_context', 0),
                    'functions_added': agentic_stats.get('functions_added', 0),
                    'security_controls_found': agentic_stats.get('security_controls_found', 0),
                    'vulnerable_found': agentic_stats.get('vulnerable_found', 0),
                    'neutral_found': agentic_stats.get('neutral_found', 0)
                }
            else:
                # Single-shot mode (default)
                enhanced = enhancer.enhance_dataset(dataset)
                summary = {
                    'mode': 'single-shot',
                    'units_enhanced': enhancer.stats['units_enhanced'],
                    'dependencies_added': enhancer.stats['dependencies_added'],
                    'callers_added': enhancer.stats['callers_added'],
                    'data_flows_extracted': enhancer.stats['data_flows_extracted']
                }

            # Write back
            write_json(self.dataset_file, enhanced)

            elapsed = (datetime.now() - start_time).total_seconds()

            result = {
                'success': True,
                'elapsed_seconds': elapsed,
                'output_file': self.dataset_file,
                'summary': summary
            }

            print()
            print(f"{SYM_OK} Success ({elapsed:.2f}s)")

            self.results['stages']['context_enhancer'] = result
            return True

        except Exception as e:
            elapsed = (datetime.now() - start_time).total_seconds()
            print(f"{SYM_FAIL} Error: {e}")
            import traceback
            traceback.print_exc()
            result = {
                'success': False,
                'elapsed_seconds': elapsed,
                'error': str(e)
            }
            self.results['stages']['context_enhancer'] = result
            return False

    def apply_exploitable_filter(self) -> bool:
        """
        Filter dataset to only include units classified as 'exploitable'.

        This is Stage 4.5 - applied after ContextEnhancer if processing_level == EXPLOITABLE.
        Requires agentic mode to have classified units with security_classification.

        Returns:
            True if filtering succeeded, False otherwise
        """
        if not self.dataset_file or not os.path.exists(self.dataset_file):
            print("No dataset to filter")
            return False

        print("=" * 60)
        print("STAGE: exploitable_filter")
        print("=" * 60)
        print()

        start_time = datetime.now()

        try:
            dataset = read_json(self.dataset_file)

            units = dataset.get("units", [])
            original_count = len(units)

            # Filter to exploitable units only
            filtered_units = []
            classification_counts = {}

            for unit in units:
                agent_context = unit.get("agent_context", {})
                classification = agent_context.get("security_classification", "unknown")
                classification_counts[classification] = classification_counts.get(classification, 0) + 1

                if classification == "exploitable":
                    filtered_units.append(unit)

            # Update dataset
            dataset["units"] = filtered_units
            dataset["metadata"] = dataset.get("metadata", {})
            dataset["metadata"]["exploitable_filter"] = {
                "original_units": original_count,
                "exploitable_units": len(filtered_units),
                "filtered_out": original_count - len(filtered_units),
                "classification_counts": classification_counts,
                "reduction_percentage": round((1 - len(filtered_units) / original_count) * 100, 1) if original_count > 0 else 0
            }

            # Write filtered dataset
            write_json(self.dataset_file, dataset)

            elapsed = (datetime.now() - start_time).total_seconds()

            summary = {
                'original_units': original_count,
                'exploitable_units': len(filtered_units),
                'classification_counts': classification_counts,
                'reduction_percentage': dataset["metadata"]["exploitable_filter"]["reduction_percentage"]
            }

            result = {
                'success': True,
                'elapsed_seconds': elapsed,
                'output_file': self.dataset_file,
                'summary': summary
            }

            print(f"{SYM_OK} Success ({elapsed:.2f}s)")
            print(f"  Classification breakdown:")
            for cls, count in sorted(classification_counts.items()):
                marker = SYM_ARROW if cls == "exploitable" else " "
                print(f"    {marker} {cls}: {count}")
            print(f"  Units: {original_count} {SYM_ARROW} {len(filtered_units)} ({summary['reduction_percentage']}% reduction)")
            print()

            self.results['stages']['exploitable_filter'] = result
            return True

        except Exception as e:
            elapsed = (datetime.now() - start_time).total_seconds()
            print(f"{SYM_FAIL} Error: {e}")
            import traceback
            traceback.print_exc()
            result = {
                'success': False,
                'elapsed_seconds': elapsed,
                'error': str(e)
            }
            self.results['stages']['exploitable_filter'] = result
            return False

    def run_full_pipeline(self):
        """Run the complete pipeline."""
        print("=" * 60)
        print("GO PARSER PIPELINE TEST")
        print("=" * 60)
        print(f"Repository: {self.repo_path}")
        print(f"Processing Level: {self.processing_level.value}")
        print(f"Started: {self.results['test_time']}")
        print()

        if not self.setup():
            print("Pipeline stopped: Setup failed")
            return self.results

        # Stage 1-4: Run go_parser all command
        if not self.run_go_parser_all():
            print("Pipeline stopped: Go parser failed")
            return self.results

        # Stage 3.5 (optional): Reachability Filter
        # Applied if processing_level >= REACHABLE
        if self.processing_level in (ProcessingLevel.REACHABLE, ProcessingLevel.CODEQL, ProcessingLevel.EXPLOITABLE):
            if not self.apply_reachability_filter():
                print("Warning: Reachability filter failed, continuing with all units")

        # Stage 3.6-3.7 (optional): CodeQL Analysis and Filter
        # Applied if processing_level >= CODEQL
        if self.processing_level in (ProcessingLevel.CODEQL, ProcessingLevel.EXPLOITABLE):
            codeql_success = self.run_codeql_analysis()
            if codeql_success:
                if not self.apply_codeql_filter():
                    print("Warning: CodeQL filter failed, continuing with reachable units")
            else:
                print("Warning: CodeQL analysis failed, continuing with reachable units only")

        # Stage 4 (optional): Context Enhancer
        if self.enable_llm:
            if not self.run_context_enhancer():
                print("Warning: Context enhancer failed, continuing with static analysis only")

            # Stage 4.5 (optional): Exploitable Filter
            # Applied only if processing_level is EXPLOITABLE and agentic mode was used
            if self.processing_level == ProcessingLevel.EXPLOITABLE:
                if self.agentic:
                    if not self.apply_exploitable_filter():
                        print("Warning: Exploitable filter failed")
                else:
                    print()
                    print("Warning: Exploitable filter requires --agentic mode for classification")
                    print("Skipping exploitable filter")
        else:
            print()
            print("Skipping LLM enhancement (use --llm to enable)")
            if self.processing_level == ProcessingLevel.EXPLOITABLE:
                print("Warning: Exploitable level requires --llm --agentic for classification")

        # Summary
        print("=" * 60)
        print("PIPELINE SUMMARY")
        print("=" * 60)

        all_success = all(
            stage.get('success', False)
            for stage in self.results['stages'].values()
        )

        self.results['success'] = all_success

        if all_success:
            print(f"{SYM_OK} All stages completed successfully")
        else:
            print(f"{SYM_FAIL} Some stages failed")

        print()
        for stage_name, stage_result in self.results['stages'].items():
            status = SYM_OK if stage_result.get('success') else SYM_FAIL
            elapsed = stage_result.get('elapsed_seconds', 0)
            print(f"  {status} {stage_name}: {elapsed:.2f}s")

            if 'summary' in stage_result:
                summary = stage_result['summary']
                if 'total_files' in summary:
                    print(f"      Files: {summary['total_files']}")
                if 'total_functions' in summary:
                    print(f"      Functions: {summary['total_functions']}")
                    if 'by_unit_type' in summary:
                        for ut, count in summary['by_unit_type'].items():
                            print(f"        - {ut}: {count}")
                if 'total_units' in summary:
                    print(f"      Units: {summary['total_units']}")
                    edges = summary.get('call_graph_edges', 0)
                    avg_deg = summary.get('avg_out_degree', 0)
                    if edges:
                        print(f"      Call graph: {edges} edges, avg degree: {avg_deg:.2f}")
                if 'units_enhanced' in summary:
                    print(f"      Units enhanced: {summary['units_enhanced']}")
                    print(f"      Dependencies added: {summary.get('dependencies_added', 0)}")
                    print(f"      Callers added: {summary.get('callers_added', 0)}")
                    print(f"      Data flows extracted: {summary.get('data_flows_extracted', 0)}")

        print()
        print(f"Output files in: {self.output_dir}")

        # Save results summary
        results_file = os.path.join(self.output_dir, 'pipeline_results.json')
        with open_utf8(results_file, 'w') as f:
            # Remove stdout/stderr from saved results (too verbose)
            clean_results = {
                'repository': self.results['repository'],
                'test_time': self.results['test_time'],
                'processing_level': self.results.get('processing_level', 'all'),
                'success': self.results.get('success', False),
                'stages': {}
            }
            for stage_name, stage_result in self.results['stages'].items():
                clean_results['stages'][stage_name] = {
                    'success': stage_result.get('success', False),
                    'elapsed_seconds': stage_result.get('elapsed_seconds', 0),
                    'output_file': stage_result.get('output_file'),
                    'summary': stage_result.get('summary', {})
                }
            json.dump(clean_results, f, indent=2)

        print(f"Results summary: {results_file}")

        return self.results


def main():
    parser = argparse.ArgumentParser(
        description='Test the Go parser pipeline on a repository',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Processing Levels (cumulative filtering):
  all         Level 1: Process all units (no filtering, highest cost)
  reachable   Level 2: Filter to units reachable from entry points
  codeql      Level 3: Filter to reachable + CodeQL-flagged units (requires CodeQL CLI)
  exploitable Level 4: Filter to reachable + CodeQL-flagged + exploitable (requires --llm --agentic)

Examples:
  # Static analysis only (all units)
  python test_pipeline.py /path/to/repo

  # With reachability filtering only
  python test_pipeline.py /path/to/repo --processing-level reachable

  # With CodeQL pre-filter + agentic classification
  python test_pipeline.py /path/to/repo --llm --agentic --processing-level codeql

  # Maximum cost savings: only exploitable units
  python test_pipeline.py /path/to/repo --llm --agentic --processing-level exploitable
"""
    )
    parser.add_argument(
        'repo_path',
        help='Path to the Go repository to analyze'
    )
    parser.add_argument(
        '--output', '-o',
        help='Output directory for pipeline artifacts',
        default=None
    )
    parser.add_argument(
        '--llm',
        action='store_true',
        help='Enable LLM context enhancement (uses Claude Sonnet)'
    )
    parser.add_argument(
        '--agentic',
        action='store_true',
        help='Use agentic mode with iterative tool use (more accurate, more expensive)'
    )
    parser.add_argument(
        '--processing-level',
        choices=['all', 'reachable', 'codeql', 'exploitable'],
        default='all',
        help='Processing level: all (L1), reachable (L2), codeql (L3), exploitable (L4)'
    )
    parser.add_argument(
        '--skip-tests',
        action='store_true',
        help='Skip test files (*_test.go)'
    )
    parser.add_argument(
        '--depth', '-d',
        type=int,
        default=3,
        help='Max dependency resolution depth (default: 3)'
    )
    parser.add_argument(
        '--name', '-n',
        default=None,
        help='Dataset name (default: derived from repo path)'
    )

    args = parser.parse_args()

    if not os.path.exists(args.repo_path):
        print(f"Error: Repository not found: {args.repo_path}")
        sys.exit(1)

    processing_level = ProcessingLevel(args.processing_level)

    # Validate processing level requirements
    if processing_level == ProcessingLevel.EXPLOITABLE and not (args.llm and args.agentic):
        print("Warning: --processing-level exploitable requires --llm --agentic for classification")
        print("Units will be filtered by reachability only, not by exploitability")

    pipeline = GoPipelineTest(
        args.repo_path,
        args.output,
        enable_llm=args.llm,
        agentic=args.agentic,
        processing_level=processing_level,
        skip_tests=args.skip_tests,
        depth=args.depth,
        name=args.name
    )
    results = pipeline.run_full_pipeline()

    sys.exit(0 if results.get('success', False) else 1)


if __name__ == '__main__':
    main()
