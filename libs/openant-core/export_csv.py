#!/usr/bin/env python3
"""
Export OpenAnt experiment results to CSV format for analysis in spreadsheets.

Combines experiment results with dataset metadata to produce a comprehensive
CSV file suitable for filtering, sorting, and analysis in Excel or Google Sheets.

Output Columns:
    - file: Source file path
    - unit_id: Unique identifier (file:function)
    - unit_description: What the code does (from LLM context)
    - unit_code: Complete source code
    - stage2_verdict: Final verdict after Stage 2 verification
    - stage2_justification: Stage 2 explanation
    - stage1_verdict: Initial Stage 1 detection verdict
    - stage1_justification: Stage 1 reasoning
    - stage1_confidence: Confidence score (0.0-1.0)
    - agentic_classification: Pre-analysis security classification

Usage:
    python export_csv.py <experiment_json> <dataset_json> [output_csv]

Example:
    python export_csv.py experiment_flowise.json datasets/flowise/dataset.json results.csv
"""

import argparse
import csv
import json
import os
import sys


def _load_diff_block(experiment_path: str) -> dict | None:
    """Look for the ``diff`` block in pipeline_output.json next to the
    experiment file. Returns None for full scans / when not found.
    Used to prepend an incremental-scan banner to CSV output.
    """
    exp_dir = os.path.dirname(os.path.abspath(experiment_path))
    candidate = os.path.join(exp_dir, "pipeline_output.json")
    if not os.path.exists(candidate):
        return None
    try:
        with open(candidate) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None
    diff = data.get("diff")
    if isinstance(diff, dict) and diff.get("mode") == "incremental":
        return diff
    return None


def _format_diff_banner(diff: dict) -> str:
    """Format the leading "# Incremental: ..." comment line for the CSV."""
    base = (diff.get("base_sha") or "")[:8]
    head = (diff.get("head_sha") or "")[:8]
    units_in = diff.get("units_in_diff")
    units_total = diff.get("units_total_parsed")
    scope = diff.get("scope") or ""
    units_str = ""
    if units_in is not None and units_total is not None:
        units_str = f", {units_in}/{units_total} units"
    scope_str = f", scope={scope}" if scope else ""
    return f"# Incremental: {base}..{head}{scope_str}{units_str}"


def load_json(path: str) -> dict:
    """Load JSON file."""
    with open(path, 'r') as f:
        return json.load(f)


def extract_file(unit_id: str) -> str:
    """Extract file path from unit ID."""
    if ':' in unit_id:
        return unit_id.rsplit(':', 1)[0]
    return unit_id


def get_stage1_verdict(result: dict) -> str:
    """Get the original Stage 1 verdict before Stage 2 modification."""
    verification = result.get('verification', {})
    verification_note = result.get('verification_note', '')

    # If Stage 2 disagreed, extract original from verification_note
    if verification_note and 'Changed from' in verification_note:
        # Format: "Changed from X to Y"
        parts = verification_note.split()
        for i, p in enumerate(parts):
            if p == 'from' and i + 1 < len(parts):
                return parts[i + 1]

    # If Stage 2 agreed, current finding is Stage 1's finding
    if verification.get('agree', True):
        return result.get('finding', '')

    # If disagreed but no note, try to infer
    # The verification.correct_finding is Stage 2's, so current finding should be Stage 2's
    # This is a fallback - ideally verification_note should exist
    return result.get('finding', '')


def export_csv(experiment_path: str, dataset_path: str, output_path: str):
    """
    Export experiment results to CSV.

    Args:
        experiment_path: Path to experiment results JSON
        dataset_path: Path to dataset JSON (for unit code and agentic context)
        output_path: Path for output CSV
    """
    # Load data
    experiment = load_json(experiment_path)
    dataset = load_json(dataset_path)

    # Build unit lookup by ID
    units_by_id = {}
    for unit in dataset.get('units', []):
        unit_id = unit.get('id', '')
        units_by_id[unit_id] = unit

    # Prepare CSV rows
    rows = []
    for result in experiment.get('results', []):
        route_key = result.get('route_key', '')

        # Get unit data from dataset
        unit = units_by_id.get(route_key, {})

        # Extract code from dataset
        code_field = unit.get('code', {})
        if isinstance(code_field, dict):
            unit_code = code_field.get('primary_code', '')
        else:
            unit_code = str(code_field) if code_field else ''

        # Get LLM context from dataset (may be None)
        llm_context = unit.get('llm_context') or {}

        # Get verification data from experiment result
        verification = result.get('verification') or {}

        # Determine Stage 1 verdict (before Stage 2 modification)
        stage1_verdict = get_stage1_verdict(result)

        # Stage 2 verdict is the final finding
        stage2_verdict = result.get('finding', '')

        # Build row
        row = {
            'file': extract_file(route_key),
            'unit_id': route_key,
            'unit_description': llm_context.get('reasoning', '')[:500] if llm_context.get('reasoning') else '',
            'unit_code': unit_code,
            'stage2_verdict': stage2_verdict,
            'stage2_justification': verification.get('explanation', ''),
            'stage1_verdict': stage1_verdict,
            'stage1_justification': result.get('reasoning', ''),
            'stage1_confidence': result.get('confidence', ''),
            'agentic_classification': llm_context.get('security_classification', '')
        }
        rows.append(row)

    # Write CSV
    fieldnames = [
        'file',
        'unit_id',
        'unit_description',
        'unit_code',
        'stage2_verdict',
        'stage2_justification',
        'stage1_verdict',
        'stage1_justification',
        'stage1_confidence',
        'agentic_classification'
    ]

    diff = _load_diff_block(experiment_path)

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        if diff is not None:
            # Comment line preceding the header — most CSV consumers
            # (Excel, Google Sheets, pandas with comment='#') ignore it,
            # while still being human-readable when opened raw.
            f.write(_format_diff_banner(diff) + "\n")
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Exported {len(rows)} rows to {output_path}")

    # Summary
    findings = {}
    for row in rows:
        f = row['stage2_verdict']
        findings[f] = findings.get(f, 0) + 1
    print(f"Findings: {findings}")


def main():
    parser = argparse.ArgumentParser(description='Export experiment results to CSV')
    parser.add_argument('experiment', help='Path to experiment results JSON')
    parser.add_argument('dataset', help='Path to dataset JSON')
    parser.add_argument('output', nargs='?', default='results.csv', help='Output CSV path (default: results.csv)')

    args = parser.parse_args()

    export_csv(args.experiment, args.dataset, args.output)


if __name__ == '__main__':
    main()
