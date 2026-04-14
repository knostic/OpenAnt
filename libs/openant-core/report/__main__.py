"""
CLI entry point for report module.

Usage:
    python -m report --help
    python -m report summary pipeline_output.json -o report.md
    python -m report disclosures pipeline_output.json -o disclosures/
    python -m report all pipeline_output.json -o output/
"""

import argparse
import json
import sys
from pathlib import Path

from .generator import generate_summary_report, generate_disclosure, generate_all
from .schema import validate_pipeline_output, ValidationError


def cmd_summary(args):
    """Generate summary report."""
    pipeline_data = json.loads(Path(args.input).read_text())

    try:
        validate_pipeline_output(pipeline_data)
    except ValidationError as e:
        print(f"Validation error: {e}", file=sys.stderr)
        sys.exit(1)

    print("Generating summary report...")
    report, usage = generate_summary_report(pipeline_data)

    output_path = Path(args.output) if args.output else Path("SUMMARY_REPORT.md")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report)
    print(f"  -> {output_path}")
    print(f"  Cost: ${usage['cost_usd']:.4f} ({usage['total_tokens']:,} tokens)")


def cmd_disclosures(args):
    """Generate disclosure documents."""
    pipeline_data = json.loads(Path(args.input).read_text())

    try:
        validate_pipeline_output(pipeline_data)
    except ValidationError as e:
        print(f"Validation error: {e}", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(args.output) if args.output else Path("disclosures")
    output_dir.mkdir(parents=True, exist_ok=True)

    product_name = pipeline_data["repository"]["name"]
    count = 0

    for i, finding in enumerate(pipeline_data["findings"], 1):
        if finding.get("stage2_verdict") not in ("confirmed", "agreed", "vulnerable"):
            continue

        print(f"Generating disclosure for {finding['short_name']}...")
        disclosure, _usage = generate_disclosure(finding, product_name)

        safe_name = finding["short_name"].replace(" ", "_").upper()
        filename = f"DISCLOSURE_{i:02d}_{safe_name}.md"
        (output_dir / filename).write_text(disclosure)
        print(f"  -> {output_dir / filename}")
        count += 1

    if count == 0:
        print("No confirmed vulnerabilities to generate disclosures for.")
    else:
        print(f"Generated {count} disclosure(s).")


def cmd_all(args):
    """Generate all reports."""
    generate_all(args.input, args.output or "output")
    print("Done.")


def main():
    parser = argparse.ArgumentParser(
        prog="report",
        description="Generate security reports and disclosure documents from OpenAnt pipeline output."
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # summary command
    summary_parser = subparsers.add_parser("summary", help="Generate summary report")
    summary_parser.add_argument("input", help="Pipeline output JSON file")
    summary_parser.add_argument("-o", "--output", help="Output file (default: SUMMARY_REPORT.md)")
    summary_parser.set_defaults(func=cmd_summary)

    # disclosures command
    disclosures_parser = subparsers.add_parser("disclosures", help="Generate disclosure documents")
    disclosures_parser.add_argument("input", help="Pipeline output JSON file")
    disclosures_parser.add_argument("-o", "--output", help="Output directory (default: disclosures/)")
    disclosures_parser.set_defaults(func=cmd_disclosures)

    # all command
    all_parser = subparsers.add_parser("all", help="Generate all reports (summary + disclosures)")
    all_parser.add_argument("input", help="Pipeline output JSON file")
    all_parser.add_argument("-o", "--output", help="Output directory (default: output/)")
    all_parser.set_defaults(func=cmd_all)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
