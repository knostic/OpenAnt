"""
CLI entry point for report module.

Usage:
    python -m report --help
    python -m report summary pipeline_output.json -o report.md
    python -m report disclosures pipeline_output.json -o disclosures/
    python -m report all pipeline_output.json -o output/
"""

import argparse
import sys
from pathlib import Path

from .generator import generate_summary_report, generate_disclosure, generate_all
from .schema import validate_pipeline_output, ValidationError
from utilities.file_io import open_utf8, read_json
from utilities.llm import (
    PhaseBinding,
    build_phase_registry,
    load_config_file,
    probe_registry_or_raise,
    resolve_llm_config,
)


def _build_report_binding(llm_config_name: str | None = None) -> PhaseBinding:
    """Resolve the ``report``-phase binding for a standalone CLI invocation.

    ``generate_summary_report`` / ``generate_disclosure`` now require a
    :class:`PhaseBinding` (issue #65). Mirror the registry-build pattern
    used by ``report.generator.generate_all`` and ``core.scanner`` so the
    standalone ``python -m report`` commands resolve the same per-phase
    model — and surface a clean LLMError on a bad key / typo'd model via
    the 1-token probe, rather than crashing mid-generation.
    """
    cf = load_config_file()
    registry = build_phase_registry(cf, resolve_llm_config(cf, llm_config_name))
    probe_registry_or_raise(registry)
    return registry.get("report")


def cmd_summary(args):
    """Generate summary report."""
    pipeline_data = read_json(args.input)

    try:
        validate_pipeline_output(pipeline_data)
    except ValidationError as e:
        print(f"Validation error: {e}", file=sys.stderr)
        sys.exit(1)

    report_binding = _build_report_binding()

    print("Generating summary report...")
    report, usage = generate_summary_report(pipeline_data, report_binding)

    output_path = Path(args.output) if args.output else Path("SUMMARY_REPORT.md")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open_utf8(output_path, "w") as f:
        f.write(report)
    print(f"  -> {output_path}")
    print(f"  Cost: ${usage['cost_usd']:.4f} ({usage['total_tokens']:,} tokens)")


def cmd_disclosures(args):
    """Generate disclosure documents."""
    pipeline_data = read_json(args.input)

    try:
        validate_pipeline_output(pipeline_data)
    except ValidationError as e:
        print(f"Validation error: {e}", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(args.output) if args.output else Path("disclosures")
    output_dir.mkdir(parents=True, exist_ok=True)

    report_binding = _build_report_binding()

    product_name = pipeline_data["repository"]["name"]
    count = 0

    for i, finding in enumerate(pipeline_data["findings"], 1):
        # "unverified" (Stage-2 could not complete) is disclosure-eligible —
        # consistent with core/reporter and report/generator.
        if finding.get("stage2_verdict") not in ("confirmed", "agreed", "vulnerable", "unverified"):
            continue

        print(f"Generating disclosure for {finding['short_name']}...")
        disclosure, _usage = generate_disclosure(finding, product_name, report_binding)

        safe_name = finding["short_name"].replace(" ", "_").upper()
        filename = f"DISCLOSURE_{i:02d}_{safe_name}.md"
        with open_utf8(output_dir / filename, "w") as f:
            f.write(disclosure)
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
