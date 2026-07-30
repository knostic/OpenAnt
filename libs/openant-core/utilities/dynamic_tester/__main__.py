"""CLI entry point: python -m utilities.dynamic_tester pipeline_output.json [--output-dir DIR]"""

import argparse
import sys

from utilities.dynamic_tester import run_dynamic_tests


def main():
    parser = argparse.ArgumentParser(
        description="Dynamic vulnerability testing using Docker containers",
    )
    parser.add_argument(
        "pipeline_output",
        help="Path to pipeline_output.json from the static analysis pipeline",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default=None,
        help="Output directory for results (default: same as input file)",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Maximum retries per finding on ERROR status (default: 3)",
    )

    args = parser.parse_args()

    results = run_dynamic_tests(
        args.pipeline_output, args.output_dir,
        max_retries=args.max_retries,
    )

    counts = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    print("\n" + "=" * 50)
    print("DYNAMIC TEST SUMMARY")
    print("=" * 50)
    for status in ["CONFIRMED", "NOT_REPRODUCED", "BLOCKED", "INCONCLUSIVE", "ERROR", "SKIPPED"]:
        if status in counts:
            print(f"  {status}: {counts[status]}")
    print(f"  TOTAL: {len(results)}")
    print("=" * 50)


if __name__ == "__main__":
    main()
