"""Markdown report generation for dynamic test results."""

from datetime import datetime, timezone

from utilities.dynamic_tester.models import DynamicTestResult


def generate_report(
    results: list[DynamicTestResult],
    repo_name: str = "unknown",
    total_cost_usd: float = 0.0,
) -> str:
    """Generate a DYNAMIC_TEST_RESULTS.md markdown report.

    Args:
        results: List of DynamicTestResult objects
        repo_name: Repository name for the header
        total_cost_usd: Total cost of test generation

    Returns:
        Markdown report string
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Count statuses
    counts = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    confirmed = counts.get("CONFIRMED", 0)
    not_reproduced = counts.get("NOT_REPRODUCED", 0)
    blocked = counts.get("BLOCKED", 0)
    inconclusive = counts.get("INCONCLUSIVE", 0)
    error = counts.get("ERROR", 0)
    skipped = counts.get("SKIPPED", 0)
    total = len(results)

    lines = [
        f"# Dynamic Test Results: {repo_name}",
        "",
        f"**Date:** {now}",
        f"**Total Findings Tested:** {total - skipped}",
        f"**Skipped (no Docker template for language):** {skipped}",
        f"**Total Cost:** ${total_cost_usd:.4f}",
        "",
        "## Summary",
        "",
        "| Status | Count |",
        "|--------|-------|",
        f"| CONFIRMED | {confirmed} |",
        f"| NOT_REPRODUCED | {not_reproduced} |",
        f"| BLOCKED | {blocked} |",
        f"| INCONCLUSIVE | {inconclusive} |",
        f"| ERROR | {error} |",
        f"| **Total** | **{total}** |",
        "",
    ]

    # Detail sections by status priority
    status_order = ["CONFIRMED", "NOT_REPRODUCED", "BLOCKED", "INCONCLUSIVE", "ERROR"]

    for status in status_order:
        status_results = [r for r in results if r.status == status]
        if not status_results:
            continue

        lines.extend([
            f"## {status} ({len(status_results)})",
            "",
        ])

        for r in status_results:
            lines.extend([
                f"### {r.finding_id}",
                "",
                f"**Status:** {r.status}",
                f"**Details:** {r.details}",
                f"**Time:** {r.elapsed_seconds:.1f}s",
                f"**Generation Cost:** ${r.generation_cost_usd:.4f}",
                "",
            ])

            if r.evidence:
                lines.append("**Evidence:**")
                lines.append("")
                for e in r.evidence:
                    lines.extend([
                        f"- **{e.type}:**",
                        "```",
                        e.content[:2000],
                        "```",
                        "",
                    ])

            if r.test_code:
                lines.extend([
                    "<details>",
                    "<summary>Generated Test Code</summary>",
                    "",
                    "```python",
                    r.test_code,
                    "```",
                    "",
                    "</details>",
                    "",
                ])

    return "\n".join(lines)
