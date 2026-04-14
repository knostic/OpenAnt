"""
Report Generator - generates security reports and disclosure documents from pipeline output.

Returns (text, usage_dict) tuples from LLM functions so callers can track costs.
"""

import json
import os
import sys
import anthropic
from pathlib import Path
from dotenv import load_dotenv

from .schema import validate_pipeline_output, ValidationError

load_dotenv()

PROMPTS_DIR = Path(__file__).parent / "prompts"
MODEL = "claude-opus-4-6"

# Pricing per million tokens
_PRICING = {
    "claude-opus-4-6": {"input": 15.00, "output": 75.00},
    "claude-opus-4-20250514": {"input": 15.00, "output": 75.00},
    "claude-sonnet-4-20250514": {"input": 3.00, "output": 15.00},
}
_DEFAULT_PRICING = {"input": 3.00, "output": 15.00}


def _extract_usage(response, model: str = MODEL) -> dict:
    """Extract usage info from an Anthropic API response."""
    usage = response.usage
    pricing = _PRICING.get(model, _DEFAULT_PRICING)
    input_cost = (usage.input_tokens / 1_000_000) * pricing["input"]
    output_cost = (usage.output_tokens / 1_000_000) * pricing["output"]
    return {
        "input_tokens": usage.input_tokens,
        "output_tokens": usage.output_tokens,
        "total_tokens": usage.input_tokens + usage.output_tokens,
        "cost_usd": round(input_cost + output_cost, 6),
    }


def _merge_usage(usages: list[dict]) -> dict:
    """Merge multiple usage dicts into one."""
    merged = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "cost_usd": 0.0}
    for u in usages:
        merged["input_tokens"] += u["input_tokens"]
        merged["output_tokens"] += u["output_tokens"]
        merged["total_tokens"] += u["total_tokens"]
        merged["cost_usd"] = round(merged["cost_usd"] + u["cost_usd"], 6)
    return merged


def _check_api_key():
    """Check that ANTHROPIC_API_KEY is set."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY environment variable not set.", file=sys.stderr)
        print("Set it with: export ANTHROPIC_API_KEY=sk-ant-...", file=sys.stderr)
        sys.exit(1)


def load_prompt(name: str) -> str:
    """Load a prompt template from the prompts directory."""
    return (PROMPTS_DIR / f"{name}.txt").read_text()


def merge_dynamic_results(pipeline_data: dict, pipeline_path: str) -> dict:
    """Merge dynamic test results into pipeline findings if available.

    Looks for dynamic_test_results.json next to the pipeline_output.json file
    and adds a 'dynamic_testing' key to each matching finding.
    """
    dynamic_path = Path(pipeline_path).parent / "dynamic_test_results.json"
    if not dynamic_path.exists():
        return pipeline_data

    dynamic_data = json.loads(dynamic_path.read_text())
    results_by_id = {}
    for result in dynamic_data.get("results", []):
        fid = result.get("finding_id")
        if fid:
            results_by_id[fid] = result

    if not results_by_id:
        return pipeline_data

    from datetime import datetime
    date_str = datetime.fromtimestamp(dynamic_path.stat().st_mtime).strftime("%B %Y")

    for finding in pipeline_data.get("findings", []):
        fid = finding.get("id")
        if fid and fid in results_by_id:
            r = results_by_id[fid]
            finding["dynamic_testing"] = {
                "status": r.get("status"),
                "details": r.get("details"),
                "evidence": r.get("evidence", []),
                "tested": f"Docker container, {date_str}",
            }

    print(f"  Merged {len(results_by_id)} dynamic test results from {dynamic_path.name}", file=sys.stderr)
    return pipeline_data


def _compact_for_summary(pipeline_data: dict) -> dict:
    """Create a compact copy of pipeline_data for the summary prompt.

    Strips large fields (vulnerable_code, steps_to_reproduce, description)
    from findings to avoid exceeding the context window.
    """
    compact = {k: v for k, v in pipeline_data.items() if k != "findings"}
    compact["findings"] = []
    for f in pipeline_data.get("findings", []):
        compact["findings"].append({
            "id": f.get("id"),
            "name": f.get("name"),
            "short_name": f.get("short_name"),
            "location": f.get("location"),
            "cwe_id": f.get("cwe_id"),
            "cwe_name": f.get("cwe_name"),
            "stage1_verdict": f.get("stage1_verdict"),
            "stage2_verdict": f.get("stage2_verdict"),
            "dynamic_testing": f.get("dynamic_testing"),
            "impact": f.get("impact"),
        })
    return compact


def generate_summary_report(pipeline_data: dict) -> tuple[str, dict]:
    """Generate a summary report from pipeline data.

    Returns:
        (report_text, usage_dict) where usage_dict has input_tokens,
        output_tokens, total_tokens, cost_usd.
    """
    _check_api_key()
    client = anthropic.Anthropic()

    summary_data = _compact_for_summary(pipeline_data)
    system_prompt = load_prompt("system")
    user_prompt = load_prompt("summary").replace("{pipeline_data}", json.dumps(summary_data, indent=2))

    response = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}]
    )

    return response.content[0].text, _extract_usage(response)


def generate_disclosure(vulnerability_data: dict, product_name: str) -> tuple[str, dict]:
    """Generate a disclosure document for a single vulnerability.

    Returns:
        (disclosure_text, usage_dict)
    """
    _check_api_key()
    client = anthropic.Anthropic()

    system_prompt = load_prompt("system")

    vuln_with_product = {**vulnerability_data, "product_name": product_name}
    user_prompt = load_prompt("disclosure").replace(
        "{vulnerability_data}",
        json.dumps(vuln_with_product, indent=2)
    )

    response = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}]
    )

    return response.content[0].text, _extract_usage(response)


def generate_all(pipeline_path: str, output_dir: str) -> None:
    """Generate all reports from a pipeline output file."""
    pipeline_data = json.loads(Path(pipeline_path).read_text())

    try:
        validate_pipeline_output(pipeline_data)
    except ValidationError as e:
        print(f"Validation error: {e}", file=sys.stderr)
        sys.exit(1)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Generate summary report
    print("Generating summary report...")
    summary, _usage = generate_summary_report(pipeline_data)
    (output_path / "SUMMARY_REPORT.md").write_text(summary)
    print(f"  -> {output_path / 'SUMMARY_REPORT.md'}")

    # Generate disclosure for each confirmed vulnerability
    disclosures_dir = output_path / "disclosures"
    disclosures_dir.mkdir(exist_ok=True)

    product_name = pipeline_data["repository"]["name"]

    for i, finding in enumerate(pipeline_data["findings"], 1):
        if finding.get("stage2_verdict") not in ("confirmed", "agreed", "vulnerable"):
            continue

        print(f"Generating disclosure for {finding['short_name']}...")
        disclosure, _usage = generate_disclosure(finding, product_name)

        safe_name = finding["short_name"].replace(" ", "_").upper()
        filename = f"DISCLOSURE_{i:02d}_{safe_name}.md"
        (disclosures_dir / filename).write_text(disclosure)
        print(f"  -> {disclosures_dir / filename}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python generator.py <pipeline_output.json> <output_dir>")
        sys.exit(1)

    generate_all(sys.argv[1], sys.argv[2])
    print("Done.")
