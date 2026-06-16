"""
Report Generator - generates security reports and disclosure documents from pipeline output.

Returns (text, usage_dict) tuples from LLM functions so callers can track costs.
"""

import json
import os
import re
import sys
from pathlib import Path
from dotenv import load_dotenv

from .schema import validate_pipeline_output, ValidationError
from utilities.file_io import open_utf8, read_json
from utilities.llm import (
    PhaseBinding,
    PhaseRegistry,
    build_phase_registry,
    load_config_file,
    lookup_pricing,
    resolve_llm_config,
)

load_dotenv()

PROMPTS_DIR = Path(__file__).parent / "prompts"


def _extract_usage(
    input_tokens: int,
    output_tokens: int,
    model: str,
    pricing: dict[str, float] | None = None,
) -> dict:
    """Build the usage dict from token counts.

    ``pricing`` is the adapter's rates for ``model`` (issue #65 §9 —
    pricing lives on the adapter, not on a shared global). When
    omitted, we fall back to the legacy ``MODEL_PRICING`` global so
    older call sites still produce a number; new code should always
    pass ``binding.adapter.pricing.get(binding.model)``.
    """
    if pricing is None:
        from utilities.llm_client import MODEL_PRICING

        pricing = MODEL_PRICING.get(model)
    if pricing is None:
        # Same one-time warning record_call emits, so an unknown model's
        # $0 cost isn't silently inconsistent between the two paths.
        from utilities.llm_client import _warn_unknown_pricing

        _warn_unknown_pricing(model)
        total_cost = 0.0
    else:
        input_cost = (input_tokens / 1_000_000) * pricing["input"]
        output_cost = (output_tokens / 1_000_000) * pricing["output"]
        total_cost = input_cost + output_cost
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "cost_usd": round(total_cost, 6),
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


def load_prompt(name: str) -> str:
    """Load a prompt template from the prompts directory."""
    with open_utf8(PROMPTS_DIR / f"{name}.txt") as f:
        return f.read()


def merge_dynamic_results(pipeline_data: dict, pipeline_path: str) -> dict:
    """Merge dynamic test results into pipeline findings if available.

    Looks for dynamic_test_results.json next to the pipeline_output.json file
    and adds a 'dynamic_testing' key to each matching finding.
    """
    dynamic_path = Path(pipeline_path).parent / "dynamic_test_results.json"
    if not dynamic_path.exists():
        return pipeline_data

    dynamic_data = read_json(dynamic_path)
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


def generate_summary_report(
    pipeline_data: dict,
    binding: PhaseBinding,
) -> tuple[str, dict]:
    """Generate a summary report from pipeline data.

    Args:
        pipeline_data: Decoded pipeline_output.json content.
        binding: Phase binding for the report phase.

    Returns:
        (report_text, usage_dict) where usage_dict has input_tokens,
        output_tokens, total_tokens, cost_usd.
    """
    from utilities.llm import Message, TextBlock

    summary_data = _compact_for_summary(pipeline_data)
    system_prompt = load_prompt("system")
    user_prompt = load_prompt("summary").replace(
        "{pipeline_data}", json.dumps(summary_data, indent=2)
    )

    result = binding.adapter.complete(
        model=binding.model,
        max_tokens=4096,
        system=system_prompt,
        messages=[Message(role="user", content=[TextBlock(user_prompt)])],
    )

    text = "\n".join(b.text for b in result.content if isinstance(b, TextBlock))
    return text, _extract_usage(
        result.input_tokens,
        result.output_tokens,
        binding.model,
        pricing=lookup_pricing(binding),
    )


def _splice_code_section(llm_output: str, code_section: str) -> str:
    """Insert the verbatim code block into the LLM-generated disclosure.

    The LLM generates everything except the Vulnerable Code section. This
    function inserts the server-built code block at the right position.

    As a safety net, if the LLM ignored the instruction and still generated
    its own ``## Vulnerable Code`` block, that block is stripped first.
    """
    if not code_section:
        return llm_output

    # Safety net: strip any LLM-generated Vulnerable Code section.
    # Matches from "## Vulnerable Code" up to the next ## heading or end of string.
    output = re.sub(
        r'## Vulnerable Code.*?(?=\n## |\Z)',
        '',
        llm_output,
        flags=re.DOTALL,
    )

    # Insert the real code section before "## Steps to Reproduce".
    insertion_point = '## Steps to Reproduce'
    if insertion_point in output:
        output = output.replace(
            insertion_point,
            f"{code_section}\n\n{insertion_point}",
            1,
        )
    else:
        # Fallback: insert before "## Impact" if Steps is missing.
        fallback = '## Impact'
        if fallback in output:
            output = output.replace(fallback, f"{code_section}\n\n{fallback}", 1)
        else:
            output += f"\n\n{code_section}"

    return output


def generate_disclosure(
    vulnerability_data: dict,
    product_name: str,
    binding: PhaseBinding,
) -> tuple[str, dict]:
    """Generate a disclosure document for a single vulnerability.

    Args:
        vulnerability_data: Finding to disclose.
        product_name: Repository / product name.
        binding: Phase binding for the report phase.

    Returns:
        (disclosure_text, usage_dict)
    """
    from utilities.llm import Message, TextBlock

    system_prompt = load_prompt("system")

    # The vulnerable-code markdown block is spliced into the LLM output
    # AFTER generation — the LLM never sees or produces it. This prevents
    # the LLM from hallucinating the snippet.
    code_section = vulnerability_data.get("vulnerable_code_section") or ""
    payload = {
        k: v for k, v in vulnerability_data.items()
        if k not in ("vulnerable_code_section", "vulnerable_code")
    }
    payload["product_name"] = product_name

    user_prompt = (
        load_prompt("disclosure")
        .replace("{vulnerability_data}", json.dumps(payload, indent=2), 1)
    )

    result = binding.adapter.complete(
        model=binding.model,
        max_tokens=4096,
        system=system_prompt,
        messages=[Message(role="user", content=[TextBlock(user_prompt)])],
    )

    llm_output = "\n".join(
        b.text for b in result.content if isinstance(b, TextBlock)
    )
    final_output = _splice_code_section(llm_output, code_section)

    return final_output, _extract_usage(
        result.input_tokens,
        result.output_tokens,
        binding.model,
        pricing=lookup_pricing(binding),
    )


def generate_all(
    pipeline_path: str,
    output_dir: str,
    registry: PhaseRegistry | None = None,
    llm_config_name: str | None = None,
) -> None:
    """Generate all reports from a pipeline output file."""
    pipeline_data = read_json(pipeline_path)

    try:
        validate_pipeline_output(pipeline_data)
    except ValidationError as e:
        print(f"Validation error: {e}", file=sys.stderr)
        sys.exit(1)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Resolve the report-phase binding once and reuse for every call.
    if registry is None:
        cf = load_config_file()
        registry = build_phase_registry(cf, resolve_llm_config(cf, llm_config_name))
    report_binding = registry.get("report")

    # Generate summary report
    print("Generating summary report...")
    summary, _usage = generate_summary_report(pipeline_data, report_binding)
    with open_utf8(output_path / "SUMMARY_REPORT.md", "w") as f:
        f.write(summary)
    print(f"  -> {output_path / 'SUMMARY_REPORT.md'}")

    # Generate disclosure for each confirmed vulnerability
    disclosures_dir = output_path / "disclosures"
    disclosures_dir.mkdir(exist_ok=True)

    product_name = pipeline_data["repository"]["name"]

    for i, finding in enumerate(pipeline_data["findings"], 1):
        # "unverified" (Stage-2 could not complete) is disclosure-eligible:
        # a degenerate verify must not silently drop a Stage-1 potential vuln
        # from triage. Kept consistent with core/reporter.generate_disclosure_docs.
        if finding.get("stage2_verdict") not in ("confirmed", "agreed", "vulnerable", "unverified"):
            continue

        print(f"Generating disclosure for {finding['short_name']}...")
        disclosure, _usage = generate_disclosure(finding, product_name, report_binding)

        safe_name = finding["short_name"].replace(" ", "_").upper()
        filename = f"DISCLOSURE_{i:02d}_{safe_name}.md"
        with open_utf8(disclosures_dir / filename, "w") as f:
            f.write(disclosure)
        print(f"  -> {disclosures_dir / filename}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python generator.py <pipeline_output.json> <output_dir>")
        sys.exit(1)

    generate_all(sys.argv[1], sys.argv[2])
    print("Done.")
