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

from core.verdict_taxonomy import DISCLOSURE_ELIGIBLE
from .schema import validate_pipeline_output, ValidationError
from utilities.file_io import normalize_results, open_utf8, read_json
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
    usage_details: dict | None = None,
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
    usage = {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "cost_usd": round(total_cost, 6),
    }
    if pricing is None:
        # #216: this fallback costs OUTSIDE the tracker — the usage dict
        # must not claim a complete cost it does not have.
        usage["cost_incomplete"] = True
    if usage_details is not None:
        # #211 pass-through capture: verbatim, informational only.
        usage["usage_details"] = usage_details
    return usage


def _merge_usage(usages: list[dict]) -> dict:
    """Merge multiple usage dicts into one.

    #211 pass-through: per-completion ``usage_details`` (when any completion
    captured provider detail fields) are carried VERBATIM as a list — same
    shape the agentic loops record — never summed, never in cost.
    """
    merged = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "cost_usd": 0.0}
    for u in usages:
        if u.get("cost_incomplete"):
            merged["cost_incomplete"] = True
        merged["input_tokens"] += u["input_tokens"]
        merged["output_tokens"] += u["output_tokens"]
        merged["total_tokens"] += u["total_tokens"]
        merged["cost_usd"] = round(merged["cost_usd"] + u["cost_usd"], 6)
    details = [u.get("usage_details") for u in usages if u.get("usage_details") is not None]
    if details:
        merged["usage_details"] = details
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
    # fa17 TRUST BOUNDARY: dynamic_test_results.json `results` is model-supplied;
    # normalize to dicts-only once so the `result.get("finding_id")` loop below
    # never calls `.get()` on a bare string/number.
    normalize_results(dynamic_data)
    results_by_id = {}
    duplicate_ids = 0
    for result in dynamic_data.get("results", []):
        fid = result.get("finding_id")
        if fid:
            if fid in results_by_id:
                # verify-wave (sonnet, state-machine axis — F2): a duplicate
                # finding_id silently last-wins with zero visibility — the
                # exact anti-pattern this merge's own "what happened is
                # SURFACED, never silent" rule exists to stop. Counted and
                # warned below; the last-wins order is unchanged (documented
                # behavior, not silently chosen).
                duplicate_ids += 1
            results_by_id[fid] = result

    if not results_by_id:
        return pipeline_data

    from datetime import datetime
    date_str = datetime.fromtimestamp(dynamic_path.stat().st_mtime).strftime("%B %Y")

    # #314: the merge verifies the IDENTITY, not just the positional ID.
    # VULN-NNN is assigned by list position — drop or add one finding
    # anywhere but the end and every later ID shifts, so a stale
    # results file left in the scan directory merges one finding's
    # result into a DIFFERENT finding, stamped with the stale file's
    # mtime and nothing marking it. Three rules, each surfaced (never
    # silent):
    #   - positional match + identity_key AGREES -> merge (auditable)
    #   - positional match + identity_key DISAGREES -> REFUSE (the stale
    #     case: a different finding) — the mis-join is refused
    #   - results without identity_key (a legacy/pre-fix file) -> ABSTAIN
    #     (never silently fall back to the positional ID: that is the
    #     defect)
    merged_count = 0
    attempted_count = 0
    skipped_count = 0
    refused_count = 0
    abstained_count = 0
    for finding in pipeline_data.get("findings", []):
        fid = finding.get("id")
        if not fid or fid not in results_by_id:
            continue
        r = results_by_id[fid]
        r_key = r.get("identity_key")
        f_key = finding.get("identity_key")
        if not r_key or not f_key:
            abstained_count += 1
            continue
        if r_key != f_key:
            refused_count += 1
            continue
        # verify-wave (opus, consumers axis — F1, reproduced): a finding
        # can enter the merge carrying a PRE-EXISTING dynamic_testing block
        # (a stale one from an earlier run, or a forged one — pipeline_output
        # is model-supplied per fa18). The merge previously only ADDED, so a
        # forged CONFIRMED block coexisted with a fresh ERROR result and
        # every consumer's dynamic_testing-first preference rendered
        # "Verified via dynamic testing" — the exact false verification
        # this fix exists to remove, re-entering through the artifact
        # channel. The merge is the single authority for a finding's
        # dynamic-verification state: clear both block keys on every
        # matched finding BEFORE attaching, so the "cannot render a failed
        # test as a verification by omission" contract holds
        # unconditionally for every finding the merge touched.
        finding.pop("dynamic_testing", None)
        finding.pop("dynamic_testing_attempted", None)
        # fa17 hardening (wave r2 + the deep-refute): the results file is
        # model-supplied — ANY status outside the harness's own VALID set
        # (exact-case) normalises to UNKNOWN: a non-string, a lowercase
        # "confirmed" (which would self-contradict the banner), whitespace,
        # or a newline-bearing string must not leak into the
        # externally-facing banner. The allowlist is the harness's own.
        from utilities.dynamic_tester.models import VALID_STATUSES
        _raw_status = r.get("status")
        if (not isinstance(_raw_status, str)
                or _raw_status not in VALID_STATUSES):
            status = "UNKNOWN"
        else:
            status = _raw_status
        # #319 (wave r1): SKIPPED is "never executed" (models.py: "distinct
        # from ERROR (a test ran and failed)") — the harness had no Docker
        # template for the finding's language. Attaching an ATTEMPTED block
        # (an attempted date, a "test SKIPPED" failure stamp) would be the
        # mirror of the defect this issue fixes: asserting a container
        # action that never happened, inverted. SKIPPED attaches nothing;
        # it is surfaced in the merge's stderr line like the abstain count.
        if status == "SKIPPED":
            skipped_count += 1
            continue
        # #319: the verification block attaches ONLY for a CONFIRMED test —
        # an ERRORED or NOT_REPRODUCED test rendered as "Verified via
        # dynamic testing" in the disclosure (both consumers keyed on the
        # block's EXISTENCE), and the unconditional `tested` Docker string
        # asserted a container run that never happened. Every other status
        # attaches a separate ATTEMPTED block: the transparency (status,
        # details, evidence, the date-stamped ATTEMPT) without the
        # verification claim — a template cannot render a failed test as a
        # verification by omission.
        if status == "CONFIRMED":
            finding["dynamic_testing"] = {
                "status": status,
                "details": r.get("details"),
                "evidence": r.get("evidence", []),
                "tested": f"Docker container, {date_str}",
                # the join is auditable after the fact
                "identity_key": r_key,
            }
            merged_count += 1
        else:
            finding["dynamic_testing_attempted"] = {
                "status": status,
                "details": r.get("details"),
                "evidence": r.get("evidence", []),
                # NOT `tested`: the container claim is reserved for a test
                # that ran and confirmed. `attempted` carries the date.
                "attempted": date_str,
                "identity_key": r_key,
            }
            attempted_count += 1

    # #314 suggestion 3: what happened is SURFACED, never silent
    print(f"  Merged {merged_count} dynamic test results from {dynamic_path.name}", file=sys.stderr)
    if attempted_count:
        print(f"  [Info] {attempted_count} dynamic test result(s) NOT confirmed "
              f"(attached as dynamic_testing_attempted — never a verification)", file=sys.stderr)
    if skipped_count:
        print(f"  [Info] {skipped_count} dynamic test result(s) SKIPPED — never "
              f"executed (no harness for the language); nothing attached", file=sys.stderr)
    if refused_count:
        print(f"  [Warning] Refused {refused_count} dynamic test result(s) whose "
              f"identity_key disagrees with the finding — a stale results file "
              f"from a previous run; re-run the dynamic tests to regenerate",
              file=sys.stderr)
    if duplicate_ids:
        print(f"  [Warning] {duplicate_ids} duplicate finding_id(s) in {dynamic_path.name} "
              f"— the LAST entry for each id was used", file=sys.stderr)
    if abstained_count:
        print(f"  [Warning] Skipped {abstained_count} dynamic test result(s) with "
              f"no identity_key (a legacy results file); re-run the dynamic "
              f"tests to regenerate", file=sys.stderr)
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
            # #215: the stamped severity + its provenance reach the summary
            # LLM — without these the "Severity" column in the template is
            # model-guessed, not read from the scan.
            "severity": f.get("severity"),
            "severity_source": f.get("severity_source"),
            "dynamic_testing": f.get("dynamic_testing"),
            # #319 (the e2e-caught gap): the ATTEMPTED block must reach the
            # summary LLM too — without it a failed test rendered "static"
            # (safe, but the failure was invisible to the reader).
            "dynamic_testing_attempted": f.get("dynamic_testing_attempted"),
            "impact": f.get("impact"),
        })
    return compact


def _context_provenance_header(pipeline_data: dict) -> str:
    """R5: a deterministic banner when context came from a repo-controlled file.

    Rendered from ``pipeline_output.json`` fields WITHOUT the LLM, on purpose: a
    threat model is attacker-influenceable (it ships in the scanned repo), so the
    notice that the security model came from that file must not be something a
    hostile file can suppress by steering the report prompt. Returns "" for the
    built-in/generated path so the banner never fires on a trusted context.
    """
    source = pipeline_data.get("context_source")
    if source == "threat_model":
        lines = [
            "> **⚠ Security model supplied by a repo-controlled file.**",
            "> This scan's attacker model came from `OPENANT.THREATMODEL.md` inside "
            "the scanned repository, which is attacker-influenceable. Treat the "
            "findings' scope as only as trustworthy as that file.",
        ]
        sha = pipeline_data.get("threat_model_sha256")
        if sha:
            lines.append(f"> Threat-model sha256: `{sha}`")
        for warning in pipeline_data.get("threat_model_warnings") or []:
            lines.append(f"> - {warning}")
        return "\n".join(lines) + "\n\n"
    if source == "repo_manual":
        # #322: the manual-override branch (OPENANT.json / OPENANT.md
        # committed by the scanned repo) was recorded as "generated", so
        # this banner never fired for the path a hostile file actually
        # controls. Disclose it the same deterministic way.
        fname = pipeline_data.get("manual_override_filename") or ""
        named = ("`" + fname + "`") if fname else "a repo-committed override file"
        lines = [
            "> **⚠ Security override supplied by a repo-committed file.**",
            "> This scan honored " + named + " committed inside "
            "the scanned repository, which is attacker-influenceable — its "
            "`not_a_vulnerability` entries suppress findings. Treat the "
            "findings' scope as only as trustworthy as that file.",
        ]
        n = pipeline_data.get("manual_exclusions")
        if isinstance(n, int):
            lines.append(
                f"> Active repo-supplied exclusions: {n} "
                "(the findings they suppress are not reported)")
        for warning in pipeline_data.get("manual_override_warnings") or []:
            lines.append(f"> - {warning}")
        return "\n".join(lines) + "\n\n"
    return ""


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
        output_tokens, total_tokens, cost_usd — plus a verbatim
        ``usage_details`` key when the provider supplied usage detail
        fields (#211 pass-through; never summed, never in cost).
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
    # #209: refuse to bless an empty summary. An empty/whitespace completion
    # (e.g. the Claude-5 thinking/empty-completion path) otherwise produces a
    # summary-free SUMMARY_REPORT.md — an empty deliverable is wrong regardless
    # of what status it is recorded under. (Historically this also left the
    # report step's status="success" with summary_path in its outputs; that
    # half is now fixed by core/step_report.py's #209 errors->status
    # derivation, so the report step correctly reports "error" when this guard
    # fires.) Guard the raw LLM output HERE, before the deterministic
    # provenance banner is prepended: on a threat-model scan the banner is
    # non-empty, so a guard on the banner+text combination would miss exactly
    # this case. Raising here also covers the standalone `python -m report
    # summary` path, which calls this producer directly.
    if not text.strip():
        raise RuntimeError(
            "summary report generation returned empty output; refusing to write "
            "a summary-free SUMMARY_REPORT.md"
        )
    # Prepend the provenance banner deterministically (see helper docstring).
    text = _context_provenance_header(pipeline_data) + text
    return text, _extract_usage(
        result.input_tokens,
        result.output_tokens,
        binding.model,
        pricing=lookup_pricing(binding),
        usage_details=result.usage_details,
    )


# #210: the only verdicts Stage-2 attacker simulation positively adjudicated.
# Every OTHER DISCLOSURE_ELIGIBLE verdict — unverified (Stage-2 attempted but
# incomplete), and vulnerable / bypassable / error (per the taxonomy these
# arise ONLY on the no-Stage-2 path, core/verdict_taxonomy.py + reporter.py's
# verdict reducer) — is NOT Stage-2-confirmed. `bypassable` especially must not
# read as confirmed: it is a bare Stage-1 finding verdict, so stamping it
# "CONFIRMED by Stage-2" would be the exact false-confirmation this banner
# exists to remove. Such findings are still disclosed (over-seed safety),
# labeled UNVERIFIED.
_STAGE2_CONFIRMED = frozenset({"confirmed", "agreed"})


def _disclosure_verdict_header(vulnerability_data: dict) -> str:
    """Deterministic, server-stamped verification banner for a disclosure.

    Lets a reader distinguish an attacker-simulation-confirmed finding from a
    not-yet-confirmed one without trusting the LLM to render the "Verified via
    ..." line (dropped in most documents), and stamps the real file/function
    location the "{affected_versions}" prompt field never carries.
    """
    verdict = str(vulnerability_data.get("stage2_verdict") or "").lower()
    stage1 = str(vulnerability_data.get("stage1_verdict") or "").lower()
    # #319: the dynamic dimension stamps FIRST — a CONFIRMED Docker test is
    # the strongest verification; an attempted-but-failed one must say NOT
    # confirmed (never "Verified via dynamic testing" for an ERROR/
    # NOT_REPRODUCED test).
    dt = vulnerability_data.get("dynamic_testing")
    dta = vulnerability_data.get("dynamic_testing_attempted")
    # #319 (wave r1): the dimensions COMPOSE — the dynamic line ADDS as a
    # second line, never REPLACES the Stage-2 stamp (the wave's regression:
    # a Stage-2 CONFIRMED finding whose harness ERRORED read "NOT confirmed
    # by dynamic testing" with the Stage-2 confirmation DROPPED — the
    # reader could not distinguish it from a Stage-1-only finding; #283's
    # ADJUDICATED wording likewise became unreachable).
    dt_line = ""
    if isinstance(dt, dict) and dt.get("status") == "CONFIRMED":
        dt_line = "CONFIRMED by dynamic testing (Docker container)"
    elif isinstance(dta, dict) and dta.get("status"):
        dt_line = f"NOT confirmed by dynamic testing (test {dta.get('status')})"
    if verdict in _STAGE2_CONFIRMED:
        status = f"CONFIRMED by Stage-2 attacker simulation ({verdict})"
    elif (verdict in ("vulnerable", "bypassable")
          and stage1 and stage1 != verdict):
        # #283: stage1 != stage2 on a still-real verdict is the Stage-2
        # RECLASSIFICATION signal (e.g. vulnerable -> bypassable, adjudicated
        # by attacker simulation). "UNVERIFIED — not confirmed by Stage-2"
        # would be FALSE here: Stage 2 DID adjudicate. When stage1 == stage2
        # (or stage1 is absent) the finding may not have been through Stage 2
        # at all — the conservative UNVERIFIED wording stays.
        status = (
            f"ADJUDICATED by Stage-2 attacker simulation — reclassified "
            f"{stage1} -> {verdict}, still a real finding"
        )
    else:  # unverified / error / same-verdict vulnerable/bypassable
        status = (
            "UNVERIFIED — not confirmed by Stage-2 attacker simulation "
            f"({verdict or 'unknown'})"
        )
    lines = [f"> **Verification:** {status}"]
    if dt_line:
        lines.append(f"> **Dynamic testing:** {dt_line}")
    loc = vulnerability_data.get("location")
    if isinstance(loc, dict) and (loc.get("file") or loc.get("function")):
        where = ":".join(str(x) for x in (loc.get("file"), loc.get("function")) if x)
        lines.append(f"> **Location:** {where}")
    return "\n".join(lines) + "\n\n"


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
    # #210: stamp the verification status + location deterministically from the
    # server-truth stage2_verdict, the same way the vulnerable code is spliced
    # in above. The prompt otherwise asks the LLM to render "Verified via ..."
    # (dropped in most documents) and an "{affected_versions}" field that is
    # never populated — so an unadjudicated Stage-1 candidate reads identically
    # to an attacker-simulation-confirmed finding.
    final_output = _disclosure_verdict_header(vulnerability_data) + final_output

    return final_output, _extract_usage(
        result.input_tokens,
        result.output_tokens,
        binding.model,
        pricing=lookup_pricing(binding),
        usage_details=result.usage_details,
    )


def generate_all(
    pipeline_path: str,
    output_dir: str,
    registry: PhaseRegistry | None = None,
    llm_config_name: str | None = None,
) -> None:
    """Generate all reports from a pipeline output file."""
    pipeline_data = read_json(pipeline_path)
    # fa18 TRUST BOUNDARY: normalize model `findings` to dicts-only once at load
    # so the summary compaction and the disclosure enumerate below iterate
    # dicts-only. Presence-guarded so an absent `findings` still fails
    # validate_pipeline_output's "missing required field" check.
    if "findings" in pipeline_data:
        normalize_results(pipeline_data, "findings")

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
        # Disclosure eligibility is defined once in
        # core.verdict_taxonomy.DISCLOSURE_ELIGIBLE, shared with
        # core/reporter.generate_disclosure_docs and report/__main__, so a
        # degenerate verify never silently drops a Stage-1 potential vuln.
        if finding.get("stage2_verdict") not in DISCLOSURE_ELIGIBLE:
            continue

        print(f"Generating disclosure for {finding['short_name']}...")
        disclosure, _usage = generate_disclosure(finding, product_name, report_binding)

        # short_name passes validation on presence only, so it may be null/empty,
        # a non-str (JSON), or contain a "/" — fall back to id, coerce to str, and
        # basename it so a null/typed/traversal short_name can't crash disclosure
        # generation (AttributeError / FileNotFoundError writing into a missing dir).
        safe_name = (os.path.basename(str(finding.get("short_name") or finding.get("id") or "finding"))
                     or "finding").replace(" ", "_").upper()
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
