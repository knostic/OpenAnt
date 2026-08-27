"""
Report generation wrapper.

Wraps the existing report generators:
- report/html_report.py — HTML report with Chart.js
- report/csv_export.py  — CSV export
- report/generator.py  — LLM-based summary and disclosure documents

Also provides ``build_pipeline_output()`` which assembles analysis results
into the ``pipeline_output.json`` format consumed by ``python -m report``
and ``run_dynamic_tests()``.
"""

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from core.schemas import ReportResult
from core.language_registry import fence_for_path
from core.verdict_taxonomy import DISCLOSURE_ELIGIBLE
from utilities.file_io import normalize_results, open_utf8, read_json, write_json

# Root of openant-core
_CORE_ROOT = Path(__file__).parent.parent


def _load_diff_metadata(scan_dir: str) -> dict | None:
    """Return a summary dict if this scan dir contains a diff_manifest.json.

    Combines fields from diff_manifest.json and diff_filter.report.json so the
    HTML/report consumers have one place to read PR/incremental metadata.
    """
    manifest_path = os.path.join(scan_dir, "diff_manifest.json")
    if not os.path.exists(manifest_path):
        return None
    try:
        manifest = read_json(manifest_path)
    except (json.JSONDecodeError, OSError):
        return None
    out = {
        "mode": "incremental",
        "base_ref": manifest.get("base_ref"),
        "base_sha": manifest.get("base_sha"),
        "head_sha": manifest.get("head_sha"),
        "scope": manifest.get("scope"),
        "pr_number": manifest.get("pr_number") or None,
        "changed_files": len(manifest.get("changed_files") or []),
    }
    filter_report = os.path.join(scan_dir, "diff_filter.report.json")
    if os.path.exists(filter_report):
        try:
            stats = read_json(filter_report)
            out["units_in_diff"] = stats.get("selected")
            out["units_total_parsed"] = stats.get("total")
            out["callers_added"] = stats.get("callers_added") or 0
            out["fallback_file_match"] = stats.get("fallback_file_match") or 0
        except (json.JSONDecodeError, OSError):
            pass
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Map language hints to the code-fence language tag used in Markdown.
# Fence tags come from the language registry, resolved per FILE. The old
# module-level map was keyed by the SCAN-WIDE language, which mislabelled every
# file whose extension implied a different tag than the scan's primary
# language — a `.ts` file in a "javascript" scan was fenced as ```javascript
# even before multi-language scanning existed.


def _coerce_to_str(value) -> str:
    """Convert a model-returned field to a plain string.

    Pipeline prompts (``prompts/vulnerability_analysis.py``,
    ``prompts/verification_prompts.py``) request string-typed fields
    like ``attack_vector`` and ``verification_explanation``. Different
    providers honor that schema with varying fidelity — Claude
    reliably returns strings, while GPT-4o sometimes structures the
    same field as a dict (``{"type": "...", "description": "..."}``)
    or a nested object.

    Rather than crash on the next ``.join`` or string concatenation
    when a model strays, coerce defensively at every consumption
    site. Strings pass through. ``None`` becomes ``""``. Dicts/lists
    get ``json.dumps``-serialised. Anything else falls back to
    ``str()``. The result is always safe to feed into ``.join`` or
    concatenation.
    """
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    try:
        return json.dumps(value)
    except (TypeError, ValueError):
        return str(value)


def _build_vulnerable_code_section(file_path: str, code: str, language: str | None) -> str:
    """Build a pre-rendered Markdown `## Vulnerable Code` section.

    The disclosure generator splices this verbatim into the LLM prompt so the
    model cannot rewrite the snippet. Prior behaviour (asking the LLM for a
    "minimal code snippet") produced fabricated code in DISCLOSURE_01/05.
    """
    if not code:
        return ""
    # Resolve by the finding's own file; fall back to the scan language only
    # when the path carries no recognizable extension.
    fence_lang = fence_for_path(file_path, fallback=language)
    return (
        "## Vulnerable Code\n\n"
        f"`{file_path}`:\n\n"
        f"```{fence_lang}\n{code}\n```"
    )


# ---------------------------------------------------------------------------
# Deduplication — collapse caller/callee pairs
# ---------------------------------------------------------------------------

def _dedup_caller_callee(
    confirmed: list[dict],
    all_results: list[dict],
    call_graph_path: str,
) -> list[dict]:
    """Remove callee findings that are only reachable via a single caller
    with the same CWE.

    This prevents the same vulnerability from being reported twice when
    a function like ``get_user()`` is the only caller of ``run_query()``
    and both share the same vulnerability class.

    Matches on CWE (integer) instead of attack_vector (LLM free text)
    because CWE is stable across runs while attack_vector varies.
    CWE-0 (unknown) never matches — two unknowns shouldn't collapse.
    """
    # FAM-ROBUST: `confirmed` and `all_results` are model-supplied lists. A
    # non-Anthropic model can emit a bare string/number where a finding dict
    # is expected; drop non-dict elements up front so every `.get()` below —
    # and this helper when called standalone — is safe.
    confirmed = [f for f in confirmed if isinstance(f, dict)]
    all_results = [r for r in all_results if isinstance(r, dict)]

    if not os.path.isfile(call_graph_path):
        return confirmed

    try:
        cg_data = read_json(call_graph_path)
    except (json.JSONDecodeError, OSError):
        return confirmed

    reverse_cg = cg_data.get("reverse_call_graph", {})

    # Build a lookup: route_key → cwe_id for confirmed findings.
    cwe_by_key: dict[str, int] = {}
    for f in confirmed:
        rk = f.get("route_key") or f.get("unit_id", "")
        cwe = f.get("cwe_id")
        if cwe is None:
            full = next(
                (r for r in all_results
                 if (r.get("route_key") or r.get("unit_id")) == rk),
                None,
            )
            cwe = full.get("cwe_id", 0) if full else 0
        cwe_by_key[rk] = cwe

    # Identify callees to remove.
    remove_keys: set[str] = set()
    for callee_key, callers in reverse_cg.items():
        if len(callers) != 1:
            continue  # multiple callers — not safe to collapse
        caller_key = callers[0]
        if caller_key not in cwe_by_key or callee_key not in cwe_by_key:
            continue  # one of them wasn't confirmed — skip
        caller_cwe = cwe_by_key[caller_key]
        callee_cwe = cwe_by_key[callee_key]
        if caller_cwe and caller_cwe != 0 and caller_cwe == callee_cwe:
            remove_keys.add(callee_key)

    if not remove_keys:
        return confirmed

    deduped = [
        f for f in confirmed
        if (f.get("route_key") or f.get("unit_id", "")) not in remove_keys
    ]
    removed = len(confirmed) - len(deduped)
    print(f"[Report] Deduplicated {removed} caller/callee finding(s)", file=sys.stderr)
    return deduped


# ---------------------------------------------------------------------------
# Pipeline output builder
# ---------------------------------------------------------------------------

def _load_reachability_metadata(scan_dir: str) -> dict | None:
    """Return the reachability-filter record for this scan, if one exists.

    The parse step (``core/parser_adapter.apply_reachability_filter``) stamps
    the true kept-unit count onto ``<scan_dir>/dataset.json`` under
    ``metadata.reachability_filter``. The reporter reads it so
    ``pipeline_stats.reachable_units`` reflects reality instead of assuming
    every analyzed unit is reachable. Returns ``None`` when the dataset or the
    record is absent/unreadable (an unfiltered scan, or a parser that recorded
    none). NOTE: on a multi-language scan the merged ``dataset.json`` currently
    carries only the first-parsed language's record (see ``dataset_merge`` /
    BUG-2b); this reader surfaces that record and warns — full per-language
    accounting is deferred to a follow-up.
    """
    dataset_path = os.path.join(scan_dir, "dataset.json")
    if not os.path.exists(dataset_path):
        return None
    try:
        dataset = read_json(dataset_path)
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(dataset, dict):
        return None
    metadata = dataset.get("metadata")
    if not isinstance(metadata, dict):
        return None
    rf = metadata.get("reachability_filter")
    return rf if isinstance(rf, dict) else None


def build_pipeline_output(
    results_path: str,
    output_path: str,
    repo_name: str | None = None,
    repo_url: str | None = None,
    language: str | None = None,
    commit_sha: str | None = None,
    application_type: str = "web_app",
    processing_level: str | None = None,
    step_reports: list[dict] | None = None,
    context_source: str = "none",
    threat_model_sha256: str | None = None,
    threat_model_warnings: list | None = None,
    skipped_steps: list | None = None,
    skipped_step_reasons: dict | None = None,
) -> tuple[str, int]:
    """Build ``pipeline_output.json`` from analysis results.

    Reads ``results.json`` or ``results_verified.json`` and transforms
    confirmed vulnerable/bypassable findings into the schema expected by
    ``report/generator.py`` and ``utilities/dynamic_tester``.

    Args:
        results_path: Path to ``results.json`` or ``results_verified.json``.
        output_path: Where to write ``pipeline_output.json``.
        repo_name: Repository name (e.g. ``"langchain-ai/langchain"``).
        repo_url: Repository URL.
        language: Primary language.
        commit_sha: Commit SHA being analyzed.
        application_type: App type for context (default ``"web_app"``).
        processing_level: Processing level used (``"reachable"``, etc.).
        step_reports: Optional list of step report dicts for duration/cost info.
        context_source: Which path supplied the security model —
            ``"threat_model"`` (a file in the scanned repo), ``"generated"``
            (built-in generator), or ``"none"``. Recorded so a scan run under
            the wrong model is distinguishable from a correct one.
        threat_model_sha256: sha256 over the raw threat-model file bytes when
            one was loaded; ``None`` (key omitted) otherwise — never the empty
            hash.
        threat_model_warnings: over-permissive-model warnings to surface in the
            artifact + report header; ``None``/empty when there are none.

    Returns:
        A ``(output_path, findings_count)`` tuple: the *output_path* written
        to and the number of findings emitted into ``pipeline_output.json``.
    """
    print(f"[Report] Building pipeline_output.json...", file=sys.stderr)

    experiment = read_json(results_path)
    # fa17 TRUST BOUNDARY: normalize model-supplied `results` to dicts-only once
    # at load so every downstream count/iterator sees the same filtered list.
    normalize_results(experiment)
    # fa18 TRUST BOUNDARY: `confirmed_findings` shares this same
    # results_verified.json trust boundary and is iterated with `finding.get(...)`
    # below (and inside _dedup_caller_callee). Normalize it to dicts-only at the
    # same load point so a non-list value (which fa15's `[c for c in confirmed]`
    # guard would raise TypeError on) or non-dict elements can't crash the build.
    # Guard on presence: an ABSENT key must stay absent so the `confirmed is None`
    # fallback below (manual filter from `results`) still fires -- materializing
    # it to [] would silently skip that fallback.
    if "confirmed_findings" in experiment:
        normalize_results(experiment, "confirmed_findings")
    # FAM-ROBUST (fa15/fa16, kept as defense-in-depth): `results` is
    # model-supplied; a non-Anthropic model can emit a bare string/number where a
    # result dict is expected. Drop non-dict elements once at the entry so the
    # confirmed filter and the full_result `next(...)` lookup below never call
    # `.get()` on a non-dict.
    all_results = [r for r in experiment.get("results", []) if isinstance(r, dict)]
    code_by_route = experiment.get("code_by_route", {})
    metrics = experiment.get("metrics", {})

    # Use confirmed_findings if present (verified results), else filter manually
    confirmed = experiment.get("confirmed_findings")
    if confirmed is None:
        # Filter on the FINAL verdict, not the `agree` flag. Stage 2 may
        # disagree on reason/CWE but still confirm vulnerable — those must
        # not be dropped. Unverified findings are included (no verification
        # dict = assumed confirmed).
        confirmed = [
            r for r in all_results
            if str(r.get("finding") or r.get("verdict", "")).lower() in ("vulnerable", "bypassable")
        ]

    # FAM-ROBUST: the `confirmed_findings` (verified-results) path comes straight
    # from model output and may contain non-dict elements; drop them before the
    # top-level `for finding in confirmed` loop `.get()`s each element.
    confirmed = [c for c in confirmed if isinstance(c, dict)]

    # ---------------------------------------------------------------
    # Dedup: collapse caller/callee pairs that share the same attack
    # vector. The call graph records A→B edges; if B is only reachable
    # through A and both have the same attack_vector, keep only A.
    # ---------------------------------------------------------------
    call_graph_path = os.path.join(
        os.path.dirname(os.path.abspath(results_path)), "call_graph.json"
    )
    confirmed = _dedup_caller_callee(confirmed, all_results, call_graph_path)

    # Build findings in PipelineOutput schema
    findings_data = []
    for i, finding in enumerate(confirmed):
        route_key = finding.get("route_key") or finding.get("unit_id", "unknown")

        # Look up full result for extra fields
        full_result = next(
            (r for r in all_results
             if (r.get("route_key") or r.get("unit_id")) == route_key),
            finding,
        )

        # Extract vulnerability details from nested structure if present
        vulns = finding.get("vulnerabilities", [])
        # Truthiness only proves the list is non-empty, not that its first
        # element is a dict. A model can return vulnerabilities=["str"]; guard
        # the element with isinstance so the vuln.get(...) reads below can't
        # raise AttributeError. Same defensive-coercion class as _coerce_to_str.
        vuln = vulns[0] if vulns and isinstance(vulns[0], dict) else {}

        description = (
            vuln.get("description")
            or finding.get("reasoning")
            or full_result.get("reasoning")
        )

        vulnerable_code = vuln.get("vulnerable_code") or code_by_route.get(route_key)
        file_path = route_key.split(":")[0] if ":" in route_key else "unknown"
        vulnerable_code_section = _build_vulnerable_code_section(
            file_path=file_path,
            code=vulnerable_code,
            language=language,
        )

        impact = vuln.get("impact") or finding.get("attack_vector")

        steps_to_reproduce = vuln.get("steps_to_reproduce")
        if not steps_to_reproduce:
            # Some non-Anthropic models return structured objects where the
            # prompt asked for strings. Coerce defensively so a stray dict
            # in attack_vector / verification_explanation / data_flow
            # doesn't crash report generation. See ``_coerce_to_str``.
            parts = []
            if finding.get("attack_vector"):
                parts.append(_coerce_to_str(finding["attack_vector"]))
            # ``or {}`` only substitutes for FALSY values; a truthy non-dict
            # exploit_path (a string/list, which non-Anthropic models emit)
            # would slip through and crash ``.get``. Guard the type too.
            exploit_path = finding.get("exploit_path")
            if not isinstance(exploit_path, dict):
                exploit_path = {}
            data_flow = exploit_path.get("data_flow")
            if data_flow:
                # ``data_flow`` is meant to be ``list[str]`` (verify
                # schema), but a model can violate that. Coerce the
                # CONTAINER first — only join step-by-step when it really
                # is a sequence; otherwise coerce the whole value. A bare
                # iterate-and-join here would crash on a scalar, char-walk
                # a bare string, and drop a dict's values. See M3.
                if isinstance(data_flow, (list, tuple)):
                    flow_str = " -> ".join(_coerce_to_str(step) for step in data_flow)
                else:
                    flow_str = _coerce_to_str(data_flow)
                parts.append("Data flow: " + flow_str)
            if finding.get("verification_explanation"):
                parts.append("Verification: " + _coerce_to_str(finding["verification_explanation"]))
            steps_to_reproduce = "\n\n".join(parts) if parts else None

        # Determine stage2 verdict.
        #
        # PR #69 F4: distinguish an INCOMPLETE verification from a genuine
        # rejection. R4-7 made the verifier fail-safe — on its four degenerate
        # paths (unparseable text / no tool calls / max iterations / finish
        # without `agree`) and on an adapter raise it returns ``agree=False``
        # but preserves the Stage-1 verdict and flags ``incomplete=True``.
        # ``agree=False`` alone is ambiguous: it can mean "Stage 2 disagreed"
        # OR "Stage 2 could not complete". Mapping the latter to "rejected" is
        # wrong (verify never rejected) and silently drops it from disclosures.
        # Map incomplete → "unverified" so it renders distinctly and stays
        # disclosure-eligible (surfaced for manual review).
        verification = finding.get("verification", {})
        # A non-Anthropic model can return ``verification`` as a truthy
        # non-dict (e.g. the string "agreed"); the ``.get`` calls below
        # would raise AttributeError and crash report generation. Coerce
        # to an empty dict — same read-side guard as exploit_path / M3.
        if not isinstance(verification, dict):
            verification = {}
        if verification.get("agree", False):
            stage2_verdict = "confirmed" if finding.get("exploit_path") else "agreed"
        elif verification.get("incomplete"):
            stage2_verdict = "unverified"
        elif verification:
            stage2_verdict = "rejected"
        else:
            stage2_verdict = finding.get("finding", "vulnerable")

        findings_data.append({
            "id": f"VULN-{i+1:03d}",
            "name": vuln.get("name", finding.get("finding", "Unknown Vulnerability")),
            "short_name": vuln.get("short_name", finding.get("verdict", "vuln")),
            "location": {
                # function is the exact complement of file so that
                # file + ":" + function == route_key round-trips (the cli.py
                # dynamic-test bridge reconstructs route_key from these two).
                # This drops the redundant file prefix that used to duplicate
                # ``file`` inside ``function`` (D3b).
                "file": route_key.split(":")[0] if ":" in route_key else "unknown",
                "function": route_key.split(":", 1)[1] if ":" in route_key else route_key,
            },
            "cwe_id": vuln.get("cwe_id") or finding.get("cwe_id") or full_result.get("cwe_id", 0),
            "cwe_name": vuln.get("cwe_name") or finding.get("cwe_name") or full_result.get("cwe_name", "Unknown"),
            "stage1_verdict": finding.get("verdict", finding.get("finding", "vulnerable")),
            "stage2_verdict": stage2_verdict,
            # #215 (partial repair): the two FINDING-SEMANTIC transit
            # fields — confidence (float 0.0-1.0 per the verdict schema,
            # json_corrector.py:32; NOT analysis_core.py:181's error-shape
            # default) and json_corrected (provenance: the finding's JSON
            # was model-repaired, json_corrector.py:278) — populated
            # upstream, surviving into results_verified.json, previously
            # DROPPED by this fixed-key record. Present-only: absent
            # upstream stays absent (never a fabricated 0/False — a REAL
            # falsy value threads through). elapsed_seconds/prompt_length
            # stay OUT (per-unit step telemetry, not finding metadata).
            **({"confidence": finding["confidence"]}
               if finding.get("confidence") is not None else {}),
            **({"json_corrected": finding["json_corrected"]}
               if finding.get("json_corrected") is not None else {}),
            "description": description,
            "vulnerable_code": vulnerable_code,
            "vulnerable_code_section": vulnerable_code_section,
            "impact": impact,
            "suggested_fix": vuln.get("suggested_fix"),
            "steps_to_reproduce": steps_to_reproduce,
        })

    # Compute costs and durations from step reports
    costs = {}
    durations = {}
    if step_reports:
        for sr in step_reports:
            step = sr.get("step", "unknown")
            if sr.get("cost_usd"):
                costs[step] = {"actual": sr["cost_usd"]}
            if sr.get("duration_seconds"):
                durations[step] = sr["duration_seconds"]

    # Populate skipped_steps from the authoritative ScanResult skip data. The
    # reporter is otherwise blind to skips (it reads only cost/duration above),
    # so pipeline_stats.skipped_steps was always [] — a crashed/skipped step
    # (most importantly a non-aborting Stage-2 verify failure) then rendered in
    # the human summary as "No steps were skipped", indistinguishable from a
    # clean fully-verified scan. Report-fidelity only: per-finding disclosure is
    # unchanged (unverified findings stay included, labeled stage2_verdict
    # 'vulnerable' vs 'confirmed'); this does NOT gate disclosure.
    _skip_reasons = skipped_step_reasons or {}
    skipped_steps_detail = [
        {"step": s, "reason": _skip_reasons.get(s, "")}
        for s in (skipped_steps or [])
    ]

    total_units = metrics.get("total", len(all_results))

    # F1: report the TRUE reachable count from the reachability filter's record
    # (persisted to <scan_dir>/dataset.json by the parse step) instead of
    # fabricating reachable_units = total_units. Surfacing original_units +
    # the reduction makes the pruning visible (a report that showed only the
    # kept count gave no hint units were pruned — the neqo misdiagnosis vector).
    # When no record exists but a filtering level was requested, warn rather
    # than silently assert full reachability (the free-function-parser /
    # not-recorded blind spot); also surface any blackout warning the filter
    # recorded (previously written to metadata only, with no report consumer).
    _reach = _load_reachability_metadata(
        os.path.dirname(os.path.abspath(results_path))
    )
    reachability_warnings: list[str] = []
    reachability_filter_applied = _reach is not None
    reachable_units = total_units
    original_units = total_units
    reachability_reduction_percentage = None
    if _reach is not None:
        if isinstance(_reach.get("reachable_units"), int):
            reachable_units = _reach["reachable_units"]
        if isinstance(_reach.get("original_units"), int):
            original_units = _reach["original_units"]
        if isinstance(_reach.get("reduction_percentage"), (int, float)):
            reachability_reduction_percentage = _reach["reduction_percentage"]
        _rf_warning = _reach.get("warning")
        if isinstance(_rf_warning, str) and _rf_warning:
            reachability_warnings.append(_rf_warning)
    elif total_units > 0 and (processing_level or "").lower() not in ("", "all", "none"):
        reachability_warnings.append(
            f"Reachability filtering was requested (level={processing_level!r}) "
            "but no reachability_filter record was found; reachable_units falls "
            "back to total_units and may overstate reachability."
        )

    # reachable_units is a parse-stage count (units the filter kept); total_units
    # is the analyze-stage total (which --limit / subset runs can truncate below
    # the kept set). Guard the cross-stage case so the report never silently
    # shows reachable_units > total_units without explanation.
    if isinstance(reachable_units, int) and reachable_units > total_units:
        reachability_warnings.append(
            f"reachable_units ({reachable_units}) exceeds analyzed total_units "
            f"({total_units}): analysis covered a subset of the reachable units "
            "(e.g. --limit). reachable_units is the reachability filter's kept "
            "count; units_analyzed reflects what was actually analyzed."
        )

    pipeline_output = {
        "repository": {
            "name": repo_name or experiment.get("dataset", "unknown"),
            "url": repo_url or "",
            "language": language or "",
            "commit_sha": commit_sha,
        },
        "analysis_date": datetime.now(timezone.utc).isoformat(),
        "application_type": application_type,
        # Which path supplied the security model (Plan DoD #9). Additive key;
        # Go consumers use comma-ok access so it is safe to add.
        "context_source": context_source,
        **(
            {"threat_model_sha256": threat_model_sha256}
            if threat_model_sha256
            else {}
        ),
        # Over-permissive-model warnings (previously stderr-only). Emitted as a
        # list so the report header can render them; empty list when none.
        "threat_model_warnings": list(threat_model_warnings or []),
        "pipeline_stats": {
            "total_units": total_units,
            "reachable_units": reachable_units,
            # Additive reachability provenance (all tolerated by the untyped
            # pipeline_stats dict in report/schema.py):
            "original_units": original_units,
            "reachability_filter_applied": reachability_filter_applied,
            "reachability_reduction_percentage": reachability_reduction_percentage,
            "reachability_warnings": reachability_warnings,
            "units_analyzed": total_units - metrics.get("errors", 0),
            "processing_level": processing_level,
            "costs": costs,
            "durations": durations,
            "skipped_steps": skipped_steps_detail,
        },
        "results": {
            "vulnerable": metrics.get("vulnerable", 0) + metrics.get("bypassable", 0),
            "safe": metrics.get("safe", 0) + metrics.get("protected", 0),
            "inconclusive": metrics.get("inconclusive", 0),
            # F13: errored units are part of `total` (see units_analyzed above), so the
            # results buckets must include them or they cannot reconcile to `total`.
            "errors": metrics.get("errors", 0),
            "total": total_units,
        },
        "findings": findings_data,
    }

    # If this scan ran in diff mode, attach the manifest + filter stats so the
    # HTML report can show a PR / incremental scan header.
    scan_dir = os.path.dirname(os.path.abspath(results_path))
    diff_meta = _load_diff_metadata(scan_dir)
    if diff_meta is not None:
        pipeline_output["diff"] = diff_meta
        _banner = (
            f"[Report] Incremental scan: base={diff_meta.get('base_ref')}, "
            f"scope={diff_meta.get('scope')}, "
            f"{diff_meta.get('units_in_diff', '?')}/{diff_meta.get('units_total_parsed', '?')} units"
        )
        if diff_meta.get("pr_number"):
            _banner += f", PR #{diff_meta['pr_number']}"
        print(_banner, file=sys.stderr)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    write_json(output_path, pipeline_output, ensure_ascii=False)
    print(f"  pipeline_output.json: {len(findings_data)} findings", file=sys.stderr)
    print(f"  Written to {output_path}", file=sys.stderr)

    return output_path, len(findings_data)


def generate_html_report(
    results_path: str,
    dataset_path: str,
    output_path: str,
) -> ReportResult:
    """Generate an interactive HTML report with Chart.js.

    Wraps generate_report.py via subprocess.

    Args:
        results_path: Path to experiment/results JSON.
        dataset_path: Path to dataset JSON.
        output_path: Path for the output HTML file.

    Returns:
        ReportResult with the output path.
    """
    print("[Report] Generating HTML report...", file=sys.stderr)

    # Pass step reports dir so the HTML report can include cost/time breakdown
    step_reports_dir = os.path.dirname(os.path.abspath(results_path))

    cmd = [
        # -P: no CWD on sys.path. `-m` prepends the process CWD to sys.path[0],
        # and the engine inherits the user's shell CWD — which, in the standard
        # `git clone X && cd X && openant report` flow, is INSIDE the scanned
        # untrusted repo. Without -P, a hostile ``report/`` package in that repo
        # shadows this one and its __init__ executes. This dropped when cwd=
        # _CORE_ROOT was removed to fix the wheel; -P restores the containment
        # the cwd pin held by accident.
        sys.executable, "-P", "-m", "report.html_report", results_path, dataset_path, output_path,
        "--step-reports-dir", step_reports_dir,
    ]

    # No cwd=_CORE_ROOT: these are now `-m` package invocations resolved through
    # the installed distribution, not source-tree-relative scripts. Depending on
    # cwd is what made them unrunnable from an installed wheel.
    result = subprocess.run(cmd, stdout=sys.stderr, stderr=sys.stderr)

    if result.returncode != 0:
        raise RuntimeError(f"HTML report generation failed (exit code {result.returncode})")

    print(f"  HTML report: {output_path}", file=sys.stderr)
    return ReportResult(output_path=output_path, format="html")


def generate_csv_report(
    results_path: str,
    dataset_path: str,
    output_path: str,
) -> ReportResult:
    """Export results to CSV.

    Wraps export_csv.py via subprocess.

    Args:
        results_path: Path to experiment/results JSON.
        dataset_path: Path to dataset JSON.
        output_path: Path for the output CSV file.

    Returns:
        ReportResult with the output path.
    """
    print("[Report] Generating CSV report...", file=sys.stderr)

    # -P: keep the untrusted CWD off sys.path so a hostile report/ package in the
    # scanned repo cannot shadow this one. See the html path above for the full note.
    cmd = [sys.executable, "-P", "-m", "report.csv_export", results_path, dataset_path, output_path]

    # No cwd=_CORE_ROOT: these are now `-m` package invocations resolved through
    # the installed distribution, not source-tree-relative scripts. Depending on
    # cwd is what made them unrunnable from an installed wheel.
    result = subprocess.run(cmd, stdout=sys.stderr, stderr=sys.stderr)

    if result.returncode != 0:
        raise RuntimeError(f"CSV export failed (exit code {result.returncode})")

    print(f"  CSV report: {output_path}", file=sys.stderr)
    return ReportResult(output_path=output_path, format="csv")


def generate_summary_report(
    results_path: str,
    output_path: str,
    llm_config_name: str | None = None,
) -> ReportResult:
    """Generate LLM-based summary report (Markdown).

    Calls report/generator.py directly (in-process) for proper cost tracking.

    Args:
        results_path: Path to pipeline_output.json or results JSON.
        output_path: Path for the output Markdown file.
        llm_config_name: Name of the llm-config to use. ``None`` falls
            through to the file's ``default_llm`` (or the built-in
            ``openant-default``).

    Returns:
        ReportResult with the output path and usage info.
    """
    import json
    from report.generator import generate_summary_report as _generate_summary, merge_dynamic_results
    from report.schema import validate_pipeline_output, ValidationError
    from utilities.llm import (
        build_phase_registry,
        load_config_file,
        probe_registry_or_raise,
        resolve_llm_config,
    )

    print("[Report] Generating summary report (LLM)...", file=sys.stderr)

    pipeline_data = read_json(results_path)
    # fa18 TRUST BOUNDARY: `findings` is a model array-of-dict read back from
    # pipeline_output.json; merge_dynamic_results (below) and the summary
    # compaction iterate it with `finding.get(...)`. Normalize to dicts-only
    # once at this load, BEFORE the merge, so a non-dict element can't crash.
    # Guard on presence so an absent `findings` still trips validation's
    # "missing required field" check rather than silently validating as empty.
    if "findings" in pipeline_data:
        normalize_results(pipeline_data, "findings")
    # Merge dynamic test results if available
    pipeline_data = merge_dynamic_results(pipeline_data, results_path)

    try:
        validate_pipeline_output(pipeline_data)
    except ValidationError as e:
        raise RuntimeError(f"Invalid pipeline output: {e}")

    # Resolve the report-phase binding once and pass it through.
    # ``generate_summary_report`` is always invoked standalone via
    # ``openant report -f summary`` — no upstream scanner has
    # pre-validated the registry, so probe it here.
    cf = load_config_file()
    registry = build_phase_registry(cf, resolve_llm_config(cf, llm_config_name))
    probe_registry_or_raise(registry)
    report_binding = registry.get("report")
    report_text, usage = _generate_summary(pipeline_data, report_binding)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open_utf8(output_path, "w") as f:
        f.write(report_text)

    print(f"  Summary report: {output_path}", file=sys.stderr)
    print(f"  Cost: ${usage['cost_usd']:.4f} ({usage['total_tokens']:,} tokens)", file=sys.stderr)

    # Record in global tracker so step_context picks it up
    _record_usage_in_tracker(usage, report_binding)

    return ReportResult(output_path=output_path, format="summary", usage=_usage_to_info(usage))


def safe_disclosure_filename(short_name: str) -> str:
    """Reduce a model-supplied name to a single safe path component.

    ``short_name`` is LLM output (``vuln.get("short_name")``), and it used to reach
    ``os.path.join`` through only ``.replace(" ", "_").upper()``. That is not
    sanitisation: ``/`` and ``..`` pass through untouched, so a name like
    ``../../../etc/pwned`` escaped the output directory and turned report generation
    into an arbitrary-write primitive.

    This matters more than a typical output-escaping bug because the threat model
    file is repository-authored and unfenced — the accepted prompt-injection gap is
    precisely a channel for steering model output, so treating that output as
    trusted compounds one accepted risk into an unaccepted one.

    Allowlist rather than blocklist: enumerate what may appear, so novel separators,
    unicode lookalikes and encoding tricks are excluded by construction instead of
    by remembering to ban them.
    """
    cleaned = re.sub(r"[^A-Za-z0-9_-]", "_", (short_name or "").strip())
    cleaned = cleaned.strip("._-")[:64]
    return cleaned.upper() or "UNNAMED"


def generate_disclosure_docs(
    results_path: str,
    output_dir: str,
    llm_config_name: str | None = None,
) -> ReportResult:
    """Generate per-vulnerability disclosure documents.

    Calls report/generator.py directly (in-process) for proper cost tracking.

    Args:
        results_path: Path to pipeline_output.json or results JSON.
        output_dir: Directory for disclosure Markdown files.
        llm_config_name: Name of the llm-config to use. ``None`` falls
            through to the file's ``default_llm``.

    Returns:
        ReportResult with the output directory path and usage info.
    """
    import json
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from report.generator import generate_disclosure as _generate_disclosure, _merge_usage, merge_dynamic_results
    from report.schema import validate_pipeline_output, ValidationError
    from utilities.llm import (
        build_phase_registry,
        load_config_file,
        probe_registry_or_raise,
        resolve_llm_config,
    )

    print("[Report] Generating disclosure documents (LLM)...", file=sys.stderr)

    pipeline_data = read_json(results_path)
    # fa18 TRUST BOUNDARY: normalize model `findings` to dicts-only at load,
    # BEFORE merge_dynamic_results / the disclosure-eligibility enumerate below,
    # so a non-dict element can't crash `finding.get("stage2_verdict")`.
    # Presence-guarded (see generate_summary_report for rationale).
    if "findings" in pipeline_data:
        normalize_results(pipeline_data, "findings")
    # Merge dynamic test results if available
    pipeline_data = merge_dynamic_results(pipeline_data, results_path)

    try:
        validate_pipeline_output(pipeline_data)
    except ValidationError as e:
        raise RuntimeError(f"Invalid pipeline output: {e}")

    os.makedirs(output_dir, exist_ok=True)

    # Resolve the report-phase binding once and reuse across the
    # ThreadPoolExecutor — adapters are stateless dispatchers, safe
    # to share. Probe the registry upfront (standalone-invocation
    # path; same rationale as generate_summary_report).
    cf = load_config_file()
    registry = build_phase_registry(cf, resolve_llm_config(cf, llm_config_name))
    probe_registry_or_raise(registry)
    report_binding = registry.get("report")

    product_name = pipeline_data["repository"]["name"]
    all_usages = []
    count = 0

    # Collect findings eligible for a disclosure document.
    #
    # Eligibility is defined once in core.verdict_taxonomy.DISCLOSURE_ELIGIBLE
    # (shared with report/generator.py and report/__main__.py) so the producer
    # (this module's stage2_verdict mapping) and every disclosure filter stay in
    # lock-step -- a verdict the producer can emit but no filter accepts is a
    # silently-dropped finding. "unverified" (Stage-2 could not COMPLETE) stays
    # eligible; "rejected" (Stage 2 actively downgraded) stays excluded.
    confirmed = [
        (i, finding) for i, finding in enumerate(pipeline_data["findings"], 1)
        if finding.get("stage2_verdict") in DISCLOSURE_ELIGIBLE
    ]

    if not confirmed:
        print("  No confirmed vulnerabilities to generate disclosures for.", file=sys.stderr)
    else:
        print(f"  Generating {len(confirmed)} disclosures in parallel (8 workers)...",
              file=sys.stderr)

        def _one(args):
            i, finding = args
            disclosure_text, usage = _generate_disclosure(finding, product_name, report_binding)
            filename = f"DISCLOSURE_{i:02d}_{safe_disclosure_filename(finding['short_name'])}.md"
            filepath = os.path.join(output_dir, filename)
            with open_utf8(filepath, "w") as f:
                f.write(disclosure_text)
            return finding["short_name"], filepath, usage

        executor = ThreadPoolExecutor(max_workers=8)
        futures = {executor.submit(_one, item): item for item in confirmed}
        try:
            for future in as_completed(futures):
                name, filepath, usage = future.result()
                all_usages.append(usage)
                count += 1
                print(f"  [{count}/{len(confirmed)}] {name} -> {filepath}",
                      file=sys.stderr)
        except KeyboardInterrupt:
            print("\n[Report] Interrupted — cancelling pending disclosures...",
                  file=sys.stderr, flush=True)
            executor.shutdown(wait=False, cancel_futures=True)
            raise
        executor.shutdown(wait=False)

    merged_usage = _merge_usage(all_usages) if all_usages else {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "cost_usd": 0.0}

    print(f"  Disclosures: {count} files in {output_dir}", file=sys.stderr)
    print(f"  Cost: ${merged_usage['cost_usd']:.4f} ({merged_usage['total_tokens']:,} tokens)", file=sys.stderr)

    # Record in global tracker so step_context picks it up
    _record_usage_in_tracker(merged_usage, report_binding)

    return ReportResult(output_path=output_dir, format="disclosure", usage=_usage_to_info(merged_usage))


def _record_usage_in_tracker(usage: dict, binding):
    """Record usage in the global TokenTracker so step_context captures it.

    The ``binding`` is the report-phase :class:`PhaseBinding` that
    produced the tokens. Both the recorded ``model`` and the cost
    rate must come from it — hardcoding either would lie when the
    report phase is configured against anything other than opus.
    """
    try:
        from utilities.llm import lookup_pricing
        from utilities.llm_client import get_global_tracker
        tracker = get_global_tracker()
        # Record as a single aggregated call
        if usage.get("total_tokens", 0) > 0:
            tracker.record_call(
                model=binding.model,
                input_tokens=usage["input_tokens"],
                output_tokens=usage["output_tokens"],
                pricing=lookup_pricing(binding),
                # #211 pass-through capture: verbatim when the generator's
                # usage dict carries it; never in the cost math.
                usage_details=usage.get("usage_details"),
            )
    except Exception:
        pass  # Best effort — don't break report generation


def _usage_to_info(usage: dict):
    """Convert a usage dict to a UsageInfo dataclass."""
    from core.schemas import UsageInfo
    return UsageInfo(
        total_calls=1,
        total_input_tokens=usage.get("input_tokens", 0),
        total_output_tokens=usage.get("output_tokens", 0),
        total_tokens=usage.get("total_tokens", 0),
        total_cost_usd=usage.get("cost_usd", 0.0),
    )
