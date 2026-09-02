"""Stage 1 analysis primitives.

These three functions were defined in ``experiment.py`` — a research harness that
is NOT a packaged module — and imported from there by ``core/analyzer.py``. That
made the installed product unimportable: `pip install openant` ships the seven
packages listed in pyproject, `experiment.py` is a loose top-level file, and
``import core.analyzer`` raised ModuleNotFoundError in any clean environment.
Verified by building a wheel and installing it into an empty venv.

The dependency also ran the wrong way round: production reaching into research
code. It now runs research -> product; ``experiment.py`` imports these from here.

Nothing else moved. These were chosen because they are exactly what ``core`` used
and they depend only on stdlib and shipped packages (utilities/, prompts/).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from datetime import datetime

from core.verdict_taxonomy import (
    FINDING_VERDICT_ORDER,
    _SEVERITIES,
    STAGE1_VERDICTS,
)
# RE-EXPORT, not unused: test_issue215's one-enum-everywhere pin asserts
# `analysis_core.SEVERITIES is SEVERITIES` — the from-import re-export form
# of the #482 trap (the second instance in this sweep). Keep + noqa.
from core.verdict_taxonomy import SEVERITIES as SEVERITIES  # noqa: F401

# the canonical lowercase finding strings a garbage-verdict row may keep
# (wave r1 opus: the finding-first sinks key on exactly these).
_CANONICAL_FINDINGS = frozenset(FINDING_VERDICT_ORDER) | {"error"}

from prompts.prompt_selector import get_analysis_prompt
from prompts.vulnerability_analysis import get_system_prompt as get_stage1_system_prompt
from utilities.context_reviewer import ContextReviewer
from utilities.json_corrector import JSONCorrector
from utilities.llm import PhaseBinding, simple_text

if TYPE_CHECKING:  # avoids a runtime cycle: context/ imports utilities/ which
    # imports prompts/ which imports core/. The annotation is a string either way.
    from context.application_context import ApplicationContext

def _normalize_result(result: dict) -> dict:
    """Normalize LLM response fields to canonical names.

    Handles cases where the model returns 'finding' instead of 'verdict',
    or uses different casing/naming conventions.
    """
    # Normalize finding -> verdict. A verdict only counts as present when it
    # is an EFFECTIVE string — {"verdict": null} is the #324 refusal shape
    # with the key present (a null verdict crashed _count_verdicts' fallback).
    verdict = result.get("verdict")
    has_verdict = isinstance(verdict, str) and verdict.strip() != ""
    # #427: an unrecognized NON-EMPTY verdict string ({"verdict": "SAY WHAT"},
    # {"verdict": "weird"} — the same untrusted model-JSON class #316's
    # garbage findings came from) previously passed through unchanged and
    # failed OPEN at every accounting sink: dropped from all _count_verdicts
    # buckets (sum < total), analyze_result_is_error -> False (adopted as
    # complete on resume, never retried), counted as completed by the
    # summary seeding, never in the disclosure set. The same garbage class
    # failed CLOSED for the FINDING key (#426) and OPEN for the verdict key —
    # close the asymmetry with the matching whitelist: known verdicts pass;
    # anything else routes to the error accounting with the raw preserved.
    # Wave r1 (opus) — the finding-kept redesign: routing the WHOLE row to
    # error even when the model's `finding` was a usable canonical string
    # ("vulnerable") EXCLUDED it from Stage-2 selection and disclosure —
    # the finding-first sinks were already counting it correctly, so the
    # erasure was a false negative for a row whose model reply asserted
    # vulnerable. The garbage VERDICT is discarded (raw preserved); a
    # USABLE finding is KEPT (the row keeps its finding-driven accounting
    # and disclosure); only when the finding is absent or itself unusable
    # does the row route to the error shape.
    if has_verdict and verdict.strip().upper() not in STAGE1_VERDICTS:
        result["raw_verdict"] = verdict
        _finding = result.get("finding")
        if isinstance(_finding, str) and _finding.strip().lower() in _CANONICAL_FINDINGS:
            # keep the canonical finding; the row's accounting is unchanged
            # (the raw verdict is preserved above for manual review).
            # famBCR panel (sonnet): the KEPT verdict must be normalized to
            # MATCH the finding — the downstream severity stamping keys on
            # `verdict`, and leaving the garbage "SAY WHAT" there silently
            # dropped severity for exactly these rows (the #436 stamp gates
            # on VULNERABLE/BYPASSABLE). The row now carries the finding's
            # canonical verdict uppercase, so every verdict-keyed consumer
            # agrees with every finding-keyed one.
            result["verdict"] = _finding.strip().upper()
        else:
            if _finding is not None and (
                    not isinstance(_finding, str) or _finding.strip()):
                # a non-string or non-empty finding beside the garbage
                # verdict is preserved raw (wave r1 fable: the #316 branch
                # preserves non-string raws; erasing them destroyed data).
                result["raw_finding"] = _finding
            result["verdict"] = "ERROR"
            result["finding"] = "error"
    if not has_verdict and "finding" in result:
        finding = result["finding"]
        if not isinstance(finding, str):
            # A non-string finding (list/dict/null/number) is a malformed model reply,
            # not a verdict — map it to ERROR so the error / manual-review accounting
            # counts it, instead of a garbage verdict (e.g. "['VULNERABLE']" from
            # str(finding).upper()) that silently escapes that accounting.
            # #316: stamp BOTH keys (verdict + finding) — the finding-keyed
            # consumers (_summary_callback, _count_verdicts) would otherwise
            # disagree with the verdict-keyed ones. Raw value preserved for
            # manual review.
            result["raw_finding"] = finding
            result["finding"] = "error"
            result["verdict"] = "ERROR"
        else:
            finding_to_verdict = {
                "vulnerable": "VULNERABLE",
                "safe": "SAFE",
                "protected": "PROTECTED",
                "bypassable": "BYPASSABLE",
                "inconclusive": "INCONCLUSIVE",
                "insufficient_context": "INSUFFICIENT_CONTEXT",
            }
            verdict = finding_to_verdict.get(finding.lower(), "ERROR")
            if verdict == "ERROR" and finding.lower() != "error":
                # #316: an unrecognized finding string is a malformed model
                # reply, not a verdict. Map it to ERROR — counted in `errors`,
                # retried on resume, manual-review-visible — instead of the
                # upper-case passthrough that escaped every accounting (the
                # non-string branch above chose the same direction).
                result["raw_finding"] = finding
                result["finding"] = "error"
            result["verdict"] = verdict
    elif not has_verdict:
        # #324: a parsed object with neither an effective verdict NOR a
        # finding (a JSON-shaped refusal, e.g. {"reasoning": ...}) is not an
        # analysis. Stamp the one error shape so it is counted in `errors`
        # (units_analyzed stops overstating) and re-analyzed on resume
        # instead of adopted as complete.
        result["verdict"] = "ERROR"
        result["finding"] = "error"

    # Ensure verdict is uppercase (wave r1 fable: STRIPPED too — a "safe "
    # passed the whitelist's .strip().upper() check and was then stored
    # unstripped, which the sinks dropped: the exact fail-open the fix
    # closes, for an input the check had just classified canonical).
    if "verdict" in result and isinstance(result["verdict"], str):
        result["verdict"] = result["verdict"].strip().upper()

    # #215: a rankable severity, FINDING-ONLY — stamped AFTER the verdict
    # decision, and only for the finding verdicts (VULNERABLE/BYPASSABLE).
    # Severity validation never produces the error shape and never touches
    # the error key (the #426 composition invariant: analyze_result_is_error
    # and _count_verdicts are keyed on verdict/finding only, and
    # is_retryable_error never sees severity). Every OTHER row — ERROR
    # (an analysis failure, not a finding), and safe/protected/inconclusive
    # (no finding to rank; the prompt itself says null) — carries NO
    # severity: a "low" on a safe unit would defeat the triage filter the
    # reporter asked for (severity=low must not return non-findings).
    if result.get("verdict") in ("VULNERABLE", "BYPASSABLE"):  # the finding verdicts (SEVERITY_FINDING_VERDICTS, uppercased)
        sev = result.get("severity")
        if isinstance(sev, str) and sev.strip().lower() in _SEVERITIES:
            result["severity"] = sev.strip().lower()
            result["severity_source"] = "model"
        else:
            # Derive conservatively: a verdict cannot know criticality, so
            # no derived "critical"; vulnerable is high, bypassable medium.
            # Stage-2 reclassifications and model omissions land here — the
            # read-time sites RE-DERIVE from the final verdict, so a stale
            # Stage-1 stamp never outranks the final one.
            result["severity"] = "high" if result["verdict"] == "VULNERABLE" else "medium"
            result["severity_source"] = "derived"
    else:
        result.pop("severity", None)
        result.pop("severity_source", None)

    # Ensure CWE fields are always present.
    if "cwe_id" not in result:
        result["cwe_id"] = 0
    if "cwe_name" not in result:
        result["cwe_name"] = None

    return result


def parse_response(response: str) -> dict:
    """Parse JSON response from Claude."""
    # Try to extract JSON from response
    response = response.strip()

    # Remove markdown code blocks if present
    if response.startswith("```json"):
        response = response[7:]
    elif response.startswith("```"):
        response = response[3:]

    if response.endswith("```"):
        response = response[:-3]

    response = response.strip()

    err = None
    try:
        result = json.loads(response)
    except json.JSONDecodeError as e:
        err = e
    else:
        if isinstance(result, dict):
            return _normalize_result(result)
        # Top-level JSON that is NOT an object (e.g. an array-of-findings
        # `[{"verdict":...}]`) — do NOT hand a list to _normalize_result (it
        # indexes by str keys -> TypeError -> uncaught, permanent coverage loss,
        # PY-2). Fall through to the depth-0 scanner, which recovers a lone
        # verdict object inside the array for free.
    # Thinking-on models wrap the final JSON verdict in prose + code on BOTH
    # sides. Scan for verdict objects at brace-DEPTH 0 only, tracking JSON-string
    # state (with escapes) so braces inside string values -- or balanced code
    # braces in the preamble -- don't offset the depth. Recovering only depth-0
    # objects stops a nested example dict INSIDE a malformed outer verdict from
    # being mistaken for the verdict.
    #
    # Recover a verdict ONLY when EXACTLY ONE depth-0 object decodes to a
    # verdict-bearing dict AND no COMPETING verdict signal exists:
    #  - several decoded verdict objects (example beside the real one, either
    #    order) -> ambiguous -> ERROR+retry (never let a trailing example {SAFE}
    #    override a real {VULNERABLE}); and
    #  - a depth-0 span that FAILED to decode but still looks like a verdict
    #    object (its text carries "verdict"/"finding") is a real verdict that
    #    didn't parse (a common trailing-comma / missing-comma slip) sitting
    #    beside a clean example -> also ambiguous -> ERROR+retry. Without this,
    #    the malformed real VULNERABLE is dropped and the clean example SAFE is
    #    returned: a silent SAST false negative (PY-NEW-1).
    # If the scan ends mid-string, quote parity is untrustworthy -> don't guess.
    # (Accepted residual, pre-existing in the prior find/rfind code: adversarial
    # stray quotes in prose can still steer depth parity; the safe fallback is
    # always ERROR->retry.)
    decoder = json.JSONDecoder()
    verdict_objs = []
    malformed_verdict_spans = 0
    depth = 0
    in_string = False
    escape = False
    obj_start = None
    for pos, ch in enumerate(response):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            if depth == 0:
                obj_start = pos
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and obj_start is not None:
                    # Decode the balanced depth-0 span in isolation: bounds the
                    # JSONDecodeError position math to the span (avoids O(n^2) on
                    # multi-MB responses, PY-NEW-2) and gives the span text for
                    # the malformed-verdict check.
                    span = response[obj_start:pos + 1]
                    try:
                        obj = decoder.decode(span)
                        if isinstance(obj, dict) and ("verdict" in obj or "finding" in obj):
                            verdict_objs.append(obj)
                    except json.JSONDecodeError:
                        # Count as a competing verdict only if the failed span
                        # carries a verdict/finding KEY (quoted, single or double)
                        # -- so a malformed real verdict triggers the ambiguity
                        # guard, but a preamble code block that merely contains the
                        # word "finding" does not over-reject to ERROR.
                        # ACCEPTED TRADE-OFF: a preamble that echoes verdict-SHAPED
                        # broken JSON (e.g. `{"verdict": v}` in analyzed code) also
                        # counts, so a legit lone verdict beside it is sent to
                        # ERROR+retry rather than recovered. That is a recovery-rate
                        # cost, not a wrong verdict (the retry re-derives it) -- the
                        # deliberate safe direction, chosen over risking the
                        # PY-NEW-1 false negative (malformed real verdict beside a
                        # clean example -> example returned as SAFE).
                        if any(k in span for k in ('"verdict"', "'verdict'", '"finding"', "'finding'")):
                            malformed_verdict_spans += 1
                    obj_start = None
    if not in_string and len(verdict_objs) == 1 and malformed_verdict_spans == 0:
        return _normalize_result(verdict_objs[0])

    detail = str(err) if err is not None else "top-level JSON is not an object"
    return {
        "verdict": "ERROR",
        "confidence": 0,
        "vulnerabilities": [],
        "reasoning": f"Failed to parse response: {detail}",
        "raw_response": response[:500],
        # Tag the failure so the detection retry pass (core/analyzer.py) can
        # re-attempt it: a malformed model response is often transient, and
        # without this key the ERROR carries error=None and is never retried
        # in-run, permanently masking the unit's true verdict.
        "error": {"type": "parse_error", "message": detail[:200]},
    }


def analyze_unit(
    binding: PhaseBinding,
    unit: dict,
    use_multifile: bool = False,
    json_corrector: JSONCorrector = None,
    context_reviewer: ContextReviewer = None,
    app_context: "ApplicationContext" = None
) -> dict:
    """
    Analyze a single code unit.

    Args:
        binding: Phase binding (provider+model) for the analyze phase.
        unit: The code unit to analyze
        use_multifile: If True, use multi-file prompt for enhanced datasets
        json_corrector: Optional JSON corrector. If not provided, one is created
                        internally when parsing fails (matching behavior of other
                        LLM-calling components like finding_verifier and context_enhancer).
        context_reviewer: Optional context reviewer for proactive context enhancement
        app_context: Optional ApplicationContext for reducing false positives

    Returns analysis result with timing and token info.
    """
    # Extract code from unit
    code_field = unit.get("code", {})
    if isinstance(code_field, dict):
        code = code_field.get("primary_code", "")
        # Check if dependencies were inlined into this unit's primary_code
        primary_origin = code_field.get("primary_origin", {})
        has_deps_inlined = primary_origin.get("deps_inlined", primary_origin.get("enhanced", False))
        files_included = primary_origin.get("files_included", [])
    else:
        code = code_field
        has_deps_inlined = False
        files_included = []

    # Extract agent context (security classification from agentic parser)
    # #326 (wave r1 opus): the agentic key is ``classification_reasoning``
    # (AgentResult.to_dict) — ``reasoning`` never exists in agent_context, so
    # the Stage-1 prompt silently lost the justification on the default mode
    # for every unit (the same key-name mismatch the CSV fix describes).
    agent_context = unit.get("agent_context") or {}
    if not isinstance(agent_context, dict):
        agent_context = {}
    security_classification = agent_context.get("security_classification")
    classification_reasoning = agent_context.get("classification_reasoning")

    # Get route info
    route = unit.get("route") or {}
    if route:
        route_key = f"{route.get('method', 'GET')}:{route.get('path', '/unknown')}"
        handler = route.get("handler", "main")
    else:
        # Non-route unit: use unit ID as identifier
        route_key = unit.get("id", "unknown")
        handler = route_key.split(":")[-1] if ":" in route_key else route_key

    # Language defaults to "code" for generic code block formatting
    language = "code"

    # Proactively enhance context if reviewer is enabled
    context_enhanced = False
    additional_files_added = []
    if context_reviewer and use_multifile:
        print(f"      Reviewing context for missing files...")
        enhanced_code, enhanced_files = context_reviewer.enhance_context(
            code=code,
            route=route_key,
            handler=handler,
            files_included=files_included
        )
        if len(enhanced_files) > len(files_included):
            additional_files_added = [f for f in enhanced_files if f not in files_included]
            code = enhanced_code
            files_included = enhanced_files
            context_enhanced = True
            print(f"      Added {len(additional_files_added)} files via LLM review")

    # Generate prompt - single unified prompt for all cases
    prompt = get_analysis_prompt(
        code=code,
        language=language,
        route=route_key,
        files_included=files_included,
        security_classification=security_classification,
        classification_reasoning=classification_reasoning,
        app_context=app_context
    )

    # Call the configured analyze-phase model with the threat-model system prompt.
    start_time = datetime.now()
    system_prompt = get_stage1_system_prompt(app_context=app_context)
    response = simple_text(binding, prompt, system=system_prompt)
    elapsed = (datetime.now() - start_time).total_seconds()

    # Parse response
    result = parse_response(response)

    # If parsing failed or verdict is missing, try JSON correction
    if result.get("verdict") in ("ERROR", None):
        # Create JSONCorrector internally if not provided (same pattern as other components).
        # JSONCorrector inherits the analyze binding — correction calls
        # go to the same provider+model as the failing call.
        if json_corrector is None:
            json_corrector = JSONCorrector(binding)
        corrected = json_corrector.attempt_correction(response)
        corrected = _normalize_result(corrected)
        if corrected.get("verdict") not in ("ERROR", None):
            # #215: the severity on a JSON-repaired record carries its own
            # provenance. ONLY a model-supplied enum value (what
            # _normalize_result stamps "model") becomes "corrected" — a
            # DERIVED stamp stays derived, or the restamp would defeat the
            # read-time re-derivation (wave round-2: the unconditional
            # "severity" in corrected fired on EVERY finding row).
            if (corrected.get("json_corrected")
                    and corrected.get("severity_source") == "model"):
                corrected["severity_source"] = "corrected"
            result = corrected

    result["route_key"] = route_key
    result["elapsed_seconds"] = elapsed
    result["prompt_length"] = len(prompt)
    result["response_length"] = len(response)
    result["code_length"] = len(code)
    result["files_included"] = files_included
    result["has_deps_inlined"] = has_deps_inlined
    result["context_reviewed"] = context_enhanced
    if additional_files_added:
        result["files_added_by_review"] = additional_files_added

    # Track security classification from agentic parser
    if security_classification:
        result["security_classification"] = security_classification
        result["classification_reasoning"] = classification_reasoning

    return result
