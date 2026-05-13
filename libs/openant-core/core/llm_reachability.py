"""
LLM-based reachability review stage.

A complementary, advisory pass over the **full, unfiltered** codebase that
uses a strong LLM (Opus by default) to surface reachability signals beyond
what the structural analysis catches:

- Likely entry points the structural pass missed (framework-specific
  handlers, plugin registrations, lambdas, message handlers, etc.).
- External content ingestion sites (HTTP request bodies, file/network
  reads, env/argv, IPC channels).
- Cross-process or async data flow indicators.

Pipeline ordering (managed by ``core/scanner.py``):

1. Parse with ``processing_level="all"`` so every unit is available.
2. ``analyze_reachability`` reviews all units and returns signals.
3. ``apply_signals`` promotes high-confidence ``entry_point`` signals by
   setting ``is_entry_point=True`` on the target unit.
4. The structural reachability filter re-runs with LLM-promoted entry
   points added as extra BFS seeds, yielding a dataset filtered to the
   user's requested ``processing_level`` but expanded by LLM findings.

Signals are **promote-only** — they never DEMOTE a unit that structural
analysis already kept. This matches the "complements, not replaces" intent
in issue #17.

Output:
- ``analyze_reachability(...)`` returns a list of ``ReachabilitySignal``
  dicts.
- ``apply_signals(dataset, signals)`` mutates the dataset in place so each
  unit gains an ``llm_reachability_signals`` field, and high-confidence
  ``entry_point`` signals set ``is_entry_point = True`` on the target unit.

Usage:
    from core.llm_reachability import analyze_reachability, apply_signals

    signals = analyze_reachability(dataset, app_context=app_ctx)
    apply_signals(dataset, signals)
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, asdict
from typing import Any, Callable, Dict, List, Optional


# Models — aligns with core/analyzer.py which uses "claude-opus-4-6" for Opus.
MODEL_PRIMARY = "claude-opus-4-6"
MODEL_SECONDARY = "claude-sonnet-4-20250514"


# Maximum number of units to send in a single LLM call. Larger batches save
# round trips but risk token-limit errors and degraded recall.
DEFAULT_BATCH_SIZE = 25

# Maximum bytes of code we send per unit. Trimmed to keep prompts tractable.
MAX_CODE_BYTES = 1500


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ReachabilitySignal:
    """A single LLM-emitted reachability signal for one unit.

    ``kind`` is one of:
      - ``entry_point`` — unit is itself a likely entry point.
      - ``external_input`` — unit receives external/untrusted input.
      - ``cross_process`` — unit participates in async / cross-process data flow.

    ``confidence`` is one of ``high``, ``medium``, ``low``.
    """

    unit_id: str
    kind: str
    confidence: str
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------


PROMPT_TEMPLATE = """You are a senior application-security engineer auditing
a codebase for REACHABILITY signals — places where untrusted input can enter
the system. A previous structural pass has already flagged some entry points
and reachable units; your job is to surface ADDITIONAL signals it may have
missed (framework-specific handlers, plugin/CLI registrations, message
queues, async tasks, file/network ingestion, env/argv, IPC, etc.).

Be conservative. Only emit a signal when the code clearly indicates one of:

  - "entry_point"      — this unit is itself a likely entry point reachable
                         by an external actor (HTTP/CLI/queue/stream handler,
                         scheduled task, framework lifecycle hook, etc.).
  - "external_input"   — this unit reads or accepts data from an external
                         source (request body, file, socket, env, argv, stdin,
                         child-process output, untrusted message, etc.).
  - "cross_process"    — this unit dispatches or receives data across async
                         / process / queue boundaries (so taint may flow in
                         or out via a path the static call-graph misses).

Confidence levels:
  - "high"   — the code unambiguously demonstrates the pattern.
  - "medium" — the pattern is present but partially obscured.
  - "low"    — only suggestive; emit only if you'd want a human reviewer.

Return STRICT JSON of the form:

  {{
    "signals": [
      {{"unit_id": "<id>", "kind": "entry_point|external_input|cross_process",
        "confidence": "high|medium|low", "reason": "<one short sentence>"}},
      ...
    ]
  }}

If no signals apply, return ``{{"signals": []}}``. Do NOT wrap the JSON in
markdown fences. Do NOT include any prose outside the JSON.

{app_context_block}

UNITS TO REVIEW (existing structural flags shown for context — your job is to
ADD signals beyond what those already capture):

{units_block}
"""


def _build_app_context_block(app_context: Optional[Dict[str, Any]]) -> str:
    """Render an optional app-context section for the prompt."""
    if not app_context:
        return "APPLICATION CONTEXT: (none provided)"
    try:
        ctx_json = json.dumps(app_context, indent=2, sort_keys=True)
    except (TypeError, ValueError):
        ctx_json = str(app_context)
    return f"APPLICATION CONTEXT:\n{ctx_json}"


def _trim_code(code: str) -> str:
    """Truncate a code blob so the batch fits in a reasonable prompt window."""
    if not code:
        return ""
    if len(code) <= MAX_CODE_BYTES:
        return code
    return code[:MAX_CODE_BYTES] + "\n# ...[truncated]"


def _unit_for_prompt(unit: Dict[str, Any]) -> Dict[str, Any]:
    """Project a unit into the minimal shape we send to the LLM."""
    code_blob = ""
    code = unit.get("code") or {}
    if isinstance(code, dict):
        code_blob = code.get("primary_code") or code.get("source") or ""
    elif isinstance(code, str):
        code_blob = code

    return {
        "unit_id": unit.get("id", ""),
        "unit_type": unit.get("unit_type", "function"),
        "is_entry_point": bool(unit.get("is_entry_point", False)),
        "reachable": unit.get("reachable"),
        "code": _trim_code(code_blob),
    }


def build_prompt(
    units: List[Dict[str, Any]],
    app_context: Optional[Dict[str, Any]] = None,
) -> str:
    """Assemble the LLM prompt for a batch of units."""
    app_block = _build_app_context_block(app_context)
    payload = [_unit_for_prompt(u) for u in units]
    units_block = json.dumps(payload, indent=2)
    return PROMPT_TEMPLATE.format(
        app_context_block=app_block,
        units_block=units_block,
    )


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------


_VALID_KINDS = {"entry_point", "external_input", "cross_process"}
_VALID_CONFIDENCES = {"high", "medium", "low"}


def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    """Best-effort JSON extraction from a model response.

    Strips common markdown fences and falls back to the first ``{...}``
    block in the text. Returns ``None`` if nothing valid is found.
    """
    if not text:
        return None
    cleaned = text.strip()

    # Strip ```json ... ``` or ``` ... ``` fences.
    fence = re.match(
        r"^```(?:json)?\s*(?P<body>.*?)\s*```\s*$",
        cleaned,
        re.DOTALL | re.IGNORECASE,
    )
    if fence:
        cleaned = fence.group("body").strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Fall back to the first balanced JSON object in the response.
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end > start:
        snippet = cleaned[start : end + 1]
        try:
            return json.loads(snippet)
        except json.JSONDecodeError:
            return None
    return None


def parse_response(
    response_text: str,
    valid_unit_ids: Optional[set] = None,
    on_error: Optional[Callable[[str], None]] = None,
) -> List[ReachabilitySignal]:
    """Parse a single LLM response into validated ``ReachabilitySignal``s.

    Malformed entries are skipped (not raised); the optional ``on_error``
    callback receives a one-line description per skipped item, useful for
    logging.
    """
    log = on_error or (lambda msg: print(f"[LLMReach] {msg}", file=sys.stderr))

    data = _extract_json(response_text)
    if not isinstance(data, dict):
        log("malformed response: not a JSON object — skipping batch")
        return []

    raw_signals = data.get("signals")
    if not isinstance(raw_signals, list):
        log("malformed response: 'signals' missing or not a list — skipping batch")
        return []

    out: List[ReachabilitySignal] = []
    for idx, item in enumerate(raw_signals):
        if not isinstance(item, dict):
            log(f"signal #{idx}: not an object — skipped")
            continue
        unit_id = item.get("unit_id")
        kind = item.get("kind")
        confidence = item.get("confidence")
        reason = item.get("reason", "")

        if not isinstance(unit_id, str) or not unit_id:
            log(f"signal #{idx}: missing unit_id — skipped")
            continue
        if kind not in _VALID_KINDS:
            log(f"signal #{idx}: invalid kind {kind!r} — skipped")
            continue
        if confidence not in _VALID_CONFIDENCES:
            log(f"signal #{idx}: invalid confidence {confidence!r} — skipped")
            continue
        if valid_unit_ids is not None and unit_id not in valid_unit_ids:
            log(f"signal #{idx}: unknown unit_id {unit_id!r} — skipped")
            continue

        out.append(
            ReachabilitySignal(
                unit_id=unit_id,
                kind=kind,
                confidence=confidence,
                reason=str(reason)[:500],
            )
        )
    return out


# ---------------------------------------------------------------------------
# Main entry points
# ---------------------------------------------------------------------------


def _chunk(items: List[Any], size: int) -> List[List[Any]]:
    """Split ``items`` into batches of ``size``.

    A non-positive ``size`` is treated as "everything in one batch" so callers
    that disable batching never hit a NameError or empty-output surprise.
    """
    if size <= 0:
        return [list(items)] if items else []
    return [items[i : i + size] for i in range(0, len(items), size)]


def analyze_reachability(
    dataset: Dict[str, Any],
    app_context: Optional[Dict[str, Any]] = None,
    client: Any = None,
    model: str = MODEL_PRIMARY,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_units: Optional[int] = None,
    on_error: Optional[Callable[[str], None]] = None,
) -> List[ReachabilitySignal]:
    """Run the LLM reachability review stage over a parsed dataset.

    Args:
        dataset: Parsed dataset with a ``units`` list, as produced by the
            parser stage. Units are expected to expose ``id``, ``code``, and
            optionally ``is_entry_point`` / ``reachable_from_entry``.
        app_context: Optional application context dict; included in the
            prompt to help the model reason about expected entry points
            (e.g. ``{"application_type": "web_app"}``).
        client: An object exposing ``analyze_sync(prompt, max_tokens=...,
            model=...)``. If omitted, an :class:`AnthropicClient` is
            instantiated lazily.
        model: Model id to use (defaults to Opus).
        batch_size: Units per LLM call.
        max_units: Optional cap on how many units to review.
        on_error: Optional callback for parse/validation issues.

    Returns:
        A flat list of :class:`ReachabilitySignal` for every unit the model
        flagged. Unknown unit ids and malformed entries are filtered out.
    """
    units = dataset.get("units") or []
    if max_units is not None and max_units >= 0:
        units = units[:max_units]
    if not units:
        return []

    if client is None:
        # Lazy import so unit tests can stub this out without an API key.
        from utilities.llm_client import AnthropicClient

        client = AnthropicClient(model=model)

    valid_ids = {u.get("id") for u in units if u.get("id")}

    signals: List[ReachabilitySignal] = []
    batches = _chunk(units, batch_size)
    for i, batch in enumerate(batches):
        prompt = build_prompt(batch, app_context=app_context)
        try:
            text = client.analyze_sync(prompt, max_tokens=4096, model=model)
        except Exception as exc:  # noqa: BLE001 — advisory stage; never crash pipeline
            msg = f"batch {i + 1}/{len(batches)} failed: {exc}"
            if on_error:
                on_error(msg)
            else:
                print(f"[LLMReach] {msg}", file=sys.stderr)
            continue

        parsed = parse_response(
            text, valid_unit_ids=valid_ids, on_error=on_error
        )
        signals.extend(parsed)

    return signals


# ---------------------------------------------------------------------------
# Signal application (promote-only)
# ---------------------------------------------------------------------------


# Confidences at or above this threshold promote ``entry_point`` signals to
# ``is_entry_point = True`` on the target unit.
_PROMOTE_ENTRY_POINT_AT = {"high"}


def apply_signals(
    dataset: Dict[str, Any],
    signals: List[ReachabilitySignal],
) -> Dict[str, int]:
    """Merge LLM signals back into ``dataset`` (in place, promote-only).

    For each unit referenced by a signal:
      - The signal is appended to a per-unit ``llm_reachability_signals`` list.
      - If the signal kind is ``entry_point`` AND its confidence is in
        :data:`_PROMOTE_ENTRY_POINT_AT`, the unit's ``is_entry_point`` field
        is set to ``True`` (never set back to ``False``).

    Crucially, this never DEMOTES a unit. ``is_entry_point=True`` set by the
    structural pass remains true regardless of what the LLM said.

    Returns a small summary dict::

        {
            "signals_applied": <n>,
            "entry_points_promoted": <n>,
            "units_touched": <n>,
        }
    """
    units = dataset.get("units") or []
    by_id = {u.get("id"): u for u in units if u.get("id")}

    promoted = 0
    touched: set = set()
    applied = 0

    for sig in signals:
        unit = by_id.get(sig.unit_id)
        if unit is None:
            continue

        existing = unit.setdefault("llm_reachability_signals", [])
        existing.append(sig.to_dict())
        applied += 1
        touched.add(sig.unit_id)

        if (
            sig.kind == "entry_point"
            and sig.confidence in _PROMOTE_ENTRY_POINT_AT
            and not unit.get("is_entry_point", False)
        ):
            unit["is_entry_point"] = True
            unit["entry_point_reason"] = f"llm_reachability: {sig.reason}"
            promoted += 1

    return {
        "signals_applied": applied,
        "entry_points_promoted": promoted,
        "units_touched": len(touched),
    }


def signals_to_json(signals: List[ReachabilitySignal]) -> List[Dict[str, Any]]:
    """Serialize a list of signals for JSON persistence."""
    return [s.to_dict() for s in signals]
