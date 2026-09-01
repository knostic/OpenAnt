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
3. ``apply_signals`` promotes ``entry_point`` signals whose confidence is
   in the promote set (``OPENANT_PROMOTE_ENTRY_POINT_AT``, default
   ``{high}`` — #345: configurable per run) by setting
   ``is_entry_point=True`` on the target unit.
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
  unit gains an ``llm_reachability_signals`` field, and ``entry_point``
  signals in the promote set set ``is_entry_point = True`` on the target unit
  (the set is configurable — see OPENANT_PROMOTE_ENTRY_POINT_AT).

Usage:
    from core.llm_reachability import analyze_reachability, apply_signals

    signals = analyze_reachability(dataset, app_context=app_ctx)
    apply_signals(dataset, signals)
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from utilities.llm import PhaseBinding


# Maximum number of units to send in a single LLM call. Larger batches save
# round trips but risk token-limit errors and degraded recall.
DEFAULT_BATCH_SIZE = 25

# Default maximum bytes of code we send per unit. Trimmed to keep prompts
# tractable. Callers can override via the ``max_code_bytes`` parameter on
# :func:`analyze_reachability` (exposed as ``--llm-reachability-max-code-bytes``
# on ``openant scan``); higher values catch entry-point indicators past the
# default cutoff in long handlers / generated code, at proportional cost.
DEFAULT_MAX_CODE_BYTES = 1500
# Backward-compatible alias for any external caller importing the old name.
MAX_CODE_BYTES = DEFAULT_MAX_CODE_BYTES


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


def _trim_code(code: str, max_bytes: int = DEFAULT_MAX_CODE_BYTES) -> str:
    """Truncate a code blob so the batch fits in a reasonable prompt window."""
    if not code:
        return ""
    if len(code) <= max_bytes:
        return code
    return code[:max_bytes] + "\n# ...[truncated]"


def _unit_for_prompt(
    unit: Dict[str, Any],
    max_code_bytes: int = DEFAULT_MAX_CODE_BYTES,
) -> Dict[str, Any]:
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
        "code": _trim_code(code_blob, max_bytes=max_code_bytes),
    }


def build_prompt(
    units: List[Dict[str, Any]],
    app_context: Optional[Dict[str, Any]] = None,
    max_code_bytes: int = DEFAULT_MAX_CODE_BYTES,
) -> str:
    """Assemble the LLM prompt for a batch of units."""
    app_block = _build_app_context_block(app_context)
    payload = [_unit_for_prompt(u, max_code_bytes=max_code_bytes) for u in units]
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


def _strip_fence(text: str) -> str:
    """Strip a leading ```json ... ``` (or bare ``` ... ```) fence."""
    fence = re.match(
        r"^```(?:json)?\s*(?P<body>.*?)\s*```\s*$",
        text,
        re.DOTALL | re.IGNORECASE,
    )
    if fence:
        return fence.group("body").strip()
    return text


def _classify_malformed(response_text: str) -> str:
    """#294: name the failure SHAPE.

    Six materially different failures — a bare array (the model answered,
    wrong shape), a truncation (budget/transport), a prose refusal (policy),
    an empty completion (adapter empty-content), fenced variants, and valid
    JSON of a non-object type — previously produced one byte-identical log
    line, so a completed run could not be diagnosed even in principle.
    """
    if not response_text or not response_text.strip():
        return "empty response (no content)"
    cleaned = _strip_fence(response_text.strip())
    try:
        value = json.loads(cleaned)
    except json.JSONDecodeError:
        # Heuristic with a known blind spot (wave catch): prose that merely
        # MENTIONS a brace ("I can't return `{}` for this") lands here as
        # "truncated" — a diagnostic label only, never behavior-affecting.
        if "{" in cleaned or "[" in cleaned:
            return "truncated or unbalanced JSON"
        return "non-JSON text (prose/refusal)"
    if isinstance(value, list):
        return "valid JSON array, expected an object"
    return f"valid JSON of wrong type {type(value).__name__}, expected an object"


def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    """Best-effort JSON extraction from a model response.

    Strips common markdown fences and falls back to the first ``{...}``
    block in the text. Returns ``None`` if nothing valid is found.
    """
    if not text:
        return None
    cleaned = _strip_fence(text.strip())

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
    batch_label: Optional[str] = None,
    on_batch_drop: Optional[Callable[[], None]] = None,
) -> List[ReachabilitySignal]:
    """Parse a single LLM response into validated ``ReachabilitySignal``s.

    Malformed entries are skipped (not raised); the optional ``on_error``
    callback receives a one-line description per skipped item, useful for
    logging.

    #294: a batch-level drop names its failure SHAPE (see
    :func:`_classify_malformed`), carries the caller-supplied
    ``batch_label`` and a truncated raw snippet (the evidence — the raw
    response was previously discarded entirely), and fires ``on_batch_drop``
    once so the caller can count the loss.
    """
    log = on_error or (lambda msg: print(f"[LLMReach] {msg}", file=sys.stderr))
    label = f" [{batch_label}]" if batch_label else ""
    # None-safe: the docstring promises malformed entries are skipped, not
    # raised — a None response_text must classify, not crash (wave catch).
    snippet = f" raw[:200]={(response_text or '')[:200]!r}"

    data = _extract_json(response_text)
    if not isinstance(data, dict):
        shape = _classify_malformed(response_text)
        log(f"malformed response: {shape} — skipping batch{label};{snippet}")
        if on_batch_drop is not None:
            on_batch_drop()
        return []

    raw_signals = data.get("signals")
    if not isinstance(raw_signals, list):
        log(f"malformed response: 'signals' missing or not a list "
            f"(got {type(raw_signals).__name__}) — skipping batch{label};{snippet}")
        if on_batch_drop is not None:
            on_batch_drop()
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
    binding: Optional["PhaseBinding"] = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_code_bytes: int = DEFAULT_MAX_CODE_BYTES,
    max_units: Optional[int] = None,
    on_error: Optional[Callable[[str], None]] = None,
    stats: Optional[Dict[str, int]] = None,
) -> List[ReachabilitySignal]:
    """Run the LLM reachability review stage over a parsed dataset.

    Args:
        dataset: Parsed dataset with a ``units`` list, as produced by the
            parser stage. Units are expected to expose ``id``, ``code``, and
            optionally ``is_entry_point`` / ``reachable_from_entry``.
        app_context: Optional application context dict; included in the
            prompt to help the model reason about expected entry points
            (e.g. ``{"application_type": "web_app"}``).
        binding: :class:`PhaseBinding` carrying the adapter+model the
            ``llm_reach`` phase should use. When omitted, a binding is
            resolved from the active config file — useful for ad-hoc
            scripts and tests; pipeline callers should always pass the
            binding their scanner built so any ``--llm-config`` override
            is honored.
        batch_size: Units per LLM call.
        max_code_bytes: Per-unit code-blob truncation limit. Higher values
            give the LLM more context (better recall on long handlers /
            generated code) at proportional Opus cost. Default 1500.
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

    if binding is None:
        # Self-contained fallback for callers that don't have a
        # registry yet (standalone scripts, tests that didn't bother
        # to pass one). Uses the same resolution path the scanner
        # uses, so behavior matches a real scan — including the
        # init-time probe so a misconfigured llm-config fails loud.
        from utilities.llm import (
            build_phase_registry,
            load_config_file,
            probe_registry_or_raise,
            resolve_llm_config,
        )

        cf = load_config_file()
        llm_config = resolve_llm_config(cf, None)
        registry = build_phase_registry(cf, llm_config)
        probe_registry_or_raise(registry)
        binding = registry.get("llm_reach")

    valid_ids = {u.get("id") for u in units if u.get("id")}

    # Lazy import so this module stays usable when callers explicitly
    # provide a binding and never want the registry fallback above.
    from utilities.llm import LLMAuthError, simple_text

    signals: List[ReachabilitySignal] = []
    batches = _chunk(units, batch_size)
    # #294: count parse-level batch drops and the units they carried —
    # a dropped batch is a coverage gap in the most consequential direction
    # (this stage decides which units are analyzed at all), and previously
    # nothing counted it: the step report said units_reviewed=N for a run
    # in which some units were never reviewed.
    dropped_batches = 0
    units_not_reviewed = 0
    for i, batch in enumerate(batches):
        prompt = build_prompt(
            batch, app_context=app_context, max_code_bytes=max_code_bytes
        )
        try:
            text = simple_text(binding, prompt, max_tokens=4096)
        except LLMAuthError:
            # Auth failures are fatal and recur on every batch — surface
            # them instead of burying them as a per-batch "failed" line,
            # so the caller can stop and tell the user the key is bad.
            raise
        except Exception as exc:  # noqa: BLE001 — advisory stage; never crash pipeline
            msg = f"batch {i + 1}/{len(batches)} failed: {exc}"
            if on_error:
                on_error(msg)
            else:
                print(f"[LLMReach] {msg}", file=sys.stderr)
            continue

        def _count_drop(batch=batch):
            nonlocal dropped_batches, units_not_reviewed
            dropped_batches += 1
            units_not_reviewed += len(batch)

        first = batch[0].get("id", "?") if batch else "?"
        last = batch[-1].get("id", "?") if batch else "?"
        parsed = parse_response(
            text, valid_unit_ids=valid_ids, on_error=on_error,
            batch_label=f"batch {i + 1}/{len(batches)}, units {first}..{last}",
            on_batch_drop=_count_drop,
        )
        signals.extend(parsed)

    if stats is not None:
        stats["batches_dropped"] = dropped_batches
        stats["units_not_reviewed"] = units_not_reviewed

    return signals


# ---------------------------------------------------------------------------
# Signal application (promote-only)
# ---------------------------------------------------------------------------


# The confidence tiers that promote an ``entry_point`` signal to
# ``is_entry_point = True`` on the target unit. This is a SET-MEMBERSHIP
# test, not an "at or above" ordering — no ordering over high/medium/low
# exists in this module, and the earlier "at or above" comment described
# semantics the code never implemented (it worked only because the set
# had one element) — #345.
#
# Configurable per run (#345): an operator can trade recall for cost —
# promotion is promote-only and never demotes, so a wrong promotion costs
# analysis budget while a missing one silently drops a unit and everything
# reachable only through it. OPENANT_PROMOTE_ENTRY_POINT_AT is a
# comma-separated subset of high/medium/low, read at apply time; invalid or
# empty content falls back to the shipped default WITH a stderr warning —
# a calibration knob must never crash the scan.
#
# The DEFAULT is the deliberate PR #50 calibration, pinned by
# test_medium_confidence_does_not_promote: medium measured 48% precision
# on the one audit #345 reports (n=25, 95% CI [30,67], an internal run the
# issue flags as not reproducible from this repository — widen only after
# the second-corpus reproduction it names), and low 0.0%.
_PROMOTE_ENTRY_POINT_AT_DEFAULT = frozenset({"high"})
# the tier vocabulary _VALID_CONFIDENCES already declares (parse validates
# incoming signals against it) — a second hand-rolled copy would drift: a
# tier added there but not here makes an operator's whole list discard
# (wave r1 opus), narrowing promotion to the default: the under-seeding
# direction.
_PROMOTE_TIERS = frozenset(_VALID_CONFIDENCES)
_ENV_PROMOTE_ENTRY_POINT_AT = "OPENANT_PROMOTE_ENTRY_POINT_AT"


def _promote_entry_point_at() -> frozenset:
    """The tiers that promote, after resolving the env override (#345)."""
    raw = os.environ.get(_ENV_PROMOTE_ENTRY_POINT_AT)
    if raw is None or raw == "":
        # blank-but-SET (OPENANT_PROMOTE_ENTRY_POINT_AT= — the CI-template
        # shape, `=$WIDEN` with WIDEN unset) WARNED, not silent: the operator
        # believes the widening is live while promotion silently narrows to
        # the default — units dropped from analysis with zero signal (wave
        # r1, sonnet+opus).
        if raw == "":
            print(
                f"[LLMReach] {_ENV_PROMOTE_ENTRY_POINT_AT} is set but empty; "
                f"falling back to the shipped default "
                f"{sorted(_PROMOTE_ENTRY_POINT_AT_DEFAULT)}",
                file=sys.stderr,
            )
        return _PROMOTE_ENTRY_POINT_AT_DEFAULT
    wanted = {t.strip().lower() for t in raw.split(",") if t.strip()}
    if not wanted or (wanted - _PROMOTE_TIERS):
        print(
            f"[LLMReach] {_ENV_PROMOTE_ENTRY_POINT_AT}={raw!r}: expected "
            f"comma-separated tiers from {sorted(_PROMOTE_TIERS)}; falling "
            "back to the shipped default "
            f"{sorted(_PROMOTE_ENTRY_POINT_AT_DEFAULT)}",
            file=sys.stderr,
        )
        return _PROMOTE_ENTRY_POINT_AT_DEFAULT
    return frozenset(wanted)


def apply_signals(
    dataset: Dict[str, Any],
    signals: List[ReachabilitySignal],
) -> Dict[str, int]:
    """Merge LLM signals back into ``dataset`` (in place, promote-only).

    For each unit referenced by a signal:
      - The signal is appended to a per-unit ``llm_reachability_signals`` list.
      - If the signal kind is ``entry_point`` AND its confidence is in the
        promote set (:func:`_promote_entry_point_at` — the shipped default
        ``{high}``, configurable via OPENANT_PROMOTE_ENTRY_POINT_AT), the
        unit's ``is_entry_point`` field is set to ``True`` (never set back
        to ``False``).

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
    promote_at = _promote_entry_point_at()

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
            and sig.confidence in promote_at
            and not unit.get("is_entry_point", False)
        ):
            unit["is_entry_point"] = True
            unit["entry_point_reason"] = f"llm_reachability: {sig.reason}"
            promoted += 1

    return {
        "signals_applied": applied,
        "entry_points_promoted": promoted,
        "units_touched": len(touched),
        # #345 (wave r1 opus): the resolved set is part of the run's
        # provenance — two scans under different sets produce different
        # promotions with byte-identical step reports otherwise.
        "promote_set": sorted(promote_at),
    }


def signals_to_json(signals: List[ReachabilitySignal]) -> List[Dict[str, Any]]:
    """Serialize a list of signals for JSON persistence."""
    return [s.to_dict() for s in signals]
