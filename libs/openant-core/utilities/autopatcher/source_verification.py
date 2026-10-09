"""Evidence Sufficiency Gate (Phase 1) — a deterministic Trust Signal.

Classifies whether the generated patch's edited content was actually
confirmed to exist in the real repository, using ONLY data
`diff_hunk_repair.repair_hunk_headers` already computes as a side effect of
Candidate 1 (content-based hunk relocation) — no new git calls, no new LLM
calls, no new repository parsing.

Scope (explicit product decision): this module produces a signal only. It
is deliberately NOT read by `pipeline._build_recommendation_v1` (the
Recommendation Policy). Phase 1 is observability-only — expose the signal,
surface it in the Trust Report, expose it through relocation telemetry, and
make it available as one more entry in the Trust Signals dict Recommendation
Policy could someday read — but do not yet decide how, or whether, it
should affect the final recommendation. That decision is deferred to a
later phase, once real evaluation runs show how often this signal fires,
whether it correlates with poor patches, and whether it produces false
positives. Do not wire this into `_build_recommendation_v1` without a
separate, explicit decision to do so.

Value vocabulary, in the same three-value + "unknown" shape every other
signal in `pipeline._compute_trust_signals` already uses (never a positive
inference from missing evidence — see that function's I1-I6 invariants):

    "Confirmed"             — at least one hunk was actually checked, and
                               every checked hunk's old-side content matched
                               the repository uniquely (`unique_match`).
    "Position Unconfirmed" — at least one hunk's old-side content exists in
                               the repository but not uniquely (`ambiguous`),
                               and none are outright absent. The content is
                               real; only its single location is unclear.
    "Unverified"            — at least one hunk's old-side content could not
                               be found anywhere in the repository
                               (`no_match`) — the direct signal that Patch
                               Generation edited text it never had verified
                               source for. Takes priority over "Position
                               Unconfirmed" when both occur in the same
                               patch.
    "Not Verified"          — no hunk could be checked at all: no
                               `repo_root`, every hunk was skipped for a
                               benign structural reason (new-file creation,
                               pure-insertion hunk with no old-side anchors),
                               or the patch had no hunks at all. This is
                               "we don't know", never treated as equivalent
                               to, or milder than, "Confirmed".
"""

from __future__ import annotations


_ICONS = {
    "Confirmed": "✓",
    "Position Unconfirmed": "⚠",
    "Unverified": "✗",
    "Not Verified": "?",
}


def _label(value: str) -> str:
    return f"{_ICONS.get(value, '')} {value}".strip()


def _files_note(records: "list", noun: str) -> str:
    files = sorted({getattr(r, "file", "") for r in records if getattr(r, "file", "")})
    shown = ", ".join(files[:3])
    extra = f" (+{len(files) - 3} more)" if len(files) > 3 else ""
    return f"{len(records)} hunk(s) {noun}: {shown}{extra}"


def classify_source_verification(relocations: "list | None") -> dict:
    """Classify a patch's per-hunk relocation records into one Trust-signal-
    shaped dict: `{"value", "label", "notes"}` — the same shape every signal
    in `pipeline._compute_trust_signals` already returns.

    `relocations` is `diff_hunk_repair.RepairResult.relocations` (a list of
    `HunkRelocationRecord`, or the structurally-identical
    `relocation_telemetry.HunkRelocationTelemetry`) — per-hunk telemetry
    Candidate 1 already produces as a side effect of its own, already-
    running repair pass. Never raises: a missing, empty, or malformed input
    degrades to "Not Verified" rather than crashing or reporting a false
    "Confirmed".
    """
    try:
        records = list(relocations or [])
    except TypeError:
        records = []

    no_match = [r for r in records if getattr(r, "relocation_reason", None) == "no_match"]
    ambiguous = [r for r in records if getattr(r, "relocation_reason", None) == "ambiguous"]
    checked = [r for r in records if getattr(r, "relocation_attempted", False)]

    if no_match:
        value = "Unverified"
        notes = _files_note(no_match, "edit content not found anywhere in the repository")
    elif ambiguous:
        value = "Position Unconfirmed"
        notes = _files_note(ambiguous, "matched repository content in more than one place")
    elif checked:
        value = "Confirmed"
        notes = f"{len(checked)} hunk(s) matched the repository uniquely"
    else:
        value = "Not Verified"
        notes = (
            "No hunk could be checked against the repository (no repo_root, "
            "or every hunk was a new-file/insertion-only change)"
        )

    return {"value": value, "label": _label(value), "notes": notes}
