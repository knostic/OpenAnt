"""Shared input budget for the regex-based call-detection scanners (Rust macro bodies,
Zig fallback function bodies).

Those scanners run ``re.finditer`` over a whole macro/function token-text. On a long
``::``/``.`` identifier chain with no trailing ``(``, ``finditer`` restarts at every
interior position and re-scans the chain forward — O(n^2) on adversarial input (a
single ~575KB macro body burns ~30 min of CPU). Possessive/atomic quantifiers do NOT
fix this (they stop intra-match backtracking, not the per-position restart) and, on
Rust's scoped-turbofish branch, change the matched call set (a reachability regression).

DESIGN DECISION (2026-08-15, user-chosen, "if it's more than a second it's not a good
balance"): the call-detection regex is left UNCHANGED and the input length fed to it is
bounded to MAX_MACRO_SCAN_CHARS. The cap is deliberately LOW (8192 → ~0.35s worst-case
adversarial body, safely under the 1s DoS budget). Because the regex is quadratic, the
cap CANNOT be raised to cover large real bodies while staying under 1s (16KB is already
~1.4s), so DoS-safety is prioritised over coverage here.

The truncation is therefore a real, disclosed reachability tradeoff — a body over the cap
loses the calls past the cut. To keep that loss NON-SILENT (a scanner that quietly
analyses less than it claims is the exact failure mode this project designs against),
``bound_macro_scan_text`` returns a ``truncated`` flag that the builders surface in the
call-graph output as ``scan_truncated`` — a machine-readable record for future
consumers (no current reader consumes it yet — the over-seed behaviour is a tracked
follow-up in issue #288). This converts a silent false-negative into a flagged,
known-incomplete scan.

RESIDUAL (deferred): the truly coverage-safe fix is overlapped-window chunking (O(n), zero
call loss except a token longer than one window, which IS the attack). It is NOT
implemented here — see issue #288. Under the current low-cap design an
attacker can still pad a macro body past 8192 chars to FORCE a real call to be dropped
(a reachability-evasion primitive), now at least flagged via ``scan_truncated``. The limit
is measured in Python string length (Unicode code points), not raw bytes.
"""
from __future__ import annotations

import sys
from typing import Tuple

MAX_MACRO_SCAN_CHARS = 8192  # ~0.35s worst-case for the quadratic Rust regex; < the 1s DoS budget.
MAX_MACRO_SCAN_BYTES = MAX_MACRO_SCAN_CHARS  # legacy alias (unit is code points, not bytes)


def bound_macro_scan_text(text: str, context: str = "", *,
                          limit: int = MAX_MACRO_SCAN_CHARS) -> Tuple[str, bool]:
    """Return ``(bounded_text, truncated)``.

    ``bounded_text`` is ``text`` unchanged if within ``limit``, else its first ``limit``
    chars. ``truncated`` is True iff the input exceeded ``limit`` (callers record it into
    the call-graph output as ``scan_truncated`` — recorded for future consumers; no
    current reader — issue #288 tracks the follow-up). A loud stderr warning is still
    emitted on truncation.
    """
    if len(text) <= limit:
        return text, False
    where = f" ({context})" if context else ""
    print(
        f"[scan-budget] WARNING: call-scan input{where} truncated "
        f"{len(text)} -> {limit} chars; calls past the cut are not extracted "
        f"(coverage gap, flagged as scan_truncated). This bounds a regex-ReDoS DoS vector.",
        file=sys.stderr,
    )
    return text[:limit], True
