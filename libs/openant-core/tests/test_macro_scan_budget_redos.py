"""FIX1 RED: the Rust and Zig call-graph regex scanners run finditer over a whole
macro-body / function-body token text. On a long dotted/scoped identifier chain with
no trailing '(', finditer restarts at every interior position and re-scans the chain
forward — O(n^2) (measured: rust ~5.5s @32KB, zig ~4.5s @40KB). Possessive quantifiers
do NOT fix it (they stop intra-match backtracking, not finditer's per-position restart)
AND regress the match set on rust's scoped-turbofish branch (a::b::<T>( -> b). So the
edge-preserving fix is a bounded per-body scan input (the exact regex is UNCHANGED, so
zero call-graph edge change), truncating only pathological bodies with a logged gap.

RED pre-fix: utilities.scan_budget.bound_macro_scan_text does not exist.
"""
import re
from pathlib import Path
import time


def test_bound_helper_exists_and_caps():
    from utilities.scan_budget import bound_macro_scan_text, MAX_MACRO_SCAN_BYTES
    huge = "a" + ".a" * 300_000            # ~600KB single body
    bounded, trunc = bound_macro_scan_text(huge, context="test")
    assert trunc is True  # machine-readable flag set on truncation
    assert len(bounded) <= MAX_MACRO_SCAN_BYTES
    # realistic bodies (under the cap) pass through UNCHANGED -> zero coverage/edge loss
    small = "vec![a::b::c(), foo.bar()]"
    small_out, small_trunc = bound_macro_scan_text(small, context="test")
    assert small_out == small and small_trunc is False


def test_over_cap_truncation_loses_calls_past_the_cut_KNOWN_RESIDUAL():
    """HONEST residual (sol-flagged): edge-preservation holds ONLY for bodies <= cap.
    A call pushed past the cut by large leading content IS lost — a bounded, disclosed
    coverage-gap chosen over an unbounded regex DoS. This test documents that behavior
    so the tradeoff is explicit, not an accidental silent FN."""
    import re
    from utilities.scan_budget import bound_macro_scan_text, MAX_MACRO_SCAN_BYTES
    RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    body = (" " * MAX_MACRO_SCAN_BYTES) + "security_sink()"
    before = [m.group(1) for m in RE.finditer(body)]
    after = [m.group(1) for m in RE.finditer(bound_macro_scan_text(body, context="test")[0])]
    assert "security_sink" in before
    assert "security_sink" not in after   # documented loss past the cap


def test_bounded_scan_is_fast_where_raw_is_quadratic():
    from utilities.scan_budget import bound_macro_scan_text
    RUST_RE = re.compile(
        r"\b((?:[A-Za-z_][A-Za-z0-9_]*::)+[A-Za-z_][A-Za-z0-9_]*"
        r"|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s*(?:::<[^>]*>)?\s*\(")
    adversarial = "a" + ".a" * 300_000      # the ReDoS payload, no trailing '('
    t = time.time()
    list(RUST_RE.finditer(bound_macro_scan_text(adversarial, context="test")[0]))
    bounded_dt = time.time() - t
    # The bound must keep this near-instant; the UNBOUNDED regex on this payload
    # ReDoS-hangs for minutes. A tight sub-second wall-clock flakes on loaded CI
    # runners (observed 1.03-1.20s on macos/windows) without catching a real
    # regression any better than a generous ceiling that a true ReDoS blows past.
    assert bounded_dt < 5.0, f"bounded scan still slow: {bounded_dt:.2f}s (bound not applied?)"


def test_rust_and_zig_regex_unchanged():
    """Edge-preservation guard: the fix must NOT alter either call-detection regex
    (altering it changes the call graph = reachability regression). Verified by source
    text (parsers need tree_sitter, unavailable in unit-test env). The exact OLD
    patterns must be present, and NO possessive quantifier (++/*+) may be introduced —
    possessive both fails to fix the DoS and regresses rust's scoped-turbofish match."""
    import os
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rust = Path(os.path.join(here, "parsers/rust/call_graph_builder.py")).read_text(encoding="utf-8")
    zig = Path(os.path.join(here, "parsers/zig/call_graph_builder.py")).read_text(encoding="utf-8")
    assert r"(?:[A-Za-z_][A-Za-z0-9_]*::)+[A-Za-z_][A-Za-z0-9_]*" in rust
    assert r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*" in rust
    assert r"[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*" in zig
    # no possessive quantifier introduced into either scanner regex
    for src, name in ((rust, "rust"), (zig, "zig")):
        assert "++" not in src and "*+" not in src, f"{name}: possessive quantifier introduced (regresses/insufficient)"
