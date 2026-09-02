"""F2 (linear literal stripper): `_blank_rust_literals` replaces the O(n^2)
`_RUST_STR_LITERAL_RE.sub(" ", text)` in `_scan_macro_body`. It must be:

  1. BYTE-IDENTICAL to the regex it replaces (any divergence is a change to the
     macro-body call set = a reachability/call-graph change). Asserted over hand
     fixtures + real-code windows + a large seeded fuzz corpus. `_RUST_STR_LITERAL_RE`
     is retained deliberately as the executable oracle for this equivalence.
  2. LINEAR — the regex ReDoS'd on an unterminated-`r#"` flood (measured multi-second);
     the stripper is a single forward cursor and stays sub-second on adversarial input.
  3. RECALL-PRESERVING — stripping BEFORE the length budget collapses a large string
     literal to one space, so a real trailing call is no longer pushed past the 8 KB cap.
     This is the regression the earlier bound-then-strip ordering introduced (a VULNERABLE
     callee silently dropped from the graph = an unreachable false-negative).
"""
import glob
import os
import random
import time

from parsers.rust.call_graph_builder import (
    _MACRO_CALL_RE,
    _RUST_STR_LITERAL_RE,
    _blank_rust_literals,
)


def _old(s):
    return _RUST_STR_LITERAL_RE.sub(" ", s)


_FIXTURES = [
    'println!("hello {}", name)',
    'panic!("call init() first")',
    'assert_eq!(actual, vec![Token::new(0, foo()), bar()])',
    'let c = \'a\'; foo()',
    "fn f<'a>(x: &'a str) { g() }",                 # lifetimes must NOT blank
    "'static lifetime and call h()",
    'r#"has "# inside"#',                            # raw one-hash w/ embedded quote-hash
    r'"esc \" quote" then call()',                   # escaped quote
    "'\\n' '\\\\' '\\'' newline_call()",             # escaped char literals
    "match x { 'A'..='Z' => up() }",                 # char ranges
    'a::b::<T>(); x.y.z()',                           # turbofish + dotted
    '"" empty() r"" q() r#""# raw_empty()',           # empty literals of each kind
    "label: 'outer loop { break 'outer; call() }",
    'unterminated "string with call( no close',       # malformed: unterminated normal
    'unterminated r#"raw with call( no close',        # malformed: unterminated raw-hash
    '"a\\\nb" trailing()',                            # backslash-newline: \\. must NOT match
    'vec![\'a\', \'b\', \'c\']',
    'no_literals_at_all(foo, bar, baz)',
    '',
]


def test_differential_on_fixtures():
    for s in _FIXTURES:
        assert _blank_rust_literals(s) == _old(s), repr(s)


def test_differential_on_real_source_windows():
    here = os.path.dirname(os.path.abspath(__file__))
    files = glob.glob(os.path.join(here, "**", "*.py"), recursive=True)
    assert files, "no corpus files found"
    for fp in files:
        txt = open(fp, encoding="utf-8", errors="ignore").read()
        for chunk in [txt] + [txt[k:k + 500] for k in range(0, len(txt), 500)]:
            assert _blank_rust_literals(chunk) == _old(chunk), f"{os.path.basename(fp)}"


def test_differential_seeded_fuzz():
    rng = random.Random(0xA17)
    alph = list('abcXYZ_0129 ()[]{}.:;,<>&*=+-/\n\t') + \
        ['"', "'", 'r"', 'r#"', '"#', '\\', '::', '\\"', "\\'", '\\n']
    for _ in range(50000):
        s = ''.join(rng.choice(alph) for _ in range(rng.randint(0, 40)))
        assert _blank_rust_literals(s) == _old(s), repr(s)


def test_stripper_is_linear_not_redos():
    # Several adversarial flood shapes must all stay well under 1s. The
    # repeated-`r#"` flood (no closing `"#`) is the one an earlier cut got wrong:
    # find('"#') scanned to EOF from ~n/3 positions -> O(n^2) (~1.8s at 240KB).
    # The monotonic short-circuit in _blank_rust_literals restores O(n).
    floods = [
        'r#"' * 200_000,            # repeated r#" (the regression shape) ~600KB
        'r"' * 200_000,             # repeated r"
        'r#"' + 'a"' * 100_000,     # single r#" prefix + quote flood
        '"' + 'a' * 200_000,        # unterminated normal string
        '"' + '\\a' * 100_000,      # backslash flood
        "'" * 200_000,              # repeated char-quote
        'r#"a' * 100_000,           # interleaved r#" + char
    ]
    for payload in floods:
        t = time.time()
        _blank_rust_literals(payload)
        dt = time.time() - t
        assert dt < 1.0, f"slow ({dt:.2f}s) on {payload[:8]!r}... len={len(payload)}"


def test_stripper_scaling_is_subquadratic():
    """Doubling the input must not ~quadruple the time (that's O(n^2)). Guards
    against a future edit reintroducing a find()-to-EOF-per-position regression."""
    def _time(payload):
        t = time.time(); _blank_rust_literals(payload); return time.time() - t
    small = _time('r#"' * 100_000)
    big = _time('r#"' * 400_000)          # 4x the input
    # linear -> ~4x; quadratic -> ~16x. Assert well under quadratic. Guard the
    # denominator against a near-zero small time on a fast machine.
    if small > 0.005:
        assert big / small < 8.0, f"scaling {big/small:.1f}x for 4x input looks quadratic"


def _calls(t):
    return [m.group(1) for m in _MACRO_CALL_RE.finditer(t)]


def test_recall_call_after_large_literal_is_preserved():
    """RED against the committed bound-first ordering: a call AFTER a >8KB string
    literal was dropped because the budget truncated the still-unstripped literal.
    Strip-first collapses the literal to one space, so both calls survive."""
    from utilities.scan_budget import bound_macro_scan_text
    body = 'foo(), "%s", bar()' % ("x" * 9016)
    stripped = _blank_rust_literals(body)
    bounded, truncated = bound_macro_scan_text(stripped, context="t")
    assert truncated is False
    assert _calls(bounded) == ["foo", "bar"]
