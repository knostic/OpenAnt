"""#673 — PR #242's depth-0 JSON scanner reaches its eight sibling modules.

PR #242 rewrote ONE of ten naive-slice sites (``core.analysis_core.parse_response``)
and its own body disclosed the residual: "Also unchanged: 7 sibling LLM-response
parsers still use the naive ``rfind("}")`` span."  There were nine such sites in
eight modules.  A brace anywhere in the model's surrounding prose made the
first-``{``-to-last-``}`` slice invalid, so the reply's JSON object was not
recovered on the deterministic path: five sites then paid for a JSONCorrector
round-trip, ``llm_reachability`` dropped the batch, ``threat_model_agent``
raised, and one ``context_corrector`` helper returned a silent ``None``.

These tests drive all nine sites, not the helper alone — a helper that nobody
calls would pass a unit test and ship the defect.
"""

import json
import re
from pathlib import Path

import pytest

# utilities.json_extract is the module this issue CREATES, so the import is
# deferred into the tests that need the helper directly: the three tests that
# drive the nine call sites and the propagation guard must still collect — and
# FAIL on the defect — against a tree where the shared home does not yet exist.

# The reply the model actually sends; the object is identical in every shape.
_OBJ = '{"verdict": "VULNERABLE", "finding": "vulnerable"}'

#: The two shapes from the issue's own executed repro that the naive slice
#: discards (``find22_repro.py``: ``naive=None  fixed=VULNERABLE``).
BRACE_IN_PROSE = [
    pytest.param("The dict {x} is unchecked.\n" + _OBJ, id="brace-before-the-json"),
    pytest.param(_OBJ + "\nNote: see {y}.", id="trailing-prose-with-a-brace"),
    pytest.param(
        "```rust\nfn f() { if x == 0 { return; } }\n```\n" + _OBJ,
        id="code-fence-with-braces-before",
    ),
]

#: Shapes the naive slice already handled.  They must keep working — a
#: robustness fix that drops a reply which parses today is a regression.
ALREADY_WORKING = [
    pytest.param(_OBJ, id="pure-json"),
    pytest.param("My analysis follows.\n" + _OBJ, id="prose-no-brace"),
    pytest.param('{"verdict": "VULNERABLE", "finding": "see } here"}', id="brace-in-a-string"),
]


# --------------------------------------------------------------------------
# the nine call sites
# --------------------------------------------------------------------------
def _no_paid_corrector(monkeypatch):
    """Disable every site's paid JSONCorrector fallback.

    Five of the nine sites recover a brace-in-prose reply today by *buying* a
    correction.  Leaving that path reachable would make the deterministic
    defect invisible: the test would pass at the base for the wrong reason.
    """
    import utilities.json_corrector as jc

    class _Refuses:
        def __init__(self, *a, **k):
            raise AssertionError(
                "the paid JSONCorrector fallback must not be reached — the "
                "deterministic extractor is what is under test"
            )

    monkeypatch.setattr(jc, "JSONCorrector", _Refuses)


def _sites():
    """(id, callable) for each of the nine naive-slice sites, at its own API."""
    from context import threat_model_agent
    from core import llm_reachability
    from utilities import (
        context_corrector,
        context_enhancer,
        context_reviewer,
        finding_verifier,
        ground_truth_challenger,
        json_corrector,
    )

    def _bare(cls, **attrs):
        obj = cls.__new__(cls)
        for k, v in attrs.items():
            setattr(obj, k, v)
        return obj

    return [
        ("1 context_corrector._parse_json_response",
         context_corrector._parse_json_response),
        ("2 context_corrector.ContextCorrector._parse_response",
         lambda s: context_corrector.ContextCorrector._parse_response(
             _bare(context_corrector.ContextCorrector, binding=None), s)),
        ("3 context_enhancer.ContextEnhancer._parse_json_response",
         lambda s: context_enhancer.ContextEnhancer._parse_json_response(
             _bare(context_enhancer.ContextEnhancer, binding=None), s)),
        ("4 context_reviewer.ContextReviewer._parse_json_response",
         lambda s: context_reviewer.ContextReviewer._parse_json_response(
             _bare(context_reviewer.ContextReviewer, binding=None), s)),
        ("5 finding_verifier.FindingVerifier._parse_json_from_text",
         lambda s: finding_verifier.FindingVerifier._parse_json_from_text(
             _bare(finding_verifier.FindingVerifier, binding=None), s)),
        ("6 ground_truth_challenger._parse_json_response",
         ground_truth_challenger._parse_json_response),
        ("7 json_corrector._parse_json_response",
         json_corrector._parse_json_response),
        ("8 llm_reachability._extract_json",
         llm_reachability._extract_json),
        ("9 threat_model_agent._extract_json",
         threat_model_agent._extract_json),
    ]


def _verdict_of(site_id, fn, reply):
    """Call a site and return its recovered verdict, or None.

    Site 9 raises instead of returning None, and site 2 normalizes; both are
    folded to the same observable so one assertion covers all nine.
    """
    from context.threat_model_agent import ThreatModelGenerationError

    try:
        out = fn(reply)
    except ThreatModelGenerationError:
        return None
    if out is None:
        return None
    assert isinstance(out, dict), (site_id, out)
    return out.get("verdict")


@pytest.mark.parametrize("reply", BRACE_IN_PROSE)
def test_the_nine_sibling_extractors_recover_a_brace_in_prose_reply(reply, monkeypatch):
    """THE defect. At the base, the naive slice discards the reply at every
    site and only a *paid* corrector can get it back; here the paid path is
    closed, so each site must recover the object deterministically."""
    _no_paid_corrector(monkeypatch)
    failed = {}
    for site_id, fn in _sites():
        got = _verdict_of(site_id, fn, reply)
        if got != "VULNERABLE":
            failed[site_id] = got
    assert not failed, (
        f"{len(failed)} of 9 sibling extractors discarded a brace-in-prose "
        f"reply (expected verdict=VULNERABLE at each): {failed}"
    )


@pytest.mark.parametrize("reply", ALREADY_WORKING)
def test_the_nine_sibling_extractors_keep_what_already_parsed(reply, monkeypatch):
    """The no-regression half: the shapes the naive slice handled still parse
    at all nine sites, with the paid fallback closed."""
    _no_paid_corrector(monkeypatch)
    failed = {}
    for site_id, fn in _sites():
        got = _verdict_of(site_id, fn, reply)
        if got != "VULNERABLE":
            failed[site_id] = got
    assert not failed, f"regression — {len(failed)} of 9 sites stopped parsing: {failed}"


def test_no_sibling_module_still_ships_the_naive_slice():
    """The propagation guard, so a tenth copy is visible on sight.

    #242 fixed one site and left nine; this asserts the mechanism has exactly
    one home.  ``utilities/json_extract.py`` is that home (it keeps the naive
    slice deliberately, as a last-resort superset guard) and is excluded.
    """
    root = Path(__file__).resolve().parent.parent
    home = root / "utilities" / "json_extract.py"
    naive = re.compile(r"""rfind\(['"]\}['"]\)""")
    offenders = []
    for path in sorted(root.rglob("*.py")):
        if path == home or "tests" in path.relative_to(root).parts:
            continue
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if naive.search(line):
                offenders.append(f"{path.relative_to(root)}:{lineno}: {line.strip()}")
    assert not offenders, (
        "the naive first-{/last-} slice is back outside its one home "
        "(utilities/json_extract.py):\n  " + "\n  ".join(offenders)
    )


# --------------------------------------------------------------------------
# the shared extractor's own contract
# --------------------------------------------------------------------------
def test_the_shared_extractor_refuses_to_guess_between_competing_objects():
    """#236's constraint, which #242 adopted rather than relaxed: never
    blind-pick first or last. A trailing ``example: {SAFE}`` block must not be
    able to override a real ``{VULNERABLE}``."""
    from utilities.json_extract import extract_json_object
    two = _OBJ + '\nFor reference, a safe reply looks like:\n{"verdict": "SAFE"}'
    assert extract_json_object(two) is None
    # neither could the naive slice: its span covers both objects
    assert json.loads is not None


def test_the_shared_extractor_is_a_strict_superset_of_the_naive_slice():
    """No base-feature drop, proved over a generated corpus rather than argued.

    The depth-0 scan has a blind spot the naive slice does not — an odd number
    of ``"`` in the prose shifts quote parity and the scan sees no depth-0
    object — which is why the extractor keeps the naive slice as a last
    resort. Any input the old code parsed must still parse, to the SAME value.
    """
    from utilities.json_extract import extract_json_object
    import itertools
    import random

    def naive(text):
        start, end = text.find("{"), text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                value = json.loads(text[start:end])
            except json.JSONDecodeError:
                return None
            if isinstance(value, dict):
                return value
        return None

    dropped, changed, covered = [], [], 0
    def check(s):
        nonlocal covered
        old = naive(s)
        if old is None:
            return
        covered += 1
        new = extract_json_object(s)
        if new is None:
            dropped.append(s)
        elif new != old:
            changed.append((s, old, new))

    # exhaustive over the alphabet that can form an object
    for length in range(7):
        for combo in itertools.product('{}"a:1', repeat=length):
            check("".join(combo))
    # randomized, wider alphabet (escapes, arrays, newlines)
    rng = random.Random(673)
    alphabet = '{}"\\a:1, \n[]'
    for _ in range(20000):
        check("".join(rng.choice(alphabet) for _ in range(rng.randint(0, 28))))
    # structured prose/object/prose
    objs = ['{"a":1}', _OBJ, '{"a":{"b":2}}', '{"a":"}"}', '{"a":"\\""}']
    for obj in objs:
        for pre in ("", "pre ", "{x} ", '" ', '"q" ', "see foo() { ", 'a"b ', "}} "):
            for post in ("", " post", " {y}", ' "', ' "z"', " } ", ' {"c":3}'):
                check(pre + obj + post)

    assert covered > 1000, f"the corpus barely exercised the old path ({covered})"
    assert not dropped, f"{len(dropped)} input(s) parsed before and not now, e.g. {dropped[:3]}"
    assert not changed, f"{len(changed)} input(s) now decode differently, e.g. {changed[:3]}"


def test_a_truncated_reply_is_no_worse_than_the_naive_slice():
    """#538's named hazard, discharged rather than inherited.

    #538 recorded that recovering from a *truncated* reachability reply "would
    persist a partial batch as reviewed, defeating the resume machinery's
    absence-as-retry". That hazard is pre-existing, not introduced here: on
    both truncation shapes the shared extractor returns exactly what the naive
    slice already returned.
    """
    from utilities.json_extract import extract_json_object
    def naive(text):
        start, end = text.find("{"), text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                return None
        return None

    for truncated in ('{"u1": {"reach": true}',       # cut mid-object
                      '{"u1": "x"}\n{"u2":',          # one complete, then cut
                      '{"u1": "x", "u2"'):            # cut mid-key
        assert extract_json_object(truncated) == naive(truncated), truncated


def test_the_scanner_reports_undecodable_spans_distinctly_from_none():
    """``parse_response`` needs the span TEXT of a failed decode to run its
    malformed-verdict ambiguity rule, and ``None`` is a legitimate decoded
    JSON value — so the sentinel must not be ``None``."""
    from utilities.json_extract import UNDECODABLE, scan_depth0_spans
    spans, in_string = scan_depth0_spans('{"a": null} and {oops} and {"b": 1}')
    assert in_string is False
    assert [v for _s, v in spans] == [{"a": None}, UNDECODABLE, {"b": 1}]
    assert UNDECODABLE is not None
    spans, in_string = scan_depth0_spans('{"a": 1} then "unclosed')
    assert in_string is True, "a scan ending inside a string must say so"


def test_the_shared_helper_imports_nothing_but_the_standard_library():
    """The reason the helper is a leaf and not part of ``analysis_core``.

    ``utilities/__init__.py`` eagerly imports six of the eight sibling modules
    and ``core/analysis_core.py`` imports two of them back — the "11-module SCC
    via utilities/__init__.py" hazard in ARCHITECTURE.md §6. A module-level
    import of anything repo-local into this helper would reintroduce it and
    break the siblings at import time.
    """
    import ast

    home = Path(__file__).resolve().parent.parent / "utilities" / "json_extract.py"
    local = {"core", "utilities", "context", "parsers", "prompts", "report",
             "github_scanner", "openant", "experiment"}
    bad = []
    # parsed, not grepped: the module's own docstring quotes the forbidden
    # import as prose, and a regex over lines reads that as an offence.
    for node in ast.walk(ast.parse(home.read_text())):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in local:
                    bad.append(f"{node.lineno}: import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            head = (node.module or "").split(".")[0]
            if node.level > 0 or head in local:
                dots = "." * node.level
                bad.append(f"{node.lineno}: from {dots}{node.module or ''} import ...")
    assert not bad, (
        "utilities/json_extract.py must import only the standard library — "
        "a repo-local import puts it back inside the utilities/ import cycle:\n  "
        + "\n  ".join(bad)
    )


# --------------------------------------------------------------------------
# the origin site keeps its verdict policy
# --------------------------------------------------------------------------
def test_parse_response_keeps_its_verdict_rules_over_the_shared_scanner():
    """The refactor is mechanical: ``parse_response`` now calls the shared
    scanner, and its verdict-specific layers — the verdict/finding key filter,
    the malformed-verdict ambiguity counter, the quote-parity guard — must
    behave exactly as #242 shipped them.  (``test_bughunt2_regressions.py``
    holds #242's own four cases; these are the ones that distinguish
    ``parse_response`` from the generic extractor.)"""
    from utilities.json_extract import extract_json_object
    from core.analysis_core import parse_response

    # the generic extractor returns the lone object; parse_response REFUSES it
    # because a second, verdict-shaped span failed to decode
    ambiguous = '{"verdict": "VULNERABLE"}\nand a broken one: {"verdict": }'
    assert parse_response(ambiguous)["verdict"] == "ERROR"
    assert parse_response(ambiguous)["error"]["type"] == "parse_error"

    # a non-verdict object is not a verdict: ERROR + the retry tag
    assert parse_response('config:\n{"debug": true}')["verdict"] == "ERROR"
    # ...while the generic extractor happily returns it
    assert extract_json_object('config:\n{"debug": true}') == {"debug": True}

    # the brace-in-prose recovery #242 shipped still works
    assert parse_response("The dict {x} is unchecked.\n" + _OBJ)["verdict"] == "VULNERABLE"


def test_parse_response_uses_the_shared_scanner_and_not_a_private_copy(monkeypatch):
    """The "one home" property, made executable.

    The extraction out of ``parse_response`` is behaviour-preserving, so every
    existing test passes whether the scan runs here or in the shared helper --
    which is precisely how nine copies of the naive slice accumulated in the
    first place: a re-inlined scanner is invisible to behavioural tests. This
    test fails if ``parse_response`` ever stops routing through the one home.
    """
    import core.analysis_core as ac

    real = ac.scan_depth0_spans
    calls = []

    def spy(text):
        calls.append(text)
        return real(text)

    monkeypatch.setattr(ac, "scan_depth0_spans", spy)
    out = ac.parse_response("The dict {x} is unchecked.\n" + _OBJ)
    assert out["verdict"] == "VULNERABLE"
    assert len(calls) == 1, (
        "parse_response did not call utilities.json_extract.scan_depth0_spans — "
        "the depth-0 scanner has been re-inlined and there are two homes again"
    )
