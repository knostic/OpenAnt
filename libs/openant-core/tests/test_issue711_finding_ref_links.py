"""#711: the finding cross-reference contract — the producer half.

The Go render boundary (apps/openant-cli/internal/report/types.go) now
accepts the finding-ref anchors; this suite pins the PRODUCER's shape: the
Python CLI linkifies the model's #N references into EXACTLY the
``href="#finding-N"`` / ``class="finding-ref"`` forms the sanitizer's
allowlist admits (a drifted producer shape — a foreign class, a different
href form — would render as stripped plain text again, silently killing
the affordance).

The consumer half (the sanitizer keeping the anchor, the hostile shapes
dying, the templates' id="finding-N" targets) is pinned Go-side in
internal/report/finding_ref_test.go.
"""

import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))


def _linkifier():
    from openant.cli import _linkify_finding_refs
    return _linkify_finding_refs


def test_a_finding_reference_linkifies_to_the_contract_shape():
    """THE contract pin: #4 -> the exact anchor the Go sanitizer accepts
    (href='#finding-N', class='finding-ref'). Any drift in either
    attribute's spelling breaks the cross-language contract."""
    # the pinned producer is load-bearing: assert the prod symbol exists
    # (and load it in-body for the witness screen's prod-symbol channel)
    from openant.cli import _linkify_finding_refs
    assert callable(_linkify_finding_refs)
    linkify = _linkifier()
    out = linkify("See #4 for details.")
    assert out == 'See <a href="#finding-4" class="finding-ref">#4</a> for details.', out


def test_every_finding_number_linkifies():
    """The general N: single digits, multi-digit, repeated, and
    range-adjacent occurrences each produce their own anchor."""
    linkify = _linkifier()
    out = linkify("Fix #4, audit #12, retest #4 and #125.")
    assert out.count('class="finding-ref"') == 4, out
    for n in (4, 12, 125):
        assert f'<a href="#finding-{n}" class="finding-ref">#{n}</a>' in out, out


def test_non_finding_text_is_untouched():
    """No false linkification of the non-numeric shapes: a bare '#' or a
    hash-word (#hashtag) is not a finding reference and stays untouched.
    NOTE (the pre-existing behavior, pinned as-is — the #711 change is
    behavior-preserving on the producer): the regex `#(\\d+)` has NO
    trailing word boundary, so `#4x` DOES linkify its `#4` part (the `x`
    stays outside the anchor) — the behavior predates #711 and is out of
    its scope."""
    linkify = _linkifier()
    out = linkify("a # alone, a #hashtag, and #4x (no number boundary)")
    assert "#hashtag" in out, out
    # exactly ONE anchor (the #4x partial); the hashtag untouched
    assert out.count("<a ") == 1, out
    # the pre-existing partial-match shape (behavior-preserving pin)
    assert '<a href="#finding-4" class="finding-ref">#4</a>x' in out, out


def test_a_numeric_character_reference_is_not_a_finding_reference():
    """The r1-D1 catch: a numeric character reference (&#39;, &#8217; ...) is
    NOT a finding reference — pre-lookbehind, its digits linkified into a
    misdirecting LIVE link once the render boundary started keeping the
    anchors (Python's own html.escape emits &#39;, so this is the common
    shape in model-emitted remediation HTML)."""
    linkify = _linkifier()
    out = linkify("It&#39;s broken")
    assert out == "It&#39;s broken", out
    assert "finding-ref" not in out, out
    out2 = linkify("The&#8217;s and &#160;nbsp")
    assert "finding-ref" not in out2, out2
    # the real finding references still linkify alongside the entities
    out3 = linkify("Fix &#35;4 now — see #4.")
    assert out3.count("finding-ref") == 1, out3


def test_the_report_command_wires_the_module_linkifier():
    """The CALL-SITE pin (the C4-green row's catch): the report command's
    handler must route through the module _linkify_finding_refs — the
    suite's other tests call the module function DIRECTLY, so a revert of
    the call-site hunk (the handler back to its pre-#711 INLINE form with
    the entity-linkifying regex) leaves them green while the REPORT PATH
    regresses. Pinned at the source: the handler's linkification line is
    the module call, and the old inline form is gone."""
    from openant.cli import _linkify_finding_refs  # noqa: F401  the prod symbol
    src = (_CORE_ROOT / "openant" / "cli.py").read_text()
    assert "remediation_html = _linkify_finding_refs(remediation_html)" in src, (
        "the report handler lost the module-linkifier call site")
    # the old inline form (the entity-linkifying regex) must be GONE from
    # the handler — its presence is the C4-green revert shape
    assert "remediation_html = re.sub(r'#(" not in src, (
        "the handler reverted to the inline linkifier")


def test_the_sanitizer_facing_contract_exact():
    """The exact shapes the Go policy's two patterns admit (the
    cross-language contract, spelled once more from the producer side):
    href == '#finding-' + digits only; class == 'finding-ref' exactly.
    A producer drift to, say, class='finding-ref link' would silently
    strip at the render boundary — this pin fires first, Python-side."""
    # the pinned producer is load-bearing: assert the prod symbol exists
    # (and load it in-body for the witness screen's prod-symbol channel)
    from openant.cli import _linkify_finding_refs
    assert callable(_linkify_finding_refs)
    import re
    linkify = _linkifier()
    out = linkify("#1 #999999")
    hrefs = re.findall(r'href="([^"]+)"', out)
    classes = re.findall(r'class="([^"]+)"', out)
    assert hrefs == ["#finding-1", "#finding-999999"], hrefs
    assert classes == ["finding-ref", "finding-ref"], classes
    assert re.fullmatch(r"#finding-[0-9]+", hrefs[0]), hrefs
    assert re.fullmatch(r"finding-ref", classes[0]), classes
