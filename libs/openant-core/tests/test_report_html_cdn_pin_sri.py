"""#502: the dev-only Python HTML report pins and SRIs its CDN scripts.

The #332 self-containment contract covers the Go-rendered reports; this
dev-only surface (the sink-is-dead boundary guards it out of every
shipped path) still loaded FLOATING chart.js majors from the CDN — no
version, no SRI. The fix: the exact SOURCES.txt URLs (the same bytes the
Go surface vendors), sha256 SRI (base64 of the vendored blobs), and
crossorigin=anonymous (without it the browser cannot verify an opaque
response and blocks the scripts). The cross-surface hash test makes the
Python pin drift-impossible: when the Go side bumps, this file goes RED
until the pin (and its hashes) follow in the same commit.
"""
from __future__ import annotations

import base64
import hashlib
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_CORE = Path(__file__).resolve().parent.parent
_REPO_ROOT = _CORE.parent.parent
_VENDOR = _REPO_ROOT / "apps" / "openant-cli" / "internal" / "report" / "vendor"

_PINNED = [
    # (url fragment, vendored filename)
    ("chart.js@4.5.1/dist/chart.umd.min.js", "chart-4.5.1.umd.min.js"),
    ("chartjs-plugin-datalabels@2.2.0/dist/chartjs-plugin-datalabels.min.js",
     "chartjs-plugin-datalabels-2.2.0.min.js"),
]


def _rendered_html(tmp_path: Path) -> str:
    import report.html_report as H
    out = tmp_path / "r.html"
    H.generate_html_report({"results": []}, {"units": []}, "", str(out))
    return out.read_text(encoding="utf-8")


def test_scripts_are_pinned_and_sri(tmp_path):
    html = _rendered_html(tmp_path)
    for frag, _ in _PINNED:
        assert frag in html, f"the pinned URL {frag} is missing"
    assert 'npm/chart.js"' not in html, "a floating chart.js reference survives"
    assert 'datalabels@2"' not in html, "a floating datalabels reference survives"
    for m in re.finditer(r"<script[^>]+chart[^>]*></script>", html):
        tag = m.group(0)
        assert 'integrity="sha256-' in tag, f"no SRI: {tag[:80]}"
        assert 'crossorigin="anonymous"' in tag, (
            f"no crossorigin: SRI on a cross-origin script without a CORS "
            f"request is unverifiable (opaque response) and the browser "
            f"BLOCKS it — {tag[:80]}")


def test_integrity_matches_the_vendored_go_bytes(tmp_path):
    """The cross-surface drift guard: the Python pin's SRI must equal
    base64(sha256()) of the very blobs the Go renderer vendors — the two
    surfaces cannot drift apart silently."""
    if not (_REPO_ROOT / "apps" / "openant-cli").exists():
        import pytest
        pytest.skip("standalone core checkout without the Go CLI tree")
    html = _rendered_html(tmp_path)
    for frag, vendored in _PINNED:
        blob = _VENDOR / vendored
        assert blob.exists(), (
            f"the vendored {vendored} is gone — the Go side bumped; update "
            f"the Python pin (URL + integrity) in the SAME commit")
        expected = "sha256-" + base64.b64encode(
            hashlib.sha256(blob.read_bytes()).digest()).decode()
        m = re.search(
            r'src="[^"]*' + re.escape(frag) + r'" integrity="(sha256-[^"]+)"', html)
        assert m, f"no integrity attr next to {frag}"
        assert m.group(1) == expected, (
            f"{frag}: the Python SRI {m.group(1)} != the vendored bytes' "
            f"{expected} — cross-surface drift (the #502 guard)")
