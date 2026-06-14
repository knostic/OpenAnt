"""Bug 1 (PHP): same-name functions defined in mutually-exclusive conditional
branches must NOT silently collapse to the last-in-source one.

Verified harmful (independent + judge, real `php` interpreter): for
  if (...) { function k(){ A } } else { function k(){ B } }
and the defensive double `function_exists` guard, the live definition can be the
EARLIER branch, but the extractor kept only the later (else) one — a silent
false negative for a SAST tool. Both branches are env-dependently reachable, so
the fix keeps BOTH (the `#L<line>` disambiguation the Python extractor already
uses), not prefer-first/larger. Collision-only: a unique name keeps its clean id.
"""
import sys
import tempfile
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.php.function_extractor import FunctionExtractor


def _extract(php_source: str, filename: str = "cond.php") -> dict:
    repo = tempfile.mkdtemp()
    Path(repo, filename).write_text(php_source)
    return FunctionExtractor(repo).extract_all([filename])


def _named(out: dict, name: str):
    return [fid for fid, d in out["functions"].items() if d.get("name") == name]


def test_conditional_ifelse_keeps_both_branches():
    src = (
        "<?php\n"
        "if (defined('X')) {\n"
        "    function k() { return if_branch(); }\n"
        "} else {\n"
        "    function k() { return else_branch(); }\n"
        "}\n"
    )
    out = _extract(src)
    ks = _named(out, "k")
    assert len(ks) == 2, f"both conditional branches of k() must be kept; got {ks}"
    bodies = " ".join(out["functions"][f]["code"] for f in ks)
    assert "if_branch" in bodies and "else_branch" in bodies, f"a branch was dropped: {bodies}"


def test_double_function_exists_guard_keeps_both():
    src = (
        "<?php\n"
        "if (!function_exists('h')) {\n"
        "    function h() { return real(); }\n"
        "}\n"
        "if (!function_exists('h')) {\n"
        "    function h() { return fallback(); }\n"
        "}\n"
    )
    out = _extract(src)
    hs = _named(out, "h")
    assert len(hs) == 2, f"both guarded defs of h() must be kept; got {hs}"


def test_unique_name_id_unchanged():
    out = _extract("<?php\nfunction solo() { return 1; }\n", filename="u.php")
    ids = _named(out, "solo")
    assert ids == ["u.php:solo"], f"unique-name id must stay byte-identical; got {ids}"
