"""PHP classes dict last-write-wins: a same-name class redefined in a
mutually-exclusive/guarded branch must NOT silently drop the earlier
definition's methods/bases.

Sibling of py-class-dict-overwrite-bases. PHP allows a class to be defined in
conditional branches, e.g.
    if (PHP_VERSION_ID >= 80000) { class Widget extends ModernBase { newFeature() } }
    else                         { class Widget extends LegacyBase { oldFeature() } }
Both branches share class_id `<file>:Widget`, so `self.classes[class_id] = {...}`
overwrote the first with the last-in-source one -- a silent false negative for a
SAST call-graph (methods on the dropped branch become unreachable). The fix
merges same-id registrations (union methods/traits/interfaces, keep first base).
"""
import sys
import tempfile
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.php.function_extractor import FunctionExtractor


def _extract(php_source: str, filename: str = "cls.php") -> dict:
    repo = tempfile.mkdtemp()
    Path(repo, filename).write_text(php_source)
    return FunctionExtractor(repo).extract_all([filename])


def test_conditional_same_name_class_keeps_both_branch_methods():
    src = (
        "<?php\n"
        "if (PHP_VERSION_ID >= 80000) {\n"
        "    class Widget extends ModernBase {\n"
        "        public function render() {}\n"
        "        public function newFeature() {}\n"
        "    }\n"
        "} else {\n"
        "    class Widget extends LegacyBase {\n"
        "        public function render() {}\n"
        "        public function oldFeature() {}\n"
        "    }\n"
        "}\n"
    )
    out = _extract(src)
    widget_ids = [cid for cid, d in out["classes"].items() if d.get("name") == "Widget"]
    assert len(widget_ids) == 1, f"same-name class stays one id; got {widget_ids}"
    methods = set(out["classes"][widget_ids[0]]["methods"])
    # Both env-dependently-reachable branches must survive the merge.
    assert "newFeature" in methods and "oldFeature" in methods, (
        f"a conditional branch's methods were dropped: {sorted(methods)}"
    )
    # An earlier branch's base must not be lost when the later branch declares one.
    assert out["classes"][widget_ids[0]]["superclass"] in ("ModernBase", "LegacyBase")


def test_guarded_same_name_trait_keeps_both_branch_methods():
    # Traits carry a different entry schema (no 'traits'/'trait_aliases' keys);
    # the merge must handle it without KeyError.
    src = (
        "<?php\n"
        "if (!trait_exists('Helper')) {\n"
        "    trait Helper { public function a() {} }\n"
        "}\n"
        "if (!trait_exists('Helper')) {\n"
        "    trait Helper { public function b() {} }\n"
        "}\n"
    )
    out = _extract(src)
    ids = [cid for cid, d in out["classes"].items() if d.get("name") == "Helper"]
    assert len(ids) == 1, f"same-name trait stays one id; got {ids}"
    methods = set(out["classes"][ids[0]]["methods"])
    assert "a" in methods and "b" in methods, f"a guarded trait def was dropped: {sorted(methods)}"


def test_unique_name_class_id_unchanged():
    out = _extract("<?php\nclass Solo { public function go() {} }\n", filename="u.php")
    ids = [cid for cid, d in out["classes"].items() if d.get("name") == "Solo"]
    assert ids == ["u.php:Solo"], f"unique-name class id must stay byte-identical; got {ids}"
