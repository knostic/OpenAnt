"""Regression test for the PHP anonymous-class method-attribution bug.

`new class { ... }` (PHP 7+) produces a tree-sitter `anonymous_class` node, which had
no handler in _extract_functions_from_tree and fell through the catch-all `else` — so
its methods were emitted with class_name=None (bare top-level functions). Two distinct
anonymous classes that both define e.g. handle() then collided on one unit id and the
later silently overwrote the earlier (data loss).

Driven through the REAL extractor (FunctionExtractor.extract_all) on a temp .php file.

DEPENDENCY (human reviewers + agents): this fix assumes the reworked
`_extract_functions_from_tree` traversal added by upstream PR #111 (PHP parser). On raw
`master` the PHP extractor has a materially different shape and these tests fail — this
change is NOT landable on master standalone. Depends-on: #111. Base this on
staging/parser-fix-stack (which already contains #111) to run it green.
"""

import os
import sys
import tempfile
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.php.function_extractor import FunctionExtractor


def _extract(php_source: str, filename: str = "anon.php") -> dict:
    repo = tempfile.mkdtemp()
    with open(os.path.join(repo, filename), "w") as fh:
        fh.write(php_source)
    return FunctionExtractor(repo).extract_all([filename])


def test_anon_class_method_attributed_to_synthetic_class():
    src = (
        "<?php\n"
        "function make() {\n"
        "    return new class {\n"
        "        public function handle() { return 1; }\n"
        "    };\n"
        "}\n"
    )
    funcs = _extract(src)["functions"]
    handle = [v for v in funcs.values() if v["name"] == "handle"]
    assert len(handle) == 1, f"expected one handle unit; got {sorted(funcs)}"
    info = handle[0]
    # The method must be attributed to a non-None synthetic anonymous-class identity,
    # not left as a bare top-level function.
    assert info["class_name"], f"handle has no class_name: {info}"
    assert info["class_name"].startswith("class@anonymous"), info["class_name"]
    assert info["qualified_name"].endswith(".handle"), info["qualified_name"]
    # make() (the enclosing named function) is unaffected.
    assert any(v["name"] == "make" for v in funcs.values()), sorted(funcs)


def test_two_anon_classes_same_method_no_collision():
    src = (
        "<?php\n"
        "function a() { return new class { public function handle() { return 1; } }; }\n"
        "function b() { return new class { public function handle() { return 2; } }; }\n"
    )
    funcs = _extract(src)["functions"]
    handle_ids = [k for k, v in funcs.items() if v["name"] == "handle"]
    assert len(handle_ids) == 2, (
        f"two distinct anon-class handle() must not collide; got {handle_ids} "
        f"(all keys: {sorted(funcs)})"
    )
    assert len(set(handle_ids)) == 2, f"duplicate ids: {handle_ids}"


def test_two_anon_classes_same_line_no_collision():
    # Two `new class {}` on ONE physical line share a start line; the synthetic id must
    # also use the column, or they collide and one method is silently lost.
    src = (
        "<?php\n"
        "$a = new class { public function handle() { return 1; } }; "
        "$b = new class { public function handle() { return 2; } };\n"
    )
    funcs = _extract(src)["functions"]
    handle_ids = [k for k, v in funcs.items() if v["name"] == "handle"]
    assert len(handle_ids) == 2, f"same-line anon classes collided; got {handle_ids}"
    assert len(set(handle_ids)) == 2, f"duplicate ids: {handle_ids}"
