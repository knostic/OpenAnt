r"""Aliased `use` imports resolve calls made via the alias (reachability FN).

`_extract_imports` used to drop the trailing `as Bar`, so a `Bar::run()` / `new Bar()` call
named the alias `Bar`, which never matched the real class `Foo`, and the edge (potentially to a
sink) was lost. The extractor now records the alias as `imports[alias] = 'use_alias:<Target>'`
and `_resolve_class_call` translates it before resolving.

Covered sibling forms (all must resolve to the real target, never to an unrelated same-named
symbol):
  * `use App\Service\Foo as Bar;`      -- plain, namespace-scope alias (static call + `new`)
  * `use App\Service\{Foo as Bar};`    -- GROUPED-use alias  (the previously-uncovered form)
"""
import os
import tempfile

from parsers.php.function_extractor import FunctionExtractor
from parsers.php.call_graph_builder import CallGraphBuilder


def _build(files: dict):
    repo = os.path.realpath(tempfile.mkdtemp())
    paths = []
    for rel, src in files.items():
        p = os.path.join(repo, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(src)
        paths.append(p)
    b = CallGraphBuilder(FunctionExtractor(repo).extract_all(paths))
    b.build_call_graph()
    return b


def _edges(b, caller_suffix):
    keys = [k for k in b.call_graph if k.endswith(caller_suffix)]
    return [e for k in keys for e in b.call_graph[k]]


def test_use_alias_static_call_resolves_to_target_class():
    b = _build({
        "svc.php": (
            "<?php\n"
            "namespace App\\Service;\n"
            "class Foo { public static function run(){ system('x'); } }\n"
        ),
        "app.php": (
            "<?php\n"
            "use App\\Service\\Foo as Bar;\n"
            "class Ctrl { public function go(){ return Bar::run(); } }\n"
        ),
    })
    assert any(e.endswith(":Foo.run") for e in _edges(b, ":Ctrl.go")), (
        f"Bar::run() (alias of App\\Service\\Foo) must resolve to Foo.run; "
        f"got {_edges(b, ':Ctrl.go')}"
    )


def test_use_alias_new_resolves_to_target_constructor():
    b = _build({
        "svc.php": (
            "<?php\n"
            "namespace App\\Service;\n"
            "class Foo { public function __construct(){ system('x'); } }\n"
        ),
        "app.php": (
            "<?php\n"
            "use App\\Service\\Foo as Bar;\n"
            "class Ctrl { public function go(){ return new Bar(); } }\n"
        ),
    })
    assert any(e.endswith(":Foo.__construct") for e in _edges(b, ":Ctrl.go")), (
        f"new Bar() (alias of App\\Service\\Foo) must resolve to Foo.__construct; "
        f"got {_edges(b, ':Ctrl.go')}"
    )


def test_grouped_use_alias_static_call_resolves_to_target_class():
    # GROUPED-use alias `use App\Service\{Foo as Bar};` -- the sibling form the narrow fix missed.
    b = _build({
        "svc.php": (
            "<?php\n"
            "namespace App\\Service;\n"
            "class Foo { public static function run(){ system('x'); } }\n"
        ),
        "app.php": (
            "<?php\n"
            "use App\\Service\\{Foo as Bar};\n"
            "class Ctrl { public function go(){ return Bar::run(); } }\n"
        ),
    })
    assert any(e.endswith(":Foo.run") for e in _edges(b, ":Ctrl.go")), (
        f"grouped-use alias Bar::run() must resolve to Foo.run; got {_edges(b, ':Ctrl.go')}"
    )


def test_grouped_use_alias_extractor_records_target():
    # The grouped form must distribute the `App\Service\` prefix over each brace item and record
    # both the alias entry and the resolved path.
    repo = os.path.realpath(tempfile.mkdtemp())
    p = os.path.join(repo, "app.php")
    with open(p, "w") as fh:
        fh.write("<?php use App\\Service\\{Foo as Bar, Baz};")
    out = FunctionExtractor(repo).extract_all([p])
    imports = out["imports"]["app.php"]
    assert imports.get("Bar") == "use_alias:Foo", imports  # grouped alias Bar -> class Foo
    assert "App\\Service\\Baz" in imports, imports         # non-aliased grouped member resolved
