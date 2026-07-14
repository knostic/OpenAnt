"""PHP unqualified-call global-namespace fallback (reachability FN fix).

PHP resolves an unqualified function call within the caller's namespace first, then
FALLS BACK to the global namespace. The call-graph builder's step-4 filter required
exact namespace equality, dropping the global-ns candidate -> a namespaced caller could
not reach a global-ns sink (e.g. system()) = a reachability false-negative.

RED before the fix: the namespaced caller's edge to the global sink is dropped.
Precision guard: a same-named function in an UNRELATED namespace must NOT be connected
(0 phantom). No-regression: an exact same-namespace target still takes precedence.
"""
import os
import tempfile

from parsers.php.function_extractor import FunctionExtractor
from parsers.php.call_graph_builder import CallGraphBuilder


def _build(files: dict):
    repo = os.path.realpath(tempfile.mkdtemp())
    paths = []
    for rel, content in files.items():
        p = os.path.join(repo, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(content)
        paths.append(p)
    b = CallGraphBuilder(FunctionExtractor(repo).extract_all(paths))
    b.build_call_graph()
    return b


def _edges(b, caller_suffix):
    keys = [k for k in b.call_graph if k.endswith(caller_suffix)]
    return [e for k in keys for e in b.call_graph[k]]


def test_unqualified_call_resolves_global_ns_fallback():
    b = _build({
        "src/a.php": "<?php\nnamespace App\\Controllers;\n"
                     "class H { public function run(){ danger($_GET['c']); } }\n",
        "src/b.php": "<?php\nfunction danger($x){ system($x); }\n",
    })
    edges = _edges(b, ":H.run")
    assert any(e.endswith("b.php:danger") for e in edges), (
        f"unqualified danger() from App\\Controllers must fall back to global \\danger "
        f"(the system() sink); got edges: {edges}"
    )


def test_global_ns_fallback_does_not_connect_unrelated_namespace():
    # Precision guard: a same-named function in an UNRELATED namespace is NOT a fallback
    # target and must not be connected (0 phantom).
    b = _build({
        "src/a.php": "<?php\nnamespace App\\Controllers;\n"
                     "class H { public function run(){ danger($_GET['c']); } }\n",
        "src/b.php": "<?php\nfunction danger($x){ system($x); }\n",           # global sink (true)
        "src/c.php": "<?php\nnamespace App\\Vendor;\nfunction danger($x){ echo $x; }\n",  # phantom risk
    })
    edges = _edges(b, ":H.run")
    assert any(e.endswith("b.php:danger") for e in edges), f"true global edge missing; got {edges}"
    assert not any("c.php" in e or "Vendor" in e for e in edges), (
        f"PHANTOM: connected the unrelated App\\Vendor\\danger; got {edges}"
    )


def test_same_namespace_target_takes_precedence():
    # No-regression: when a same-namespace function AND a global one both exist, the
    # unqualified call must bind the SAME-namespace one (PHP precedence), not drop or
    # bind global.
    b = _build({
        "src/a.php": "<?php\nnamespace App\\Controllers;\n"
                     "class H { public function run(){ helper($_GET['c']); } }\n"
                     "function helper($x){ system($x); }\n",   # same-ns (App\\Controllers)
        "src/b.php": "<?php\nfunction helper($x){ echo $x; }\n",  # global namesake
    })
    edges = _edges(b, ":H.run")
    assert any(e.endswith("a.php:App\\Controllers\\helper") or "a.php" in e for e in edges), (
        f"same-namespace helper() must take precedence over the global namesake; got {edges}"
    )
    assert not any("b.php" in e for e in edges), (
        f"must NOT bind the global namesake when a same-ns target exists; got {edges}"
    )
