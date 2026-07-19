"""PHP bare (unqualified) call must NOT bind to a same-named class METHOD.

In PHP a bare `foo()` inside a method has NO implicit `$this->` -- it resolves to a
function (current namespace, then the global namespace). To call a method you must
write `$this->foo()`, `self::foo()`, or `static::foo()`. The call-graph builder's
step-1 ("check same class first (implicit $this)") wrongly preferred a same-named
METHOD over the free function, MISDIRECTING the edge to the method.

RED before the fix: the bare `helper()` edge points at the same-class method
Svc.helper instead of the free function helper (the true system() sink).
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


def test_barecall_binds_free_function_not_same_class_method():
    b = _build({
        "src/a.php": "<?php\n"
                     "class Svc {\n"
                     "  public function run($x){ helper($x); }\n"   # bare call -> free function
                     "  public function helper($x){ echo $x; }\n"   # same-named METHOD (misdirect risk)
                     "}\n",
        "src/b.php": "<?php\nfunction helper($x){ system($x); }\n",  # free function (true sink)
    })
    edges = _edges(b, ":Svc.run")
    assert any(e.endswith("b.php:helper") for e in edges), (
        f"bare helper() must bind the FREE function (the system() sink), not the "
        f"same-class method; got edges: {edges}"
    )
    assert not any(e.endswith(":Svc.helper") for e in edges), (
        f"MISDIRECT: bare helper() bound the same-class method Svc.helper; got {edges}"
    )
