"""Trait method aliasing `use T { foo as bar; }` resolves (reachability FN fix).

_extract_trait_names captured only bare trait names, dropping the `foo as bar` alias, so
`$this->bar()` did not resolve to the trait's `T::foo` and the edge (potentially to a sink)
was lost. Precision: the alias resolves ONLY to the aliased trait method, never to an
unrelated same-named method in another class.
"""
import os
import tempfile

from parsers.php.function_extractor import FunctionExtractor
from parsers.php.call_graph_builder import CallGraphBuilder


def _build(src: str):
    repo = os.path.realpath(tempfile.mkdtemp())
    p = os.path.join(repo, "app.php")
    with open(p, "w") as fh:
        fh.write(src)
    b = CallGraphBuilder(FunctionExtractor(repo).extract_all([p]))
    b.build_call_graph()
    return b


def _edges(b, caller_suffix):
    keys = [k for k in b.call_graph if k.endswith(caller_suffix)]
    return [e for k in keys for e in b.call_graph[k]]


def test_trait_alias_resolves_to_trait_method():
    b = _build(
        "<?php\n"
        "trait Greet { public function hello(){ system('x'); } }\n"
        "class A { use Greet { hello as greeting; }\n"
        "  public function run(){ return $this->greeting(); } }\n"
    )
    assert any(e.endswith(":Greet.hello") for e in _edges(b, ":A.run")), (
        f"$this->greeting() (alias of Greet::hello) must resolve to Greet.hello; "
        f"got {_edges(b, ':A.run')}"
    )


def test_trait_alias_does_not_leak_to_unrelated_same_named_method():
    # Precision: an unrelated class D with a real method `greeting` must NOT be connected.
    b = _build(
        "<?php\n"
        "trait Greet { public function hello(){ system('x'); } }\n"
        "class A { use Greet { hello as greeting; }\n"
        "  public function run(){ return $this->greeting(); } }\n"
        "class D { public function greeting(){ return 99; } }\n"
    )
    edges = _edges(b, ":A.run")
    assert any(e.endswith(":Greet.hello") for e in edges), f"true trait edge missing; got {edges}"
    assert not any("D.greeting" in e for e in edges), (
        f"PHANTOM: alias leaked to unrelated D.greeting; got {edges}"
    )
