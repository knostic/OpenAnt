"""define_singleton_method emits a unit (reachability FN fix).

The `call`-node DSL branch handled define_method and alias_method but had no case for
define_singleton_method, so `define_singleton_method(:sing_exec){...}` produced NO unit
and its body (an eval sink) was never extracted -> a reachable sink dropped.
"""
import os
import tempfile

from parsers.ruby.function_extractor import FunctionExtractor
from parsers.ruby.call_graph_builder import CallGraphBuilder


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


def test_define_singleton_method_emitted_as_unit():
    b = _build({
        "app.rb": "require 'sinatra'\n"
                  "class Facade\n"
                  "  define_singleton_method(:sing_exec) { |arg| eval(arg) }\n"
                  "end\n"
                  "get '/run' do\n"
                  "  Facade.sing_exec(params[:code])\n"
                  "end\n",
    })
    assert any("sing_exec" in k for k in b.functions), (
        f"define_singleton_method(:sing_exec) must be emitted as a unit; funcs={list(b.functions)}"
    )


def test_define_singleton_method_reachable_from_route():
    b = _build({
        "app.rb": "require 'sinatra'\n"
                  "class Facade\n"
                  "  define_singleton_method(:sing_exec) { |arg| eval(arg) }\n"
                  "end\n"
                  "get '/run' do\n"
                  "  Facade.sing_exec(params[:code])\n"
                  "end\n",
    })
    route = [k for k in b.call_graph if k.endswith(":/run")]
    assert route and any("sing_exec" in e for e in b.call_graph[route[0]]), (
        f"route /run must reach Facade.sing_exec (the eval sink); "
        f"route={route}, edges={b.call_graph.get(route[0]) if route else None}"
    )
