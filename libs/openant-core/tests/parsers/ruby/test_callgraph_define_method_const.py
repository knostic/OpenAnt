"""define_method(CONST) with a literal-const name emits the unit (reachability FN fix).

`NAME = :dyn_exec; define_method(NAME){...}` defines the method dyn_exec, but only a
literal-symbol/string arg was handled, so a constant-named define_method dropped the
unit. Determinate-only: the constant must have exactly one literal binding; a
non-literal / reassigned / lowercase-local name stays dropped (0 phantom).
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


def test_define_method_const_literal_name_emitted_and_reachable():
    b = _build({
        "app.rb": "require 'sinatra'\n"
                  "NAME = :dyn_exec\n"
                  "class Facade\n"
                  "  define_method(NAME) { |arg| eval(arg) }\n"
                  "end\n"
                  "get '/run' do\n"
                  "  Facade.dyn_exec(params[:code])\n"
                  "end\n",
    })
    assert any(k.endswith(":Facade.dyn_exec") for k in b.functions), (
        f"define_method(NAME) with NAME=:dyn_exec must emit Facade.dyn_exec; "
        f"funcs={list(b.functions)}"
    )
    route = [k for k in b.call_graph if k.endswith(":/run")]
    assert route and any("Facade.dyn_exec" in e for e in b.call_graph[route[0]]), (
        f"route /run must reach Facade.dyn_exec; edges={b.call_graph.get(route[0]) if route else None}"
    )


def test_nondeterminate_const_names_stay_dropped_no_phantom():
    b = _build({
        "app.rb": "require 'sinatra'\n"
                  "HANDLER = build_handler()\n"   # non-literal RHS -> unresolvable
                  "DUP = :a\n"
                  "DUP = :b\n"                     # reassigned -> ambiguous -> blacklisted
                  "class Facade\n"
                  "  define_method(HANDLER) { |arg| eval(arg) }\n"
                  "  define_method(DUP) { |arg| eval(arg) }\n"
                  "  define_method(lower) { |arg| eval(arg) }\n"  # lowercase local -> not a constant
                  "end\n",
    })
    assert not any(k.endswith(".HANDLER") for k in b.functions), list(b.functions)
    assert not any(k.endswith(".DUP") for k in b.functions), list(b.functions)
    assert not any(k.endswith(".a") or k.endswith(".b") for k in b.functions), list(b.functions)
    assert not any(k.endswith(".lower") for k in b.functions), list(b.functions)
