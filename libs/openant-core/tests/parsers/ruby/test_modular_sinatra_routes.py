"""Modular Sinatra routes (inside `< Sinatra::Base`) are emitted as route handlers.

The Sinatra route DSL branch only fired at top level (class_name is None), so
`get '/run' do ... end` inside `class App < Sinatra::Base` produced no route_handler
unit -> the route body (and its sink) was never extracted or seeded. The class case
is gated on the class extending Sinatra::Base/Application, so an unrelated class
method named like a verb is not spuriously seeded.
"""
import os
import tempfile

from parsers.ruby.function_extractor import FunctionExtractor
from parsers.ruby.call_graph_builder import CallGraphBuilder


def _build(src: str):
    repo = os.path.realpath(tempfile.mkdtemp())
    p = os.path.join(repo, "app.rb")
    with open(p, "w") as fh:
        fh.write(src)
    return CallGraphBuilder(FunctionExtractor(repo).extract_all([p]))


def _has_route_handler(b):
    return any((v.get("unit_type") == "route_handler") for v in b.functions.values())


def test_modular_sinatra_route_is_route_handler():
    b = _build(
        "require 'sinatra/base'\n"
        "class App < Sinatra::Base\n"
        "  get '/run' do\n"
        "    system(params[:cmd])\n"
        "  end\n"
        "end\n"
    )
    assert _has_route_handler(b), (
        f"modular Sinatra route must be a route_handler unit; "
        f"units={[(k, v.get('unit_type')) for k, v in b.functions.items()]}"
    )


def test_classic_top_level_route_still_route_handler():
    # No-regression: classic top-level style keeps working.
    b = _build("require 'sinatra'\nget '/x' do\n  system('a')\nend\n")
    assert _has_route_handler(b), "classic top-level Sinatra route must still be a route_handler"


def test_verb_named_method_in_non_sinatra_class_not_seeded():
    # Precision: a `get '/x' do..end` inside a class that is NOT a Sinatra subclass
    # must NOT become a route_handler (no over-seeding).
    b = _build("class Plain\n  get '/x' do\n    system('y')\n  end\nend\n")
    assert not _has_route_handler(b), (
        f"a verb call inside a non-Sinatra class must not be a route_handler; "
        f"units={[(k, v.get('unit_type')) for k, v in b.functions.items()]}"
    )
