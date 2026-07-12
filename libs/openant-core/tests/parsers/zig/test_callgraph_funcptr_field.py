"""Struct field-init function pointers resolve (reachability FN fix).

`const h = T{ .cb = knownFn }; h.cb()` invokes knownFn, but only `const alias = fn`
bindings were indexed, not struct field-init bindings, so the h.cb() -> knownFn edge
was dropped. Precision: only a determinate `.field = <known function>` is bound; a
param/runtime funcptr never over-connects.
"""
import json
import os
import tempfile

from core.parser_adapter import parse_repository


def _cg(files: dict):
    repo = os.path.realpath(tempfile.mkdtemp())
    for rel, content in files.items():
        p = os.path.join(repo, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(content)
    out = tempfile.mkdtemp()
    parse_repository(repo, out, language="zig", processing_level="all",
                     skip_tests=True, name="r")
    return json.load(open(os.path.join(out, "call_graph.json")))


def _edges(cg, caller_suffix):
    keys = [k for k in cg["call_graph"] if k.endswith(caller_suffix)]
    return [e for k in keys for e in cg["call_graph"][k]]


def test_struct_field_funcptr_call_resolves():
    cg = _cg({
        "main.zig": "const std = @import(\"std\");\n"
                    "const Handler = struct { callback: *const fn () void };\n"
                    "fn dangerousSink() void { std.process.exit(1); }\n"
                    "fn normalCallee() void {}\n"
                    "pub fn main() void {\n"
                    "    normalCallee();\n"
                    "    const h = Handler{ .callback = dangerousSink };\n"
                    "    h.callback();\n"
                    "}\n",
    })
    assert any("dangerousSink" in e for e in _edges(cg, ":main")), (
        f"h.callback() bound to dangerousSink must resolve; got {_edges(cg, ':main')}"
    )


def test_param_funcptr_does_not_over_connect():
    # Precision: a funcptr received as a parameter (not a determinate .field=fn
    # binding) must not connect to any function.
    cg = _cg({
        "main.zig": "fn sink() void {}\n"
                    "fn run(cb: *const fn () void) void { cb(); }\n"
                    "pub fn main() void { run(sink); }\n",
    })
    # run's cb() must NOT phantom-connect to sink (cb is a param, undecidable here)
    assert not any("sink" in e for e in _edges(cg, ":run")), (
        f"param funcptr cb() must not over-connect to sink; got {_edges(cg, ':run')}"
    )
