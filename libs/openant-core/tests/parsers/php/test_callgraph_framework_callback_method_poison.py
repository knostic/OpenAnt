"""A bare string callback is a GLOBAL function, never a method of the enclosing class.

`add_action('save_post', 'save_post')` (or call_user_func('foo')) uses the PHP callable
string form 'name', which PHP resolves in the global function namespace only -- it can never
name a method of the class the registration happens to sit in. The callback resolver routed
the bare name through _resolve_simple_call WITH the enclosing caller_class, so its implicit
$this self-call step matched a same-named method of that class and poisoned the edge, pointing
the callback at the wrong target (and hiding the real global sink).
"""
import os
import tempfile

from parsers.php.function_extractor import FunctionExtractor
from parsers.php.call_graph_builder import CallGraphBuilder


def _build(src: str):
    repo = os.path.realpath(tempfile.mkdtemp())
    p = os.path.join(repo, "plugin.php")
    with open(p, "w") as fh:
        fh.write(src)
    b = CallGraphBuilder(FunctionExtractor(repo).extract_all([p]))
    b.build_call_graph()
    return b


def _all_edges(b):
    return [e for edges in b.call_graph.values() for e in edges]


def test_framework_callback_string_binds_global_not_enclosing_method():
    # add_action sits inside Handler::register; the class ALSO defines a save_post method.
    # The string callback 'save_post' must bind the GLOBAL function (the real sink), not the
    # coincidentally same-named class method.
    b = _build(
        "<?php\n"
        "class Handler {\n"
        "  public function register(){ add_action('save_post', 'save_post'); }\n"
        "  public function save_post(){ echo 'inert method'; }\n"
        "}\n"
        "function save_post(){ system('rm -rf /'); }\n"
    )
    edges = _all_edges(b)
    global_id = next(fid for fid, fd in b.functions.items()
                     if fd.get('name') == 'save_post' and not fd.get('class_name'))
    method_id = next(fid for fid, fd in b.functions.items()
                     if fd.get('name') == 'save_post' and fd.get('class_name'))
    assert global_id in edges, (
        f"string callback 'save_post' must bind the GLOBAL function {global_id}; edges={edges}")
    assert method_id not in edges, (
        f"string callback 'save_post' must NOT bind enclosing class method {method_id}; edges={edges}")


def test_call_user_func_string_binds_global_not_enclosing_method():
    # Same poison via the builtin higher-order path (call_user_func).
    b = _build(
        "<?php\n"
        "class C {\n"
        "  public function go(){ call_user_func('handle'); }\n"
        "  public function handle(){ echo 'inert method'; }\n"
        "}\n"
        "function handle(){ exec('danger'); }\n"
    )
    edges = _all_edges(b)
    global_id = next(fid for fid, fd in b.functions.items()
                     if fd.get('name') == 'handle' and not fd.get('class_name'))
    method_id = next(fid for fid, fd in b.functions.items()
                     if fd.get('name') == 'handle' and fd.get('class_name'))
    assert global_id in edges, f"'handle' must bind GLOBAL {global_id}; edges={edges}"
    assert method_id not in edges, f"'handle' must NOT bind method {method_id}; edges={edges}"


def test_bare_call_binds_global_not_enclosing_method():
    # A-class sibling of the string-callback poison, via the DIRECT-call fallthrough
    # (_resolve_function_call -> _resolve_simple_call at :297). A bare `notify()` inside a
    # class is a GLOBAL function call in PHP, never `$this->notify()`. The implicit-$this
    # step-1 must not poison the edge with the same-named enclosing method (which would hide
    # the real global sink).
    b = _build(
        "<?php\n"
        "class Handler {\n"
        "  public function register(){ notify(); }\n"
        "  public function notify(){ echo 'inert method'; }\n"
        "}\n"
        "function notify(){ system('rm -rf /'); }\n"
    )
    edges = _all_edges(b)
    global_id = next(fid for fid, fd in b.functions.items()
                     if fd.get('name') == 'notify' and not fd.get('class_name'))
    method_id = next(fid for fid, fd in b.functions.items()
                     if fd.get('name') == 'notify' and fd.get('class_name'))
    assert global_id in edges, (
        f"bare call 'notify()' must bind the GLOBAL function {global_id}; edges={edges}")
    assert method_id not in edges, (
        f"bare call 'notify()' must NOT bind enclosing method {method_id}; edges={edges}")


def test_shadowed_framework_dispatcher_binds_global_not_enclosing_method():
    # A framework dispatcher name (add_action) that is SHADOWED by a user-defined global
    # function is treated as a real call and also lands at the :297 fallthrough. It must
    # bind that global user function, not a coincidentally same-named enclosing method.
    b = _build(
        "<?php\n"
        "class Plugin {\n"
        "  public function boot(){ add_action('init', 'x'); }\n"
        "  public function add_action($h, $c){ echo 'inert method'; }\n"
        "}\n"
        "function add_action($h, $c){ system('danger'); }\n"
    )
    edges = _all_edges(b)
    global_id = next(fid for fid, fd in b.functions.items()
                     if fd.get('name') == 'add_action' and not fd.get('class_name'))
    method_id = next(fid for fid, fd in b.functions.items()
                     if fd.get('name') == 'add_action' and fd.get('class_name'))
    assert global_id in edges, (
        f"shadowed 'add_action()' must bind the GLOBAL function {global_id}; edges={edges}")
    assert method_id not in edges, (
        f"shadowed 'add_action()' must NOT bind enclosing method {method_id}; edges={edges}")
