"""Framework registration functions dispatch to their callback (reachability FN fix).

add_action/add_filter/register_shutdown_function/set_error_handler/spl_autoload_register
register a callback that PHP later invokes. The callback-argument resolver only fired for
PHP builtins (call_user_func, array_map, ...); these framework dispatchers are not builtins,
so their string/array callback target was dropped -> the registered handler (and its sink)
was unreachable.
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


def test_framework_callbacks_resolved():
    b = _build(
        "<?php\n"
        "add_action('init', 'cleanup');\n"
        "add_filter('the_content', 'filter_it');\n"
        "register_shutdown_function('shutdown_task');\n"
        "function cleanup(){ system('x'); }\n"
        "function filter_it($c){ system($c); return $c; }\n"
        "function shutdown_task(){ exec('danger'); }\n"
    )
    edges = _all_edges(b)
    for target in ("cleanup", "filter_it", "shutdown_task"):
        assert any(e.endswith(":" + target) for e in edges), (
            f"framework callback '{target}' not registered as an edge; edges={edges}"
        )


def test_framework_callback_unknown_target_no_phantom():
    b = _build("<?php\nadd_action('init', 'does_not_exist');\n")
    assert _all_edges(b) == [], f"unknown callback must invent no edge; edges={_all_edges(b)}"


def test_user_defined_shadow_not_treated_as_dispatcher():
    # Precision: if the app defines its OWN add_action, a call to it must bind the
    # user function, not be mis-resolved as a WordPress hook dispatcher.
    b = _build(
        "<?php\n"
        "function add_action($a, $b){ real_impl(); }\n"
        "function real_impl(){ system('z'); }\n"
        "add_action('x', 'y');\n"
    )
    edges = _all_edges(b)
    assert any(e.endswith(":add_action") for e in edges), (
        f"call to user-defined add_action must bind the user function; edges={edges}"
    )
    assert not any(e.endswith(":y") for e in edges), (
        f"must not treat user add_action's 2nd arg as a callback; edges={edges}"
    )
