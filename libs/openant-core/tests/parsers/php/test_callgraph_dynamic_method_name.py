"""Literal-bound dynamic method `$this->$m()` resolves (reachability FN fix).

`$m = "danger"; $this->$m()` invokes danger(), but the dynamic-name member call was
dropped. Determinate-only: resolve when $m has a SINGLE literal binding in the method;
a parameter / runtime / interpolated name stays unresolved (0 phantom).
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


def _edges(b, suffix):
    keys = [k for k in b.call_graph if k.endswith(suffix)]
    return [e for k in keys for e in b.call_graph[k]]


_SRC = (
    "<?php\n"
    "class C {\n"
    "  public function danger($x){ system($x); }\n"
    "  public function safe(){ return 1; }\n"
    "  public function runLiteral(){ $m = \"danger\"; return $this->$m(); }\n"
    "  public function runTainted($x){ return $this->$x(); }\n"
    "  public function runRuntime(){ $m = $_GET['x']; return $this->$m(); }\n"
    "  public function runInterp($p){ $m = \"dang$p\"; return $this->$m(); }\n"
    "}\n"
)


def test_literal_dynamic_method_resolves():
    b = _build(_SRC)
    assert any(e.endswith(":C.danger") for e in _edges(b, ":C.runLiteral")), (
        f"$m=\"danger\"; $this->$m() must resolve to C.danger; got {_edges(b, ':C.runLiteral')}"
    )


def test_nondeterminate_dynamic_names_stay_unresolved():
    b = _build(_SRC)
    for caller in (":C.runTainted", ":C.runRuntime", ":C.runInterp"):
        assert not any("C.danger" in e or "C.safe" in e for e in _edges(b, caller)), (
            f"{caller}: a param/runtime/interpolated dynamic name must not resolve "
            f"(0 phantom); got {_edges(b, caller)}"
        )
