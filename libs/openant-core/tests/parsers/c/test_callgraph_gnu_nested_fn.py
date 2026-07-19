"""GNU nested functions are extracted (reachability FN fix).

The `function_definition` branch processed the outer function but did not descend into
its body, so a nested `int inner(){...}` (a GNU C extension) was never extracted and the
outer->inner edge was lost.
"""
import os
import tempfile

from parsers.c.function_extractor import FunctionExtractor


def _extract(filename: str, src: str):
    repo = os.path.realpath(tempfile.mkdtemp())
    with open(os.path.join(repo, filename), "w") as fh:
        fh.write(src)
    return FunctionExtractor(repo).extract_all(files=[filename])["functions"]


def test_gnu_nested_function_extracted():
    fns = _extract(
        "n.c",
        "int outer(int x){\n"
        "    int inner(int y){ return y + 1; }\n"
        "    return inner(x);\n"
        "}\n"
        "int main(){ return outer(1); }\n",
    )
    # The nested func_id is scoped by its enclosing function
    # (`n.c:outer.inner`), so it ends with `.inner`, not `:inner`
    # (PR150-c-nested-fn-collision).
    assert any(k.endswith(":inner") or k.endswith(".inner") for k in fns), (
        f"GNU nested function inner() must be extracted; funcs={list(fns)}"
    )
    # sanity: the outer functions are still present (no regression to normal extraction)
    assert any(k.endswith(":outer") for k in fns) and any(k.endswith(":main") for k in fns), (
        f"outer/main must still be extracted; funcs={list(fns)}"
    )
