"""GNU nested functions with the same name in different enclosing functions
must NOT collide (PR150-c-nested-fn-collision).

PR #150 descends into function bodies to extract GNU nested functions but built
their func_id as `path:name` without the enclosing-function scope. Two enclosing
functions that each define a same-named nested helper therefore minted the SAME
func_id (`t.c:helper`); `_store_function` treated the second as an ODR-duplicate
(same signature) and dropped it, so one of the two distinct nested definitions was
silently overwritten. The fix qualifies a nested function's func_id with its
enclosing-function scope (`t.c:outer_a.helper`).
"""
import os
import tempfile

from parsers.c.function_extractor import FunctionExtractor


def _extract(filename: str, src: str):
    repo = os.path.realpath(tempfile.mkdtemp())
    with open(os.path.join(repo, filename), "w") as fh:
        fh.write(src)
    return FunctionExtractor(repo).extract_all(files=[filename])["functions"]


def test_same_named_nested_functions_do_not_collide():
    fns = _extract(
        "t.c",
        "int outer_a(int x){\n"
        "    int helper(int y){ return y + 1; }\n"
        "    return helper(x);\n"
        "}\n"
        "int outer_b(int x){\n"
        "    int helper(int y){ return y + 2; }\n"
        "    return helper(x);\n"
        "}\n"
        "int main(){ return outer_a(1) + outer_b(2); }\n",
    )
    helpers = [v for v in fns.values() if v["name"] == "helper"]
    # Both nested helpers must survive as distinct nodes (not collapsed to one).
    assert len(helpers) == 2, (
        f"both nested helper() definitions must be extracted, got {len(helpers)}; keys={list(fns)}"
    )
    # And they must be the two genuinely-different bodies (+1 vs +2), proving no overwrite.
    assert len({h["code"] for h in helpers}) == 2, (
        f"the two nested helpers must keep distinct bodies; keys={list(fns)}"
    )
    # func_ids are scoped by the enclosing function, so both are addressable.
    assert "t.c:outer_a.helper" in fns and "t.c:outer_b.helper" in fns, (
        f"nested func_ids must carry enclosing-function scope; keys={list(fns)}"
    )


def test_same_named_nested_lambdas_do_not_collide():
    """A-class sibling: named lambdas (`auto f = [](){...};`) declared inside two
    different enclosing functions must not collide either. Before the extension,
    `_process_lambda_declaration` built `func_id = path:name` with no enclosing
    scope, so `outer_a`'s and `outer_b`'s same-named lambda minted the SAME
    func_id and one was overwritten."""
    fns = _extract(
        "t.cpp",
        "int outer_a(int x){\n"
        "    auto lam = [](int y){ return y + 1; };\n"
        "    return lam(x);\n"
        "}\n"
        "int outer_b(int x){\n"
        "    auto lam = [](int y){ return y + 2; };\n"
        "    return lam(x);\n"
        "}\n"
        "int main(){ return outer_a(1) + outer_b(2); }\n",
    )
    lams = [v for v in fns.values() if v["name"] == "lam"]
    # Both lambdas must survive as distinct nodes (not collapsed to one).
    assert len(lams) == 2, (
        f"both nested lambda lam definitions must be extracted, got {len(lams)}; keys={list(fns)}"
    )
    # And they must keep the two genuinely-different bodies (+1 vs +2), proving no overwrite.
    assert len({l["code"] for l in lams}) == 2, (
        f"the two nested lambdas must keep distinct bodies; keys={list(fns)}"
    )
    # func_ids are scoped by the enclosing function, so both are addressable.
    assert "t.cpp:outer_a.lam" in fns and "t.cpp:outer_b.lam" in fns, (
        f"lambda func_ids must carry enclosing-function scope; keys={list(fns)}"
    )


def test_nested_lambdas_in_overloaded_enclosers_do_not_collide():
    """FA3: the two enclosing functions have the SAME BARE NAME (`outer`) and
    differ only by overload signature (`int outer(int)` vs `int outer(double)`).
    `_store_function` disambiguates the enclosers themselves, but if the nested
    scope is built from the enclosing function's BARE full_name (`outer`) instead
    of its DISAMBIGUATED id, both same-named nested lambdas mint the identical
    `t.cpp:outer.lam` and one is silently overwritten. The scope must be built
    from the disambiguated enclosing id so the nested lambdas stay distinct."""
    fns = _extract(
        "t.cpp",
        "int outer(int x){\n"
        "    auto lam = [](int y){ return y + 1; };\n"
        "    return lam(x);\n"
        "}\n"
        "int outer(double x){\n"
        "    auto lam = [](int y){ return y + 2; };\n"
        "    return lam((int)x);\n"
        "}\n"
        "int main(){ return outer(1) + outer(2.0); }\n",
    )
    lams = [v for v in fns.values() if v["name"] == "lam"]
    assert len(lams) == 2, (
        f"both nested lambdas inside the overloaded enclosers must survive, "
        f"got {len(lams)}; keys={list(fns)}"
    )
    assert len({l["code"] for l in lams}) == 2, (
        f"the two nested lambdas must keep distinct bodies (+1 vs +2); keys={list(fns)}"
    )


def test_nested_functions_in_overloaded_enclosers_do_not_collide():
    """FA3 sibling: GNU nested functions (not lambdas) inside two overloaded
    enclosers must not collide either — same root cause, same fix path."""
    fns = _extract(
        "t.cpp",
        "int outer(int x){\n"
        "    int helper(int y){ return y + 1; }\n"
        "    return helper(x);\n"
        "}\n"
        "int outer(double x){\n"
        "    int helper(int y){ return y + 2; }\n"
        "    return helper((int)x);\n"
        "}\n"
        "int main(){ return outer(1) + outer(2.0); }\n",
    )
    helpers = [v for v in fns.values() if v["name"] == "helper"]
    assert len(helpers) == 2, (
        f"both nested helpers inside the overloaded enclosers must survive, "
        f"got {len(helpers)}; keys={list(fns)}"
    )
    assert len({h["code"] for h in helpers}) == 2, (
        f"the two nested helpers must keep distinct bodies (+1 vs +2); keys={list(fns)}"
    )
