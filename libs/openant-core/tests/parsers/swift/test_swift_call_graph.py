"""Swift call-graph resolution + regression tests (Sol/Fable review items)."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _helpers import build, edges  # noqa: E402


def test_constructor_call_resolves_to_init(tmp_path):
    """`Point(...)` (callee text `Point`) must resolve to `Point.init` (Fable F1)."""
    _, cg = build(tmp_path, {"P.swift": """
        struct Point { init(x: Int) { seed() } }
        func make() { let p = Point(x: 1) }
    """})
    assert ("make", "Point.init") in edges(cg)


def test_self_dispatch_uses_enclosing_type(tmp_path):
    _, cg = build(tmp_path, {"S.swift": """
        class S { func a() { self.b() } func b() {} }
    """})
    assert ("S.a", "S.b") in edges(cg)


def test_superclass_method_resolves_via_inheritance(tmp_path):
    """A bare/inherited call resolves to a method on the superclass (Fable F3)."""
    _, cg = build(tmp_path, {"H.swift": """
        class Base { func base() {} }
        class Sub: Base { func run() { base() } }
    """})
    assert ("Sub.run", "Base.base") in edges(cg)


def test_protocol_extension_default_dispatch(tmp_path):
    """A conformer's call resolves to a protocol-extension default impl (Fable F3)."""
    _, cg = build(tmp_path, {"P.swift": """
        protocol Greeter { func hello() }
        extension Greeter { func hello() { defaultHello() } }
        func defaultHello() {}
        struct Impl: Greeter {
            func use() { let g: Greeter = self; g.hello() }
        }
    """})
    assert ("Impl.use", "Greeter.hello") in edges(cg)


def test_typed_local_member_dispatch(tmp_path):
    _, cg = build(tmp_path, {"T.swift": """
        struct A { func go() {} }
        struct B { func go() {} }
        func caller() { let a = A(); a.go() }
    """})
    e = edges(cg)
    assert ("caller", "A.go") in e
    assert ("caller", "B.go") not in e, "must not over-connect to B.go"


def test_subscript_access_is_not_a_call(tmp_path):
    """`items[i]` must NOT create an edge to a function named `items` (Fable F9)."""
    _, cg = build(tmp_path, {"S.swift": """
        func items() {}
        func read() { let xs = [1,2,3]; let y = xs[0] }
    """})
    assert ("read", "items") not in edges(cg)


def test_deinit_snippet_no_phantom_self_edge(tmp_path):
    """Standalone `deinit {}` reparses as a call to `deinit`; must be dropped so
    deinit units don't gain phantom deinit->deinit edges (Fable F11)."""
    _, cg = build(tmp_path, {"D.swift": """
        class A { deinit { cleanup() } }
        class B { deinit { teardown() } }
        func cleanup() {}
        func teardown() {}
    """})
    e = edges(cg)
    assert ("A.deinit", "cleanup") in e   # real call kept
    # no deinit -> deinit phantom
    assert not any(caller.endswith("deinit") and callee.endswith("deinit") for caller, callee in e)


def test_function_reference_argument_edge(tmp_path):
    """A known function passed as an argument is a callback target (Fable F13)."""
    _, cg = build(tmp_path, {"C.swift": """
        func handler() {}
        func register(_ cb: () -> Void) {}
        func setup() { register(handler) }
    """})
    assert ("setup", "handler") in edges(cg)


def test_optional_typed_receiver_dispatches(tmp_path):
    """`let x: T?` must still type-dispatch `x.m()` (unwrap optional_type, Fable F5)."""
    _, cg = build(tmp_path, {"O.swift": """
        struct T { func m() {} }
        func f() { let x: T? = nil; x?.m() }
    """})
    assert ("f", "T.m") in edges(cg)


def test_array_typed_var_not_bound_to_element(tmp_path):
    """`let a: [Foo]` must NOT bind `a` to Foo, so `a.append()` does not dispatch
    to a Foo member named append (Fable F5)."""
    _, cg = build(tmp_path, {"A.swift": """
        struct Foo { func append() {} }
        func f() { let a: [Foo] = []; a.append() }
    """})
    assert ("f", "Foo.append") not in edges(cg)


def test_trailing_closure_body_calls_attributed_to_caller(tmp_path):
    """Calls inside a trailing closure are attributed to the enclosing unit."""
    _, cg = build(tmp_path, {"T.swift": """
        func validate() {}
        func run() { doWork { validate() } }
        func doWork(_ f: () -> Void) {}
    """})
    e = edges(cg)
    assert ("run", "validate") in e
    assert ("run", "doWork") in e


def test_ambiguous_bare_call_bounded_fanout(tmp_path):
    """A bare call ambiguous across <=3 unrelated types fans out (recall); a large
    fan-out is dropped (Fable F17 / namespace-leak guard)."""
    # Candidates are CROSS-FILE (so the same-file tier does not short-circuit)
    # and the caller is top-level (no enclosing type). 3 unrelated `handle` ->
    # bounded fan-out keeps all 3.
    _, cg3 = build(tmp_path / "r3", {
        "a.swift": "struct A { func handle() {} }",
        "b.swift": "struct B { func handle() {} }",
        "c.swift": "struct C { func handle() {} }",
        "d.swift": "func dispatch() { handle() }",
    })
    handled = {callee for caller, callee in edges(cg3) if caller == "dispatch"}
    assert handled == {"A.handle", "B.handle", "C.handle"}

    # 4 unrelated `handle` -> gross fan-out dropped.
    _, cg4 = build(tmp_path / "r4", {
        "a.swift": "struct A { func handle() {} }",
        "b.swift": "struct B { func handle() {} }",
        "c.swift": "struct C { func handle() {} }",
        "e.swift": "struct D { func handle() {} }",
        "d.swift": "func dispatch() { handle() }",
    })
    handled4 = {callee for caller, callee in edges(cg4) if caller == "dispatch"}
    assert handled4 == set(), "gross fan-out must drop to avoid namespace leak"


def test_cross_file_builtin_named_method_not_dropped(tmp_path):
    """SW-1 regression: a bare implicit-`self` call to a user method whose name
    collides with a Swift builtin (`filter`) but is declared in a SIBLING file
    (idiomatic type-split-across-extensions) must NOT be silently dropped — else
    the whole subtree behind it goes unreachable and unanalyzed (silent FN)."""
    _, cg = build(tmp_path, {
        "A.swift": "class Repo { func fetch() { filter() } }",
        "B.swift": "extension Repo { func filter() { dangerousSink() } func dangerousSink() {} }",
    })
    e = edges(cg)
    assert ("Repo.fetch", "Repo.filter") in e, "cross-file builtin-named self call dropped"
    assert ("Repo.filter", "Repo.dangerousSink") in e, "subtree must stay reachable"


def test_free_function_builtin_shadow_does_not_over_connect(tmp_path):
    """R2D-2: the SW-1 builtin-bypass must cover METHODS only. A bare stdlib call
    (`max`) must NOT fabricate an edge just because the repo declares a FREE function
    of the same name in another file — that would phantom-edge every stdlib call."""
    _, cg = build(tmp_path, {
        "A.swift": "func process() { let m = max(1, 2) }",
        "B.swift": "func max(_ x: Int, _ y: Int) -> Int { return x }",
    })
    callees = {callee for caller, callee in edges(cg) if caller == "process"}
    assert "max" not in callees and "B.max" not in callees, "stdlib max() phantom-edged to free fn"


def test_builtin_named_method_does_not_phantom_global_call(tmp_path):
    """R3A-3: a repo METHOD named after a bare-callable stdlib GLOBAL (`print`) must NOT
    draw a phantom edge from every bare `print()` call — only collection-method builtins
    (filter/map/...) get the SW-1 implicit-self bypass, not the bare globals."""
    _, cg = build(tmp_path, {
        "A.swift": 'func work() { print("hi") }',
        "B.swift": "class Logger { func print(_ s: String) {} }",
    })
    callees = {callee for caller, callee in edges(cg) if caller == "work"}
    assert "Logger.print" not in callees and "print" not in callees, "bare print() phantom-edged"


def test_actor_methods_extracted_and_call_graphed(tmp_path):
    """`actor` is a first-class container keyword in the extractor but had no fixture.
    An actor's methods must be extracted and their intra-actor call edges built (Swift
    concurrency is common; a missed actor method = a silent unanalyzed unit)."""
    _, cg = build(tmp_path, {"A.swift": """
        actor BankAccount {
            var balance = 0
            func deposit(_ n: Int) { record(n) }
            func record(_ n: Int) { balance += n }
        }
    """})
    e = edges(cg)
    assert ("BankAccount.deposit", "BankAccount.record") in e, "actor-isolated method call edge missing"


def test_same_file_dependency_is_boundaried_out_of_target(tmp_path):
    """R3B-2: a same-file dependency's body must sit AFTER the FILE_BOUNDARY (context),
    not inside the target's 'ANALYZE THIS FUNCTION ONLY' block (split_on_boundary part[0])."""
    from _helpers import extract, CallGraphBuilder, UnitGenerator
    ext = extract(tmp_path, {
        "A.swift": "func target(){ helper() }\nfunc helper(){ danger() }\nfunc danger(){}\n"})
    cg = CallGraphBuilder(ext).build()
    dataset, _ = UnitGenerator(cg, str(tmp_path)).generate(name="s")
    target = [u for u in dataset["units"] if "target" in u["id"]][0]
    primary = target["code"]["primary_code"]
    target_block = primary.split("File Boundary")[0]
    assert "func helper" not in target_block, "same-file dep leaked into the target block"
    assert "File Boundary" in primary
