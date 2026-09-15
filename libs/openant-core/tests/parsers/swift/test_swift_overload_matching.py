"""Regression tests for the constructor/method overload phantom-edge fixes
(experiment findings F1-F4 + P-4). Before these, a `Type(...)` call linked to
EVERY init overload and a typed method call to EVERY same-name overload — ~53% of
edges on the pilot repos were phantom (inflation 2.8-2.95x). The call-site
signature matcher (labels + arity + defaults) narrows to the compatible overloads.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _helpers import build, extract, edges  # noqa: E402


def test_ctor_label_match_selects_one_overload(tmp_path):
    """F1: one `Opt(name:)` call resolves to ONLY the init(name:) overload, not all
    three inits (the dominant phantom-edge class)."""
    _, cg = build(tmp_path, {"a.swift": """
        struct Opt {
            init(name: String) { seedA() }
            init(flag: Bool) { seedB() }
            init(name: String, help: String) { seedC() }
        }
        func seedA(){}; func seedB(){}; func seedC(){}
        func caller() { let o = Opt(name: "x") }
    """})
    ctor_edges = {b for a, b in edges(cg) if a == "caller" and ".init" in b}
    assert ctor_edges == {"Opt.init"}, f"expected only init(name:), got {ctor_edges}"


def test_ctor_default_args_omittable(tmp_path):
    """F7: a defaulted param may be omitted — `C(name:)` matches init(name:parsing:)
    where parsing has a default."""
    _, cg = build(tmp_path, {"a.swift": """
        struct C { init(name: String, parsing: Int = 0) { seed() } }
        func seed() {}
        func f() { let c = C(name: "x") }
    """})
    assert ("f", "C.init") in edges(cg)


def test_method_overload_narrowed_by_labels(tmp_path):
    """F2: a typed-receiver call to an overloaded method links to the matching
    overload only, not every same-name overload."""
    _, cg = build(tmp_path, {"a.swift": """
        struct API {
            func request(url: String) { hitA() }
            func request(url: String, retries: Int) { hitB() }
        }
        func hitA(){}; func hitB(){}
        func caller() { let a = API(); a.request(url: "x") }
    """})
    e = edges(cg)
    # the 1-arg call selects request(url:) — must NOT also link request(url:retries:)
    assert ("caller", "API.request") in e
    reqs = {b for a, b in e if a == "caller" and "request" in b}
    assert len(reqs) == 1, f"expected 1 request overload, got {reqs}"


def test_conformer_fanout_survives_matching(tmp_path):
    """The matcher narrows same-TYPE overloads but must NOT drop conformer fan-out
    (same signature on different types) — that dynamic dispatch is real."""
    _, cg = build(tmp_path, {"a.swift": """
        protocol P { func handle() }
        struct A: P { func handle() { doA() } }
        struct B: P { func handle() { doB() } }
        func doA(){}; func doB(){}
        func dispatch(p: P) { p.handle() }
    """})
    handled = {b for a, b in edges(cg) if a == "dispatch"}
    assert handled == {"A.handle", "B.handle"}, f"conformer fan-out lost: {handled}"


def test_generic_constructor_resolves(tmp_path):
    """F3: `Box<Int>(value:)` parses as constructor_expression — must still edge."""
    _, cg = build(tmp_path, {"a.swift": """
        struct Box<T> { init(value: T) { seed() } }
        func seed() {}
        func f() { let b = Box<Int>(value: 3) }
    """})
    assert ("f", "Box.init") in edges(cg)


def test_nested_type_constructor_resolves(tmp_path):
    """F4: `Outer.Inner(x:)` must resolve to the nested type's init (was [])."""
    _, cg = build(tmp_path, {"a.swift": """
        struct Outer { struct Inner { init(x: Int) { seed() } } }
        func seed() {}
        func f() { let i = Outer.Inner(x: 1) }
    """})
    assert ("f", "Outer.Inner.init") in edges(cg)


def test_super_init_resolves_to_superclass(tmp_path):
    """P-4: `super.init()` must resolve to the SUPERclass's init, never the caller's
    own (subclass) init."""
    _, cg = build(tmp_path, {"a.swift": """
        class Base { init() { baseSeed() } }
        class Sub: Base { init(x: Int) { super.init() } }
        func baseSeed() {}
    """})
    e = edges(cg)
    assert ("Sub.init", "Base.init") in e
    assert ("Sub.init", "Sub.init") not in e


def test_param_defaults_extracted(tmp_path):
    """The extractor records per-param has_default (drives the matcher)."""
    ext = extract(tmp_path, {"a.swift": """
        struct C { init(a: Int, b: Int = 3, c: Int = 4) {} }
    """})
    inits = [f for f in ext["functions"].values() if f["name"] == "init"]
    assert inits
    assert inits[0]["param_defaults"] == [False, True, True]


def test_no_recall_loss_unmatched_falls_back(tmp_path):
    """An unmatched ctor call on a REPO-DECLARED type falls back to all inits
    (recall) rather than dropping the edge — a missed edge would silently prune the
    paid scan."""
    # positional-only call against a labeled-only init: subsequence match fails →
    # fallback keeps the edge because C is repo-declared.
    _, cg = build(tmp_path, {"a.swift": """
        struct C { init(name: String) { seed() } }
        func seed() {}
        func f() { let c = C("x") }
    """})
    assert ("f", "C.init") in edges(cg)


def test_external_type_ctor_no_phantom_fallback(tmp_path):
    """A construction of an EXTERNAL type (repo-EXTENDED, not declared) whose labels
    match no repo extension init emits NO edge — it is the stdlib constructor. On
    security-pcc this killed 12,000 phantom edges (String.init 13025→1026): a stdlib
    `String(format:)` was fanning to all 17 repo `extension String` inits."""
    _, cg = build(tmp_path, {"a.swift": """
        extension String { init(cBuffer: Int) { seed() } }
        func seed() {}
        func f() {
            let a = String(cBuffer: 1)      // matches the repo extension init -> edge
            let b = String(format: "%d", 3) // stdlib ctor, no repo match -> NO edge
        }
    """})
    e = edges(cg)
    assert ("f", "String.init") in e            # the real extension-init call resolves
    # exactly one String.init edge from f (the cBuffer one), not a fan-out
    string_edges = [b for a, b in e if a == "f" and b == "String.init"]
    assert len(string_edges) == 1


def test_bare_name_collision_prefers_same_file(tmp_path):
    """When a bare type name is declared in MANY files with identical signatures
    (SwiftProtobuf's per-message `_StorageClass` — 202 units/30 files), a
    constructor call prefers the SAME-FILE init. Cut protobuf 2.95x→1.41x."""
    files = {}
    for i in range(3):
        files[f"m{i}.swift"] = f"""
            struct Msg{i} {{
                final class Storage {{ init() {{ seed{i}() }} }}
                func make() {{ let s = Storage() }}
            }}
            func seed{i}() {{}}
        """
    _, cg = build(tmp_path, files)
    e = edges(cg)
    # Msg0.make constructs its OWN Storage — must not fan to Msg1/Msg2's Storage.init
    make0_ctor = [b for a, b in e if a == "Msg0.make" and b.endswith("Storage.init")]
    # resolves to a Storage.init, and NOT all three files' Storage.init
    assert len(make0_ctor) == 1


def test_return_type_typing_disambiguates_receiver(tmp_path):
    """A local typed by a factory's unique return type dispatches on that type, not
    the unknown-receiver path (Sol/Fable convergent F6 fix)."""
    _, cg = build(tmp_path, {"a.swift": """
        struct Client { func send() { hit() } }
        struct Other { func send() {} }
        func hit() {}
        func makeClient() -> Client { return Client() }
        func caller() { let c = makeClient(); c.send() }
    """})
    sends = {b for a, b in edges(cg) if a == "caller" and "send" in b}
    assert sends == {"Client.send"}, f"return-type typing failed: {sends}"


def test_underscore_type_ctor_typed(tmp_path):
    """FR-7: an underscore-prefixed generated type (`_Storage()`) is recognised as a
    constructor call (the leading-underscore isupper gap)."""
    _, cg = build(tmp_path, {"a.swift": """
        struct _Storage { init() { seed() } }
        func seed() {}
        func f() { let s = _Storage() }
    """})
    assert ("f", "_Storage.init") in edges(cg)


def test_selector_target_captured(tmp_path):
    """PR-lessons NEW-3: `#selector(handleTap)` target-action edge is captured."""
    _, cg = build(tmp_path, {"a.swift": """
        class C { func setup() { btn.addTarget(self, action: #selector(handleTap)) }
                  @objc func handleTap() { work() } }
        func work() {}
    """})
    assert ("C.setup", "C.handleTap") in edges(cg)


def test_canonical_interface_methods_present(tmp_path):
    """PR-lessons NEW-4 (sibling lockstep): Swift builder has get_dependencies/
    get_callers like the Zig/C builders."""
    from _helpers import CallGraphBuilder, FunctionExtractor, RepositoryScanner  # noqa
    d = str(tmp_path)
    (tmp_path / "a.swift").write_text("func a(){ b() }\nfunc b(){ c() }\nfunc c(){}")
    b = CallGraphBuilder(FunctionExtractor(d, RepositoryScanner(d).scan()).extract())
    b.build_call_graph()
    a_id = [f for f in b.functions if f.endswith(":a")][0]
    deps = {x.split(":", 1)[1] for x in b.get_dependencies(a_id)}
    assert {"b", "c"} <= deps  # transitive callees
    c_id = [f for f in b.functions if f.endswith(":c")][0]
    assert any(x.endswith(":a") for x in b.get_callers(c_id))


def test_unknown_receiver_member_no_enclosing_type_fanout(tmp_path):
    """INV-N2/FR-2: an unknown-receiver member call `base.next()` must NOT fan to
    every unit sharing the caller's bare class_name. Inside SeqA.Iterator.next,
    `base.next()` (base untyped) must not link to SeqB/SeqC's Iterator.next."""
    files = {}
    for i, nm in enumerate(["A", "B", "C", "D"]):
        body = "let x = base.next()" if i == 0 else "work()"
        files[f"{nm}.swift"] = f"struct Seq{nm} {{ struct Iterator {{ func next() {{ {body} }} }} }}"
    files["w.swift"] = "func work() {}"
    _, cg = build(tmp_path, files)
    q = {a: cg["functions"][a]["qualified_name"] for a in cg["functions"]}
    seqa = [a for a in cg["call_graph"] if q.get(a) == "SeqA.Iterator.next"]
    nexts = {q[b] for a in seqa for b in cg["call_graph"][a]
             if cg["functions"].get(b, {}).get("name") == "next"}
    assert nexts == set(), f"unknown-receiver base.next() fanned out: {nexts}"


def test_bare_self_call_still_uses_enclosing_type(tmp_path):
    """Control: a genuine bare call `foo()` inside a type still prefers the enclosing
    type (only unknown-receiver MEMBER calls skip that heuristic)."""
    _, cg = build(tmp_path, {"a.swift": "struct T { func a() { b() } func b() {} }"})
    assert ("T.a", "T.b") in edges(cg)


def test_unknown_receiver_no_uncapped_same_file_fanout(tmp_path):
    """FR-6: an unknown-receiver member call must not fan to all same-name methods in
    the caller's (large) file via the uncapped same-file tier."""
    # one file with a caller making an unknown-receiver call + 5 same-name visit methods
    src = "struct Big {\n  func drive() { v.visit() }\n"
    src += "".join(f"  func visit() {{ s{i}() }}\n" for i in range(5))  # 5 same-file visit (no, same name collides on id)
    src += "}\n" + "".join(f"func s{i}(){{}}\n" for i in range(5))
    _, cg = build(tmp_path, {"a.swift": src})
    # v.visit() unknown receiver -> must not fan to all 5+ same-file visit units (>K -> drop)
    drive = [a for a in cg["call_graph"] if cg["functions"].get(a, {}).get("name") == "drive"]
    visits = {b for a in drive for b in cg["call_graph"].get(a, []) if cg["functions"].get(b, {}).get("name") == "visit"}
    assert len(visits) <= 3, f"same-file uncapped fan-out: {len(visits)} visit edges"


def test_complex_receiver_no_nb1_bypass(tmp_path):
    """Sol-A: a complex-receiver member call (`items[i].load()`) must NOT re-enter the
    caller-locality heuristics and fan across same-bare-named nested types."""
    files = {}
    for i, nm in enumerate(["A", "B", "C", "D"]):
        body = "items[0].load()" if i == 0 else "noop()"
        files[f"{nm}.swift"] = f"struct Box{nm} {{ struct Thing {{ func load() {{ {body} }} }} }}"
    files["w.swift"] = "func noop() {}"
    _, cg = build(tmp_path, files)
    q = {a: cg["functions"][a]["qualified_name"] for a in cg["functions"]}
    loads = {q[b] for a in cg["call_graph"] if q.get(a) == "BoxA.Thing.load"
             for b in cg["call_graph"][a] if cg["functions"].get(b, {}).get("name") == "load"}
    assert loads == set(), f"complex receiver bypassed NB-1: {loads}"


def test_conditional_alias_union(tmp_path):
    """NEW-5: a conditionally-reassigned closure var unions all branch targets."""
    _, cg = build(tmp_path, {"a.swift":
        "func a(){};func b(){};func d(){};func caller(){ var g = a; if cond { g = b } else { g = d }; g() }"})
    al = {cg["functions"][x]["qualified_name"] for a, bs in cg["call_graph"].items()
          if cg["functions"].get(a, {}).get("name") == "caller" for x in bs}
    assert al == {"a", "b", "d"}, f"conditional alias union failed: {al}"


def test_qualified_ctor_filter(tmp_path):
    """FR-3: `Msg1.Storage()` resolves to Msg1's Storage.init only, not all files'."""
    files = {f"m{i}.swift": f"struct Msg{i} {{ struct Storage {{ init() {{ s{i}() }} }} }}\nfunc s{i}(){{}}"
             for i in range(3)}
    files["c.swift"] = "func mk(){ let x = Msg1.Storage() }"
    _, cg = build(tmp_path, files)
    inits = {cg["functions"][b]["qualified_name"] for a, bs in cg["call_graph"].items()
             if cg["functions"].get(a, {}).get("name") == "mk"
             for b in bs if ".init" in cg["functions"][b].get("qualified_name", "")}
    assert inits == {"Msg1.Storage.init"}, f"qualified ctor filter failed: {inits}"


def test_file_scope_stored_closure_extracted(tmp_path):
    """NEW-1: a file-scope stored closure in an ordinary (non-main.swift) file is
    extracted as a unit so its body's calls are visible (was an extraction blackout)."""
    ext = extract(tmp_path, {"Config.swift":
        "func sink(_ x: Int){}\nlet handler: (Int)->Void = { x in sink(x) }\nfunc caller(){ handler(1) }"})
    names = {f["qualified_name"] for f in ext["functions"].values()}
    assert "handler" in names, f"file-scope closure not extracted: {names}"
    _, cg = build(tmp_path, {"Config.swift":
        "func sink(_ x: Int){}\nlet handler: (Int)->Void = { x in sink(x) }\nfunc caller(){ handler(1) }"})
    e = {(cg["functions"][a]["name"], cg["functions"][b]["name"])
         for a, bs in cg["call_graph"].items() for b in bs}
    assert ("handler", "sink") in e and ("caller", "handler") in e


def test_local_var_not_emitted_as_unit(tmp_path):
    """NEW-1 over-emission guard: a LOCAL `let` inside a function body is NOT a
    file-scope global and must not become a unit (top_level gate)."""
    ext = extract(tmp_path, {"a.swift":
        "func mk()->Int{return 0}\nfunc use(_ x:Int){}\nfunc work(){ let localVar = mk(); use(localVar) }"})
    names = {f["qualified_name"] for f in ext["functions"].values()}
    assert "localVar" not in names, f"local var wrongly emitted: {names}"


def test_main_swift_not_double_counted(tmp_path):
    """NEW-1 guard: a main.swift file-scope binding is not emitted twice (top-level
    synthesis already covers it)."""
    ext = extract(tmp_path, {"main.swift": "let x = boot()\nfunc boot(){}"})
    qns = [f["qualified_name"] for f in ext["functions"].values() if f["qualified_name"] in ("<top-level>", "x")]
    assert qns == ["<top-level>"], f"main.swift double-counted: {qns}"


def test_solc_qualified_ctor_narrows_bare_collision(tmp_path):
    """Sol-C: `let it = SeqA.Iterator(); it.next()` dispatches to SeqA.Iterator.next
    ONLY — a `let x = Outer.Inner()` receiver carries canonical identity that narrows
    the bare-class_name collision with an unrelated SeqB.Iterator.next."""
    _, cg = build(tmp_path, {
        "a.swift": ("enum SeqA { struct Iterator { func next() { sinkA() } } }\n"
                    "func sinkA() {}\n"
                    "func drive() { let it = SeqA.Iterator(); it.next() }\n"),
        "b.swift": ("enum SeqB { struct Iterator { func next() { sinkB() } } }\n"
                    "func sinkB() {}\n"),
    })
    e = edges(cg)
    assert ("drive", "SeqA.Iterator.next") in e
    assert ("drive", "SeqB.Iterator.next") not in e, "Sol-C phantom cross-type edge"


def test_solc_var_reassign_conformer_keeps_both(tmp_path):
    """Recall floor (Fable case 1): a `var` reassigned across two conformers has BOTH
    edges genuine — the let-only hint must NOT fire, so both survive."""
    _, cg = build(tmp_path, {
        "a.swift": ("protocol IterP { func next() }\n"
                    "struct SeqA { struct Iterator: IterP { func next() { sinkA() } } }\n"
                    "func sinkA() {}\n"
                    "func drive(cond: Bool) {\n"
                    "    var it: IterP = SeqA.Iterator()\n"
                    "    if cond { it = SeqB.Iterator() }\n"
                    "    it.next()\n"
                    "}\n"),
        "b.swift": ("struct SeqB { struct Iterator: IterP { func next() { sinkB() } } }\n"
                    "func sinkB() {}\n"),
    })
    e = edges(cg)
    assert ("drive", "SeqA.Iterator.next") in e and ("drive", "SeqB.Iterator.next") in e


def test_solc_protocol_ext_default_kept_by_recall_floor(tmp_path):
    """Recall floor (Fable case 2): when `next` is a protocol-EXTENSION default (not on
    the concrete Inner type), the qualified hint's subset is empty -> keep the full bare
    set so the real P.next edge is never dropped."""
    _, cg = build(tmp_path, {
        "a.swift": ("protocol P { }\n"
                    "extension P { func next() { sinkP() } }\n"
                    "func sinkP() {}\n"
                    "struct SeqA { struct Iterator: P {} }\n"
                    "func drive() { let it: P = SeqA.Iterator(); it.next() }\n"),
    })
    e = edges(cg)
    assert ("drive", "P.next") in e, "recall floor dropped the protocol-extension default"


def test_sole_incompatible_samefile_no_block_compatible_crossfile(tmp_path):
    """Sol-E: a same-file `helper(x:)` incompatible with the call `helper(y:1)` must
    not block the compatible cross-file `helper(y:)` — else `drive` cannot reach
    `sink` (reachable only through the correct overload)."""
    _, cg = build(tmp_path, {
        "a.swift": "func helper(x: Int) {}\nfunc drive() { helper(y: 1) }\n",
        "b.swift": "func helper(y: Int) { sink() }\nfunc sink() {}\n",
    })
    fns, g = cg["functions"], cg["call_graph"]
    drive = next(i for i, f in fns.items() if f["name"] == "drive")
    reach, stack = set(), [drive]
    while stack:
        for v in g.get(stack.pop(), []):
            if v not in reach:
                reach.add(v); stack.append(v)
    assert "sink" in {fns[r]["name"] for r in reach}, \
        "Sol-E: compatible cross-file helper(y:)->sink not reached"


def test_c1_uppercase_enum_case_not_mistyped(tmp_path):
    """C1 (Fable): `let r = Result2.Success(1)` is an enum-case construction, not an
    `Outer.Inner()` ctor — must not type `r` as the nonexistent type `Success` and
    dead-end `r.handle()`."""
    _, cg = build(tmp_path, {"a.swift":
        "enum Result2 { case Success(Int); case Failure(String); func handle() { sink() } }\n"
        "func sink() {}\nfunc caller() { let r = Result2.Success(1); r.handle() }\n"})
    assert ("caller", "Result2.handle") in edges(cg)


def test_c2_qualified_hint_narrows_after_signature_matching(tmp_path):
    """C2 (Fable): `let v = Outer2.Inner(); v.m()` dispatches to the inherited,
    arity-compatible Base.m — not the arity-incompatible Inner.m(x:) that a name-only
    qualified filter (applied before overload matching) would wrongly keep."""
    _, cg = build(tmp_path, {"a.swift":
        "class Base { func m() { sink3() } }\nfunc sink3() {}\n"
        "class Outer2 { class Inner: Base { func m(x: Int) { } } }\n"
        "func caller3() { let v = Outer2.Inner(); v.m() }\n"})
    e = edges(cg)
    assert ("caller3", "Base.m") in e and ("caller3", "Outer2.Inner.m") not in e


def test_e_variadic_samefile_kept_over_crossfile_phantom(tmp_path):
    """E (Fable): a variadic same-file `process(Int...)` fails _sig_compatible's arity
    bound but is the real target of `process(1,2,3)`; the label-only fall-through gate
    must keep it (reach sink2), not redirect to a cross-file String overload."""
    _, cg = build(tmp_path, {
        "a.swift": "func process(_ values: Int...) { sink2() }\nfunc sink2() {}\nfunc caller2() { process(1, 2, 3) }\n",
        "b.swift": "func process(_ s: String, _ t: String = \"x\", _ u: String = \"y\") { }\n",
    })
    fns, g = cg["functions"], cg["call_graph"]
    c2 = next(i for i, f in fns.items() if f["name"] == "caller2")
    reach, st = set(), [c2]
    while st:
        for v in g.get(st.pop(), []):
            if v not in reach:
                reach.add(v); st.append(v)
    assert "sink2" in {fns[r]["name"] for r in reach}, "E: variadic same-file process dropped"
