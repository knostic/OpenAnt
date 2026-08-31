"""#318: typed receivers resolve inherited methods (the C suite's floor).

The Python call-graph builder resolves an inherited method when the receiver is ``self`` or
``super()`` (two BFS walks over ``self.classes[...]['bases']`` exist) but drops the same call
when the receiver is a locally-constructed instance (M1: ``s = Sub(); s.inherited()``) or the
class name (M2: ``Sub.inherited_cm()``) — the typed-receiver path simply never consults the
bases. The base data is recorded; the receiver's type is inferred; the resolution is missing.

The project already decided the required behaviour in C (``test_call_graph_builder_dispatch.py``
Bug [30], the SOUND FLOOR): walk UP the base-class chain to the first ancestor that defines the
method, same-file, own-first (the most-derived definition wins), no derived-override fan-out,
no ancestor defining the method => no edge.

The reachability direction: a method whose only callers use a typed receiver gets an empty
caller set and is PRUNED while its caller is kept — false negatives, with nothing in the
output distinguishing "not called" from "call not recognised".
"""
import sys
import tempfile
from pathlib import Path

CORE = str(Path(__file__).resolve().parents[3])  # libs/openant-core
if CORE not in sys.path:
    sys.path.insert(0, CORE)

from parsers.python.function_extractor import FunctionExtractor  # noqa: E402
from parsers.python.call_graph_builder import CallGraphBuilder  # noqa: E402


def _build(src: str, filename: str = "app.py"):
    """The real pipeline: extract from a temp dir + build the graph (the
    symmetry test's own harness pattern)."""
    d = tempfile.mkdtemp()
    (Path(d) / filename).write_text(src)
    builder = CallGraphBuilder(FunctionExtractor(d).extract_all())
    builder.build_call_graph()
    return builder


def _edges_to(builder, caller: str):
    """A method's key carries its class (app.py:Sub.via_self); a module
    function's is bare (app.py:f). Match either shape for the caller name."""
    edges = [c for key, callees in builder.call_graph.items()
             if key.startswith("app.py:")
             and (key.rsplit(":", 1)[1].endswith("." + caller)
                  or key == f"app.py:{caller}")
             for c in callees]
    return sorted(edges)


_FIVE_RECEIVERS = '''
class Base:
    def inherited_method(self): return 1
    @classmethod
    def inherited_cm(cls): return 2

class Sub(Base):
    def own_method(self): return 3
    def via_self(self):   return self.inherited_method()
    def via_super(self):  return super().inherited_method()
    def via_self_cm(self): return self.inherited_cm()

def via_local_instance():
    s = Sub()
    return s.inherited_method()      # M1

def via_class_name():
    return Sub.inherited_cm()        # M2

def control_own():
    s = Sub()
    return s.own_method()            # control: same shape, non-inherited
'''


def test_m1_local_instance_inherited_method_resolves():
    """M1 — the issue's executed repro shape: a locally-constructed receiver
    calling a method declared only on a same-file base."""
    b = _build(_FIVE_RECEIVERS)
    assert "app.py:Base.inherited_method" in _edges_to(b, "via_local_instance"), (
        _edges_to(b, "via_local_instance"))


def test_m2_class_name_inherited_classmethod_resolves():
    """M2 — the class-name receiver: Sub.inherited_cm() must resolve like
    self.inherited_cm() does."""
    b = _build(_FIVE_RECEIVERS)
    assert "app.py:Base.inherited_cm" in _edges_to(b, "via_class_name"), (
        _edges_to(b, "via_class_name"))


def test_control_and_existing_paths_unchanged():
    """The control (own method, same receiver shape) and the already-working
    self/super paths keep resolving."""
    b = _build(_FIVE_RECEIVERS)
    assert "app.py:Sub.own_method" in _edges_to(b, "control_own")
    assert "app.py:Base.inherited_method" in _edges_to(b, "via_self")
    assert "app.py:Base.inherited_method" in _edges_to(b, "via_super")
    assert "app.py:Base.inherited_cm" in _edges_to(b, "via_self_cm")


_C_GUARDS = '''
class Base:
    def m(self): return 1
    def only_base(self): return 1

class Mid(Base):
    def m(self): return 2        # the nearest ancestor override

class Over(Mid):
    def m(self): return 3        # the derived override

class NoOver(Mid):
    pass

class Deep(Base):
    pass

class Base2:
    def unrelated(self): return 1

class Orphan(Base2):
    def only_orphan(self): return 1

def call_over():
    o = Over()
    return o.m()

def call_noover():
    n = NoOver()
    return n.m()

def call_deep():
    d = Deep()
    return d.m()

def call_orphan_unrelated():
    o = Orphan()
    return o.missing_method()     # no ancestor defines it
'''


def test_override_resolves_to_derived():
    """The C guard: the most-derived definition wins (the derived override,
    not the base's)."""
    b = _build(_C_GUARDS)
    assert "app.py:Over.m" in _edges_to(b, "call_over")


def test_no_override_resolves_to_nearest_ancestor():
    """The C guard: an un-overridden method resolves to the nearest ancestor
    that defines it (Mid, not Base)."""
    b = _build(_C_GUARDS)
    assert "app.py:Mid.m" in _edges_to(b, "call_noover")


def test_deep_chain_resolves_to_defining_ancestor():
    b = _build(_C_GUARDS)
    assert "app.py:Base.m" in _edges_to(b, "call_deep")


def test_no_ancestor_defining_method_emits_no_edge():
    """The C guard: no ancestor defining the method => NO edge (not a
    name-based fallback — that would emit false edges)."""
    b = _build(_C_GUARDS)
    assert _edges_to(b, "call_orphan_unrelated") == [], _edges_to(b, "call_orphan_unrelated")


def test_cross_file_typed_receiver_still_resolves():
    """The existing cross-file simple-name single-match path (a typed
    receiver whose class lives in another file) must keep working — the
    same-file base walk is ADDITIONAL, not a replacement."""
    src_a = """
class Remote:
    def remote_method(self): return 1
"""
    src_b = """
def local_call():
    r = Remote()
    return r.remote_method()
"""
    d = tempfile.mkdtemp()
    (Path(d) / "a.py").write_text(src_a)
    (Path(d) / "b.py").write_text(src_b)
    b = CallGraphBuilder(FunctionExtractor(d).extract_all())
    b.build_call_graph()
    assert "a.py:Remote.remote_method" in sorted(
        b.call_graph.get("b.py:local_call", []))


_SHADOWING = '''
class Base:
    def bar(self): return 1
class Foo(Base):
    pass
class v:                      # a class whose name shadows the local below
    def bar(self): return 2
def f():
    v = Foo()
    return v.bar()
'''


def test_shadowing_redirected_to_the_right_callee():
    """The issue's own correction: M1 is not purely additive — today the
    fall-through to _resolve_module_call binds the LOCAL-shadowed class name
    (the wrong callee: the class v, while the receiver is a Foo). The base
    walk REDIRECTS the edge to Base.bar."""
    b = _build(_SHADOWING)
    edges = _edges_to(b, "f")
    assert "app.py:Base.bar" in edges, edges
    assert "app.py:v.bar" not in edges, edges


# ---------------------------------------------------------------------------
# the need-check additions: the empty subclass, the annotated receiver, the
# three additional edge families, the approximations documented
# ---------------------------------------------------------------------------

_EMPTY_SUBCLASS = """
class BaseConfig:
    @classmethod
    def load(cls): return 1

class Config(BaseConfig):
    pass                          # no own methods — the most common M2 shape

def f():
    return Config.load()
"""


def test_m2_method_less_subclass_resolves():
    """The need-check's blocking finding: the M2 gate keyed on
    methods_by_class, so a method-less subclass (``class Config(Base):
    pass``) never reached the base walk. The gate now keys on the class
    index."""
    b = _build(_EMPTY_SUBCLASS)
    assert "app.py:BaseConfig.load" in _edges_to(b, "f"), _edges_to(b, "f")


_ANNOTATED = """
class Base:
    def inherited(self): return 1
class Sub(Base):
    pass

def g(s: Sub):
    return s.inherited()         # an annotated-parameter receiver, inherited
"""


def test_annotated_receiver_inherited():
    """#309 composition: the annotated receiver routes through the same
    _resolve_class_method; the base walk makes its INHERITED calls resolve
    (the #309 suite covered only own methods)."""
    b = _build(_ANNOTATED)
    assert "app.py:Base.inherited" in _edges_to(b, "g"), _edges_to(b, "g")


_EXTRA_FAMILIES = """
class Base:
    def __init__(self): self.x = 1
    def __call__(self): return 1
    @property
    def p(self): return 2

class Sub(Base):
    pass

def make():
    s = Sub()                    # the inherited ctor
    return s

def call_it(s: Sub):
    return s()                   # the inherited __call__

def read_p(s: Sub):
    return s.p                   # the inherited @property read
"""


def test_inherited_ctor_resolves():
    """The need-check's disclosure: the fix's reach is wider than M1/M2 —
    the constructor fallback (``Sub()`` with no own ``__init__``) now binds
    the inherited ``Base.__init__``."""
    b = _build(_EXTRA_FAMILIES)
    assert "app.py:Base.__init__" in _edges_to(b, "make"), _edges_to(b, "make")


def test_inherited_dunder_call_resolves():
    b = _build(_EXTRA_FAMILIES)
    assert "app.py:Base.__call__" in _edges_to(b, "call_it"), _edges_to(b, "call_it")


def test_inherited_property_read_resolves():
    """The #309 property-read path with an INHERITED @property."""
    b = _build(_EXTRA_FAMILIES)
    assert "app.py:Base.p" in _edges_to(b, "read_p"), _edges_to(b, "read_p")


_DIAMOND = """
class X:
    def m(self): return 1
class A(X):
    pass
class B:
    def m(self): return 2
class C(A, B):
    pass

def call_c():
    c = C()
    return c.m()
"""


def test_diamond_documents_the_bfs_choice():
    """The documented approximation (shared with the self walk): the FIFO
    BFS is not the C3 MRO — pinned as the CURRENT semantics so a future MRO
    change is a conscious decision."""
    b = _build(_DIAMOND)
    edges = _edges_to(b, "call_c")
    assert edges and all(e in ("app.py:B.m", "app.py:X.m") for e in edges), edges


_DOTTED = """
class Base:
    def m(self): return 1
class Sub(ext.Base):
    pass

def call_sub():
    s = Sub()
    return s.m()
"""


def test_dotted_external_base_documented():
    """The documented shared caveat (the self walk's own): ``class
    Sub(ext.Base)`` splits to the simple name ``Base`` and mis-links a
    same-file unrelated ``Base``. Pinned as CURRENT semantics."""
    b = _build(_DOTTED)
    edges = _edges_to(b, "call_sub")
    assert "app.py:Base.m" in edges, edges


# ---------------------------------------------------------------------------
# wave round-1: the hijack/phantom guards, the floor's negative halves, the
# ordering pin, the subscripted bases
# ---------------------------------------------------------------------------

def test_function_local_class_does_not_hijack_import(tmp_path):
    """Wave r1 (A#1): a function-local ``class Foo(Base)`` is keyed at file
    scope, and the walk (ahead of the cross-file match) bound the local
    Base instead of the imported namesake. The guard: a function-local
    class must not fire the walk — the cross-file match stays
    authoritative (the module-level binding at any other call site is
    the IMPORT)."""
    (tmp_path / "x.py").write_text(
        "class Foo:\n"
        "    def m(self): return 0\n")
    (tmp_path / "app.py").write_text(
        "from x import Foo\n"
        "class Base:\n"
        "    def m(self): return 1\n"
        "def maker():\n"
        "    class Foo(Base): pass\n"
        "    return Foo\n"
        "def f():\n"
        "    v = Foo()\n"
        "    return v.m()      # the runtime callee: x.Foo.m\n")
    b = CallGraphBuilder(FunctionExtractor(str(tmp_path)).extract_all())
    b.build_call_graph()
    edges = sorted(b.call_graph.get("app.py:f", []))
    assert "x.py:Foo.m" in edges, edges
    assert "app.py:Base.m" not in edges, edges


_M2_PHANTOM = """
class Base: pass
class Foo(Base): pass
class VBase:
    def bar(self): return 9
class v(VBase): pass

def f():
    v = Foo()
    return v.bar()          # the typed chain has no bar
"""


def test_m2_phantom_variable_named_like_a_class():
    """Wave r1 (A#2): the widened M2 gate admitted ANY same-file class name —
    a LOCAL VARIABLE named ``v`` with a class ``v`` in the file fabricated an
    edge to VBase.bar. The guard: a receiver that is a known local variable
    is not a class-name reference."""
    b = _build(_M2_PHANTOM)
    assert _edges_to(b, "f") == [], _edges_to(b, "f")


_FLOOR_NEGATIVE = """
class Base:
    def m(self): return 1
class Derived(Base):
    def m(self): return 2          # the override

def base_typed():
    b = Base()
    return b.m()                   # must resolve to Base.m, NOT Derived.m
"""


def test_base_typed_receiver_does_not_fan_out_to_derived():
    """Wave r1 (C#3): the floor's CENTRAL case had no fixture — a receiver
    of the BASE type must not link the derived override (the no-fan-out
    half; the C suite's paired assertion, now with its negative)."""
    b = _build(_FLOOR_NEGATIVE)
    assert _edges_to(b, "base_typed") == ["app.py:Base.m"], _edges_to(b, "base_typed")


def test_override_guard_pairs_the_negative():
    """Wave r1 (C#2): the override pins dropped the C suite's paired
    negative halves — an implementation fanning out to EVERY ancestor
    definition passed. Exact pins now."""
    b = _build(_C_GUARDS)
    assert _edges_to(b, "call_over") == ["app.py:Over.m"], _edges_to(b, "call_over")
    assert _edges_to(b, "call_noover") == ["app.py:Mid.m"], _edges_to(b, "call_noover")
    assert _edges_to(b, "call_deep") == ["app.py:Base.m"], _edges_to(b, "call_deep")


_ORDERING = """
# a.py: the same-file base
class Base:
    def m(self): return 1
# (the cross-file namesake is in other.py)
class Sub(Base):
    pass

def f():
    s = Sub()
    return s.m()
"""


def test_walk_wins_over_cross_file_namesake(tmp_path):
    """Wave r1 (C#4): the ordering (the walk BEFORE the cross-file match)
    was untested — swap the two blocks and all the other tests still
    passed. The competing shape: a same-file base AND a unique cross-file
    class defining the method — the walk must win."""
    (tmp_path / "other.py").write_text(
        "class Sub:\n"
        "    def m(self): return 9\n")       # a cross-file namesake
    (tmp_path / "app.py").write_text(_ORDERING)
    b = CallGraphBuilder(FunctionExtractor(str(tmp_path)).extract_all())
    b.build_call_graph()
    assert sorted(b.call_graph.get("app.py:f", [])) == ["app.py:Base.m"], (
        sorted(b.call_graph.get("app.py:f", [])))


_SUBSCRIPTED = """
class Base:
    def inherited(self): return 1
class Sub(Base[int]):           # the subscripted Generic idiom
    pass

def f():
    s = Sub()
    return s.inherited()
"""


def test_subscripted_base_resolves():
    """Wave r1 (A#4 + B#2): ``class Sub(Base[int])`` dropped the base
    entirely (bases == []) — the walk AND the self walk were blind on
    generic code. The extractor now unwraps the subscript."""
    b = _build(_SUBSCRIPTED)
    assert _edges_to(b, "f") == ["app.py:Base.inherited"], _edges_to(b, "f")


def test_diamond_pinned_to_the_fifo_semantics():
    """Wave r1 (C#5): the either-answer pin was a tautology — the FIFO
    semantics pinned EXACTLY so a future MRO change is a conscious decision."""
    b = _build(_DIAMOND)
    assert _edges_to(b, "call_c") == ["app.py:B.m"], _edges_to(b, "call_c")


def test_dotted_base_pinned_exactly():
    """Wave r1 (C#6): the approximation pinned exactly (nothing else
    emitted)."""
    b = _build(_DOTTED)
    assert _edges_to(b, "call_sub") == ["app.py:Base.m"], _edges_to(b, "call_sub")


def test_block_wrapped_local_class_does_not_hijack(tmp_path):
    """Wave r2 #1: the function_local flag only covered a DIRECT class child
    of the function body — a block-wrapped one (``if cond: class Foo(Base)``)
    escaped and the hijack shape persisted. The flag now threads through
    _descend_into_blocks."""
    (tmp_path / "x.py").write_text("class Foo:\n    def m(self): return 0\n")
    (tmp_path / "app.py").write_text(
        "from x import Foo\n"
        "class Base:\n"
        "    def m(self): return 1\n"
        "def maker():\n"
        "    if True:\n"
        "        class Foo(Base): pass\n"
        "    return Foo\n"
        "def f():\n"
        "    v = Foo()\n"
        "    return v.m()\n")
    b = CallGraphBuilder(FunctionExtractor(str(tmp_path)).extract_all())
    b.build_call_graph()
    edges = sorted(b.call_graph.get("app.py:f", []))
    assert "x.py:Foo.m" in edges, edges
    assert "app.py:Base.m" not in edges, edges


def test_merge_reconciles_the_function_local_flag(tmp_path):
    """Wave r2 #2: the merge never reconciled the flag — a module-level
    namesake declared AFTER a function-local one inherited function_local
    and its inherited methods went unresolved. The merged flag is ANDed."""
    (tmp_path / "app.py").write_text(
        "class Base:\n"
        "    def m(self): return 1\n"
        "def maker():\n"
        "    class Sub(Base): pass\n"     # the function-local namesake, FIRST
        "    return Sub\n"
        "class Sub(Base):\n"             # the genuine module-level class, SECOND
        "    pass\n"
        "def f():\n"
        "    s = Sub()\n"
        "    return s.m()\n")
    b = CallGraphBuilder(FunctionExtractor(str(tmp_path)).extract_all())
    b.build_call_graph()
    assert sorted(b.call_graph.get("app.py:f", [])) == ["app.py:Base.m"], (
        sorted(b.call_graph.get("app.py:f", [])))


_UNTYPED_PARAM = """
class Base:
    @classmethod
    def m(cls): return 1
class Foo(Base):
    pass

def f(Foo):            # an UNTYPED parameter sharing the class's name
    return Foo.m()
"""


def test_untyped_param_sharing_a_class_name_is_a_variable():
    """Wave r2 #3: the variable guard covered only local_types bindings —
    an untyped parameter (or for-target / with-as) named like a class still
    reached the class branch and fabricated an inherited edge. The guard
    now covers every locally-BOUND name."""
    b = _build(_UNTYPED_PARAM)
    assert _edges_to(b, "f") == [], _edges_to(b, "f")


_NESTED_SCOPE = """
class Foo:
    @classmethod
    def own(cls): return 1

def f():
    def helper(Foo): return Foo     # a nested def's param — NOT the caller's binding
    return Foo.own()                 # the class reference — must resolve
"""


def test_nested_scope_param_does_not_block_the_class_ref():
    """Wave r3 #3: the r2 bound-names collector over-reached (nested
    def/lambda params + comprehension targets + an inverted global) — a
    nested scope's param sharing a CLASS's name blocked the correct
    ``Class.own_method()`` edge (a correct-to-wrong regression). The
    collector is now scoped to the caller's own bindings."""
    b = _build(_NESTED_SCOPE)
    assert _edges_to(b, "f") == ["app.py:Foo.own"], _edges_to(b, "f")


_MERGED_HIJACK = """
class Base:
    def m(self): return 1

def maker():
    class Foo(Base): pass       # the function-local namesake (has the base)
    return Foo

class Foo:                      # the module-level class (no bases)
    pass

def f():
    v = Foo()
    return v.m()                # the module-level Foo has NO base — no edge
"""


def test_merge_does_not_union_local_bases_into_module_class():
    """Wave r3 #4: the bases union + the ANDed flag let the walk fire on the
    strength of the FUNCTION-LOCAL declaration's base for the module-level
    namesake (the hijack, same-file). A function-local declaration's bases
    no longer merge into a module-level namesake."""
    b = _build(_MERGED_HIJACK)
    assert _edges_to(b, "f") == [], _edges_to(b, "f")


_NESTED_ASSIGN = """
class Foo:
    @classmethod
    def own(cls): return 1

def f():
    def helper():
        Foo = 1              # a nested def's LOCAL assignment
    return Foo.own()
"""


def test_nested_assign_does_not_block_the_class_ref():
    """Wave r4 #1: the r3 scoping only gated the nested-def PARAMS — every
    other binding kind inside a nested scope still leaked into the caller's
    bound set, blocking the correct Class.own_method() edge."""
    b = _build(_NESTED_ASSIGN)
    assert _edges_to(b, "f") == ["app.py:Foo.own"], _edges_to(b, "f")


_NESTED_WALRUS_FOR_WITH = """
class Foo:
    @classmethod
    def own(cls): return 1

def f(xs):
    g = lambda: [Foo for Foo in xs]      # a comprehension target
    def h(ys):
        for Foo in ys: pass              # a nested for-target
    def w():
        with open("x") as Foo: pass      # a nested with-as
    return Foo.own()
"""


def test_comprehension_for_with_targets_do_not_block_the_class_ref():
    """Wave r4 #1 (the rest of the family): comprehension targets, nested
    for-targets, nested with-as — all bind in their OWN scopes."""
    b = _build(_NESTED_WALRUS_FOR_WITH)
    assert _edges_to(b, "f") == ["app.py:Foo.own"], _edges_to(b, "f")


_NESTED_DEF_NAME = """
class Foo:
    @classmethod
    def own(cls): return 1

def f():
    def Foo(): return 2        # a nested def NAME — binds in the CALLER's scope
    Foo()
    return Foo.own()
"""


def test_nested_def_name_does_block_the_class_ref():
    """Wave r4 #2: the inverted rule — a nested def's NAME binds in the
    CALLER's scope (unlike its params), so ``Foo.own()`` after ``def Foo()``
    is a reference to the local function, not the class: no class edge."""
    b = _build(_NESTED_DEF_NAME)
    assert "app.py:Foo.own" not in _edges_to(b, "f"), _edges_to(b, "f")


_M2_LOCAL_BINDING = """
class Base:
    def m(self): return 1

def factory():
    class Foo(Base): pass       # the function-local namesake
    return Foo

Foo = factory()                 # a module-level NON-CLASS binding of the name

def f():
    return Foo.m()
"""


def test_m2_function_local_gate_module_level_binding():
    """Wave r4 #4: the M2 path lacked M1's function_local gate — a
    module-level non-class binding of the name plus a function-local
    ``class Foo(Base)`` fabricated the Base.m edge for ``Foo.m()``. The
    gate is mirrored."""
    b = _build(_M2_LOCAL_BINDING)
    assert _edges_to(b, "f") == [], _edges_to(b, "f")


_DEF_IN_FUNC = """
class Base:
    @classmethod
    def inherited(cls): return 1

def maker():
    class Foo(Base):
        @classmethod
        def own(cls): return 2
    Foo.own()            # master resolved this; r4's guard lost it — restored
    return Foo
"""


def test_classmethod_on_a_caller_defined_class_resolves():
    """Wave r5 #1 (a correct-to-wrong regression): a classmethod called BY
    NAME on a class the caller itself defines — master resolved it through
    the class branch; r4's blanket variable-guard skipped the branch and
    the edge vanished. A caller-DEFINED class name is a class reference,
    not a variable."""
    b = _build(_DEF_IN_FUNC)
    assert "app.py:Foo.own" in _edges_to(b, "maker"), _edges_to(b, "maker")


_WALRUS_EXCEPT = """
class Foo:
    @classmethod
    def own(cls): return 1

def f(xs):
    try:
        if (Foo := len(xs)) > 0:     # a walrus at the caller's own level
            pass
    except ValueError as Foo:        # an except-alias at the caller's level
        pass
    return Foo.own()                 # Foo is BOUND here — a variable, no edge
"""


def test_walrus_and_except_alias_bind():
    """Wave r5 #2 (the unpinned rules): a walrus target and an except-alias
    at the caller's own level bind the name — the class reference must NOT
    fire (each scope rule the docstring claims, now actually pinned)."""
    b = _build(_WALRUS_EXCEPT)
    assert "app.py:Foo.own" not in _edges_to(b, "f"), _edges_to(b, "f")


_CLASS_BODY_BINDINGS = """
class Foo:
    @classmethod
    def own(cls): return 1

def f():
    class K:
        Foo = 1           # a CLASS-BODY binding — K's scope, not the caller's
    return Foo.own()
"""


def test_class_body_binding_does_not_block_the_class_ref():
    """Wave r5 #2: a binding inside a nested CLASS body is that class's
    scope, not the caller's."""
    b = _build(_CLASS_BODY_BINDINGS)
    assert _edges_to(b, "f") == ["app.py:Foo.own"], _edges_to(b, "f")


_DEEPER_DEF = """
class Foo:
    @classmethod
    def own(cls): return 1

def f():
    def outer():
        def Foo(): return 2       # a DEEPER def's name — outer's scope, not f's
        return Foo()
    return Foo.own()
"""


def test_deeper_def_name_does_not_block_the_class_ref():
    """Wave r5 #2: a def name two levels down binds in ITS enclosing scope,
    not the caller's."""
    b = _build(_DEEPER_DEF)
    assert "app.py:Foo.own" in _edges_to(b, "f"), _edges_to(b, "f")


_GLOBAL_DECL = """
class Foo:
    @classmethod
    def own(cls): return 1

def f():
    global Foo           # declares Foo NON-local — NOT a caller-local binding
    return Foo.own()
"""


def test_global_declaration_is_not_a_caller_binding():
    """Wave r5 #2: ``global X`` declares the name NON-local — the collector
    deliberately has no ast.Global branch (the docstring's claim, pinned)."""
    b = _build(_GLOBAL_DECL)
    assert "app.py:Foo.own" in _edges_to(b, "f"), _edges_to(b, "f")


_M2_GATE_PIN = """
class Base:
    @classmethod
    def inherited(cls): return 1

def maker():
    class Foo(Base):
        @classmethod
        def own(cls): return 2
    return Foo.inherited()      # the INHERITED classmethod by name — the
                                # defined_here gate exception, not the own-scan
"""


def test_defined_here_walk_inherited_by_name():
    """Wave r6 #1: the defined_here M2 exception was unpinned — the r5
    fixture only exercised the OWN-method scan. The inherited classmethod
    by name inside the defining function resolves through the gated walk."""
    b = _build(_M2_GATE_PIN)
    assert _edges_to(b, "maker") == ["app.py:Base.inherited"], _edges_to(b, "maker")


_M1_CTOR_IN_DEFINING = """
class Base:
    def __init__(self): self.x = 1
    def inherited_method(self): return 1

def maker():
    class Foo(Base):
        pass
    s = Foo()                  # the inherited ctor inside the defining caller
    return s.inherited_method() # M1 inside the defining caller
"""


def test_m1_and_ctor_inside_the_defining_function():
    """Wave r6 #3: the defined-caller exception was wired into M2 only —
    the M1/ctor shapes inside the defining function stayed unresolved
    (master failed too, but the r5 principle holds for both shapes)."""
    b = _build(_M1_CTOR_IN_DEFINING)
    edges = _edges_to(b, "maker")
    assert "app.py:Base.inherited_method" in edges, edges
    assert "app.py:Base.__init__" in edges, edges


_MERGED_LOCAL_NAMESAKES = """
class BaseA: pass
class BaseB:
    @classmethod
    def load(cls): return 1

def a():
    class Foo(BaseA): pass
    return Foo.load()           # walks the MERGED [BaseA, BaseB] — over-seed

def b():
    class Foo(BaseB): pass
    return Foo.load()
"""


def test_merged_local_namesakes_disclosed_overseed():
    """Wave r6 #2: two FUNCTION-LOCAL namesakes merge their bases (the same
    scope) and the defined_here exception walks the union inside either
    defining function — a() never touches BaseB but reaches BaseB.load.
    The OVER-SEED direction (safe per the project's reachability rule),
    disclosed and pinned as CURRENT semantics."""
    b = _build(_MERGED_LOCAL_NAMESAKES)
    assert "app.py:BaseB.load" in _edges_to(b, "a"), _edges_to(b, "a")
    assert "app.py:BaseB.load" in _edges_to(b, "b"), _edges_to(b, "b")


_CALL_PROP_IN_DEFINING = """
class Base:
    def __init__(self): self.x = 1
    def __call__(self): return 1
    @property
    def p(self): return 2

def maker():
    class Foo(Base):
        pass
    s = Foo()
    s()                     # the inherited __call__ inside the defining caller
    return s.p              # the inherited @property read ditto
"""


def test_dunder_call_and_property_inside_the_defining_function():
    """Wave r7 #1: the r6 wiring claim was half true — the __call__ fallback
    and the #309 property-read path never received defined_classes, so both
    stayed unresolved inside the defining caller. Pinned."""
    b = _build(_CALL_PROP_IN_DEFINING)
    edges = _edges_to(b, "maker")
    assert "app.py:Base.__call__" in edges, edges
    assert "app.py:Base.p" in edges, edges


_MATCH_CAPTURE = """
class Foo:
    @classmethod
    def own(cls): return 1

def f(x):
    match x:
        case {"k": Foo}:      # a match-capture at the caller's level
            pass
    return Foo.own()
"""


def test_match_capture_binds_the_name():
    """Wave r7 #2: a MatchAs capture binds like an except-alias — the class
    reference after it is a variable reference, no edge."""
    b = _build(_MATCH_CAPTURE)
    assert "app.py:Foo.own" not in _edges_to(b, "f"), _edges_to(b, "f")


_SELF_SUPER_LOCAL_NAMESAKE = """
class Base:
    def m(self): return 1

class Foo:                 # the module-level namesake (no bases)
    pass

def maker():
    class Foo(Base):       # the function-local namesake (the real base)
        def go(self):
            return self.m()
        def go2(self):
            return super().m()
    return Foo
"""


def test_self_and_super_survive_the_local_namesake():
    """Deep-refute #1 (a correct-to-wrong regression): the r3 merge RESET the
    file-scope bases to the module side's — severing self.m()/super().m()
    inside the function-local class's own methods (the parent's union
    resolved both). The union now survives in all_bases for the self/super
    walks while the file-scope bases stay module-side."""
    b = _build(_SELF_SUPER_LOCAL_NAMESAKE)
    assert "app.py:Base.m" in _edges_to(b, "go"), _edges_to(b, "go")
    assert "app.py:Base.m" in _edges_to(b, "go2"), _edges_to(b, "go2")


_OWN_METHOD_SKIP = """
class Base:
    @classmethod
    def own(cls): return 1

def f(Foo):
    return Foo.own()       # an untyped param — the OWN method is SKIPPED too
"""


def test_bound_receiver_skips_the_own_method_scan_decision():
    """Deep-refute #3 (an FN trade, DECIDED + pinned): for a receiver the
    caller's scope BINDS, the whole class branch is skipped — the own-method
    scan included (the parent's name-based guess resolved it). A variable is
    not the class: the name-based edge is a guess the anti-phantom rule
    rejects; only the TYPED resolution applies."""
    b = _build(_OWN_METHOD_SKIP)
    assert _edges_to(b, "f") == [], _edges_to(b, "f")


_PARAM_CTOR = """
class Base:
    def __init__(self): self.x = 1

def f(Foo):
    return Foo()          # a parameter shadowing the class — not a ctor call
"""


def test_param_named_like_a_class_is_not_a_ctor_call():
    """Deep-refute #2: the ctor fallback lacked the bound-name guard — a
    parameter named like a class fabricated the inherited __init__ edge."""
    b = _build(_PARAM_CTOR)
    assert _edges_to(b, "f") == [], _edges_to(b, "f")
