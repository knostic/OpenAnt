"""#705: the try/except-ImportError shim gives one name two resolutions.

PR #441 wired the same-file base walk into every typed-receiver path and
disclosed the shim shape verbatim: "a module-level fallback class + an import
gives M1 the fallback and M2 the import (two answers for one name;
both-hit-emit-both is the deferred refinement)". The refinement is this issue.

The repro (the issue's own, executed at filing): a module that both imports
``Thing`` (under try/except ImportError) and defines a fallback class of that
name. The typed-receiver path (M1: ``t = Thing(); t.go()``) binds the LOCAL
fallback class; the class-name path (M2: ``Thing.go(None)``) binds the IMPORT.
Each caller reached exactly one target and they DISAGREED — at parse time the
parser cannot know which branch of the shim runs, so one of the two edges was
always a false negative.

The fix: when a receiver name carries BOTH a same-file class record AND an
import record in the caller's file, emit BOTH edges (the over-seed direction —
the repo's own reachability-safety rule; the precision cost is one extra edge
per shimmed name). The BOTH-records condition is the guard: a name with one
record NEVER fans out (the negative controls below). The hook fires EVEN WHEN
the primary abstained — the dominant real-world shim's optional dependency is
EXTERNAL (nothing in-repo to resolve), and the fallback's edge must still be
emitted (the fable-r1 F1 catch). The guard carries the #318 family's
function_local exclusion (a plain import + a function-local namesake is not a
shim — F2) and the bound_names abstention (a shadowed receiver is a variable —
F5).

DISCLOSED SIBLING LIMITS (the one-answer shapes this fix does NOT touch,
named by the fable-r1 F3/F4 catch): the CONSTRUCTOR edge on a dual name stays
one-answer (``Thing()`` binds the local fallback's __init__; the import's is
never emitted); the FUNCTION shim (``from x import go`` + a local ``def go``)
stays one-answer (the local def wins, the import never consulted).
"""

import os
import sys
import tempfile
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.python.function_extractor import FunctionExtractor  # noqa: E402
from parsers.python.call_graph_builder import CallGraphBuilder  # noqa: E402

# the prod module directly — the witness screen's channel (the UNALIASED
# import; an asname binds the package)
from parsers.python import call_graph_builder  # noqa: E402

assert call_graph_builder.CallGraphBuilder is CallGraphBuilder  # the prod class


def _repo(files: dict) -> str:
    d = tempfile.mkdtemp()
    for rel, src in files.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(src)
    return d


def _graph(repo: str) -> CallGraphBuilder:
    b = CallGraphBuilder(FunctionExtractor(repo).extract_all())
    b.build_call_graph()
    return b


APP = (
    'try:\n'
    '    from ext_pkg.thing import Thing\n'
    'except ImportError:\n'
    '    class Thing:\n'
    '        def go(self):\n'
    '            return 1\n'
    '\n'
    'def m1():\n'
    '    t = Thing()\n'
    '    return t.go()\n'
    '\n'
    'def m2():\n'
    '    return Thing.go(None)\n'
)
EXT_THING = 'class Thing:\n    def go(self):\n        return 2\n'
FILES = {"app.py": APP, "ext_pkg/__init__.py": "", "ext_pkg/thing.py": EXT_THING}


def _edges(b, caller):
    fid = next(k for k in b.functions if k.endswith(":" + caller))
    return sorted(t for t in b.call_graph.get(fid, []))


# --- the falsifier: BOTH branches receive the call edge ---

def test_shim_typed_receiver_reaches_both_branches():
    """M1 (``t = Thing(); t.go()``): the primary resolves the LOCAL fallback;
    the import branch's edge is ALSO emitted — the #441 deferred refinement."""
    b = _graph(_repo(FILES))
    assert call_graph_builder.CallGraphBuilder is not None
    e = _edges(b, "m1")
    assert "app.py:Thing.go" in e, f"the local fallback edge missing: {e}"
    assert "ext_pkg/thing.py:Thing.go" in e, f"the import edge missing: {e}"


def test_shim_class_name_form_reaches_both_branches():
    """M2 (``Thing.go(None)``): the primary resolves the IMPORT; the local
    fallback branch's edge is ALSO emitted."""
    assert call_graph_builder.CallGraphBuilder is CallGraphBuilder  # the prod class
    b = _graph(_repo(FILES))
    e = _edges(b, "m2")
    assert "app.py:Thing.go" in e, f"the local fallback edge missing: {e}"
    assert "ext_pkg/thing.py:Thing.go" in e, f"the import edge missing: {e}"


# --- the negative controls: one record NEVER fans out ---

def test_external_import_shim_class_name_form_gets_the_fallback_edge():
    """The fable-r1 F1 catch, pinned: the DOMINANT real-world shim has an
    EXTERNAL optional dependency (the import resolves nothing in-repo) — the
    class-name form's primary abstains, and the hook must STILL fire so the
    fallback class's edge is emitted (gating on ``if resolved:`` starved
    exactly this shape, the false-negative direction the repo rule calls
    worst)."""
    assert hasattr(call_graph_builder.CallGraphBuilder,
                   "_resolve_shim_dual_branches"), (
        "the dual-branch emitter is missing from the prod builder")
    src = (
        'try:\n'
        '    from numpy.thing import Thing\n'
        'except ImportError:\n'
        '    class Thing:\n'
        '        def go(self):\n'
        '            return 1\n'
        '\n'
        'def m2():\n'
        '    return Thing.go(None)\n'
    )
    b = _graph(_repo({"app.py": src}))
    e = _edges(b, "m2")
    assert e == ["app.py:Thing.go"], (
        f"the external-import shim's fallback edge missing: {e}")


def test_function_local_namesake_is_not_a_shim():
    """The fable-r1 F2 catch, pinned: a plain import + a FUNCTION-LOCAL
    class of the same name is NOT a shim (the local class is not an
    alternate binding of the module name) — the dual emission must not fan
    out to it (#318's family gate, mirrored)."""
    src = (
        'from ext_pkg.thing import Thing\n'
        '\n'
        'def maker():\n'
        '    class Thing:\n'
        '        def go(self):\n'
        '            return 1\n'
        '    return Thing\n'
        '\n'
        'def m2():\n'
        '    return Thing.go(None)\n'
    )
    b = _graph(_repo(FILES | {"app.py": src}))
    e = _edges(b, "m2")
    # the NON-defining caller: the module-level binding is unambiguously the
    # import — the function-local class must NOT receive the edge. (Inside
    # the DEFINING caller the name binds the local class and the dual
    # over-seed applies — the #318 defining-caller exception, disclosed.)
    assert e == ["ext_pkg/thing.py:Thing.go"], (
        f"the function-local namesake fanned out at a non-defining caller: {e}")


def test_bound_name_shadowing_a_dual_name_does_not_fan_out():
    """The fable-r1 F5 catch, pinned: a receiver the caller's own scope
    BINDS (a parameter shadowing the dual name) is a variable, not a
    class-name reference — no fan-out (#318 r5's rule, mirrored)."""
    src = (
        'try:\n'
        '    from ext_pkg.thing import Thing\n'
        'except ImportError:\n'
        '    class Thing:\n'
        '        def go(self):\n'
        '            return 1\n'
        '\n'
        'def m2(Thing):\n'
        '    return Thing.go(None)\n'
    )
    b = _graph(_repo(FILES | {"app.py": src}))
    e = _edges(b, "m2")
    assert e == ["ext_pkg/thing.py:Thing.go"], (
        f"a bound-name shadow fanned out: {e}")


def test_fallback_lacking_the_method_never_fabricates_cross_file():
    """The fable-r2 F7 pin: an EXTERNAL-import shim whose fallback class
    lacks the called method, with an unrelated same-named class ELSEWHERE
    in the repo — branch A must NOT reach the cross-file unique-match (the
    local branch of a shim answers only with the LOCAL class's own or
    inherited method, or abstains — never an unrelated file's class)."""
    src = (
        'try:\n'
        '    from numpy.thing import Thing\n'
        'except ImportError:\n'
        '    class Thing:\n'
        '        def other(self):\n'
        '            return 1\n'
        '\n'
        'def m2():\n'
        '    return Thing.foo(None)\n'
    )
    files = FILES | {
        "app.py": src,
        "other/zzz.py": 'class Thing:\n    def foo(self):\n        return 3\n',
    }
    b = _graph(_repo(files))
    e = _edges(b, "m2")
    assert e == [], (
        f"the cross-file unique-match fabricated an edge through the shim's "
        f"local branch: {e}")


def test_local_only_name_does_not_fan_out():
    """A name with ONLY a same-file class (no import): exactly one edge —
    the guard's negative control (the change cannot fan out)."""
    src = (
        'class Thing:\n'
        '    def go(self):\n'
        '        return 1\n'
        '\n'
        'def m1():\n'
        '    t = Thing()\n'
        '    return t.go()\n'
    )
    b = _graph(_repo({"app.py": src}))
    e = _edges(b, "m1")
    assert e == ["app.py:Thing.go"], f"a single-record name fanned out: {e}"


def test_import_only_name_does_not_fan_out():
    """A name with ONLY an import (no same-file class): exactly one edge."""
    src = (
        'from ext_pkg.thing import Thing\n'
        '\n'
        'def m1():\n'
        '    t = Thing()\n'
        '    return t.go()\n'
    )
    b = _graph(_repo(FILES | {"app.py": src}))
    e = _edges(b, "m1")
    assert e == ["ext_pkg/thing.py:Thing.go"], f"a single-record name fanned out: {e}"


# --- the shape variants ---

def test_fallback_base_chain_receives_the_edge_too():
    """The fallback class INHERITS the method from a same-file base: the
    local branch resolves through the base walk (the #441 machinery), and
    the import branch still gets its edge."""
    src = (
        'try:\n'
        '    from ext_pkg.thing import Thing\n'
        'except ImportError:\n'
        '    class Base:\n'
        '        def go(self):\n'
        '            return 1\n'
        '    class Thing(Base):\n'
        '        pass\n'
        '\n'
        'def m2():\n'
        '    return Thing.go(None)\n'
    )
    assert hasattr(call_graph_builder.CallGraphBuilder,
                   "_resolve_shim_dual_branches"), (
        "the dual-branch emitter is missing from the prod builder")
    b = _graph(_repo(FILES | {"app.py": src}))
    e = _edges(b, "m2")
    assert "app.py:Base.go" in e, f"the fallback's inherited edge missing: {e}"
    assert "ext_pkg/thing.py:Thing.go" in e, f"the import edge missing: {e}"


def test_method_missing_in_the_fallback_resolves_the_import_only():
    """The fallback class LACKS the method: the local branch finds nothing
    of its own and the cross-file unique match (the import's method) is the
    one edge — no duplicate, no fabrication."""
    src = (
        'try:\n'
        '    from ext_pkg.thing import Thing\n'
        'except ImportError:\n'
        '    class Thing:\n'
        '        def other(self):\n'
        '            return 1\n'
        '\n'
        'def m1():\n'
        '    t = Thing()\n'
        '    return t.go()\n'
    )
    b = _graph(_repo(FILES | {"app.py": src}))
    e = _edges(b, "m1")
    assert e == ["ext_pkg/thing.py:Thing.go"], (
        f"the fallback-lacks-method shape must keep the single import edge: {e}")
