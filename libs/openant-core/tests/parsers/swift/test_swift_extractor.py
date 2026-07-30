"""Swift function-extractor contract + regression tests.

Grounded in the Sol/Fable pre-implementation reviews. Each test guards a
concrete Swift extraction hazard that would silently drop or mis-key a unit.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _helpers import extract, leaf  # noqa: E402


def _ids(ext):
    return {leaf(fid) for fid in ext["functions"]}


def _by_leaf(ext, name):
    return [f for fid, f in ext["functions"].items() if leaf(fid) == name]


def test_overloaded_inits_not_overwritten(tmp_path):
    """Swift overloads/initializers must NOT collide on func_id (silent overwrite
    was Sol's #1 blocker: `functions.update()` drops all but the last)."""
    ext = extract(tmp_path, {"A.swift": """
        struct A {
            init() {}
            init(path: String) {}
            init(data: Int) {}
        }
        func parse(_ s: String) {}
        func parse(_ n: Int) {}
    """})
    ids = list(ext["functions"].keys())
    inits = [i for i in ids if i.endswith("A.init") or ":A.init(" in i]
    assert len(inits) == 3, f"expected 3 distinct init units, got {inits}"
    parses = [i for i in ids if leaf(i).startswith("parse")]
    assert len(parses) == 2, f"expected 2 distinct parse overloads, got {parses}"


def test_init_and_deinit_named(tmp_path):
    """init_declaration/deinit_declaration have no simple_identifier child; the
    extractor must synthesize the names (else the units are dropped)."""
    ext = extract(tmp_path, {"C.swift": """
        class C {
            init() {}
            deinit { cleanup() }
        }
    """})
    names = {f["name"] for f in ext["functions"].values()}
    assert "init" in names
    assert "deinit" in names
    ctor = _by_leaf(ext, "C.init")
    assert ctor and ctor[0]["unit_type"] == "constructor"


def test_nested_type_qualified_name_no_collision(tmp_path):
    """Two `Inner` types under different outer types must not collide."""
    ext = extract(tmp_path, {"N.swift": """
        struct Outer1 { struct Inner { func f() {} } }
        struct Outer2 { struct Inner { func f() {} } }
    """})
    ids = _ids(ext)
    assert "Outer1.Inner.f" in ids
    assert "Outer2.Inner.f" in ids
    # class_name stays the BARE leaf for receiver dispatch.
    fs = _by_leaf(ext, "Outer1.Inner.f")
    assert fs and fs[0]["class_name"] == "Inner"


def test_public_extension_member_extracted_and_exported(tmp_path):
    """A func inside a `public extension` is extracted (0.7.3 sometimes wraps the
    first member in an ERROR node — the all-children walk descends it) and
    inherits the extension's public access (Fable F6/F10)."""
    ext = extract(tmp_path, {"E.swift": """
        public extension Foo {
            func bar() { work() }
        }
    """})
    bars = _by_leaf(ext, "Foo.bar")
    assert bars, "func inside public extension must be extracted"
    assert bars[0]["class_name"] == "Foo"
    assert bars[0]["is_exported"] is True, "public-extension member inherits public"


def test_public_member_in_internal_type_not_exported(tmp_path):
    """A public method inside an INTERNAL type is not public API (Fable F6)."""
    ext = extract(tmp_path, {"T.swift": """
        struct Internal {
            public func looksPublic() {}
        }
        public struct Exposed {
            public func realPublic() {}
        }
    """})
    assert _by_leaf(ext, "Internal.looksPublic")[0]["is_exported"] is False
    assert _by_leaf(ext, "Exposed.realPublic")[0]["is_exported"] is True


def test_public_class_members_default_internal(tmp_path):
    """Members of a `public class` still default to internal (only `public
    extension` members inherit public) — Fable F6 refinement."""
    ext = extract(tmp_path, {"P.swift": """
        public class Svc {
            func helper() {}
        }
    """})
    assert _by_leaf(ext, "Svc.helper")[0]["is_exported"] is False


def test_generic_type_identity_strips_params(tmp_path):
    """`Box<T>` nominal identity is `Box`, not `Box<T>` (Sol §generic)."""
    ext = extract(tmp_path, {"G.swift": """
        struct Box<T> { func unwrap() -> T { return get() } }
    """})
    assert "Box.unwrap" in _ids(ext)


def test_computed_property_and_observers_emitted(tmp_path):
    """Computed getters/setters + willSet/didSet are call-bearing units (the
    single biggest reachability lever per Sol Q2 / Fable F4)."""
    ext = extract(tmp_path, {"A.swift": """
        class A {
            var computed: Int { get { return calcGet() } set { applySet() } }
            var observed: Int = 0 { willSet { onWill() } didSet { onDid() } }
        }
    """})
    ids = _ids(ext)
    assert "A.computed" in ids          # getter
    assert "A.computed.set" in ids      # setter
    assert "A.observed.willSet" in ids
    assert "A.observed.didSet" in ids


def test_main_classification(tmp_path):
    """A `main` function classifies as unit_type 'main' (an ENTRY_POINT_TYPE).
    (The `@main` attribute sits on the TYPE, not the method — name==main is the
    signal that seeds reachability.) Function-level attributes are captured."""
    ext = extract(tmp_path, {"App.swift": """
        @main struct App { static func main() { run() } }
        class H { @objc func onEvent() {} }
    """})
    m = _by_leaf(ext, "App.main")
    assert m and m[0]["unit_type"] == "main"
    ev = _by_leaf(ext, "H.onEvent")
    assert ev and "@objc" in ev[0]["decorators"]


def test_inheritance_recorded(tmp_path):
    """Superclass + protocol conformances are recorded for dispatch (Fable F3)."""
    ext = extract(tmp_path, {"I.swift": """
        class Impl: Base, Proto { func f() {} }
        extension Impl: Extra {}
    """})
    assert set(ext["inheritance"].get("Impl", [])) >= {"Base", "Proto", "Extra"}
