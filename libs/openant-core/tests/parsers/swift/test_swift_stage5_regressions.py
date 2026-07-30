"""Regression tests for the Stage-5 post-build audit fixes (Sol / Fable /
independent / auditor / expert). Each guards a confirmed real-target defect."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _helpers import build, extract, edges, leaf  # noqa: E402


def test_toplevel_try_await_daemon_root(tmp_path):
    """FH2/E-01: a `try await Daemon().start()` root parses as a top-level
    try_expression — it must still become a main unit (daemon-root blackout)."""
    ext = extract(tmp_path, {"main.swift": """
        import Foundation
        try await CloudBoardDaemon().start(port: 9000)
    """})
    tops = [f for f in ext["functions"].values() if f["qualified_name"] == "<top-level>"]
    assert tops and tops[0]["unit_type"] == "main"
    assert "start" in tops[0]["code"]


def test_parsable_command_run_seeded(tmp_path):
    """FH4/E-02: `ParsableCommand.run()` is runtime-invoked → seeded as main."""
    ext = extract(tmp_path, {"Cmd.swift": """
        struct Tool: ParsableCommand { func run() throws { doWork() } }
        func doWork() {}
    """})
    run = [f for f in ext["functions"].values() if f["name"] == "run"]
    assert run and run[0]["unit_type"] == "main"


def test_codable_init_from_seeded(tmp_path):
    """ES4: `Codable init(from:)` decodes untrusted input → seeded."""
    ext = extract(tmp_path, {"M.swift": """
        struct Msg: Decodable { init(from decoder: Decoder) throws { parse() } }
        func parse() {}
    """})
    inits = [f for f in ext["functions"].values() if f["name"] == "init"]
    assert inits and inits[0]["unit_type"] == "main"


def test_dotted_builtin_member_call_kept(tmp_path):
    """CG-01/S3: a typed receiver's method named like a builtin (`self.append`)
    must resolve, not be dropped by the builtin filter."""
    _, cg = build(tmp_path, {"M.swift": """
        struct Metrics {
            func record() { self.append(1) }
            func append(_ x: Int) { sink() }
        }
        func sink() {}
    """})
    assert ("Metrics.record", "Metrics.append") in edges(cg)


def test_untyped_builtin_receiver_not_mislinked(tmp_path):
    """CG-01 guard: an UNKNOWN-receiver builtin method must NOT link to a same-named
    user method (`xs.map` is stdlib, not the repo `map`)."""
    _, cg = build(tmp_path, {"M.swift": """
        func map(_ f: Int) {}
        func run(xs: [Int]) { xs.map { $0 } }
    """})
    assert ("run", "map") not in edges(cg)


def test_arg_ref_labeled_captured_and_scoped(tmp_path):
    """CG-02: labeled function-ref arg captured; CG-03: a local value is NOT."""
    _, cg = build(tmp_path, {"M.swift": """
        func handleRequest() {}
        func register(use: () -> Void) {}
        func setup() { register(use: handleRequest) }
        func other(value: Int) { consume(value) }
        func consume(_ v: Int) {}
    """})
    e = edges(cg)
    assert ("setup", "handleRequest") in e       # labeled fn-ref captured (CG-02)
    # `value` is a local param, not a function ref — even though a func could share
    # the name, it must not fabricate an edge (CG-03 scoping).
    assert not any(callee == "value" for _, callee in e)


def test_external_receiver_not_bound_to_caller(tmp_path):
    """CG-04: a typed EXTERNAL receiver whose method misses must NOT fall back to
    the caller's own same-named method."""
    _, cg = build(tmp_path, {"M.swift": """
        struct Release { func encode() { audit() } func run() { let e = JSONEncoder(); e.encode(self) } }
        func audit() {}
    """})
    # e is JSONEncoder (external); e.encode must NOT bind to Release.encode.
    assert ("Release.run", "Release.encode") not in edges(cg)


def test_protocol_existential_reaches_conformers(tmp_path):
    """S1: a call on a protocol-typed receiver reaches the conformers' witnesses."""
    _, cg = build(tmp_path, {"M.swift": """
        protocol Authorizer { func authorize() }
        struct Policy: Authorizer { func authorize() { checkPolicy() } }
        func checkPolicy() {}
        func dispatch(a: Authorizer) { a.authorize() }
    """})
    assert ("dispatch", "Policy.authorize") in edges(cg)


def test_local_func_not_phantom_method(tmp_path):
    """E-04: a nested local func is function-scoped, not a method of the type."""
    ext = extract(tmp_path, {"M.swift": """
        class Outer { func method() { func helper() {} } }
    """})
    helpers = [f for f in ext["functions"].values() if f["name"] == "helper"]
    assert helpers and helpers[0]["class_name"] is None


def test_self_constructor_resolves(tmp_path):
    """S6a: `Self(...)` resolves to the caller type's constructors."""
    _, cg = build(tmp_path, {"M.swift": """
        struct Token { init(v: Int) { seed() } static func make() -> Token { return Self(v: 1) } }
        func seed() {}
    """})
    assert ("Token.make", "Token.init") in edges(cg)


def test_public_extension_of_public_type_exported(tmp_path):
    """S4a/E-03: a public member of an unmodified extension of a PUBLIC repo type
    is public API (library-mode seed)."""
    ext = extract(tmp_path, {"C.swift": """
        public struct Client {}
        extension Client { public func send() {} }
    """})
    send = [f for f in ext["functions"].values() if leaf_name(f) == "send"]
    assert send and send[0]["is_exported"] is True


def leaf_name(f):
    return f["name"]
