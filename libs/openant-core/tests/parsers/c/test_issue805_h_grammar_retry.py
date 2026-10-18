"""#805 end-to-end regression: an ambiguous ``.h`` file selects its grammar
BY CONTENT — the C parse first, a C++ retry when the C tree carries
errors — and the selected grammar selects the EXTRACTION, not merely the
tree.

At the base (``parsers/c/function_extractor.py``) the grammar routing was
extension-only in both stages: ``_get_parser`` routed ``.h`` (a member of
``C_EXTENSIONS``) to the C tree-sitter grammar and ``_is_cpp_file``
returned False for it, gating off every C++ extraction branch (lambdas,
namespaces, class member functions, the method/constructor/destructor
classification). The extractor never checked ``tree.root_node.has_error``
— a C++ ``.h`` parsed with ERROR nodes under the C grammar and the file
vanished with no stat and no stderr:

* the template-only fixture (byte-identical ``tpl.h``/``tpl.hpp``)
  yielded ZERO units from the ``.h`` copy — a silent false negative, the
  worse direction under the over-seed rule;
* the class/namespace fixture (``same.h``/``same.hpp``) yielded 7
  mis-shaped whole-body ``function`` units (``class_name=None``, the
  destructor/constructor/overrides LOST, a bogus lambda-parameter unit)
  where the ``.hpp`` control yields 8 properly-shaped ones;
* the ``extern "C"``-guarded fixture (``api.h``) parses with errors
  under BOTH grammars, extracts its one unit on the recovered C tree,
  and was never counted anywhere — no diagnostics key existed (the
  silent-skip blackout).

The fix (``_parse_selecting_grammar``): a clean C parse stands; a C parse
with errors retries under the C++ grammar — a CLEAN C++ parse wins and
selects the C++ extraction/classification (``is_cpp`` travels WITH the
selected tree, never re-derived from the extension); when BOTH parses
carry errors, the extension default stands, the recovered tree still
feeds extraction (over-seed preserved — the base's own behavior), and
the SELECTED tree's ERROR state is counted in the extension-independent
``files_with_parse_errors`` key so the silent failure is visible. The selection travels with the extraction output
(``cpp_grammar_files``) so the call-graph builder re-parses those
files' function BODIES under the same grammar.

The fixtures are the campaign's own byte-identical pairs (preserved at
``e2e/campaign/c-header-wave-20261014/`` with their SHA manifests); the
corpus honesty: the OpenAnt repo's own tree carries NO ``.h``/``.hpp``
files, so the fixture differential IS the corpus here — the in-tree
C-family suites (green at the head) carry the no-regression leg.

Shapes:

  S1 -- the WITNESS (red at base): the template-only ``.h`` yields the
        SAME unit signatures as its byte-identical ``.hpp`` control
        (the differential, not fixed numbers — 0 vs 4 at the base).
  S2 -- the WITNESS (red at base): the class/namespace ``.h`` yields the
        same signatures as its ``.hpp`` control (7 mis-shaped vs 8
        properly-shaped at the base).
  S3 -- the CONTROL (green at base AND head): a declaration-only ``.h``
        yields ZERO units — the C declaration-vs-definition split is
        correct and untouched (a clean C parse; the retry never fires).
  S4 -- the CONTROL: a static-inline ``.h`` extracts identically at both
        trees (a clean C parse; the retry never fires).
  S5 -- the CONTROL (green at base AND head): the ``extern "C"``-guarded
        ``.h`` (errors under BOTH grammars) extracts the SAME one unit
        at base and head — the extension default stands, the over-seed
        is preserved.
  S6 -- the WITNESS (red at base): the both-errored ``.h`` is COUNTED
        in ``files_with_parse_errors`` — the extension-independent
        diagnostics key (checked for EVERY file; the r1 catch: counting
        it in files_with_errors made the stat extension-dependent — the
        same content counted as .h but not .c — and broke its partition
        with files_processed). files_with_errors keeps the lost-file
        semantics and stays partitioned.
  S7 -- the WITNESS (red at base): the grammar selection travels with
        the output — ``cpp_grammar_files`` names the content-selected
        files, and the call-graph builder consults it (the ``.h``
        bodies re-parse under the C++ grammar; at the base the key is
        absent and the builder re-derives the wrong grammar).
  S6b -- the WITNESS (red at base): a LEGIT C file whose type is a
        typedef/macro spelled ``namespace`` fires the tell's retry (the
        C++ grammar rejects the keyword) — the selected C tree's OWN
        state rides the diagnostics flag (never hard-coded), so the
        clean tree counts nothing and the .h twin behaves identically
        to its .c twin (the r2-F3 catch).
  S8 -- the WITNESS (red at base): the NAMESPACE tell — a C++ header of
        free inline functions wrapped in ``namespace`` parses ERROR-FREE
        under the C grammar as bogus whole-namespace span units, so the
        has_error trigger never fires; the structural tell (a definition
        typed ``namespace``, found at the top level or under the
        preprocessor-condition nodes — the include-guarded and
        ``#ifdef __cplusplus`` forms) retries it under the C++ grammar
        and the proper units extract (the r1-F1/r2-F1/r2-F2 catches;
        the fixture parses CLEAN under C by the guard assert, so the
        TELL — not has_error — is what the witness exercises).
"""

import sys
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[3]  # libs/openant-core
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

pytest.importorskip("tree_sitter_cpp")

from parsers.c.call_graph_builder import CallGraphBuilder  # noqa: E402
from parsers.c.function_extractor import FunctionExtractor  # noqa: E402

# ---------------------------------------------------------------------------
# The campaign's byte-identical fixtures (the shapes, inline)
# ---------------------------------------------------------------------------

_TPL = """#pragma once
template <typename T>
class Box {
public:
    Box(T v) : v_(v) {}
    T get() const { return v_; }
    template <typename U> U as() const { return static_cast<U>(v_); }
private:
    T v_;
};
template <typename T> T maxof(T a, T b) { return a > b ? a : b; }
"""

_SAME = """#pragma once
#include <string>

namespace shapes {

class Base {
public:
    virtual ~Base() {}
    virtual double area() const = 0;
    virtual const char* name() const { return "base"; }
};

class Circle : public Base {
public:
    explicit Circle(double r) : r_(r) {}
    double area() const override { return 3.14159 * r_ * r_; }
    const char* name() const override { return "circle"; }
    void handle(const std::string& s) { last_ = s; }
private:
    double r_;
    std::string last_;
};

inline double twice(double x) { return 2 * x; }

auto lam = [](int a) { return a + 1; };

} // namespace shapes
"""

_DECL = """#ifndef DECL_H
#define DECL_H
int foo(int);
void bar(void);
struct S { int a; };
#endif
"""

_INL = "static inline int inl_add(int a, int b) { return a + b; }\nint inl_decl(int);\n"

_API = """#ifndef API_H
#define API_H
#ifdef __cplusplus
extern "C" {
#endif
int api_open(const char *path);
static inline int api_twice(int x) { return 2 * x; }
int api_close(int fd);
#ifdef __cplusplus
}
#endif
#endif
"""

_MAIN = '#include "tpl.h"\nint use(const char *s, int n){ Box<int> b(1); return b.get(); }\n'


def _build_fx(root: Path) -> Path:
    """The campaign's differential layout: the byte-identical .h/.hpp
    pairs + the controls + a consumer, one flat tree."""
    fx = root / "fx"
    fx.mkdir(parents=True)
    (fx / "tpl.h").write_text(_TPL, encoding="utf-8")
    (fx / "tpl.hpp").write_text(_TPL, encoding="utf-8")
    (fx / "same.h").write_text(_SAME, encoding="utf-8")
    (fx / "same.hpp").write_text(_SAME, encoding="utf-8")
    (fx / "decl.h").write_text(_DECL, encoding="utf-8")
    (fx / "inl.h").write_text(_INL, encoding="utf-8")
    (fx / "api.h").write_text(_API, encoding="utf-8")
    (fx / "main.cpp").write_text(_MAIN, encoding="utf-8")
    return fx


def _signatures(out: dict, fname: str):
    """The per-file unit signatures: (name, unit_type, class_name) — the
    file_path is the ONLY thing the differential must not compare."""
    return sorted(
        (fd["name"], fd["unit_type"], fd.get("class_name"))
        for fd in out["functions"].values()
        if fd["file_path"] == fname
    )


@pytest.fixture(scope="module")
def extraction(tmp_path_factory) -> dict:
    """The REAL extractor over the differential fixture tree."""
    root = tmp_path_factory.mktemp("issue805")
    fx = _build_fx(root)
    ex = FunctionExtractor(str(fx))
    return ex.extract_all()


# ---------------------------------------------------------------------------
# S1/S2 — the .h/.hpp differential (the witnesses)
# ---------------------------------------------------------------------------

def test_the_template_h_yields_the_hpp_signatures(tmp_path):
    """S1: the template-only .h must yield the SAME unit signatures as its
    byte-identical .hpp control — at the base the .h copy yields ZERO
    units (the silent false negative) while the .hpp control yields four.
    Drives the REAL extractor (parsers/c/function_extractor.py — the
    grammar selection) over the pair alone."""
    from parsers.c.function_extractor import FunctionExtractor

    root = tmp_path / "s1"
    root.mkdir()
    (root / "tpl.h").write_text(_TPL, encoding="utf-8")
    (root / "tpl.hpp").write_text(_TPL, encoding="utf-8")
    out = FunctionExtractor(str(root)).extract_all()
    got_h = _signatures(out, "tpl.h")
    got_hpp = _signatures(out, "tpl.hpp")
    assert got_h == got_hpp, (
        f"the template .h must extract like its byte-identical .hpp "
        f"control: .h={got_h} vs .hpp={got_hpp}")


def test_the_class_h_yields_the_hpp_signatures(tmp_path):
    """S2: the class/namespace .h must yield the same signatures as its
    .hpp control — at the base the .h copy yields 7 mis-shaped units
    (class_name=None, the destructor/constructor/overrides LOST) where
    the .hpp control yields 8 properly-shaped ones (methods, the
    constructor, the destructor, the lambda, the free inline).
    Drives the REAL extractor (parsers/c/function_extractor.py — the
    grammar selection) over the pair alone."""
    from parsers.c.function_extractor import FunctionExtractor

    root = tmp_path / "s2"
    root.mkdir()
    (root / "same.h").write_text(_SAME, encoding="utf-8")
    (root / "same.hpp").write_text(_SAME, encoding="utf-8")
    out = FunctionExtractor(str(root)).extract_all()
    got_h = _signatures(out, "same.h")
    got_hpp = _signatures(out, "same.hpp")
    assert got_h == got_hpp, (
        f"the class .h must extract like its .hpp control: "
        f".h={got_h} vs .hpp={got_hpp}")
    # the properly-shaped classes, not just the counts: the .h's methods
    # carry their class and the inheritance map populates from them (the
    # name field is the QUALIFIED scope, e.g. shapes::Circle::Circle)
    assert ("shapes::Circle::Circle", "constructor", "Circle") in got_h, got_h
    assert ("shapes::Base::~Base", "destructor", "Base") in got_h, got_h
    assert out["class_bases"].get("Circle") == ["Base"], out["class_bases"]


# ---------------------------------------------------------------------------
# S3/S4/S5 — the controls (green at base AND head)
# ---------------------------------------------------------------------------

def test_a_declaration_only_h_yields_zero_units(extraction):
    """S3: the C declaration-vs-definition split is correct and untouched
    — a prototype-bearing .h produces ZERO units at the base AND at the
    head (a clean C parse; the retry never fires)."""
    assert _signatures(extraction, "decl.h") == []


def test_a_clean_c_h_extracts_identically(extraction):
    """S4: a static-inline .h (a clean C parse) extracts its one unit at
    both trees — the retry never fires for clean C content."""
    assert _signatures(extraction, "inl.h") == [
        ("inl_add", "static_function", None)]


def test_the_both_errored_h_keeps_its_extension_default_units(extraction):
    """S5: the extern-"C"-guarded .h errors under BOTH grammars — the
    extension default stands and the recovered C tree still feeds
    extraction (the over-seed preserved: the SAME one unit the base
    extracted)."""
    assert _signatures(extraction, "api.h") == [
        ("api_twice", "static_function", None)]


# ---------------------------------------------------------------------------
# S6 — the surfaced stat (the witness)
# ---------------------------------------------------------------------------

def test_the_both_errored_h_is_counted_extension_independently(tmp_path):
    """S6: a file whose selected tree carries ERROR nodes is COUNTED in
    files_with_parse_errors — the extension-independent diagnostics key
    (checked for EVERY file, not just the retried .h class). At the base
    the errors were invisible everywhere (the silent-skip blackout).
    files_with_errors keeps the LOST-FILE semantics and stays
    partitioned with files_processed: a processed-with-parse-errors file
    rides ONLY the diagnostics key (the r1-F2 catch: the first shape
    counted it in files_with_errors for .h but not for byte-identical
    .c content). Drives the REAL extractor (the prod file under test:
    parsers/c/function_extractor.py)."""
    from parsers.c.function_extractor import FunctionExtractor

    root = tmp_path / "s6"
    root.mkdir()
    (root / "api.h").write_text(_API, encoding="utf-8")
    # the SAME content as .c: the diagnostics key fires for it too —
    # the rule is the tree's ERROR nodes, never the extension
    (root / "same.c").write_text(_API, encoding="utf-8")
    out = FunctionExtractor(str(root)).extract_all()
    stats = out["statistics"]
    assert stats.get("files_with_parse_errors") == 2, stats
    # the lost-file partition untouched: both files were PROCESSED
    assert stats["files_with_errors"] == 0, stats
    assert stats["files_processed"] == 2, stats
    # the over-seed preserved: both files' units stand
    assert _signatures(out, "api.h") == [("api_twice", "static_function", None)]
    assert _signatures(out, "same.c") == [("api_twice", "static_function", None)]


def test_a_typedefd_namespace_type_does_not_miscount(tmp_path):
    """S6b (the r2-F3 catch): a LEGIT C file whose type is a typedef or
    macro spelled ``namespace`` fires the tell's retry (the C++ grammar
    rejects ``namespace`` as a keyword), and the first shape then
    hard-coded the diagnostics flag — a CLEAN C tree counted as a parse
    error, and only for the .h twin (the extension-dependence the r1-F2
    fix closed, reopened). The flag is the SELECTED tree's own state
    now: the clean C tree counts nothing, identical to its .c twin."""
    from parsers.c.function_extractor import FunctionExtractor

    body = ("typedef int namespace;\n"
            "namespace f(void) { return 0; }\n"
            "static namespace g(namespace x) { return x; }\n")
    root = tmp_path / "s6b"
    root.mkdir()
    (root / "legit.h").write_text(body, encoding="utf-8")
    (root / "legit.c").write_text(body, encoding="utf-8")
    out = FunctionExtractor(str(root)).extract_all()
    stats = out["statistics"]
    # the extension default stands: both twins processed, no diagnostics
    # (the selected C tree is clean), no lost files
    assert stats.get("files_with_parse_errors") == 0, stats
    assert stats["files_with_errors"] == 0, stats
    assert stats["files_processed"] == 2, stats
    # the units stand in both twins (the over-seed; the C grammar reads
    # the typedef'd type fine)
    assert _signatures(out, "legit.h") == _signatures(out, "legit.c")


# ---------------------------------------------------------------------------
# S7 — the selection travels (the witness)
# ---------------------------------------------------------------------------

def test_the_grammar_selection_travels_to_the_call_graph(extraction):
    """S7: the content-selected C++ grammar for the ambiguous .h files
    travels with the extraction output — cpp_grammar_files names exactly
    the selected files (at the base the key is absent), and the
    call-graph builder consults it so their function BODIES re-parse
    under the C++ grammar (at the base the builder re-derives the C
    grammar from the extension and mis-parses the C++ bodies)."""
    assert set(extraction.get("cpp_grammar_files", [])) == {
        "same.h", "tpl.h"}, extraction.get("cpp_grammar_files")

    b = CallGraphBuilder(extraction)
    assert b._get_parser_for_file("tpl.h") is b.cpp_parser, (
        "the selected .h's bodies must re-parse under the C++ grammar")
    assert b._get_parser_for_file("same.h") is b.cpp_parser
    # the extension default still routes the unselected files
    assert b._get_parser_for_file("api.h") is b.c_parser
    assert b._get_parser_for_file("main.cpp") is b.cpp_parser
    assert b._get_parser_for_file("decl.h") is b.c_parser



# ---------------------------------------------------------------------------
# S8 — r1-F1: the namespace tell (the clean-parse C++ shape)
# ---------------------------------------------------------------------------

_UTIL_NS = """namespace util {
inline int clamp(int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); }
inline int align_up(int n, int a) { return (n + a - 1) & ~(a - 1); }
namespace detail {
inline int helper(int x) { return x * 2; }
}
}
"""

_UTIL_NS_GUARDED = """#ifndef UTIL_H
#define UTIL_H
namespace util {
inline int clamp(int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); }
inline int align_up(int n, int a) { return (n + a - 1) & ~(a - 1); }
}
#endif
"""


def _assert_c_parse_is_clean(content: str) -> None:
    """The S8 fixture guard (the r2-F2 catch): the tell's witness must
    parse CLEAN under the C grammar — else the ORDINARY has_error retry
    selects C++ and the tell is never exercised (the first S8 fixture
    carried a ``detail::`` call whose ``::`` errors the C parse; every
    assertion passed at the PRE-TELL head). This guard makes that class
    of fixture drift impossible."""
    import tree_sitter_c as tsc
    from tree_sitter import Language, Parser

    tree = Parser(Language(tsc.language())).parse(content.encode("utf-8"))
    assert not tree.root_node.has_error, (
        "the S8 fixture must parse CLEAN under the C grammar — a "
        "has_error fixture does not exercise the namespace tell")


def test_the_namespace_only_h_retries_under_the_cpp_grammar(tmp_path):
    """S8 (the r1-F1/r2-F1/r2-F2 catches): a C++ header of free inline
    functions wrapped in `namespace` parses ERROR-FREE under the C
    grammar — as function_definitions typed `namespace` with
    whole-namespace BODIES — so the has_error trigger never fires and
    the bogus span units persist. The structural tell (a definition
    typed exactly `namespace` — an impossible C definition) retries
    under the C++ grammar and the proper units extract, matching the
    .hpp control. The r2 widenings: the fixture is ::-free (a `detail::`
    call would ERROR the C parse and launder the test through the
    has_error path — the guard assert below pins that) and the
    include-guarded form (the DOMINANT real-world shape — the namespace
    nests under the preproc_ifdef node, so the tell's scan descends
    through the preprocessor conditions) is covered too."""
    from parsers.c.function_extractor import FunctionExtractor

    _assert_c_parse_is_clean(_UTIL_NS)
    _assert_c_parse_is_clean(_UTIL_NS_GUARDED)

    root = tmp_path / "s8"
    root.mkdir()
    (root / "util.h").write_text(_UTIL_NS, encoding="utf-8")
    (root / "util.hpp").write_text(_UTIL_NS, encoding="utf-8")
    # the dominant real form: the include-guarded namespace header
    (root / "guarded.h").write_text(_UTIL_NS_GUARDED, encoding="utf-8")
    (root / "guarded.hpp").write_text(_UTIL_NS_GUARDED, encoding="utf-8")
    out = FunctionExtractor(str(root)).extract_all()
    got_h = _signatures(out, "util.h")
    got_hpp = _signatures(out, "util.hpp")
    assert got_h == got_hpp, (
        f"the namespace-only .h must extract like its .hpp control: "
        f".h={got_h} vs .hpp={got_hpp}")
    # the proper qualified names, not the bogus whole-namespace spans
    assert ("util::align_up", "function", None) in got_h, got_h
    assert ("util::detail::helper", "function", None) in got_h, got_h
    assert "util.h" in out.get("cpp_grammar_files", []), out.get(
        "cpp_grammar_files")

    got_gh = _signatures(out, "guarded.h")
    got_ghpp = _signatures(out, "guarded.hpp")
    assert got_gh == got_ghpp, (
        f"the include-guarded namespace .h must extract like its .hpp "
        f"control (the tell descends through the preproc node): "
        f".h={got_gh} vs .hpp={got_ghpp}")
    assert ("util::clamp", "function", None) in got_gh, got_gh
    assert "guarded.h" in out.get("cpp_grammar_files", []), out.get(
        "cpp_grammar_files")
    # the guarded form parsed CLEAN under C by construction: the tell
    # (not has_error) selected it, so no parse-error diagnostic rides
    assert out["statistics"].get("files_with_parse_errors") == 0, (
        out["statistics"])
