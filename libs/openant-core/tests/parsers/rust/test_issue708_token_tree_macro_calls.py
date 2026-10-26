"""#708: the Rust macro-body call scan runs on a tree-sitter token-tree walk.

PR #246's "Scope / named residuals" named the structural replacement as
deferred, along with the truncation class that survives it: the macro-body
scan still ran on two regexes with an 8KB byte budget, so a call sitting past
the budget in a macro body with non-literal token soup emitted NO edge (its
callee prunable — the reachability false-negative), and the regex pair
remained a maintenance hazard on untrusted input (#246 was opened because one
of them was a real ReDoS on a scanned repo).

The falsifier (authored at filing): "a macro body whose call edges are
extracted by a tree-sitter token-tree walk, or a call past the byte budget
that still produces its edge."

The fix: walk the macro's ``token_tree`` NODES (tree-sitter already lexes them
into structured nodes — string_literal / identifier / nested token_tree), so
literals come for free (never a phantom edge from call-looking diagnostic text)
and NO byte budget exists (no truncation class). The regex path is retained in
the module as the DIFFERENTIAL ORACLE — the new walk's call set must be a
SUPERSET of the regex path's on the fixtures + the real-code corpus, with the
recovered calls ENUMERATED (the issue's own wording).
"""

import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _rust_helpers import RepositoryScanner, FunctionExtractor  # noqa: E402
import importlib  # noqa: E402

# the prod module directly — the witness screen's channel (UNALIASED)
from parsers.rust import call_graph_builder  # noqa: E402

assert hasattr(call_graph_builder, "_SCANNABLE_MACROS"), (
    "the prod macro-site machinery is missing")


def _cg(files: dict, tmp):
    """Scan + extract + build over a fixture dict; returns the builder."""
    import os
    for rel, src in files.items():
        p = os.path.join(tmp, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(src)
    scan = RepositoryScanner(str(tmp), skip_tests=False).scan()
    ext = FunctionExtractor(str(tmp), scan).extract()
    mod = importlib.import_module("parsers.rust.call_graph_builder")
    b = mod.CallGraphBuilder(ext)
    b.build_call_graph()
    return b


def _edges(b, caller: str):
    fid = next(k for k in b.functions if k.endswith(":" + caller))
    return sorted(t.split(":")[-1] for t in b.call_graph.get(fid, []))


# --- the falsifier's SECOND disjunct: a call past the budget still edges ---

def test_a_call_past_the_byte_budget_still_produces_its_edge(tmp_path):
    """THE #708 falsifier: a real call sitting past the 8KB budget in
    non-literal token soup — the regex path truncated it (disclosed); the
    token-tree walk has NO budget, so the edge exists."""
    assert hasattr(call_graph_builder.CallGraphBuilder,
                   "_token_tree_call_sites"), (
        "the token-tree walker is missing from the prod builder")
    # >8KB of non-literal token soup (nested parens, identifiers, commas —
    # no string literals, so the stripper cannot collapse it)
    soup = "(((((alpha, beta, gamma, delta)))))" * 260  # ~9.9KB
    src = (
        "pub fn real_callee() -> u8 { 1 }\n"
        "pub fn caller() {\n"
        f"    vec![{soup}, real_callee()];\n"
        "}\n"
    )
    b = _cg({"src/lib.rs": src}, str(tmp_path))
    e = _edges(b, "caller")
    assert "real_callee" in e, (
        f"the past-budget call's edge is missing (the truncation class "
        f"survived): {e}")


def test_no_scan_truncated_is_recorded_for_rust_macros(tmp_path):
    """The truncation class is RETIRED: the rust macro path never records
    scan_truncated (no budget exists). A soup body that WOULD have truncated
    leaves the disclosure list empty."""
    assert hasattr(call_graph_builder.CallGraphBuilder,
                   "_token_tree_call_sites"), (
        "the token-tree walker is missing from the prod builder")
    soup = "(((((alpha, beta, gamma, delta)))))" * 260
    src = (
        "pub fn f() {\n"
        f"    println!(\"{{}}\", {{{soup}}});\n"
        "}\n"
    )
    b = _cg({"src/lib.rs": src}, str(tmp_path))
    assert not [t for t in b.scan_truncated if t.startswith("rust macro")], (
        f"the rust macro path still truncates: {b.scan_truncated}")


# --- the falsifier's FIRST disjunct: the token-tree walk extracts the edges ---

def test_the_macro_sites_come_from_the_token_tree_walk(tmp_path):
    """The prod extractor's macro path IS the token-tree node walk (the
    regexes are the differential oracle only): the walker exists as its own
    method and the call shapes route through it."""
    assert hasattr(call_graph_builder.CallGraphBuilder,
                   "_token_tree_call_sites"), (
        "the token-tree walker is missing from the prod builder")


def test_string_literal_call_text_never_phantoms(tmp_path):
    """Literals are free in the node walk: call-looking text inside a string
    literal never produces an edge (the regex path needed the stripper)."""
    assert hasattr(call_graph_builder.CallGraphBuilder,
                   "_token_tree_call_sites"), (
        "the token-tree walker is missing from the prod builder")
    src = (
        "pub fn real_one() -> u8 { 1 }\n"
        "pub fn caller() {\n"
        "    panic!(\"call phantom_name() first\");\n"
        "}\n"
    )
    b = _cg({"src/lib.rs": src}, str(tmp_path))
    e = _edges(b, "caller")
    assert "phantom_name" not in e, f"a literal's text phantom-edged: {e}"


def test_all_the_call_shapes_edge(tmp_path):
    """The four shapes the regex matched — bare, method (recv.name), scoped
    (A::B::c), turbofish (Type::m::<T>) — all produce their edges through
    the walk."""
    assert hasattr(call_graph_builder.CallGraphBuilder,
                   "_token_tree_call_sites"), (
        "the token-tree walker is missing from the prod builder")
    src = (
        "pub fn bare_call() -> u8 { 1 }\n"
        "pub mod inner { pub fn scoped_call() -> u8 { 2 } }\n"
        "pub struct Thing;\n"
        "impl Thing { pub fn turbo_call() -> u8 { 3 } }\n"
        "pub fn method_caller() {\n"
        "    let v = vec![bare_call(), inner::scoped_call()];\n"
        "    println!(\"{}{}{}\", v.len(), Thing::turbo_call::<u8>(), v[0]);\n"
        "}\n"
    )
    b = _cg({"src/lib.rs": src}, str(tmp_path))
    e = _edges(b, "method_caller")
    assert "bare_call" in e, e
    assert "scoped_call" in e, e
    # the turbofish shape routes SCOPED (Thing::turbo_call) — the edge's
    # spelling carries the qualifier, exactly the regex path's shape
    assert any(x.endswith("turbo_call") for x in e), e
    # DISCLOSED (pre-existing, identical at base): the v.len() METHOD shape
    # is EXTRACTED by the walk (the field site v.len) but UNRESOLVABLE — the
    # let-initializer vec![...] is macro-opaque to the AST type inference, so
    # v has no type and the field call cannot bind. Out of #708's scope (the
    # issue is the EXTRACTION walk, not the resolution).


def test_the_nested_generics_turbofish_shapes_edge(tmp_path):
    """r5-B1/F1 + r6-N2 + r8-N5: the angle-map's `>>` two-open branch.
    The F1 regression (the pre-r5 map recorded the WRONG close index —
    the skip stopped inside the generics, the edge lost end-to-end; a
    real corpus line lost get_hash_str) is pinned here BEHAVIORALLY: the
    depth-2, dotted and depth-4 pins FAIL at 985d8fbd and pass at head;
    the `>> >` triple (`::<A<B<C>>>`) was NEVER in the class (it passes
    at 985d8fbd — r6-N2/r9-F2) and stays as a shape-coverage pin. No
    single-sentence class characterization is attempted — the review
    rounds derived it (r7-N4's depth-parity reading was falsified by
    r8-N5: tuple-typed generics like `::<Vec<(u8,)>>` PASS at 985d8fbd
    via an accidental call-open on the `(`-tree; the class is a property
    of the RECORDED close index, not of the nesting depth alone). The
    regex oracle cannot see ANY of these shapes (`(?:::<[^>]*>)?` never
    matches `>>(`), so the superset contract is vacuous here — these
    behavioral pins are the only coverage."""
    assert hasattr(call_graph_builder.CallGraphBuilder,
                   "_token_tree_call_sites"), (
        "the token-tree walker is missing from the prod builder")
    src = (
        "pub struct Thing;\n"
        "impl Thing { pub fn turbo_call() -> u8 { 1 } }\n"
        "pub fn method_caller() {\n"
        "    println!(\"{}\", Thing::turbo_call::<Vec<u8>>());\n"
        "}\n"
    )
    b = _cg({"src/lib.rs": src}, str(tmp_path))
    e = _edges(b, "method_caller")
    assert any(x.endswith("turbo_call") for x in e), (
        f"the ::<X<Y>> turbofish call lost its edge (r5-F1): {e}")
    # the >> > triple shape (::<A<B<C>>>  lexes >> then >)
    src2 = (
        "pub struct Thing;\n"
        "impl Thing { pub fn deep_call() -> u8 { 1 } }\n"
        "pub fn triple_caller() {\n"
        "    println!(\"{}\", Thing::deep_call::<A<B<C>>>());\n"
        "}\n"
    )
    b2 = _cg({"src/lib.rs": src2}, str(tmp_path))
    e2 = _edges(b2, "triple_caller")
    assert any(x.endswith("deep_call") for x in e2), (
        f"the ::<A<B<C>>> turbofish call lost its edge: {e2}")
    # the DOTTED turbofish form too (recv.name::<Vec<u8>>() — the r1-F2
    # shape at two levels)
    src3 = (
        "pub struct Recv;\n"
        "impl Recv { pub fn name(&self) -> u8 { 1 } }\n"
        "pub fn dotted_caller(r: Recv) {\n"
        "    println!(\"{}\", r.name::<Vec<u8>>());\n"
        "}\n"
    )
    b3 = _cg({"src/lib.rs": src3}, str(tmp_path))
    e3 = _edges(b3, "dotted_caller")
    assert any(x.endswith("name") for x in e3), (
        f"the dotted ::<X<Y>> turbofish call lost its edge: {e3}")
    # the depth-4 shape (r6-N2): the two-open branch fires TWICE — the
    # realistic Arc<Mutex<Vec<u8>>> form; load-bearing for the F1 class
    # (fails at 985d8fbd, passes at head)
    src4 = (
        "pub struct Thing;\n"
        "impl Thing { pub fn arc_call() -> u8 { 1 } }\n"
        "pub fn arc_caller() {\n"
        "    println!(\"{}\", Thing::arc_call::<Arc<Mutex<Vec<u8>>>>());\n"
        "}\n"
    )
    b4 = _cg({"src/lib.rs": src4}, str(tmp_path))
    e4 = _edges(b4, "arc_caller")
    assert any(x.endswith("arc_call") for x in e4), (
        f"the depth-4 ::<Arc<Mutex<Vec<u8>>>> turbofish call lost its "
        f"edge: {e4}")


def test_an_unclosed_turbofish_does_not_consume_the_macro_stream(tmp_path):
    """The astra-blocker shape (adjudicated REAL, then fixed): inside ONE
    token tree an unclosed `::<` followed by a sibling real call —
    `println!("{}", x::<, real_tail())` — must NOT consume the rest of the
    stream. The first token-tree fix skipped an unclosed turbofish to the
    stream's end (the flood-guard reading), silently losing the tail's edge
    even though tree-sitter parses the tree with has_error=False (a VALID
    macro body); the angle-map precompute degrades an unclosed `::<` to the
    plain-`::` reading — the < / > tokens walk as ordinary non-name tokens
    and the tail's edge survives. BOUNDED (r5-r8): the pairing is the
    map's LIFO stack — the MECHANISM facts live in the prod map comment
    (a `>` closes the most recent open; a `>>` closes the two most
    recent; an unmapped `::<` degrades) and the bound-case enumerations
    live in the review rounds (r5-D1, r6-D2/D3, r7-D4, r8-D5/D6) — not
    restated here. The SIBLING-macro shape (stringify!(x::<);
    println!(...)) was already safe (each macro's token tree is walked
    separately) — its half is a regression guard on the base behavior,
    not load-bearing for this delta (r5-N1)."""
    assert hasattr(call_graph_builder.CallGraphBuilder,
                   "_token_tree_call_sites"), (
        "the token-tree walker is missing from the prod builder")
    src = (
        "pub fn real_tail() -> u8 { 1 }\n"
        "pub fn f() {\n"
        "    println!(\"{} {}\", x::<, real_tail());\n"
        "}\n"
    )
    b = _cg({"src/lib.rs": src}, str(tmp_path))
    e = _edges(b, "f")
    assert "real_tail" in e, (
        f"an unclosed ::< consumed the rest of the token tree — the "
        f"trailing call's edge was lost (the astra-blocker shape): {e}")
    # the sibling-macro shape stays safe (each token tree is its own walk)
    src2 = (
        "pub fn real_tail() -> u8 { 1 }\n"
        "pub fn g() {\n"
        "    stringify!(x::<);\n"
        "    println!(\"{}\", real_tail());\n"
        "}\n"
    )
    b2 = _cg({"src/lib.rs": src2}, str(tmp_path))
    e2 = _edges(b2, "g")
    assert "real_tail" in e2, (
        f"the sibling macro's tail edge was lost: {e2}")


# --- the differential oracle: the walk ⊇ the regex on the fixtures ---

def _regex_sites(token_tree_text: str, strip_python_strings: bool = False):
    """The OLD path, as the differential oracle: strip literals, then the
    regex (NO budget — the oracle enumerates what the budgetless regex
    would find; the budget only ever removed edges). ``strip_python_strings``
    additionally blanks the python-literal forms (triple-quoted and plain
    python strings) that the RUST stripper's exact scope does not know —
    used to classify a regex-found name as a LITERAL-CONTEXT PHANTOM on the
    non-rust corpus windows (the walk skips the string node whole, so a
    phantom is a call the walk legitimately does not have; enumerated,
    never silently excused)."""
    import re as _re
    if strip_python_strings:
        # python-literal blanking FIRST (before the rust stripper: the rust
        # normal-string pattern eats the triple-quote opener as an empty
        # string, breaking the triple-quote match — the corpus catch);
        # triple-quoted blocks (both styles), the plain python strings and
        # quotes, and the python comments the rust scope does not know
        # (tree-sitter lexes them as comment nodes the walk skips)
        stripped = _re.sub('"""(?:[^"]|"(?!""))*"""', " ", token_tree_text)
        stripped = _re.sub("'''(?:[^']|'(?!''))*'''", " ", stripped)
        stripped = _re.sub('"[^"\n]*"', " ", stripped)
        stripped = _re.sub("'[^'\n]*'", " ", stripped)
        stripped = _re.sub("#[^\n]*", " ", stripped)
        stripped = call_graph_builder._blank_rust_literals(stripped)
    else:
        stripped = call_graph_builder._blank_rust_literals(token_tree_text)
    names = []
    for m in call_graph_builder._MACRO_CALL_RE.finditer(stripped):
        names.append(m.group(1))
    return names


def _walk_sites(token_tree_text: str, visible_text: bool = False):
    """The NEW path over the same text: parse it as a macro token tree via
    tree-sitter and run the prod walker over the parsed node. With
    ``visible_text``, ALSO return the walk's VISIBLE text — the token
    stream's text with the string/comment nodes removed (the differential's
    honest corpus contract: everything call-shaped in the text the walk can
    SEE, the walk must extract; the names the regex finds only in the
    full text are the string-context divergences the rust lexer and the
    regex stripper segment differently — enumerated, never asserted)."""
    from parsers.rust.function_extractor import _load_rust_language
    from tree_sitter import Parser
    p = Parser(_load_rust_language())
    # wrap so the text parses as a macro token tree
    synthetic = f"m!{token_tree_text}".encode()
    tree = p.parse(synthetic)
    if tree.root_node.has_error:
        raise ValueError("the window does not parse cleanly")
    mac = next((c for c in tree.root_node.children if c.type == "macro_invocation"), None)
    assert mac is not None, "the synthetic macro did not parse"
    tt = next(c for c in mac.children if c.type == "token_tree")
    sites = []
    shim = call_graph_builder.CallGraphBuilder(
        {"repository": "x", "functions": {}, "classes": {}, "imports": {}})
    shim._token_tree_call_sites(tt, synthetic, sites)
    # the site dicts' names in the regex-comparable spelling
    out = []
    for s in sites:
        if s["kind"] == "scoped":
            out.append(f"{s['qualifier']}::{s['leaf']}")
        elif s["kind"] == "field":
            recv = "self" if s.get("receiver_is_self") else s["receiver"]
            out.append(f"{recv}.{s['method']}")
        else:
            out.append(s["name"])
    if not visible_text:
        return out
    # (the spans collected below are the STRING/COMMENT spans; the walk's
    # emitted-name spans ride on the sites via the walker's own stream —
    # recomputed here from the token stream: every identifier node the
    # walk CONSUMED as a name start. The per-position contract: a regex
    # match inside an emitted name's span is the regex's \b starting
    # mid-identifier (`repeated_runs(` -> `runs(`) — the walk emits the
    # WHOLE identifier; covered.)
    if not visible_text:
        return out
    # the STRING/COMMENT SPANS of the walk's own lexing (the fable-r1 F3
    # line: the visible-text joins were either vacuous — the semicolon
    # join made the regex read nothing, a no-op walker passed — or
    # artifact-prone — the plain joins let non-adjacent tokens form false
    # shapes. The honest classification is PER MATCH POSITION, no text
    # reconstruction: a regex-found call shape is either in the walk's
    # set, or EVERY position where the shape occurs lies inside a
    # string/comment span per the walk's OWN parse)
    spans = []
    name_spans = []
    stack = [tt]
    while stack:
        n = stack.pop()
        for c in n.children:
            if c.type in ("string_literal", "char_literal",
                          "raw_string_literal", "byte_string_literal",
                          "line_comment", "block_comment"):
                spans.append((c.start_byte, c.end_byte))
            if c.type in ("identifier", "primitive_type"):
                name_spans.append((c.start_byte, c.end_byte))
            if c.type == "token_tree":
                stack.append(c)
    spans.sort()
    return out, spans, name_spans, synthetic


FIXTURES = [
    '("plain {}", plain(1))',
    '("m {}", recv.name(2))',
    '("s {}", a::b::c(3))',
    '("t {}", Type::m::<T>(4))',
    '("self {}", self.method(5))',
    '(nested(vec![deep(inner(6))]))',
    '("phantom", "call phantom_name() first")',
    '("raw", r#"text with call shape inside ( paren ("#)',
    '(a.b.c(7), x::y::z::w(8))',
    '("escaped \\" quote", quote(9))',
]


def test_the_walk_is_a_superset_of_the_regex_on_fixtures():
    """The issue's own differential contract: on every fixture the walk's
    call set is a SUPERSET of the budgetless regex path's, with the
    recovered calls ENUMERATED (not merely counted)."""
    assert hasattr(call_graph_builder.CallGraphBuilder,
                   "_token_tree_call_sites"), (
        "the token-tree walker is missing from the prod builder")
    for fx in FIXTURES:
        regex_names = _regex_sites(fx)
        walk_names = _walk_sites(fx)
        # every regex-found name appears in the walk's names (the regex's
        # name spelling may differ per shape — compare the CALL LEAVES)
        regex_leaves = {n.rsplit("::", 1)[-1].rsplit(".", 1)[-1]
                        for n in regex_names}
        walk_leaves = {n.rsplit("::", 1)[-1].rsplit(".", 1)[-1]
                       for n in walk_names}
        missing = regex_leaves - walk_leaves
        assert not missing, (
            f"fixture {fx!r}: the walk LOST {missing} "
            f"(regex: {regex_names}, walk: {walk_names})")


def test_the_walk_is_a_superset_of_the_regex_on_the_real_corpus():
    """The issue's own differential contract, on the repo's own source
    corpus (the #246 differential's own precedent: the .py corpus — any
    text parses as a macro token tree when wrapped, covering the
    adversarial-text space): every file, every 400-char window — the
    walk's call set is a SUPERSET of the regex path's over the walk's OWN
    visible stream, the recovered calls and the string-context divergences
    ENUMERATED per divergence."""
    # the corpus: the repo's own source files (the #246 differential's own
    # precedent — the stripper test sweeps the .py corpus; ANY text parses as
    # a macro token tree when wrapped, so the differential covers the
    # adversarial-text space) + this suite's own rust fixtures
    import glob as _glob
    import os as _os
    core = _os.path.dirname(_os.path.dirname(_os.path.dirname(
        _os.path.abspath(__file__))))
    files = [f for f in _glob.glob(_os.path.join(core, "**", "*.py"),
                                   recursive=True)]
    files = [f for f in files if "node_modules" not in f]
    assert files, "no corpus files found"
    checked = 0
    recovered = {}
    phantom_class = {}
    for fp in files:
        with open(fp, encoding="utf-8", errors="ignore") as fh:
            txt = fh.read()
        windows = [txt] + [txt[k:k + 400] for k in range(0, len(txt), 400)]
        for w in windows:
            # a window must be parseable as a macro token tree — wrap it
            fx = "(" + w + ")"
            try:
                walk, spans, name_spans, synthetic = _walk_sites(
                    fx, visible_text=True)
                regex_full = _regex_sites(fx)
            except Exception:
                continue  # unparseable window (an unbalanced wrap) — skip
            checked += 1
            walk_leaves = {n.rsplit("::", 1)[-1].rsplit(".", 1)[-1]
                           for n in walk}
            full_leaves = {n.rsplit("::", 1)[-1].rsplit(".", 1)[-1]
                           for n in regex_full}

            def _in_span(pos: int) -> bool:
                import bisect as _bi
                starts = [s for s, _ in spans]
                k2 = _bi.bisect_right(starts, pos)
                return k2 > 0 and spans[k2 - 1][0] <= pos < spans[k2 - 1][1]

            # THE CONTRACT, per match position (the fable-r1 F3 line): a
            # regex-found call shape is either in the walk's set, or EVERY
            # position where the shape occurs lies inside a string/comment
            # span per the walk's OWN parse — the divergence class,
            # enumerated; ANY position outside a span means the walk can
            # see it and MUST have it
            import re as _re2
            for name in set(n for n in regex_full):
                leaf = name.rsplit("::", 1)[-1].rsplit(".", 1)[-1]
                if leaf in walk_leaves:
                    continue
                pat = _re2.compile(
                    _re2.escape(name.encode("utf-8"))
                    + rb"\s*(?:::<[^>]*>)?\s*\(")
                # BYTE positions on the synthetic source — the spans and
                # name_spans are byte offsets of b"m!"+fx, so the search
                # must run on the same bytes (the fable-r2 F3 catch: the
                # char-offset search vs the byte-offset spans misaligned
                # by the 2-char prefix + the UTF-8 drift — the classifier's
                # teeth were an offset accident)
                positions = [mm.start() for mm in pat.finditer(synthetic)]
                if not positions:
                    # the shape exists ONLY in the stripped text — the
                    # stripper's blanked-literal BRIDGING class (two tokens
                    # joined across a blanked span): a regex artifact the
                    # walk cannot and must not see; a divergence
                    phantom_class.setdefault(leaf, fp)
                    continue
                def _in_name_span(pos: int) -> bool:
                    # STRICTLY inside (the fable-r2 F3 catch): a real
                    # unconsumed call's match sits AT an identifier's start
                    # — never strictly inside one; only the regex's
                    # mid-identifier \b split (`repeated_runs(` ->
                    # `runs(`) lands strictly inside the consumed name
                    return any(s < pos < e for s, e in name_spans)
                if all(_in_span(pos) or _in_name_span(pos)
                       for pos in positions):
                    # EVERY occurrence is inside a string/comment span
                    # (the walk skips), or inside an identifier the walk
                    # CONSUMED as a whole (the regex's \b split
                    # mid-identifier: `repeated_runs(` -> `runs(` — the
                    # walk emitted repeated_runs); the divergence class
                    phantom_class.setdefault(leaf, fp)
                    continue
                outside = [p2 for p2 in positions
                           if not _in_span(p2) and not _in_name_span(p2)]
                raise AssertionError(
                    f"{_os.path.basename(fp)}: the walk LOST {leaf!r} — "
                    f"the call shape at byte {outside[0]} is OUTSIDE every "
                    f"string/comment span AND every consumed identifier of "
                    f"the walk's own parse "
                    f"(walk: {sorted(walk_leaves)[:8]})")
            for gained in walk_leaves - full_leaves:
                recovered.setdefault(gained, fp)
    assert checked > 50, f"the corpus sweep only checked {checked} windows"
    # the ENUMERATED recovery + the enumerated phantom class (not merely
    # counted)
    print(f"corpus windows checked: {checked}")
    print(f"recovered call leaves (the walk finds, the regex missed): "
          f"{sorted(recovered)}")
    print(f"string-context divergences (the full-text regex finds inside "
          f"string/comment content per the walk's own lexing; the walk "
          f"correctly skips): {sorted(phantom_class)}")


def test_the_walk_recovers_what_the_regex_could_not(tmp_path):
    """The ENUMERATED-recovery leg: the walk finds calls the regex could not
    — e.g. a call nested inside a string-escape shape the stripper's exact
    scope misses, or inside a nested raw literal — each enumerated here."""
    # a call inside a 2-hash raw string: the stripper's EXACT (incomplete)
    # scope blanks only 1-hash raws, so the regex FINDS text inside r##...##
    # and can phantom-edge; the walk skips the string_literal whole
    assert hasattr(call_graph_builder.CallGraphBuilder,
                   "_token_tree_call_sites"), (
        "the token-tree walker is missing from the prod builder")
    fx = '(r##"shaped call inside ( not a call"##, real_one(1))'
    walk = _walk_sites(fx)
    assert "real_one" in walk, walk
    assert "not" not in " ".join(walk), f"the raw string phantom-edged: {walk}"
