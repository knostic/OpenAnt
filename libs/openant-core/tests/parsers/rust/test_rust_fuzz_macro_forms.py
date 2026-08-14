"""S4: recognize more fuzz-harness macro forms — aliased libFuzzer imports and
AFL's `fuzz!` — while NOT over-matching an unrelated macro.

The base recognizer (_FUZZ_MACRO_NAMES=('fuzz_target',), leaf-name match) sees
only libFuzzer's `fuzz_target!` (bare or path-qualified). It misses:
  - an aliased import `use libfuzzer_sys::fuzz_target as ft; ft!(...)`
  - AFL's `fuzz!` (path-qualified `afl::fuzz!` or `use afl::fuzz; fuzz!(...)`)
A fuzz harness is an untrusted entry point; a missed one makes everything
reachable only from it a reachability false-negative.

Recognition resolves the invoked macro name THROUGH the file's `use` imports to
its origin crate, and matches only:
  - macro_name == 'fuzz_target'  (any crate — the distinctive libFuzzer name), OR
  - macro_name == 'fuzz' AND origin crate is 'afl'  (generic name, afl-gated).
Path-resolution is the over-match guard: `use evil::thing as fuzz_target` resolves
to evil::thing and is NOT a harness; a bare `fuzz!` with no afl import is NOT one.

Out of scope (deferred follow-up): macro_rules!-wrapped harnesses.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _rust_helpers import build  # noqa: E402

FRAME = """
pub struct Frame;
impl Frame {
    pub fn decode(d: &[u8]) -> Frame { Frame }
}
"""


def _harness_ids(cg):
    return [k for k, v in cg["functions"].items() if v.get("synthetic_harness")]


def _one(tmp_path, fuzz_src):
    _, cg = build(tmp_path, {"src.rs": FRAME, "fuzz/h.rs": fuzz_src}, skip_tests=False)
    return cg


# --- forms that MUST now be recognized (RED pre-fix: 0 harnesses) ---

def test_aliased_libfuzzer_import_is_seeded(tmp_path):
    cg = _one(tmp_path,
              "use libfuzzer_sys::fuzz_target as ft;\n"
              "ft!(|data: &[u8]| { let _ = Frame::decode(data); });\n")
    assert len(_harness_ids(cg)) == 1, "aliased `fuzz_target as ft` harness not seeded"


def test_afl_path_qualified_is_seeded(tmp_path):
    cg = _one(tmp_path,
              "afl::fuzz!(|data: &[u8]| { let _ = Frame::decode(data); });\n")
    assert len(_harness_ids(cg)) == 1, "`afl::fuzz!` harness not seeded"


def test_afl_imported_fuzz_is_seeded(tmp_path):
    cg = _one(tmp_path,
              "use afl::fuzz;\n"
              "fuzz!(|data: &[u8]| { let _ = Frame::decode(data); });\n")
    assert len(_harness_ids(cg)) == 1, "`use afl::fuzz; fuzz!` harness not seeded"


# --- negative controls: must NOT be recognized ---

def test_bare_fuzz_without_afl_import_is_not_seeded(tmp_path):
    # A user macro coincidentally named `fuzz!`, no afl import -> not a harness.
    cg = _one(tmp_path,
              "fuzz!(some, args, here);\n")
    assert len(_harness_ids(cg)) == 0, "over-matched a non-afl `fuzz!` macro"


def test_evil_alias_to_fuzz_target_name_is_not_seeded(tmp_path):
    # `fuzz_target` is here an ALIAS for an unrelated macro -> must resolve to
    # evil::thing and NOT be treated as the libFuzzer harness. Uses a CLOSURE
    # body so the recognizer (not the closure-shape guard in _handle_fuzz_target)
    # is what must reject it.
    cg = _one(tmp_path,
              "use evil::thing as fuzz_target;\n"
              "fuzz_target!(|data: &[u8]| { let _ = Frame::decode(data); });\n")
    assert len(_harness_ids(cg)) == 0, "over-matched an aliased non-harness macro"


# --- guard: the base forms must still work (byte-identity) ---

def test_base_bare_fuzz_target_still_seeded(tmp_path):
    cg = _one(tmp_path,
              "fuzz_target!(|data: &[u8]| { let _ = Frame::decode(data); });\n")
    assert len(_harness_ids(cg)) == 1, "base bare fuzz_target! regressed"


def test_base_path_qualified_libfuzzer_still_seeded(tmp_path):
    cg = _one(tmp_path,
              "libfuzzer_sys::fuzz_target!(|data: &[u8]| { let _ = Frame::decode(data); });\n")
    assert len(_harness_ids(cg)) == 1, "base libfuzzer_sys::fuzz_target! regressed"


# --- AFL brought into bare macro scope (classic afl.rs forms) ---

def test_afl_macro_use_extern_crate_is_seeded(tmp_path):
    # The classic afl.rs README form: `#[macro_use] extern crate afl;` brings
    # `fuzz!` into bare scope.
    cg = _one(tmp_path,
              "#[macro_use] extern crate afl;\n"
              "fn main() { fuzz!(|data: &[u8]| { let _ = Frame::decode(data); }); }\n")
    assert len(_harness_ids(cg)) == 1, "`#[macro_use] extern crate afl` harness not seeded"


def test_afl_glob_import_is_seeded(tmp_path):
    cg = _one(tmp_path,
              "use afl::*;\n"
              "fuzz!(|data: &[u8]| { let _ = Frame::decode(data); });\n")
    assert len(_harness_ids(cg)) == 1, "`use afl::*; fuzz!` harness not seeded"


def test_plain_extern_crate_afl_without_macro_use_is_not_seeded(tmp_path):
    # `extern crate afl;` WITHOUT `#[macro_use]` does NOT bring the macro into
    # scope (edition-2015 rule) — a bare `fuzz!` must not be recognized.
    cg = _one(tmp_path,
              "extern crate afl;\n"
              "fn main() { fuzz!(|data: &[u8]| { let _ = Frame::decode(data); }); }\n")
    assert len(_harness_ids(cg)) == 0, "over-matched `fuzz!` under plain `extern crate afl`"


def test_afl_non_macro_import_does_not_scope_fuzz(tmp_path):
    # Importing a specific non-macro item from afl does NOT bring `fuzz!` into
    # scope; a coincidental bare `fuzz!` must not be recognized.
    cg = _one(tmp_path,
              "use afl::Corpus;\n"
              "fuzz!(some, args);\n")
    assert len(_harness_ids(cg)) == 0, "over-matched a bare `fuzz!` on a non-macro afl import"
