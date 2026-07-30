"""
Conformance test for F2: shared segment-membership directory exclusion.

Bug (two independent call sites used SUBSTRING containment instead of
whole-path-segment membership):

  * parsers/ruby/function_extractor.py:838
        any(excl in path_str for excl in ['.git','vendor','.bundle','tmp',...])
    A file whose path merely *contains* an excluded token as a substring
    (e.g. a repo checked out under a ``tmpXXXX`` temp dir, or a ``vendored/``
    directory containing ``vendor``) was silently dropped.

  * parsers/zig/repository_scanner.py:116  (_matches_exclude_pattern)
        for pattern in self.exclude_patterns: if pattern in name: return True
    ``contest`` matched pattern ``test``; ``rebuild`` matched ``build``.

Fix: both delegate to utilities.path_filters.should_exclude_directory, whose
contract mirrors core/parser_adapter.py:57 -- whole path-segment membership,
``any(p in patterns for p in Path(path).parts)``.

The test drives the REAL call sites (no direct import of the new helper), so:
  * ORIGINAL core  -> substring semantics -> assertions fail  (RED)
  * PATCHED core   -> segment  semantics  -> assertions pass  (GREEN)

Point it at a specific core tree with env OPENANT_CORE_ROOT (defaults to the
pristine repo).  The orchestrator runs it once against the pristine core (RED)
and once against a patched copy (GREEN).

    OPENANT_CORE_ROOT=/path/to/openant-core \
        python -m pytest F2-shared-segment-exclusion.test.py
"""

import importlib.util
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

_CORE_ROOT = os.environ.get(
    "OPENANT_CORE_ROOT",
    str(Path(__file__).resolve().parent.parent.parent),
)
if _CORE_ROOT not in sys.path:
    sys.path.insert(0, _CORE_ROOT)


def _load(mod_name: str, rel_path: str):
    path = os.path.join(_CORE_ROOT, rel_path)
    spec = importlib.util.spec_from_file_location(mod_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ----------------------------------------------------------------------------
# zig: _matches_exclude_pattern must be whole-segment, not substring.
# ----------------------------------------------------------------------------
def _scanner_cls():
    return _load("_f2_zig_scanner", "parsers/zig/repository_scanner.py").RepositoryScanner


def test_zig_exclude_pattern_is_segment_not_substring():
    with tempfile.TemporaryDirectory() as repo:
        scanner = _scanner_cls()(repo, exclude_patterns=["test", "build"])
        # Names that merely CONTAIN an excluded token are NOT excluded.
        assert scanner._matches_exclude_pattern("contest") is False
        assert scanner._matches_exclude_pattern("rebuild") is False
        assert scanner._matches_exclude_pattern("latest") is False
        # Exact whole-name segments ARE excluded.
        assert scanner._matches_exclude_pattern("test") is True
        assert scanner._matches_exclude_pattern("build") is True
        # No patterns -> nothing excluded.
        empty = _scanner_cls()(repo, exclude_patterns=[])
        assert empty._matches_exclude_pattern("build") is False


def test_zig_scan_keeps_substring_named_dirs():
    RepositoryScanner = _scanner_cls()
    with tempfile.TemporaryDirectory() as repo:
        root = Path(repo)
        for d in ("contest", "test", "src"):
            (root / d).mkdir()
        (root / "contest" / "a.zig").write_text("fn a() void {}\n")
        (root / "test" / "b.zig").write_text("fn b() void {}\n")
        (root / "src" / "c.zig").write_text("fn c() void {}\n")

        scanner = RepositoryScanner(str(root), skip_tests=False, exclude_patterns=["test"])
        result = scanner.scan()
        found = {f["path"].replace(os.sep, "/") for f in result["files"]}

        assert "contest/a.zig" in found          # substring 'test' must NOT exclude
        assert "src/c.zig" in found
        assert "test/b.zig" not in found          # exact segment IS excluded


# ----------------------------------------------------------------------------
# ruby: extract_all's exclusion must be whole-segment, not substring.
# ----------------------------------------------------------------------------
def _extractor_cls():
    return _load("_f2_ruby_extractor", "parsers/ruby/function_extractor.py").FunctionExtractor


def test_ruby_extract_all_keeps_substring_named_dirs():
    FunctionExtractor = _extractor_cls()
    # NOTE: mkdtemp() yields a leaf like ``tmpXXXX`` -- it CONTAINS 'tmp' as a
    # substring but is not an exact 'tmp' segment.  Substring semantics (the
    # bug) therefore drop EVERY file under it; segment semantics keep them.
    repo = tempfile.mkdtemp()
    try:
        root = Path(repo)
        for d in ("vendored", "vendor", "src"):
            (root / d).mkdir()
        (root / "vendored" / "keep.rb").write_text("def keep_me\nend\n")
        (root / "vendor" / "skip.rb").write_text("def skip_me\nend\n")
        (root / "src" / "plain.rb").write_text("def plain\nend\n")

        extractor = FunctionExtractor(str(root))
        base = extractor.repo_path
        processed = []
        # Isolate the FILTER decision from tree-sitter parsing: record which
        # files survive exclusion and would have been parsed.
        extractor.process_file = lambda p: processed.append(
            Path(p).relative_to(base).as_posix()
        )
        extractor.extract_all()

        assert "vendored/keep.rb" in processed   # substring 'vendor' must NOT exclude
        assert "src/plain.rb" in processed        # not excluded by tmp-prefixed root
        assert "vendor/skip.rb" not in processed  # exact segment IS excluded
    finally:
        shutil.rmtree(repo, ignore_errors=True)


if __name__ == "__main__":
    # importlib mode: the file name contains '-'/'.test' and is not a valid
    # module identifier for pytest's default (prepend) import mode.
    raise SystemExit(pytest.main([__file__, "-v", "--import-mode=importlib"]))
