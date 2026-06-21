"""Regression tests for three independent defects in parsers/python/function_extractor.py.

Segment-vs-substring exclusion: extract_all() no-args branch excludes files via an UNANCHORED
  substring test (`any(excl in str(file_path) ...)`), so a file whose path merely contains a token
  ('myvenv/keep.py' contains 'venv') is wrongly skipped. Fix: match whole path SEGMENTS.
Entry-point classification: classify_function uses `'<token>' in path_lower` substring tests to
  assign ENTRY-POINT unit_types, so 'interviews/api.py' is classified 'view_function' (a false
  reachability seed). Fix: match the 'views'/'middleware' tokens as whole path segments. ('test' is
  intentionally left as a substring -- see the in-code note; it is not an entry-point type.)
Relative-import anchor: extract_imports ignores ast.ImportFrom.level, so relative imports lose their
  package anchor ('from . import X' -> bare 'X'). Fix: reconstruct the absolute anchor from the
  importing file's location.

Loads function_extractor under a UNIQUE module name (not the bare 'function_extractor', which the c/
go/php/ruby/zig parsers also ship) so a bare import cannot pollute sys.modules for sibling tests.
"""
import ast
import importlib.util
import sys
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]                  # libs/openant-core
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))                           # for utilities.* if imported

_spec = importlib.util.spec_from_file_location(
    "py_function_extractor_isolated", str(CORE / "parsers" / "python" / "function_extractor.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
FunctionExtractor = _mod.FunctionExtractor


# ---- extract_all excludes by path segment, not substring ----
def test_extract_all_excludes_on_path_segments_not_substring(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    for d in ("myvenv", "venv", ".git", "pkg/__pycache__", "src"):
        (repo / d).mkdir(parents=True, exist_ok=True)
    (repo / "myvenv" / "keep.py").write_text("def f(): pass\n")      # 'venv' substring -> wrongly skipped pre-fix
    (repo / "src" / "clean.py").write_text("def g(): pass\n")
    (repo / "venv" / "skip.py").write_text("def h(): pass\n")        # real venv/ -> excluded
    (repo / ".git" / "hook.py").write_text("def i(): pass\n")        # .git -> excluded
    (repo / "pkg" / "__pycache__" / "c.py").write_text("def j(): pass\n")  # __pycache__ -> excluded

    ex = FunctionExtractor(str(repo))
    processed = []
    monkeypatch.setattr(ex, "process_file",
                        lambda fp: processed.append(Path(fp).relative_to(ex.repo_path).as_posix()))
    ex.extract_all()
    seen = set(processed)

    assert "myvenv/keep.py" in seen, f"'myvenv' wrongly excluded by 'venv' substring: {sorted(seen)}"
    assert "src/clean.py" in seen
    assert "venv/skip.py" not in seen, "a real venv/ directory must stay excluded"
    assert ".git/hook.py" not in seen, ".git must stay excluded"
    assert "pkg/__pycache__/c.py" not in seen, "__pycache__ must stay excluded"


# ---- classify_function matches entry-point tokens by segment, not substring ----
def test_classify_function_entrypoint_tokens_match_segments_not_substring(tmp_path):
    ex = FunctionExtractor(str(tmp_path))
    c = lambda path: ex.classify_function("handler", [], None, path)

    # genuine segments still classify (no regression)
    assert c("app/views.py") == "view_function"
    assert c("app/views/handlers.py") == "view_function"
    assert c("app/middleware/auth.py") == "middleware"
    # substring over-matches must NOT seed entry-point types
    assert c("interviews/api.py") != "view_function", "'interviews' wrongly matched 'views'"
    assert c("app/previews/x.py") != "view_function", "'previews' wrongly matched 'views'"
    assert c("app/previewmiddleware.py") != "middleware", "'previewmiddleware' wrongly matched 'middleware'"


# ---- extract_imports preserves the relative-import package anchor (node.level) ----
def test_extract_imports_preserves_relative_package_anchor(tmp_path):
    ex = FunctionExtractor(str(tmp_path))
    src = "from . import helpers\nfrom ..util import U\nfrom os import path\n"
    imports = ex.extract_imports(ast.parse(src), "pkg/sub/mod.py")

    assert imports["helpers"] == "pkg.sub.helpers", f"relative 'from . import' lost anchor: {imports}"
    assert imports["U"] == "pkg.util.U", f"relative 'from ..util import' lost anchor: {imports}"
    assert imports["path"] == "os.path", f"absolute import must be unchanged: {imports}"
