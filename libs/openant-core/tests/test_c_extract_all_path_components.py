"""Regression: c/function_extractor extract_all over-excludes by substring.

extract_all filters discovered files with `any(excl in str(file_path) for excl in [.git,build,test,
node_modules])` — an unanchored SUBSTRING test against the absolute path. So a file whose path merely
*contains* a token is wrongly skipped ('src/latest/main.c' contains 'test'; 'contest/sol.c' too), and an
ANCESTOR dir of repo_path that contains a token poisons the whole scan (a checkout under '/home/tester/'
excludes everything — pytest's own tmp_path, which contains 'test', reproduces this). Fix: match on path
COMPONENTS relative to repo_path, using c's own token set.
"""
import importlib.util
import sys
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]                              # libs/openant-core
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))                                       # for utilities.file_io

# Load the C parser's function_extractor under a UNIQUE module name (not the bare
# 'function_extractor') so we do NOT pollute sys.modules for sibling parser tests:
# parsers/python also ships a 'function_extractor' module, and a bare import here would
# shadow it for the whole pytest session. The C module imports only stdlib + tree_sitter_c +
# utilities.file_io, so no parsers/c entry on sys.path is required.
_spec = importlib.util.spec_from_file_location(
    "c_function_extractor_isolated", str(CORE / "parsers" / "c" / "function_extractor.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
FunctionExtractor = _mod.FunctionExtractor


def test_extract_all_excludes_on_path_components_not_substring(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    for d in ("src/latest", "contest", "src", "test", ".git"):
        (repo / d).mkdir(parents=True, exist_ok=True)
    (repo / "src" / "latest" / "main.c").write_text("int latest_fn(void){return 1;}\n")
    (repo / "contest" / "sol.c").write_text("int contest_fn(void){return 2;}\n")
    (repo / "src" / "clean.c").write_text("int clean_fn(void){return 3;}\n")
    (repo / "test" / "helper.c").write_text("int test_helper(void){return 4;}\n")   # real test/ dir
    (repo / ".git" / "hook.c").write_text("int git_fn(void){return 5;}\n")          # .git

    ex = FunctionExtractor(str(repo))
    processed = []
    monkeypatch.setattr(ex, "process_file",
                        lambda fp: processed.append(Path(fp).relative_to(ex.repo_path).as_posix()))
    ex.extract_all()
    procset = set(processed)

    # path merely CONTAINS a token -> must still be processed (substring match was the bug)
    assert "src/latest/main.c" in procset, f"'latest' wrongly excluded by 'test' substring: {sorted(procset)}"
    assert "contest/sol.c" in procset, f"'contest' wrongly excluded: {sorted(procset)}"
    assert "src/clean.c" in procset
    # genuine excluded directory NAMES stay excluded
    assert "test/helper.c" not in procset, "a real test/ directory should stay excluded"
    assert ".git/hook.c" not in procset, ".git should stay excluded"
