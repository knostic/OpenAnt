"""Regression: context_corrector.gather_source_files must cover every language OpenAnt parses.

When the LLM returns INSUFFICIENT_CONTEXT, ContextCorrector.gather_source_files() walks the repo to
feed candidate source files to the LLM-based semantic search. Its default extension list historically
covered only the JS/TS family (.js/.ts/.jsx/.tsx/.ejs/.pug/.hbs/.json). OpenAnt, however, parses
c, go, php, python, ruby, rust and zig. For a repo in any of those languages the default glob gathers
NO source files, so context correction is silently skipped for every non-JS project.

This test drives the real gather_source_files with its DEFAULT extensions (all three call sites pass no
extensions arg) over a mixed-language repo and asserts each supported language's source is discovered.
"""
from pathlib import Path

from utilities.context_corrector import gather_source_files

# language -> a representative source filename that must be discoverable by default
LANG_FILES = {
    "go": "main.go",
    "python": "app.py",
    "ruby": "server.rb",
    "rust": "lib.rs",
    "php": "index.php",
    "zig": "build.zig",
    "c": "parser.c",
    "javascript": "handler.js",  # baseline that already worked
}


def test_gather_source_files_covers_all_parsed_languages(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    for fname in LANG_FILES.values():
        (repo / fname).write_text(f"// content of {fname}\n", encoding="utf-8")

    gathered = gather_source_files(str(repo))  # DEFAULT extensions (what every caller uses)
    gathered_names = {Path(f["relative_path"]).name for f in gathered}

    missing = {lang: fname for lang, fname in LANG_FILES.items() if fname not in gathered_names}
    assert not missing, f"gather_source_files skipped source for languages OpenAnt parses: {missing}"
