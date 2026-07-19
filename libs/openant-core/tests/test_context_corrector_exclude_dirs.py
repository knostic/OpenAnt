"""Regression: gather_source_files must mirror the parsers' canonical skip dirs.

The default extension list of gather_source_files was broadened from JS-only to
every language OpenAnt parses (go/python/ruby/rust/php/zig/c). That broadened
walk now descends into dependency/build/VCS trees the JS-only default never
reached -- Python __pycache__/.venv, Ruby .bundle/tmp, a top-level .git, etc.
If exclude_dirs is not extended to mirror the canonical skip set
(config/languages.json -> skip_dirs, unioned with the extractors' skips), the
corrector "corrects" security context against vendored/generated code.

This test drives the real gather_source_files with DEFAULT extensions over a
repo that places source files BOTH at the top level (must be gathered) and
inside canonical skip dirs (must be excluded).
"""
from pathlib import Path

from utilities.context_corrector import gather_source_files

# Top-level source that MUST be gathered.
INCLUDED = {
    "handler.js",
    "app.py",
    "server.rb",
    "index.ts",
}

# (skip_dir, filename) source that MUST be excluded because it lives under a
# canonical non-source directory. Covers the dirs the pre-fix JS-only default
# already excluded (node_modules) AND the ones only reachable once the walk
# went multi-language (__pycache__, .venv, .bundle, tmp, vendor, .git).
EXCLUDED = {
    ("node_modules", "lib.ts"),   # audit-named case (already excluded pre-fix)
    ("__pycache__", "mod.py"),    # python build cache
    (".venv", "site.py"),         # python virtualenv
    (".bundle", "gem.rb"),        # ruby bundler
    ("tmp", "scratch.rb"),        # ruby tmp
    ("vendor", "vend.go"),        # vendored deps
    (".git", "hook.py"),          # VCS internals
}


def test_gather_source_files_excludes_canonical_skip_dirs(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    for fname in INCLUDED:
        (repo / fname).write_text(f"// top-level {fname}\n", encoding="utf-8")

    for skip_dir, fname in EXCLUDED:
        d = repo / skip_dir
        d.mkdir(parents=True, exist_ok=True)
        (d / fname).write_text(f"// vendored/generated {fname}\n", encoding="utf-8")

    gathered = gather_source_files(str(repo))  # DEFAULT extensions (what every caller uses)
    gathered_names = {Path(f["relative_path"]).name for f in gathered}

    missing = INCLUDED - gathered_names
    assert not missing, f"top-level source was dropped: {missing}"

    leaked = {f"{d}/{fn}" for d, fn in EXCLUDED if fn in gathered_names}
    assert not leaked, f"gather_source_files walked into canonical skip dirs: {sorted(leaked)}"
