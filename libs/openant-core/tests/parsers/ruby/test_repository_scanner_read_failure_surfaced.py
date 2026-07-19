"""Regression test for RepositoryScanner silent directory-read-failure drop.

When ``scan_directory`` cannot read a directory (PermissionError / OSError) it
prints a warning to *stderr* and ``return``s, dropping every file underneath
that directory from the scan. The structured ``scan()`` result, however, carried
NO signal of this: ``statistics`` reported a fully "successful" scan even though
the module promises to "Enumerate ALL Ruby source files ... for complete
coverage". A programmatic consumer of the JSON/dict result (which does not watch
stderr) therefore received a silently-incomplete file list.

Fix: record failed directory reads in ``statistics`` so the drop is observable
in the structured result. This test asserts that signal exists.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[3]
if str(_CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CORE_ROOT))


def _load_scanner():
    path = _CORE_ROOT / "parsers" / "ruby" / "repository_scanner.py"
    spec = importlib.util.spec_from_file_location("rs_ruby_read_failure", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.RepositoryScanner


SCANNER = _load_scanner()


def test_unreadable_directory_is_surfaced_in_statistics(tmp_path, monkeypatch):
    # root.rb is readable; the nested dir will be made to fail on read.
    (tmp_path / "root.rb").write_text("class A; end\n")
    unreadable = tmp_path / "unreadable"
    unreadable.mkdir()
    (unreadable / "hidden.rb").write_text("class B; end\n")
    target = unreadable.resolve()

    orig_iterdir = Path.iterdir

    def fake_iterdir(self):
        if self.resolve() == target:
            raise PermissionError("simulated read failure")
        return orig_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", fake_iterdir)

    scanner = SCANNER(str(tmp_path))
    result = scanner.scan()
    stats = result["statistics"]

    # hidden.rb under the unreadable dir was dropped (documents the drop).
    paths = {f["path"] for f in result["files"]}
    assert "root.rb" in paths
    assert not any(p.endswith("hidden.rb") for p in paths)

    # The silent-drop must be surfaced in the structured result, not only stderr.
    assert stats.get("directories_read_failed", 0) >= 1, (
        "directory-read failure was swallowed silently: the scan result gives "
        "no signal that files were dropped"
    )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "-p", "no:cacheprovider"]))
