"""Markdown code fences must be chosen per FILE, not per scan.

The reporter was handed the scan-wide language and used it for every finding's
fence. That is wrong even in a single-language scan: a ``.ts`` file inside a
"javascript" scan was fenced as ```javascript. In a multi-language scan it is
wrong for every finding outside the primary language.
"""

import pytest

from core.reporter import _build_vulnerable_code_section

CODE = "const x = 1;"


def fence_of(section: str) -> str:
    """The info-string of the first fence in a rendered section."""
    for line in section.splitlines():
        if line.startswith("```"):
            return line.lstrip("`").strip()
    return ""


class TestFenceFollowsTheFile:
    @pytest.mark.parametrize("path,expected", [
        ("src/app.ts", "typescript"),
        ("src/app.tsx", "typescript"),
        ("src/app.js", "javascript"),
        ("src/app.jsx", "javascript"),
        ("app/main.py", "python"),
        ("cmd/root.go", "go"),
        ("lib/a.c", "c"),
        ("lib/a.cpp", "cpp"),
        ("app/m.rb", "ruby"),
        ("i.php", "php"),
        ("main.zig", "zig"),
    ])
    def test_extension_decides_the_fence(self, path, expected):
        section = _build_vulnerable_code_section(
            file_path=path, code=CODE, language="javascript"
        )
        assert fence_of(section) == expected

    def test_typescript_is_not_mislabelled_as_javascript(self):
        """Fails on main: the scan-wide 'javascript' wins over the .ts file."""
        section = _build_vulnerable_code_section(
            file_path="src/app.ts", code=CODE, language="javascript"
        )
        assert fence_of(section) == "typescript"

    def test_scan_language_does_not_override_the_file(self):
        """A python finding in a javascript-primary scan fences as python."""
        section = _build_vulnerable_code_section(
            file_path="tools/gen.py", code=CODE, language="javascript"
        )
        assert fence_of(section) == "python"


class TestFallbacks:
    def test_unknown_path_falls_back_to_the_scan_language(self):
        section = _build_vulnerable_code_section(
            file_path="unknown", code=CODE, language="python"
        )
        assert fence_of(section) == "python"

    def test_unknown_path_and_unknown_language_degrades_to_bare_fence(self):
        section = _build_vulnerable_code_section(
            file_path="unknown", code=CODE, language=None
        )
        assert fence_of(section) == ""

    def test_empty_code_yields_no_section(self):
        assert _build_vulnerable_code_section(
            file_path="a.py", code="", language="python"
        ) == ""
