"""PR #763 review: repository source shown to the model is fenced with its own
language, not always ```python. Only the label changes: the fenced source and
every parser that reads these blocks back are unaffected."""

from __future__ import annotations

import pytest

from utilities.autopatcher import patch_challenger as pc
from utilities.autopatcher.remediation_planner import (
    _extract_fenced_code,
    _fence_language,
    _render_definition_block,
    _render_full_file_block,
    _render_source_excerpt,
)

_SOURCES = {
    "pkg/handler.py": ("python", "def handle(req):\n    return run(req)"),
    "vault/handler.go": ("go", "func handle(req *Request) error {\n\treturn run(req)\n}"),
    "src/sds.c": ("c", "sds sdsnew(const char *init) {\n    return sdsnewlen(init, strlen(init));\n}"),
    "Sources/Files.swift": ("swift", "func move() throws {\n    try fm.moveItem(at: a, to: b)\n}"),
    "config/rules.unknownext": ("", "rule a = b"),
}


@pytest.mark.parametrize("path", list(_SOURCES))
class TestFenceLabels:
    def test_label_matches_the_language(self, path):
        assert _fence_language(path) == _SOURCES[path][0]

    def test_every_renderer_uses_the_label_and_keeps_the_source(self, path):
        label, source = _SOURCES[path]
        for block in (
            _render_definition_block(path, "handle", 1, len(source.splitlines()), source),
            _render_full_file_block(path, source),
            _render_source_excerpt(path, "handle", 1, len(source.splitlines()), source),
        ):
            assert f"\n```{label}\n{source}\n```\n" in block
            assert "```python" not in block or label == "python"
            assert _extract_fenced_code(block).rstrip("\n") == source


class TestChallengerReadsAnyLabel:
    def test_complete_block_proof_accepts_a_go_block(self):
        """The `absent`-guard completeness proof must keep recognizing a
        renderer's complete block whatever its language label."""
        source = "func handle(req *Request) error {\n\treturn run(req)\n}"
        block = _render_definition_block("vault/handler.go", "handle", 1, 3, source)
        assert list(pc._mechanically_verified_complete_blocks(block)) == [source]
