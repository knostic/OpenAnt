"""File-boundary markers must be comment-syntax-agnostic.

Producers emit the boundary using each language's own comment syntax — Python
and Ruby use ``#``, the rest use ``//`` — because a ``//`` line inside Python
source is a syntax error. Every consumer, however, matched the ``//`` form
literally. The result was not a cosmetic schema complaint: for Python and Ruby
multi-file units the split never fired, so the whole concatenation was handed
to the model as the target function and the "do NOT analyze these" context
section vanished.

These tests pin the invariant substring — everything between the comment
prefix and the end — as the thing consumers agree on.
"""

import pytest

from core.file_boundary import (
    BOUNDARY_TEXT,
    boundary_for_language,
    boundary_in_code,
    has_boundary,
    split_on_boundary,
)

PY_CODE = "def target():\n    pass\n\n# ========== File Boundary ==========\n\ndef dep():\n    pass\n"
JS_CODE = "function target() {}\n\n// ========== File Boundary ==========\n\nfunction dep() {}\n"


class TestDetection:
    @pytest.mark.parametrize("code", [PY_CODE, JS_CODE])
    def test_both_comment_styles_are_detected(self, code):
        assert has_boundary(code)

    def test_code_without_a_boundary_is_not_detected(self):
        assert not has_boundary("def only():\n    pass\n")

    def test_the_invariant_text_carries_no_comment_prefix(self):
        assert not BOUNDARY_TEXT.startswith("#")
        assert not BOUNDARY_TEXT.startswith("//")
        assert "File Boundary" in BOUNDARY_TEXT


class TestSplitting:
    @pytest.mark.parametrize("code,dep_name", [(PY_CODE, "dep"), (JS_CODE, "dep")])
    def test_split_separates_target_from_dependencies(self, code, dep_name):
        parts = split_on_boundary(code)
        assert len(parts) == 2
        assert "target" in parts[0]
        assert dep_name not in parts[0], (
            "dependency code leaked into the target part — this is the bug "
            "that put 3 functions inside the ANALYZE-ONLY prompt block"
        )
        assert dep_name in parts[1]

    def test_single_file_code_yields_one_part(self):
        assert len(split_on_boundary("def only():\n    pass\n")) == 1

    def test_multiple_boundaries_split_into_all_parts(self):
        code = (
            "def a(): pass\n"
            "# ========== File Boundary ==========\n"
            "def b(): pass\n"
            "# ========== File Boundary ==========\n"
            "def c(): pass\n"
        )
        assert len(split_on_boundary(code)) == 3

    def test_mixed_comment_styles_in_one_blob_all_split(self):
        """Defensive: a merged multi-language unit could carry both."""
        code = (
            "def a(): pass\n"
            "# ========== File Boundary ==========\n"
            "function b() {}\n"
            "// ========== File Boundary ==========\n"
            "def c(): pass\n"
        )
        assert len(split_on_boundary(code)) == 3


class TestBoundaryForLanguage:
    @pytest.mark.parametrize("language,prefix", [
        ("python", "#"),
        ("ruby", "#"),
        ("javascript", "//"),
        ("go", "//"),
        ("c", "//"),
        ("php", "//"),
        ("zig", "//"),
    ])
    def test_emits_the_comment_syntax_the_language_actually_uses(self, language, prefix):
        marker = boundary_for_language(language)
        assert marker.strip().startswith(prefix)
        assert BOUNDARY_TEXT in marker

    def test_unknown_language_defaults_to_slash_style(self):
        """Matches the pre-existing default in the agentic enhancer."""
        assert boundary_for_language("cobol").strip().startswith("//")

    def test_is_case_insensitive(self):
        assert boundary_for_language("Python").strip().startswith("#")


class TestRealProducerOutputRoundTrips:
    """The exact strings the producers emit must be splittable."""

    @pytest.mark.parametrize("marker", [
        "\n\n# ========== File Boundary ==========\n\n",   # python, ruby
        "\n\n// ========== File Boundary ==========\n\n",  # js, go, c, php, zig
    ])
    def test_producer_marker_splits(self, marker):
        code = f"def target(): pass{marker}def dep(): pass"
        parts = split_on_boundary(code)
        assert len(parts) == 2
        assert "dep" not in parts[0]


class TestBoundaryInCode:
    """Re-joining must echo the producer's own marker, not impose one."""

    def test_python_code_round_trips_its_hash_marker(self):
        assert boundary_in_code(PY_CODE).strip().startswith("#")

    def test_javascript_code_round_trips_its_slash_marker(self):
        assert boundary_in_code(JS_CODE).strip().startswith("//")

    def test_falls_back_to_language_when_code_has_no_boundary(self):
        assert boundary_in_code("def only(): pass", "python").strip().startswith("#")

    def test_falls_back_to_default_when_nothing_is_known(self):
        assert boundary_in_code("def only(): pass").strip().startswith("//")

    def test_split_then_join_is_lossless_for_both_styles(self):
        for code in (PY_CODE, JS_CODE):
            parts = split_on_boundary(code)
            rejoined = boundary_in_code(code).join(p.strip() for p in parts)
            assert BOUNDARY_TEXT in rejoined
            assert rejoined.count(BOUNDARY_TEXT) == code.count(BOUNDARY_TEXT)
