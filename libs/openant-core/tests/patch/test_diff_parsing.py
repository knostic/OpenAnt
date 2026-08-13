from utilities.autopatcher.diff_parsing import DiffHunk, parse_diff, semantic_delta


def test_empty_input_returns_no_files_or_hunks():
    changed_files, file_hunks = parse_diff("")
    assert changed_files == []
    assert file_hunks == {}


def test_non_diff_input_returns_no_files_or_hunks():
    changed_files, file_hunks = parse_diff("hello\nworld\nthis is not a diff\n")
    assert changed_files == []
    assert file_hunks == {}


def test_one_changed_file_one_hunk():
    diff = (
        "--- a/a.py\n"
        "+++ b/a.py\n"
        "@@ -1,1 +1,3 @@\n"
        "+def foo():\n"
        "+    pass\n"
    )
    changed_files, file_hunks = parse_diff(diff)
    assert changed_files == ["a.py"]
    assert list(file_hunks.keys()) == ["a.py"]
    hunks = file_hunks["a.py"]
    assert len(hunks) == 1
    assert hunks[0] == DiffHunk(
        new_start=1, new_count=3, lines=["+def foo():", "+    pass"]
    )


def test_multiple_changed_files():
    diff = (
        "--- a/a.py\n"
        "+++ b/a.py\n"
        "@@ -1,1 +1,1 @@\n"
        "+a\n"
        "--- a/b.py\n"
        "+++ b/b.py\n"
        "@@ -1,1 +1,1 @@\n"
        "+b\n"
    )
    changed_files, file_hunks = parse_diff(diff)
    assert changed_files == ["a.py", "b.py"]
    assert file_hunks["a.py"][0].lines == ["+a"]
    assert file_hunks["b.py"][0].lines == ["+b"]


def test_multiple_hunks_in_one_file():
    diff = (
        "--- a/a.py\n"
        "+++ b/a.py\n"
        "@@ -1,2 +1,2 @@\n"
        " class Retry:\n"
        "-old\n"
        "+new\n"
        "@@ -7,2 +7,2 @@\n"
        "     def new(self, **kw):\n"
        "-        return Retry(**kw)\n"
        "+        return Retry(**kw, extra=True)\n"
    )
    changed_files, file_hunks = parse_diff(diff)
    assert changed_files == ["a.py"]
    hunks = file_hunks["a.py"]
    assert len(hunks) == 2
    assert hunks[0].new_start == 1 and hunks[0].new_count == 2
    assert hunks[1].new_start == 7 and hunks[1].new_count == 2


def test_hunk_header_metadata_with_explicit_count():
    diff = "+++ b/a.py\n@@ -1,5 +10,20 @@\n context\n"
    _, file_hunks = parse_diff(diff)
    hunk = file_hunks["a.py"][0]
    assert hunk.new_start == 10
    assert hunk.new_count == 20


def test_hunk_header_metadata_defaults_count_to_one_when_omitted():
    # "@@ -1 +1 @@" form: no ",N" count suffix on the new-file side.
    diff = "+++ b/a.py\n@@ -1 +1 @@\n+x\n"
    _, file_hunks = parse_diff(diff)
    hunk = file_hunks["a.py"][0]
    assert hunk.new_start == 1
    assert hunk.new_count == 1


def test_added_removed_and_context_lines_are_preserved_with_markers():
    diff = (
        "--- a/a.py\n"
        "+++ b/a.py\n"
        "@@ -1,3 +1,3 @@\n"
        " context line\n"
        "-removed line\n"
        "+added line\n"
    )
    _, file_hunks = parse_diff(diff)
    assert file_hunks["a.py"][0].lines == [
        " context line",
        "-removed line",
        "+added line",
    ]


def test_lines_without_a_recognized_marker_are_dropped():
    # A line inside a hunk that isn't prefixed with ' ', '+', or '-' (e.g. a
    # "\ No newline at end of file" marker) is not appended to hunk.lines.
    diff = (
        "+++ b/a.py\n"
        "@@ -1,1 +1,1 @@\n"
        "+added\n"
        "\\ No newline at end of file\n"
    )
    _, file_hunks = parse_diff(diff)
    assert file_hunks["a.py"][0].lines == ["+added"]


def test_minus_a_and_plus_b_paths_used_correctly():
    # Only "+++ b/..." sets the tracked filename; "--- a/..." is recognized
    # only as a hunk-flush boundary, and its own path is never used.
    diff = (
        "--- a/old_name.py\n"
        "+++ b/new_name.py\n"
        "@@ -1,1 +1,1 @@\n"
        "+x\n"
    )
    changed_files, file_hunks = parse_diff(diff)
    assert changed_files == ["new_name.py"]
    assert "old_name.py" not in file_hunks


def test_dash_a_line_flushes_pending_hunk_before_next_file():
    # A trailing hunk for the first file must be flushed when the second
    # file's "--- a/" line appears, not silently merged into the next file.
    diff = (
        "--- a/a.py\n"
        "+++ b/a.py\n"
        "@@ -1,1 +1,1 @@\n"
        "+from a\n"
        "--- a/b.py\n"
        "+++ b/b.py\n"
        "@@ -1,1 +1,1 @@\n"
        "+from b\n"
    )
    _, file_hunks = parse_diff(diff)
    assert len(file_hunks["a.py"]) == 1
    assert file_hunks["a.py"][0].lines == ["+from a"]
    assert len(file_hunks["b.py"]) == 1
    assert file_hunks["b.py"][0].lines == ["+from b"]


# ---------------------------------------------------------------------------
# semantic_delta
# ---------------------------------------------------------------------------

class TestSemanticDelta:
    def test_extracts_additions_and_removals_per_file_excludes_context(self):
        diff = (
            "--- a/a.py\n"
            "+++ b/a.py\n"
            "@@ -1,3 +1,3 @@\n"
            " context line\n"
            "-removed line\n"
            "+added line\n"
        )
        delta = semantic_delta(diff)
        assert delta == {"a.py": (["+added line"], ["-removed line"])}

    def test_empty_for_pure_context_only_change_across_files(self):
        # No real diff has zero +/- lines, but the function must not raise
        # or invent entries for a file with none.
        diff = "--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,1 @@\n context only\n"
        assert semantic_delta(diff) == {"a.py": ([], [])}

    def test_unaffected_by_context_or_header_differences(self):
        """The core safety property: two diffs whose ONLY difference is
        surrounding context/header metadata must report an identical
        semantic delta."""
        thin = (
            "--- a/a.py\n+++ b/a.py\n@@ -5,2 +5,2 @@\n"
            " ctx\n-old\n+new\n"
        )
        expanded = (
            "--- a/a.py\n+++ b/a.py\n@@ -3,6 +3,6 @@\n"
            " before2\n before1\n ctx\n-old\n+new\n after1\n"
        )
        assert semantic_delta(thin) == semantic_delta(expanded)

    def test_detects_a_real_addition_difference(self):
        a = "--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,1 @@\n-old\n+new\n"
        b = "--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,2 @@\n-old\n+new\n+extra\n"
        assert semantic_delta(a) != semantic_delta(b)

    def test_multi_hunk_multi_file_preserves_order(self):
        diff = (
            "--- a/a.py\n+++ b/a.py\n"
            "@@ -1,1 +1,1 @@\n-a_old\n+a_new\n"
            "@@ -10,1 +10,1 @@\n-a_old2\n+a_new2\n"
            "--- a/b.py\n+++ b/b.py\n"
            "@@ -1,1 +1,1 @@\n-b_old\n+b_new\n"
        )
        delta = semantic_delta(diff)
        assert delta["a.py"] == (["+a_new", "+a_new2"], ["-a_old", "-a_old2"])
        assert delta["b.py"] == (["+b_new"], ["-b_old"])
