"""Tests for the generic TAP (Test Anything Protocol) result parser.

Fixtures fall into two groups:

  - hand-authored, generic TAP14-shaped fixtures (all-pass, single/multiple
    failures, one level of "# Subtest:" nesting, skip/todo, malformed,
    truncated, diagnostics/YAML) -- these exercise the parser's actual
    mechanics and are NOT tied to any one ecosystem.
  - fixtures captured directly from minimist's own `tap` v0.4.13 CLI via
    its `--tap` flag (see TestExactMinimistCapturedOutput) -- real
    inspected output, not invented. It is NOT well-formed single-document
    TAP (see that class's docstring), which is itself the point: it
    proves the parser fails closed on the actual shape a real, old TAP
    producer emits, rather than assuming a rosier hypothetical.
"""

from __future__ import annotations

from utilities.autopatcher.tap_parser import parse_tap


class TestEmptyOrMissingInput:
    def test_none_returns_none(self):
        assert parse_tap(None) is None

    def test_empty_string_returns_none(self):
        assert parse_tap("") is None

    def test_whitespace_only_returns_none(self):
        assert parse_tap("   \n\n  ") is None


class TestFlatAllPass:
    def test_all_pass(self):
        text = "TAP version 13\n1..3\nok 1 - first\nok 2 - second\nok 3 - third\n"
        parsed = parse_tap(text)
        assert parsed is not None
        assert parsed.mode == "full"
        assert parsed.passed == 3
        assert parsed.failed == 0
        assert parsed.failed_test_ids == []

    def test_tap_version_line_is_optional(self):
        """Older TAP (TAP12) omits the version line entirely -- still
        valid, unambiguous TAP."""
        text = "1..2\nok 1 - a\nok 2 - b\n"
        parsed = parse_tap(text)
        assert parsed is not None
        assert parsed.passed == 2

    def test_plan_line_position_does_not_matter(self):
        """The plan ("1..N") may appear before or after the test lines --
        this parser does not require or cross-check its position/count."""
        text = "TAP version 13\nok 1 - a\nok 2 - b\n1..2\n"
        parsed = parse_tap(text)
        assert parsed is not None
        assert parsed.passed == 2


class TestOneFailingLeaf:
    def test_single_failure(self):
        text = (
            "TAP version 13\n1..2\n"
            "ok 1 - passes\n"
            "not ok 2 - fails\n"
            "  ---\n"
            "  operator: equal\n"
            "  expected: 2\n"
            "  actual: 1\n"
            "  ...\n"
        )
        parsed = parse_tap(text)
        assert parsed is not None
        assert parsed.passed == 1
        assert parsed.failed == 1
        assert parsed.failed_test_ids == ["fails"]


class TestFailureDiagnostics:
    """Bounded diagnostic text from a TAP YAML block (--- ... ...),
    associated ONLY with the immediately-preceding FAILING test line --
    never used as identity, never attached to a passing test, never
    leaked across an unrelated test."""

    def test_diagnostic_block_associated_with_failing_test(self):
        text = (
            "TAP version 13\n1..2\n"
            "ok 1 - passes\n"
            "not ok 2 - fails\n"
            "  ---\n"
            "  operator: equal\n"
            "  expected: 2\n"
            "  actual: 1\n"
            "  ...\n"
        )
        parsed = parse_tap(text)
        assert parsed is not None
        diag = parsed.failure_diagnostics["fails"]
        assert "expected: 2" in diag
        assert "actual: 1" in diag

    def test_passing_test_gets_no_diagnostic_even_with_a_yaml_block(self):
        text = (
            "TAP version 13\n1..1\n"
            "ok 1 - passes\n"
            "  ---\n"
            "  note: this is fine\n"
            "  ...\n"
        )
        parsed = parse_tap(text)
        assert parsed is not None
        assert parsed.failure_diagnostics == {}

    def test_diagnostic_does_not_leak_to_the_next_test(self):
        """A diagnostic block always describes the PRECEDING line -- it
        must never be associated with a later, unrelated test."""
        text = (
            "TAP version 13\n1..2\n"
            "ok 1 - passes\n"
            "  ---\n"
            "  note: unrelated to test 2\n"
            "  ...\n"
            "not ok 2 - fails_without_diagnostic\n"
        )
        parsed = parse_tap(text)
        assert parsed is not None
        assert "fails_without_diagnostic" not in parsed.failure_diagnostics

    def test_free_form_comment_is_never_a_diagnostic_or_an_identity(self):
        """A bare '#' comment (not a YAML block, not a Subtest: marker) is
        always ignored -- it must never become identity, and this feature
        must not start mining it for diagnostic text either (only the
        already-structurally-delimited YAML block construct is safe to
        use for that -- see the module docstring)."""
        text = (
            "TAP version 13\n1..1\n"
            "not ok 1 - fails\n"
            "# some free-form comment about the failure\n"
        )
        parsed = parse_tap(text)
        assert parsed is not None
        assert parsed.failed_test_ids == ["fails"]
        assert parsed.failure_diagnostics == {}

    def test_diagnostic_is_bounded(self):
        huge_line = "  detail: " + ("x" * 50_000)
        text = (
            "TAP version 13\n1..1\n"
            "not ok 1 - fails\n"
            "  ---\n"
            f"{huge_line}\n"
            "  ...\n"
        )
        parsed = parse_tap(text)
        assert parsed is not None
        diag = parsed.failure_diagnostics["fails"]
        assert len(diag) < 3_000
        assert "truncated" in diag

    def test_subtest_child_diagnostic_uses_hierarchical_id(self):
        text = (
            "TAP version 13\n"
            "# Subtest: test/parse.js\n"
            "    ok 1 - parses flags\n"
            "    not ok 2 - parses negative numbers\n"
            "      ---\n"
            "      expected: -1\n"
            "      actual: 1\n"
            "      ...\n"
            "    1..2\n"
            "not ok 1 - test/parse.js\n"
            "1..1\n"
        )
        parsed = parse_tap(text)
        assert parsed is not None
        diag = parsed.failure_diagnostics["test/parse.js > parses negative numbers"]
        assert "expected: -1" in diag


class TestMultipleFailures:
    def test_several_failures_among_passes(self):
        text = "TAP version 13\n1..4\nok 1 - a\nnot ok 2 - b\nnot ok 3 - c\nok 4 - d\n"
        parsed = parse_tap(text)
        assert parsed is not None
        assert parsed.passed == 2
        assert parsed.failed == 2
        assert parsed.failed_test_ids == ["b", "c"]


class TestNestedSubtests:
    """One level of "# Subtest: NAME" nesting -- TAP14's documented
    nested-test convention. A subtest's own rollup line (the "ok"/"not
    ok N - NAME" line that appears back at the outer indentation once the
    subtest's children are done) must NOT be counted as an independent
    additional failure on top of its children -- see module docstring
    "parent summary not double-counted"."""

    _TEXT = (
        "TAP version 13\n"
        "# Subtest: test/parse.js\n"
        "    ok 1 - parses flags\n"
        "    not ok 2 - parses negative numbers\n"
        "    1..2\n"
        "not ok 1 - test/parse.js\n"
        "1..1\n"
    )

    def test_children_are_counted_with_hierarchical_ids(self):
        parsed = parse_tap(self._TEXT)
        assert parsed is not None
        assert parsed.passed == 1
        assert parsed.failed == 1
        assert parsed.failed_test_ids == ["test/parse.js > parses negative numbers"]

    def test_parent_rollup_line_is_not_a_second_failure(self):
        """Exactly one failure is recorded (the child), not two (child +
        rollup) -- this is the double-counting bug this parser must
        avoid."""
        parsed = parse_tap(self._TEXT)
        assert parsed is not None
        assert parsed.failed == 1

    def test_all_passing_subtest_rolls_up_cleanly(self):
        text = (
            "TAP version 13\n"
            "# Subtest: test/bool.js\n"
            "    ok 1 - a\n"
            "    ok 2 - b\n"
            "    1..2\n"
            "ok 1 - test/bool.js\n"
            "1..1\n"
        )
        parsed = parse_tap(text)
        assert parsed is not None
        assert parsed.passed == 2
        assert parsed.failed == 0

    def test_empty_subtest_falls_back_to_the_rollup_line_as_the_identity(self):
        """A subtest with no recorded children at all (e.g. only
        diagnostics inside it) has no leaf identity to promote -- the
        rollup line itself becomes the best available identity, per
        module docstring's _drain_open_subtest."""
        text = "TAP version 13\n# Subtest: empty-group\n    # just a comment, no tests\nnot ok 1 - empty-group\n1..1\n"
        parsed = parse_tap(text)
        assert parsed is not None
        assert parsed.failed == 1
        assert parsed.failed_test_ids == ["empty-group"]

    def test_nested_deeper_than_one_level_is_unsupported_fails_closed(self):
        text = (
            "TAP version 13\n"
            "# Subtest: outer\n"
            "    # Subtest: inner\n"
            "        ok 1 - a\n"
            "    ok 1 - inner\n"
            "ok 1 - outer\n"
        )
        assert parse_tap(text) is None

    def test_subtest_opened_but_never_rolled_up_is_truncated(self):
        text = "TAP version 13\n# Subtest: group\n    ok 1 - a\n    ok 2 - b\n"
        assert parse_tap(text) is None


class TestBaselinePatchedDiffSemantics:
    """The TAP parser's ONLY job is to produce failed_test_ids the
    generic comparator (existing_test_regression.compare_runs) can diff
    -- these tests confirm the IDs it produces are stable enough for
    that, mirroring the same three cases proven for JUnit."""

    def test_same_failure_in_two_parses_produces_the_same_id(self):
        text = "TAP version 13\n1..2\nok 1 - a\nnot ok 2 - flaky-name\n"
        first = parse_tap(text)
        second = parse_tap(text)
        assert first.failed_test_ids == second.failed_test_ids == ["flaky-name"]

    def test_failure_only_in_one_side_is_distinguishable(self):
        baseline = parse_tap("TAP version 13\n1..2\nok 1 - a\nok 2 - b\n")
        patched = parse_tap("TAP version 13\n1..2\nok 1 - a\nnot ok 2 - b\n")
        assert set(patched.failed_test_ids) - set(baseline.failed_test_ids) == {"b"}

    def test_fixed_failure_disappears_from_the_diff(self):
        baseline = parse_tap("TAP version 13\n1..2\nnot ok 1 - a\nok 2 - b\n")
        patched = parse_tap("TAP version 13\n1..2\nok 1 - a\nok 2 - b\n")
        assert set(baseline.failed_test_ids) - set(patched.failed_test_ids) == {"a"}


class TestSkippedAndTodoDirectives:
    def test_skip_directive_is_neither_pass_nor_fail(self):
        text = "TAP version 13\n1..2\nok 1 - a\nnot ok 2 - b # SKIP not implemented yet\n"
        parsed = parse_tap(text)
        assert parsed is not None
        assert parsed.passed == 1
        assert parsed.failed == 0
        assert parsed.skipped == 1
        assert parsed.failed_test_ids == []

    def test_todo_directive_is_also_treated_as_skipped(self):
        """Deliberate simplification (see tap_parser.py's module
        docstring): a passing TODO test does not need special "you can
        remove the TODO now" handling for this feature's purposes -- it
        only needs to never appear as a failure."""
        text = "TAP version 13\n1..2\nok 1 - a\nok 2 - b # TODO fix later\n"
        parsed = parse_tap(text)
        assert parsed is not None
        assert parsed.skipped == 1
        assert parsed.failed == 0

    def test_directive_is_case_insensitive(self):
        text = "TAP version 13\n1..1\nnot ok 1 - b # skip reason\n"
        parsed = parse_tap(text)
        assert parsed.skipped == 1
        assert parsed.failed == 0


class TestDiagnosticsAndYamlNeverBecomeFakeTestIds:
    def test_generic_comment_lines_are_ignored(self):
        text = "TAP version 13\n1..1\n# just some diagnostic note\nok 1 - a\n# another note\n"
        parsed = parse_tap(text)
        assert parsed is not None
        assert parsed.passed == 1
        assert parsed.failed == 0

    def test_yaml_diagnostic_block_is_skipped_entirely(self):
        text = (
            "TAP version 13\n1..1\n"
            "not ok 1 - a\n"
            "  ---\n"
            "  operator: equal\n"
            "  expected:\n"
            "    - 1\n"
            "    - 2\n"
            "  actual: 1\n"
            "  ...\n"
        )
        parsed = parse_tap(text)
        assert parsed is not None
        assert parsed.failed == 1
        assert parsed.failed_test_ids == ["a"]

    def test_lines_that_look_like_ok_inside_a_yaml_block_are_not_counted(self):
        """A YAML diagnostic value could itself happen to contain text
        starting with "ok" -- while inside an open YAML block, nothing is
        parsed as a test line, regardless of content."""
        text = (
            "TAP version 13\n1..1\n"
            "not ok 1 - a\n"
            "  ---\n"
            "  message: \"ok 99 - not a real test\"\n"
            "  ...\n"
        )
        parsed = parse_tap(text)
        assert parsed is not None
        assert parsed.failed == 1
        assert parsed.failed_test_ids == ["a"]


class TestMalformedTap:
    def test_plain_text_with_no_tap_structure_returns_none(self):
        assert parse_tap("Cannot find module 'tap'\nModule not found\n") is None

    def test_multiple_top_level_version_declarations_returns_none(self):
        """A single TAP document must declare its version at most once --
        seeing it twice at the top level signals an ambiguous/concatenated
        stream this parser will not guess at unwrapping (this is exactly
        the real minimist `--tap` shape -- see
        TestExactMinimistCapturedOutput below)."""
        text = "TAP version 13\n1..1\nok 1 - a\nTAP version 13\n1..1\nok 1 - b\n"
        assert parse_tap(text) is None


class TestTruncatedTap:
    def test_unterminated_yaml_block_returns_none(self):
        text = "TAP version 13\n1..2\nok 1 - a\nnot ok 2 - b\n  ---\n  reason: cut off here\n"
        assert parse_tap(text) is None

    def test_cut_off_mid_line_stream_with_recognizable_prefix_still_parses_what_it_saw(self):
        """A stream truncated cleanly BETWEEN complete lines (no open
        subtest, no open YAML block) is not itself ambiguous -- the
        parser reports what it could read. Truncation that leaves a
        construct open (see the two cases above) is what triggers None."""
        text = "TAP version 13\n1..3\nok 1 - a\nok 2 - b\n"
        parsed = parse_tap(text)
        assert parsed is not None
        assert parsed.passed == 2


class TestExactMinimistCapturedOutput:
    """Fixtures captured verbatim from the REAL, currently-checked-out
    minimist repository's own `tap` v0.4.13 CLI, via its `--tap` flag
    (`node_modules/.bin/tap --tap test/all_bool.js`), as part of this
    task's required "confirm before implementing" inspection step. This
    is NOT what the repository's normal `npm test` invocation emits --
    that prints tap's own pretty per-file summary reporter, which isn't
    TAP at all (see test_plan_discovery.py's TAP prompt-rule docstring).
    `--tap` is captured here purely to characterize, from real inspected
    ground truth, what this producer's TAP dialect actually looks like.

    Initial inspection mistook this dialect for "multiple top-level TAP
    version declarations" (a real, generically-rejectable malformation --
    see TestMalformedTap above). Closer reading shows that is NOT what is
    happening: node-tap 0.4.13 nests each file's own inner stream ENTIRELY
    inside "#"-prefixed comment lines -- including its inner "TAP version
    13" line -- so there really is only ONE top-level version declaration.
    What actually happens is more subtle and, for a GENERIC parser,
    unfixable without ecosystem-specific guessing: the real per-assertion
    "ok"/"not ok" lines AND the per-file rollup line ("ok N -
    test/all_bool.js") are emitted at the SAME (zero) indentation, with no
    "# Subtest:" marker connecting them -- i.e. this producer uses NEITHER
    TAP construct this parser recognizes as nesting. A byte-for-byte
    generic TAP consumer has no principled way to tell "this ok line is a
    per-file summary" apart from "this ok line is the file's 5th real
    assertion" -- per the bare TAP spec, both are equally valid,
    equally-weighted top-level test results. This parser therefore (and
    per the module docstring's explicit instruction not to invent
    minimist-specific unwrapping) counts the rollup line as its own leaf
    result too, alongside the real assertions -- a disclosed, known
    over-counting artifact for producers using this exact un-nested,
    un-marked rollup style, never an under-counting/false-negative one:
    a real failure is never hidden by it, only (at worst) reported under
    an extra, redundant identity alongside the real one. This is itself
    strong, additional, real-inspection-backed evidence for why
    result_strategy="tap" is not enabled for minimist's evidenced `npm
    test` entry point (see test_plan_discovery.py) -- independent of, and
    in addition to, the more fundamental fact that plain `npm test`
    doesn't emit any of this without the `--tap` flag this feature is not
    permitted to add."""

    # Captured via: cd <minimist checkout> && node_modules/.bin/tap --tap test/all_bool.js
    _SINGLE_FILE_CAPTURE = (
        "TAP version 13\n"
        "# all_bool.js\n"
        "# TAP version 13\n"
        "# flag boolean true (default all --args to boolean)\n"
        "ok 1 should be equivalent\n"
        "ok 2 should be equivalent\n"
        "# flag boolean true only affects double hyphen arguments without equals signs\n"
        "ok 3 should be equivalent\n"
        "ok 4 should be equivalent\n"
        "# tests 4\n"
        "# pass  4\n"
        "# ok\n"
        "ok 5 test/all_bool.js\n"
        "\n"
        "\n"
        "1..5\n"
        "# tests 5\n"
        "# pass  5\n"
        "\n"
        "# ok\n"
    )

    # Captured via a deliberately introduced failing assertion, same tool:
    # node_modules/.bin/tap --tap <one-file-with-one-pass-one-fail>
    _SINGLE_FILE_WITH_FAILURE_CAPTURE = (
        "TAP version 13\n"
        "# fail.js\n"
        "# TAP version 13\n"
        "# one pass one fail\n"
        "ok 1 should be equal\n"
        "not ok 2 one should equal two (intentional fail)\n"
        "  ---\n"
        "    operator: equal\n"
        "    expected: 2\n"
        "    actual:   1\n"
        "  ...\n"
        "# tests 2\n"
        "# pass  1\n"
        "# fail  1\n"
        "not ok 3 /tmp/minimist_check/tapfixture/fail.js\n"
        "  ---\n"
        "    exit:    1\n"
        "    command: \"node fail.js\"\n"
        "  ...\n"
        "\n"
        "\n"
        "1..3\n"
        "# tests 3\n"
        "# pass  1\n"
        "# fail  2\n"
    )

    def test_real_capture_has_exactly_one_top_level_version_line(self):
        """Sanity-checks the fixture itself against the corrected
        understanding above: only ONE unprefixed "TAP version 13" line --
        the inner one is a "#"-prefixed comment, not a second
        declaration."""
        lines = self._SINGLE_FILE_CAPTURE.splitlines()
        assert lines.count("TAP version 13") == 1
        assert lines.count("# TAP version 13") == 1

    def test_real_capture_all_pass_does_not_fail_closed(self):
        """This shape does NOT hit the "multiple version declarations"
        rejection (see the corrected class docstring) -- it parses, just
        with an extra (harmless, since nothing failed) counted "test" for
        the per-file rollup line."""
        parsed = parse_tap(self._SINGLE_FILE_CAPTURE)
        assert parsed is not None
        assert parsed.failed == 0
        assert parsed.failed_test_ids == []

    def test_real_capture_with_failure_double_counts_the_rollup_line(self):
        """Documents the known, disclosed limitation explicitly: the one
        real assertion failure ("not ok 2 ...") and the per-file rollup
        line ("not ok 3 /path/to/fail.js") are indistinguishable to a
        generic parser given this producer's un-nested, un-marked style,
        so both are counted -- over-counting, never silently dropping,
        the real failure. See the class docstring for why this is not
        special-cased."""
        parsed = parse_tap(self._SINGLE_FILE_WITH_FAILURE_CAPTURE)
        assert parsed is not None
        assert parsed.failed == 2
        assert "one should equal two (intentional fail)" in parsed.failed_test_ids
        assert "/tmp/minimist_check/tapfixture/fail.js" in parsed.failed_test_ids
