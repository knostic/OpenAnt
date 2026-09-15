"""Thresholds must apply, and every exclusion must be reported.

Two defects, one fix:

1. The threshold rule was UNREACHABLE. `_select_languages_for` returns None
   unless --languages or --all-languages is passed, and both of those bypass
   thresholds — so `--min-language-files` / `--min-language-share` were
   advertised no-ops.
2. `LanguageSelection.excluded` was computed and discarded, so a dropped
   language left no trace anywhere.

For a security scanner the second is the dangerous one: a 4-file PHP upload
handler in a JS monorepo is exactly what the tool exists to find, and silently
skipping it to save ~0.1s of parse time is the wrong trade. Thresholds are
allowed to skip work; they are not allowed to do it quietly.
"""

import json
from pathlib import Path


from openant.cli import build_parser, resolve_language_selection


class TestThresholdsActuallyApply:
    def test_threshold_flags_change_the_selection(self):
        """The flags were previously inert on every reachable code path."""
        counts = {"python": 100, "go": 3}

        strict = resolve_language_selection(
            build_parser().parse_args([
                "parse", "/r", "--multi-language", "--min-language-files", "5",
            ]), counts)
        assert strict.selected == ["python"], "go should be below a 5-file floor"

        permissive = resolve_language_selection(
            build_parser().parse_args([
                "parse", "/r", "--multi-language", "--min-language-files", "1",
                "--min-language-share", "0.0",
            ]), counts)
        assert permissive.selected == ["python", "go"], (
            "lowering the floor must actually admit go — the flags were no-ops"
        )

    def test_multi_language_flag_enables_the_thresholded_path(self):
        """A way to say 'multi-language, but apply the policy'."""
        sel = resolve_language_selection(
            build_parser().parse_args(["parse", "/r", "--multi-language"]),
            {"python": 100, "go": 3},
        )
        assert sel.selected == ["python"]
        assert "go" in sel.excluded


class TestExclusionsAreLoud:
    def test_excluded_reaches_the_scan_result(self):
        from core.schemas import ScanResult

        r = ScanResult(output_dir="/o", excluded_languages={"go": "3 files below threshold"})
        assert r.to_dict()["excluded_languages"] == {"go": "3 files below threshold"}

    def test_excluded_reaches_the_parse_result(self):
        from core.schemas import ParseResult

        r = ParseResult(dataset_path="/d", excluded_languages={"php": "1 file"})
        assert r.to_dict()["excluded_languages"] == {"php": "1 file"}

    def test_exclusions_are_printed_to_stderr(self, capsys):
        from core.language_selection import report_exclusions

        report_exclusions({"php": "1 file(s) (20.00%) below threshold of 5"})
        err = capsys.readouterr().err
        assert "php" in err
        assert "COVERAGE GAP" in err.upper(), "an exclusion must be visibly a gap"

    def test_no_exclusions_prints_nothing(self, capsys):
        from core.language_selection import report_exclusions

        report_exclusions({})
        assert capsys.readouterr().err == ""

    def test_reason_survives_verbatim(self, capsys):
        from core.language_selection import report_exclusions

        report_exclusions({"go": "3 file(s) (2.91%) below threshold of 5"})
        assert "2.91%" in capsys.readouterr().err


class TestExclusionsSurviveBothBranches:
    """The single-language branch must carry exclusions too.

    A repo whose thresholds admit exactly ONE language takes the legacy
    branch — which is precisely the case where a coverage gap exists and most
    needs reporting. Wiring only the multi-language branch left the machine-
    readable field empty exactly when it mattered.
    """

    def test_single_language_result_still_reports_exclusions(self, tmp_path):
        import subprocess
        import sys

        repo = tmp_path / "repo"
        (repo / "src").mkdir(parents=True)
        for i in range(20):
            (repo / "src" / f"m{i}.py").write_text("def f():\n    pass\n")
        (repo / "src" / "up.php").write_text("<?php\nfunction up($f){}\n")

        out = subprocess.run(
            [sys.executable, "-m", "openant", "parse", str(repo),
             "--output", str(tmp_path / "out"), "--multi-language", "--level", "all"],
            capture_output=True, text=True, cwd=str(Path(__file__).parent.parent),
        )
        payload = json.loads(out.stdout)
        excluded = payload.get("data", {}).get("excluded_languages", {})
        assert "php" in excluded, (
            "single-language branch dropped the exclusion from the JSON "
            f"envelope; got {excluded!r}"
        )
