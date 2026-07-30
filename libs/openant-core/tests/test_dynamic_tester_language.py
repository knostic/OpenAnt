"""Dynamic-test language must follow the FINDING's file, and never be guessed.

Two defects existed together:

  * ``LANGUAGE_MAP`` covered only python/js/ts/go, and
  * ``repo_info["language"]`` defaulted to ``"Python"``.

So a C finding produced a *Python* Dockerfile — an LLM call whose result was
guaranteed to fail. Skipping with a reason costs nothing; guessing costs tokens
and produces a misleading ERROR result.
"""

import pytest

from core.language_registry import docker_template_for
from utilities.dynamic_tester.test_generator import resolve_docker_template


class TestTemplateFollowsTheFinding:
    @pytest.mark.parametrize("file_path,expected", [
        ("app/main.py", "python"),
        ("src/index.js", "node"),
        ("src/index.ts", "node"),
        ("cmd/root.go", "go"),
        ("app/models.rb", "ruby"),
        ("public/index.php", "php"),
    ])
    def test_supported_languages_resolve_to_their_template(self, file_path, expected):
        assert resolve_docker_template(file_path, scan_language="python") == expected

    def test_findings_file_wins_over_the_scan_language(self):
        """A Go finding in a Python-primary scan must not get a Python image."""
        assert resolve_docker_template("cmd/root.go", scan_language="python") == "go"


class TestUnsupportedLanguagesSkipRatherThanGuess:
    @pytest.mark.parametrize("file_path", ["lib/parse.c", "lib/parse.cpp", "main.zig"])
    def test_languages_without_a_template_return_none(self, file_path):
        assert resolve_docker_template(file_path, scan_language="python") is None, (
            "a language with no Docker template must yield None so the caller "
            "can skip; falling back to Python generated a guaranteed-failing test"
        )

    def test_registry_agrees_that_c_and_zig_have_no_template(self):
        assert docker_template_for("c") is None
        assert docker_template_for("zig") is None

    def test_unknown_extension_falls_back_to_the_scan_language(self):
        assert resolve_docker_template("unknown", scan_language="go") == "go"

    def test_unknown_extension_and_unusable_scan_language_returns_none(self):
        assert resolve_docker_template("unknown", scan_language="c") is None
        assert resolve_docker_template("unknown", scan_language=None) is None

    def test_never_silently_defaults_to_python(self):
        """The old behaviour: everything unknown became a Python image."""
        assert resolve_docker_template("lib/parse.c", scan_language=None) != "python"
        assert resolve_docker_template("main.zig", scan_language=None) != "python"


class TestPromptStatesTheLanguageNotTheDockerTemplate:
    """The prompt's `Language:` line must name a LANGUAGE.

    Regression: an earlier fix reused the docker-template resolver for the
    prompt variable, so a JavaScript finding announced `Language: node` — the
    base-image name, not the language. The model was being told the wrong
    thing about the code it was writing a test for.
    """

    def _language_line(self, file_path, scan_language):
        from utilities.dynamic_tester.test_generator import _build_finding_prompt

        prompt = _build_finding_prompt(
            {"location": {"file": file_path}, "name": "X", "description": "d"},
            {"name": "r", "language": scan_language, "application_type": "web_app"},
        )
        for line in prompt.splitlines():
            if line.startswith("Language:"):
                return line.split(":", 1)[1].strip()
        return None

    def test_javascript_finding_says_javascript_not_node(self):
        assert self._language_line("src/app.js", "javascript") == "javascript"

    def test_typescript_finding_is_not_reported_as_node(self):
        assert self._language_line("src/app.ts", "javascript") != "node"

    def test_go_finding_says_go(self):
        assert self._language_line("cmd/root.go", "go") == "go"

    def test_finding_file_language_wins_over_scan_language(self):
        assert self._language_line("tools/gen.py", "javascript") == "python"

    def test_unknown_extension_falls_back_to_scan_language(self):
        assert self._language_line("unknown", "ruby") == "ruby"


class TestUnsupportedLanguageFindingsAreSkipped:
    """A finding whose language has no Docker template must be SKIPPED.

    Generating a test anyway spends an LLM call on something the harness has
    no template guidance for. Skipping with a recorded reason is cheaper and
    leaves an auditable trail, rather than a mystery ERROR result.
    """

    def test_skip_decision_is_exposed_as_a_helper(self):
        from utilities.dynamic_tester import should_skip_for_language

        skip, reason = should_skip_for_language("lib/parse.c", "c")
        assert skip is True
        assert "c" in reason.lower()

    def test_supported_language_is_not_skipped(self):
        from utilities.dynamic_tester import should_skip_for_language

        assert should_skip_for_language("src/app.js", "javascript")[0] is False
        assert should_skip_for_language("app/main.py", "python")[0] is False

    def test_zig_is_skipped(self):
        from utilities.dynamic_tester import should_skip_for_language

        assert should_skip_for_language("main.zig", "zig")[0] is True

    def test_unknown_extension_defers_to_scan_language(self):
        from utilities.dynamic_tester import should_skip_for_language

        assert should_skip_for_language("unknown", "go")[0] is False
        assert should_skip_for_language("unknown", "c")[0] is True

    def test_reason_names_the_language_so_the_trail_is_auditable(self):
        from utilities.dynamic_tester import should_skip_for_language

        _, reason = should_skip_for_language("main.zig", "zig")
        assert "zig" in reason
        assert "template" in reason.lower()


class TestSkippedIsAFirstClassStatus:
    """A skipped finding must be countable, not an unrecognized string.

    Emitting a status the models/reporter don't know about makes skipped
    findings vanish from the summary — the same silent-gap failure the skip
    was introduced to avoid.
    """

    def test_skipped_is_a_valid_status(self):
        from utilities.dynamic_tester.models import VALID_STATUSES

        assert "SKIPPED" in VALID_STATUSES

    def test_reporter_counts_skipped_findings(self):
        from utilities.dynamic_tester.models import DynamicTestResult
        from utilities.dynamic_tester.reporter import generate_report

        results = [
            DynamicTestResult(finding_id="A", status="CONFIRMED", details=""),
            DynamicTestResult(finding_id="B", status="SKIPPED", details="no template for zig"),
        ]
        report = generate_report(results, repo_name="r", total_cost_usd=0.0)
        assert "SKIPPED" in report.upper(), "skipped findings are invisible in the report"
