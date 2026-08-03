import os
from pathlib import Path
import json

from utilities.autopatcher.impact_surface import LightweightImpactAnalyzer
from utilities.autopatcher.pipeline import enhance_findings_with_impact, TargetRepoContext


def write_file(p: Path, text: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def make_diff_for(path: str) -> str:
    # minimal unified diff header for file
    return f"+++ b/{path}\n@@ -1,1 +1,3 @@\n+def placeholder():\n"


def test_low_impact_same_file(tmp_path):
    # repo with a.py only; changed symbol used only in same file
    repo = tmp_path / "repo"
    repo.mkdir()
    a = repo / "a.py"
    write_file(a, "def foo(x):\n    return x\n\nprint(foo(1))\n")

    diff = """+++ b/a.py
@@ -1,3 +1,5 @@
+def foo(x):
+    return x
"""

    analyzer = LightweightImpactAnalyzer()
    ctx = TargetRepoContext(repo)
    report = analyzer.analyze(diff, repo_context=ctx)

    assert report.impact_level == "low"
    assert isinstance(report.impact_summary, str)


def test_medium_impact_two_files(tmp_path):
    repo = tmp_path / "repo2"
    repo.mkdir()
    a = repo / "a.py"
    b = repo / "b.py"
    c = repo / "c.py"
    write_file(a, "def foo(x):\n    return x\n")
    write_file(b, "from a import foo\nprint(foo(2))\n")
    write_file(c, "x = foo(3)\n")

    diff = """+++ b/a.py
@@ -1,1 +1,3 @@
+def foo(x):
+    return x
"""

    analyzer = LightweightImpactAnalyzer()
    ctx = TargetRepoContext(repo)
    report = analyzer.analyze(diff, repo_context=ctx)

    assert report.impact_level == "medium"
    assert len(report.affected_files) == 2


def test_high_impact_three_files_or_entrypoint(tmp_path):
    repo = tmp_path / "repo3"
    repo.mkdir()
    a = repo / "a.py"
    b = repo / "b.py"
    c = repo / "c.py"
    d = repo / "api" / "routes.py"
    write_file(a, "def foo(x):\n    return x\n")
    write_file(b, "print(foo(2))\n")
    write_file(c, "print(foo(3))\n")
    write_file(d, "from a import foo\n# route uses foo\n")

    diff = """+++ b/a.py
@@ -1,1 +1,3 @@
+def foo(x):
+    return x
"""

    analyzer = LightweightImpactAnalyzer()
    ctx = TargetRepoContext(repo)
    report = analyzer.analyze(diff, repo_context=ctx)

    # either >=3 external files or entrypoint hit should mark high
    assert report.impact_level == "high"


def test_enhance_findings_with_impact():
    challenger = {}
    # simulate impact report dicts
    high = {"impact_level": "high"}
    med = {"impact_level": "medium"}
    low = {"impact_level": "low"}

    # high
    c1 = dict(challenger)
    enhance_findings_with_impact(c1, high)
    assert "impact_annotations" in c1 and any("propagate" in s for s in c1["impact_annotations"])

    # medium
    c2 = dict(challenger)
    enhance_findings_with_impact(c2, med)
    assert "impact_annotations" in c2 and len(c2["impact_annotations"]) > 0

    # low
    c3 = dict(challenger)
    enhance_findings_with_impact(c3, low)
    assert "impact_annotations" not in c3


def test_constant_hunk_does_not_extract_init(tmp_path):
    """Regression: constant-only hunk must not fall back to __init__ and produce HIGH impact.

    Reproduces the urllib3 cookie-redirect case: a frozenset constant is
    modified, no def appears in the hunk, and several other files define
    __init__. Without the fix the upward scan grabs __init__, the search
    matches every class file, and impact is incorrectly HIGH.
    """
    repo = tmp_path / "repo_constant"
    repo.mkdir()

    # The patched file: class with __init__ above a class-level constant.
    write_file(
        repo / "retry.py",
        "\n".join([
            "class Retry:",
            "    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization'])",
            "",
            "    def __init__(self, retries=3):",
            "        self.retries = retries",
        ]),
    )

    # Five other files that each define __init__ — would inflate count if searched.
    for i in range(5):
        write_file(
            repo / f"module{i}.py",
            f"class Foo{i}:\n    def __init__(self):\n        pass\n",
        )

    # Diff touches only the constant; no def in the hunk.
    diff = (
        "--- a/retry.py\n"
        "+++ b/retry.py\n"
        "@@ -1,2 +1,2 @@\n"
        " class Retry:\n"
        "-    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization'])\n"
        "+    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization', 'Cookie'])\n"
    )

    analyzer = LightweightImpactAnalyzer()
    ctx = TargetRepoContext(repo)
    report = analyzer.analyze(diff, repo_context=ctx)

    assert "__init__" not in report.changed_symbols, (
        "constant-only hunk must not fall back to __init__"
    )
    assert report.impact_level == "low", (
        f"expected low impact for constant change, got {report.impact_level!r}; "
        f"affected_files={report.affected_files}"
    )


def test_sensitive_auth_bumps_low_to_medium(tmp_path):
    # changed auth file with no external usages should be bumped to medium
    repo = tmp_path / "repo_sensitive"
    (repo / "app").mkdir(parents=True)
    auth = repo / "app" / "auth.py"
    write_file(auth, "def authenticate(user, pwd):\n    return True\n")

    diff = """+++ b/app/auth.py
@@ -1,1 +1,3 @@
+def authenticate(user, pwd):
+    return True
"""

    analyzer = LightweightImpactAnalyzer()
    ctx = TargetRepoContext(repo)
    report = analyzer.analyze(diff, repo_context=ctx)

    assert report.impact_level == "medium"
    assert "authenticate" in (report.changed_symbols or [])


def test_non_python_repo_reports_not_applicable_not_low(tmp_path):
    # A C change with zero extractable Python symbols must not be scored
    # "low impact" (which reads as a reassuring, verified-clean finding).
    # It must be explicitly "not_applicable" instead.
    repo = tmp_path / "repo_c"
    repo.mkdir()
    write_file(repo / "lib" / "http.c", "int Curl_follow(void) { return 0; }\n")

    diff = """+++ b/lib/http.c
@@ -1,1 +1,3 @@
+int Curl_follow(void) {
+    return 0;
+}
"""

    analyzer = LightweightImpactAnalyzer()
    ctx = TargetRepoContext(repo)
    report = analyzer.analyze(diff, repo_context=ctx, repo_language="c")

    assert report.impact_level == "not_applicable"
    assert report.impact_level != "low"
    assert report.changed_symbols == []
    assert report.usage_matches == []
    assert report.affected_files == []
    # Diff parsing itself is language-agnostic and must still work.
    assert report.changed_files == ["lib/http.c"]
    assert "Not Applicable" in report.impact_summary


def test_python_repo_impact_unchanged_by_default(tmp_path):
    # Default repo_language="python" must reproduce prior behavior exactly.
    repo = tmp_path / "repo_default"
    repo.mkdir()
    a = repo / "a.py"
    write_file(a, "def foo(x):\n    return x\n\nprint(foo(1))\n")

    diff = """+++ b/a.py
@@ -1,3 +1,5 @@
+def foo(x):
+    return x
"""

    analyzer = LightweightImpactAnalyzer()
    ctx = TargetRepoContext(repo)
    report = analyzer.analyze(diff, repo_context=ctx)

    assert report.impact_level == "low"


# ---------------------------------------------------------------------------
# Symbol-resolution robustness (the urllib3 hunk-drift incident and its
# resilience requirements: diff line offsets, nearby comments, whitespace-only
# edits, insertion/deletion before the target, equivalent patch formatting).
# ---------------------------------------------------------------------------

_RETRY_FILE = "\n".join([
    "class Retry:",
    "    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization'])",
    "",
    "    def __init__(self, retries=3):",
    "        self.retries = retries",
    "",
    "    def new(self, **kw):",
    "        return Retry(**kw)",
])

# Other files that each define __init__ — if the analyzer ever falls back to
# that name, usage search inflates across all of them, exactly reproducing
# the false-HIGH-impact incident.
_OTHER_INIT_FILES = {f"module{i}.py": f"class Foo{i}:\n    def __init__(self):\n        pass\n" for i in range(5)}


def _write_retry_repo(tmp_path, retry_text=_RETRY_FILE, extra_files=None):
    repo = tmp_path / "repo"
    repo.mkdir()
    write_file(repo / "retry.py", retry_text)
    for name, content in {**_OTHER_INIT_FILES, **(extra_files or {})}.items():
        write_file(repo / name, content)
    return repo


class TestShiftedHunkHeaders:
    """The core incident: a hunk header claiming the wrong line number for
    byte-identical content must not change which symbol is resolved."""

    def test_correct_header_resolves_constant(self, tmp_path):
        repo = _write_retry_repo(tmp_path)
        diff = (
            "--- a/retry.py\n+++ b/retry.py\n"
            "@@ -1,2 +1,2 @@\n"
            " class Retry:\n"
            "-    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization'])\n"
            "+    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization', 'Cookie'])\n"
        )
        report = LightweightImpactAnalyzer().analyze(diff, repo_context=TargetRepoContext(repo))
        assert report.changed_symbols == ["DEFAULT_REMOVE_HEADERS"]
        assert report.impact_level == "low"

    def test_wildly_shifted_header_still_resolves_the_same_constant(self, tmp_path):
        """Same file, same content change, header claims line 50 instead of
        line 2 — the actual incident, reproduced deterministically."""
        repo = _write_retry_repo(tmp_path)
        diff = (
            "--- a/retry.py\n+++ b/retry.py\n"
            "@@ -50,2 +50,2 @@\n"
            " class Retry:\n"
            "-    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization'])\n"
            "+    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization', 'Cookie'])\n"
        )
        report = LightweightImpactAnalyzer().analyze(diff, repo_context=TargetRepoContext(repo))
        assert report.changed_symbols == ["DEFAULT_REMOVE_HEADERS"]
        assert "__init__" not in report.changed_symbols
        assert report.impact_level == "low"

    def test_shifted_header_on_a_function_change_still_resolves_correctly(self, tmp_path):
        repo = _write_retry_repo(tmp_path)
        diff = (
            "--- a/retry.py\n+++ b/retry.py\n"
            "@@ -999,2 +999,2 @@\n"
            "     def new(self, **kw):\n"
            "-        return Retry(**kw)\n"
            "+        return Retry(**kw, extra=True)\n"
        )
        report = LightweightImpactAnalyzer().analyze(diff, repo_context=TargetRepoContext(repo))
        assert report.changed_symbols == ["new"]

    def test_two_runs_with_different_headers_same_content_agree(self, tmp_path):
        """Direct stability check: semantically identical patches, differing
        only in hunk header line number, must produce the identical report."""
        repo = _write_retry_repo(tmp_path)
        body = (
            " class Retry:\n"
            "-    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization'])\n"
            "+    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization', 'Cookie'])\n"
        )
        diff_a = f"--- a/retry.py\n+++ b/retry.py\n@@ -189,2 +189,2 @@\n{body}"
        diff_b = f"--- a/retry.py\n+++ b/retry.py\n@@ -196,2 +196,2 @@\n{body}"

        report_a = LightweightImpactAnalyzer().analyze(diff_a, repo_context=TargetRepoContext(repo))
        report_b = LightweightImpactAnalyzer().analyze(diff_b, repo_context=TargetRepoContext(repo))

        assert report_a.changed_symbols == report_b.changed_symbols
        assert report_a.impact_level == report_b.impact_level
        assert report_a.affected_files == report_b.affected_files


class TestSymbolKindRendering:
    """Release-polish change #9: the low-impact summary's changed-symbol
    mention must only append "()" for a function/method — a constant,
    class attribute, or field must never render as if it were callable
    (e.g. `DEFAULT_REMOVE_HEADERS_ON_REDIRECT()` for a changed constant)."""

    def test_constant_change_does_not_render_as_callable(self, tmp_path):
        repo = _write_retry_repo(tmp_path)
        diff = (
            "--- a/retry.py\n+++ b/retry.py\n"
            "@@ -1,2 +1,2 @@\n"
            " class Retry:\n"
            "-    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization'])\n"
            "+    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization', 'Cookie'])\n"
        )
        report = LightweightImpactAnalyzer().analyze(diff, repo_context=TargetRepoContext(repo))
        assert report.impact_level == "low"
        assert "DEFAULT_REMOVE_HEADERS()" not in report.impact_summary
        assert "`DEFAULT_REMOVE_HEADERS`" in report.impact_summary

    def test_function_change_still_renders_as_callable(self, tmp_path):
        repo = _write_retry_repo(tmp_path)
        diff = (
            "--- a/retry.py\n+++ b/retry.py\n"
            "@@ -999,2 +999,2 @@\n"
            "     def new(self, **kw):\n"
            "-        return Retry(**kw)\n"
            "+        return Retry(**kw, extra=True)\n"
        )
        report = LightweightImpactAnalyzer().analyze(diff, repo_context=TargetRepoContext(repo))
        assert report.changed_symbols == ["new"]
        assert report.impact_level == "low"
        assert "`new()`" in report.impact_summary


class TestWhitespaceOnlyChanges:
    def test_reindentation_only_produces_no_symbol_and_low_impact(self, tmp_path):
        repo = _write_retry_repo(tmp_path)
        diff = (
            "--- a/retry.py\n+++ b/retry.py\n"
            "@@ -1,2 +1,2 @@\n"
            " class Retry:\n"
            "-    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization'])\n"
            "+        DEFAULT_REMOVE_HEADERS = frozenset(['Authorization'])\n"
        )
        report = LightweightImpactAnalyzer().analyze(diff, repo_context=TargetRepoContext(repo))
        assert report.changed_symbols == []
        assert report.impact_level == "low"

    def test_trailing_whitespace_only_produces_no_symbol(self, tmp_path):
        repo = _write_retry_repo(tmp_path)
        diff = (
            "--- a/retry.py\n+++ b/retry.py\n"
            "@@ -7,1 +7,1 @@\n"
            "-    def new(self, **kw):\n"
            "+    def new(self, **kw):   \n"
        )
        report = LightweightImpactAnalyzer().analyze(diff, repo_context=TargetRepoContext(repo))
        assert report.changed_symbols == []


class TestInsertionBeforeTarget:
    def test_lines_inserted_above_target_do_not_break_resolution(self, tmp_path):
        """The header's claimed line number is stale (as if computed before
        20 lines were inserted above the target) — content match must still
        find the real, shifted location."""
        padded = "\n".join([f"# padding line {i}" for i in range(20)]) + "\n" + _RETRY_FILE
        repo = _write_retry_repo(tmp_path, retry_text=padded)
        diff = (
            "--- a/retry.py\n+++ b/retry.py\n"
            "@@ -1,2 +1,2 @@\n"  # stale: correct pre-padding location
            " class Retry:\n"
            "-    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization'])\n"
            "+    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization', 'Cookie'])\n"
        )
        report = LightweightImpactAnalyzer().analyze(diff, repo_context=TargetRepoContext(repo))
        assert report.changed_symbols == ["DEFAULT_REMOVE_HEADERS"]


class TestNearbyComments:
    def test_misleading_def_in_comment_is_ignored(self, tmp_path):
        """A comment that looks like a function definition must never be
        mistaken for real code — ast parsing never sees comments at all."""
        text = "\n".join([
            "class Retry:",
            "    # def __init__(self): pass  -- old implementation, removed",
            "    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization'])",
            "",
            "    def __init__(self, retries=3):",
            "        self.retries = retries",
        ])
        repo = _write_retry_repo(tmp_path, retry_text=text)
        diff = (
            "--- a/retry.py\n+++ b/retry.py\n"
            "@@ -1,3 +1,3 @@\n"
            " class Retry:\n"
            "     # def __init__(self): pass  -- old implementation, removed\n"
            "-    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization'])\n"
            "+    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization', 'Cookie'])\n"
        )
        report = LightweightImpactAnalyzer().analyze(diff, repo_context=TargetRepoContext(repo))
        assert report.changed_symbols == ["DEFAULT_REMOVE_HEADERS"]
        assert "__init__" not in report.changed_symbols


class TestConstantAssignmentChanges:
    def test_class_level_constant(self, tmp_path):
        repo = _write_retry_repo(tmp_path)
        diff = (
            "--- a/retry.py\n+++ b/retry.py\n"
            "@@ -1,2 +1,2 @@\n"
            " class Retry:\n"
            "-    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization'])\n"
            "+    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization', 'Cookie'])\n"
        )
        report = LightweightImpactAnalyzer().analyze(diff, repo_context=TargetRepoContext(repo))
        assert report.changed_symbols == ["DEFAULT_REMOVE_HEADERS"]

    def test_module_level_constant(self, tmp_path):
        text = "DEFAULT_TIMEOUT = 30\n\ndef connect():\n    return DEFAULT_TIMEOUT\n"
        repo = _write_retry_repo(tmp_path, retry_text=text)
        diff = (
            "--- a/retry.py\n+++ b/retry.py\n"
            "@@ -1,1 +1,1 @@\n"
            "-DEFAULT_TIMEOUT = 30\n"
            "+DEFAULT_TIMEOUT = 60\n"
        )
        report = LightweightImpactAnalyzer().analyze(diff, repo_context=TargetRepoContext(repo))
        assert report.changed_symbols == ["DEFAULT_TIMEOUT"]


class TestFunctionChanges:
    def test_change_inside_method_body_resolves_to_method_name(self, tmp_path):
        repo = _write_retry_repo(tmp_path)
        diff = (
            "--- a/retry.py\n+++ b/retry.py\n"
            "@@ -7,2 +7,2 @@\n"
            "     def new(self, **kw):\n"
            "-        return Retry(**kw)\n"
            "+        return Retry(**kw, extra=True)\n"
        )
        report = LightweightImpactAnalyzer().analyze(diff, repo_context=TargetRepoContext(repo))
        assert report.changed_symbols == ["new"]

    def test_change_to_signature_line_resolves_to_function_name(self, tmp_path):
        repo = _write_retry_repo(tmp_path)
        diff = (
            "--- a/retry.py\n+++ b/retry.py\n"
            "@@ -7,1 +7,1 @@\n"
            "-    def new(self, **kw):\n"
            "+    def new(self, **kw, strict=False):\n"
        )
        report = LightweightImpactAnalyzer().analyze(diff, repo_context=TargetRepoContext(repo))
        assert report.changed_symbols == ["new"]


class TestMultipleHunks:
    def test_two_hunks_in_same_file_resolve_two_distinct_symbols(self, tmp_path):
        repo = _write_retry_repo(tmp_path)
        diff = (
            "--- a/retry.py\n+++ b/retry.py\n"
            "@@ -1,2 +1,2 @@\n"
            " class Retry:\n"
            "-    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization'])\n"
            "+    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization', 'Cookie'])\n"
            "@@ -7,2 +7,2 @@\n"
            "     def new(self, **kw):\n"
            "-        return Retry(**kw)\n"
            "+        return Retry(**kw, extra=True)\n"
        )
        report = LightweightImpactAnalyzer().analyze(diff, repo_context=TargetRepoContext(repo))
        assert set(report.changed_symbols) == {"DEFAULT_REMOVE_HEADERS", "new"}

    def test_hunks_across_two_files_resolve_independently(self, tmp_path):
        repo = _write_retry_repo(tmp_path, extra_files={
            "helpers.py": "def build_url():\n    return ''\n",
        })
        diff = (
            "--- a/retry.py\n+++ b/retry.py\n"
            "@@ -1,2 +1,2 @@\n"
            " class Retry:\n"
            "-    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization'])\n"
            "+    DEFAULT_REMOVE_HEADERS = frozenset(['Authorization', 'Cookie'])\n"
            "--- a/helpers.py\n+++ b/helpers.py\n"
            "@@ -1,2 +1,2 @@\n"
            "-def build_url():\n"
            "-    return ''\n"
            "+def build_url():\n"
            "+    return 'https://'\n"
        )
        report = LightweightImpactAnalyzer().analyze(diff, repo_context=TargetRepoContext(repo))
        assert set(report.changed_symbols) == {"DEFAULT_REMOVE_HEADERS", "build_url"}
        assert set(report.changed_files) == {"retry.py", "helpers.py"}
