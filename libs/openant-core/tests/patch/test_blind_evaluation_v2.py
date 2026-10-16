"""Tests for blind-evaluation-filter/v2 (utilities/autopatcher/tools/
blind_evaluation.py, run_traced.py --blind-filter-policy v2).

Hermetic: LLM_PROVIDER=mock, fetch_cve mocked, no network. Synthetic
placeholder repositories and revisions only -- no benchmark data.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
from unittest import mock

import pytest

import utilities.autopatcher.pipeline as pipeline_module
from utilities.autopatcher.cve_converter import cve_to_vuln_text as REAL_CVE_TO_VULN_TEXT
from utilities.autopatcher.tools import blind_evaluation as be
from utilities.autopatcher.tools.blind_evaluation import (
    KIND_CODE_CHANGE,
    KIND_MALFORMED,
    KIND_ORDINARY,
    KIND_PINNED_CONTENT,
    LINK_REMOVED_TOKEN,
    REVISION_REMOVED_TOKEN,
    RULE_ID,
    RULE_ID_V2,
    UNSUPPORTED_CODE_CHANGE,
    V2_ABORT_CODE,
    V2_ABORT_INVARIANT,
    V2_ABORT_MALFORMED,
    V2_ABORT_MARKDOWN,
    V2_ABORT_REVISION,
    V2_ABORT_TRUNCATED,
    V2_GITHUB_COMMIT,
    V2_GITHUB_COMMITS,
    V2_GITHUB_COMPARE,
    V2_GITHUB_PATCH_FILE,
    V2_GITHUB_PULL,
    V2_OTHER_HOST,
    V2_REVISION_TOKEN,
    BlindEvaluationError,
    BlindEvaluationSession,
    GitHubRepository,
    blind_vulnerability_text,
    blind_vulnerability_text_v2,
    classify_reference_url,
    classify_url_v2,
    replay_transformations,
    sha256_text,
)

from tests.patch.test_blind_evaluation import (  # noqa: F401 -- fixtures/helpers reused as-is
    COMMIT_URL,
    COMPARE_URL,
    CVE_ID,
    ISSUE_URL,
    MAILING_URL,
    MIXED_CVE,
    MODULE_PATH,
    PIP_FIXTURE,
    SCRIPT_PATH,
    URLLIB3_BLIND_SHA,
    URLLIB3_FIXTURE,
    URLLIB3_ORIGINAL_SHA,
    _PipelineSpy,
    _assert_globals_restored,
    _cve,
    _main,
    _outside_references,
    _references_body,
)

TARGET = GitHubRepository("acme", "widget")
TARGET_REMOTE = "https://github.com/acme/widget.git"

REV = "0123456789abcdef0123456789abcdef01234567"          # the revision in COMMIT_URL
OTHER_REV = "fedcba9876543210fedcba9876543210fedcba98"    # unrelated revision
PULL = "https://github.com/acme/widget/pull/7"
EXT_PULL = "https://github.com/curator/review/pull/99"
PATH = "src/widget/parser.py"
BLOB_REM = f"https://github.com/acme/widget/blob/{REV}/{PATH}#L51-L51"
BLOB_OTHER = f"https://github.com/acme/widget/blob/{OTHER_REV}/{PATH}#L51"
HEAD = "The widget parser mishandles nested brackets."


def _desc(*paragraphs: str) -> str:
    return "\n\n".join((HEAD, *paragraphs))


def _render(refs=(MAILING_URL,), *paragraphs: str) -> str:
    return REAL_CVE_TO_VULN_TEXT(_cve(list(refs), _desc(*paragraphs)))


def _v2(text, *, raw=(), target=TARGET, repo_root=None, same_repo=None):
    return blind_vulnerability_text_v2(
        text, same_repo_github=same_repo, raw_reference_urls=raw, target_repository=target, repo_root=repo_root,
    )


def _abort(text, **kw) -> list:
    with pytest.raises(BlindEvaluationError) as ei:
        _v2(text, **kw)
    return ei.value.unsupported_references


def _description(text: str) -> str:
    section = text.split("## Vulnerability description\n", 1)[1].split("\n## Affected products", 1)[0]
    return section.split("**Type:**", 1)[1].split("\n\n", 1)[1]


def _assert_untouched_lines_identical(original: str, result) -> None:
    """Every original line not named by a transformation survives byte-for-byte, in order."""
    touched = {t["line_no"] for t in result.transformations}
    kept = [line for n, line in enumerate(original.splitlines(keepends=True), 1) if n not in touched]
    out = iter(result.blinded_text.splitlines(keepends=True))
    assert all(any(line == o for o in out) for line in kept)


@pytest.fixture
def checkout(tmp_path):
    root = tmp_path / "checkout"
    (root / "src" / "widget").mkdir(parents=True)
    (root / PATH).write_text("x = 1\n")
    return root


# --- classification (what a URL is) ----------------------------------------


class TestClassificationV2:
    @pytest.mark.parametrize("url,category,revisions", [
        (COMMIT_URL, V2_GITHUB_COMMIT, (REV,)),
        ("https://github.com/acme/widget/commit/0123abc", V2_GITHUB_COMMIT, ("0123abc",)),
        (f"https://github.com/acme/widget/commit/{REV}.patch", V2_GITHUB_COMMIT, (REV,)),
        (f"https://github.com/acme/widget/commit/{REV}?w=1", V2_GITHUB_COMMIT, (REV,)),
        (f"https://github.com/acme/widget/commit/{REV}#diff-{'a' * 64}", V2_GITHUB_COMMIT, (REV,)),
        (f"https://github.com/acme/widget/COMMIT/{REV}", V2_GITHUB_COMMIT, (REV,)),
        (f"https://www.github.com/acme/widget/commit/{REV}", V2_GITHUB_COMMIT, (REV,)),
        (f"http://user@github.com:443/acme/widget/commit/{REV}", V2_GITHUB_COMMIT, (REV,)),
        ("https://github.com/acme/widget/commit/v1.2.3", V2_GITHUB_COMMIT, ()),
        (f"https://github.com/acme/widget/commits/{REV}", V2_GITHUB_COMMITS, (REV,)),
        ("https://github.com/acme/widget/commits/main", V2_GITHUB_COMMITS, ()),
        (COMPARE_URL, V2_GITHUB_COMPARE, ()),
        (f"https://github.com/acme/widget/compare/1.0...{REV}", V2_GITHUB_COMPARE, (REV,)),
        (f"https://github.com/acme/widget/compare/fork:{REV}..main.diff", V2_GITHUB_COMPARE, (REV,)),
        (PULL, V2_GITHUB_PULL, ()),
        ("https://github.com/acme/widget/pull/7/files", V2_GITHUB_PULL, ()),
        ("https://github.com/acme/widget/pull/1234567", V2_GITHUB_PULL, ()),  # PR number is not a revision
        (f"https://github.com/acme/widget/pull/7/commits/{REV}", V2_GITHUB_PULL, (REV,)),
        ("https://github.com/acme/widget/pulls", V2_GITHUB_PULL, ()),
        (EXT_PULL, V2_GITHUB_PULL, ()),
        ("https://github.com/acme/widget/blob/main/fix.patch", V2_GITHUB_PATCH_FILE, ()),
        ("https://gitlab.com/acme/widget/-/merge_requests/3", V2_OTHER_HOST, ()),
        ("https://patches.example.org/fix-traversal.diff", V2_OTHER_HOST, ()),
    ])
    def test_code_change_forms(self, url, category, revisions):
        c = classify_url_v2(url)
        assert (c.kind, c.category, c.revisions) == (KIND_CODE_CHANGE, category, revisions)

    @pytest.mark.parametrize("url,rev,path", [
        (BLOB_REM, REV, ("src", "widget", "parser.py#L51-L51".split("#")[0])),
        (f"https://github.com/acme/widget/tree/{REV}/src/widget", REV, ("src", "widget")),
        (f"https://github.com/acme/widget/blame/{REV}/{PATH}", REV, ("src", "widget", "parser.py")),
        (f"https://github.com/acme/widget/raw/{REV}/{PATH}", REV, ("src", "widget", "parser.py")),
        (f"https://raw.githubusercontent.com/acme/widget/{REV}/{PATH}", REV, ("src", "widget", "parser.py")),
        ("https://github.com/acme/widget/blob/0123ABC/x.py", "0123abc", ("x.py",)),
    ])
    def test_revision_pinned_content(self, url, rev, path):
        c = classify_url_v2(url)
        assert c.kind == KIND_PINNED_CONTENT and c.pinned_revision == rev and c.pinned_path == path
        assert c.repository == TARGET

    @pytest.mark.parametrize("url", [
        f"https://github.com/acme/widget/blob/main/{PATH}",
        "https://github.com/acme/widget/tree/v1.0.0/src",
        "https://raw.githubusercontent.com/acme/widget/refs/heads/main/x.py",
        ISSUE_URL,
        "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
        "https://github.com/acme/widget/releases/tag/1.0.1",
        "https://github.com/acme/widget",
        "https://github.com/pull",
        "https://github.com/acme/pull/issues/1",
        MAILING_URL,
    ])
    def test_ordinary(self, url):
        assert classify_url_v2(url).kind == KIND_ORDINARY

    @pytest.mark.parametrize("url", [
        f"https://github.com//widget/commit/{REV}",
        f"https://github.com/acme/../commit/{REV}",
        f"https://github.com/-acme/widget/pull/7",
        f"https://github.com/acme/w%20x/blob/{REV}/x.py",
        f"ftp://github.com/acme/widget/commit/{REV}",
        f"https://raw.githubusercontent.com/-acme/widget/{REV}/x.py",
    ])
    def test_malformed(self, url):
        assert classify_url_v2(url).kind == KIND_MALFORMED

    def test_v1_classifier_unchanged(self):
        assert classify_reference_url(PULL).category == UNSUPPORTED_CODE_CHANGE
        assert classify_reference_url(BLOB_REM).category == be.ORDINARY


# --- References entries -------------------------------------------------------


class TestReferencesV2:
    def test_external_standalone_pull_reference_removed(self):
        original = _render([MAILING_URL, COMMIT_URL, EXT_PULL, ISSUE_URL])
        r = _v2(original)
        assert r.rule_id == RULE_ID_V2
        assert _references_body(r.blinded_text) == [f"- {MAILING_URL}", f"- {ISSUE_URL}"]
        assert r.removed_by_v2 == (COMMIT_URL, EXT_PULL) and r.removed_same_repo_github == ()
        assert r.removed_reference_lines == (f"- {COMMIT_URL}", f"- {EXT_PULL}")
        assert _outside_references(r.blinded_text) == _outside_references(original)
        # exactly the V1 whole-line deletion: input minus those two lines
        assert r.blinded_text == original.replace(f"- {COMMIT_URL}\n", "").replace(f"- {EXT_PULL}\n", "")
        # V1 aborts on the same input
        with pytest.raises(BlindEvaluationError):
            blind_vulnerability_text(original)

    @pytest.mark.parametrize("url", [PULL, "https://github.com/acme/widget/pull/7/files",
                                     "https://github.com/acme/widget/pull/7/files#diff-abc"])
    def test_same_repo_pull_variants_removed_with_or_without_same_repo_policy(self, url):
        original = _render([MAILING_URL, url])
        for same_repo in (None, TARGET):
            r = _v2(original, same_repo=same_repo)
            assert _references_body(r.blinded_text) == [f"- {MAILING_URL}"]
            assert r.removed_by_v2 == (url,) and r.removed_same_repo_github == ()

    def test_same_repo_policy_still_governs_ordinary_same_repo_references(self):
        original = _render([MAILING_URL, ISSUE_URL])
        assert _v2(original).blinded_text == original
        r = _v2(original, same_repo=TARGET)
        assert r.removed_same_repo_github == (ISSUE_URL,) and r.removed_by_v2 == ()
        assert r.transformations[0]["attribution"] == "same_repo_github"

    @pytest.mark.parametrize("cve,same_repo", [
        (MIXED_CVE, None), (MIXED_CVE, TARGET), (URLLIB3_FIXTURE, None), (PIP_FIXTURE, None),
    ])
    def test_commit_and_compare_results_identical_to_v1(self, cve, same_repo):
        original = REAL_CVE_TO_VULN_TEXT(cve)
        v1 = blind_vulnerability_text(original, same_repo_github=same_repo)
        v2 = _v2(original, same_repo=same_repo, raw=be._raw_reference_urls(cve))
        assert v2.blinded_text == v1.blinded_text and v2.blinded_sha256 == v1.blinded_sha256
        assert v2.removed_references == v1.removed_references

    def test_validated_fixture_hash_reproduced(self):
        r = _v2(REAL_CVE_TO_VULN_TEXT(URLLIB3_FIXTURE), raw=be._raw_reference_urls(URLLIB3_FIXTURE))
        assert (r.original_sha256, r.blinded_sha256) == (URLLIB3_ORIGINAL_SHA, URLLIB3_BLIND_SHA)

    def test_malformed_github_reference_aborts(self):
        bad = f"https://github.com//widget/commit/{REV}"
        problems = _abort(_render([MAILING_URL, bad]))
        assert [(p["category"], p["url"], p["context"]) for p in problems] == [
            (V2_ABORT_MALFORMED, bad, "references_entry")]

    def test_pinned_reference_removed_only_at_remediation_revision(self):
        assert _references_body(_v2(_render([MAILING_URL, BLOB_OTHER, COMMIT_URL])).blinded_text) == [
            f"- {MAILING_URL}", f"- {BLOB_OTHER}"]
        r = _v2(_render([MAILING_URL, BLOB_REM, COMMIT_URL]))
        assert _references_body(r.blinded_text) == [f"- {MAILING_URL}"]
        assert r.transformations[0]["matched_revision"] == REV


# --- prose: structural line forms, embedded spans, fail-closed -------------------


class TestProseV2:
    @pytest.mark.parametrize("line", [
        f"Resolved in {PULL}",
        f"Resolved in {PULL}.",
        f"Fixed by {PULL}",
        f"fix: {PULL}",
        f"Patch: <{PULL}>",
        f"- Patched in {EXT_PULL}",
        f"Resolved in {PULL}, {EXT_PULL}",
        f"Fixed in {COMMIT_URL}",
    ])
    def test_structural_remediation_pointer_line_deleted(self, line):
        original = _render([MAILING_URL], "Nested input triggers unbounded recursion.", line)
        r = _v2(original)
        assert _description(r.blinded_text) == _desc("Nested input triggers unbounded recursion.") + "\n"
        pointer = [t for t in r.transformations if t["context"] == "remediation_pointer_line"]
        assert len(pointer) == 1 and pointer[0]["original_line"] == line
        assert [t["context"] for t in r.transformations if t["line_no"] != pointer[0]["line_no"]] == [
            "blank_line_collapse"]
        _assert_untouched_lines_identical(original, r)

    def test_pointer_prefix_regex_is_linear_on_long_whitespace(self):
        import time
        for probe in ("Fix" + " " * 200_000 + "x", "Fixed in" + " \t" * 100_000 + ":x"):
            start = time.perf_counter()
            assert be._POINTER_PREFIX_RE.match(probe) is None
            assert time.perf_counter() - start < 1.0

    @pytest.mark.parametrize("prefix,ok", [
        ("Fix ", True), ("Fix: ", True), ("Fix : ", True), ("Fixed in ", True), ("fixed by: ", True),
        ("- Patched via ", True), ("Fix", False), ("Fix:", False), ("Fixed upstream in ", False), ("Fixes ", False),
    ])
    def test_pointer_prefix_language(self, prefix, ok):
        assert bool(be._POINTER_PREFIX_RE.match(prefix)) is ok

    @pytest.mark.parametrize("line,expected", [
        (f"Resolved upstream in {PULL}", f"Resolved upstream in {LINK_REMOVED_TOKEN}"),
        (f"This was resolved in {PULL} by the maintainers.",
         f"This was resolved in {LINK_REMOVED_TOKEN} by the maintainers."),
    ])
    def test_pointer_rule_is_narrow(self, line, expected):
        r = _v2(_render([MAILING_URL], line))
        assert expected in r.blinded_text and "pull/7" not in r.blinded_text

    @pytest.mark.parametrize("line", [PULL, f"<{PULL}>", f"- {PULL}", f"* {COMMIT_URL}", f"({PULL})",
                                      f"{PULL}.", f"{PULL}, {EXT_PULL}", f"[upstream]({PULL})"])
    def test_standalone_code_change_line_deleted(self, line):
        original = _render([MAILING_URL], "Nested input triggers unbounded recursion.", line, "Affects 1.x.")
        r = _v2(original)
        assert _description(r.blinded_text) == _desc("Nested input triggers unbounded recursion.",
                                                     "Affects 1.x.") + "\n"
        _assert_untouched_lines_identical(original, r)

    @pytest.mark.parametrize("line,expected", [
        (f"See {PULL} for details about the affected parser.",
         f"See {LINK_REMOVED_TOKEN} for details about the affected parser."),
        (f"The parser (see {PULL}) recurses without a depth limit.",
         f"The parser (see {LINK_REMOVED_TOKEN}) recurses without a depth limit."),
        (f"Reported in {ISSUE_URL}; discussed in {PULL}!",
         f"Reported in {ISSUE_URL}; discussed in {LINK_REMOVED_TOKEN}!"),
        (f"Discussed in {ISSUE_URL} and {PULL}.", f"Discussed in {ISSUE_URL} and {LINK_REMOVED_TOKEN}."),
        (f"parser.py was changed in {COMMIT_URL}.", f"parser.py was changed in {LINK_REMOVED_TOKEN}."),
        (f"See ({PULL}.) here.", f"See ({LINK_REMOVED_TOKEN}.) here."),
        (f"Compare <{COMPARE_URL}> with the release notes.",
         f"Compare {LINK_REMOVED_TOKEN} with the release notes."),
    ])
    def test_embedded_prose_keeps_surrounding_text(self, line, expected):
        original = _render([MAILING_URL], line)
        r = _v2(original)
        assert _description(r.blinded_text) == _desc(expected) + "\n"
        (t,) = r.transformations
        assert t["action"] == "replace_span" and t["context"] == "embedded_prose"
        assert t["replacement"] == LINK_REMOVED_TOKEN and t["original_line"] == line
        _assert_untouched_lines_identical(original, r)

    @pytest.mark.parametrize("line,expected", [
        (f"See the [upstream change]({COMMIT_URL}) for context.", "See the upstream change for context."),
        (f"See [0123abcdef]({COMMIT_URL}) for context.", f"See {LINK_REMOVED_TOKEN} for context."),
        (f"See [{ISSUE_URL}]({PULL}) for context.", f"See {LINK_REMOVED_TOKEN} for context."),
        (f"See [PR #7]({PULL}) for context.", f"See {LINK_REMOVED_TOKEN} for context."),
        (f"See [pull request 7]({PULL}) for context.", f"See {LINK_REMOVED_TOKEN} for context."),
        (f"See [the 2.0 change]({PULL}) for context.", "See the 2.0 change for context."),
    ])
    def test_markdown_link(self, line, expected):
        r = _v2(_render([MAILING_URL], line))
        assert _description(r.blinded_text) == _desc(expected) + "\n"
        assert r.transformations[0]["context"] == "markdown_link"

    @pytest.mark.parametrize("line", [
        f'See [the fix]({PULL} "title") here.',
        f"See ![diagram]({PULL}) here.",
        f"See [{PULL}]({ISSUE_URL}) here.",
        f"See <{PULL} here.",
    ])
    def test_ambiguous_markdown_or_brackets_fail_closed(self, line):
        problems = _abort(_render([MAILING_URL], line))
        assert {p["category"] for p in problems} == {V2_ABORT_MARKDOWN}

    def test_ordinary_prose_urls_untouched(self):
        original = _render([MAILING_URL], f"Reported at {ISSUE_URL} and {BLOB_OTHER}; see `{ISSUE_URL}`.")
        r = _v2(original)
        assert r.blinded_text == original and r.transformations == ()

    def test_malformed_github_url_in_prose_aborts(self):
        bad = f"https://github.com/-acme/widget/pull/7"
        problems = _abort(_render([MAILING_URL], f"See {bad} for details."))
        assert [(p["category"], p["url"]) for p in problems] == [(V2_ABORT_MALFORMED, bad)]

    @pytest.mark.parametrize("paragraph,context", [
        (f"```\ncurl {PULL}\n```", "fenced_code"),
        (f"~~~sh\ngit fetch {COMMIT_URL}\n~~~", "fenced_code"),
        (f"Run `curl {PULL}` to reproduce.", "inline_code"),
    ])
    def test_code_change_url_in_code_fails_closed(self, paragraph, context):
        problems = _abort(_render([MAILING_URL], paragraph))
        assert [(p["category"], p["context"]) for p in problems] == [(V2_ABORT_CODE, context)]

    def test_ordinary_url_in_code_untouched(self):
        original = _render([MAILING_URL], f"```\ncurl {ISSUE_URL}\n```")
        assert _v2(original).blinded_text == original

    def test_truncated_url_in_heading_fails_closed(self):
        long_url = "https://example.org/" + "a" * 150
        original = REAL_CVE_TO_VULN_TEXT(_cve([MAILING_URL], f"{long_url} breaks the parser."))
        assert original.splitlines()[0].endswith("...")
        problems = _abort(original)
        assert [p["category"] for p in problems] == [V2_ABORT_TRUNCATED]

    def test_code_change_url_in_heading_replaced_not_deleted(self):
        original = REAL_CVE_TO_VULN_TEXT(_cve([MAILING_URL], f"Resolved in {PULL} upstream."))
        r = _v2(original)
        assert r.blinded_text.splitlines()[0] == f"# Resolved in {LINK_REMOVED_TOKEN} upstream."
        assert {t["context"] for t in r.transformations} == {"heading", "embedded_prose"}

    def test_revision_inside_unrecognized_url_fails_closed(self):
        gitiles = f"https://chromium.googlesource.com/project/+/{REV}"
        problems = _abort(_render([MAILING_URL, COMMIT_URL], f"Mirror: {gitiles} for reference."))
        assert [p["category"] for p in problems] == [V2_ABORT_REVISION]

    def test_unrelated_hex_in_prose_untouched(self):
        original = _render([MAILING_URL, COMMIT_URL], f"Build {OTHER_REV[:12]} is affected.")
        assert f"Build {OTHER_REV[:12]} is affected." in _v2(original).blinded_text


# --- bare remediation revisions in prose ---------------------------------------


REV2 = "89abcdef0123456789abcdef0123456789abcdef"
COMMIT2_URL = f"https://github.com/acme/widget/commit/{REV2}"


class TestBareRevisionV2:
    @pytest.mark.parametrize("token", [REV, REV[:7], REV[:11], REV.upper(), REV[:11].upper()])
    def test_known_revision_token_redacted(self, token):
        line = f"This issue has been addressed in commit {token} which has been included in 5.4."
        original = _render([MAILING_URL, COMMIT_URL], line)
        r = _v2(original)
        expected = f"This issue has been addressed in commit {REVISION_REMOVED_TOKEN} which has been included in 5.4."
        assert _description(r.blinded_text) == _desc(expected) + "\n"
        (t,) = [t for t in r.transformations if t["action"] == "redact_revision"]
        assert t == {
            "action": "redact_revision", "context": "embedded_prose", "line_no": t["line_no"],
            "original_line": line, "start": line.index(token), "end": line.index(token) + len(token),
            "original_span": token, "replacement": REVISION_REMOVED_TOKEN, "category": V2_REVISION_TOKEN,
            "matched_revision": REV, "reason": t["reason"],
        }
        assert original.splitlines()[t["line_no"] - 1] == line
        _assert_untouched_lines_identical(original, r)

    def test_simple_inline_code_token_keeps_backticks(self):
        line = f"This issue has been addressed in commit `{REV[:11]}` which has been included in 5.4."
        r = _v2(_render([MAILING_URL, COMMIT_URL], line))
        assert (f"This issue has been addressed in commit `{REVISION_REMOVED_TOKEN}` which has been included in 5.4."
                in r.blinded_text)
        assert [t["context"] for t in r.transformations if t["action"] == "redact_revision"] == ["inline_code_token"]

    @pytest.mark.parametrize("fmt", ["({t})", "[{t}]", "{t}.", "{t},", "{t};", "{t}:", "{t}!", "{t}?", "'{t}'",
                                     '"{t}"', "{{{t}}}"])
    def test_punctuation_around_token(self, fmt):
        line = "Fixed by " + fmt.format(t=REV[:9]) + " upstream"
        r = _v2(_render([MAILING_URL, COMMIT_URL], line))
        assert "Fixed by " + fmt.format(t=REVISION_REMOVED_TOKEN) + " upstream" in r.blinded_text

    def test_multiple_known_revisions_on_one_line(self):
        line = f"Commits {REV[:7]} and {REV2[:10]} fixed it; {OTHER_REV[:8]} did not."
        r = _v2(_render([MAILING_URL, COMMIT_URL, COMMIT2_URL], line))
        t = REVISION_REMOVED_TOKEN
        assert f"Commits {t} and {t} fixed it; {OTHER_REV[:8]} did not." in r.blinded_text
        redactions = [t for t in r.transformations if t["action"] == "redact_revision"]
        assert [x["matched_revision"] for x in redactions] == [REV, REV2]

    def test_short_known_revision_matches_longer_token(self):
        short_commit = f"https://github.com/acme/widget/commit/{REV[:7]}"
        r = _v2(_render([MAILING_URL, short_commit], f"Fixed by {REV} upstream."))
        assert f"Fixed by {REVISION_REMOVED_TOKEN} upstream." in r.blinded_text

    @pytest.mark.parametrize("line", [
        f"Build {OTHER_REV[:12]} is affected.",                  # unrelated SHA
        "Versions 1234567 and 2.0.1 are affected.",              # number / version
        f"Prefix {REV[:6]} is too short to match.",              # below minimum length
        f"Digest {'f' * 3}{REV[:10]} differs.",                  # longer hex, revision not at its start
        f"Identifier x{REV[:10]} and {REV[:10]}z are distinct.", # alphanumeric containment
    ])
    def test_not_redacted(self, line):
        original = _render([MAILING_URL, COMMIT_URL], line)
        r = _v2(original)
        assert line in r.blinded_text
        assert not [t for t in r.transformations if t["action"] == "redact_revision"]

    @pytest.mark.parametrize("line", [
        f"Digest {REV}ff is not a revision token.",               # longer hex starting with the revision
        f"Build tag rev_{REV[:10]} is affected.",                 # identifier with separator
        f"Apply {REV[:10]}.patch upstream.",                      # file-name continuation
        f"Run `git show {REV[:10]}` to see it.",                  # part of a larger code span
        f"See ref={REV[:10]} in the log.",
    ])
    def test_non_standalone_known_revision_fails_closed_not_partially_redacted(self, line):
        problems = _abort(_render([MAILING_URL, COMMIT_URL], line))
        assert [p["category"] for p in problems] == [V2_ABORT_REVISION]

    def test_known_revision_in_fenced_code_fails_closed(self):
        problems = _abort(_render([MAILING_URL, COMMIT_URL], f"```\ngit checkout {REV[:10]}\n```"))
        assert [p["category"] for p in problems] == [V2_ABORT_REVISION]

    def test_revision_inside_sanitized_url_not_separately_redacted(self, checkout):
        r = _v2(_render([MAILING_URL, COMMIT_URL], f"See {COMMIT_URL} and {BLOB_REM} here."), repo_root=checkout)
        assert f"See {LINK_REMOVED_TOKEN} and {PATH} here." in r.blinded_text
        assert {t["action"] for t in r.transformations} == {"delete_line", "replace_span"}

    def test_revision_in_markdown_link_text_handled_by_link_rule(self):
        r = _v2(_render([MAILING_URL, COMMIT_URL], f"See [{REV[:9]}]({COMMIT_URL}) here."))
        assert f"See {LINK_REMOVED_TOKEN} here." in r.blinded_text
        assert not [t for t in r.transformations if t["action"] == "redact_revision"]

    def test_heading_token_redacted(self):
        original = REAL_CVE_TO_VULN_TEXT(_cve([MAILING_URL, COMMIT_URL], f"Commit {REV[:8]} fixes a parser bug."))
        r = _v2(original)
        assert r.blinded_text.splitlines()[0] == f"# Commit {REVISION_REMOVED_TOKEN} fixes a parser bug."
        assert REV[:7] not in r.blinded_text

    def test_without_pass1_revision_nothing_is_redacted(self):
        original = _render([MAILING_URL], f"Addressed in commit {REV[:11]}.")
        r = _v2(original)
        assert r.blinded_text == original and r.transformations == ()

    def test_revision_from_raw_references_redacted(self):
        refs = [f"https://lists.example.org/msg{n}.html" for n in range(5)] + [COMMIT_URL]
        cve = _cve(refs, _desc(f"Addressed in commit {REV[:11]}."))
        r = _v2(REAL_CVE_TO_VULN_TEXT(cve), raw=be._raw_reference_urls(cve))
        assert f"Addressed in commit {REVISION_REMOVED_TOKEN}." in r.blinded_text

    def test_replay_includes_redactions_and_rejects_tampering(self):
        original = _render([MAILING_URL, COMMIT_URL], f"See {PULL} and commit `{REV[:11]}` for the parser.")
        r = _v2(original)
        record = json.loads(json.dumps(list(r.transformations)))
        assert replay_transformations(original, record) == r.blinded_text
        assert [t["action"] for t in record] == ["replace_span", "redact_revision", "delete_line"]
        bad = json.loads(json.dumps(record))
        next(t for t in bad if t["action"] == "redact_revision")["matched_revision"] = OTHER_REV
        with pytest.raises(BlindEvaluationError, match="inconsistent"):
            replay_transformations(original, bad)

    def test_post_transform_scan_still_strict(self, monkeypatch):
        monkeypatch.setattr(be, "REVISION_REMOVED_TOKEN", REV[:12])
        problems = _abort(_render([MAILING_URL, COMMIT_URL], f"Addressed in commit {REV[:11]}."))
        assert [p["category"] for p in problems] == [V2_ABORT_REVISION]


# --- pass 2: revision-pinned links ---------------------------------------------


class TestPinnedV2:
    def test_blob_at_remediation_revision_reduced_to_existing_target_path(self, checkout):
        original = _render([MAILING_URL, COMMIT_URL], "Nested input triggers recursion.", BLOB_REM)
        r = _v2(original, repo_root=checkout)
        assert _description(r.blinded_text) == _desc("Nested input triggers recursion.", PATH) + "\n"
        (t,) = [t for t in r.transformations if t["action"] == "replace_span"]
        assert (t["context"], t["replacement"], t["matched_revision"]) == ("standalone_url_line", PATH, REV)
        assert t["path_retained"] is True and t["path_exists_at_target"] is True
        assert REV[:7] not in r.blinded_text and "#L51" not in r.blinded_text
        assert r.remediation_revisions[0] == {"revision": REV, "source_url": COMMIT_URL,
                                              "source": "rendered_references"}

    def test_path_absent_at_target_removed(self, tmp_path):
        r = _v2(_render([MAILING_URL, COMMIT_URL], BLOB_REM), repo_root=tmp_path)
        (t,) = [t for t in r.transformations if t["action"] == "replace_span"]
        assert t["replacement"] == LINK_REMOVED_TOKEN
        assert t["path_retained"] is False and t["path_exists_at_target"] is False

    @pytest.mark.parametrize("target,root_needed", [(None, True), (TARGET, False)])
    def test_no_target_checkout_means_no_path(self, checkout, target, root_needed):
        r = _v2(_render([MAILING_URL, COMMIT_URL], BLOB_REM), target=target,
                repo_root=checkout if root_needed else None)
        (t,) = [t for t in r.transformations if t["action"] == "replace_span"]
        assert t["replacement"] == LINK_REMOVED_TOKEN and t["path_exists_at_target"] is None

    def test_external_repository_blob_at_remediation_revision_removed(self, checkout):
        ext = BLOB_REM.replace("/acme/", "/forker/")
        r = _v2(_render([MAILING_URL, COMMIT_URL], f"Copied from {ext} originally."), repo_root=checkout)
        assert f"Copied from {LINK_REMOVED_TOKEN} originally." in r.blinded_text

    def test_embedded_blob_keeps_prose(self, checkout):
        r = _v2(_render([MAILING_URL, COMMIT_URL], f"The vulnerable code is {BLOB_REM} in the parser."),
                repo_root=checkout)
        assert f"The vulnerable code is {PATH} in the parser." in r.blinded_text

    @pytest.mark.parametrize("url", [BLOB_OTHER, f"https://github.com/acme/widget/blob/main/{PATH}#L3"])
    def test_blob_not_at_remediation_revision_untouched(self, checkout, url):
        original = _render([MAILING_URL, COMMIT_URL], f"The vulnerable code is {url} in the parser.")
        r = _v2(original, repo_root=checkout)
        assert f"The vulnerable code is {url} in the parser." in r.blinded_text
        assert all(t["context"] == "references_entry" for t in r.transformations)

    @pytest.mark.parametrize("url,expected", [
        (f"https://github.com/acme/widget/tree/{REV}/src/widget", "src/widget"),
        (f"https://github.com/acme/widget/blame/{REV}/{PATH}", PATH),
        (f"https://github.com/acme/widget/raw/{REV}/{PATH}", PATH),
        (f"https://raw.githubusercontent.com/acme/widget/{REV}/{PATH}", PATH),
        (f"https://github.com/acme/widget/blob/{REV[:7]}/{PATH}?plain=1#L5", PATH),
    ])
    def test_tree_blame_raw_variants(self, checkout, url, expected):
        r = _v2(_render([MAILING_URL, COMMIT_URL], f"Location: {url} here."), repo_root=checkout)
        assert f"Location: {expected} here." in r.blinded_text

    def test_short_remediation_revision_matches_full_pinned_revision(self, checkout):
        short_commit = f"https://github.com/acme/widget/commit/{REV[:7]}"
        r = _v2(_render([MAILING_URL, short_commit], BLOB_REM), repo_root=checkout)
        assert PATH in r.blinded_text and REV[:7] not in r.blinded_text

    def test_revision_from_raw_references_beyond_rendering_cap(self, checkout):
        refs = [f"https://lists.example.org/msg{n}.html" for n in range(5)] + [COMMIT_URL]
        cve = _cve(refs, _desc(BLOB_REM))
        original = REAL_CVE_TO_VULN_TEXT(cve)
        assert COMMIT_URL not in original  # past the converter's five-reference cap
        assert _v2(original, repo_root=checkout).blinded_text == original  # unknown revision: untouched
        r = _v2(original, raw=be._raw_reference_urls(cve), repo_root=checkout)
        assert PATH in r.blinded_text and REV[:7] not in r.blinded_text
        assert r.remediation_revisions == ({"revision": REV, "source_url": COMMIT_URL,
                                            "source": "raw_advisory_references"},)

    @pytest.mark.parametrize("suffix", ["../etc/passwd", "src/%2E%2E/x.py", "src/a%2Fb.py", ".git/config"])
    def test_unsafe_pinned_path_not_retained(self, checkout, suffix):
        url = f"https://github.com/acme/widget/blob/{REV}/{suffix}"
        r = _v2(_render([MAILING_URL, COMMIT_URL], f"At {url} here."), repo_root=checkout)
        assert f"At {LINK_REMOVED_TOKEN} here." in r.blinded_text

    def test_symlink_escaping_checkout_not_retained(self, checkout, tmp_path):
        outside = tmp_path / "outside.py"
        outside.write_text("")
        os.symlink(outside, checkout / "link.py")
        url = f"https://github.com/acme/widget/blob/{REV}/link.py"
        r = _v2(_render([MAILING_URL, COMMIT_URL], f"At {url} here."), repo_root=checkout)
        assert f"At {LINK_REMOVED_TOKEN} here." in r.blinded_text

    def test_pointer_line_with_pinned_link_deleted(self, checkout):
        r = _v2(_render([MAILING_URL, COMMIT_URL], "Nested input recursion.", f"Fixed in {BLOB_REM}"),
                repo_root=checkout)
        assert _description(r.blinded_text) == _desc("Nested input recursion.") + "\n"


# --- invariants and provenance ------------------------------------------------


class TestInvariantsV2:
    def _complex(self, checkout):
        original = _render(
            [MAILING_URL, COMMIT_URL, EXT_PULL, ISSUE_URL],
            f"See {PULL} for details about the affected parser.", BLOB_REM, f"Resolved in {PULL}",
        )
        return original, _v2(original, repo_root=checkout)

    def test_replay_reproduces_blinded_text_and_record_is_json(self, checkout):
        original, r = self._complex(checkout)
        record = json.loads(json.dumps(list(r.transformations)))
        assert replay_transformations(original, record) == r.blinded_text
        assert [t["line_no"] for t in record] == sorted(t["line_no"] for t in record)
        for key in ("action", "context", "line_no", "original_line", "reason", "matched_revision"):
            assert all(key in t for t in record)
        _assert_untouched_lines_identical(original, r)

    def test_replay_rejects_tampered_record(self, checkout):
        original, r = self._complex(checkout)
        record = json.loads(json.dumps(list(r.transformations)))
        span = next(t for t in record if t["action"] == "replace_span")
        span["original_span"] = "x"
        with pytest.raises(BlindEvaluationError, match="does not match"):
            replay_transformations(original, record)

    def test_post_transform_rescan_aborts_on_surviving_code_change_url(self, checkout, monkeypatch):
        monkeypatch.setattr(be, "LINK_REMOVED_TOKEN", EXT_PULL)
        original, _ = _render([MAILING_URL], f"See {PULL} for details."), None
        problems = _abort(original)
        assert [p["category"] for p in problems] == [V2_ABORT_INVARIANT]

    def test_replay_mismatch_aborts(self, checkout, monkeypatch):
        monkeypatch.setattr(be, "replay_transformations", lambda original, record: original)
        with pytest.raises(BlindEvaluationError) as ei:
            self._complex(checkout)
        assert [p["category"] for p in ei.value.unsupported_references] == [V2_ABORT_INVARIANT]

    def test_output_has_no_code_change_url_or_revision(self, checkout):
        _, r = self._complex(checkout)
        for word in ("pull/7", "pull/99", "commit/", REV[:7]):
            assert word not in r.blinded_text
        assert f"See {LINK_REMOVED_TOKEN} for details about the affected parser." in r.blinded_text
        assert PATH in r.blinded_text and "Resolved" not in r.blinded_text


# --- V1 stays the default and unchanged ---------------------------------------


class TestV1Unchanged:
    def test_v1_filter_unchanged(self):
        r = blind_vulnerability_text(REAL_CVE_TO_VULN_TEXT(URLLIB3_FIXTURE))
        assert (r.rule_id, r.original_sha256, r.blinded_sha256) == (RULE_ID, URLLIB3_ORIGINAL_SHA, URLLIB3_BLIND_SHA)
        assert r.transformations == () and r.remediation_revisions == () and r.removed_by_v2 == ()
        with pytest.raises(BlindEvaluationError):
            blind_vulnerability_text(_render([MAILING_URL, PULL]))

    def test_session_defaults_to_v1(self):
        s = BlindEvaluationSession()
        assert s.policy == "v1" and s.rule_id == RULE_ID
        manifest = s.to_manifest_dict()
        for key in ("transformations", "removed_by_v2", "remediation_revisions", "path_retention"):
            assert key not in manifest

    def test_unknown_policy_rejected(self):
        with pytest.raises(BlindEvaluationError, match="unknown blind filter policy"):
            BlindEvaluationSession(policy="v3").__enter__()

    def test_no_benchmark_identifiers_in_v2_implementation(self):
        source = MODULE_PATH.read_text(encoding="utf-8").lower()
        for name in ("waitress", "langchain", "advisory-review", "pylons", "recursive_url"):
            assert name not in source


# --- run_traced --blind-filter-policy ------------------------------------------


@pytest.fixture(scope="module")
def run_traced():
    spec = importlib.util.spec_from_file_location("run_traced_v2_tests", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(run_traced, tmp_path, monkeypatch, cve, extra_args, remote=TARGET_REMOTE, with_file=True):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    if remote is not None:
        subprocess.run(["git", "remote", "add", "origin", remote], cwd=repo, check=True)
    if with_file:
        (repo / "src" / "widget").mkdir(parents=True)
        (repo / PATH).write_text("def parse(s):\n    return s\n")
    out = tmp_path / "out"
    argv = ["--cve", CVE_ID, "--repo-root", str(repo), "--output", str(out), "--quiet", *extra_args]
    with mock.patch("utilities.autopatcher.cve_fetcher.fetch_cve", return_value=cve) as m_fetch:
        rc = run_traced.main(argv)
    manifest_path = out / "trace" / "run_manifest.json"
    return rc, out, (json.loads(manifest_path.read_text()) if manifest_path.exists() else None), m_fetch


V2_CVE = _cve([MAILING_URL, COMMIT_URL, EXT_PULL], _desc(BLOB_REM, f"Resolved in {PULL}"))


class TestRunTracedV2:
    def test_flag_defaults_to_v1(self, run_traced):
        args = run_traced.build_parser().parse_args(["--cve", "X", "--repo-root", "/r", "--blind-evaluation"])
        assert args.blind_filter_policy is None

    def test_rejected_without_blind_evaluation(self, run_traced, tmp_path, monkeypatch, capsys):
        rc, _, manifest, m_fetch = _run(run_traced, tmp_path, monkeypatch, V2_CVE, ["--blind-filter-policy", "v2"])
        assert rc == 2 and manifest is None
        m_fetch.assert_not_called()
        assert "--blind-filter-policy requires --blind-evaluation" in capsys.readouterr().err

    def test_rejects_unknown_policy(self, run_traced):
        with pytest.raises(SystemExit):
            run_traced.build_parser().parse_args(["--cve", "X", "--blind-evaluation", "--blind-filter-policy", "v3"])

    @pytest.mark.parametrize("strip", [False, True])
    def test_v2_end_to_end_verified(self, run_traced, tmp_path, monkeypatch, strip):
        spy = _PipelineSpy()
        extra = ["--blind-evaluation", "--blind-filter-policy", "v2"]
        if strip:
            extra.append("--blind-strip-same-repo-github-references")
        with mock.patch.object(pipeline_module, "run", side_effect=spy):
            rc, out, manifest, _ = _run(run_traced, tmp_path, monkeypatch, V2_CVE, extra)
        assert rc == 0 and manifest["status"] == "success"
        original = REAL_CVE_TO_VULN_TEXT(V2_CVE)
        b = manifest["blind_evaluation"]
        assert b["rule_id"] == RULE_ID_V2 and b["status"] == "verified"
        assert b["pipeline_input_verified"] is True and b["vulnerability_artifact_verified"] is True
        assert b["original_sha256"] == sha256_text(original)
        assert spy.texts and sha256_text(spy.texts[0]) == b["blinded_sha256"] == b["pipeline_input_sha256"]
        blinded = spy.texts[0]
        assert _description(blinded) == _desc(PATH) + "\n"
        assert _references_body(blinded) == [f"- {MAILING_URL}"]
        assert b["removed_by_v2"] == [COMMIT_URL, EXT_PULL] and "removed_by_v1" not in b
        assert b["path_retention"] == {"target_repository": "github.com/acme/widget", "target_checkout_checked": True}
        assert b["raw_reference_url_count"] == 3
        assert b["post_transform_checks"]["transformation_replay_verified"] is True
        assert replay_transformations(original, b["transformations"]) == blinded
        assert ("same_repo_github_policy" in b) is strip
        sidecar = out / "trace" / "blind_evaluation"
        assert json.loads((sidecar / "transformations.json").read_text())["transformations"] == b["transformations"]
        assert set(b["sidecar_files"].values()) == {p.name for p in sidecar.iterdir()}

    def test_v2_without_github_origin_never_retains_paths(self, run_traced, tmp_path, monkeypatch):
        spy = _PipelineSpy()
        with mock.patch.object(pipeline_module, "run", side_effect=spy):
            rc, _, manifest, _ = _run(run_traced, tmp_path, monkeypatch, V2_CVE,
                                      ["--blind-evaluation", "--blind-filter-policy", "v2"], remote=None)
        assert rc == 0 and manifest["blind_evaluation"]["path_retention"]["target_repository"] is None
        assert _description(spy.texts[0]) == _desc(LINK_REMOVED_TOKEN) + "\n"

    def test_v2_abort_before_pipeline(self, run_traced, tmp_path, monkeypatch):
        cve = _cve([MAILING_URL, COMMIT_URL], _desc(f"Introduced before rev_{REV[:10]} landed."))
        spy = _PipelineSpy()
        with mock.patch.object(pipeline_module, "run", side_effect=spy):
            rc, _, manifest, _ = _run(run_traced, tmp_path, monkeypatch, cve,
                                      ["--blind-evaluation", "--blind-filter-policy", "v2"])
        b = manifest["blind_evaluation"]
        assert rc == 2 and spy.texts == [] and manifest["llm_call_count"] == 0
        assert b["rule_id"] == RULE_ID_V2 and b["status"] == "aborted" and b["pipeline_entry_count"] == 0
        assert [u["category"] for u in b["unsupported_references"]] == [V2_ABORT_REVISION]

    def test_explicit_v1_identical_to_default(self, run_traced, tmp_path, monkeypatch):
        rc1, _, default = _main(run_traced, tmp_path, monkeypatch, MIXED_CVE, ["--blind-evaluation"], name="a")
        rc2, _, explicit = _main(run_traced, tmp_path, monkeypatch, MIXED_CVE,
                                    ["--blind-evaluation", "--blind-filter-policy", "v1"], name="b")
        assert rc1 == rc2 == 0
        assert set(default["blind_evaluation"]) == set(explicit["blind_evaluation"])
        assert explicit["blind_evaluation"]["rule_id"] == RULE_ID
        assert explicit["blind_evaluation"]["blinded_sha256"] == default["blind_evaluation"]["blinded_sha256"]
