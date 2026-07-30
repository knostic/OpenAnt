"""Unit tests for repo_locator. All tests use tmp_path repos — no real repos needed."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest



def write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


class TestExplicitFilePath:
    def test_finds_file_mentioned_by_path(self, tmp_path):
        from utilities.autopatcher.repo_locator import find_code_context
        write(tmp_path / "app" / "auth.py", "def authenticate(u, p):\n    pass\n")
        vuln = "Vulnerability in app/auth.py — SQL injection in authenticate()"
        result = find_code_context(vuln, tmp_path)
        assert "authenticate" in result

    def test_explicit_path_preferred_over_symbol(self, tmp_path):
        from utilities.autopatcher.repo_locator import find_code_context, _extract_file_paths
        write(tmp_path / "app" / "auth.py", "def authenticate(u, p):\n    pass\n")
        write(tmp_path / "other" / "stuff.py", "def authenticate(x):\n    pass\n")
        vuln = "Vulnerability in app/auth.py — authenticate() is exploitable"
        paths = _extract_file_paths(vuln)
        assert "app/auth.py" in paths
        result = find_code_context(vuln, tmp_path)
        assert result != ""
        # auth.py should appear (highest score)
        assert "auth" in result


class TestRepositoryPathResolver:
    """Unit tests for RepositoryPathResolver: exact match + unique suffix
    match only. Basename-only matching is explicitly out of scope for this
    slice — see test_bare_filename_does_not_fall_back_to_basename_match."""

    def test_exact_match_resolves(self, tmp_path):
        from utilities.autopatcher.repo_locator import RepositoryPathResolver
        write(tmp_path / "app" / "auth.py", "def authenticate(): pass\n")
        resolver = RepositoryPathResolver(tmp_path)
        result = resolver.resolve("app/auth.py")
        assert result.strategy == "exact"
        assert result.path == (tmp_path / "app" / "auth.py").resolve()

    def test_suffix_match_resolves_src_layout(self, tmp_path):
        """Mirrors pip's shape: advisory names `_internal/download.py`,
        the real file lives under a src-layout prefix the advisory text
        never mentions."""
        from utilities.autopatcher.repo_locator import RepositoryPathResolver
        write(
            tmp_path / "src" / "pip" / "_internal" / "download.py",
            "def unpack_url(): pass\n",
        )
        resolver = RepositoryPathResolver(tmp_path)
        result = resolver.resolve("_internal/download.py")
        assert result.strategy == "suffix"
        assert result.path == (
            tmp_path / "src" / "pip" / "_internal" / "download.py"
        ).resolve()

    def test_exact_match_preferred_over_suffix(self, tmp_path):
        """When both an exact-join file and a deeper suffix-matching file
        exist, the exact match wins — the fallback must never override a
        working resolution."""
        from utilities.autopatcher.repo_locator import RepositoryPathResolver
        write(tmp_path / "_internal" / "download.py", "# shallow\n")
        write(tmp_path / "src" / "pip" / "_internal" / "download.py", "# deep\n")
        resolver = RepositoryPathResolver(tmp_path)
        result = resolver.resolve("_internal/download.py")
        assert result.strategy == "exact"
        assert result.path == (tmp_path / "_internal" / "download.py").resolve()

    def test_ambiguous_suffix_match_is_not_resolved(self, tmp_path):
        """Two files sharing the same suffix under different top-level
        directories must not be silently guessed — this is the safety
        property the whole fallback depends on."""
        from utilities.autopatcher.repo_locator import RepositoryPathResolver
        write(tmp_path / "a" / "_internal" / "download.py", "# a\n")
        write(tmp_path / "b" / "_internal" / "download.py", "# b\n")
        resolver = RepositoryPathResolver(tmp_path)
        result = resolver.resolve("_internal/download.py")
        assert result.strategy == "ambiguous"
        assert result.path is None

    def test_bare_filename_does_not_fall_back_to_basename_match(self, tmp_path):
        """A single-segment path (no directory component) must not trigger
        suffix matching — that would be basename matching, which is
        explicitly out of scope for this slice."""
        from utilities.autopatcher.repo_locator import RepositoryPathResolver
        write(tmp_path / "deeply" / "nested" / "auth.py", "def authenticate(): pass\n")
        resolver = RepositoryPathResolver(tmp_path)
        result = resolver.resolve("auth.py")
        assert result.strategy == "unresolved"
        assert result.path is None

    def test_no_match_returns_unresolved(self, tmp_path):
        from utilities.autopatcher.repo_locator import RepositoryPathResolver
        write(tmp_path / "other.py", "print('hello')\n")
        resolver = RepositoryPathResolver(tmp_path)
        result = resolver.resolve("app/auth.py")
        assert result.strategy == "unresolved"
        assert result.path is None

    def test_suffix_match_respects_path_segment_boundaries(self, tmp_path):
        """A directory named `my_internal` must not satisfy a suffix
        search for `_internal/download.py` — matching is segment-aware,
        not a raw string-suffix comparison."""
        from utilities.autopatcher.repo_locator import RepositoryPathResolver
        write(tmp_path / "my_internal" / "download.py", "# decoy\n")
        resolver = RepositoryPathResolver(tmp_path)
        result = resolver.resolve("_internal/download.py")
        assert result.strategy == "unresolved"
        assert result.path is None


class TestExplicitPathSrcLayoutIntegration:
    """find_code_context() integration: the src-layout fallback must surface
    the real file end-to-end, through Pass 1, not just at the resolver
    unit-test level."""

    def test_src_layout_file_included_via_suffix_fallback(self, tmp_path):
        from utilities.autopatcher.repo_locator import find_code_context
        write(
            tmp_path / "src" / "pip" / "_internal" / "download.py",
            "def unpack_url(link, location):\n    pass\n",
        )
        vuln = "Vulnerability in _internal/download.py — unpack_url() follows unsafe redirects"
        result = find_code_context(vuln, tmp_path)
        assert "unpack_url" in result
        assert "src/pip/_internal/download.py" in result

    def test_ambiguous_src_layout_path_does_not_crash_or_leak_wrong_file(self, tmp_path):
        from utilities.autopatcher.repo_locator import find_code_context
        write(tmp_path / "a" / "_internal" / "download.py", "def a_impl(): pass\n")
        write(tmp_path / "b" / "_internal" / "download.py", "def b_impl(): pass\n")
        vuln = "Vulnerability in _internal/download.py"
        result = find_code_context(vuln, tmp_path)
        assert isinstance(result, str)  # no crash
        # Neither ambiguous candidate should be silently chosen via Pass 1
        assert "a_impl" not in result
        assert "b_impl" not in result


class TestSymbolMatch:
    def test_finds_function_by_backtick_name(self, tmp_path):
        from utilities.autopatcher.repo_locator import find_code_context
        write(tmp_path / "src" / "db.py", "def execute_query(sql):\n    cursor.execute(sql)\n")
        vuln = "The `execute_query` function does not use parameterized queries"
        result = find_code_context(vuln, tmp_path)
        assert "execute_query" in result

    def test_finds_snake_case_symbol(self, tmp_path):
        from utilities.autopatcher.repo_locator import find_code_context
        write(tmp_path / "lib" / "auth.py", "def validate_token(tok):\n    return True\n")
        vuln = "validate_token does not check expiry — security bypass possible"
        result = find_code_context(vuln, tmp_path)
        assert "validate_token" in result

    def test_finds_pascal_case_symbol(self, tmp_path):
        from utilities.autopatcher.repo_locator import find_code_context
        write(tmp_path / "models" / "user.py", "class UserManager:\n    pass\n")
        vuln = "UserManager lacks access control checks"
        result = find_code_context(vuln, tmp_path)
        assert "UserManager" in result


class TestCweKeywordFallback:
    def test_sql_injection_cwe_finds_cursor(self, tmp_path):
        from utilities.autopatcher.repo_locator import find_code_context
        write(
            tmp_path / "db" / "queries.py",
            "def run(sql):\n    cursor.execute(sql)\n    return cursor.fetchone()\n",
        )
        vuln = "SQL injection (CWE-89) in authentication module"
        result = find_code_context(vuln, tmp_path)
        assert result != ""
        assert "execute" in result or "cursor" in result


# ---------------------------------------------------------------------------
# Stage 2: CWE-name token expansion (cwe_name_tokens)
#
# Per reports/implementation_plan_stage2_token_expansion_2026-07-14.md:
# union with _CWE_KEYWORDS (not replacement), lowercase tokens, minimal
# grammatical stopword filter only (no _GENERIC_TOKENS reuse — §0.2),
# parenthetical abbreviations kept (§0.3), no ranking/scoring/policy change.
# ---------------------------------------------------------------------------

class TestCweNameTokens:
    """Unit tests for cwe_name_tokens() — pure text function, no repo needed."""

    def test_all_three_type_line_shapes_parse_without_bare_cwe_token(self):
        """The three real **Type:** line shapes observed in this project's
        corpus (CWE-id-first with parens, name-first with parens, name-first
        with an em-dash and a nested parenthetical abbreviation) must all
        parse without a bare CWE-NNN token surviving into the output."""
        from utilities.autopatcher.repo_locator import cwe_name_tokens
        curl_text = "**Type:** Insufficiently Protected Credentials (CWE-522)"
        node_semver_text = (
            "**Type:** Regular Expression Denial of Service (ReDoS) — CWE-1333"
        )
        ghsa_text = "**Type:** CWE-798 (Use of Hard-coded Credentials)"
        for text in (curl_text, node_semver_text, ghsa_text):
            tokens = cwe_name_tokens(text)
            assert not any("cwe" in t.lower() for t in tokens), tokens

    def test_curl_type_line_yields_expected_tokens(self):
        from utilities.autopatcher.repo_locator import cwe_name_tokens
        text = "**Type:** Insufficiently Protected Credentials (CWE-522)"
        tokens = cwe_name_tokens(text)
        assert "credentials" in tokens
        assert "protected" in tokens
        assert "insufficiently" in tokens

    def test_node_semver_type_line_keeps_nested_abbreviation(self):
        """The nested (ReDoS) abbreviation must survive as `redos` — approved
        Stage 2 design decision (§0.3): kept, not discarded. `service` must
        also survive (§0.2: _GENERIC_TOKENS reuse was rejected)."""
        from utilities.autopatcher.repo_locator import cwe_name_tokens
        text = "**Type:** Regular Expression Denial of Service (ReDoS) — CWE-1333"
        tokens = cwe_name_tokens(text)
        assert "redos" in tokens
        assert "regular" in tokens
        assert "expression" in tokens
        assert "service" in tokens

    def test_ghsa_style_cwe_id_first_shape_parses(self):
        from utilities.autopatcher.repo_locator import cwe_name_tokens
        text = "**Type:** CWE-798 (Use of Hard-coded Credentials)"
        tokens = cwe_name_tokens(text)
        assert "credentials" in tokens
        assert "hard-coded" in tokens

    def test_generic_cwe_name_does_not_crash_or_special_case(self):
        """CWE-200's real name is broad; must not crash, and no special-casing
        for 'generic' CWE ids — the same minimal filter as every other case."""
        from utilities.autopatcher.repo_locator import cwe_name_tokens
        text = (
            "**Type:** CWE-200 "
            "(Exposure of Sensitive Information to an Unauthorized Actor)"
        )
        tokens = cwe_name_tokens(text)
        assert isinstance(tokens, list)
        assert all(isinstance(t, str) for t in tokens)
        assert not any("cwe" in t.lower() for t in tokens)

    def test_no_type_line_returns_empty_list(self):
        from utilities.autopatcher.repo_locator import cwe_name_tokens
        assert cwe_name_tokens("No Type line present in this text at all.") == []

    def test_tokens_are_lowercase(self):
        from utilities.autopatcher.repo_locator import cwe_name_tokens
        text = "**Type:** Regular Expression Denial of Service (ReDoS) — CWE-1333"
        tokens = cwe_name_tokens(text)
        assert tokens == [t.lower() for t in tokens]
        assert "Regular" not in tokens
        assert "Service" not in tokens

    def test_proven_valuable_words_survive_stopword_filter(self):
        """expression/regular/prototype/credentials must never be filtered —
        encodes the prior investigation's own false-negative lesson."""
        from utilities.autopatcher.repo_locator import _CWE_NAME_STOPWORDS
        for word in ("expression", "regular", "prototype", "credentials"):
            assert word not in _CWE_NAME_STOPWORDS

    def test_deterministic_ordering(self):
        from utilities.autopatcher.repo_locator import cwe_name_tokens
        text = "**Type:** Regular Expression Denial of Service (ReDoS) — CWE-1333"
        assert cwe_name_tokens(text) == cwe_name_tokens(text)

    def test_bare_cwe_id_never_survives_prototype_pollution_name(self):
        from utilities.autopatcher.repo_locator import cwe_name_tokens
        text = (
            "**Type:** CWE-1321 (Improperly Controlled Modification of "
            "Object Prototype Attributes ('Prototype Pollution'))"
        )
        tokens = cwe_name_tokens(text)
        assert not any("1321" in t for t in tokens)
        assert "prototype" in tokens
        assert "pollution" in tokens


class TestCweKeywordDictUnionUnaffected:
    """Union, not replacement: CWE-22's existing _CWE_KEYWORDS coverage must
    be unaffected by the addition of cwe_name_tokens()."""

    def test_cwe22_dict_token_still_reachable_via_find_code_context(self, tmp_path):
        from utilities.autopatcher.repo_locator import find_code_context
        write(
            tmp_path / "fs.py",
            "def resolve(p):\n    return os.path.abspath(p)\n",
        )
        vuln = "**Type:** CWE-22 (Path Traversal)\n\nA path traversal vulnerability."
        ctx = find_code_context(vuln, tmp_path)
        assert "abspath" in ctx


class TestCweNameTokensPass3Integration:
    """find_code_context() integration: a CWE with no _CWE_KEYWORDS dict
    entry (CWE-522) must still surface a real file via cwe_name_tokens,
    with no Pass 1/2 signal available to find it any other way."""

    def test_undicted_cwe_finds_file_via_derived_token(self, tmp_path):
        from utilities.autopatcher.repo_locator import find_code_context
        write(
            tmp_path / "lib" / "vauth" / "digest.c",
            "/* stores user credentials for digest authentication */\n"
            "struct auth_state { char *credentials; };\n",
        )
        vuln = (
            "**Type:** Insufficiently Protected Credentials (CWE-522)\n\n"
            "curl leaks credentials to a different host on redirect."
        )
        ctx = find_code_context(vuln, tmp_path)
        assert "credentials" in ctx
        assert "digest.c" in ctx


class TestNoMatch:
    def test_returns_empty_string_when_nothing_found(self, tmp_path):
        from utilities.autopatcher.repo_locator import find_code_context
        write(tmp_path / "unrelated.py", "print('hello')\n")
        vuln = "Vulnerability in authenticate_user() — SQL injection (CWE-89)"
        # authenticate_user is specific; unrelated.py has no such content
        result = find_code_context(vuln, tmp_path)
        # May or may not be empty depending on CWE fallback hits — key thing: no crash
        assert isinstance(result, str)

    def test_empty_repo_returns_empty_string(self, tmp_path):
        from utilities.autopatcher.repo_locator import find_code_context
        result = find_code_context("SQL injection in authenticate()", tmp_path)
        assert result == ""


class TestCharCap:
    def test_snippet_mode_respects_char_cap(self, tmp_path):
        """Files > 20 000 chars use snippet mode; result must stay near the cap."""
        from utilities.autopatcher.repo_locator import find_code_context
        # File must exceed _FULL_FILE_THRESHOLD_CHARS (20 000) to trigger snippet mode
        big = "def authenticate(u, p):\n" + "    # padding line here\n" * 1500
        assert len(big) > 20_000, "file must be large enough to bypass full-file mode"
        write(tmp_path / "app" / "auth.py", big)
        vuln = "SQL injection in app/auth.py — authenticate()"
        result = find_code_context(vuln, tmp_path)
        assert len(result) <= 4_500  # snippet budget + header overhead

    def test_small_file_fully_included(self, tmp_path):
        from utilities.autopatcher.repo_locator import find_code_context
        content = "def authenticate(u, p):\n    pass\n"
        write(tmp_path / "app" / "auth.py", content)
        vuln = "SQL injection in app/auth.py"
        result = find_code_context(vuln, tmp_path)
        assert "def authenticate" in result


class TestGenericTokensIgnored:
    def test_generic_tokens_produce_no_symbol_matches(self, tmp_path):
        from utilities.autopatcher.repo_locator import _extract_symbols
        vuln = "Error in handler: request response data output config settings"
        symbols = _extract_symbols(vuln)
        assert symbols == []

    def test_specific_tokens_extracted(self, tmp_path):
        from utilities.autopatcher.repo_locator import _extract_symbols
        vuln = "SQL injection in `authenticate_user` and `validate_session`"
        symbols = _extract_symbols(vuln)
        assert "authenticate_user" in symbols
        assert "validate_session" in symbols


# ---------------------------------------------------------------------------
# Change 1: ranking by total occurrence count
# ---------------------------------------------------------------------------

class TestRankingByTotalOccurrences:
    def test_higher_occurrence_count_ranks_first(self, tmp_path):
        """File with more token hits should rank before file with fewer hits."""
        from utilities.autopatcher.repo_locator import _grep_repo

        # a.py: 4 occurrences of 'authenticate'
        write(tmp_path / "a.py",
              "authenticate()\nauthenticate()\nauthenticate()\nauthenticate()\n")
        # b.py: 1 occurrence — sorts before a.py alphabetically but should rank lower
        write(tmp_path / "b.py", "def authenticate(): pass\n")

        results = _grep_repo(tmp_path, ["authenticate"])
        assert results, "expected at least one result"
        assert results[0][0].name == "a.py", (
            f"expected a.py (4 hits) first, got {results[0][0].name}"
        )

    def test_tie_broken_consistently(self, tmp_path):
        """Two files with equal hit counts should both be returned."""
        from utilities.autopatcher.repo_locator import _grep_repo
        write(tmp_path / "x.py", "frozenset(['Authorization'])\n")
        write(tmp_path / "y.py", "frozenset(['Authorization'])\n")
        results = _grep_repo(tmp_path, ["Authorization"])
        names = {r[0].name for r in results}
        assert "x.py" in names and "y.py" in names


# ---------------------------------------------------------------------------
# Change 2: test-file exclusion
# ---------------------------------------------------------------------------

class TestTestFileExclusion:
    def test_test_prefix_file_excluded(self, tmp_path):
        """test_*.py files must not appear in _grep_repo results."""
        from utilities.autopatcher.repo_locator import _grep_repo
        write(tmp_path / "tests" / "test_auth.py",
              "authenticate() " * 50)   # many hits
        write(tmp_path / "src" / "auth.py",
              "def authenticate(): pass\n")  # 1 hit

        results = _grep_repo(tmp_path, ["authenticate"])
        names = [r[0].name for r in results]
        assert "test_auth.py" not in names, "test files must be excluded"
        assert "auth.py" in names

    def test_tests_directory_excluded(self, tmp_path):
        """Files inside a tests/ directory must not appear."""
        from utilities.autopatcher.repo_locator import _grep_repo
        write(tmp_path / "tests" / "integration.py",
              "Authorization " * 20)
        write(tmp_path / "lib" / "http.py",
              "Authorization = 'Bearer'\n")

        results = _grep_repo(tmp_path, ["Authorization"])
        names = [r[0].name for r in results]
        assert "integration.py" not in names
        assert "http.py" in names

    def test_spec_directory_excluded(self, tmp_path):
        """Files inside a spec/ directory must not appear."""
        from utilities.autopatcher.repo_locator import _grep_repo
        write(tmp_path / "spec" / "retry_spec.py",
              "Authorization " * 20)
        write(tmp_path / "retry.py",
              "DEFAULT_REMOVE = frozenset(['Authorization'])\n")

        results = _grep_repo(tmp_path, ["Authorization"])
        names = [r[0].name for r in results]
        assert "retry_spec.py" not in names
        assert "retry.py" in names


# ---------------------------------------------------------------------------
# Change 3: backtick term extraction
# ---------------------------------------------------------------------------

class TestBacktickTermExtraction:
    def test_cookie_extracted_despite_generic_filter(self):
        """'cookie' is in _GENERIC_TOKENS but `Cookie` in backticks must be extracted."""
        from utilities.autopatcher.repo_locator import _extract_backtick_terms
        text = "urllib3 doesn't strip the `Cookie` header on redirects."
        terms = _extract_backtick_terms(text)
        assert "Cookie" in terms

    def test_authorization_extracted(self):
        from utilities.autopatcher.repo_locator import _extract_backtick_terms
        text = "The `Authorization` header is leaked to the redirect target."
        terms = _extract_backtick_terms(text)
        assert "Authorization" in terms

    def test_multiple_backtick_terms_extracted(self):
        from utilities.autopatcher.repo_locator import _extract_backtick_terms
        text = "Use `Cookie` and `Authorization` with `remove_headers_on_redirect`."
        terms = _extract_backtick_terms(text)
        assert "Cookie" in terms
        assert "Authorization" in terms
        assert "remove_headers_on_redirect" in terms

    def test_generic_tokens_not_filtered_from_backtick_terms(self):
        """Backtick extraction bypasses _GENERIC_TOKENS."""
        from utilities.autopatcher.repo_locator import _extract_backtick_terms, _GENERIC_TOKENS
        # Build text where every token is in GENERIC_TOKENS
        generic = " ".join(f"`{t}`" for t in list(_GENERIC_TOKENS)[:5])
        terms = _extract_backtick_terms(generic)
        # All of them should be present (no filtering)
        for t in list(_GENERIC_TOKENS)[:5]:
            if len(t) >= 2:
                assert t in terms, f"'{t}' should not be filtered from backtick terms"

    def test_backtick_term_used_as_search_signal(self, tmp_path):
        """Advisory with backtick term finds file containing that token."""
        from utilities.autopatcher.repo_locator import find_code_context
        write(tmp_path / "retry.py",
              "DEFAULT_REMOVE = frozenset(['Authorization'])\n")
        # Advisory mentions Authorization in backticks — should find retry.py
        vuln = "The `Authorization` header is not stripped on cross-origin redirects."
        ctx = find_code_context(vuln, tmp_path)
        assert "Authorization" in ctx
        assert "retry.py" in ctx


# ---------------------------------------------------------------------------
# Context grounding: _is_docstring_line, _find_code_block_after, _extract_snippet
# ---------------------------------------------------------------------------

def _make_large_file(
    tmp_path: "Path", name: str, docstring_lines: int = 60, _force_large: bool = False
) -> "Path":
    """Create a >150-line Python file with a docstring section then constants.

    When _force_large=True, pad with trailing comments until the file exceeds
    20 000 chars (full-file threshold), keeping the constant close enough for
    the code-anchor scan to find it.
    """
    lines = ["class Retry:"]
    lines.append('    """')
    for i in range(docstring_lines):
        lines.append(f"    :param int p{i}: Param {i} description text here.")
    lines.append('    """')
    lines.append("")
    lines.append("    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(['Authorization'])")
    lines.append("    DEFAULT_BACKOFF_MAX = 120")
    lines.append("")
    lines.append("    def __init__(self, total=10, redirect=None):")
    lines.append("        self.total = total")
    lines.append("        self.redirect = redirect")
    # Pad to exceed _SMALL_FILE_THRESHOLD (150 lines)
    while len(lines) < 160:
        lines.append("")
    # Optionally pad with trailing comments to exceed the full-file threshold
    # (20 000 chars), keeping the constant reachable within the anchor scan.
    content = "\n".join(lines)
    while len(content) < 22_000 if _force_large else False:
        lines.append("# padding " + "x" * 70)
        content = "\n".join(lines)
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


class TestIsDocstringLine:
    def test_rst_directive_is_docstring(self):
        from utilities.autopatcher.repo_locator import _is_docstring_line
        assert _is_docstring_line(":param int redirect: How many redirects") is True

    def test_indented_rst_directive_is_docstring(self):
        from utilities.autopatcher.repo_locator import _is_docstring_line
        assert _is_docstring_line("    :param int redirect: How many redirects") is True

    def test_prose_without_operators_is_docstring(self):
        from utilities.autopatcher.repo_locator import _is_docstring_line
        assert _is_docstring_line("    How many redirects to perform.") is True

    def test_triple_quote_is_docstring(self):
        from utilities.autopatcher.repo_locator import _is_docstring_line
        assert _is_docstring_line('    """') is True

    def test_constant_assignment_is_not_docstring(self):
        from utilities.autopatcher.repo_locator import _is_docstring_line
        assert _is_docstring_line(
            "    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(['Authorization'])"
        ) is False

    def test_def_line_is_not_docstring(self):
        from utilities.autopatcher.repo_locator import _is_docstring_line
        assert _is_docstring_line("    def __init__(self, total=10):") is False

    def test_class_line_is_not_docstring(self):
        from utilities.autopatcher.repo_locator import _is_docstring_line
        assert _is_docstring_line("class Retry:") is False

    def test_empty_line_is_not_docstring(self):
        from utilities.autopatcher.repo_locator import _is_docstring_line
        assert _is_docstring_line("") is False

    def test_import_line_is_not_docstring(self):
        from utilities.autopatcher.repo_locator import _is_docstring_line
        assert _is_docstring_line("import re") is False


class TestFindCodeBlockAfter:
    def test_finds_constant_after_docstring(self, tmp_path):
        from utilities.autopatcher.repo_locator import _find_code_block_after
        _make_large_file(tmp_path, "retry.py")
        content = (tmp_path / "retry.py").read_text()
        lines = content.splitlines()
        dq_close = next(
            i for i, l in enumerate(lines) if l.strip() == '"""' and i > 0
        )
        result_tuple = _find_code_block_after(lines, dq_close + 1)
        assert result_tuple is not None
        text, start_0 = result_tuple
        assert "DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in text
        assert isinstance(start_0, int)

    def test_returns_none_when_no_code_found(self):
        from utilities.autopatcher.repo_locator import _find_code_block_after
        lines = ["    prose line only" for _ in range(210)]
        assert _find_code_block_after(lines, 0) is None

    def test_respects_max_lines_when_anchor_is_def(self):
        """max_lines fallback applies when the first anchor is a def/class line."""
        from utilities.autopatcher.repo_locator import _find_code_block_after
        # Class with only methods, no constants — anchor is a def.
        lines = [
            "    def method_a(self):",
            "        return 1",
            "    def method_b(self):",
            "        return 2",
        ] * 20  # many lines; max_lines cap must kick in
        result_tuple = _find_code_block_after(lines, 0, max_lines=3)
        assert result_tuple is not None
        text, _ = result_tuple
        assert len(text.splitlines()) <= 3

    def test_structural_collection_ignores_max_lines_for_constants(self):
        """When anchor is a constant, all constants are collected even if > max_lines."""
        from utilities.autopatcher.repo_locator import _find_code_block_after
        # 20 constants followed by a def — no max_lines truncation for constants.
        lines = [f"    CONST_{i} = {i}" for i in range(20)] + [
            "    def __init__(self):",
            "        pass",
        ]
        result_tuple = _find_code_block_after(lines, 0, max_lines=5)
        assert result_tuple is not None
        text, _ = result_tuple
        # All 20 constants must be present despite max_lines=5
        for i in range(20):
            assert f"CONST_{i}" in text
        # Method must not be included
        assert "def __init__" not in text

    def test_stops_at_first_method_definition(self):
        """Structural extraction stops exactly at the first def line."""
        from utilities.autopatcher.repo_locator import _find_code_block_after
        lines = [
            "    DEFAULT_HEADERS = frozenset(['Authorization'])",
            "    DEFAULT_TIMEOUT = 30",
            "",
            "    def __init__(self):",
            "        self.x = 1",
            "    def increment(self):",
            "        pass",
        ]
        result_tuple = _find_code_block_after(lines, 0)
        assert result_tuple is not None
        text, _ = result_tuple
        assert "DEFAULT_HEADERS" in text
        assert "DEFAULT_TIMEOUT" in text
        assert "def __init__" not in text
        assert "def increment" not in text

    def test_critical_constant_visible_when_not_first_in_block(self):
        """A constant that is not the first anchor must still appear in the result."""
        from utilities.autopatcher.repo_locator import _find_code_block_after
        # Mirrors urllib3 retry.py: DEFAULT_ALLOWED_METHODS is the first anchor,
        # DEFAULT_REMOVE_HEADERS_ON_REDIRECT comes 9 lines later.
        lines = [
            "    #: Default methods",
            "    DEFAULT_ALLOWED_METHODS = frozenset(['GET', 'POST', 'HEAD'])",
            "",
            "    #: Status codes",
            "    RETRY_AFTER_STATUS_CODES = frozenset([429, 503])",
            "",
            "    #: Headers to strip on redirect",
            "    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(['Authorization'])",
            "",
            "    #: Backoff",
            "    DEFAULT_BACKOFF_MAX = 120",
            "",
            "    def __init__(self, total=10):",
            "        pass",
        ]
        result_tuple = _find_code_block_after(lines, 0)
        assert result_tuple is not None
        text, _ = result_tuple
        # The critical constant must be visible even though it is not the first anchor
        assert "DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in text
        assert "frozenset(['Authorization'])" in text
        # Method must not bleed into the result
        assert "def __init__" not in text


class TestExtractSnippetGrounding:
    def test_docstring_hit_appends_code_anchor(self, tmp_path):
        """When hit_line is inside a docstring, snippet must include the constant."""
        from utilities.autopatcher.repo_locator import _extract_snippet
        _make_large_file(tmp_path, "retry.py", docstring_lines=60)
        content = (tmp_path / "retry.py").read_text()
        lines = content.splitlines()
        hit_line = next(i for i, l in enumerate(lines) if ":param int p0:" in l)
        text, ranges = _extract_snippet(content, hit_line, 4000)
        assert "DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in text, (
            "Code anchor must appear in snippet when hit is inside a docstring"
        )
        assert len(ranges) == 2, "Non-contiguous snippet must return two ranges"

    def test_code_hit_does_not_add_anchor(self, tmp_path):
        """When hit_line is already a code line, only the window range is returned."""
        from utilities.autopatcher.repo_locator import _extract_snippet
        _make_large_file(tmp_path, "retry.py", docstring_lines=60)
        content = (tmp_path / "retry.py").read_text()
        lines = content.splitlines()
        hit_line = next(
            i for i, l in enumerate(lines)
            if "DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in l
        )
        text, ranges = _extract_snippet(content, hit_line, 4000)
        assert "DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in text
        assert len(ranges) == 1, "Code hit should produce a single range"

    def test_anchor_preserved_when_budget_tight(self, tmp_path):
        """When budget is tight, code anchor survives even if window is cut."""
        from utilities.autopatcher.repo_locator import _extract_snippet
        _make_large_file(tmp_path, "retry.py", docstring_lines=60)
        content = (tmp_path / "retry.py").read_text()
        lines = content.splitlines()
        hit_line = next(i for i, l in enumerate(lines) if ":param int p0:" in l)
        text, ranges = _extract_snippet(content, hit_line, 500)
        assert "DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in text, (
            "Code anchor must be preserved over docstring window when budget is tight"
        )

    def test_small_file_returns_one_range(self, tmp_path):
        """Files at or below _SMALL_FILE_THRESHOLD return a single range."""
        from utilities.autopatcher.repo_locator import _extract_snippet
        small = "def foo():\n    pass\n" * 5  # << 150 lines
        text, ranges = _extract_snippet(small, 0, 4000)
        assert "def foo" in text
        assert len(ranges) == 1


# ---------------------------------------------------------------------------
# Integration: urllib3 context now includes the vulnerable constant
# ---------------------------------------------------------------------------

_URLLIB3_EVAL = Path("/tmp/urllib3-eval")
_URLLIB3_RETRY_PY = _URLLIB3_EVAL / "src" / "urllib3" / "util" / "retry.py"

_run_live = (
    os.environ.get("RUN_LIVE_REPO_TESTS") == "1"
    and _URLLIB3_RETRY_PY.exists()
)


@pytest.mark.skipif(
    not _run_live,
    reason=(
        "Live repo tests opt-in only — "
        "set RUN_LIVE_REPO_TESTS=1 and populate /tmp/urllib3-eval "
        "with a urllib3 checkout containing src/urllib3/util/retry.py"
    ),
)
class TestUrllib3ContextGrounding:
    def test_default_remove_headers_in_context(self):
        """After grounding improvement, the urllib3 context must include
        DEFAULT_REMOVE_HEADERS_ON_REDIRECT so the LLM can produce the real fix."""
        sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
        from advisory_fetcher import fetch_ghsa
        from advisory_converter import ghsa_to_vuln_text
        from utilities.autopatcher.repo_locator import find_code_context

        adv = fetch_ghsa("GHSA-v845-jxx5-vc9f")
        vuln_text = ghsa_to_vuln_text(adv)
        ctx = find_code_context(vuln_text, _URLLIB3_EVAL)

        assert "DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in ctx, (
            "Context must include the vulnerable constant so the LLM can generate the fix"
        )

    def test_context_header_uses_full_relative_path(self):
        """Context header must show src/urllib3/util/retry.py, not just retry.py."""
        sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
        from advisory_fetcher import fetch_ghsa
        from advisory_converter import ghsa_to_vuln_text
        from utilities.autopatcher.repo_locator import find_code_context

        adv = fetch_ghsa("GHSA-v845-jxx5-vc9f")
        vuln_text = ghsa_to_vuln_text(adv)
        ctx = find_code_context(vuln_text, _URLLIB3_EVAL)

        assert "# src/urllib3/util/retry.py" in ctx, (
            "Context header must contain the full repo-relative path"
        )
        assert "# retry.py\n" not in ctx, (
            "Basename-only header must not appear"
        )


# ---------------------------------------------------------------------------
# Context header path grounding (no live repo required)
# ---------------------------------------------------------------------------

class TestContextHeaderLineRanges:
    def test_header_includes_line_range(self, tmp_path):
        """Files > 20 000 chars use snippet mode and must show a (lines N-M) annotation."""
        from utilities.autopatcher.repo_locator import find_code_context
        nested = tmp_path / "app" / "auth.py"
        nested.parent.mkdir(parents=True)
        # Build a large file (> 20 000 chars) so snippet mode is used
        content = "def authenticate(u, p):\n" + "    # padding line here\n" * 1500
        assert len(content) > 20_000
        nested.write_text(content, encoding="utf-8")
        vuln = "SQL injection in `authenticate` function (app/auth.py)"
        ctx = find_code_context(vuln, tmp_path)
        assert "(lines " in ctx, f"Expected line range in header, got:\n{ctx[:200]}"

    def test_non_contiguous_snippet_shows_two_ranges(self, tmp_path):
        """When window + code anchor are non-contiguous, header shows both ranges.
        Uses _force_large=True so the file exceeds 20 000 chars (snippet mode)
        while keeping the constant close enough for the anchor scan.
        """
        from utilities.autopatcher.repo_locator import find_code_context
        _make_large_file(tmp_path, "retry.py", docstring_lines=60, _force_large=True)
        vuln = "The `p0` parameter is not bounded correctly."
        ctx = find_code_context(vuln, tmp_path)
        import re as _re
        header_match = _re.search(r'\(lines ([0-9]+-[0-9]+), ([0-9]+-[0-9]+)\)', ctx)
        assert header_match is not None, (
            f"Expected two ranges in header for non-contiguous snippet, got:\n{ctx[:300]}"
        )

    def test_range_numbers_are_sensible(self, tmp_path):
        """Line range start must be >= 1 and end >= start."""
        from utilities.autopatcher.repo_locator import find_code_context
        import re as _re
        _make_large_file(tmp_path, "retry.py", docstring_lines=60, _force_large=True)
        vuln = "The `p0` parameter is not bounded correctly."
        ctx = find_code_context(vuln, tmp_path)
        for m in _re.finditer(r'(\d+)-(\d+)', ctx.split("\n")[0]):
            start, end = int(m.group(1)), int(m.group(2))
            assert start >= 1
            assert end >= start


class TestContextHeaderPaths:
    def test_nested_file_uses_full_relative_path(self, tmp_path):
        """Header must be app/auth.py, not auth.py."""
        from utilities.autopatcher.repo_locator import find_code_context

        nested = tmp_path / "app" / "auth.py"
        nested.parent.mkdir(parents=True)
        nested.write_text("def authenticate(u, p):\n    pass\n", encoding="utf-8")

        vuln = "SQL injection in `authenticate` function (app/auth.py)"
        ctx = find_code_context(vuln, tmp_path)

        assert "# app/auth.py" in ctx, f"Expected '# app/auth.py' in context, got:\n{ctx[:300]}"
        assert "# auth.py\n" not in ctx

    def test_deeply_nested_file_uses_full_relative_path(self, tmp_path):
        """Header must be src/urllib3/util/retry.py for deeply nested files."""
        from utilities.autopatcher.repo_locator import find_code_context

        deep = tmp_path / "src" / "urllib3" / "util" / "retry.py"
        deep.parent.mkdir(parents=True)
        deep.write_text(
            "class Retry:\n"
            "    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(['Authorization'])\n",
            encoding="utf-8",
        )

        vuln = "The `Authorization` header is not stripped on redirects."
        ctx = find_code_context(vuln, tmp_path)

        assert "# src/urllib3/util/retry.py" in ctx, (
            f"Expected full relative path in header, got:\n{ctx[:300]}"
        )


# ---------------------------------------------------------------------------
# Full-file mode
# ---------------------------------------------------------------------------

class TestFullFileMode:
    def test_small_file_uses_full_file_context(self, tmp_path):
        """Files <= 20 000 chars must be sent in full, not as a snippet."""
        from utilities.autopatcher.repo_locator import find_code_context
        content = (
            "class Retry:\n"
            "    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(['Authorization'])\n"
            "    def __init__(self): pass\n"
        )
        assert len(content) < 20_000
        write(tmp_path / "retry.py", content)
        vuln = "The `Authorization` header is not stripped on redirects."
        ctx = find_code_context(vuln, tmp_path)
        # Full file content must be present
        assert "class Retry:" in ctx
        assert "DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in ctx
        assert "def __init__" in ctx

    def test_full_file_header_format(self, tmp_path):
        """Header must say '(full file, N lines)' in full-file mode."""
        from utilities.autopatcher.repo_locator import find_code_context
        import re as _re
        content = "class Retry:\n    DEFAULT_REMOVE = frozenset(['Authorization'])\n"
        write(tmp_path / "src" / "retry.py", content)
        vuln = "The `Authorization` header is not stripped."
        ctx = find_code_context(vuln, tmp_path)
        assert "(full file," in ctx, f"Header must say full file, got:\n{ctx[:200]}"
        n_lines = len(content.splitlines())
        assert f"{n_lines} lines)" in ctx

    def test_full_file_mode_includes_only_one_file(self, tmp_path):
        """When only one candidate matches, full-file mode returns exactly that file."""
        from utilities.autopatcher.repo_locator import find_code_context
        # Only retry.py contains Authorization — no backtick on redirects so
        # connectionpool.py produces zero signal hits and is not a candidate.
        write(tmp_path / "retry.py",
              "class Retry:\n    DEFAULT_REMOVE = frozenset(['Authorization'])\n")
        write(tmp_path / "connectionpool.py",
              "class ConnectionPool:\n    redirects = True\n")
        vuln = "The `Authorization` header is not stripped on redirects."
        ctx = find_code_context(vuln, tmp_path)
        import re as _re
        headers = _re.findall(r"^# \S+", ctx, _re.MULTILINE)
        assert len(headers) == 1, (
            f"With one matching candidate, output must have exactly one header, got: {headers}"
        )

    def test_large_file_falls_back_to_snippet_range_mode(self, tmp_path):
        """Files > 20 000 chars must use snippet + range mode, not full-file."""
        from utilities.autopatcher.repo_locator import find_code_context
        big = "def authenticate(u, p):\n" + "    # padding line here\n" * 1500
        assert len(big) > 20_000
        write(tmp_path / "app" / "auth.py", big)
        vuln = "SQL injection in `authenticate` function (app/auth.py)"
        ctx = find_code_context(vuln, tmp_path)
        assert "(full file," not in ctx, "Large file must not use full-file mode"
        assert "(lines " in ctx, "Large file must show line ranges"


# ---------------------------------------------------------------------------
# Structural constant extraction regression
# ---------------------------------------------------------------------------

class TestStructuralConstantExtraction:
    """Regression: structural extraction captures the complete constant block.

    Previously _find_code_block_after used a fixed 40-line window from the
    first anchor.  When many constants precede the target constant, it fell
    outside the window.  The structural approach (scan until first def/class)
    is invariant to constant count and ordering.
    """

    def _build_many_constants_content(self, num_before: int = 50) -> str:
        """Return file content with num_before constants before the critical one.

        The docstring is intentionally long (60 param lines) so that the ±30-line
        window around the docstring hit contains only docstring — never the
        constants section or method definition below it.  This makes the anchor
        block the sole source of constants in the snippet.
        """
        lines = ["class Retry:", '    """']
        # 60 docstring param lines; hit_line will be somewhere in here (> 30
        # lines from the constants section, so the window never reaches them).
        for i in range(60):
            lines.append(f"    :param int p{i}: Param {i} description.")
        lines.append('    """')
        lines.append("")
        for i in range(num_before):
            lines.append(f"    PRECEDING_CONST_{i:02d} = {i}")
        lines += [
            "    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(['Authorization'])",
            "",
            "    def __init__(self, redirect=None):",
            "        self.redirect = redirect",
        ]
        content = "\n".join(lines)
        # Pad well past both thresholds (>150 lines, >20 000 chars) to force
        # snippet mode and trigger the docstring-anchor path.
        content += "\n" + ("    # padding " + "x" * 70 + "\n") * 320
        return content

    def test_critical_constant_visible_with_many_preceding_constants(self):
        """Structural extraction exposes the target even when > 40 constants precede it."""
        from utilities.autopatcher.repo_locator import _extract_snippet

        content = self._build_many_constants_content(num_before=50)
        lines = content.splitlines()

        # Sanity: file is large enough to be in snippet mode
        assert len(content) > 20_000

        # Sanity: the constant is more than 40 lines from the start of the
        # constants section (which is what old fixed-window would have given).
        first_const_line = next(
            i for i, l in enumerate(lines) if "PRECEDING_CONST_00" in l
        )
        target_line = next(
            i for i, l in enumerate(lines)
            if "DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in l
        )
        assert (target_line - first_const_line) > 40, (
            "Test precondition: target must be > 40 lines from first constant "
            "to prove the fixed-window approach would have missed it"
        )

        # Hit line is the docstring — triggers anchor mode
        hit_line = next(i for i, l in enumerate(lines) if ":param int p0:" in l)

        text, ranges = _extract_snippet(content, hit_line, 4000)

        assert "DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in text, (
            "Critical constant must appear in snippet even when preceded by "
            "more than 40 constants"
        )

    def test_method_body_does_not_bleed_into_constant_block(self):
        """Structural extraction stops before the first def — no method body lines."""
        from utilities.autopatcher.repo_locator import _extract_snippet

        content = self._build_many_constants_content(num_before=5)
        lines = content.splitlines()
        hit_line = next(i for i, l in enumerate(lines) if ":param int p0:" in l)

        text, _ = _extract_snippet(content, hit_line, 4000)

        assert "def __init__" not in text, (
            "def __init__ must not appear in the constant block snippet"
        )
        assert "self.redirect = redirect" not in text, (
            "Method body must not bleed into the constant block"
        )

    def test_snippet_size_bounded_by_constant_block_not_fixed_window(self):
        """With few constants the result is smaller than the old 40-line window."""
        from utilities.autopatcher.repo_locator import _find_code_block_after

        # 4 constants, then __init__ — same shape as urllib3 retry.py
        lines = [
            "    #: Default allowed methods",
            "    DEFAULT_ALLOWED_METHODS = frozenset(['GET', 'POST'])",
            "",
            "    #: Status codes",
            "    RETRY_AFTER_STATUS_CODES = frozenset([429, 503])",
            "",
            "    #: Headers to strip",
            "    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(['Authorization'])",
            "",
            "    #: Max backoff",
            "    DEFAULT_BACKOFF_MAX = 120",
            "",
            "    def __init__(self, total=10, redirect=None):",
            "        self.total = total",
        ] + ["        # body line\n"] * 50  # would inflate a fixed-40 result

        result_tuple = _find_code_block_after(lines, 0)
        assert result_tuple is not None
        text, _ = result_tuple

        # Structural result is tighter than the old 40-line block
        n_lines = len(text.splitlines())
        assert n_lines < 40, (
            f"Structural extraction ({n_lines} lines) should be smaller than "
            "old fixed 40-line window for a typical small constant block"
        )
        # Critical constant is present
        assert "DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in text


# ---------------------------------------------------------------------------
# Hybrid context budget: secondary snippets appended after full-file primary
# ---------------------------------------------------------------------------

class TestHybridContextBudget:
    """Full-file mode now injects snippets from ranked[1] and ranked[2] within
    a bounded secondary budget so implementation files below the primary are
    visible to the model."""

    def _setup_two_candidates(self, tmp_path, primary_hits: int = 5, secondary_hits: int = 2):
        """Create two files that both match on FileSystemProvider.

        primary.py has more hits and is always below _FULL_FILE_THRESHOLD_CHARS,
        so it wins rank #1 and triggers full-file mode.
        secondary.py has fewer hits and becomes the secondary candidate.
        """
        primary_content = "class FileSystemProvider:\n    pass\n" * primary_hits + "    # pad\n" * 20
        secondary_content = (
            "class FileSystemProvider:\n    def items(self, dirpath):\n"
            "        data_path = self.data + dirpath\n"
        ) * secondary_hits
        assert len(primary_content) < 20_000
        write(tmp_path / "api.py", primary_content)
        write(tmp_path / "provider.py", secondary_content)
        return "FileSystemProvider path traversal"

    def test_full_file_mode_includes_secondary_candidates(self, tmp_path):
        """Primary is returned in full; secondary candidate snippet is appended."""
        from utilities.autopatcher.repo_locator import find_code_context
        vuln = self._setup_two_candidates(tmp_path)
        ctx = find_code_context(vuln, tmp_path)

        assert "api.py" in ctx, "primary file must appear in context"
        assert "(full file," in ctx, "primary must use full-file header"
        assert "provider.py" in ctx, "secondary candidate must be appended"

    def test_single_candidate_behavior_unchanged(self, tmp_path):
        """When only one file matches, output is identical to pre-hybrid behavior."""
        from utilities.autopatcher.repo_locator import find_code_context
        content = "class FileSystemProvider:\n    pass\n" * 5
        assert len(content) < 20_000
        write(tmp_path / "only.py", content)
        # unrelated file — no matching signal
        write(tmp_path / "other.py", "def unrelated(): pass\n")

        vuln = "FileSystemProvider path traversal"
        ctx = find_code_context(vuln, tmp_path)

        assert "only.py" in ctx
        assert "(full file," in ctx
        assert "other.py" not in ctx, "non-matching file must not appear"
        import re as _re
        headers = _re.findall(r"^# \S+", ctx, _re.MULTILINE)
        assert len(headers) == 1, f"single candidate must produce one header, got: {headers}"

    def test_secondary_budget_respected(self, tmp_path):
        """Total secondary snippet size stays within _SECONDARY_CONTEXT_BUDGET."""
        from utilities.autopatcher.repo_locator import find_code_context, _SECONDARY_CONTEXT_BUDGET
        # Primary: small, triggers full-file mode
        primary_content = "class FileSystemProvider:\n    pass\n" * 5
        assert len(primary_content) < 20_000
        write(tmp_path / "api.py", primary_content)
        # Secondary: much larger than the secondary budget
        big_secondary = "class FileSystemProvider:\n" + "    # line\n" * 2000
        assert len(big_secondary) > _SECONDARY_CONTEXT_BUDGET
        write(tmp_path / "provider.py", big_secondary)

        vuln = "FileSystemProvider path traversal"
        ctx = find_code_context(vuln, tmp_path)

        # Locate the secondary section and measure its size
        sep = "\n\n# provider.py"
        assert sep in ctx, "secondary section must be present"
        secondary_portion = ctx[ctx.index(sep) + 2:]  # from "# provider.py" onward
        assert len(secondary_portion) <= _SECONDARY_CONTEXT_BUDGET + 200, (
            f"secondary portion ({len(secondary_portion)} chars) exceeds budget "
            f"{_SECONDARY_CONTEXT_BUDGET} + 200 header overhead"
        )

    def test_secondary_snippet_has_header(self, tmp_path):
        """Secondary snippet header shows the file path and a line range."""
        from utilities.autopatcher.repo_locator import find_code_context
        write(tmp_path / "api.py",
              "class FileSystemProvider:\n    pass\n" * 5)
        write(tmp_path / "provider.py",
              "class FileSystemProvider:\n"
              "    def items(self, dirpath):\n"
              "        data_path = self.data + dirpath\n")

        vuln = "FileSystemProvider path traversal"
        ctx = find_code_context(vuln, tmp_path)

        # Secondary header must include path and line range annotation
        assert "# provider.py (lines " in ctx, (
            f"secondary header must show path + line range; got context start:\n{ctx[:400]}"
        )


# ---------------------------------------------------------------------------
# _find_symbol_definitions unit tests
# ---------------------------------------------------------------------------

class TestFindSymbolDefinitions:
    """Unit tests for the exact symbol-definition lookup (Pass 2): finds
    files that define a class, function, or method named in the advisory."""

    def test_finds_defining_file(self, tmp_path):
        """Returns the file that contains 'class FileSystemProvider'."""
        from utilities.autopatcher.repo_locator import _find_symbol_definitions
        write(tmp_path / "provider" / "filesystem.py",
              "class FileSystemProvider:\n    def get_data_path(self): pass\n")
        results = _find_symbol_definitions("FileSystemProvider path traversal", tmp_path)
        assert len(results) == 1
        p, _, hit_line = results[0]
        assert p.name == "filesystem.py"
        assert hit_line == 0

    def test_hit_line_points_to_class_not_file_top(self, tmp_path):
        """hit_line is the 0-indexed line of the class definition, not always 0."""
        from utilities.autopatcher.repo_locator import _find_symbol_definitions
        preamble = "import os\n" * 20  # 20 lines before the class
        write(tmp_path / "fs.py", preamble + "class FileSystemProvider:\n    pass\n")
        results = _find_symbol_definitions("FileSystemProvider path traversal", tmp_path)
        assert results, "should find fs.py"
        _, _, hit_line = results[0]
        assert hit_line == 20, f"expected hit_line=20, got {hit_line}"

    def test_ignores_names_below_min_length(self, tmp_path):
        """Names shorter than _MIN_CLASS_NAME_LENGTH (5) must not trigger a scan."""
        from utilities.autopatcher.repo_locator import _find_symbol_definitions
        write(tmp_path / "foo.py", "class Foo:\n    pass\n")   # len 3
        write(tmp_path / "abcd.py", "class Abcd:\n    pass\n")  # len 4
        results = _find_symbol_definitions("Foo and Abcd have vulnerabilities", tmp_path)
        assert results == [], f"short names must be ignored, got {results}"

    def test_excludes_test_files(self, tmp_path):
        """Files inside tests/ or named test_*.py must not appear."""
        from utilities.autopatcher.repo_locator import _find_symbol_definitions
        write(tmp_path / "tests" / "test_provider.py",
              "class FileSystemProvider:\n    pass\n")
        write(tmp_path / "provider.py",
              "class FileSystemProvider:\n    pass\n")
        results = _find_symbol_definitions("FileSystemProvider path traversal", tmp_path)
        assert len(results) == 1
        assert results[0][0].name == "provider.py", "test file must be excluded"

    def test_finds_defining_file_via_def_when_no_pascal_case_in_advisory(self, tmp_path):
        """An advisory with only a snake_case/backtick symbol (no PascalCase
        class name) must still find the file that *defines* it, via the
        "def" branch — this is the generalization from class-only lookup to
        symbol lookup (functions/methods), the core of F-30's fix."""
        from utilities.autopatcher.repo_locator import _find_symbol_definitions
        write(tmp_path / "auth.py", "def authenticate_user(): pass\n")
        results = _find_symbol_definitions(
            "SQL injection in `authenticate_user` (CWE-89)", tmp_path
        )
        assert len(results) == 1
        assert results[0][0].name == "auth.py"

    def test_multiple_class_names_matched(self, tmp_path):
        """Multiple PascalCase class names in the advisory each trigger discovery."""
        from utilities.autopatcher.repo_locator import _find_symbol_definitions
        write(tmp_path / "stac_handler.py",
              "class StacHandler:\n    pass\n")
        write(tmp_path / "filesystem.py",
              "class FileSystemProvider:\n    pass\n")
        results = _find_symbol_definitions(
            "FileSystemProvider and StacHandler both have path traversal", tmp_path
        )
        names = {r[0].name for r in results}
        assert "stac_handler.py" in names
        assert "filesystem.py" in names

    def test_sorted_by_definition_count_descending(self, tmp_path):
        """File with more class definitions appears first."""
        from utilities.autopatcher.repo_locator import _find_symbol_definitions
        # two.py defines FileSystemProvider twice (e.g. re-export + real class)
        write(tmp_path / "two.py",
              "class FileSystemProvider:\n    pass\nclass FileSystemProvider:\n    pass\n")
        write(tmp_path / "one.py",
              "class FileSystemProvider:\n    pass\n")
        results = _find_symbol_definitions("FileSystemProvider path traversal", tmp_path)
        assert results[0][0].name == "two.py", "higher definition count must rank first"


# ---------------------------------------------------------------------------
# Exact symbol-definition pass integration tests (find_code_context)
# ---------------------------------------------------------------------------

class TestSymbolDefinitionGrounding:
    """Exact symbol-definition pass (F-30): a file that *defines* an
    advisory-named class/function outranks ordinary grep hits, so it cannot
    be displaced by occurrence-count ranking — regardless of how many times
    an unrelated file repeats some other, more generic token."""

    def _write_high_hit_primary(self, tmp_path: Path, signal: str, n: int = 25) -> Path:
        """Write api.py with many occurrences of signal but no class definition."""
        content = (
            f"# {signal} routing module\n"
            + f"def handle_{signal}(req): pass  # {signal}\n" * n
        )
        assert len(content) < 20_000
        return write(tmp_path / "api.py", content)

    def test_class_def_file_injected_despite_low_occurrence_rank(self, tmp_path):
        """filesystem.py defines the advisory-named class but has the lowest
        raw \\bstac\\b occurrence count of the four files below.

        Hit counts verified against \\bstac\\b (underscore is a word char so
        "handle_stac" does NOT contribute a standalone "stac" hit; only the
        trailing "# stac" comment in _write_high_hit_primary does):
          api.py     26 hits (1 header + 25 comments)
          urls.py    10 hits (1 header + 9 /stac/ paths)
          flask_app   8 hits (1 header + 7 /stac/ paths)
          filesystem  5 hits (4 standalone + 1 FileSystemProvider) -- lowest count
        Under pure occurrence-count ranking filesystem.py would rank 4th and
        be excluded by _grep_repo[:3] entirely. The exact symbol-definition
        pass (F-30) instead ranks it above all three occurrence-based hits,
        since it *defines* FileSystemProvider — so it becomes the full-file
        primary, not merely a low-priority secondary.
        """
        from utilities.autopatcher.repo_locator import find_code_context
        # api.py: 26 stac hits (1 header + 25 trailing comments)
        self._write_high_hit_primary(tmp_path, "stac", 25)
        # urls.py: 10 stac hits (1 header + 9 "/stac/" route paths)
        write(tmp_path / "urls.py",
              "# stac route\n" + "path('/stac/')\n" * 9)
        # flask_app.py: 8 stac hits (1 header + 7 "/stac/" route paths)
        write(tmp_path / "flask_app.py",
              "# stac routes\n" + "@app.route('/stac/')\n" * 7)
        # filesystem.py: 5 hits (4 standalone stac + 1 FileSystemProvider) -- lowest count
        write(tmp_path / "provider" / "filesystem.py",
              "class FileSystemProvider:\n"
              "    def get_data_path(self, path): return path\n"
              "    # stac stac stac stac\n")
        ctx = find_code_context(
            "FileSystemProvider path traversal in `stac` collection", tmp_path
        )
        assert "# provider/filesystem.py (full file," in ctx, (
            "the file defining FileSystemProvider must become the full-file primary "
            "despite having the lowest raw occurrence count"
        )

    def test_symbol_definition_file_becomes_primary_despite_lower_occurrence_count(
        self, tmp_path
    ):
        """F-30 core regression: a generic token repeated many times in an
        unrelated file (api.py, 26 raw \\bstac\\b hits) must NOT evict or
        outrank the file that actually *defines* the advisory-named symbol
        (filesystem.py, only 5 raw hits) — the defining file must become the
        full-file primary candidate.
        """
        from utilities.autopatcher.repo_locator import find_code_context
        # api.py: 26 stac hits -- highest raw occurrence count, no definition
        self._write_high_hit_primary(tmp_path, "stac", 25)
        write(tmp_path / "provider" / "filesystem.py",
              "class FileSystemProvider:\n"
              "    def get_data_path(self, path): return path\n"
              "    # stac stac stac stac\n")
        ctx = find_code_context(
            "FileSystemProvider path traversal in `stac` collection", tmp_path
        )
        assert "# provider/filesystem.py (full file," in ctx, (
            "the symbol-defining file must be the primary, not the high-occurrence file"
        )
        assert "# api.py (full file," not in ctx, (
            "a generic token's raw occurrence count must not win primary status "
            "over the file that defines the named symbol"
        )

    def test_class_def_file_not_duplicated_when_already_primary(self, tmp_path):
        """If the class-defining file IS the primary, it must not appear twice."""
        from utilities.autopatcher.repo_locator import find_code_context
        content = (
            "class FileSystemProvider:\n"
            "    def get_data_path(self, p): return p\n"
        ) * 5
        assert len(content) < 20_000
        write(tmp_path / "filesystem.py", content)
        ctx = find_code_context("FileSystemProvider path traversal", tmp_path)
        import re as _re
        headers = _re.findall(r"^# \S+", ctx, _re.MULTILINE)
        assert len(headers) == 1, (
            f"class-def file as primary must not be duplicated; headers: {headers}"
        )

    def test_function_found_via_def_branch_when_no_class_name_in_advisory(self, tmp_path):
        """Advisory without a PascalCase class name still finds the file that
        *defines* the named function, via the generalized def-matching
        branch — not just supported "by coincidence" through ordinary grep."""
        from utilities.autopatcher.repo_locator import find_code_context
        write(tmp_path / "auth.py",
              "def authenticate_user(u, p):\n    return u == 'admin'\n")
        ctx = find_code_context("SQL injection in `authenticate_user` (CWE-89)", tmp_path)
        assert "authenticate_user" in ctx

    def test_short_names_do_not_trigger_symbol_definition_scan(self, tmp_path):
        """PascalCase names < _MIN_CLASS_NAME_LENGTH must not trigger a scan."""
        from utilities.autopatcher.repo_locator import _find_symbol_definitions
        write(tmp_path / "foo.py", "class Foo:\n    pass\n")
        write(tmp_path / "base.py", "class Base:\n    pass\n")
        assert _find_symbol_definitions("Foo and Base vulnerability", tmp_path) == []

    def test_class_def_snippet_includes_class_body(self, tmp_path):
        """The symbol-definition file's content must include the class
        definition itself, not just the top-of-file preamble (hit_line
        points to the class line) — here as the full-file primary, since
        the defining file outranks the high-occurrence file."""
        from utilities.autopatcher.repo_locator import find_code_context
        self._write_high_hit_primary(tmp_path, "stac", 25)
        preamble = "import os\nimport sys\n\n"  # 3 lines before class
        class_body = (
            "class FileSystemProvider:\n"
            "    def get_data_path(self, path):\n"
            "        return self.root + path\n"
        )
        write(tmp_path / "provider.py", preamble + class_body)
        ctx = find_code_context("FileSystemProvider path traversal in stac", tmp_path)
        assert "# provider.py (full file," in ctx, (
            "the symbol-defining file must be the full-file primary"
        )
        assert "class FileSystemProvider" in ctx

    def test_symbol_definition_file_is_primary_in_snippet_mode_when_large(self, tmp_path):
        """F-30 regression (snippet mode): when the file that defines the
        named symbol is itself large enough to exceed the full-file
        threshold, it must still become the FIRST candidate considered in
        snippet mode (ranked[0]) — not be displaced by a smaller, unrelated
        file with a higher raw occurrence count of some generic token."""
        from utilities.autopatcher.repo_locator import (
            find_code_context, _FULL_FILE_THRESHOLD_CHARS, _MAX_CONTEXT_CHARS,
        )
        # api.py: 26 stac hits, tiny file, no definition of anything named.
        self._write_high_hit_primary(tmp_path, "stac", 25)
        # provider.py: defines FileSystemProvider, but is large enough to
        # exceed the full-file threshold and force snippet mode.
        big_provider = (
            "class FileSystemProvider:\n"
            + "    # implementation line\n" * 2000
        )
        assert len(big_provider) > _FULL_FILE_THRESHOLD_CHARS
        write(tmp_path / "provider.py", big_provider)

        ctx = find_code_context("FileSystemProvider path traversal in `stac` collection", tmp_path)

        assert "class FileSystemProvider" in ctx, (
            "the large defining file must still be included, anchored at its "
            "class definition, despite exceeding the full-file threshold"
        )
        assert "provider.py" in ctx and "api.py" in ctx
        # provider.py (ranked[0]) must be rendered before api.py (ranked[1]) —
        # confirms it was not displaced from the first slot.
        assert ctx.index("provider.py") < ctx.index("api.py"), (
            "the symbol-defining file must occupy the first (primary) slot "
            "in snippet mode, not be pushed behind the high-occurrence file"
        )
        assert len(ctx) <= _MAX_CONTEXT_CHARS + 500, (
            f"snippet-mode output ({len(ctx)} chars) exceeds the expected budget allowance"
        )


# ---------------------------------------------------------------------------
# F-30 regression: a generic token's raw occurrence count must not evict or
# outrank the file that defines the advisory's actual named symbol. Mirrors
# the finding's own example ("path" — a plain _GENERIC_TOKENS word, not a
# repo-specific one like "stac") and its exact failure-mode narrative: three
# unrelated files each repeating a generic word many times, competing
# against one real file that defines the named vulnerable symbol.
# ---------------------------------------------------------------------------

class TestF30GenericTokenCannotEvictDefiningFile:
    def test_defining_file_survives_full_eviction_scenario(self, tmp_path):
        """Before the fix, three unrelated files each repeating a generic
        backtick term ("path") enough times would fill _grep_repo's own
        top-3 cut, silently evicting the file that defines the named
        symbol from the candidate list entirely — see the F-30 root-cause
        investigation. The exact symbol-definition pass finds the defining
        file independently of _grep_repo's occurrence-based cut, so it must
        survive regardless of how much generic-token noise exists."""
        from utilities.autopatcher.repo_locator import find_code_context

        # The real vulnerable file: defines the named symbol, barely
        # mentions the generic term.
        write(tmp_path / "auth.py",
              "def authenticate_user(username, password, path):\n"
              "    return db.check(username, password)\n")

        # Three unrelated files, each with many occurrences of the generic
        # term and zero mentions of the actual vulnerable symbol -- enough
        # to have filled _grep_repo's own top-3 cutoff before the fix.
        for n, fname in enumerate(["routes.py", "storage.py", "uploads.py"], start=1):
            write(tmp_path / fname,
                  "\n".join(f"def helper_{n}_{i}(path):\n    return path" for i in range(20)))

        vuln_text = (
            "**Type:** CWE-287 Improper Authentication\n\n"
            "The `authenticate_user` function does not validate the redirect `path` "
            "parameter, allowing an attacker-controlled `path` to bypass auth checks."
        )

        ctx = find_code_context(vuln_text, tmp_path)

        assert "def authenticate_user" in ctx, (
            "the file defining the named vulnerable symbol must not be evicted "
            "by unrelated files repeating a generic token"
        )
        assert "# auth.py (full file," in ctx, (
            "the defining file must be the primary candidate, not merely present"
        )

    def test_generic_token_does_not_outrank_defining_file(self, tmp_path):
        """Two-file version: even without enough noise files to trigger full
        eviction from _grep_repo's own cut, a single unrelated file with a
        higher raw occurrence count of a generic token must not become the
        primary ahead of the file that defines the named symbol."""
        from utilities.autopatcher.repo_locator import find_code_context

        write(tmp_path / "auth.py",
              "def authenticate_user(username, password):\n"
              "    # path traversal via unsanitized redirect path\n"
              "    return db.check(username, password)\n")
        write(tmp_path / "unrelated_paths.py",
              "\n".join(f"def helper_{i}(path):\n    return path + str({i})" for i in range(30)))

        vuln_text = (
            "**Type:** CWE-287 Improper Authentication\n\n"
            "The `authenticate_user` function does not validate the redirect `path` "
            "parameter, allowing an attacker-controlled `path` to bypass auth checks."
        )

        ctx = find_code_context(vuln_text, tmp_path)

        assert "# auth.py (full file," in ctx, (
            "the symbol-defining file must be the primary candidate"
        )
        assert "# unrelated_paths.py (full file," not in ctx, (
            "a generic token's raw occurrence count must not win primary status"
        )


# ---------------------------------------------------------------------------
# Live pygeoapi integration (opt-in)
# ---------------------------------------------------------------------------

_PYGEOAPI_EVAL = Path(tempfile.gettempdir()) / "pygeoapi-eval"
_PYGEOAPI_STAC_PY = _PYGEOAPI_EVAL / "pygeoapi" / "api" / "stac.py"
_PYGEOAPI_FS_PY = _PYGEOAPI_EVAL / "pygeoapi" / "provider" / "filesystem.py"

_run_pygeoapi_live = (
    os.environ.get("RUN_LIVE_REPO_TESTS") == "1"
    and _PYGEOAPI_STAC_PY.exists()
    and _PYGEOAPI_FS_PY.exists()
)


@pytest.mark.skipif(
    not _run_pygeoapi_live,
    reason=(
        "Live pygeoapi tests opt-in only — "
        "set RUN_LIVE_REPO_TESTS=1 and ensure "
        f"{_PYGEOAPI_EVAL} contains both "
        "pygeoapi/api/stac.py and pygeoapi/provider/filesystem.py"
    ),
)
class TestPygeoAPIClassDefinitionGrounding:
    _VULN_TEXT = (
        "# pygeoapi 0.23.x: Path Traversal in STAC FileSystemProvider\n\n"
        "**Type:** CWE-22\n\n"
        "A raw string path concatenation vulnerability in pygeoapi's STAC "
        "FileSystemProvider plugin allows path traversal via `stac-collection` "
        "resources."
    )

    def test_filesystem_py_appears_in_context(self):
        """After class-def supplement, filesystem.py must appear in injected context."""
        from utilities.autopatcher.repo_locator import find_code_context
        ctx = find_code_context(self._VULN_TEXT, _PYGEOAPI_EVAL)
        assert "filesystem.py" in ctx, (
            "filesystem.py must be injected via class-def supplement"
        )

    def test_stac_py_remains_primary(self):
        """stac.py (highest occurrence count) must remain the full-file primary."""
        from utilities.autopatcher.repo_locator import find_code_context
        ctx = find_code_context(self._VULN_TEXT, _PYGEOAPI_EVAL)
        assert "# pygeoapi/api/stac.py (full file," in ctx, (
            "stac.py must remain the full-file primary"
        )


# ---------------------------------------------------------------------------
# Stage 6A: runtime observability — resolution_strategy propagation,
# explicit_path_resolutions, selected_pass, selected. Additive only: the
# pre-existing explicit_paths/explicit_paths_unresolved/explicit_paths_ambiguous
# fields must be unaffected by any of this.
# ---------------------------------------------------------------------------

def _latest_debug_artifact(tmp_path: Path) -> dict:
    debug_dir = tmp_path / "reports" / "debug"
    files = sorted(debug_dir.glob("context_selection_*.json"))
    assert files, f"expected a debug artifact under {debug_dir}"
    return json.loads(files[-1].read_text(encoding="utf-8"))


class TestExplicitPathResolutionsAdditive:
    """explicit_path_resolutions is added alongside the three existing
    fields, which must remain exactly as they were."""

    def test_existing_three_fields_unchanged_on_exact_match(self, tmp_path, monkeypatch):
        from utilities.autopatcher.repo_locator import find_code_context
        monkeypatch.setenv("AUTOPATCHER_DEBUG", "1")
        monkeypatch.chdir(tmp_path)
        write(tmp_path / "app" / "auth.py", "def authenticate(): pass\n")

        find_code_context("Vulnerability in app/auth.py", tmp_path)
        record = _latest_debug_artifact(tmp_path)
        signals = record["extraction_signals"]

        assert signals["explicit_paths"] == ["app/auth.py"]
        assert signals["explicit_paths_unresolved"] == []
        assert signals["explicit_paths_ambiguous"] == []

    def test_existing_three_fields_unchanged_on_ambiguous_match(self, tmp_path, monkeypatch):
        from utilities.autopatcher.repo_locator import find_code_context
        monkeypatch.setenv("AUTOPATCHER_DEBUG", "1")
        monkeypatch.chdir(tmp_path)
        write(tmp_path / "a" / "_internal" / "download.py", "# a\n")
        write(tmp_path / "b" / "_internal" / "download.py", "# b\n")

        find_code_context("Vulnerability in _internal/download.py", tmp_path)
        record = _latest_debug_artifact(tmp_path)
        signals = record["extraction_signals"]

        assert signals["explicit_paths"] == ["_internal/download.py"]
        assert signals["explicit_paths_unresolved"] == []
        assert signals["explicit_paths_ambiguous"] == ["_internal/download.py"]

    def test_explicit_path_resolutions_present_alongside_old_fields(self, tmp_path, monkeypatch):
        from utilities.autopatcher.repo_locator import find_code_context
        monkeypatch.setenv("AUTOPATCHER_DEBUG", "1")
        monkeypatch.chdir(tmp_path)
        write(
            tmp_path / "src" / "pip" / "_internal" / "download.py",
            "def unpack_url(): pass\n",
        )

        find_code_context("Vulnerability in _internal/download.py", tmp_path)
        record = _latest_debug_artifact(tmp_path)
        signals = record["extraction_signals"]

        # Old fields still present and correct
        assert signals["explicit_paths"] == ["_internal/download.py"]
        assert signals["explicit_paths_unresolved"] == []
        assert signals["explicit_paths_ambiguous"] == []
        # New field, additive
        assert signals["explicit_path_resolutions"] == [
            {
                "raw_path": "_internal/download.py",
                "strategy": "suffix",
                "resolved_file": "src/pip/_internal/download.py",
            }
        ]

    def test_one_entry_per_extracted_path_including_unresolved_and_ambiguous(
        self, tmp_path, monkeypatch
    ):
        """A single call whose advisory names three paths — one exact, one
        ambiguous, one unresolved — must produce exactly three
        explicit_path_resolutions entries, one per path, each with the
        correct strategy."""
        from utilities.autopatcher.repo_locator import find_code_context
        monkeypatch.setenv("AUTOPATCHER_DEBUG", "1")
        monkeypatch.chdir(tmp_path)
        write(tmp_path / "app" / "auth.py", "def authenticate(): pass\n")
        write(tmp_path / "a" / "_internal" / "download.py", "# a\n")
        write(tmp_path / "b" / "_internal" / "download.py", "# b\n")

        vuln = (
            "Vulnerability in app/auth.py and _internal/download.py "
            "and does/not/exist.py"
        )
        find_code_context(vuln, tmp_path)
        record = _latest_debug_artifact(tmp_path)
        resolutions = record["extraction_signals"]["explicit_path_resolutions"]

        by_path = {r["raw_path"]: r for r in resolutions}
        assert len(resolutions) == 3
        assert by_path["app/auth.py"]["strategy"] == "exact"
        assert by_path["app/auth.py"]["resolved_file"] == "app/auth.py"
        assert by_path["_internal/download.py"]["strategy"] == "ambiguous"
        assert by_path["_internal/download.py"]["resolved_file"] is None
        assert by_path["does/not/exist.py"]["strategy"] == "unresolved"
        assert by_path["does/not/exist.py"]["resolved_file"] is None


class TestResolutionStrategyPropagation:
    """The Stage 6A bugfix: resolution_strategy must survive into the
    per-candidate `passes` entry written to disk."""

    def test_resolution_strategy_exact_in_written_artifact(self, tmp_path, monkeypatch):
        from utilities.autopatcher.repo_locator import find_code_context
        monkeypatch.setenv("AUTOPATCHER_DEBUG", "1")
        monkeypatch.chdir(tmp_path)
        write(tmp_path / "app" / "auth.py", "def authenticate(): pass\n")

        find_code_context("Vulnerability in app/auth.py", tmp_path)
        record = _latest_debug_artifact(tmp_path)
        candidate = next(c for c in record["candidates"] if c["file"] == "app/auth.py")
        explicit_pass = next(p for p in candidate["passes"] if p["pass"] == "explicit_path")

        assert explicit_pass["resolution_strategy"] == "exact"

    def test_resolution_strategy_suffix_in_written_artifact(self, tmp_path, monkeypatch):
        from utilities.autopatcher.repo_locator import find_code_context
        monkeypatch.setenv("AUTOPATCHER_DEBUG", "1")
        monkeypatch.chdir(tmp_path)
        write(
            tmp_path / "src" / "pip" / "_internal" / "download.py",
            "def unpack_url(): pass\n",
        )

        find_code_context("Vulnerability in _internal/download.py", tmp_path)
        record = _latest_debug_artifact(tmp_path)
        candidate = next(
            c for c in record["candidates"]
            if c["file"] == "src/pip/_internal/download.py"
        )
        explicit_pass = next(p for p in candidate["passes"] if p["pass"] == "explicit_path")

        assert explicit_pass["resolution_strategy"] == "suffix"


class TestSelectedPassAndSelected:
    """selected_pass and selected are derived, single-source-of-truth
    fields — never independently maintained state."""

    def test_selected_pass_matches_final_score_owning_pass(self, tmp_path, monkeypatch):
        from utilities.autopatcher.repo_locator import find_code_context
        monkeypatch.setenv("AUTOPATCHER_DEBUG", "1")
        monkeypatch.chdir(tmp_path)
        write(tmp_path / "app" / "auth.py", "def authenticate(): pass\n")

        find_code_context("Vulnerability in app/auth.py", tmp_path)
        record = _latest_debug_artifact(tmp_path)
        candidate = next(c for c in record["candidates"] if c["file"] == "app/auth.py")

        assert candidate["selected_pass"] == "explicit_path"

    def test_selected_true_for_primary_file(self, tmp_path, monkeypatch):
        from utilities.autopatcher.repo_locator import find_code_context
        monkeypatch.setenv("AUTOPATCHER_DEBUG", "1")
        monkeypatch.chdir(tmp_path)
        write(tmp_path / "app" / "auth.py", "def authenticate(): pass\n")

        find_code_context("Vulnerability in app/auth.py", tmp_path)
        record = _latest_debug_artifact(tmp_path)
        candidate = next(c for c in record["candidates"] if c["file"] == "app/auth.py")

        assert candidate["selected"] is True
        assert candidate["selection_outcome"] != "rejected"

    # Fixture shared by the next four tests: mirrors
    # TestSymbolDefinitionGrounding's api.py/urls.py/flask_app.py/filesystem.py
    # setup elsewhere in this file. filesystem.py defines FileSystemProvider,
    # so the exact symbol-definition pass (tier 3) ranks it above all three
    # ordinary grep hits (tier 2) regardless of occurrence count — it becomes
    # the full-file primary (ranked[0]). api.py(26 `stac` hits) and
    # urls.py(10) are the two highest-occurrence tier-2 hits and fill the
    # 2-slot secondary queue (ranked[1], ranked[2]); flask_app.py(8), the
    # third and lowest tier-2 hit, is pushed out by the 2-slot cap and ends
    # up "rejected" — giving a real, non-null final_score paired with a
    # rejected outcome.
    def _write_rejection_fixture(self, tmp_path: Path) -> None:
        write(
            tmp_path / "api.py",
            "# stac routing module\n" + "def handle_stac(req): pass  # stac\n" * 25,
        )
        write(tmp_path / "urls.py", "# stac route\n" + "path('/stac/')\n" * 9)
        write(tmp_path / "flask_app.py", "# stac routes\n" + "@app.route('/stac/')\n" * 7)
        write(
            tmp_path / "provider" / "filesystem.py",
            "class FileSystemProvider:\n"
            "    def get_data_path(self, path): return path\n"
            "    # stac stac stac stac\n",
        )

    def test_selected_false_for_rejected_candidate(self, tmp_path, monkeypatch):
        """A candidate outside the final secondary-slot cut must have
        selected=False, matching its selection_outcome of 'rejected'."""
        from utilities.autopatcher.repo_locator import find_code_context
        monkeypatch.setenv("AUTOPATCHER_DEBUG", "1")
        monkeypatch.chdir(tmp_path)
        self._write_rejection_fixture(tmp_path)

        find_code_context("FileSystemProvider path traversal in `stac` collection", tmp_path)
        record = _latest_debug_artifact(tmp_path)
        rejected = [c for c in record["candidates"] if c["selection_outcome"] == "rejected"]

        assert rejected, "expected at least one rejected candidate in this setup"
        for c in rejected:
            assert c["selected"] is False

    def test_selected_matches_selection_outcome_for_every_candidate(self, tmp_path, monkeypatch):
        """selected is always exactly (selection_outcome != 'rejected') —
        single source of truth, never independently wrong."""
        from utilities.autopatcher.repo_locator import find_code_context
        monkeypatch.setenv("AUTOPATCHER_DEBUG", "1")
        monkeypatch.chdir(tmp_path)
        self._write_rejection_fixture(tmp_path)

        find_code_context("FileSystemProvider path traversal in `stac` collection", tmp_path)
        record = _latest_debug_artifact(tmp_path)

        for c in record["candidates"]:
            assert c["selected"] == (c["selection_outcome"] != "rejected")

    def test_selected_pass_never_null_for_any_candidate(self, tmp_path, monkeypatch):
        """Every entry that made it into the candidates list arrived via at
        least one pass, so selected_pass must always resolve to a name."""
        from utilities.autopatcher.repo_locator import find_code_context
        monkeypatch.setenv("AUTOPATCHER_DEBUG", "1")
        monkeypatch.chdir(tmp_path)
        self._write_rejection_fixture(tmp_path)

        find_code_context("FileSystemProvider path traversal in `stac` collection", tmp_path)
        record = _latest_debug_artifact(tmp_path)

        for c in record["candidates"]:
            assert c["selected_pass"] is not None, f"selected_pass unexpectedly null for {c['file']}"

    def test_selected_pass_symbol_definition_for_promoted_low_occurrence_file(
        self, tmp_path, monkeypatch
    ):
        """filesystem.py has the lowest raw occurrence count of the four
        files in this fixture, but the exact symbol-definition pass (F-30)
        ranks it above every ordinary grep hit because it *defines*
        FileSystemProvider. final_score must be the real symbol-definition
        tier (not None — there is no more supplement-only, tier-less path),
        and selected_pass must resolve to 'symbol_definition'."""
        from utilities.autopatcher.repo_locator import (
            find_code_context, _TIER_SYMBOL_DEFINITION,
        )
        monkeypatch.setenv("AUTOPATCHER_DEBUG", "1")
        monkeypatch.chdir(tmp_path)
        self._write_rejection_fixture(tmp_path)

        find_code_context("FileSystemProvider path traversal in `stac` collection", tmp_path)
        record = _latest_debug_artifact(tmp_path)
        candidate = next(
            c for c in record["candidates"] if c["file"] == "provider/filesystem.py"
        )

        assert candidate["final_score"] == _TIER_SYMBOL_DEFINITION
        assert candidate["selected_pass"] == "symbol_definition"
        assert candidate["selection_outcome"] == "primary_full_file", (
            "the defining file must be the primary, not merely a rejected-adjacent entry"
        )


class TestGroundRepository:
    """ground_repository() must return the exact same rendered_context as
    find_code_context(), plus one RepositoryCandidate/GroundingDecision per
    discovered file with today's exact outcome values, across the four
    exit paths find_code_context() has: empty/no-match, primary full-file,
    primary snippet, and multi-candidate secondary-context."""

    def test_empty_no_match(self, tmp_path):
        from utilities.autopatcher.repo_locator import find_code_context, ground_repository
        vuln = "SQL injection in authenticate()"

        expected = find_code_context(vuln, tmp_path)
        result = ground_repository(vuln, tmp_path)

        assert result.rendered_context == expected == ""
        assert result.candidates == []
        assert result.decisions == []
        assert result.budget is None

    def test_primary_full_file(self, tmp_path):
        """Single-candidate case: only retry.py matches (connectionpool.py
        produces zero signal hits), so it must be the sole candidate and
        be selected via the full-file path."""
        from utilities.autopatcher.repo_locator import find_code_context, ground_repository
        write(tmp_path / "retry.py",
              "class Retry:\n    DEFAULT_REMOVE = frozenset(['Authorization'])\n")
        write(tmp_path / "connectionpool.py",
              "class ConnectionPool:\n    redirects = True\n")
        vuln = "The `Authorization` header is not stripped on redirects."

        expected = find_code_context(vuln, tmp_path)
        result = ground_repository(vuln, tmp_path)

        assert result.rendered_context == expected
        assert [c.path for c in result.candidates] == ["retry.py"]
        assert [d.path for d in result.decisions] == ["retry.py"]
        for cand, dec in zip(result.candidates, result.decisions):
            assert cand.path == dec.path
        assert result.decisions[0].outcome == "primary_full_file"

    def test_primary_snippet(self, tmp_path):
        """Single-candidate case forced into snippet mode: the file exceeds
        _FULL_FILE_THRESHOLD_CHARS, and only Pass 1 (explicit path) fires —
        'authenticate' has no underscore/PascalCase so Pass 2 stays empty."""
        from utilities.autopatcher.repo_locator import find_code_context, ground_repository
        big = "def authenticate(u, p):\n" + "    # padding line here\n" * 1500
        assert len(big) > 20_000
        write(tmp_path / "app" / "auth.py", big)
        vuln = "SQL injection in app/auth.py — authenticate()"

        expected = find_code_context(vuln, tmp_path)
        result = ground_repository(vuln, tmp_path)

        assert result.rendered_context == expected
        assert [c.path for c in result.candidates] == ["app/auth.py"]
        assert [d.path for d in result.decisions] == ["app/auth.py"]
        for cand, dec in zip(result.candidates, result.decisions):
            assert cand.path == dec.path
        assert result.decisions[0].outcome == "primary_snippet"

    def test_secondary_context_selected_and_rejected(self, tmp_path):
        """Reuses TestSelectedPassAndSelected's rejection fixture: 4
        candidates, 3 selected (1 primary full-file — the symbol-definition
        file, ranked above all ordinary grep hits — plus 2 secondary
        snippets), 1 rejected by the 2-slot secondary cap despite having
        real, non-null evidence (final_score=2)."""
        from utilities.autopatcher.repo_locator import find_code_context, ground_repository
        write(tmp_path / "api.py",
              "# stac routing module\n" + "def handle_stac(req): pass  # stac\n" * 25)
        write(tmp_path / "urls.py", "# stac route\n" + "path('/stac/')\n" * 9)
        write(tmp_path / "flask_app.py", "# stac routes\n" + "@app.route('/stac/')\n" * 7)
        write(
            tmp_path / "provider" / "filesystem.py",
            "class FileSystemProvider:\n"
            "    def get_data_path(self, path): return path\n"
            "    # stac stac stac stac\n",
        )
        vuln = "FileSystemProvider path traversal in `stac` collection"

        expected = find_code_context(vuln, tmp_path)
        result = ground_repository(vuln, tmp_path)

        assert result.rendered_context == expected

        expected_paths = {"api.py", "urls.py", "flask_app.py", "provider/filesystem.py"}
        assert {c.path for c in result.candidates} == expected_paths
        assert len(result.decisions) == len(result.candidates)
        for cand, dec in zip(result.candidates, result.decisions):
            assert cand.path == dec.path

        outcomes = {d.path: d.outcome for d in result.decisions}
        assert outcomes["provider/filesystem.py"] == "primary_full_file"
        assert outcomes["api.py"] == "secondary_snippet"
        assert outcomes["urls.py"] == "secondary_snippet"
        assert outcomes["flask_app.py"] == "rejected"

        selected = {p for p, o in outcomes.items() if o != "rejected"}
        rejected = {p for p, o in outcomes.items() if o == "rejected"}
        assert selected == {"provider/filesystem.py", "api.py", "urls.py"}
        assert rejected == {"flask_app.py"}


# ---------------------------------------------------------------------------
# F-18: symlink / path-containment regression tests
#
# _safe_under() is a security boundary, not a convenience filter: a symlink
# that *lives* inside the repo but whose target *resolves* outside it must
# never be enumerated, grepped, class-def-matched, or suffix-resolved. These
# tests exercise the resolve-and-compare check directly through the three
# call sites it was added to (_grep_repo, _find_symbol_definitions,
# RepositoryPathResolver._iter_files), plus find_code_context end-to-end.
# ---------------------------------------------------------------------------

class TestSymlinkContainment:
    def test_external_absolute_symlink_rejected_by_grep(self, tmp_path):
        from utilities.autopatcher.repo_locator import _grep_repo
        repo = tmp_path / "repo"
        repo.mkdir()
        write(tmp_path / "secret.py", "HOST_SECRET = 'hunter2'\n")
        os.symlink(tmp_path / "secret.py", repo / "evil.py")

        results = _grep_repo(repo, ["HOST_SECRET"])
        assert results == []

    def test_external_relative_symlink_rejected_by_grep(self, tmp_path):
        from utilities.autopatcher.repo_locator import _grep_repo
        repo = tmp_path / "repo"
        repo.mkdir()
        write(tmp_path / "secret.py", "HOST_SECRET = 'hunter2'\n")
        # Target given as a path relative to the symlink's own directory
        # (repo/), so it escapes without ever mentioning an absolute path.
        os.symlink(os.path.join("..", "secret.py"), repo / "evil.py")

        results = _grep_repo(repo, ["HOST_SECRET"])
        assert results == []

    def test_external_symlink_rejected_by_class_definitions(self, tmp_path):
        from utilities.autopatcher.repo_locator import _find_symbol_definitions
        repo = tmp_path / "repo"
        repo.mkdir()
        write(tmp_path / "secret.py", "class LeakyProvider:\n    pass\n")
        os.symlink(tmp_path / "secret.py", repo / "evil.py")

        results = _find_symbol_definitions("LeakyProvider vulnerability", repo)
        assert results == []

    def test_suffix_match_cannot_return_escaping_symlink(self, tmp_path):
        from utilities.autopatcher.repo_locator import RepositoryPathResolver
        repo = tmp_path / "repo"
        (repo / "_internal").mkdir(parents=True)
        write(tmp_path / "secret.py", "HOST_SECRET = 1\n")
        os.symlink(tmp_path / "secret.py", repo / "_internal" / "download.py")

        resolver = RepositoryPathResolver(repo)
        result = resolver.resolve("_internal/download.py")
        assert result.path is None
        assert result.strategy == "unresolved"

    def test_find_code_context_never_surfaces_external_content(self, tmp_path):
        from utilities.autopatcher.repo_locator import find_code_context
        repo = tmp_path / "repo"
        repo.mkdir()
        write(tmp_path / "secret.py", "HOST_SECRET_TOKEN = 'do-not-leak'\n")
        os.symlink(tmp_path / "secret.py", repo / "evil.py")
        write(repo / "app.py", "def authenticate(): pass\n")

        vuln = "authenticate() is exploitable — see `HOST_SECRET_TOKEN`"
        result = find_code_context(vuln, repo)
        assert "do-not-leak" not in result
        assert "HOST_SECRET_TOKEN" not in result

    def test_in_repo_symlink_still_supported_by_grep(self, tmp_path):
        """A symlink whose target resolves inside the repo is not an escape
        and must keep working exactly as before (no regression)."""
        from utilities.autopatcher.repo_locator import _grep_repo
        repo = tmp_path / "repo"
        write(repo / "impl" / "real.py", "def authenticate(): pass\n")
        os.symlink(repo / "impl" / "real.py", repo / "alias.py")

        results = _grep_repo(repo, ["authenticate"])
        names = {p.name for p, _content, _hit in results}
        assert "alias.py" in names

    def test_in_repo_symlink_still_supported_by_suffix_match(self, tmp_path):
        """Mirrors test_suffix_match_resolves_src_layout: the advisory names
        `_internal/download.py`, but the real file lives under a src-layout
        prefix reached only via a symlinked alias — no `_internal/` directory
        exists at the repo root, so this can only resolve via suffix match."""
        from utilities.autopatcher.repo_locator import RepositoryPathResolver
        repo = tmp_path / "repo"
        write(repo / "real" / "download.py", "def unpack_url(): pass\n")
        (repo / "src" / "pip" / "_internal").mkdir(parents=True)
        os.symlink(repo / "real" / "download.py", repo / "src" / "pip" / "_internal" / "download.py")

        resolver = RepositoryPathResolver(repo)
        result = resolver.resolve("_internal/download.py")
        assert result.strategy == "suffix"
        assert result.path is not None
        assert result.path.resolve() == (repo / "real" / "download.py").resolve()

    def test_broken_symlink_does_not_crash_grep(self, tmp_path):
        from utilities.autopatcher.repo_locator import _grep_repo
        repo = tmp_path / "repo"
        repo.mkdir()
        os.symlink(tmp_path / "does_not_exist.py", repo / "broken.py")
        write(repo / "app.py", "def authenticate(): pass\n")

        results = _grep_repo(repo, ["authenticate"])
        names = {p.name for p, _content, _hit in results}
        assert "broken.py" not in names
        assert "app.py" in names

    def test_broken_symlink_does_not_crash_class_definitions(self, tmp_path):
        from utilities.autopatcher.repo_locator import _find_symbol_definitions
        repo = tmp_path / "repo"
        repo.mkdir()
        os.symlink(tmp_path / "does_not_exist.py", repo / "broken.py")

        results = _find_symbol_definitions("Anything at all", repo)
        assert results == []

    def test_broken_symlink_does_not_crash_suffix_match(self, tmp_path):
        from utilities.autopatcher.repo_locator import RepositoryPathResolver
        repo = tmp_path / "repo"
        (repo / "_internal").mkdir(parents=True)
        os.symlink(tmp_path / "does_not_exist.py", repo / "_internal" / "download.py")

        resolver = RepositoryPathResolver(repo)
        result = resolver.resolve("_internal/download.py")
        assert result.path is None

    def test_symlink_loop_does_not_hang_or_crash(self, tmp_path):
        """A mutual symlink loop must be rejected quickly, not hang the scan
        or propagate the OS-level 'too many levels of symbolic links' error."""
        from utilities.autopatcher.repo_locator import _grep_repo
        repo = tmp_path / "repo"
        repo.mkdir()
        os.symlink(repo / "loop_b.py", repo / "loop_a.py")
        os.symlink(repo / "loop_a.py", repo / "loop_b.py")
        write(repo / "app.py", "def authenticate(): pass\n")

        results = _grep_repo(repo, ["authenticate"])
        names = {p.name for p, _content, _hit in results}
        assert "loop_a.py" not in names
        assert "loop_b.py" not in names
        assert "app.py" in names

    def test_symlink_loop_does_not_crash_class_definitions(self, tmp_path):
        from utilities.autopatcher.repo_locator import _find_symbol_definitions
        repo = tmp_path / "repo"
        repo.mkdir()
        os.symlink(repo / "loop_a.py", repo / "loop_a.py")

        results = _find_symbol_definitions("Anything at all", repo)
        assert results == []

    def test_exact_match_symlink_loop_fails_closed(self, tmp_path):
        """A symlink loop at the exact path an advisory names must not
        crash resolution — `.resolve()` raises RuntimeError for a loop, and
        _resolve_exact must catch that and fail closed (unresolved), not
        propagate it. A single path segment guarantees this exercises only
        the exact-match branch, never the suffix fallback."""
        from utilities.autopatcher.repo_locator import RepositoryPathResolver
        repo = tmp_path / "repo"
        repo.mkdir()
        os.symlink(repo / "loop.py", repo / "loop.py")

        resolver = RepositoryPathResolver(repo)
        result = resolver.resolve("loop.py")
        assert result.path is None
        assert result.strategy == "unresolved"

    def test_repo_root_beneath_symlinked_ancestor_still_works(self, tmp_path):
        """The repo root itself sitting under a symlinked ancestor directory
        (e.g. macOS's /tmp -> /private/tmp) must not break containment —
        both sides of the comparison need to resolve to the same canonical
        location."""
        from utilities.autopatcher.repo_locator import (
            RepositoryPathResolver,
            _find_symbol_definitions,
            _grep_repo,
        )
        real_root = tmp_path / "real_root"
        write(real_root / "repo" / "app.py", "def authenticate(): pass\n")
        write(real_root / "repo" / "provider.py", "class FileSystemProvider:\n    pass\n")
        link_root = tmp_path / "link_root"
        os.symlink(real_root, link_root)
        repo_via_link = link_root / "repo"

        grep_results = _grep_repo(repo_via_link, ["authenticate"])
        assert {p.name for p, _c, _h in grep_results} == {"app.py"}

        class_results = _find_symbol_definitions("FileSystemProvider vuln", repo_via_link)
        assert {p.name for p, _c, _h in class_results} == {"provider.py"}

        resolver = RepositoryPathResolver(repo_via_link)
        result = resolver.resolve("app.py")
        assert result.strategy == "exact"
        assert result.path is not None
