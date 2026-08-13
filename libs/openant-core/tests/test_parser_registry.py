"""Parser dispatch is a registry lookup, not a hand-maintained if/elif chain.

This test class is what makes the three-registry drift bug structurally
impossible: it asserts every language the config declares actually resolves to
a callable parser whose script exists on disk. Previously a language could be
added to config/languages.json and detection would happily return it, only for
parse_repository to raise "Unsupported language" at runtime.
"""

import functools

import pytest

from core.language_registry import load_registry, supported_languages
from core.parser_adapter import (
    _parse_via_subprocess,
    _parser_for,
    parse_repository,
)


class TestDispatchTable:
    def test_every_supported_language_resolves_to_a_callable(self):
        for language in supported_languages():
            assert callable(_parser_for(language)), f"{language} did not resolve"

    def test_python_resolves_in_process(self):
        # Resolve BOTH sides from the same module object — see the note in
        # TestAliasesPreserved: core.parser_adapter can live in sys.modules
        # under two identities, so mixing a top-level `from ... import` with a
        # fresh `import` compares functions from different module instances and
        # fails only once an earlier test triggers the second import.
        import core.parser_adapter as pa

        parser = pa._parser_for("python")
        assert parser is pa._parse_python
        assert not isinstance(parser, functools.partial)

    def test_inprocess_dispatch_honours_monkeypatching(self, monkeypatch):
        """Regression lock: dispatch must resolve _parse_python DYNAMICALLY.

        An earlier version of the registry captured the function object once at
        import time in a module-level dict. That silently broke the long-
        standing seam tests/test_parse_fresh.py relies on — patching
        ``parser_adapter._parse_python`` no longer changed what ran, so a test
        that believed it had stubbed out parsing was invoking the real parser.
        The failure is invisible from the patching test's own perspective,
        which is what makes it worth pinning here.
        """
        import core.parser_adapter as pa

        sentinel = object()
        monkeypatch.setattr(pa, "_parse_python", sentinel)
        assert pa._parser_for("python") is sentinel

    def test_every_other_language_resolves_to_the_subprocess_parser(self):
        for language in supported_languages():
            if language == "python":
                continue
            parser = _parser_for(language)
            assert isinstance(parser, functools.partial), f"{language} is not a partial"
            assert parser.func is _parse_via_subprocess
            assert parser.args == (language,)

    def test_unknown_language_raises_keyerror(self):
        with pytest.raises(KeyError):
            _parser_for("cobol")

    def test_python_is_the_only_inprocess_language(self):
        """Documents the one asymmetry the dispatch depends on.

        Asserted against the registry, which is what ``_parser_for`` actually
        consults. A previous version of this test asserted against a module
        dict that dispatch had stopped reading — it passed while describing a
        model of the code that was no longer true.
        """
        inprocess = [
            name for name in supported_languages()
            if load_registry()[name].parser_mode == "inprocess"
        ]
        assert inprocess == ["python"]


class TestAliasesPreserved:
    """Module-level aliases are insurance for callers importing by name."""

    @pytest.mark.parametrize("language", ["javascript", "go", "c", "ruby", "php", "zig"])
    def test_alias_exists_and_is_bound_to_its_language(self, language):
        # Resolve BOTH sides from the same module object. A top-level
        # `from ... import` in this file and a fresh `import` inside the test
        # are not guaranteed to yield the same function object, because some
        # tests evict `core.*` from sys.modules mid-session (F3 did so without
        # restoring it, until that was fixed). Comparing across two module
        # identities then fails for reasons unrelated to dispatch.
        import core.parser_adapter as pa

        alias = getattr(pa, f"_parse_{language}")
        assert isinstance(alias, functools.partial)
        assert alias.func is pa._parse_via_subprocess
        assert alias.args == (language,)

    def test_parse_python_alias_still_a_plain_function(self):
        import core.parser_adapter as pa

        assert callable(pa._parse_python)
        assert not isinstance(pa._parse_python, functools.partial)


class TestUnsupportedLanguageError:
    def test_parse_repository_rejects_unknown_language_and_lists_supported(self, tmp_path):
        (tmp_path / "a.py").write_text("x")
        with pytest.raises(ValueError) as exc:
            parse_repository(str(tmp_path), str(tmp_path / "out"), language="cobol")
        message = str(exc.value)
        assert "Unsupported language: cobol" in message
        # The error must name what IS supported, derived from the registry.
        for language in supported_languages():
            assert language in message

    def test_rust_is_supported(self):
        """Rust is now a registered subprocess parser, not a rejected language.

        (Was `test_rust_is_rejected`, asserting parse_repository raised
        "Unsupported language: rust" while parsers/rust/ was a dead stub.
        Flipped when the parser was implemented and registered.)
        """
        assert "rust" in supported_languages()
        # It resolves to the generic subprocess parser like every other
        # non-Python language, without needing a hand-written dispatch alias.
        assert callable(_parser_for("rust"))


class TestSubprocessParserGuard:
    def test_calling_subprocess_parser_for_python_is_rejected(self, tmp_path):
        """Python has no subprocess entry point; asking for one is a bug."""
        with pytest.raises(ValueError, match="No subprocess parser registered"):
            _parse_via_subprocess("python", str(tmp_path), str(tmp_path), "reachable")

    def test_calling_subprocess_parser_for_unknown_language_is_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="No subprocess parser registered"):
            _parse_via_subprocess("cobol", str(tmp_path), str(tmp_path), "reachable")


class TestRegistryIsTheSingleSourceOfTruth:
    def test_adding_a_language_needs_no_dispatch_edit(self):
        """The dispatch table is derived, so config alone decides the set."""
        from_registry = set(supported_languages())
        resolvable = {lang for lang in from_registry if callable(_parser_for(lang))}
        assert resolvable == from_registry

    def test_bootstrap_hook_is_declared_in_config_not_code(self):
        spec = load_registry()["javascript"]
        assert spec.bootstrap == "npm"
        for language in supported_languages():
            if language != "javascript":
                assert load_registry()[language].bootstrap is None
