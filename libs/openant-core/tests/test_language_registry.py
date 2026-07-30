"""Consistency guards for the language registry.

These tests are the real deliverable of the registry work. The registry itself
is a small amount of code; what actually prevents the recurring bug is asserting
that every *other* description of the supported-language set agrees with it.

Zig is the worked example of the failure being guarded against: it was added to
``config/languages.json`` and to the parser dispatch chain, but never reached
``scan.go``/``parse.go`` help text or ``README.md``. Nothing failed, so nobody
noticed.
"""

import json
import re
from pathlib import Path

import pytest

from core.language_registry import (
    find_languages_config,
    docker_template_for,
    extension_map,
    fence_for_path,
    language_for_path,
    load_registry,
    parser_script_path,
    skip_dirs,
    supported_languages,
)

REPO_ROOT = Path(__file__).parent.parent.parent.parent
CORE_ROOT = Path(__file__).parent.parent


@pytest.fixture(scope="module")
def raw_config() -> dict:
    with open(find_languages_config(), encoding="utf-8") as f:
        return json.load(f)


class TestRegistryVsLegacyConfig:
    """The legacy flat maps and the per-language block must stay in lock-step.

    Both are live: Python reads the flat ``extensions`` map today and the Go
    detector reads the same file. They can only coexist safely if a test pins
    them together.
    """

    def test_extensions_block_matches_languages_block(self, raw_config):
        legacy = raw_config["extensions"]
        derived = extension_map()
        assert derived == legacy, (
            "config/languages.json: the flat 'extensions' map and the union of "
            "per-language 'extensions' lists have diverged.\n"
            f"  only in flat map: {sorted(set(legacy) - set(derived))}\n"
            f"  only in per-language: {sorted(set(derived) - set(legacy))}"
        )

    def test_no_extension_claimed_by_two_languages(self, raw_config):
        """A duplicate claim would make detection order-dependent."""
        seen: dict[str, str] = {}
        duplicates = []
        for name, entry in raw_config["languages"].items():
            for ext in entry["extensions"]:
                if ext in seen:
                    duplicates.append(f"{ext}: {seen[ext]} and {name}")
                seen[ext] = name
        assert not duplicates, f"extensions claimed by multiple languages: {duplicates}"

    def test_skip_dirs_round_trips(self, raw_config):
        assert skip_dirs() == frozenset(raw_config["skip_dirs"])


class TestRegistryShape:
    def test_every_language_is_enabled_and_named_consistently(self):
        for name, spec in load_registry().items():
            assert spec.name == name
            assert spec.extensions, f"{name} claims no extensions"
            assert spec.parser_mode in ("inprocess", "subprocess"), (
                f"{name} has unknown parser mode {spec.parser_mode!r}"
            )

    def test_python_is_the_only_inprocess_parser(self):
        """Documents the asymmetry the parser dispatch depends on."""
        inprocess = [n for n, s in load_registry().items() if s.parser_mode == "inprocess"]
        assert inprocess == ["python"]

    def test_every_subprocess_parser_script_exists_on_disk(self):
        """A registry entry pointing at a missing script is a latent crash."""
        missing = []
        for name, spec in load_registry().items():
            if spec.parser_mode != "subprocess":
                continue
            path = parser_script_path(name)
            assert path is not None, f"{name} is subprocess-mode but declares no script"
            if not path.is_file():
                missing.append(f"{name} -> {path}")
        assert not missing, f"declared parser scripts not found: {missing}"

    def test_inprocess_parser_declares_no_script(self):
        assert parser_script_path("python") is None

    def test_only_javascript_declares_a_bootstrap(self):
        """The npm bootstrap is JS-specific; a stray one elsewhere is a bug."""
        boots = {n: s.bootstrap for n, s in load_registry().items() if s.bootstrap}
        assert boots == {"javascript": "npm"}


class TestSupportedLanguages:
    def test_matches_the_known_set(self):
        assert supported_languages() == [
            "c", "go", "javascript", "php", "python", "ruby", "zig",
        ]

    def test_is_sorted_and_deterministic(self):
        assert supported_languages() == sorted(supported_languages())
        assert supported_languages() == supported_languages()

    def test_rust_is_not_supported(self):
        """parsers/rust/ contains only __pycache__ and is untracked by git.

        It has no config entry and no dispatch branch, so it must not appear as
        a supported language. Pinned so a stray directory can't imply support.
        """
        assert "rust" not in supported_languages()


class TestLanguageForPath:
    @pytest.mark.parametrize("path,expected", [
        ("app/main.py", "python"),
        ("src/index.js", "javascript"),
        ("src/index.ts", "javascript"),
        ("cmd/root.go", "go"),
        ("lib/parse.c", "c"),
        ("lib/parse.hpp", "c"),
        ("app/models.rb", "ruby"),
        ("public/index.php", "php"),
        ("src/main.zig", "zig"),
        ("README.md", None),
        ("Makefile", None),
    ])
    def test_resolves_by_extension(self, path, expected):
        assert language_for_path(path) == expected

    def test_is_case_insensitive(self):
        assert language_for_path("SRC/MAIN.PY") == "python"


class TestFenceForPath:
    """Fence resolution is per-file, which fixes a live bug.

    ``.ts`` files are currently fenced as ``javascript`` because the reporter
    passes the scan-wide language rather than the file's extension.
    """

    @pytest.mark.parametrize("path,expected", [
        ("src/app.py", "python"),
        ("src/app.js", "javascript"),
        ("src/app.ts", "typescript"),
        ("src/app.tsx", "typescript"),
        ("src/app.jsx", "javascript"),
        ("cmd/main.go", "go"),
        ("lib/a.c", "c"),
        ("lib/a.h", "c"),
        ("lib/a.cpp", "cpp"),
        ("lib/a.cc", "cpp"),
        ("app/m.rb", "ruby"),
        ("i.php", "php"),
        ("main.zig", "zig"),
    ])
    def test_resolves_by_extension(self, path, expected):
        assert fence_for_path(path) == expected

    def test_unknown_extension_uses_fallback_language(self):
        assert fence_for_path("unknown", fallback="python") == "python"

    def test_unknown_extension_with_dict_fence_fallback_uses_default(self):
        """A fallback of 'javascript' must yield the '*' entry, not crash."""
        assert fence_for_path("unknown", fallback="javascript") == "javascript"
        assert fence_for_path("unknown", fallback="c") == "c"

    def test_unknown_everything_returns_empty_string(self):
        """An empty fence tag is valid Markdown — degrade, don't raise."""
        assert fence_for_path("unknown") == ""
        assert fence_for_path("unknown", fallback="cobol") == ""


class TestDockerTemplate:
    def test_known_templates(self):
        assert docker_template_for("python") == "python"
        assert docker_template_for("javascript") == "node"
        assert docker_template_for("go") == "go"

    def test_languages_without_a_template_return_none(self):
        """None means SKIP. Callers must not fall back to a guess.

        Falling back to the previous default ("Python") generated a Python
        Dockerfile for a C finding — an LLM call with a guaranteed-failing
        result.
        """
        assert docker_template_for("c") is None
        assert docker_template_for("zig") is None

    def test_unknown_language_returns_none(self):
        assert docker_template_for("cobol") is None


class TestNoDriftInOtherDescriptions:
    """The four-way drift guard. These are the tests that earn the refactor."""

    def test_argparse_choices_match_registry(self):
        """Both `scan` and `parse` subparsers must offer exactly the registry."""
        from openant.cli import build_parser

        parser = build_parser()
        subparsers = [
            action for action in parser._actions
            if hasattr(action, "choices") and isinstance(action.choices, dict)
        ]
        assert subparsers, "no subparsers found on the CLI parser"

        expected = ["auto", *supported_languages()]
        checked = []
        for sub in subparsers:
            for cmd_name, cmd_parser in sub.choices.items():
                for action in cmd_parser._actions:
                    if action.dest == "language" and action.choices:
                        assert list(action.choices) == expected, (
                            f"`{cmd_name} --language` choices drifted from the registry: "
                            f"{list(action.choices)} != {expected}"
                        )
                        checked.append(cmd_name)

        assert sorted(checked) == ["parse", "scan"], (
            f"expected scan and parse to constrain --language, checked: {checked}"
        )

    def test_readme_documents_every_supported_language(self):
        """This is exactly how Zig got dropped from the docs."""
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        section = re.search(
            r"##\s*Supported languages\s*\n(.*?)(?=\n##\s)", readme, re.DOTALL
        )
        assert section, "README.md has no '## Supported languages' section"
        body = section.group(1).lower()

        missing = [lang for lang in supported_languages() if lang not in body]
        assert not missing, (
            f"README 'Supported languages' section omits: {missing}. "
            "Every registry language must be documented."
        )

    # Docs inside libs/openant-core that state the supported-language set as a
    # LIVE claim about current capability. Enumerated repo-wide rather than
    # taken from the one or two files a reviewer happened to name — the whole
    # point of this guard is that partial enumeration is how the drift started.
    #
    # Deliberately excluded, with reasons:
    #   parsers/javascript/PARSER_UPGRADE_PLAN.md — scopes CodeQL query packs
    #     for the JS parser, a different quantity than OpenAnt's supported set.
    #   CURRENT_IMPLEMENTATION.md — its only enumeration ("the same prompt is
    #     used for Python, JavaScript, and Go") was reworded to "every
    #     supported language", so it now makes no enumerated claim to guard.
    #     Re-add it if an enumeration reappears.
    LANGUAGE_CLAIM_DOCS = [
        "CLAUDE.md",
        "README.md",
        "PIPELINE_MANUAL.md",
        "DOCUMENTATION.md",
        "OPENANT.md",
    ]

    # Phrasings that assert a supported/applicable language SET. Kept broader
    # than "Supports X" because the drift does not confine itself to one
    # sentence shape: the instance this guard originally missed read "the same
    # prompt is used for Python, JavaScript, and Go" — an enumeration that
    # reads as exhaustive without ever using the word "supports".
    _CLAIM_PATTERNS = [
        r"supports? python",
        r"supported languages:",
        r"used for python",
        r"works (?:with|on) python",
        r"languages?:\s*python",
    ]

    @pytest.mark.parametrize("doc", LANGUAGE_CLAIM_DOCS)
    def test_core_docs_do_not_understate_supported_languages(self, doc):
        """A doc may summarise, but must not assert a set that omits languages.

        The failure mode is a sentence like "Supports Python,
        JavaScript/TypeScript, and Go" written when three languages were all
        there were, and never revisited as four more landed. Such a sentence
        reads as authoritative and is wrong.
        """
        path = CORE_ROOT / doc
        assert path.is_file(), f"{doc} not found at {path}"
        text = path.read_text(encoding="utf-8").lower()

        pattern = "|".join(self._CLAIM_PATTERNS)
        claims = [
            line.strip() for line in text.splitlines() if re.search(pattern, line)
        ]

        # A doc listed here that matches NOTHING means the patterns went stale,
        # not that the doc became safe. Skipping would let the guard be
        # defeated by the very rewording it exists to catch, so fail instead
        # and force either a pattern update or removal from the list.
        assert claims, (
            f"{doc} is listed as making a supported-language claim, but no "
            f"claim phrasing matched. Either the wording changed (extend "
            f"_CLAIM_PATTERNS) or the claim is gone (drop {doc} from "
            f"LANGUAGE_CLAIM_DOCS). Do not leave this silently unguarded."
        )

        for claim in claims:
            missing = [lang for lang in supported_languages() if lang not in claim]
            assert not missing, (
                f"{doc} asserts a supported-language set omitting {missing}:\n"
                f"  {claim}\n"
                "Either list every registry language or reword so it does not "
                "read as an exhaustive set."
            )

    def test_go_flag_help_is_derived_not_hardcoded(self):
        """Go help text must not hardcode a language list.

        A literal list in the help string is what let scan.go and parse.go fall
        behind config. Assert the Go sources call the shared helper instead.
        """
        cmd_dir = REPO_ROOT / "apps" / "openant-cli" / "cmd"
        offenders = []
        for filename in ("init.go", "scan.go", "parse.go"):
            path = cmd_dir / filename
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            # Only single-line string literals that read like flag help — i.e.
            # mention "Language" and then enumerate names. Import paths and
            # multi-line code blobs are not help text and must not match.
            for match in re.finditer(r'"(Language[^"\n]*)"', text):
                literal = match.group(1)
                # A literal naming two or more languages is a hardcoded list.
                named = [lang for lang in supported_languages() if lang in literal]
                if len(named) >= 2:
                    offenders.append(f"{filename}: {literal!r}")
        assert not offenders, (
            "hardcoded language lists found in Go flag help; derive from "
            f"internal/languages.FlagHelp() instead: {offenders}"
        )
