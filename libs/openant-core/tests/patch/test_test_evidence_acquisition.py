"""Tests for bounded, deterministic, generic repository-evidence
acquisition.

Key invariant under test throughout: this module GATHERS evidence, it
never DECIDES a test command -- there is no assertion anywhere in this
file (or in the module) of the shape "X file present -> command is Y".
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import utilities.autopatcher.test_evidence_acquisition as evidence_mod
from utilities.autopatcher.test_evidence_acquisition import (
    _MAX_RAW_READ_BYTES,
    _MAX_TOTAL_BYTES,
    _fit_within_budget,
    _read_bounded_text,
    gather_test_plan_evidence,
)


class TestConfigFiles:
    def test_pyproject_toml_content_included(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        names = [name for name, _ in bundle.present_config_files]
        assert "pyproject.toml" in names

    def test_package_json_scripts_engines_and_dependencies_extracted(self, tmp_path: Path):
        """Setup-command grounding (test_plan_discovery.py) needs to see
        declared dependencies, not just scripts/engines -- see
        _package_json_relevant_fields's docstring for the real minimist
        run this fixes. `name`/`version` remain excluded -- they carry no
        test-plan signal."""
        (tmp_path / "package.json").write_text(json.dumps({
            "name": "demo", "version": "1.0.0",
            "dependencies": {"some-lib": "0.0.1"},
            "devDependencies": {"tap": "~0.4.0"},
            "scripts": {"test": "jest"},
            "engines": {"node": ">=18"},
        }), encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        content = dict(bundle.present_config_files)["package.json"]
        assert "jest" in content
        assert "engines" in content
        assert "dependencies" in content and "some-lib" in content
        assert "devDependencies" in content and "tap" in content
        assert "demo" not in content  # name/version still excluded -- no test-plan signal

    def test_package_manager_field_extracted(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(json.dumps({
            "scripts": {"test": "jest"}, "packageManager": "yarn@3.2.0",
        }), encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        content = dict(bundle.present_config_files)["package.json"]
        assert "yarn@3.2.0" in content

    def test_package_json_with_only_dependencies_still_produces_evidence(self, tmp_path: Path):
        """Confirms dependencies/devDependencies are each independently
        sufficient to produce evidence, not merely additive alongside
        scripts/engines."""
        (tmp_path / "package.json").write_text(json.dumps({
            "devDependencies": {"tap": "~0.4.0"},
        }), encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        names = [name for name, _ in bundle.present_config_files]
        assert "package.json" in names

    def test_absent_files_not_listed(self, tmp_path: Path):
        bundle = gather_test_plan_evidence(tmp_path)
        assert bundle.present_config_files == ()

    def test_malformed_package_json_does_not_crash(self, tmp_path: Path):
        (tmp_path / "package.json").write_text("{not valid json", encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        names = [name for name, _ in bundle.present_config_files]
        assert "package.json" not in names

    def test_large_file_content_is_bounded(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("x = 1\n" * 10_000, encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        content = dict(bundle.present_config_files)["pyproject.toml"]
        assert len(content) < 5000

    def test_requirements_txt_variants_included(self, tmp_path: Path):
        for name in ("requirements.txt", "requirements-dev.txt", "requirements-test.txt",
                     "dev-requirements.txt", "test-requirements.txt"):
            (tmp_path / name).write_text("flask==2.0\n", encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        names = {n for n, _ in bundle.present_config_files}
        assert names == {
            "requirements.txt", "requirements-dev.txt", "requirements-test.txt",
            "dev-requirements.txt", "test-requirements.txt",
        }

    def test_pipfile_included(self, tmp_path: Path):
        (tmp_path / "Pipfile").write_text("[packages]\nflask = \"*\"\n", encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        assert "Pipfile" in dict(bundle.present_config_files)

    def test_requirements_txt_evidence_is_not_a_command_decision(self, tmp_path: Path):
        """Adding requirements.txt as evidence must not come bundled with
        any inferred command -- the bundle exposes no such thing."""
        (tmp_path / "requirements.txt").write_text("pytest\n", encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        assert not hasattr(bundle, "install_command")
        assert not hasattr(bundle, "test_command")


class TestLockfiles:
    def test_lockfile_presence_recorded_without_content(self, tmp_path: Path):
        (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3}' * 1000, encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        assert "package-lock.json" in bundle.present_lockfiles
        assert all("package-lock.json" != name for name, _ in bundle.present_config_files)


class TestCiSnippets:
    def test_workflow_with_test_keyword_included(self, tmp_path: Path):
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text("jobs:\n  test:\n    steps:\n      - run: pytest\n", encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        assert any(path.endswith("ci.yml") for path, _ in bundle.ci_snippets)

    def test_workflow_without_test_keyword_excluded(self, tmp_path: Path):
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "publish.yml").write_text("jobs:\n  publish:\n    steps:\n      - run: deploy.sh\n", encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        assert bundle.ci_snippets == ()

    def test_bounded_number_of_ci_files(self, tmp_path: Path):
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        for i in range(5):
            (wf / f"ci{i}.yml").write_text("jobs:\n  test:\n    steps: [pytest]\n", encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        assert len(bundle.ci_snippets) <= 2

    def test_missing_workflows_dir_does_not_crash(self, tmp_path: Path):
        bundle = gather_test_plan_evidence(tmp_path)
        assert bundle.ci_snippets == ()

    def test_relevant_step_after_original_truncation_boundary_is_preserved(self, tmp_path: Path):
        """Direct regression anchor for the real replay finding: a real
        urllib3-shaped CI workflow whose actual test-execution step sits
        well past the original naive `text[:_MAX_CI_BYTES]` boundary --
        that step must now be preserved, not silently cut off."""
        from utilities.autopatcher.test_evidence_acquisition import _MAX_CI_BYTES

        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        boilerplate = "\n".join(f"  # unrelated CI boilerplate line {i}" for i in range(400))
        content = (
            "name: CI\n"
            "on: [push, pull_request]\n"
            "jobs:\n"
            "  build:\n"
            f"{boilerplate}\n"
            "  test:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v3\n"
            "      - name: Run the test suite\n"
            "        run: nox -s test\n"
        )
        assert len(content) > _MAX_CI_BYTES  # the original bug's precondition
        assert content.index("nox -s test") > _MAX_CI_BYTES  # past the old head-only boundary
        (wf / "ci.yml").write_text(content, encoding="utf-8")

        bundle = gather_test_plan_evidence(tmp_path)
        snippet = dict(bundle.ci_snippets)[".github/workflows/ci.yml"]
        assert "nox -s test" in snippet
        assert len(snippet) <= _MAX_CI_BYTES + 100  # still bounded

    def test_beginning_only_boilerplate_does_not_consume_the_entire_budget(self, tmp_path: Path):
        """The unrelated preamble must not be what fills the budget --
        the relevant step must survive even when the preamble ALONE would
        already exceed the per-item cap on its own."""
        from utilities.autopatcher.test_evidence_acquisition import _MAX_CI_BYTES

        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        # Many short, ordinary boilerplate LINES (realistic YAML shape) --
        # their combined size alone already exceeds the per-item cap.
        boilerplate = "\n".join(f"  # unrelated boilerplate line {i}" for i in range(2000))
        assert len(boilerplate) > _MAX_CI_BYTES * 3
        content = boilerplate + "\njobs:\n  test:\n    steps:\n      - run: pytest -v\n"
        (wf / "ci.yml").write_text(content, encoding="utf-8")

        bundle = gather_test_plan_evidence(tmp_path)
        snippet = dict(bundle.ci_snippets)[".github/workflows/ci.yml"]
        assert "pytest -v" in snippet

    def test_multiple_relevant_sections_remain_bounded(self, tmp_path: Path):
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        filler = "\n".join(f"  # filler {i}" for i in range(200))
        content = (
            "jobs:\n"
            "  test-py38:\n"
            "    steps:\n      - run: pytest -k py38\n"
            f"{filler}\n"
            "  test-py311:\n"
            "    steps:\n      - run: pytest -k py311\n"
            f"{filler}\n"
        )
        from utilities.autopatcher.test_evidence_acquisition import _MAX_CI_BYTES
        (wf / "ci.yml").write_text(content, encoding="utf-8")

        bundle = gather_test_plan_evidence(tmp_path)
        snippet = dict(bundle.ci_snippets)[".github/workflows/ci.yml"]
        assert "pytest -k py38" in snippet
        assert "pytest -k py311" in snippet
        assert len(snippet) <= _MAX_CI_BYTES + 100

    def test_provenance_file_name_intact(self, tmp_path: Path):
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        boilerplate = "\n".join(f"# line {i}" for i in range(500))
        (wf / "ci.yml").write_text(f"{boilerplate}\njobs:\n  test:\n    steps:\n      - run: pytest\n", encoding="utf-8")

        bundle = gather_test_plan_evidence(tmp_path)
        assert ".github/workflows/ci.yml" in bundle.citable_identifiers
        names = [path for path, _ in bundle.ci_snippets]
        assert names == [".github/workflows/ci.yml"]

    def test_non_python_shaped_workflow_relevant_section_preserved(self, tmp_path: Path):
        """Generic across ecosystems -- not Python/pytest-specific. A
        Node-shaped CI workflow with a large, unrelated preamble (lint,
        build matrix, docs) before the actual `npm test` step."""
        from utilities.autopatcher.test_evidence_acquisition import _MAX_CI_BYTES

        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        boilerplate = "\n".join(f"  # node ci boilerplate line {i}" for i in range(400))
        content = (
            "name: Node CI\n"
            "jobs:\n"
            "  lint-and-build:\n"
            f"{boilerplate}\n"
            "  test:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/setup-node@v3\n"
            "      - name: Run tests\n"
            "        run: npm test\n"
        )
        assert content.index("npm test") > _MAX_CI_BYTES
        (wf / "ci.yml").write_text(content, encoding="utf-8")

        bundle = gather_test_plan_evidence(tmp_path)
        snippet = dict(bundle.ci_snippets)[".github/workflows/ci.yml"]
        assert "npm test" in snippet


class TestRelevanceFilteredExcerptOnConfigFiles:
    """The SAME relevance-aware bounding used for CI files also applies
    to config-file truncation (_read_bounded) -- e.g. a large noxfile.py
    whose actual `test` session sits after several unrelated sessions
    (lint, docs, mypy)."""

    def test_noxfile_test_session_preserved_past_original_truncation_boundary(self, tmp_path: Path):
        from utilities.autopatcher.test_evidence_acquisition import _MAX_FILE_BYTES

        unrelated_sessions = "\n\n".join(
            f"@nox.session\ndef lint_variant_{i}(session):\n    session.run('flake8')"
            for i in range(150)
        )
        content = (
            "import nox\n\n"
            f"{unrelated_sessions}\n\n"
            "@nox.session\n"
            "def test(session):\n"
            "    session.run('pytest', '-v', 'test/')\n"
        )
        assert len(content) > _MAX_FILE_BYTES
        assert content.index("def test(session)") > _MAX_FILE_BYTES
        (tmp_path / "noxfile.py").write_text(content, encoding="utf-8")

        bundle = gather_test_plan_evidence(tmp_path)
        content_seen = dict(bundle.present_config_files)["noxfile.py"]
        assert "def test(session)" in content_seen
        assert "pytest" in content_seen


class TestRelevanceFilteredExcerptUnit:
    """Direct unit coverage for _relevance_filtered_excerpt -- the shared
    mechanism behind both CI-file and config-file bounded truncation."""

    def test_text_within_limit_returned_unchanged(self):
        from utilities.autopatcher.test_evidence_acquisition import _relevance_filtered_excerpt
        text = "short text, no truncation needed"
        assert _relevance_filtered_excerpt(text, 1000) == text

    def test_no_relevant_line_anywhere_falls_back_to_head_only(self):
        """True "nothing test-relevant is identifiable" case -- existing
        bounded head-only fallback behavior is acceptable here."""
        from utilities.autopatcher.test_evidence_acquisition import _relevance_filtered_excerpt
        text = "\n".join(f"unrelated boilerplate line {i}" for i in range(500))
        assert len(text) > 200
        out = _relevance_filtered_excerpt(text, 200)
        assert out.startswith("unrelated boilerplate line 0")
        assert "truncated" in out
        assert len(out) <= 250

    def test_relevant_line_far_past_the_limit_is_preserved(self):
        from utilities.autopatcher.test_evidence_acquisition import _relevance_filtered_excerpt
        boilerplate = "\n".join(f"unrelated line {i}" for i in range(500))
        text = boilerplate + "\nrun: pytest -v\n" + boilerplate
        assert text.index("pytest") > 3000
        out = _relevance_filtered_excerpt(text, 3000)
        assert "pytest -v" in out
        assert len(out) <= 3100

    def test_bounded_surrounding_context_included(self):
        from utilities.autopatcher.test_evidence_acquisition import _relevance_filtered_excerpt
        boilerplate = "\n".join(f"unrelated line {i}" for i in range(500))
        text = boilerplate + "\nname: Run tests\nrun: |\n  pytest -v\n" + boilerplate
        out = _relevance_filtered_excerpt(text, 3000)
        assert "name: Run tests" in out
        assert "pytest -v" in out


class TestDirectoryListing:
    def test_top_level_entries_present(self, tmp_path: Path):
        (tmp_path / "tests").mkdir()
        (tmp_path / "src").mkdir()
        bundle = gather_test_plan_evidence(tmp_path)
        assert any(e.startswith("tests") for e in bundle.directory_listing)
        assert any(e.startswith("src") for e in bundle.directory_listing)

    def test_ignored_directories_excluded(self, tmp_path: Path):
        (tmp_path / "node_modules").mkdir()
        (tmp_path / ".git").mkdir()
        bundle = gather_test_plan_evidence(tmp_path)
        assert not any("node_modules" in e for e in bundle.directory_listing)
        assert not any(".git" in e for e in bundle.directory_listing)

    def test_bounded_entry_count(self, tmp_path: Path):
        for i in range(500):
            (tmp_path / f"file_{i}.txt").write_text("x", encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        assert len(bundle.directory_listing) <= 200


class TestReadmeExcerpt:
    def test_testing_section_extracted(self, tmp_path: Path):
        (tmp_path / "README.md").write_text(
            "# Demo\n\nSome intro.\n\n## Testing\n\nRun `pytest` to run tests.\n\n## License\n\nMIT\n",
            encoding="utf-8",
        )
        bundle = gather_test_plan_evidence(tmp_path)
        assert bundle.readme_excerpt is not None
        assert "pytest" in bundle.readme_excerpt
        assert "License" not in bundle.readme_excerpt
        assert bundle.readme_source == "README.md"

    def test_no_matching_heading_returns_none(self, tmp_path: Path):
        (tmp_path / "README.md").write_text("# Demo\n\nJust a description.\n", encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        assert bundle.readme_excerpt is None
        assert bundle.readme_source is None

    def test_missing_readme_does_not_crash(self, tmp_path: Path):
        bundle = gather_test_plan_evidence(tmp_path)
        assert bundle.readme_excerpt is None
        assert bundle.readme_source is None

    def test_readme_source_is_a_citable_identifier(self, tmp_path: Path):
        (tmp_path / "README.md").write_text("# Demo\n\n## Testing\n\npytest\n", encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        assert "README.md" in bundle.citable_identifiers


class TestBudgetAndEmptiness:
    def test_empty_repo_is_empty(self, tmp_path: Path):
        bundle = gather_test_plan_evidence(tmp_path)
        assert bundle.is_empty is True

    def test_nonexistent_repo_root_does_not_crash(self, tmp_path: Path):
        bundle = gather_test_plan_evidence(tmp_path / "does-not-exist")
        assert bundle.is_empty is True

    def test_non_empty_when_any_evidence_present(self, tmp_path: Path):
        (tmp_path / "go.mod").write_text("module demo\n\ngo 1.22\n", encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        assert bundle.is_empty is False

    def test_prompt_text_never_includes_full_repository(self, tmp_path: Path):
        """A large source file unrelated to test configuration must never
        appear in the rendered evidence text."""
        (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
        (tmp_path / "app.py").write_text("SECRET_MARKER_NOT_EVIDENCE = 1\n" * 100, encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        text = bundle.to_prompt_text()
        assert "SECRET_MARKER_NOT_EVIDENCE" not in text

    def test_never_decides_a_command(self, tmp_path: Path):
        """The evidence bundle is pure data -- it must expose no method or
        attribute that could be read as 'the' command."""
        (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        assert not hasattr(bundle, "test_command")
        assert not hasattr(bundle, "command")


class TestCitableIdentifiers:
    def test_config_file_is_citable(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        assert "pyproject.toml" in bundle.citable_identifiers

    def test_lockfile_is_citable(self, tmp_path: Path):
        (tmp_path / "poetry.lock").write_text("[[package]]\n", encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        assert "poetry.lock" in bundle.citable_identifiers

    def test_ci_snippet_is_citable(self, tmp_path: Path):
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text("jobs:\n  test:\n    steps: [pytest]\n", encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        assert ".github/workflows/ci.yml" in bundle.citable_identifiers

    def test_directory_listing_entry_is_citable(self, tmp_path: Path):
        (tmp_path / "tests").mkdir()
        bundle = gather_test_plan_evidence(tmp_path)
        assert "tests/" in bundle.citable_identifiers

    def test_file_never_shown_is_not_citable(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        assert "tox.ini" not in bundle.citable_identifiers


class TestBoundedReadsDoNotLoadArbitrarilyLargeFiles:
    def test_read_bounded_text_never_exceeds_raw_limit(self, tmp_path: Path):
        huge = tmp_path / "huge.toml"
        huge.write_text("x" * (_MAX_RAW_READ_BYTES * 4), encoding="utf-8")
        text = _read_bounded_text(huge, raw_limit=_MAX_RAW_READ_BYTES)
        assert text is not None
        assert len(text) <= _MAX_RAW_READ_BYTES

    def test_oversized_config_file_is_not_fully_read(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("x" * 5_000_000, encoding="utf-8")  # 5 MB
        bundle = gather_test_plan_evidence(tmp_path)
        content = dict(bundle.present_config_files)["pyproject.toml"]
        assert len(content) < 5000

    def test_oversized_package_json_degrades_without_crashing(self, tmp_path: Path):
        huge_scripts = {"scripts": {f"task{i}": "x" * 1000 for i in range(2000)}}
        (tmp_path / "package.json").write_text(json.dumps(huge_scripts), encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        names = {n for n, _ in bundle.present_config_files}
        if "package.json" in names:
            assert len(dict(bundle.present_config_files)["package.json"]) <= 4096

    def test_oversized_ci_workflow_bounded(self, tmp_path: Path):
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text("test pytest\n" + "x" * 1_000_000, encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        assert bundle.ci_snippets
        _, content = bundle.ci_snippets[0]
        assert len(content) < 5000

    def test_oversized_readme_bounded(self, tmp_path: Path):
        (tmp_path / "README.md").write_text(
            "# Demo\n\n## Testing\n\n" + "x" * 1_000_000, encoding="utf-8",
        )
        bundle = gather_test_plan_evidence(tmp_path)
        assert bundle.readme_excerpt is not None
        assert len(bundle.readme_excerpt) <= 1500


class TestFitWithinBudget:
    """Direct tests of the priority-ordered greedy accumulator."""

    def test_readme_dropped_when_it_alone_exceeds_remaining_budget(self):
        with mock.patch.object(evidence_mod, "_MAX_TOTAL_BYTES", 110):
            config = (("a.toml", "x" * 50),)     # cost 56
            ci = ((".b.yml", "y" * 40),)         # cost 46
            readme = ("README.md", "z" * 40)     # cost 49 -- doesn't fit remaining 8
            kept_config, kept_dirs, kept_ci, kept_readme, truncated = _fit_within_budget(
                config, (), ci, readme,
            )
        assert kept_config == config
        assert kept_ci == ci
        assert kept_readme is None
        assert truncated is True

    def test_ci_and_readme_both_dropped_when_budget_very_tight(self):
        with mock.patch.object(evidence_mod, "_MAX_TOTAL_BYTES", 60):
            config = (("a.toml", "x" * 50),)     # cost 56 -- fits, leaves 4
            ci = ((".b.yml", "y" * 40),)         # cost 46 -- does not fit in 4
            readme = ("README.md", "z" * 40)     # cost 49 -- does not fit either
            kept_config, kept_dirs, kept_ci, kept_readme, truncated = _fit_within_budget(
                config, (), ci, readme,
            )
        assert kept_config == config
        assert kept_ci == ()
        assert kept_readme is None
        assert truncated is True

    def test_nothing_dropped_when_everything_fits(self):
        config = (("a.toml", "x" * 10),)
        ci = ((".b.yml", "y" * 10),)
        readme = ("README.md", "z" * 10)
        kept_config, kept_dirs, kept_ci, kept_readme, truncated = _fit_within_budget(
            config, ("dir1/",), ci, readme,
        )
        assert kept_config == config
        assert kept_ci == ci
        assert kept_readme == readme
        assert truncated is False

    def test_final_evidence_size_guarantee_under_pathological_input(self, tmp_path: Path):
        """Stuff oversized content into every category at once and prove
        the RENDERED bundle's total item content never exceeds
        _MAX_TOTAL_BYTES, aside from the small fixed markdown-header
        overhead in to_prompt_text -- this is the advertised budget
        actually holding, not merely each item being individually capped."""
        from utilities.autopatcher.test_evidence_acquisition import _CONFIG_FILES
        for name in _CONFIG_FILES:
            if name == "package.json":
                continue
            (tmp_path / name).write_text("x" * 100_000, encoding="utf-8")
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        for i in range(5):
            (wf / f"ci{i}.yml").write_text("test\n" + "y" * 100_000, encoding="utf-8")
        (tmp_path / "README.md").write_text("# Demo\n\n## Testing\n\n" + "z" * 100_000, encoding="utf-8")
        for i in range(500):
            (tmp_path / f"dirent_{i}").write_text("q", encoding="utf-8")

        bundle = gather_test_plan_evidence(tmp_path)

        item_total = (
            sum(len(n) + len(c) for n, c in bundle.present_config_files)
            + sum(len(n) + len(c) for n, c in bundle.ci_snippets)
            + sum(len(e) for e in bundle.directory_listing)
            + len(bundle.readme_excerpt or "")
        )
        assert item_total <= _MAX_TOTAL_BYTES
        assert bundle.truncated is True

    def test_truncated_flag_false_when_everything_fits(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
        bundle = gather_test_plan_evidence(tmp_path)
        assert bundle.truncated is False
