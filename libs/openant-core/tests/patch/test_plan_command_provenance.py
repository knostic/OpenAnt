"""Tests for the evidence-backed repository-owned command provenance
check (test_plan_command_provenance.py) -- isolated from the LLM/
discovery plumbing, exercising the deterministic filesystem-safety and
command-level-evidence-grounding algorithm directly."""

from __future__ import annotations

import os

from utilities.autopatcher.test_evidence_acquisition import EvidenceBundle
from utilities.autopatcher.test_plan_command_provenance import resolve_repository_owned_commands


def _evidence(
    *, config_files=(), ci_snippets=(), directory_listing=(), readme_excerpt=None, readme_source=None,
) -> EvidenceBundle:
    return EvidenceBundle(
        present_config_files=tuple(config_files),
        present_lockfiles=(),
        ci_snippets=tuple(ci_snippets),
        directory_listing=tuple(directory_listing),
        readme_source=readme_source,
        readme_excerpt=readme_excerpt,
        truncated=False,
    )


class TestNonRepoRelativeTokensAreUntouched:
    """Only "./"-prefixed argv[0] tokens are this module's concern --
    everything else (bare binaries, absolute paths, "../" traversal) is
    left completely alone, deferring entirely to
    test_plan_validation's existing static allowlist."""

    def test_bare_binary_is_ignored_not_trusted(self, tmp_path):
        trusted, reason = resolve_repository_owned_commands(
            (("curl", "http://evil.example"),), tmp_path, _evidence(),
        )
        assert trusted == frozenset()
        assert reason is None

    def test_absolute_path_is_ignored_not_trusted(self, tmp_path):
        (tmp_path / "script.sh").write_text("#!/bin/sh\n")
        trusted, reason = resolve_repository_owned_commands(
            ((str(tmp_path / "script.sh"),),), tmp_path,
            _evidence(config_files=[("x.txt", str(tmp_path / "script.sh"))]),
        )
        assert trusted == frozenset()
        assert reason is None

    def test_parent_traversal_without_dot_slash_prefix_is_ignored_not_trusted(self, tmp_path):
        trusted, reason = resolve_repository_owned_commands(
            (("../outside.sh",),), tmp_path, _evidence(config_files=[("x.txt", "../outside.sh")]),
        )
        assert trusted == frozenset()
        assert reason is None

    def test_empty_command_is_skipped(self, tmp_path):
        trusted, reason = resolve_repository_owned_commands(((),), tmp_path, _evidence())
        assert trusted == frozenset()
        assert reason is None


class TestAcceptRealGitPythonShape:
    def test_evidenced_script_in_ci_content_is_accepted(self, tmp_path):
        (tmp_path / "init-tests-after-clone.sh").write_text("#!/bin/sh\necho hi\n")
        evidence = _evidence(
            ci_snippets=[(".github/workflows/alpine-test.yml", "run: ./init-tests-after-clone.sh\n")],
        )
        trusted, reason = resolve_repository_owned_commands(
            (("./init-tests-after-clone.sh",),), tmp_path, evidence,
        )
        assert reason is None
        assert trusted == frozenset({"./init-tests-after-clone.sh"})

    def test_a_second_differently_named_and_differently_evidenced_script_is_also_accepted(self, tmp_path):
        """Proves genericity -- this is not GitPython-specific. Evidenced
        via config-file content (a Makefile) instead of CI, and nested
        under a subdirectory, matching the "./tools/ci.py"-style future
        shapes this architecture must support without any per-path code."""
        (tmp_path / "tools").mkdir()
        (tmp_path / "tools" / "ci.py").write_text("#!/usr/bin/env python\nprint('ci')\n")
        evidence = _evidence(config_files=[("Makefile", "test:\n\t./tools/ci.py\n")])
        trusted, reason = resolve_repository_owned_commands(
            (("./tools/ci.py",),), tmp_path, evidence,
        )
        assert reason is None
        assert trusted == frozenset({"./tools/ci.py"})

    def test_evidenced_via_readme_excerpt_is_accepted(self, tmp_path):
        (tmp_path / "dev-test.sh").write_text("#!/bin/sh\n")
        evidence = _evidence(readme_source="README.md", readme_excerpt="Run `./dev-test.sh` to test.")
        trusted, reason = resolve_repository_owned_commands(
            (("./dev-test.sh",),), tmp_path, evidence,
        )
        assert reason is None
        assert trusted == frozenset({"./dev-test.sh"})

    def test_multiple_commands_each_independently_checked(self, tmp_path):
        (tmp_path / "a.sh").write_text("#!/bin/sh\n")
        (tmp_path / "b.sh").write_text("#!/bin/sh\n")
        evidence = _evidence(config_files=[("Makefile", "./a.sh\n./b.sh\n")])
        trusted, reason = resolve_repository_owned_commands(
            (("./a.sh",), ("./b.sh", "--flag")), tmp_path, evidence,
        )
        assert reason is None
        assert trusted == frozenset({"./a.sh", "./b.sh"})


class TestRejectNonexistentScript:
    def test_evidenced_but_missing_file_is_rejected(self, tmp_path):
        evidence = _evidence(ci_snippets=[("ci.yml", "run: ./does-not-exist.sh\n")])
        trusted, reason = resolve_repository_owned_commands(
            (("./does-not-exist.sh",),), tmp_path, evidence,
        )
        assert trusted == frozenset()
        assert reason is not None
        assert "does not exist" in reason


class TestRejectTraversalWithDotSlashPrefix:
    def test_dot_slash_dot_dot_traversal_rejected(self, tmp_path):
        (tmp_path / "child").mkdir()
        outside = tmp_path.parent / "outside.sh"
        outside.write_text("#!/bin/sh\n")
        try:
            evidence = _evidence(config_files=[("x.txt", "./child/../../outside.sh\n")])
            trusted, reason = resolve_repository_owned_commands(
                (("./child/../../outside.sh",),), tmp_path, evidence,
            )
            assert trusted == frozenset()
            assert reason is not None
            assert "'..'" in reason
        finally:
            outside.unlink(missing_ok=True)


class TestRejectSymlinkEscape:
    def test_symlink_resolving_outside_repo_root_is_rejected(self, tmp_path):
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        outside = tmp_path / "outside.sh"
        outside.write_text("#!/bin/sh\necho outside\n")
        link = repo_root / "escape.sh"
        os.symlink(outside, link)
        evidence = _evidence(config_files=[("x.txt", "./escape.sh\n")])
        trusted, reason = resolve_repository_owned_commands(
            (("./escape.sh",),), repo_root, evidence,
        )
        assert trusted == frozenset()
        assert reason is not None
        assert "escapes repo_root" in reason


class TestRejectExistsButNotEvidenced:
    def test_real_file_never_mentioned_in_any_evidence_content_is_rejected(self, tmp_path):
        (tmp_path / "setup_helper.sh").write_text("#!/bin/sh\n")
        trusted, reason = resolve_repository_owned_commands(
            (("./setup_helper.sh",),), tmp_path, _evidence(),
        )
        assert trusted == frozenset()
        assert reason is not None
        assert "not grounded" in reason

    def test_name_containing_test_but_present_only_in_directory_listing_is_rejected(self, tmp_path):
        """The core no-heuristic proof: despite LOOKING test-related by
        name, and despite genuinely existing, a script that is never
        mentioned in any CONTENT-bearing evidence -- only in the bare
        directory listing -- must still be rejected. Directory listing
        entries prove existence only, never test-workflow intent."""
        (tmp_path / "run_test_thing.sh").write_text("#!/bin/sh\n")
        evidence = _evidence(directory_listing=("run_test_thing.sh",))
        trusted, reason = resolve_repository_owned_commands(
            (("./run_test_thing.sh",),), tmp_path, evidence,
        )
        assert trusted == frozenset()
        assert reason is not None
        assert "not grounded" in reason

    def test_directory_is_not_a_regular_file_even_if_evidenced(self, tmp_path):
        (tmp_path / "scripts").mkdir()
        evidence = _evidence(config_files=[("x.txt", "./scripts\n")])
        trusted, reason = resolve_repository_owned_commands(
            (("./scripts",),), tmp_path, evidence,
        )
        assert trusted == frozenset()
        assert reason is not None
        assert "not a regular file" in reason


class TestCitesLegitimateFileButProposesUngroundedCommand:
    """The adversarial case: the model's `evidence` list (checked
    elsewhere, in test_plan_discovery.py's file-citation check) may
    contain a real, actually-shown file -- but that alone must never
    launder an unrelated, unevidenced command. This module only ever
    looks at the CONTENT of what was shown, never at what the model
    merely claims to have used."""

    def test_real_evidenced_file_whose_content_never_mentions_the_command_is_rejected(self, tmp_path):
        (tmp_path / "totally-fabricated-script.sh").write_text("#!/bin/sh\n")
        # package.json is real, shown evidence -- but its CONTENT says
        # nothing about the fabricated script.
        evidence = _evidence(config_files=[("package.json", '{"scripts": {"test": "jest"}}')])
        trusted, reason = resolve_repository_owned_commands(
            (("./totally-fabricated-script.sh",),), tmp_path, evidence,
        )
        assert trusted == frozenset()
        assert reason is not None
        assert "not grounded" in reason
