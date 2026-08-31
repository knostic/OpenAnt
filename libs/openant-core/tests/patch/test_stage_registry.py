"""Tests for the canonical 13-stage Auto Patcher registry
(utilities/autopatcher/stage_registry.py) -- Foundation Batch A.

Hermetic, pure-Python: no repo fixtures, no LLM, no filesystem I/O beyond
importing the module under test.
"""

from __future__ import annotations

import pytest

from utilities.autopatcher import stage_registry
from utilities.autopatcher.stage_registry import (
    CANONICAL_STAGE_ORDER,
    STAGE_DEPENDENCIES,
    STAGE_OWNED_LLM_TAGS,
    STAGE_SPECS,
    is_canonical_stage,
)

_EXPECTED_ORDER = (
    "repository_analysis_and_remediation_planning",
    "remediation_strategy",
    "guided_context_acquisition",
    "patch_generation_and_post_patch_investigation",
    "challenger",
    "patch_repair_and_calibration",
    "patch_review",
    "confidence_scoring",
    "impact_and_behavior_analysis",
    "test_analysis_and_plan",
    "existing_test_comparison",
    "trust_signals_and_recommendation",
    "report_generation",
)


class TestCanonicalStageList:
    def test_registry_contains_exactly_13_canonical_stages_in_order(self):
        assert CANONICAL_STAGE_ORDER == _EXPECTED_ORDER
        assert len(CANONICAL_STAGE_ORDER) == 13

    def test_no_duplicate_canonical_stage_names(self):
        assert len(set(CANONICAL_STAGE_ORDER)) == len(CANONICAL_STAGE_ORDER)

    def test_test_plan_discovery_is_not_a_canonical_top_level_stage(self):
        assert "test_plan_discovery" not in CANONICAL_STAGE_ORDER
        assert "test_plan_discovery" not in STAGE_SPECS
        assert not is_canonical_stage("test_plan_discovery")

    def test_no_legacy_s14_style_names(self):
        for name in CANONICAL_STAGE_ORDER:
            assert not name.lower().startswith("s1"), name
            assert "14a" not in name and "14b" not in name

    def test_stage_specs_keys_match_canonical_order_exactly(self):
        assert set(STAGE_SPECS.keys()) == set(CANONICAL_STAGE_ORDER)


class TestDependencyGraph:
    def test_every_stage_has_explicit_dependencies_declared(self):
        for name in CANONICAL_STAGE_ORDER:
            assert name in STAGE_DEPENDENCIES
            assert isinstance(STAGE_DEPENDENCIES[name], tuple)

    def test_every_dependency_refers_to_a_registered_stage(self):
        for name, deps in STAGE_DEPENDENCIES.items():
            for dep in deps:
                assert dep in STAGE_SPECS, f"{name!r} depends on unregistered stage {dep!r}"

    def test_dependency_graph_is_acyclic(self):
        """Kahn's algorithm: a valid topological order must exist."""
        remaining = {name: set(deps) for name, deps in STAGE_DEPENDENCIES.items()}
        ordered = []
        while remaining:
            ready = [name for name, deps in remaining.items() if not deps]
            assert ready, f"cycle detected among remaining stages: {sorted(remaining)}"
            for name in ready:
                ordered.append(name)
                del remaining[name]
            for deps in remaining.values():
                deps.difference_update(ready)
        assert set(ordered) == set(CANONICAL_STAGE_ORDER)

    def test_no_stage_depends_on_itself(self):
        for name, deps in STAGE_DEPENDENCIES.items():
            assert name not in deps

    def test_first_stage_has_no_dependencies(self):
        assert STAGE_DEPENDENCIES["repository_analysis_and_remediation_planning"] == ()

    def test_dependencies_are_not_lazily_all_previous_stages(self):
        """Sanity check straight from the architecture report: at least one
        stage must NOT depend on every stage that numerically precedes it
        (proving the graph is genuinely sparse, not "stage N depends on
        1..N-1")."""
        # existing_test_comparison precedes trust_signals_and_recommendation
        # and report_generation, but impact_and_behavior_analysis does NOT
        # depend on challenger or patch_review, even though both precede it.
        assert "challenger" not in STAGE_DEPENDENCIES["impact_and_behavior_analysis"]
        assert "patch_review" not in STAGE_DEPENDENCIES["impact_and_behavior_analysis"]

    def test_report_generation_depends_on_all_twelve_other_stages(self):
        assert set(STAGE_DEPENDENCIES["report_generation"]) == set(CANONICAL_STAGE_ORDER) - {"report_generation"}

    def test_trust_signals_and_recommendation_does_not_depend_on_patch_review_or_confidence_scoring(self):
        """Non-obvious, explicitly verified fact from the architecture
        report: trust signal computation never reads Patch Review or
        Confidence Scoring output."""
        deps = set(STAGE_DEPENDENCIES["trust_signals_and_recommendation"])
        assert "patch_review" not in deps
        assert "confidence_scoring" not in deps


class TestCapabilityMetadata:
    def test_every_stage_declares_capability_metadata(self):
        for name in CANONICAL_STAGE_ORDER:
            spec = STAGE_SPECS[name]
            assert isinstance(spec.requires_repo_access, bool)
            assert isinstance(spec.requires_docker, bool)
            assert isinstance(spec.requires_llm_provider, bool)
            assert isinstance(spec.owns_external_execution, bool)

    def test_report_generation_never_requires_docker(self):
        assert STAGE_SPECS["report_generation"].requires_docker is False

    def test_report_generation_requires_no_llm(self):
        spec = STAGE_SPECS["report_generation"]
        assert spec.requires_llm_provider is False

    def test_report_generation_requires_repo_access(self):
        # Batch B8 correction: _build_report() reads the repository (e.g.
        # tests_for_file() for Suggested Tests) whenever repo_root is not
        # None -- previously declared False, a real capability-metadata gap.
        spec = STAGE_SPECS["report_generation"]
        assert spec.requires_repo_access is True

    def test_only_existing_test_comparison_requires_docker(self):
        docker_stages = [n for n in CANONICAL_STAGE_ORDER if STAGE_SPECS[n].requires_docker]
        assert docker_stages == ["existing_test_comparison"]

    def test_deterministic_stages_never_require_llm_provider(self):
        for name in ("impact_and_behavior_analysis", "trust_signals_and_recommendation", "report_generation"):
            assert STAGE_SPECS[name].requires_llm_provider is False


class TestLLMOwnership:
    def test_every_stage_declares_llm_ownership_explicitly(self):
        for name in CANONICAL_STAGE_ORDER:
            assert name in STAGE_OWNED_LLM_TAGS
            assert isinstance(STAGE_OWNED_LLM_TAGS[name], tuple)

    def test_deterministic_stages_own_zero_llm_tags(self):
        for name in ("impact_and_behavior_analysis", "trust_signals_and_recommendation", "report_generation", "existing_test_comparison"):
            assert STAGE_OWNED_LLM_TAGS[name] == ()

    def test_stage4_and_stage6_generation_tags_are_distinguishable(self):
        """The exact ambiguity Batch A was asked to fix: Stage 4 (patch
        generation) and Stage 6 (repair) must NOT share an LLM tag for
        their respective patch-generation/regeneration calls."""
        stage4_tags = set(STAGE_OWNED_LLM_TAGS["patch_generation_and_post_patch_investigation"])
        stage6_tags = set(STAGE_OWNED_LLM_TAGS["patch_repair_and_calibration"])
        generation_tags_shared = stage4_tags & stage6_tags & {
            "patch_generation", "patch_generation_contract_retry", "patch_repair_regeneration",
        }
        assert generation_tags_shared == set(), (
            f"Stage 4 and Stage 6 share generation-related LLM tags: {generation_tags_shared}"
        )
        assert "patch_repair_regeneration" in stage6_tags
        assert "patch_repair_regeneration" not in stage4_tags

    def test_known_ambiguous_tags_are_tracked_not_hidden(self):
        """The "challenger" tag ambiguity between Stage 5 and Stage 6 was
        explicitly OUT of Batch A's approved scope -- it must be visible
        in KNOWN_AMBIGUOUS_LLM_TAGS, not silently absent."""
        assert "challenger" in stage_registry.KNOWN_AMBIGUOUS_LLM_TAGS
        assert set(stage_registry.KNOWN_AMBIGUOUS_LLM_TAGS["challenger"]) == {
            "challenger", "patch_repair_and_calibration",
        }


class TestRegistryIsStaticAndImportOrderIndependent:
    """Cleanup batch: stage_registry.py must never depend on what else has
    been imported, in what order -- replayability lives entirely in
    replay_engine.REPLAY_HANDLERS, a separate module this one has never
    heard of."""

    def test_stage_specs_is_immutable(self):
        with pytest.raises(TypeError):
            STAGE_SPECS["repository_analysis_and_remediation_planning"] = None

    def test_stage_spec_has_no_run_fn_or_replayability_concept(self):
        """StageSpec is pure metadata -- it does not know how (or whether)
        a stage can be replayed."""
        spec = STAGE_SPECS["test_analysis_and_plan"]
        assert not hasattr(spec, "run_fn")
        assert not hasattr(spec, "is_replayable")
        assert not hasattr(spec, "dependencies_for_current_run_fn")
        assert not hasattr(spec, "effective_dependencies")

    def test_stage_registry_module_has_no_registration_function(self):
        """No register_*()-style function exists anywhere in this module
        -- there is nothing for another module to call that would mutate
        this one's state."""
        assert not hasattr(stage_registry, "register_run_fn")
        for attr_name in dir(stage_registry):
            if attr_name.startswith("register_"):
                pytest.fail(f"unexpected registration-style function: {attr_name}")

    def test_registry_contents_identical_regardless_of_construction_order(self):
        """Building the registry twice, independently, must produce
        byte-identical StageSpec content every time -- the pure-literal
        construction has no hidden order dependency."""
        fresh_a = stage_registry._build_registry()
        fresh_b = stage_registry._build_registry()
        assert fresh_a == fresh_b
        assert dict(STAGE_SPECS) == fresh_a

    def test_importing_replay_engine_does_not_mutate_stage_specs(self):
        """The core guarantee this cleanup batch was asked to establish:
        importing replay_engine.py (which HAS the only knowledge of which
        stages are replayable today) must leave stage_registry.STAGE_SPECS
        completely unchanged."""
        before = dict(STAGE_SPECS)
        import utilities.autopatcher.replay_engine  # noqa: F401 (import for side-effect check)
        import importlib

        importlib.reload(utilities.autopatcher.replay_engine)  # even a re-import must not mutate
        after = dict(STAGE_SPECS)
        assert before == after
