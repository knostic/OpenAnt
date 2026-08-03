"""Tests for post_patch_investigation.derive_pre_patch_anchors (Phase 2:
Pre-Patch Anchor Derivation).

Builds fixtures from the real dataclasses (RepositoryCandidate,
CandidateEnrichment, DiscoveryEvidence, RepositoryUnderstanding) rather than
mocking -- this module is pure data transformation, so real objects are
both simpler and more honest than mocks.
"""

from __future__ import annotations

import copy
import dataclasses
import inspect

import pytest

from utilities.autopatcher.evidence_fusion import RepositoryUnderstanding
from utilities.autopatcher.repository_grounding_models import (
    CandidateEnrichment,
    DiscoveryEvidence,
    RepositoryCandidate,
)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _evidence(tier=3, hit_line=10, pass_name="explicit_path"):
    return DiscoveryEvidence(
        pass_name=pass_name,
        tier=tier,
        matched_tokens=None,
        total_occurrences=None,
        hit_line=hit_line,
        resolution_strategy=None,
    )


def _candidate(path: str, enrichment=None, best_tier=3) -> RepositoryCandidate:
    return RepositoryCandidate(
        path=path,
        evidence=[_evidence(tier=best_tier)],
        best_tier=best_tier,
        enrichment=enrichment,
    )


def _enrichment(**overrides) -> CandidateEnrichment:
    defaults = dict(
        functions_in_file=[],
        resolved_function=None,
        resolution_note=None,
        callees=[],
        callers_by_call_graph=[],
        callers_by_text_search=[],
        is_reachable_from_entry_point=None,
        entry_point_path=None,
        related_tests=[],
        test_support_rating=None,
        sink_matches=None,
        enrichment_errors=[],
    )
    defaults.update(overrides)
    return CandidateEnrichment(**defaults)


def _resolved(func_id, name="authenticate", start_line=1, end_line=5, unit_type="function", class_name=None):
    return {
        "id": func_id,
        "name": name,
        "startLine": start_line,
        "endLine": end_line,
        "unitType": unit_type,
        "className": class_name,
    }


def _understanding(candidates, relationships=None, notes=None, context_available=True) -> RepositoryUnderstanding:
    return RepositoryUnderstanding(
        candidate_evidence=candidates,
        relationships=relationships or [],
        fusion_notes=notes or [],
        investigation_context_available=context_available,
    )


# ---------------------------------------------------------------------------
# 1. resolved_function anchor
# ---------------------------------------------------------------------------

class TestResolvedFunctionAnchor:
    def test_derived_with_stable_deterministic_id(self):
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        func_id = "auth.py:authenticate"
        candidate = _candidate("auth.py", _enrichment(resolved_function=_resolved(func_id)))
        anchors = derive_pre_patch_anchors(_understanding([candidate]))

        matches = [a for a in anchors if a.kind == "resolved_function"]
        assert len(matches) == 1
        anchor = matches[0]
        assert anchor.display_id == f"resolved_function:{func_id}"
        assert anchor.candidate_path == "auth.py"
        assert anchor.key.func_id == func_id
        assert anchor.key.name == "authenticate"
        assert anchor.key.class_name is None
        assert anchor.key.unit_type == "function"
        assert anchor.before_value.start_line == 1
        assert anchor.before_value.end_line == 5
        assert anchor.source == "candidate_enrichment.resolved_function"

    def test_line_number_changes_alone_do_not_change_identity(self):
        """#2/#3: identical qualified function, different line range ->
        same (kind, key) identity and same display_id, different
        before_value."""
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        func_id = "auth.py:authenticate"
        candidate_v1 = _candidate("auth.py", _enrichment(
            resolved_function=_resolved(func_id, start_line=1, end_line=5)
        ))
        candidate_v2 = _candidate("auth.py", _enrichment(
            resolved_function=_resolved(func_id, start_line=20, end_line=30)
        ))

        anchors_v1 = derive_pre_patch_anchors(_understanding([candidate_v1]))
        anchors_v2 = derive_pre_patch_anchors(_understanding([candidate_v2]))

        a1 = next(a for a in anchors_v1 if a.kind == "resolved_function")
        a2 = next(a for a in anchors_v2 if a.kind == "resolved_function")

        assert (a1.kind, a1.key) == (a2.kind, a2.key)
        assert a1.key == a2.key
        assert a1.display_id == a2.display_id
        assert a1.before_value != a2.before_value
        assert a1.before_value.start_line == 1
        assert a2.before_value.start_line == 20


# ---------------------------------------------------------------------------
# 4/5/14. call_edge anchors
# ---------------------------------------------------------------------------

class TestCallEdgeAnchor:
    def test_derived_once_and_deduplicated_across_both_endpoints(self):
        """A calls B: A's callees names B's func_id, and B's
        callers_by_call_graph names A's func_id -- same real edge, must
        collapse to exactly one anchor."""
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        func_a = "a.py:funcA"
        func_b = "b.py:funcB"
        candidate_a = _candidate("a.py", _enrichment(
            resolved_function=_resolved(func_a, name="funcA"),
            callees=[func_b],
        ))
        candidate_b = _candidate("b.py", _enrichment(
            resolved_function=_resolved(func_b, name="funcB"),
            callers_by_call_graph=[func_a],
        ))

        anchors = derive_pre_patch_anchors(_understanding([candidate_a, candidate_b]))

        edges = [a for a in anchors if a.kind == "call_edge"]
        assert len(edges) == 1
        edge = edges[0]
        assert edge.display_id == f"call_edge:{func_a}->{func_b}"
        assert edge.key.caller_func_id == func_a
        assert edge.key.callee_func_id == func_b
        assert edge.before_value is True
        assert edge.candidate_path == "a.py"  # caller's file, per docstring

    def test_duplicate_entries_within_one_field_also_deduplicated(self):
        """#14 variant: the same callee listed twice in one candidate's own
        callees list must still produce one anchor."""
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        func_a = "a.py:funcA"
        func_b = "b.py:funcB"
        candidate = _candidate("a.py", _enrichment(
            resolved_function=_resolved(func_a, name="funcA"),
            callees=[func_b, func_b],
        ))
        anchors = derive_pre_patch_anchors(_understanding([candidate]))
        edges = [a for a in anchors if a.kind == "call_edge"]
        assert len(edges) == 1

    def test_callers_by_text_search_never_creates_call_edge(self):
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        func_id = "auth.py:authenticate"
        candidate = _candidate("auth.py", _enrichment(
            resolved_function=_resolved(func_id, name="authenticate"),
            callers_by_text_search=[
                {"id": "other.py:caller", "name": "caller", "file": "other.py", "matches": []}
            ],
        ))
        anchors = derive_pre_patch_anchors(_understanding([candidate]))
        assert not [a for a in anchors if a.kind == "call_edge"]


# ---------------------------------------------------------------------------
# 6. reachability anchor
# ---------------------------------------------------------------------------

class TestReachabilityAnchor:
    def test_true_false_and_none_are_distinguishable(self):
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        reachable_candidate = _candidate("a.py", _enrichment(
            resolved_function=_resolved("a.py:funcA", name="funcA"),
            is_reachable_from_entry_point=True,
            entry_point_path=["entry.py:main", "a.py:funcA"],
        ))
        unreachable_candidate = _candidate("b.py", _enrichment(
            resolved_function=_resolved("b.py:funcB", name="funcB"),
            is_reachable_from_entry_point=False,
        ))
        # resolved but reachability computation itself failed (real path in
        # candidate_enrichment._enrich_one's try/except): resolved_function
        # is set, is_reachable_from_entry_point stays None.
        unresolved_candidate = _candidate("c.py", _enrichment(
            resolved_function=_resolved("c.py:funcC", name="funcC"),
            is_reachable_from_entry_point=None,
        ))

        anchors = derive_pre_patch_anchors(_understanding(
            [reachable_candidate, unreachable_candidate, unresolved_candidate]
        ))
        reach = {a.candidate_path: a for a in anchors if a.kind == "reachability"}

        assert reach["a.py"].before_value.reachable is True
        assert reach["a.py"].before_value.entry_point_path == ("entry.py:main", "a.py:funcA")
        assert reach["b.py"].before_value.reachable is False
        assert reach["b.py"].before_value.entry_point_path is None
        assert reach["c.py"].before_value.reachable is None
        assert reach["c.py"].before_value.entry_point_path is None


# ---------------------------------------------------------------------------
# 7. sink_match anchor
# ---------------------------------------------------------------------------

class TestSinkMatchAnchor:
    def test_preserves_provenance_and_stable_key(self):
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        candidate = _candidate("auth.py", _enrichment(
            sink_matches=[{"file": "auth.py", "line": 10, "method": "authenticate", "snippet": "os.system(cmd)"}],
        ))
        anchors = derive_pre_patch_anchors(_understanding([candidate]))
        matches = [a for a in anchors if a.kind == "sink_match"]
        assert len(matches) == 1
        anchor = matches[0]
        assert anchor.display_id == "sink_match:auth.py:authenticate"
        assert anchor.key.candidate_path == "auth.py"
        assert anchor.key.method == "authenticate"
        assert anchor.before_value.line == 10
        assert anchor.before_value.snippet == "os.system(cmd)"
        assert anchor.source == "candidate_enrichment.sink_matches"

    def test_module_level_sink_uses_module_label(self):
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        candidate = _candidate("auth.py", _enrichment(
            sink_matches=[{"file": "auth.py", "line": 3, "method": None, "snippet": "os.system(x)"}],
        ))
        anchors = derive_pre_patch_anchors(_understanding([candidate]))
        anchor = next(a for a in anchors if a.kind == "sink_match")
        assert anchor.display_id == "sink_match:auth.py:<module>"
        assert anchor.key.method is None

    def test_none_vs_empty_sink_matches_both_produce_no_anchors(self):
        """None = not attempted, [] = attempted and found nothing -- both
        are honest "no anchor" states, never fabricated."""
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        none_candidate = _candidate("a.py", _enrichment(sink_matches=None))
        empty_candidate = _candidate("b.py", _enrichment(sink_matches=[]))
        anchors = derive_pre_patch_anchors(_understanding([none_candidate, empty_candidate]))
        assert not [a for a in anchors if a.kind == "sink_match"]

    def test_sink_match_derived_even_when_resolved_function_is_none(self):
        """sink_matches is computed independently of function resolution
        in candidate_enrichment._enrich_one -- must not be silently
        skipped just because no function was resolved."""
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        candidate = _candidate("auth.py", _enrichment(
            resolved_function=None,
            sink_matches=[{"file": "auth.py", "line": 10, "method": "run", "snippet": "os.system(x)"}],
        ))
        anchors = derive_pre_patch_anchors(_understanding([candidate]))
        assert len(anchors) == 1
        assert anchors[0].kind == "sink_match"


def _literal_entry(qualified_name, name, class_name=None, kind="frozenset_call", value=None, line=1, end_line=1):
    return {
        "qualified_name": qualified_name, "class_name": class_name, "name": name,
        "outcome": "literal", "ast_literal_kind": kind, "value": value,
        "line": line, "end_line": end_line,
    }


class TestConstantValueAnchor:
    def test_derived_for_the_cve_2023_43804_shape(self):
        """The exact motivating case: a class-level frozenset constant."""
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        entry = _literal_entry(
            "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT", "DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
            class_name="Retry", value=frozenset({"Authorization"}),
        )
        candidate = _candidate("retry.py", _enrichment(
            resolved_function=_resolved("retry.py:Retry.increment", class_name="Retry"),
            scope_constants=[entry],
        ))
        anchors = derive_pre_patch_anchors(_understanding([candidate]))
        matches = [a for a in anchors if a.kind == "constant_value"]
        assert len(matches) == 1
        anchor = matches[0]
        assert anchor.display_id == "constant_value:retry.py:Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT"
        assert anchor.key.qualified_name == "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT"
        assert anchor.key.class_name == "Retry"
        assert anchor.before_value.value == frozenset({"Authorization"})
        assert anchor.before_value.ast_literal_kind == "frozenset_call"
        assert anchor.source == "candidate_enrichment.scope_constants"

    def test_non_literal_outcome_produces_no_anchor(self):
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        entry = _literal_entry("BACKEND", "BACKEND", kind=None, value=None)
        entry["outcome"] = "non_literal"
        candidate = _candidate("a.py", _enrichment(scope_constants=[entry]))
        anchors = derive_pre_patch_anchors(_understanding([candidate]))
        assert not [a for a in anchors if a.kind == "constant_value"]

    def test_derived_even_when_resolved_function_is_none(self):
        """Mirrors sink_match's independence from resolved_function --
        candidate_enrichment already decided scoping; derivation must not
        re-gate on it."""
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        entry = _literal_entry("TIMEOUT", "TIMEOUT", value=30, kind="Constant")
        candidate = _candidate("a.py", _enrichment(resolved_function=None, scope_constants=[entry]))
        anchors = derive_pre_patch_anchors(_understanding([candidate]))
        assert len(anchors) == 1
        assert anchors[0].kind == "constant_value"

    def test_deduplicated_across_two_candidates_in_the_same_class(self):
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        entry = _literal_entry(
            "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT", "DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
            class_name="Retry", value=frozenset({"Authorization"}),
        )
        candidate_a = _candidate("retry.py", _enrichment(
            resolved_function=_resolved("retry.py:Retry.increment", name="increment", class_name="Retry"),
            scope_constants=[entry],
        ))
        candidate_b = _candidate("retry.py", _enrichment(
            resolved_function=_resolved("retry.py:Retry.__repr__", name="__repr__", class_name="Retry"),
            scope_constants=[dict(entry)],
        ))
        anchors = derive_pre_patch_anchors(_understanding([candidate_a, candidate_b]))
        assert len([a for a in anchors if a.kind == "constant_value"]) == 1

    def test_none_vs_empty_scope_constants_both_produce_no_anchors(self):
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        empty_candidate = _candidate("a.py", _enrichment(scope_constants=[]))
        anchors = derive_pre_patch_anchors(_understanding([empty_candidate]))
        assert not [a for a in anchors if a.kind == "constant_value"]


# ---------------------------------------------------------------------------
# 8. related_test is deferred -- never produced by this phase
# ---------------------------------------------------------------------------

class TestRelatedTestDeferred:
    def test_related_tests_data_produces_no_anchors(self):
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        candidate = _candidate("auth.py", _enrichment(
            related_tests=[{"path": "/abs/tests/test_auth.py", "proximity": "same-file", "reason": "x"}],
            test_support_rating=("Good", 0.05, {}),
        ))
        anchors = derive_pre_patch_anchors(_understanding([candidate]))
        assert anchors == []
        assert not any(a.kind == "related_test" for a in anchors)


# ---------------------------------------------------------------------------
# 9/10. no fabrication / empty input
# ---------------------------------------------------------------------------

class TestNoFabrication:
    def test_candidate_without_enrichment_produces_no_anchors(self):
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        candidate = _candidate("auth.py", enrichment=None)
        anchors = derive_pre_patch_anchors(_understanding([candidate]))
        assert anchors == []

    def test_empty_understanding_returns_empty_list(self):
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        anchors = derive_pre_patch_anchors(_understanding([]))
        assert anchors == []


# ---------------------------------------------------------------------------
# 11/12. determinism and purity
# ---------------------------------------------------------------------------

class TestDeterminismAndPurity:
    def test_repeated_derivation_produces_equal_anchors_in_equal_order(self):
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        candidate = _candidate("auth.py", _enrichment(
            resolved_function=_resolved("auth.py:authenticate"),
            callees=["auth.py:helper"],
            is_reachable_from_entry_point=True,
            entry_point_path=["entry.py:main", "auth.py:authenticate"],
            sink_matches=[{"file": "auth.py", "line": 10, "method": "authenticate", "snippet": "x"}],
        ))
        understanding = _understanding([candidate])

        result1 = derive_pre_patch_anchors(understanding)
        result2 = derive_pre_patch_anchors(understanding)
        assert result1 == result2
        assert [(a.kind, a.key) for a in result1] == [(a.kind, a.key) for a in result2]
        assert [a.display_id for a in result1] == [a.display_id for a in result2]

    def test_input_understanding_and_candidates_not_mutated(self):
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        enrichment = _enrichment(
            resolved_function=_resolved("auth.py:authenticate"),
            callees=["auth.py:helper"],
            sink_matches=[{"file": "auth.py", "line": 10, "method": "authenticate", "snippet": "x"}],
        )
        candidate = _candidate("auth.py", enrichment)
        understanding = _understanding([candidate])
        snapshot = copy.deepcopy(understanding)

        derive_pre_patch_anchors(understanding)

        assert understanding == snapshot
        assert candidate.enrichment is enrichment  # same object, never replaced

    def test_no_disallowed_imports_and_no_repo_root_parameter(self):
        """#13: no I/O, parsing, environment, network, subprocess, or LLM
        imports; confirms the pure "RepositoryUnderstanding -> Anchors"
        signature has no repo_root (or any other) parameter beyond
        `understanding`."""
        import utilities.autopatcher.post_patch_investigation as mod
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        source = inspect.getsource(mod)
        disallowed = [
            "import subprocess", "import socket", "import requests",
            "import os", "import shutil", "import tempfile",
            "anthropic", "openai", "urllib",
        ]
        for token in disallowed:
            assert token not in source, f"unexpected token found: {token}"

        params = list(inspect.signature(derive_pre_patch_anchors).parameters)
        assert params == ["understanding"]


# ---------------------------------------------------------------------------
# 15. global identity uniqueness
# ---------------------------------------------------------------------------

class TestIdentityUniqueness:
    def test_identities_unique_across_candidates_and_kinds(self):
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        candidate_a = _candidate("a.py", _enrichment(
            resolved_function=_resolved("a.py:funcA", name="funcA"),
            callees=["b.py:funcB"],
            is_reachable_from_entry_point=True,
            entry_point_path=["entry.py:main", "a.py:funcA"],
            sink_matches=[{"file": "a.py", "line": 5, "method": "funcA", "snippet": "x"}],
        ))
        candidate_b = _candidate("b.py", _enrichment(
            resolved_function=_resolved("b.py:funcB", name="funcB"),
            callers_by_call_graph=["a.py:funcA"],
            is_reachable_from_entry_point=False,
            sink_matches=[{"file": "b.py", "line": 8, "method": "funcB", "snippet": "y"}],
        ))

        anchors = derive_pre_patch_anchors(_understanding([candidate_a, candidate_b]))

        # (kind, key) is the authoritative semantic identity.
        identities = [(a.kind, a.key) for a in anchors]
        assert len(identities) == len(set(identities))

        # display_id happens to also be unique for this fixture, but that's
        # incidental to the rendering format, not a guarantee -- (kind, key)
        # is what's actually relied on for uniqueness.
        display_ids = [a.display_id for a in anchors]
        assert len(display_ids) == len(set(display_ids))

        assert len(anchors) >= 5  # 2 resolved_function + 1 call_edge + 2 reachability + 2 sink_match

    def test_anchor_instances_are_hashable(self):
        """Bonus of the typed key/value design: unlike a dict-based Anchor,
        every field here is hashable, so Anchor itself can be hashed --
        confirms the typed representation is a real improvement, not just
        a relabeling."""
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        candidate = _candidate("auth.py", _enrichment(resolved_function=_resolved("auth.py:authenticate")))
        anchors = derive_pre_patch_anchors(_understanding([candidate]))
        assert {a for a in anchors}  # no TypeError: unhashable type


# ---------------------------------------------------------------------------
# Identity semantics: (kind, key), not key alone, not a stored id field
# ---------------------------------------------------------------------------

class TestIdentitySemantics:
    def test_kind_disambiguates_structurally_identical_keys(self):
        """Regression guard for the exact reasoning behind using (kind, key)
        instead of key alone: NamedTuple equality/hash ignore the declared
        subclass (they inherit tuple.__eq__/__hash__, which compare
        positionally) -- so a CallEdgeKey and a SinkMatchKey with the same
        field values compare equal as plain tuples. Including `kind` in the
        identity is what tells them apart."""
        from utilities.autopatcher.post_patch_investigation import CallEdgeKey, SinkMatchKey

        call_edge_key = CallEdgeKey(caller_func_id="auth.py", callee_func_id="authenticate")
        sink_match_key = SinkMatchKey(candidate_path="auth.py", method="authenticate")

        assert call_edge_key == sink_match_key  # NamedTuple equality ignores subclass
        assert hash(call_edge_key) == hash(sink_match_key)
        assert ("call_edge", call_edge_key) != ("sink_match", sink_match_key)

    def test_anchor_has_no_stored_id_field(self):
        from utilities.autopatcher.post_patch_investigation import Anchor

        field_names = {f.name for f in dataclasses.fields(Anchor)}
        assert "id" not in field_names
        assert field_names == {"kind", "candidate_path", "key", "before_value", "source", "origin"}

    def test_display_id_is_a_computed_property_not_a_field(self):
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        candidate = _candidate("auth.py", _enrichment(resolved_function=_resolved("auth.py:authenticate")))
        anchor = derive_pre_patch_anchors(_understanding([candidate]))[0]

        assert isinstance(type(anchor).display_id, property)
        assert anchor.display_id == "resolved_function:auth.py:authenticate"

    def test_anchor_remains_frozen_and_hashable_without_id_field(self):
        from utilities.autopatcher.post_patch_investigation import derive_pre_patch_anchors

        candidate = _candidate("auth.py", _enrichment(resolved_function=_resolved("auth.py:authenticate")))
        anchor = derive_pre_patch_anchors(_understanding([candidate]))[0]

        assert dataclasses.fields(anchor)  # sanity: still a dataclass
        with pytest.raises(dataclasses.FrozenInstanceError):
            anchor.candidate_path = "changed.py"
        hash(anchor)  # must not raise
