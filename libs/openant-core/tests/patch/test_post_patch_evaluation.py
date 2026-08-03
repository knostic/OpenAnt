"""Tests for post_patch_evaluation.evaluate_anchors (Phase 3: Post-Patch
Anchor Evaluation).

evaluate_anchors() is pure over two already-computed inputs (a list of
Anchor and an InvestigationContext | None), so every fixture here is built
purely in memory -- RepositoryIndex and ReachabilityAnalyzer both accept
plain dicts directly, with no file I/O -- exactly like Phase 2's tests.
"""

from __future__ import annotations

import copy
import inspect
from unittest import mock

from utilities.agentic_enhancer.reachability_analyzer import ReachabilityAnalyzer
from utilities.agentic_enhancer.repository_index import RepositoryIndex
from utilities.autopatcher.candidate_enrichment import InvestigationContext
from utilities.autopatcher.post_patch_investigation import (
    Anchor,
    CallEdgeKey,
    ReachabilityKey,
    ReachabilityValue,
    ResolvedFunctionKey,
    ResolvedFunctionValue,
    SinkMatchKey,
    SinkMatchValue,
)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _function(func_id, start_line=1, end_line=5, name=None, unit_type="function", class_name=None):
    return {
        "id": func_id,
        "name": name or func_id.rsplit(":", 1)[-1],
        "startLine": start_line,
        "endLine": end_line,
        "unitType": unit_type,
        "className": class_name,
    }


def _context(functions, call_graph=None, reverse_call_graph=None, entry_points=None) -> InvestigationContext:
    index = RepositoryIndex({"functions": functions})
    reverse_call_graph = reverse_call_graph or {}
    entry_points = entry_points or set()
    reachability = ReachabilityAnalyzer(functions, reverse_call_graph, entry_points)
    return InvestigationContext(
        index=index,
        call_graph=call_graph or {},
        reverse_call_graph=reverse_call_graph,
        reachability=reachability,
    )


def _resolved_function_anchor(func_id, start_line=1, end_line=5, candidate_path="a.py"):
    return Anchor(
        kind="resolved_function",
        candidate_path=candidate_path,
        key=ResolvedFunctionKey(func_id=func_id, name=func_id.rsplit(":", 1)[-1], class_name=None, unit_type="function"),
        before_value=ResolvedFunctionValue(start_line=start_line, end_line=end_line),
        source="candidate_enrichment.resolved_function",
    )


def _call_edge_anchor(caller_id, callee_id, candidate_path="a.py"):
    return Anchor(
        kind="call_edge",
        candidate_path=candidate_path,
        key=CallEdgeKey(caller_func_id=caller_id, callee_func_id=callee_id),
        before_value=True,
        source="candidate_enrichment.callees",
    )


def _reachability_anchor(func_id, reachable, entry_point_path=None, candidate_path="a.py"):
    return Anchor(
        kind="reachability",
        candidate_path=candidate_path,
        key=ReachabilityKey(func_id=func_id),
        before_value=ReachabilityValue(
            reachable=reachable,
            entry_point_path=tuple(entry_point_path) if entry_point_path else None,
        ),
        source="candidate_enrichment.is_reachable_from_entry_point",
    )


def _sink_match_anchor(candidate_path="a.py", method="run", line=10, snippet="os.system(x)"):
    return Anchor(
        kind="sink_match",
        candidate_path=candidate_path,
        key=SinkMatchKey(candidate_path=candidate_path, method=method),
        before_value=SinkMatchValue(line=line, snippet=snippet),
        source="candidate_enrichment.sink_matches",
    )


# ---------------------------------------------------------------------------
# resolved_function
# ---------------------------------------------------------------------------

class TestResolvedFunctionEvaluation:
    def test_unchanged(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id = "a.py:foo"
        anchor = _resolved_function_anchor(func_id, start_line=1, end_line=5)
        context = _context({func_id: _function(func_id, start_line=1, end_line=5)})

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "unchanged"
        assert obs.after_value == ResolvedFunctionValue(start_line=1, end_line=5)
        assert obs.evaluated_via == "agentic_enhancer.repository_index.RepositoryIndex.get_function"

    def test_changed(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id = "a.py:foo"
        anchor = _resolved_function_anchor(func_id, start_line=1, end_line=5)
        context = _context({func_id: _function(func_id, start_line=20, end_line=30)})

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "changed"
        assert obs.after_value == ResolvedFunctionValue(start_line=20, end_line=30)
        assert obs.before_value == ResolvedFunctionValue(start_line=1, end_line=5)

    def test_disappeared(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        anchor = _resolved_function_anchor("a.py:foo")
        context = _context({})  # func_id no longer present

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "disappeared"
        assert obs.after_value is None
        assert "no longer present" in obs.details

    def test_evaluation_error_on_unexpected_exception(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        anchor = _resolved_function_anchor("a.py:foo")
        broken_context = mock.MagicMock()
        broken_context.index.get_function.side_effect = RuntimeError("index corrupted")

        obs = evaluate_anchors([anchor], broken_context)[0]
        assert obs.status == "evaluation_error"
        assert obs.after_value is None
        assert "index corrupted" in obs.details


# ---------------------------------------------------------------------------
# call_edge
# ---------------------------------------------------------------------------

class TestCallEdgeEvaluation:
    def test_unchanged_when_edge_still_present(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        caller, callee = "a.py:foo", "b.py:bar"
        anchor = _call_edge_anchor(caller, callee)
        context = _context(
            {caller: _function(caller), callee: _function(callee)},
            call_graph={caller: [callee]},
        )

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "unchanged"
        assert obs.after_value is True

    def test_disappeared_when_caller_no_longer_calls_callee(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        caller, callee = "a.py:foo", "b.py:bar"
        anchor = _call_edge_anchor(caller, callee)
        context = _context(
            {caller: _function(caller), callee: _function(callee)},
            call_graph={caller: []},  # caller exists but no longer calls callee
        )

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "disappeared"
        assert obs.after_value is False

    def test_unresolved_when_caller_no_longer_resolves(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        anchor = _call_edge_anchor("a.py:foo", "b.py:bar")
        context = _context({})  # caller itself is gone

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "unresolved"
        assert obs.after_value is None


# ---------------------------------------------------------------------------
# reachability
# ---------------------------------------------------------------------------

class TestReachabilityEvaluation:
    def test_unchanged(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id, entry_id = "a.py:foo", "entry.py:main"
        anchor = _reachability_anchor(func_id, reachable=True, entry_point_path=[entry_id, func_id])
        context = _context(
            {func_id: _function(func_id), entry_id: _function(entry_id)},
            reverse_call_graph={func_id: [entry_id]},
            entry_points={entry_id},
        )

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "unchanged"
        assert obs.after_value.reachable is True

    def test_changed_true_to_false(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id = "a.py:foo"
        anchor = _reachability_anchor(func_id, reachable=True, entry_point_path=["entry.py:main", func_id])
        context = _context({func_id: _function(func_id)})  # no reverse edges, no entry points -> unreachable now

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "changed"
        assert obs.after_value.reachable is False
        assert obs.after_value.entry_point_path is None

    def test_changed_when_previously_unresolved(self):
        """before_value.reachable is None (a rare pre-patch
        enrichment-exception state) transitioning to a definite value is a
        known/unknown transition, not a presence/absence one -- reported
        as `changed`, the same as any other value difference, not a
        dedicated status."""
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id, entry_id = "a.py:foo", "entry.py:main"
        anchor = _reachability_anchor(func_id, reachable=None, entry_point_path=None)
        context = _context(
            {func_id: _function(func_id), entry_id: _function(entry_id)},
            reverse_call_graph={func_id: [entry_id]},
            entry_points={entry_id},
        )

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "changed"
        assert obs.after_value.reachable is True

    def test_unresolved_when_function_gone(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        anchor = _reachability_anchor("a.py:foo", reachable=True, entry_point_path=["entry.py:main", "a.py:foo"])
        context = _context({})

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "unresolved"
        assert obs.after_value is None

    def test_evaluation_error_on_unexpected_exception(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id = "a.py:foo"
        anchor = _reachability_anchor(func_id, reachable=True)
        broken_context = mock.MagicMock()
        broken_context.index.get_function.return_value = _function(func_id)
        broken_context.reachability.is_reachable_from_entry_point.side_effect = RuntimeError("bfs exploded")

        obs = evaluate_anchors([anchor], broken_context)[0]
        assert obs.status == "evaluation_error"
        assert "bfs exploded" in obs.details


# ---------------------------------------------------------------------------
# sink_match -- deferred, always unresolved
# ---------------------------------------------------------------------------

class TestSinkMatchDeferred:
    def test_always_unresolved_regardless_of_context(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        anchor = _sink_match_anchor()
        context = _context({"a.py:run": _function("a.py:run")})

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.status == "unresolved"
        assert "deferred" in obs.details
        assert obs.evaluated_via == "deferred"

    def test_unresolved_even_with_no_context(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        anchor = _sink_match_anchor()
        obs = evaluate_anchors([anchor], None)[0]
        assert obs.status == "unresolved"


# ---------------------------------------------------------------------------
# Missing context
# ---------------------------------------------------------------------------

class TestMissingContext:
    def test_context_dependent_kinds_become_evaluation_error(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        anchors = [
            _resolved_function_anchor("a.py:foo"),
            _call_edge_anchor("a.py:foo", "b.py:bar"),
            _reachability_anchor("a.py:foo", reachable=True),
        ]
        observations = evaluate_anchors(anchors, None)
        assert all(o.status == "evaluation_error" for o in observations)
        assert all(o.after_value is None for o in observations)


# ---------------------------------------------------------------------------
# Ordering, provenance, determinism, purity
# ---------------------------------------------------------------------------

class TestOrderingAndProvenance:
    def test_ordering_preserved_across_mixed_kinds(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id = "a.py:foo"
        anchors = [
            _sink_match_anchor(),
            _resolved_function_anchor(func_id),
            _call_edge_anchor(func_id, "b.py:bar"),
            _reachability_anchor(func_id, reachable=True),
        ]
        context = _context({func_id: _function(func_id)})

        observations = evaluate_anchors(anchors, context)
        assert [o.anchor_kind for o in observations] == [a.kind for a in anchors]
        assert [o.anchor_key for o in observations] == [a.key for a in anchors]

    def test_provenance_preserved(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id = "a.py:foo"
        anchor = _resolved_function_anchor(func_id)
        context = _context({func_id: _function(func_id)})

        obs = evaluate_anchors([anchor], context)[0]
        assert obs.anchor_kind == anchor.kind
        assert obs.anchor_key == anchor.key
        assert obs.candidate_path == anchor.candidate_path
        assert obs.source == anchor.source
        assert obs.evaluated_via == "agentic_enhancer.repository_index.RepositoryIndex.get_function"


class TestDeterminismAndPurity:
    def test_repeated_evaluation_is_deterministic(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id = "a.py:foo"
        anchors = [_resolved_function_anchor(func_id), _reachability_anchor(func_id, reachable=True)]
        context = _context({func_id: _function(func_id)})

        result1 = evaluate_anchors(anchors, context)
        result2 = evaluate_anchors(anchors, context)
        assert result1 == result2

    def test_no_mutation_of_anchors_or_context(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id = "a.py:foo"
        anchors = [_resolved_function_anchor(func_id, start_line=1, end_line=5)]
        context = _context({func_id: _function(func_id, start_line=1, end_line=5)})
        anchors_snapshot = copy.deepcopy(anchors)

        evaluate_anchors(anchors, context)

        assert anchors == anchors_snapshot
        assert context.index.get_function(func_id) == _function(func_id, start_line=1, end_line=5)

    def test_empty_anchors_returns_empty_list(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        assert evaluate_anchors([], None) == []
        assert evaluate_anchors([], _context({})) == []

    def test_no_disallowed_imports(self):
        import utilities.autopatcher.post_patch_evaluation as mod

        source = inspect.getsource(mod)
        disallowed = [
            "import subprocess", "import socket", "import requests",
            "import tempfile", "import shutil",
            "anthropic", "openai", "urllib",
        ]
        for token in disallowed:
            assert token not in source, f"unexpected token found: {token}"

    def test_no_recommendation_or_verdict_vocabulary(self):
        """#16: statuses and details must never read as a recommendation --
        only comparison-neutral facts."""
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors

        func_id = "a.py:foo"
        anchors = [
            _resolved_function_anchor(func_id),
            _call_edge_anchor(func_id, "b.py:bar"),
            _reachability_anchor(func_id, reachable=True),
            _sink_match_anchor(),
        ]
        context = _context({})  # force every branch to produce a details string

        observations = evaluate_anchors(anchors, context)
        blocklist = ["fixed", "correct", "success", "vulnerable", "safe", "remediat"]
        for obs in observations:
            text = (obs.details or "").lower()
            for word in blocklist:
                assert word not in text, f"{word!r} found in details: {text!r}"


# ---------------------------------------------------------------------------
# render_post_patch_investigation
# ---------------------------------------------------------------------------

class TestRenderPostPatchInvestigation:
    def test_empty_observations(self):
        from utilities.autopatcher.post_patch_evaluation import render_post_patch_investigation

        rendered = render_post_patch_investigation([])
        assert rendered.startswith("## Post-Patch Investigation")
        assert "No anchors were available to re-evaluate." in rendered

    def test_grouped_by_status(self):
        from utilities.autopatcher.post_patch_evaluation import (
            AnchorObservation, render_post_patch_investigation,
        )

        def _obs(status, kind="resolved_function", details=None):
            return AnchorObservation(
                anchor_kind=kind,
                anchor_key=ResolvedFunctionKey(func_id="a.py:foo", name="foo", class_name=None, unit_type="function"),
                candidate_path="a.py",
                status=status,
                before_value=ResolvedFunctionValue(start_line=1, end_line=5),
                after_value=ResolvedFunctionValue(start_line=1, end_line=9) if status == "changed" else None,
                details=details,
                source="candidate_enrichment.resolved_function",
                evaluated_via="agentic_enhancer.repository_index.RepositoryIndex.get_function",
            )

        observations = [
            _obs("changed"),
            _obs("disappeared", details="function id no longer present in the patched copy"),
            _obs("unchanged"),
            _obs("unresolved", details="function id no longer resolves in the patched copy"),
            _obs("evaluation_error", details="lookup failed: RuntimeError: boom"),
        ]
        rendered = render_post_patch_investigation(observations)

        assert "### Changed" in rendered
        assert "### Disappeared" in rendered
        assert "### Unchanged" in rendered
        assert "### Remaining Unknowns" in rendered
        # Changed/Disappeared content appears under their own headings.
        changed_idx = rendered.index("### Changed")
        disappeared_idx = rendered.index("### Disappeared")
        unchanged_idx = rendered.index("### Unchanged")
        unknowns_idx = rendered.index("### Remaining Unknowns")
        assert changed_idx < disappeared_idx < unchanged_idx < unknowns_idx
        assert "resolved_function:a.py:foo" in rendered[changed_idx:disappeared_idx]
        assert "no longer present" in rendered[disappeared_idx:unchanged_idx]
        assert "1 anchor(s) confirmed unchanged" in rendered[unchanged_idx:unknowns_idx]
        # Both unresolved and evaluation_error land in Remaining Unknowns, never elsewhere.
        unknowns_section = rendered[unknowns_idx:]
        assert "unresolved" in unknowns_section
        assert "evaluation_error" in unknowns_section

    def test_sink_match_always_lands_in_remaining_unknowns(self):
        """sink_match is always status='unresolved' today (Phase 3 defers
        it) -- confirms it's never miscategorized into a determinate group."""
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors, render_post_patch_investigation

        anchors = [_sink_match_anchor()]
        observations = evaluate_anchors(anchors, None)
        rendered = render_post_patch_investigation(observations)

        assert "### Remaining Unknowns" in rendered
        unknowns_idx = rendered.index("### Remaining Unknowns")
        assert "sink_match" in rendered[unknowns_idx:]
        # Never appears in the determinate-looking sections above.
        assert "sink_match" not in rendered[:rendered.index("### Changed")]

    def test_never_mutates_input(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors, render_post_patch_investigation

        func_id = "a.py:foo"
        anchors = [_resolved_function_anchor(func_id)]
        context = _context({func_id: _function(func_id)})
        observations = evaluate_anchors(anchors, context)
        snapshot = list(observations)

        render_post_patch_investigation(observations)

        assert observations == snapshot

    def test_never_exceeds_max_chars(self):
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors, render_post_patch_investigation

        anchors = [
            _resolved_function_anchor(f"a{i}.py:foo", candidate_path=f"a{i}.py")
            for i in range(50)
        ]
        context = _context({})  # everything -> disappeared, exercises the per-group item cap
        observations = evaluate_anchors(anchors, context)

        rendered = render_post_patch_investigation(observations, max_chars=500)
        assert len(rendered) <= 500
        assert "(+" in rendered or "truncated" in rendered

    def test_no_recommendation_or_verdict_vocabulary_in_data_sections(self):
        """The blocklist applies to the data-driven sections (Changed/
        Disappeared/Unchanged/Remaining Unknowns), not the fixed preamble
        -- which legitimately says "not a verdict that the patch is
        correct... or a successful fix" to explicitly disclaim exactly
        those words, the same way evidence_fusion.py's own preamble does."""
        from utilities.autopatcher.post_patch_evaluation import evaluate_anchors, render_post_patch_investigation

        func_id = "a.py:foo"
        anchors = [
            _resolved_function_anchor(func_id),
            _call_edge_anchor(func_id, "b.py:bar"),
            _reachability_anchor(func_id, reachable=True),
            _sink_match_anchor(),
        ]
        context = _context({})
        rendered = render_post_patch_investigation(evaluate_anchors(anchors, context))

        data_sections = rendered[rendered.index("### Changed"):]
        blocklist = ["fixed", "correct", "success", "vulnerable", "safe", "remediat"]
        lowered = data_sections.lower()
        for word in blocklist:
            assert word not in lowered, f"{word!r} found in rendered data sections"
