"""Unit tests for the experimental recursive concern-tree resolver
(`utilities.autopatcher.concern_tree`).

This is an EXPERIMENTAL module, not wired into production Challenger or the
pipeline -- these tests exercise ONLY `concern_tree.py` in isolation, using
a mocked/stubbed LLM throughout (no live LLM calls). `test_patch_challenger.py`
is run separately, unmodified, to confirm concerns_v2 baseline behavior is
untouched (see the completion report; not duplicated here).
"""

from __future__ import annotations

import inspect
from pathlib import Path
from unittest import mock

from utilities.autopatcher.concern_tree import (
    evaluate_concern_tree,
    parse_action,
    Limits,
    EvidencePool,
)


def _llm(*responses):
    m = mock.MagicMock()
    m.complete.side_effect = list(responses)
    return m


def _proven(rationale="established", citation="x", necessary_conditions=("nothing further",),
            evidence_conflict_check=("none found",)):
    nc = "\n".join(f"- {c}" for c in necessary_conditions)
    ecc = "\n".join(f"- {c}" for c in evidence_conflict_check)
    return (
        f"Necessary conditions:\n{nc}\n"
        f"Evidence conflict check:\n{ecc}\n"
        f"Action: PROVEN\nRationale: {rationale}\nCitations:\n- {citation}\n"
    )


def _refuted(rationale="refuted", citation="x", necessary_conditions=("nothing further",),
             evidence_conflict_check=("none found",)):
    nc = "\n".join(f"- {c}" for c in necessary_conditions)
    ecc = "\n".join(f"- {c}" for c in evidence_conflict_check)
    return (
        f"Necessary conditions:\n{nc}\n"
        f"Evidence conflict check:\n{ecc}\n"
        f"Action: REFUTED\nRationale: {rationale}\nCitations:\n- {citation}\n"
    )


def _decompose(children, rationale="needs decomposition"):
    lines = "\n".join(f"- {c}" for c in children)
    return f"Action: DECOMPOSE\nRationale: {rationale}\nChildren:\n{lines}\n"


def _request_evidence(request_type="file_source", file_hint="mod.py", symbol="none", rationale="need more evidence"):
    return (
        f"Action: REQUEST_EVIDENCE\nRationale: {rationale}\n"
        f"Request type: {request_type}\nFile hint: {file_hint}\nSymbol: {symbol}\n"
    )


def _unresolved(reason="cannot be established"):
    return f"Action: UNRESOLVED\nReason: {reason}\n"


class TestDirectVerdicts:
    def test_direct_proven(self):
        llm = _llm(_proven(citation="the operation is unconditional"))
        result = evaluate_concern_tree(
            "op always occurs", code_context="the operation is unconditional", patch="", llm=llm,
        )
        assert result["root_final_status"] == "PROVEN"
        assert result["nodes"][result["root_id"]]["citations"] == ["the operation is unconditional"]

    def test_direct_refuted(self):
        llm = _llm(_refuted(citation="raise Err()"))
        result = evaluate_concern_tree("op occurs", code_context="raise Err()", patch="", llm=llm)
        assert result["root_final_status"] == "REFUTED"


class TestDecomposition:
    def test_decomposition_with_children(self):
        llm = _llm(
            _decompose(["does a guard exist", "does the guard stop it"]),
            _proven(citation="if flag: raise Err()"),
            _proven(citation="raise Err()"),
            _refuted(citation="if flag: raise Err()", rationale="both sub-questions hold"),
        )
        result = evaluate_concern_tree(
            "op can occur", code_context="if flag: raise Err()\nop()", patch="", llm=llm,
        )
        assert result["root_final_status"] == "REFUTED"
        assert len(result["nodes"]) == 3
        root = result["nodes"][result["root_id"]]
        assert set(root["children"]) == {c for c in root["children"]}
        assert len(root["children"]) == 2
        for cid in root["children"]:
            assert result["nodes"][cid]["status"] == "PROVEN"

    def test_nested_decomposition_and_depth_tracking(self):
        llm = _llm(
            _decompose(["question A"]),
            _decompose(["question A sub 1", "question A sub 2"]),
            _proven(citation="line_x"),
            _proven(citation="line_y"),
            _refuted(citation="line_x", rationale="grandchildren resolve this"),  # "question A" reconsidered
            _refuted(citation="line_x", rationale="question A resolves the root"),  # root reconsidered
        )
        result = evaluate_concern_tree("root question", code_context="line_x\nline_y", patch="", llm=llm)
        assert result["totals"]["max_depth_reached"] == 2
        assert result["root_final_status"] == "REFUTED"
        depths = sorted(n["depth"] for n in result["nodes"].values())
        assert depths == [0, 1, 2, 2]


class TestEvidenceAcquisition:
    def test_request_then_retry_then_resolved(self, tmp_path):
        (tmp_path / "mod.py").write_text("def f():\n    if flag:\n        raise Err()\n    op()\n")
        llm = _llm(
            _request_evidence(file_hint="mod.py"),
            _proven(citation="raise Err()"),
        )
        result = evaluate_concern_tree(
            "op can occur", code_context="", patch="", llm=llm,
            repo_root=tmp_path, investigation_context=object(),
        )
        assert result["root_final_status"] == "PROVEN"
        root = result["nodes"][result["root_id"]]
        assert len(root["evidence_requests"]) == 1
        assert root["evidence_requests"][0]["resolved"] is True
        assert root["evidence_requests"][0]["included"] is True
        assert result["totals"]["evidence_acquired"] == 1

    def test_evidence_visible_to_later_sibling_node(self, tmp_path):
        (tmp_path / "mod.py").write_text("def f():\n    if flag:\n        raise Err()\n    op()\n")
        llm = _llm(
            _decompose(["question A", "question B"]),
            _request_evidence(file_hint="mod.py"),   # child A acquires it
            _proven(citation="if flag:"),
            _proven(citation="raise Err()"),          # child B sees it already, no request needed
            _refuted(citation="if flag:", rationale="both hold"),
        )
        result = evaluate_concern_tree(
            "op can occur", code_context="", patch="", llm=llm,
            repo_root=tmp_path, investigation_context=object(),
        )
        assert result["root_final_status"] == "REFUTED"
        assert result["totals"]["evidence_acquired"] == 1
        child_ids = result["nodes"][result["root_id"]]["children"]
        assert result["nodes"][child_ids[1]]["status"] == "PROVEN"

    def test_unavailable_evidence_is_unresolved(self, tmp_path):
        llm = _llm(_request_evidence(file_hint="does_not_exist.py"))
        result = evaluate_concern_tree(
            "op can occur", code_context="", patch="", llm=llm,
            repo_root=tmp_path, investigation_context=object(),
        )
        assert result["root_final_status"] == "UNRESOLVED"
        assert result["nodes"][result["root_id"]]["unresolved_reason"] == "no_progress"
        assert result["nodes"][result["root_id"]]["evidence_requests"][0]["resolved"] is False

    def test_no_repo_root_fails_closed(self):
        llm = _llm(_request_evidence(file_hint="mod.py"))
        result = evaluate_concern_tree("op can occur", code_context="", patch="", llm=llm)
        assert result["root_final_status"] == "UNRESOLVED"
        assert result["nodes"][result["root_id"]]["evidence_requests"][0]["failure_reason"] == "no_repo_root"

    def test_repeated_identical_request_is_no_progress(self, tmp_path):
        (tmp_path / "mod.py").write_text("op()\n")
        llm = _llm(
            _request_evidence(file_hint="mod.py"),
            _request_evidence(file_hint="mod.py"),  # duplicate request from the same node
        )
        result = evaluate_concern_tree(
            "op can occur", code_context="", patch="", llm=llm,
            repo_root=tmp_path, investigation_context=object(), limits=Limits(max_evidence_requests_per_node=5),
        )
        assert result["root_final_status"] == "UNRESOLVED"
        assert result["nodes"][result["root_id"]]["unresolved_reason"] == "no_progress"

    def test_reacquiring_already_included_evidence_is_no_progress(self, tmp_path):
        (tmp_path / "mod.py").write_text("op()\n")
        (tmp_path / "other.py").write_text("op()\n")
        llm = _llm(
            _request_evidence(file_hint="mod.py"),
            _request_evidence(file_hint="mod.py", rationale="asking again, differently worded"),
        )
        result = evaluate_concern_tree(
            "op can occur", code_context="", patch="", llm=llm,
            repo_root=tmp_path, investigation_context=object(), limits=Limits(max_evidence_requests_per_node=5),
        )
        assert result["root_final_status"] == "UNRESOLVED"


class TestStructuralRejections:
    def test_duplicate_child_rejected(self):
        llm = _llm(_decompose(["same question", "same question"]))
        result = evaluate_concern_tree("root", code_context="x", patch="", llm=llm)
        assert result["root_final_status"] == "UNRESOLVED"
        assert result["nodes"][result["root_id"]]["unresolved_reason"] == "duplicate_child"

    def test_child_equal_to_ancestor_rejected(self):
        llm = _llm(_decompose(["root question re-decomposed as itself".lower()]))
        result = evaluate_concern_tree("root question re-decomposed as itself", code_context="x", patch="", llm=llm)
        assert result["root_final_status"] == "UNRESOLVED"
        assert result["nodes"][result["root_id"]]["unresolved_reason"] == "child_equals_ancestor_or_self"

    def test_child_equal_to_grandparent_ancestor_rejected(self):
        llm = _llm(
            _decompose(["intermediate question"]),
            _decompose(["root proposition"]),  # child equals the ROOT (a grandparent-level ancestor)
            _unresolved(reason="the sub-question could not be resolved"),  # root reconsidered
        )
        result = evaluate_concern_tree("root proposition", code_context="x", patch="", llm=llm)
        intermediate_id = result["nodes"][result["root_id"]]["children"][0]
        assert result["nodes"][intermediate_id]["status"] == "UNRESOLVED"
        assert result["nodes"][intermediate_id]["unresolved_reason"] == "child_equals_ancestor_or_self"


class TestLimits:
    def test_max_depth_enforced(self):
        # Each level decomposes into exactly one fresh, uniquely-worded
        # child -- would recurse forever without MAX_DEPTH. A DECOMPOSE
        # that would create a child past the depth limit is rejected
        # outright (no throwaway over-depth node is ever created).
        counter = {"n": 0}

        def make_response(*_args, **_kwargs):
            counter["n"] += 1
            return _decompose([f"question {counter['n']}"])

        llm = mock.MagicMock()
        llm.complete.side_effect = make_response
        result = evaluate_concern_tree(
            "root", code_context="x", patch="", llm=llm,
            limits=Limits(max_depth=2, max_total_nodes_per_root=50),
        )
        assert result["totals"]["max_depth_reached"] <= 2
        deepest = max(result["nodes"].values(), key=lambda n: n["depth"])
        assert deepest["depth"] == 2
        assert deepest["status"] == "UNRESOLVED"
        assert deepest["unresolved_reason"] == "max_depth"

    def test_max_total_nodes_enforced(self):
        llm = _llm(_decompose(["a", "b", "c", "d", "e"]))
        result = evaluate_concern_tree(
            "root", code_context="x", patch="", llm=llm,
            limits=Limits(max_children_per_decomposition=5, max_total_nodes_per_root=3),
        )
        assert result["root_final_status"] == "UNRESOLVED"
        assert result["nodes"][result["root_id"]]["unresolved_reason"] == "node_budget_exhausted"
        assert result["totals"]["total_nodes"] == 1

    def test_semantic_evaluation_attempt_limit(self, tmp_path):
        (tmp_path / "a.py").write_text("op()\n")
        (tmp_path / "b.py").write_text("op()\n")
        (tmp_path / "c.py").write_text("op()\n")
        llm = _llm(
            _request_evidence(file_hint="a.py", rationale="r1"),
            _request_evidence(file_hint="b.py", rationale="r2"),
            _request_evidence(file_hint="c.py", rationale="r3"),
        )
        result = evaluate_concern_tree(
            "root", code_context="", patch="", llm=llm,
            repo_root=tmp_path, investigation_context=object(),
            limits=Limits(max_evidence_requests_per_node=5, max_acquisition_rounds_per_node=5,
                           max_semantic_evaluations_per_node=2),
        )
        assert result["root_final_status"] == "UNRESOLVED"
        assert result["nodes"][result["root_id"]]["unresolved_reason"] == "evaluation_limit_reached"
        assert result["totals"]["semantic_evaluation_calls"] == 2


class TestProvenance:
    def test_invalid_provenance_overrides_claimed_proven(self):
        llm = _llm(_proven(citation="this text is not present anywhere in the evidence"))
        result = evaluate_concern_tree("root", code_context="totally different content", patch="", llm=llm)
        assert result["root_final_status"] == "UNRESOLVED"
        assert result["nodes"][result["root_id"]]["unresolved_reason"] == "invalid_provenance"

    def test_invalid_provenance_overrides_claimed_refuted(self):
        llm = _llm(_refuted(citation="fabricated quote"))
        result = evaluate_concern_tree("root", code_context="real evidence text", patch="", llm=llm)
        assert result["root_final_status"] == "UNRESOLVED"
        assert result["nodes"][result["root_id"]]["unresolved_reason"] == "invalid_provenance"


class TestMalformedOutput:
    def test_missing_action_line_is_invalid_output(self):
        llm = _llm("no action line here at all")
        result = evaluate_concern_tree("root", code_context="x", patch="", llm=llm)
        assert result["root_final_status"] == "UNRESOLVED"
        assert result["nodes"][result["root_id"]]["unresolved_reason"] == "invalid_output"

    def test_multiple_action_lines_is_invalid_output(self):
        llm = _llm("Action: PROVEN\nAction: REFUTED\nRationale: r\nCitations:\n- x\n")
        result = evaluate_concern_tree("root", code_context="x", patch="", llm=llm)
        assert result["root_final_status"] == "UNRESOLVED"
        assert result["nodes"][result["root_id"]]["unresolved_reason"] == "invalid_output"

    def test_unrecognized_action_is_invalid_output(self):
        llm = _llm("Action: MAYBE\nRationale: r\n")
        result = evaluate_concern_tree("root", code_context="x", patch="", llm=llm)
        assert result["root_final_status"] == "UNRESOLVED"
        assert result["nodes"][result["root_id"]]["unresolved_reason"] == "invalid_output"

    def test_proven_missing_citations_is_invalid_output(self):
        llm = _llm("Action: PROVEN\nRationale: r\n")
        assert parse_action(llm.complete()).kind == "INVALID"


class TestParentReconsideration:
    def test_unresolved_child_still_reaches_parent_reconsideration(self):
        llm = _llm(
            _decompose(["question A", "question B"]),
            _proven(citation="line_x"),
            _unresolved(reason="cannot tell"),
            _unresolved(reason="one child unresolved, cannot conclude"),
        )
        result = evaluate_concern_tree("root", code_context="line_x", patch="", llm=llm)
        root = result["nodes"][result["root_id"]]
        assert len(root["attempts"]) == 2  # initial DECOMPOSE + reconsideration
        assert root["attempts"][1]["action"] == "UNRESOLVED"
        child_ids = root["children"]
        statuses = {result["nodes"][cid]["status"] for cid in child_ids}
        assert statuses == {"PROVEN", "UNRESOLVED"}
        assert result["root_final_status"] == "UNRESOLVED"

    def test_reconsideration_uses_the_same_evaluator_call_path(self):
        """Parent reconsideration must be indistinguishable, at the call
        level, from any other node's evaluation -- same function, same
        prompt file, same parser -- never a separate composition engine."""
        llm = _llm(
            _decompose(["question A"]),
            _proven(citation="x"),
            _refuted(citation="x", rationale="reconsidered"),
        )
        with mock.patch("utilities.autopatcher.concern_tree._evaluate", wraps=__import__(
            "utilities.autopatcher.concern_tree", fromlist=["_evaluate"]
        )._evaluate) as spy:
            evaluate_concern_tree("root", code_context="x", patch="", llm=llm)
        # 3 calls total: root initial, child initial, root reconsideration --
        # ALL through the identical _evaluate function.
        assert spy.call_count == 3

    def test_reconsideration_can_decompose_further(self):
        llm = _llm(
            _decompose(["question A"]),
            _proven(citation="line_x"),
            _decompose(["question B"], rationale="child A alone was insufficient"),
            _proven(citation="line_y"),
            _refuted(citation="line_x", rationale="now both hold"),
        )
        result = evaluate_concern_tree("root", code_context="line_x\nline_y", patch="", llm=llm)
        assert result["root_final_status"] == "REFUTED"
        root = result["nodes"][result["root_id"]]
        assert len(root["children"]) == 2


class TestAuthorityBoundary:
    def test_evaluate_concern_tree_has_no_vulnerability_text_parameter(self):
        sig = inspect.signature(evaluate_concern_tree)
        assert "vulnerability_text" not in sig.parameters

    def test_internal_evaluate_has_no_vulnerability_text_parameter(self):
        from utilities.autopatcher.concern_tree import _evaluate
        sig = inspect.signature(_evaluate)
        assert "vulnerability_text" not in sig.parameters

    def test_evidence_pool_never_stores_vulnerability_text(self):
        pool = EvidencePool(code_context="repo evidence", patch="diff")
        assert not hasattr(pool, "vulnerability_text")
        # Structural guarantee: sources() can only ever expose what the
        # pool was constructed with -- code_context/patch/acquired text.
        assert set(pool.sources()) <= {"repo evidence", "diff", ""}

    def test_citation_naming_vulnerability_text_only_content_fails(self):
        """A citation that exists only in a `vulnerability_text`-shaped
        string never passed into the pool must not validate -- proves the
        boundary is structural (the pool literally never received it),
        not merely a naming convention."""
        llm = _llm(_proven(citation="only in the advisory, not the repo"))
        result = evaluate_concern_tree(
            "root", code_context="unrelated repo content", patch="",
            llm=llm,
        )
        assert result["root_final_status"] == "UNRESOLVED"
        assert result["nodes"][result["root_id"]]["unresolved_reason"] == "invalid_provenance"


class TestBaselineIsolation:
    def test_no_production_module_imports_concern_tree(self):
        """concerns_v2 (`patch_challenger.py`) and `pipeline.py` must never
        import from this experimental module -- one-directional dependency
        only (concern_tree.py -> reused primitives, never the reverse)."""
        challenger_src = Path("utilities/autopatcher/patch_challenger.py").read_text()
        pipeline_src = Path("utilities/autopatcher/pipeline.py").read_text()
        assert "concern_tree" not in challenger_src
        assert "concern_tree" not in pipeline_src


class TestDecomposeDrivenByReasoningComplexityNotEvidenceAvailability:
    """Regression guard for the DECOMPOSE-vs-REQUEST_EVIDENCE conceptual
    fix: a proposition must be decomposable purely because resolving it
    combines multiple independent judgments -- EVEN WHEN every fact
    needed for every child is already present in the pool. Decomposition
    and evidence acquisition are two different dimensions and must never
    be conflated by the controller's own behavior (the prompt-side fix is
    covered separately by `TestPromptContentRegressionGuard` below)."""

    _EVIDENCE = "fact_one: enabled\nfact_two: enabled\nfact_three: enabled\n"

    def _user_message(self, call):
        args, kwargs = call
        return args[1] if len(args) > 1 else kwargs["user_message"]

    def test_decompose_with_all_evidence_already_present(self):
        llm = _llm(
            _decompose(
                ["is fact one true", "is fact two true"],
                rationale="two independent judgments are needed",
            ),
            _proven(citation="fact_one: enabled", rationale="fact one holds"),
            _proven(citation="fact_two: enabled", rationale="fact two holds"),
            _refuted(citation="fact_one: enabled", rationale="both sub-questions together establish this"),
        )
        result = evaluate_concern_tree(
            "the combined condition does not hold", code_context=self._EVIDENCE, patch="", llm=llm,
        )

        # No evidence acquisition occurred anywhere in the tree -- the
        # DECOMPOSE here was driven purely by reasoning complexity.
        assert result["totals"]["evidence_requests"] == 0
        assert result["totals"]["evidence_acquired"] == 0
        for node in result["nodes"].values():
            assert node["evidence_requests"] == []

        root = result["nodes"][result["root_id"]]
        assert root["attempts"][0]["action"] == "DECOMPOSE"
        assert len(root["children"]) == 2
        for cid in root["children"]:
            assert result["nodes"][cid]["status"] == "PROVEN"
        assert result["root_final_status"] == "REFUTED"

        # Inspect the ACTUAL inputs supplied to the evaluator at every
        # call (not just the canned responses) to prove the required
        # properties directly, rather than merely asserting a call count.
        calls = llm.complete.call_args_list
        assert len(calls) == 4  # root initial, child 1, child 2, root reconsideration

        # 1. The evidence was present BEFORE decomposition -- already in
        #    the very first, root-level call.
        root_initial_message = self._user_message(calls[0])
        assert self._EVIDENCE.strip() in root_initial_message

        # 2. The SAME evidence remained available to both children (no
        #    pruning per child).
        for call in calls[1:3]:
            assert self._EVIDENCE.strip() in self._user_message(call)

        # 3. No acquisition occurred at any point in the sequence -- the
        #    evidence text is identical, byte-for-byte, in every one of
        #    the four calls (nothing was ever added to the pool).
        for call in calls:
            assert self._EVIDENCE.strip() in self._user_message(call)

        # 4. Child results were supplied during parent reconsideration.
        reconsideration_message = self._user_message(calls[3])
        assert "Sub-question results" in reconsideration_message
        assert "is fact one true" in reconsideration_message
        assert "is fact two true" in reconsideration_message
        assert "PROVEN" in reconsideration_message

    def test_atomic_proposition_still_resolves_directly_without_decomposing(self):
        """Companion case: an already-atomic proposition must still be
        resolvable in one step -- the fix must not push the evaluator
        toward decomposing everything indiscriminately."""
        llm = _llm(_proven(citation="fact_one: enabled"))
        result = evaluate_concern_tree(
            "fact one holds", code_context=self._EVIDENCE, patch="", llm=llm,
        )
        assert result["root_final_status"] == "PROVEN"
        assert result["nodes"][result["root_id"]]["children"] == []


class TestAdversarialTerminalCheckStructure:
    """Structural (shape-only) gate for the two new terminal-check
    sections required before PROVEN/REFUTED (`Necessary conditions:` /
    `Evidence conflict check:`). Never a semantic judgment of their
    content -- only presence/non-emptiness is enforced (see module
    docstring's deterministic-vs-semantic boundary)."""

    def test_proven_with_both_sections_parses(self):
        action = parse_action(_proven())
        assert action.kind == "PROVEN"
        assert action.necessary_conditions == ("nothing further",)
        assert action.evidence_conflict_check == ("none found",)

    def test_refuted_with_both_sections_parses(self):
        action = parse_action(_refuted())
        assert action.kind == "REFUTED"
        assert action.necessary_conditions == ("nothing further",)
        assert action.evidence_conflict_check == ("none found",)

    def test_proven_missing_necessary_conditions_fails_closed(self):
        raw = "Evidence conflict check:\n- none found\nAction: PROVEN\nRationale: r\nCitations:\n- x\n"
        assert parse_action(raw).kind == "INVALID"

    def test_proven_empty_necessary_conditions_fails_closed(self):
        raw = (
            "Necessary conditions:\nEvidence conflict check:\n- none found\n"
            "Action: PROVEN\nRationale: r\nCitations:\n- x\n"
        )
        assert parse_action(raw).kind == "INVALID"

    def test_proven_missing_evidence_conflict_check_fails_closed(self):
        raw = "Necessary conditions:\n- nothing further\nAction: PROVEN\nRationale: r\nCitations:\n- x\n"
        assert parse_action(raw).kind == "INVALID"

    def test_proven_empty_evidence_conflict_check_fails_closed(self):
        raw = (
            "Necessary conditions:\n- nothing further\nEvidence conflict check:\n"
            "Action: PROVEN\nRationale: r\nCitations:\n- x\n"
        )
        assert parse_action(raw).kind == "INVALID"

    def test_refuted_missing_necessary_conditions_fails_closed(self):
        raw = "Evidence conflict check:\n- none found\nAction: REFUTED\nRationale: r\nCitations:\n- x\n"
        assert parse_action(raw).kind == "INVALID"

    def test_refuted_empty_necessary_conditions_fails_closed(self):
        raw = (
            "Necessary conditions:\nEvidence conflict check:\n- none found\n"
            "Action: REFUTED\nRationale: r\nCitations:\n- x\n"
        )
        assert parse_action(raw).kind == "INVALID"

    def test_refuted_missing_evidence_conflict_check_fails_closed(self):
        raw = "Necessary conditions:\n- nothing further\nAction: REFUTED\nRationale: r\nCitations:\n- x\n"
        assert parse_action(raw).kind == "INVALID"

    def test_refuted_empty_evidence_conflict_check_fails_closed(self):
        raw = (
            "Necessary conditions:\n- nothing further\nEvidence conflict check:\n"
            "Action: REFUTED\nRationale: r\nCitations:\n- x\n"
        )
        assert parse_action(raw).kind == "INVALID"

    def test_decompose_remains_valid_without_terminal_only_fields(self):
        action = parse_action(_decompose(["question A", "question B"]))
        assert action.kind == "DECOMPOSE"
        assert action.necessary_conditions == ()
        assert action.evidence_conflict_check == ()

    def test_request_evidence_remains_valid_without_terminal_only_fields(self):
        action = parse_action(_request_evidence())
        assert action.kind == "REQUEST_EVIDENCE"
        assert action.necessary_conditions == ()
        assert action.evidence_conflict_check == ()

    def test_unresolved_remains_valid_without_terminal_only_fields(self):
        action = parse_action(_unresolved())
        assert action.kind == "UNRESOLVED"
        assert action.necessary_conditions == ()
        assert action.evidence_conflict_check == ()

    def test_terminal_trace_records_necessary_conditions(self):
        llm = _llm(_proven(necessary_conditions=("a specific dependency this rests on",)))
        result = evaluate_concern_tree("root", code_context="x", patch="", llm=llm)
        root = result["nodes"][result["root_id"]]
        assert root["attempts"][0]["necessary_conditions"] == ["a specific dependency this rests on"]

    def test_terminal_trace_records_evidence_conflict_check(self):
        llm = _llm(_proven(evidence_conflict_check=("checked already-visible evidence, nothing conflicts",)))
        result = evaluate_concern_tree("root", code_context="x", patch="", llm=llm)
        root = result["nodes"][result["root_id"]]
        assert root["attempts"][0]["evidence_conflict_check"] == ["checked already-visible evidence, nothing conflicts"]

    def test_deterministic_gate_does_not_inspect_semantic_content(self):
        """Arbitrary, generic non-empty text -- including nonsense -- must
        pass the structural gate: the deterministic parser only checks
        that the section exists and is non-empty, never whether its
        content is correct, complete, or even sensible."""
        raw = _proven(
            necessary_conditions=("literally anything, gibberish included: xyzzy 12345",),
            evidence_conflict_check=("also arbitrary: qwerty asdf",),
        )
        assert parse_action(raw).kind == "PROVEN"


class TestGenericAdversarialProtocolScenarios:
    """End-to-end scripted scenarios (mocked LLM) demonstrating the new
    protocol's intended shape. These mock the MODEL's choices -- they do
    not test model judgment itself -- they prove the CONTROLLER correctly
    carries each scenario through to the expected tree shape. No
    mechanism vocabulary (guard/control-flow/parser/etc.) anywhere."""

    def test_complex_proposition_decomposes_instead_of_premature_terminal(self):
        """Item 20 -- an independent necessary condition is identified and
        the evaluator chooses DECOMPOSE on its first call rather than
        answering PROVEN/REFUTED immediately."""
        llm = _llm(
            _decompose(
                ["is the primary fact directly evidenced",
                 "does anything already shown prevent it from applying"],
                rationale="the candidate conclusion depends on an independent, not-yet-checked condition",
            ),
            _proven(citation="fact_one: enabled"),
            _proven(citation="no override present", rationale="nothing prevents the primary fact from applying"),
            _proven(citation="fact_one: enabled", rationale="both sub-questions together establish the root"),
        )
        result = evaluate_concern_tree(
            "the outcome always follows from the primary fact",
            code_context="fact_one: enabled\nno override present", patch="", llm=llm,
        )
        assert result["root_final_status"] == "PROVEN"
        root = result["nodes"][result["root_id"]]
        assert root["attempts"][0]["action"] == "DECOMPOSE"
        assert len(root["children"]) == 2

    def test_atomic_proposition_resolves_inline_after_terminal_checks(self):
        """Item 21 -- necessary conditions are resolved inline and the
        conflict check finds nothing, so the proposition still terminates
        directly, without unnecessary decomposition."""
        llm = _llm(_proven(
            citation="value_is_set: true",
            necessary_conditions=("the flag is actually set, not merely declared",),
            evidence_conflict_check=("none found",),
        ))
        result = evaluate_concern_tree(
            "the flag is set", code_context="value_is_set: true", patch="", llm=llm,
        )
        assert result["root_final_status"] == "PROVEN"
        root = result["nodes"][result["root_id"]]
        assert root["children"] == []
        assert root["attempts"][0]["necessary_conditions"] == ["the flag is actually set, not merely declared"]

    def test_conflicting_visible_evidence_prevents_premature_terminal_verdict(self):
        """Item 22 -- evidence supporting a candidate conclusion is
        present, but the evidence-conflict check surfaces already-visible
        conflicting evidence, so the evaluator does not finalize a
        premature PROVEN on the first pass -- it decomposes instead."""
        llm = _llm(
            _decompose(
                ["does the supporting fact hold",
                 "does the already-visible countermanding fact defeat it"],
                rationale="the evidence conflict check found something already shown that is in tension "
                          "with the initial candidate conclusion",
            ),
            _proven(citation="supporting_fact: true"),
            _proven(citation="countermanding_fact: true", rationale="the countermanding fact also holds"),
            _refuted(citation="countermanding_fact: true",
                     rationale="the countermanding fact defeats the supporting one"),
        )
        result = evaluate_concern_tree(
            "the supporting fact determines the outcome",
            code_context="supporting_fact: true\ncountermanding_fact: true", patch="", llm=llm,
        )
        assert result["root_final_status"] == "REFUTED"
        root = result["nodes"][result["root_id"]]
        assert root["attempts"][0]["action"] == "DECOMPOSE"

    def test_missing_repository_fact_triggers_request_evidence_not_guess(self, tmp_path):
        """Item 23 -- the terminal analysis identifies a necessary
        condition that depends on a specific repository fact genuinely
        absent from the pool, and requests it rather than guessing."""
        (tmp_path / "mod.py").write_text("fact_one: enabled\n")
        llm = _llm(
            _request_evidence(file_hint="mod.py", rationale="need to see whether the fact is actually set"),
            _proven(citation="fact_one: enabled"),
        )
        result = evaluate_concern_tree(
            "the fact is set", code_context="", patch="", llm=llm,
            repo_root=tmp_path, investigation_context=object(),
        )
        assert result["root_final_status"] == "PROVEN"
        root = result["nodes"][result["root_id"]]
        assert root["attempts"][0]["action"] == "REQUEST_EVIDENCE"

    def test_universal_claim_exposes_completeness_obligation_instead_of_one_example(self):
        """Item 24 -- a proposition phrased as a universal/absence claim
        is not accepted on the strength of a single observed example; the
        evaluator exposes the completeness obligation via DECOMPOSE
        instead of terminating on one supporting instance."""
        llm = _llm(
            _decompose(
                ["does the one directly-evidenced case behave this way",
                 "is there any other case not shown here that might behave differently"],
                rationale="the claim is universal in scope; one example is not enough to establish completeness",
            ),
            _proven(citation="case_one: behaves_this_way"),
            _unresolved(reason="whether other cases exist is not resolvable from the evidence shown"),
            _unresolved(reason="completeness across all cases cannot be established from what is shown"),
        )
        result = evaluate_concern_tree(
            "this always behaves the same way in every case",
            code_context="case_one: behaves_this_way", patch="", llm=llm,
        )
        assert result["root_final_status"] == "UNRESOLVED"
        root = result["nodes"][result["root_id"]]
        assert root["attempts"][0]["action"] == "DECOMPOSE"


class TestPromptContentRegressionGuard:
    """Locks the DECOMPOSE-vs-REQUEST_EVIDENCE conceptual fix into the
    prompt file itself, so this specific conceptual regression cannot
    silently return later without a test noticing."""

    def _text(self):
        from utilities.autopatcher.concern_tree import _PROMPT_PATH
        return _PROMPT_PATH.read_text(encoding="utf-8")

    def test_old_evidence_gated_decompose_instruction_is_gone(self):
        text = self._text()
        assert "already know the answer to from evidence already shown" not in text
        assert "resolve it directly with PROVEN/REFUTED instead of\ncreating a child" not in text

    def test_decompose_is_explicitly_about_reasoning_not_evidence(self):
        text = self._text()
        assert "REASONING COMPLEXITY, not" in text
        assert "EVEN IF every fact needed for every child is already fully visible" in text

    def test_decompose_and_request_evidence_definitions_are_both_present_and_distinct(self):
        text = self._text()
        assert "this proposition requires combining more than one" in text
        assert "a specific repository fact needed to resolve THIS" in text
        assert "must never be conflated" in text

    def test_atomicity_and_relatedness_guidance_still_present(self):
        """The pre-existing instructions this fix must NOT weaken."""
        text = self._text()
        assert "never a question about something unrelated to the parent" in text
        assert "genuinely atomic" in text

    def test_terminal_check_guidance_present_and_generic(self):
        """Locks in the generic adversarial terminal-verdict protocol
        (necessary conditions + evidence conflict check) -- and confirms
        no mechanism-specific vocabulary was introduced for it."""
        text = self._text()
        assert "Necessary conditions" in text
        assert "Evidence conflict check" in text
        assert "BEFORE the `Action:` line" in text
        assert "none found" in text
        for forbidden in ("control flow", "control-flow", "data flow", "data-flow",
                           "state transition", "ordering", "parser complete", "config_complete"):
            assert forbidden not in text.lower()

    def test_terminal_check_does_not_require_proving_negation_separately(self):
        text = self._text()
        assert "not a requirement to prove the proposition AND separately disprove" in text

    def test_absence_and_universal_claim_guidance_present(self):
        text = self._text()
        assert "Absence and universal claims" in text
        assert "no other path" in text
        assert "never modified" in text

    def test_citation_format_requires_one_exact_contiguous_quote(self):
        """Item 18 -- the prompt explicitly requires one exact contiguous
        quote per citation."""
        text = self._text()
        assert "one exact contiguous quote" in text

    def test_citation_format_forbids_split_joined_escaped_or_paraphrased(self):
        """Item 19 -- the prompt explicitly forbids split citations,
        joined citations, invented escaping, and paraphrase."""
        text = self._text()
        assert "never split one quotation across" in text
        assert "never combine two separate quotations into one" in text
        assert "do not add escape characters that were not" in text
        assert "literally present in the evidence" in text
        assert "never paraphrase, summarize, or reconstruct from memory" in text
