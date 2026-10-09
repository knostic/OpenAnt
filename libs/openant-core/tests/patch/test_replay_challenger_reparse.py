"""Tests for the zero-LLM deterministic Challenger reparse debug tool
(utilities/autopatcher/tools/replay_challenger_reparse.py).

Hermetic: hand-built manifest fixtures on tmp_path (same convention as
test_lineage.py), no LLM, no real repo, no Docker, no network. This file
tests the WRAPPER's own resolution/equivalence behavior -- it does not
duplicate patch_challenger.py's own test suite (test_patch_challenger.py
already covers every parsing/derivation rule)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from utilities.autopatcher.lineage import (
    INVOCATION_KIND_INITIAL,
    LineageError,
    make_execution_id,
    new_execution_record,
    new_full_run_manifest,
)
from utilities.autopatcher.tools.replay_challenger_reparse import (
    ReparseError,
    reparse_challenger_response,
    replay_challenger_reparse,
)

_CODE_CONTEXT = (
    "#### Full file (last resort): `pkg/mod.py` (2 lines)\n\n"
    "```python\n"
    "def f():\n"
    "    op()\n"
    "```\n"
)

_VULNERABILITY_TEXT = "some vuln"
_PATCH = "some diff"

_RESPONSE_TEXT = (
    "Verification status: VERIFIED_FIXED\n\n"
    "Concerns:\n\n"
    "1. Role: primary\n"
    "   Description: a concern\n"
    "   Operation present in evidence: present\n"
    "   Preceding guard: absent\n"
    "   Guard provenance: whole function\n"
    "   Function provenance: def f():\n"
    "   Operation provenance: op()\n"
    "   Guard default state: not_applicable\n"
    "   Guard effect: not_applicable\n"
    "   Reentry state propagation: not_applicable\n"
    "   Requires explicit non-default action: not_applicable\n"
    "   Contract addresses override: not_applicable\n\n"
    "Edge cases:\n- none\n\n"
    "Potential issues:\n- none\n\n"
    "Summary:\n- none\n"
)


def _write_manifest(run_dir: Path, executions: list) -> Path:
    manifest = new_full_run_manifest(
        target_repository={"repo_root": "/repo", "repo_commit": "aaa"},
        openant={"patcher_commit": "bbb"},
        llm={"provider": "mock", "model": "mock"},
        executions=executions,
    )
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return run_dir


def _build_archived_run(
    tmp_path: Path, *, response_text: str = _RESPONSE_TEXT, include_s4: bool = True,
    include_challenger: bool = True, nested_trace_dir: bool = False,
) -> Path:
    """A minimal, hand-built archived full-run directory: one
    patch_generation_and_post_patch_investigation execution (S4) whose
    artifact carries vulnerability_text/patch/challenger_context, and one
    challenger execution whose own llm_calls entry points at a raw
    response file.

    `nested_trace_dir=False` (default): everything (manifest, artifacts,
    response file) lives directly in `run_dir` -- mirrors a bare
    run_traced.py layout with no nested trace/, and `run_dir` is itself
    the returned path.

    `nested_trace_dir=True`: reproduces the REAL run_traced.py layout AND
    the real path-shape discrepancy this fixture exists to regress-test:
    everything lives under `run_dir/trace/`, but `consumed`'s recorded
    `"run"` identity is still the ROOT spelling (`str(run_dir)`, without
    `/trace`) -- exactly as real run_traced.py writes it (it always
    records `output_dir`, the run root, never the trace/ subdirectory it
    actually writes run_manifest.json into). The returned path is the
    ROOT (`run_dir`), matching what a caller resolves the manifest from
    either way; test cases exercise the mismatch explicitly."""
    run_dir = tmp_path / "run"
    manifest_dir = (run_dir / "trace") if nested_trace_dir else run_dir
    manifest_dir.mkdir(parents=True, exist_ok=True)
    consumed_run = str(run_dir)  # the ROOT spelling -- what real run_traced.py records

    executions = []
    s4_id = make_execution_id(1, "patch_generation_and_post_patch_investigation")
    if include_s4:
        s4_artifact_path = manifest_dir / "004_patch_generation_and_post_patch_investigation.json"
        s4_artifact_path.write_text(json.dumps({
            "vulnerability_text": _VULNERABILITY_TEXT,
            "patch": _PATCH,
            "challenger_context": _CODE_CONTEXT,
            "code_context": _CODE_CONTEXT,
        }), encoding="utf-8")
        executions.append(new_execution_record(
            execution_id=s4_id,
            canonical_stage="patch_generation_and_post_patch_investigation",
            sequence=1,
            invocation_kind=INVOCATION_KIND_INITIAL,
            outcome="settled",
            artifact_path=str(s4_artifact_path),
        ))

    if include_challenger:
        response_path = manifest_dir / "002_challenger.response.txt"
        response_path.write_text(response_text, encoding="utf-8")
        (manifest_dir / "002_challenger.prompt.txt").write_text("irrelevant", encoding="utf-8")
        challenger_artifact_path = manifest_dir / "005_challenger.json"
        challenger_artifact_path.write_text(json.dumps({"challenger": {}}), encoding="utf-8")
        executions.append(new_execution_record(
            execution_id=make_execution_id(2, "challenger"),
            canonical_stage="challenger",
            sequence=2,
            invocation_kind=INVOCATION_KIND_INITIAL,
            outcome="settled",
            consumed={"patch_generation_and_post_patch_investigation": {"run": consumed_run, "execution_id": s4_id}},
            artifact_path=str(challenger_artifact_path),
            llm_calls=[{
                "seq": 2,
                "stage": "challenger",
                "prompt_file": "002_challenger.prompt.txt",
                "response_file": "002_challenger.response.txt",
            }],
        ))

    _write_manifest(manifest_dir, executions)
    return run_dir


class TestThinWrapperEquivalence:
    """The most important property: the wrapper's result must be
    IDENTICAL to calling the current production post-response functions
    directly with the same (response, code_context, patch,
    vulnerability_text) -- no replay-specific semantic transformation."""

    def test_replay_result_matches_direct_reparse_call(self, tmp_path):
        run_dir = _build_archived_run(tmp_path)
        output_dir = tmp_path / "out"

        artifact = replay_challenger_reparse(run_dir, output_dir)

        expected = reparse_challenger_response(
            _RESPONSE_TEXT,
            code_context=_CODE_CONTEXT,
            patch=_PATCH,
            vulnerability_text=_VULNERABILITY_TEXT,
            # what production replay passes for an S4 artifact predating
            # challenger_provenance_parts / challenger_post_patch_definitions
            provenance_context="", post_patch_definitions=[],
        )
        assert artifact["result"] == expected

    def test_written_artifact_matches_returned_artifact(self, tmp_path):
        run_dir = _build_archived_run(tmp_path)
        output_dir = tmp_path / "out"

        artifact = replay_challenger_reparse(run_dir, output_dir)

        on_disk = json.loads((output_dir / "challenger_reparse.json").read_text())
        assert on_disk == artifact

    def test_absence_deescalation_is_visible_through_the_wrapper(self, tmp_path):
        """Sanity check that the wrapper genuinely exercises the current
        deterministic derivation (not a stale/cached copy): the fixture's
        `Preceding guard: absent` concern must resolve `unresolved`, per
        the current de-escalation rule -- proving this tool would in fact
        surface the architecture change against a real archived trace."""
        run_dir = _build_archived_run(tmp_path)
        artifact = replay_challenger_reparse(run_dir, tmp_path / "out")

        concern = artifact["result"]["concerns"][0]
        assert concern["malformed"] is False, concern.get("malformed_reason")
        assert concern["default_execution_reachability"] == "unresolved"
        assert concern["consequence"] == "UNRESOLVED"


class TestArchivedResponseWithoutHypothesizedOutcome:
    """Archived responses predate the `Hypothesized outcome:` field
    entirely -- its absence must be treated as a normal, valid case, not
    an error."""

    def test_missing_field_normalizes_to_none_not_an_error(self, tmp_path):
        run_dir = _build_archived_run(tmp_path)  # _RESPONSE_TEXT has no such field
        artifact = replay_challenger_reparse(run_dir, tmp_path / "out")

        concern = artifact["result"]["concerns"][0]
        assert concern["malformed"] is False
        assert concern["hypothesized_outcome"] is None


class TestHistoricalConsumedIdentityIgnoresRunRootVsTraceDirSpelling:
    """Regression test for the real failure diagnosed against
    /tmp/urllib3-tree-n5/run-1: the archived `challenger` execution's own
    `consumed` entry records the RUN-ROOT spelling of its dependency's
    run identity (exactly what real run_traced.py writes), while
    --source-run/`source_run` here is supplied using the TRACE-DIRECTORY
    spelling of that SAME physical run. Both spellings name the same
    historical run. The wrapper must resolve the exact historical
    artifact by following the recorded consumed identity directly
    (lineage.load_manifest() + an execution_id lookup) -- never via
    lineage.resolve_effective()'s current/effective-lineage resolution,
    which is exactly the freshness check that spuriously reported this
    real case as STALE."""

    def test_resolves_via_recorded_identity_despite_differing_source_run_spelling(self, tmp_path):
        run_root = _build_archived_run(tmp_path, nested_trace_dir=True)
        trace_dir = run_root / "trace"
        assert str(run_root) != str(trace_dir)  # the two spellings genuinely differ

        # Supplying the TRACE-DIR spelling as source_run is exactly the
        # shape that triggered the real STALE failure when the lookup
        # went through resolve_effective() -- it must not here.
        artifact = replay_challenger_reparse(trace_dir, tmp_path / "out")

        expected = reparse_challenger_response(
            _RESPONSE_TEXT,
            code_context=_CODE_CONTEXT,
            patch=_PATCH,
            vulnerability_text=_VULNERABILITY_TEXT,
            # what production replay passes for an S4 artifact predating
            # challenger_provenance_parts / challenger_post_patch_definitions
            provenance_context="", post_patch_definitions=[],
        )
        assert artifact["result"] == expected
        assert artifact["upstream_artifact_path"] == str(
            trace_dir / "004_patch_generation_and_post_patch_investigation.json"
        )

    def test_resolves_identically_via_run_root_spelling_too(self, tmp_path):
        """Same fixture, but source_run supplied using the ROOT spelling
        (the one that matches the recorded consumed identity exactly) --
        must resolve to the same result, confirming the fix is spelling-
        independent, not merely "happens to work for the trace-dir case"."""
        run_root = _build_archived_run(tmp_path, nested_trace_dir=True)

        artifact = replay_challenger_reparse(run_root, tmp_path / "out")

        expected = reparse_challenger_response(
            _RESPONSE_TEXT,
            code_context=_CODE_CONTEXT,
            patch=_PATCH,
            vulnerability_text=_VULNERABILITY_TEXT,
            # what production replay passes for an S4 artifact predating
            # challenger_provenance_parts / challenger_post_patch_definitions
            provenance_context="", post_patch_definitions=[],
        )
        assert artifact["result"] == expected


class TestNoLlmRequired:
    def test_no_llm_client_constructed_and_zero_calls_recorded(self, tmp_path, monkeypatch):
        """Deleting any provider credential from the environment must not
        affect this tool at all -- it never constructs an LLM client."""
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        run_dir = _build_archived_run(tmp_path)
        artifact = replay_challenger_reparse(run_dir, tmp_path / "out")

        assert artifact["llm_calls_made"] == 0


class TestMalformedSourceRunFailsClearly:
    def test_missing_run_manifest_raises_lineage_error(self, tmp_path):
        empty_dir = tmp_path / "not-a-run"
        empty_dir.mkdir()
        with pytest.raises(LineageError):
            replay_challenger_reparse(empty_dir, tmp_path / "out")

    def test_no_challenger_execution_raises_reparse_error(self, tmp_path):
        run_dir = _build_archived_run(tmp_path, include_challenger=False)
        with pytest.raises(ReparseError, match="challenger"):
            replay_challenger_reparse(run_dir, tmp_path / "out")

    def test_missing_upstream_dependency_raises_reparse_error(self, tmp_path):
        run_dir = _build_archived_run(tmp_path, include_s4=False)
        with pytest.raises(ReparseError, match="patch_generation_and_post_patch_investigation"):
            replay_challenger_reparse(run_dir, tmp_path / "out")

    def test_no_partial_output_written_on_failure(self, tmp_path):
        run_dir = _build_archived_run(tmp_path, include_challenger=False)
        output_dir = tmp_path / "out"
        with pytest.raises(ReparseError):
            replay_challenger_reparse(run_dir, output_dir)
        assert not (output_dir / "challenger_reparse.json").exists()


# ---------------------------------------------------------------------------
# PR #763 validation (N4): the tool is production `challenge_patch()` with the
# archived text in place of the LLM -- never a drifting copy of its logic.
# ---------------------------------------------------------------------------

import sys as _sys  # noqa: E402

_sys.path.insert(0, str(Path(__file__).parent))
from test_challenger_citation_polarity import (  # noqa: E402
    ADDING, FAR_GUARD_PATCH, FAR_GUARD_POST, GUARD, OP, PRE_CTX, SCOPING_BYPASSES,
    _post_definition, _post_definition_text, _v1, _v2,
)


def _reply(block, header="VERIFIED_FIXED", summary="- none"):
    return (f"Verification status: {header}\n\nConcerns:\n\n{block}\n"
            f"Edge cases:\n- none\n\nPotential issues:\n- none\n\nSummary:\n{summary}\n")


_FAR_CTX = PRE_CTX + "\n\n" + _post_definition_text(FAR_GUARD_POST)
_PARITY_CASES = {
    # (response, patch, shown context, post_patch_definitions)
    "v1-blocked-fails-closed": (_reply(_v1(GUARD)), ADDING, "", None),
    "v2-removed-guard-cross-file": (_reply(_v2(OP, GUARD)), SCOPING_BYPASSES["re-added-in-another-file"], PRE_CTX, None),
    "v2-trusted-definition-supports": (_reply(_v2(OP, GUARD)), FAR_GUARD_PATCH, _FAR_CTX, [_post_definition(FAR_GUARD_POST)]),
    "v2-text-definition-only": (_reply(_v2(OP, GUARD)), FAR_GUARD_PATCH, _FAR_CTX, None),
    "no-concerns-section": ("Verification status: VERIFIED_FIXED\n\nSummary:\nFixed.\n", ADDING, "", None),
    "self-contradicting-header": (_reply(_v2(OP, GUARD), header="RESIDUAL_VULNERABILITY"), ADDING, "", None),
    "substantive-summary": (_reply(_v2(OP, GUARD), summary="Still exploitable via bulk."), ADDING, "", None),
    "ambiguous-block-numbering": (_reply(_v2(OP, GUARD) + "\n2) Role: additional\n   Description: x\n"), ADDING, "", None),
}


class TestProductionParity:
    @pytest.mark.parametrize("case", list(_PARITY_CASES))
    def test_tool_result_equals_production(self, case):
        from unittest import mock

        from utilities.autopatcher.patch_challenger import challenge_patch

        response, patch, shown, definitions = _PARITY_CASES[case]
        llm = mock.MagicMock()
        llm.complete.return_value = response
        production = challenge_patch(
            "vuln", patch, llm, code_context=shown, provenance_context=shown or None,
            post_patch_definitions=definitions,
        )
        tool = reparse_challenger_response(
            response, code_context=shown, patch=patch, vulnerability_text="vuln",
            provenance_context=shown or None, post_patch_definitions=definitions,
        )
        assert tool == production

    def test_archived_run_uses_recorded_parts_and_definitions(self, tmp_path):
        """End to end through the tool: the S4 artifact's recorded citation
        parts and trusted definitions reach the decision exactly as the
        replay engine passes them."""
        run_dir = _build_archived_run(tmp_path, response_text=_reply(_v2(OP, GUARD)))
        s4_path = run_dir / "004_patch_generation_and_post_patch_investigation.json"
        s4_path.write_text(json.dumps({
            "vulnerability_text": "vuln", "patch": FAR_GUARD_PATCH, "challenger_context": _FAR_CTX,
            "challenger_provenance_parts": [_FAR_CTX],
            "challenger_post_patch_definitions": [_post_definition(FAR_GUARD_POST)],
        }), encoding="utf-8")
        artifact = replay_challenger_reparse(run_dir, tmp_path / "out")
        assert artifact["result"]["verification_status"] == "VERIFIED_FIXED"

        # the same archive without the trusted record fails closed
        s4_path.write_text(json.dumps({
            "vulnerability_text": "vuln", "patch": FAR_GUARD_PATCH, "challenger_context": _FAR_CTX,
            "challenger_provenance_parts": [_FAR_CTX],
        }), encoding="utf-8")
        artifact = replay_challenger_reparse(run_dir, tmp_path / "out2")
        assert artifact["result"]["verification_status"] == "INSUFFICIENT_EVIDENCE"
