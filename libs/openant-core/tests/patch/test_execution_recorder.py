"""Tests for utilities/autopatcher/execution_recorder.py -- Batch B2's
passive StageExecution recorder.

Hermetic: no LLM, no repo, no pipeline.run() -- exercises ExecutionRecorder
directly against a synthetic, hand-built `call_log` list, exactly the shape
tools/run_traced.py's LLMCallTracer.calls already produces. See
test_pipeline_execution_recording.py / test_run_traced_execution_recording.py
for end-to-end proof through the real pipeline/run_traced.py.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

import pytest

from utilities.autopatcher.execution_recorder import ExecutionRecorder, ExecutionRecorderError, to_jsonable
from utilities.autopatcher import lineage


def _call(seq, stage, **extra):
    """One synthetic LLM-call record, matching the shape
    llm_call_tracing.LLMCallCapture / tools/run_traced.py's LLMCallTracer
    actually produce (seq/stage/prompt/response/started_at/finished_at,
    plus prompt_chars/response_chars/prompt_file/response_file once
    LLMCallTracer's on_call hook has run)."""
    record = {
        "seq": seq, "stage": stage, "prompt": f"prompt-{seq}", "response": f"response-{seq}",
        "started_at": f"t{seq}-start", "finished_at": f"t{seq}-end",
        "prompt_chars": 10, "response_chars": 10,
        "prompt_file": f"{seq:03d}_{stage}.prompt.txt", "response_file": f"{seq:03d}_{stage}.response.txt",
    }
    record.update(extra)
    return record


# ---------------------------------------------------------------------------
# Basic lifecycle
# ---------------------------------------------------------------------------

class TestBasicLifecycle:
    def test_sequence_starts_at_one_and_increments(self, tmp_path):
        call_log = []
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=tmp_path / "executions")
        h1 = rec.start("repository_analysis_and_remediation_planning")
        r1 = rec.finish(h1, outcome="generated")
        h2 = rec.start("remediation_strategy")
        r2 = rec.finish(h2, outcome="generated")
        assert r1["sequence"] == 1
        assert r2["sequence"] == 2

    def test_execution_id_format(self, tmp_path):
        call_log = []
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=tmp_path / "executions")
        h1 = rec.start("repository_analysis_and_remediation_planning")
        r1 = rec.finish(h1, outcome="generated")
        assert r1["execution_id"] == "001_repository_analysis_and_remediation_planning"

    def test_executions_accumulate_in_order(self, tmp_path):
        call_log = []
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=tmp_path / "executions")
        for name in ("repository_analysis_and_remediation_planning", "remediation_strategy", "guided_context_acquisition"):
            h = rec.start(name)
            rec.finish(h, outcome="x")
        assert [e["canonical_stage"] for e in rec.executions] == [
            "repository_analysis_and_remediation_planning", "remediation_strategy", "guided_context_acquisition",
        ]

    def test_invocation_kind_defaults_to_initial(self, tmp_path):
        call_log = []
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=tmp_path / "executions")
        h = rec.start("challenger")
        r = rec.finish(h, outcome="settled")
        assert r["invocation_kind"] == lineage.INVOCATION_KIND_INITIAL

    def test_invoked_by_is_null_when_not_given(self, tmp_path):
        call_log = []
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=tmp_path / "executions")
        h = rec.start("challenger")
        r = rec.finish(h, outcome="settled")
        assert r["invoked_by"] is None


# ---------------------------------------------------------------------------
# consumed / invoked_by edge construction (exact identity, per B1 invariants)
# ---------------------------------------------------------------------------

class TestConsumedAndInvokedByEdges:
    def test_consumed_references_exact_run_and_execution_id(self, tmp_path):
        call_log = []
        run_dir = str(tmp_path / "the-run")
        rec = ExecutionRecorder(call_log=call_log, run_dir=run_dir, artifacts_dir=tmp_path / "executions")
        h1 = rec.start("repository_analysis_and_remediation_planning")
        s1 = rec.finish(h1, outcome="generated")
        h2 = rec.start("remediation_strategy", consumed=[s1])
        s2 = rec.finish(h2, outcome="generated")
        assert s2["consumed"] == {
            "repository_analysis_and_remediation_planning": {"run": run_dir, "execution_id": "001_repository_analysis_and_remediation_planning"},
        }

    def test_consumed_keyed_by_dependency_canonical_stage(self, tmp_path):
        call_log = []
        run_dir = str(tmp_path)
        rec = ExecutionRecorder(call_log=call_log, run_dir=run_dir, artifacts_dir=tmp_path / "executions")
        s1 = rec.finish(rec.start("repository_analysis_and_remediation_planning"), outcome="x")
        s2 = rec.finish(rec.start("remediation_strategy", consumed=[s1]), outcome="x")
        s3 = rec.finish(rec.start("guided_context_acquisition", consumed=[s1, s2]), outcome="x")
        assert set(s3["consumed"].keys()) == {"repository_analysis_and_remediation_planning", "remediation_strategy"}

    def test_empty_consumed_when_none_given(self, tmp_path):
        call_log = []
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=tmp_path / "executions")
        r = rec.finish(rec.start("repository_analysis_and_remediation_planning"), outcome="x")
        assert r["consumed"] == {}

    def test_invoked_by_references_exact_identity(self, tmp_path):
        call_log = []
        run_dir = str(tmp_path)
        rec = ExecutionRecorder(call_log=call_log, run_dir=run_dir, artifacts_dir=tmp_path / "executions")
        s6_1 = rec.finish(rec.start("patch_repair_and_calibration"), outcome="retry_patch")
        s4_2 = rec.finish(
            rec.start("patch_generation_and_post_patch_investigation", invocation_kind="retry", invoked_by=s6_1),
            outcome="settled",
        )
        assert s4_2["invoked_by"] == {"run": run_dir, "execution_id": s6_1["execution_id"]}
        assert s4_2["invocation_kind"] == "retry"


# ---------------------------------------------------------------------------
# LLM-call attribution -- the Final Correction 2 mechanism: cursor/slice
# against an EXTERNALLY-OWNED, already-ordered call_log, no capture of its
# own, no monkeypatching, no duplication, no leakage between brackets.
# ---------------------------------------------------------------------------

class TestLLMCallAttribution:
    def test_does_not_monkeypatch_call_llm(self, tmp_path):
        """Constructing/using an ExecutionRecorder must never touch
        utilities.autopatcher.llm_client.call_llm -- it is purely a passive
        reader of a list some OTHER mechanism already owns."""
        import utilities.autopatcher.llm_client as llm_client_module

        original = llm_client_module.call_llm
        call_log = []
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=tmp_path / "executions")
        h = rec.start("challenger")
        call_log.append(_call(1, "challenger"))
        rec.finish(h, outcome="settled")
        assert llm_client_module.call_llm is original

    def test_execution_recorder_module_imports_no_capture_class(self):
        """Structural check: execution_recorder.py must not import
        LLMCallCapture (or anything from llm_call_tracing) at all -- it has
        no business owning a capture/monkeypatch mechanism (Final
        Correction 2)."""
        import utilities.autopatcher.execution_recorder as er_module
        assert "LLMCallCapture" not in dir(er_module)
        assert not hasattr(er_module, "llm_call_tracing")

    def test_calls_made_during_bracket_attach_to_that_execution(self, tmp_path):
        call_log = []
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=tmp_path / "executions")
        h = rec.start("repository_analysis_and_remediation_planning")
        call_log.append(_call(1, "remediation_planning"))
        r = rec.finish(h, outcome="generated")
        assert [c["seq"] for c in r["llm_calls"]] == [1]

    def test_multiple_calls_during_one_bracket_all_attach_to_it(self, tmp_path):
        """S4's internal contract-retry/applicability-retry calls all
        belong to ONE S4 execution -- proven here with a synthetic
        multi-call window standing in for that internal retry behavior."""
        call_log = []
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=tmp_path / "executions")
        h = rec.start("patch_generation_and_post_patch_investigation")
        call_log.append(_call(1, "patch_generation"))
        call_log.append(_call(2, "patch_generation_contract_retry"))
        call_log.append(_call(3, "patch_generation"))
        r = rec.finish(h, outcome="settled")
        assert [c["seq"] for c in r["llm_calls"]] == [1, 2, 3]

    def test_calls_before_start_are_excluded(self, tmp_path):
        call_log = [_call(1, "remediation_planning")]  # happened BEFORE this execution starts
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=tmp_path / "executions")
        h = rec.start("remediation_strategy")
        call_log.append(_call(2, "remediation_strategy"))
        r = rec.finish(h, outcome="generated")
        assert [c["seq"] for c in r["llm_calls"]] == [2]

    def test_calls_after_finish_are_excluded(self, tmp_path):
        call_log = []
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=tmp_path / "executions")
        h = rec.start("challenger")
        call_log.append(_call(1, "challenger"))
        r = rec.finish(h, outcome="settled")
        call_log.append(_call(2, "finding_calibration"))  # repair loop, unrecorded, after recording stopped
        assert [c["seq"] for c in r["llm_calls"]] == [1]

    def test_adjacent_stages_do_not_leak_into_each_other(self, tmp_path):
        """S1's calls belong only to S1; S2's calls belong only to S2 --
        proves non-overlapping windows across the whole S1-S5 sequence."""
        call_log = []
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=tmp_path / "executions")

        h1 = rec.start("repository_analysis_and_remediation_planning")
        call_log.append(_call(1, "remediation_planning"))
        s1 = rec.finish(h1, outcome="generated")

        h2 = rec.start("remediation_strategy")
        call_log.append(_call(2, "remediation_strategy"))
        s2 = rec.finish(h2, outcome="generated")

        h3 = rec.start("guided_context_acquisition")
        call_log.append(_call(3, "guided_context_request"))
        call_log.append(_call(4, "guided_context_request"))
        s3 = rec.finish(h3, outcome="ready")

        h4 = rec.start("patch_generation_and_post_patch_investigation")
        call_log.append(_call(5, "patch_generation"))
        s4 = rec.finish(h4, outcome="settled")

        h5 = rec.start("challenger")
        call_log.append(_call(6, "challenger"))
        s5 = rec.finish(h5, outcome="settled")

        assert [c["seq"] for c in s1["llm_calls"]] == [1]
        assert [c["seq"] for c in s2["llm_calls"]] == [2]
        assert [c["seq"] for c in s3["llm_calls"]] == [3, 4]
        assert [c["seq"] for c in s4["llm_calls"]] == [5]
        assert [c["seq"] for c in s5["llm_calls"]] == [6]
        # No call appears in two execution records.
        all_seqs = [c["seq"] for exe in (s1, s2, s3, s4, s5) for c in exe["llm_calls"]]
        assert sorted(all_seqs) == [1, 2, 3, 4, 5, 6]
        assert len(all_seqs) == len(set(all_seqs))

    def test_repair_loop_calls_after_recording_stops_attach_nowhere(self, tmp_path):
        """Calls made by an unrecorded region (e.g. the repair loop, which
        B2 never brackets) must not be falsely attached to the last
        recorded execution (S5) -- they simply never appear in `executions`
        at all, which is the honest, correct outcome."""
        call_log = []
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=tmp_path / "executions")
        h5 = rec.start("challenger")
        call_log.append(_call(1, "challenger"))
        s5 = rec.finish(h5, outcome="settled")
        # Repair loop fires afterward, unrecorded:
        call_log.append(_call(2, "finding_calibration"))
        call_log.append(_call(3, "patch_repair_regeneration"))
        call_log.append(_call(4, "challenger"))
        assert [c["seq"] for c in s5["llm_calls"]] == [1]
        assert len(rec.executions) == 1

    def test_llm_calls_strip_full_prompt_response_text(self, tmp_path):
        """Full prompt/response text stays in the *.prompt.txt/*.response.txt
        files already written elsewhere -- the execution record keeps only
        pointers (prompt_file/response_file) plus small metadata."""
        call_log = []
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=tmp_path / "executions")
        h = rec.start("challenger")
        call_log.append(_call(1, "challenger"))
        r = rec.finish(h, outcome="settled")
        assert "prompt" not in r["llm_calls"][0]
        assert "response" not in r["llm_calls"][0]
        assert r["llm_calls"][0]["prompt_file"] == "001_challenger.prompt.txt"

    def test_llm_calls_json_serializable_as_is(self, tmp_path):
        call_log = []
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=tmp_path / "executions")
        h = rec.start("challenger")
        call_log.append(_call(1, "challenger"))
        r = rec.finish(h, outcome="settled")
        json.dumps(r["llm_calls"])  # must not raise


# ---------------------------------------------------------------------------
# Artifact files
# ---------------------------------------------------------------------------

class TestArtifactFiles:
    def test_artifact_written_with_execution_id_filename(self, tmp_path):
        artifacts_dir = tmp_path / "executions"
        rec = ExecutionRecorder(call_log=[], run_dir=str(tmp_path), artifacts_dir=artifacts_dir)
        h = rec.start("repository_analysis_and_remediation_planning")
        r = rec.finish(h, outcome="generated", artifact={"plan_result": {"rendered": "x"}})
        expected = artifacts_dir / "001_repository_analysis_and_remediation_planning.json"
        assert expected.is_file()
        assert r["artifact_path"] == str(expected)

    def test_artifact_content_matches_what_was_written(self, tmp_path):
        artifacts_dir = tmp_path / "executions"
        rec = ExecutionRecorder(call_log=[], run_dir=str(tmp_path), artifacts_dir=artifacts_dir)
        h = rec.start("challenger")
        rec.finish(h, outcome="settled", artifact={"challenger": {"still_vulnerable": False}})
        written = json.loads((artifacts_dir / "001_challenger.json").read_text())
        assert written == {"challenger": {"still_vulnerable": False}}

    def test_no_artifact_file_when_artifact_is_none(self, tmp_path):
        artifacts_dir = tmp_path / "executions"
        rec = ExecutionRecorder(call_log=[], run_dir=str(tmp_path), artifacts_dir=artifacts_dir)
        h = rec.start("challenger")
        r = rec.finish(h, outcome="skipped_no_candidate_patch", artifact=None)
        assert r["artifact_path"] is None
        assert not artifacts_dir.exists() or not list(artifacts_dir.glob("*.json"))

    def test_repeated_executions_of_same_stage_do_not_collide(self, tmp_path):
        """Even though B2 only ever records one execution per canonical
        stage, the filename must not assume that -- execution_id (not bare
        canonical_stage) is the filename, so two executions of the SAME
        stage in one run never overwrite each other."""
        artifacts_dir = tmp_path / "executions"
        rec = ExecutionRecorder(call_log=[], run_dir=str(tmp_path), artifacts_dir=artifacts_dir)
        rec.finish(rec.start("challenger"), outcome="a", artifact={"n": 1})
        rec.finish(rec.start("challenger"), outcome="b", artifact={"n": 2})
        first = json.loads((artifacts_dir / "001_challenger.json").read_text())
        second = json.loads((artifacts_dir / "002_challenger.json").read_text())
        assert first == {"n": 1}
        assert second == {"n": 2}

    def test_artifacts_are_immutable_once_written(self, tmp_path):
        artifacts_dir = tmp_path / "executions"
        rec = ExecutionRecorder(call_log=[], run_dir=str(tmp_path), artifacts_dir=artifacts_dir)
        rec.finish(rec.start("challenger"), outcome="a", artifact={"n": 1})
        before = (artifacts_dir / "001_challenger.json").read_bytes()
        rec.finish(rec.start("patch_generation_and_post_patch_investigation"), outcome="settled", artifact={"n": 2})
        assert (artifacts_dir / "001_challenger.json").read_bytes() == before


# ---------------------------------------------------------------------------
# to_jsonable -- the recursive dataclass/NamedTuple serializer
# ---------------------------------------------------------------------------

class _NTInner(NamedTuple):
    file: "str | None"
    symbol: "str | None"


class _NTOuter(NamedTuple):
    edit: _NTInner
    reason: str


@dataclass
class _DCInner:
    name: str
    tags: "list[str]"


@dataclass
class _DCOuter:
    inner: _DCInner
    items: "list[_NTOuter]"


class TestToJsonable:
    def test_primitives_pass_through(self):
        assert to_jsonable(None) is None
        assert to_jsonable("x") == "x"
        assert to_jsonable(1) == 1
        assert to_jsonable(1.5) == 1.5
        assert to_jsonable(True) is True

    def test_path_becomes_string(self):
        assert to_jsonable(Path("/a/b")) == str(Path("/a/b"))

    def test_flat_namedtuple_becomes_keyed_dict(self):
        nt = _NTInner(file="a.py", symbol="foo")
        result = to_jsonable(nt)
        assert result == {"file": "a.py", "symbol": "foo"}
        assert isinstance(result, dict)

    def test_nested_namedtuple_stays_keyed_not_positional(self):
        """THE core proof: a NamedTuple nested inside another NamedTuple
        must serialize as a keyed object at BOTH levels -- json.dumps on a
        bare NamedTuple would otherwise silently produce a positional
        array for the inner one."""
        outer = _NTOuter(edit=_NTInner(file="a.py", symbol="foo"), reason="unresolved_symbol")
        result = to_jsonable(outer)
        assert result == {"edit": {"file": "a.py", "symbol": "foo"}, "reason": "unresolved_symbol"}
        assert isinstance(result["edit"], dict)  # NOT a list/tuple

    def test_namedtuple_list_field_all_keyed(self):
        class Holder(NamedTuple):
            edits: "list"
        h = Holder(edits=[_NTInner(file="a.py", symbol=None), _NTInner(file="b.py", symbol="x")])
        result = to_jsonable(h)
        assert result["edits"] == [{"file": "a.py", "symbol": None}, {"file": "b.py", "symbol": "x"}]

    def test_dataclass_recurses_into_nested_dataclass_and_namedtuple(self):
        outer = _DCOuter(
            inner=_DCInner(name="n", tags=["a", "b"]),
            items=[_NTOuter(edit=_NTInner(file="a.py", symbol="foo"), reason="x")],
        )
        result = to_jsonable(outer)
        assert result == {
            "inner": {"name": "n", "tags": ["a", "b"]},
            "items": [{"edit": {"file": "a.py", "symbol": "foo"}, "reason": "x"}],
        }

    def test_dict_and_list_and_set_recurse(self):
        assert to_jsonable({"a": [1, 2, {3, 4}]}) in (
            {"a": [1, 2, [3, 4]]}, {"a": [1, 2, [4, 3]]},
        )

    def test_none_passes_through_in_container(self):
        assert to_jsonable({"x": None}) == {"x": None}

    def test_result_is_always_json_dumpable(self):
        outer = _DCOuter(
            inner=_DCInner(name="n", tags=["a"]),
            items=[_NTOuter(edit=_NTInner(file=None, symbol=None), reason="x")],
        )
        json.dumps(to_jsonable(outer))  # must not raise

    def test_round_trip_preserves_keyed_shape(self):
        outer = _NTOuter(edit=_NTInner(file="a.py", symbol="foo"), reason="x")
        round_tripped = json.loads(json.dumps(to_jsonable(outer)))
        assert round_tripped == {"edit": {"file": "a.py", "symbol": "foo"}, "reason": "x"}

    def test_unsupported_type_raises_instead_of_stringifying(self):
        """Correction 2: no str()/repr() fallback -- an object type
        to_jsonable() doesn't explicitly support must raise, not degrade
        to a display string."""
        class _Unsupported:
            pass

        with pytest.raises(ExecutionRecorderError):
            to_jsonable(_Unsupported())

    def test_unsupported_type_error_never_contains_object_repr_as_the_result(self):
        class _Unsupported:
            def __repr__(self):
                return "<_Unsupported object at 0xdeadbeef>"

        with pytest.raises(ExecutionRecorderError) as exc_info:
            to_jsonable(_Unsupported())
        # The failure is an exception, not a returned "<... object at
        # 0x...>" string standing in as if it were valid JSON content.
        assert "cannot serialize" in str(exc_info.value)

    def test_unsupported_type_nested_inside_supported_container_also_raises(self):
        class _Unsupported:
            pass

        with pytest.raises(ExecutionRecorderError):
            to_jsonable({"ok": "fine", "bad": _Unsupported()})
        with pytest.raises(ExecutionRecorderError):
            to_jsonable([1, 2, _Unsupported()])

    def test_unsupported_type_nested_inside_dataclass_also_raises(self):
        @dataclass
        class _Unsupported:
            pass

        @dataclass
        class _Holder:
            bad: object

        # _Unsupported is itself a supported dataclass -- use a genuinely
        # unsupported field value (a set of unhashable dicts is invalid
        # Python; use a bare function object, which is never supported).
        with pytest.raises(ExecutionRecorderError):
            to_jsonable(_Holder(bad=lambda: None))

    def test_set_of_strings_serializes_sorted_and_deterministic(self):
        result = to_jsonable({"c", "a", "b"})
        assert result == ["a", "b", "c"]

    def test_frozenset_of_strings_serializes_sorted(self):
        result = to_jsonable(frozenset({"z", "y"}))
        assert result == ["y", "z"]

    def test_set_of_namedtuples_serializes_deterministically_via_json_key_fallback(self):
        """Converted NamedTuple elements become dicts, which are not
        orderable with `<` -- this must fall back to sorting by each
        element's own JSON form rather than raising or returning an
        arbitrary hash-seed-dependent order."""
        items = {_NTInner(file="b.py", symbol=None), _NTInner(file="a.py", symbol=None)}
        result = to_jsonable(items)
        assert result == [{"file": "a.py", "symbol": None}, {"file": "b.py", "symbol": None}]

    def test_repeated_calls_on_equal_but_freshly_constructed_sets_match(self):
        """Same logical set, two different Python objects/insertion
        orders -- must serialize identically (a real determinism proof,
        not just "returns a list")."""
        a = to_jsonable({"x", "y", "z"})
        b = to_jsonable(set(["z", "x", "y"]))
        assert a == b


# ---------------------------------------------------------------------------
# Correction 1: LLM ownership validated against stage_registry.
# STAGE_OWNED_LLM_TAGS -- cursor/slice remains the attribution mechanism;
# this only proves the bracket and canonical ownership agree.
# ---------------------------------------------------------------------------

class TestLLMOwnershipValidation:
    def test_valid_s1_call_passes(self, tmp_path):
        call_log = []
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=tmp_path / "executions")
        h = rec.start("repository_analysis_and_remediation_planning")
        call_log.append(_call(1, "remediation_planning"))
        r = rec.finish(h, outcome="generated")
        assert [c["seq"] for c in r["llm_calls"]] == [1]

    def test_valid_s2_call_passes(self, tmp_path):
        call_log = []
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=tmp_path / "executions")
        h = rec.start("remediation_strategy")
        call_log.append(_call(1, "remediation_strategy"))
        rec.finish(h, outcome="generated")

    def test_valid_s3_call_passes(self, tmp_path):
        call_log = []
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=tmp_path / "executions")
        h = rec.start("guided_context_acquisition")
        call_log.append(_call(1, "guided_context_request"))
        rec.finish(h, outcome="ready")

    def test_valid_s4_multiple_internal_calls_all_accepted(self, tmp_path):
        """Multiple legitimate Stage-4 internal calls (contract retry) --
        both of Stage 4's owned tags, several calls -- must all pass."""
        call_log = []
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=tmp_path / "executions")
        h = rec.start("patch_generation_and_post_patch_investigation")
        call_log.append(_call(1, "patch_generation"))
        call_log.append(_call(2, "patch_generation_contract_retry"))
        call_log.append(_call(3, "patch_generation"))
        r = rec.finish(h, outcome="settled")
        assert len(r["llm_calls"]) == 3

    def test_valid_s5_call_passes(self, tmp_path):
        call_log = []
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=tmp_path / "executions")
        h = rec.start("challenger")
        call_log.append(_call(1, "challenger"))
        rec.finish(h, outcome="settled")

    def test_unexpected_tag_inside_stage_bracket_is_rejected(self, tmp_path):
        """A "challenger" call captured inside a
        repository_analysis_and_remediation_planning bracket -- the
        bracket and canonical ownership disagree -- must fail loudly."""
        call_log = []
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=tmp_path / "executions")
        h = rec.start("repository_analysis_and_remediation_planning")
        call_log.append(_call(1, "challenger"))
        with pytest.raises(ExecutionRecorderError, match="challenger"):
            rec.finish(h, outcome="generated")

    def test_stage_with_no_owned_tags_rejects_any_call(self, tmp_path):
        """impact_and_behavior_analysis owns zero LLM tags -- ANY captured
        call inside its bracket is an error, no special-casing needed."""
        call_log = []
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=tmp_path / "executions")
        h = rec.start("impact_and_behavior_analysis")
        call_log.append(_call(1, "confidence_scorer"))
        with pytest.raises(ExecutionRecorderError):
            rec.finish(h, outcome="x")

    def test_ownership_failure_happens_before_any_file_write(self, tmp_path):
        artifacts_dir = tmp_path / "executions"
        call_log = []
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=artifacts_dir)
        h = rec.start("repository_analysis_and_remediation_planning")
        call_log.append(_call(1, "challenger"))
        with pytest.raises(ExecutionRecorderError):
            rec.finish(h, outcome="generated", artifact={"x": 1})
        assert not artifacts_dir.exists()
        assert rec.executions == []

    def test_ownership_failure_does_not_leave_a_dangling_open_handle(self, tmp_path):
        """finish() pops the handle even on failure -- proves the recorder
        doesn't get stuck in a state where the same handle could be
        finished twice."""
        call_log = []
        rec = ExecutionRecorder(call_log=call_log, run_dir=str(tmp_path), artifacts_dir=tmp_path / "executions")
        h = rec.start("repository_analysis_and_remediation_planning")
        call_log.append(_call(1, "challenger"))
        with pytest.raises(ExecutionRecorderError):
            rec.finish(h, outcome="generated")
        assert h not in rec._open


# ---------------------------------------------------------------------------
# Correction 3: artifact write-once enforcement at the storage boundary.
# ---------------------------------------------------------------------------

class TestArtifactWriteOnceEnforcement:
    def test_writing_over_an_existing_artifact_file_fails_closed(self, tmp_path):
        """Simulates the storage boundary being asked to write an
        execution_id that already has a file on disk (e.g. a stray file
        left by something else, or a future bug in sequence assignment) --
        must refuse, not overwrite."""
        artifacts_dir = tmp_path / "executions"
        artifacts_dir.mkdir(parents=True)
        (artifacts_dir / "001_challenger.json").write_text('{"pre_existing": true}', encoding="utf-8")

        rec = ExecutionRecorder(call_log=[], run_dir=str(tmp_path), artifacts_dir=artifacts_dir)
        h = rec.start("challenger")
        with pytest.raises(ExecutionRecorderError, match="immutable"):
            rec.finish(h, outcome="settled", artifact={"new": True})

        # The pre-existing file must be completely untouched.
        assert json.loads((artifacts_dir / "001_challenger.json").read_text()) == {"pre_existing": True}
        # And the execution must not have been recorded as if it succeeded.
        assert rec.executions == []
