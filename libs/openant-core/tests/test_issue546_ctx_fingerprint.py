"""Tests for issue #546 — the deterministic-context-sources fingerprint.

The checkpoint family's resume keys excluded the app-context payload —
correctly for the NARRATED text (the non-determinism trap), but the
context is derived from deterministic repo sources; a repo edit that
changes the derivation while leaving a unit's code identical replayed
stale signals under the changed analysis context. The fix: the context
ARTIFACT carries source_sha256 (the deterministic-derivation identity —
each arm's own input: the threat-model file's bytes, the override's
content, the LLM arm's gathered-sources digest), and the gated phases
fold it into their identity keys via extra_key.
"""
from __future__ import annotations

import json
from pathlib import Path

from context.application_context import (
    context_sources_digest,
    gather_context_sources,
)


class TestContextSourcesDigest:
    def _repo(self, tmp_path: Path, files: dict) -> Path:
        for name, content in files.items():
            f = tmp_path / name
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(content)
        return tmp_path

    def test_same_files_same_digest(self, tmp_path):
        a = context_sources_digest(gather_context_sources(
            self._repo(Path(tmp_path), {"README.md": "x"})))
        b = context_sources_digest(gather_context_sources(
            self._repo(Path(tmp_path), {"README.md": "x"})))
        assert a == b and a

    def test_content_change_differs(self, tmp_path):
        a = context_sources_digest(gather_context_sources(
            self._repo(Path(tmp_path), {"README.md": "x"})))
        (Path(tmp_path) / "README.md").write_text("changed")
        b = context_sources_digest(gather_context_sources(Path(tmp_path)))
        assert a != b

    def test_new_context_file_differs(self, tmp_path):
        a = context_sources_digest(gather_context_sources(
            self._repo(Path(tmp_path), {"README.md": "x"})))
        (Path(tmp_path) / "go.mod").write_text("module x")
        b = context_sources_digest(gather_context_sources(Path(tmp_path)))
        assert a != b

    def test_output_dir_artifacts_do_not_invalidate(self, tmp_path):
        """THE self-invalidation hazard: [directory_structure] lists the
        in-repo output dir; the digest must exclude it — writing new
        artifacts into results/ does NOT change the digest."""
        self._repo(Path(tmp_path), {"README.md": "x"})
        a = context_sources_digest(gather_context_sources(Path(tmp_path)))
        (Path(tmp_path) / "results").mkdir()
        (Path(tmp_path) / "results" / "analyze_checkpoints").mkdir()
        (Path(tmp_path) / "results" / "scan.json").write_text("{}")
        b = context_sources_digest(gather_context_sources(Path(tmp_path)))
        assert a == b

    def test_untracked_py_file_under_results_unchanged(self, tmp_path):
        """[detected_patterns] rglobs *.py capped at 100 — an untracked
        file under the output dir must not shift the digest (excluded)."""
        self._repo(Path(tmp_path), {"README.md": "x"})
        a = context_sources_digest(gather_context_sources(Path(tmp_path)))
        (Path(tmp_path) / "results").mkdir()
        (Path(tmp_path) / "results" / "new_thing.py").write_text("x=1")
        b = context_sources_digest(gather_context_sources(Path(tmp_path)))
        assert a == b


class TestProducerStamps:
    def _gen(self, tmp_path, monkeypatch, narrations):
        from context import application_context as ac

        (tmp_path / "README.md").write_text("stub repo")
        calls = iter([json.dumps({"application_type": "cli_tool",
                                  "purpose": n}) for n in narrations])

        class _R:
            stop_reason = "end_turn"
            input_tokens = 1
            output_tokens = 1
            usage_details = None

            def __init__(self, text):
                self.content = [type("B", (), {"text": text})()]

        def fake_sc(binding, prompt, system=None, max_tokens=0, tracker=None):
            return _R(next(calls))

        monkeypatch.setattr(ac, "simple_completion", fake_sc)
        from utilities.llm import PhaseBinding

        class _A:
            name = "t"
            supports_tools = True

            def validate(self, model):
                pass

        b = PhaseBinding(phase="app_context", adapter=_A(), model="m",
                         provider_name="p")
        return (ac.generate_application_context(
                    repo_path=Path(tmp_path), binding=b),
                ac.generate_application_context(
                    repo_path=Path(tmp_path), binding=b))

    def test_llm_arm_stamps_the_digest(self, tmp_path, monkeypatch):
        """A source landing BETWEEN the two calls → the stamps differ."""
        from context import application_context as ac
        (tmp_path / "README.md").write_text("stub repo")
        narrations = iter(["one", "DIFFERENT"])

        class _R:
            stop_reason = "end_turn"
            input_tokens = 1
            output_tokens = 1
            usage_details = None

            def __init__(self, text):
                self.content = [type("B", (), {"text": text})()]

        def fake_sc(binding, prompt, system=None, max_tokens=0, tracker=None):
            return _R(json.dumps({"application_type": "cli_tool",
                                  "purpose": next(narrations)}))

        monkeypatch.setattr(ac, "simple_completion", fake_sc)
        from utilities.llm import PhaseBinding

        class _A:
            name = "t"
            supports_tools = True

            def validate(self, model):
                pass

        b = PhaseBinding(phase="app_context", adapter=_A(), model="m",
                         provider_name="p")
        ctx1 = ac.generate_application_context(
            repo_path=Path(tmp_path), binding=b)
        (tmp_path / "package.json").write_text("{}")  # the source lands
        ctx2 = ac.generate_application_context(
            repo_path=Path(tmp_path), binding=b)
        assert ctx1.source_sha256 != ctx2.source_sha256

    def test_llm_same_sources_same_stamp(self, tmp_path, monkeypatch):
        """SAME sources, DIFFERENT narration → the same stamp."""
        (ctx1, ctx2) = self._gen(Path(tmp_path), monkeypatch,
                                  ["one", "DIFFERENT"])
        assert ctx1.source_sha256 == ctx2.source_sha256

    def test_llm_arm_supplied_sha_is_overwritten(self, tmp_path, monkeypatch):
        """A model-emitted source_sha256 (steerable by the scanned repo's
        sources text) must never pin the identity — the stamp is DERIVED
        (#546's review round: the identity is computed, never adopted)."""
        from context import application_context as ac
        (tmp_path / "README.md").write_text("stub repo")
        supplied = iter(["0" * 64, "1" * 64])
        narrated = iter(["p", "p"])

        class _R:
            stop_reason = "end_turn"
            input_tokens = 1
            output_tokens = 1
            usage_details = None

            def __init__(self, text):
                self.content = [type("B", (), {"text": text})()]

        def fake_sc(binding, prompt, system=None, max_tokens=0, tracker=None):
            return _R(json.dumps({"application_type": "cli_tool",
                                  "purpose": next(narrated),
                                  "source_sha256": next(supplied)}))

        monkeypatch.setattr(ac, "simple_completion", fake_sc)
        from utilities.llm import PhaseBinding

        class _A:
            name = "t"
            supports_tools = True

            def validate(self, model):
                pass

        b = PhaseBinding(phase="app_context", adapter=_A(), model="m",
                         provider_name="p")
        ctx1 = ac.generate_application_context(
            repo_path=Path(tmp_path), binding=b)
        ctx2 = ac.generate_application_context(
            repo_path=Path(tmp_path), binding=b)
        # SAME sources → the same DERIVED digest — regardless of the two
        # DIFFERENT supplied constants.
        assert ctx1.source_sha256 == ctx2.source_sha256
        assert ctx1.source_sha256 not in ("0" * 64, "1" * 64)

    def test_override_arm_supplied_sha_is_overwritten(self):
        """A repo-supplied OPENANT.json source_sha256 must never pin the
        identity — the stamp is computed over the override content."""
        from context.application_context import _application_context_from_override
        ctx = _application_context_from_override(
            {"application_type": "cli_tool", "purpose": "p",
             "source_sha256": "0" * 64},
            "OPENANT.json")
        assert ctx.source_sha256 is not None
        assert ctx.source_sha256 != "0" * 64


class TestFoldSiteReads:
    """#546 follow-up (3a): pin the READS at the actual gate sites, not just
    the _analyze_fingerprint helper — the verifier and LLR folds had no
    wiring tests (a key-name drift there silently keys None and #546
    returns with nothing failing)."""

    def test_llr_fold_reads_the_dict_context(self, tmp_path):
        """End-to-end through the REAL analyze_reachability gate: two runs
        with the same units/binding but DIFFERENT source_sha256 in the
        artifact dict produce DIFFERENT persisted identities (the fold is
        live at the LLR read site); the same sha reproduces (stability)."""
        import json as _json
        from pathlib import Path
        from core.llm_reachability import analyze_reachability
        from core.backend_identity import FINGERPRINT_FILE
        from tests.test_issue532_llr_resume import (
            FakeAdapter, FakeTracker, _binding, _make_unit, _canned, _sig)

        def sidecar_digest(cp):
            fp = _json.loads(Path(cp, FINGERPRINT_FILE).read_text())
            return fp.get("key_digest")
        cp = str(tmp_path / "cp")
        dataset = {"units": [_make_unit("a:f1")]}
        canned = _canned(_sig("a:f1"))

        analyze_reachability(
            dataset, app_context={"source_sha256": "a" * 64, "application_type": "cli_tool"},
            binding=_binding(FakeAdapter([canned])),
            checkpoint_path=cp, tracker=FakeTracker())
        d1 = sidecar_digest(cp)
        assert d1, "the sidecar identity was not persisted"

        # Same sha -> same digest (stability: the narration never keys).
        analyze_reachability(
            dataset, app_context={"source_sha256": "a" * 64, "application_type": "cli_tool"},
            binding=_binding(FakeAdapter([canned])),
            checkpoint_path=cp, tracker=FakeTracker())
        assert sidecar_digest(cp) == d1

        # Different sha -> different digest (invalidation: the fold is live).
        analyze_reachability(
            dataset, app_context={"source_sha256": "b" * 64, "application_type": "cli_tool"},
            binding=_binding(FakeAdapter([canned])),
            checkpoint_path=cp, tracker=FakeTracker())
        assert sidecar_digest(cp) != d1

    def test_llr_fold_accepts_the_dataclass_shape(self, tmp_path):
        """#546 follow-up (3b): a direct caller passing an ApplicationContext
        (not the artifact dict) must fold the same identity — the dict-only
        read used to silently fold nothing for that shape."""
        from context.application_context import ApplicationContext
        from tests.test_issue532_llr_resume import (
            FakeAdapter, FakeTracker, _binding, _make_unit, _canned, _sig)
        from core.llm_reachability import analyze_reachability
        import json as _json
        from pathlib import Path
        from core.backend_identity import FINGERPRINT_FILE
        cp1 = str(tmp_path / "cp1"); cp2 = str(tmp_path / "cp2")
        dataset = {"units": [_make_unit("a:f1")]}
        canned = _canned(_sig("a:f1"))
        ctx_dict = {"source_sha256": "c" * 64, "application_type": "cli_tool"}
        ctx_obj = ApplicationContext(application_type="cli_tool",
                                     purpose="p",
                                     source_sha256="c" * 64)
        for cp, ctx in ((cp1, ctx_dict), (cp2, ctx_obj)):
            analyze_reachability(
                dataset, app_context=ctx,
                binding=_binding(FakeAdapter([canned])),
                checkpoint_path=cp, tracker=FakeTracker())
        d_dict = _json.loads(Path(cp1, FINGERPRINT_FILE).read_text())["key_digest"]
        d_obj = _json.loads(Path(cp2, FINGERPRINT_FILE).read_text())["key_digest"]
        assert d_dict == d_obj, "the dataclass shape folded a different identity than the dict shape"

    def test_override_with_yaml_date_stays_derived(self):
        """#546 follow-up (3c): a YAML override with a non-JSON-serializable
        scalar (an unquoted date -> datetime.date) must NOT land
        source_sha256=None (the silent fold-skip = stale adoption after an
        override edit); default=str keeps the identity DERIVED, and the
        derivation is stable across calls."""
        import datetime
        from context.application_context import _application_context_from_override
        ctx1 = _application_context_from_override(
            {"application_type": "cli_tool", "purpose": "p",
             "deadline": datetime.date(2026, 1, 1)},
            "OPENANT.yaml")
        ctx2 = _application_context_from_override(
            {"application_type": "cli_tool", "purpose": "p",
             "deadline": datetime.date(2026, 1, 1)},
            "OPENANT.yaml")
        assert ctx1.source_sha256 is not None, (
            "a YAML date landed source_sha256=None — the invalidation fold "
            "is silently skipped for this run")
        assert ctx1.source_sha256 == ctx2.source_sha256, (
            "the date-bearing override's identity is not stable across "
            "calls — every run would re-pay")
        # The invalidation direction: a CHANGED date value must re-key
        # (the derivation is a function of the content, not just present).
        ctx3 = _application_context_from_override(
            {"application_type": "cli_tool", "purpose": "p",
             "deadline": datetime.date(2026, 6, 1)},
            "OPENANT.yaml")
        assert ctx3.source_sha256 != ctx1.source_sha256

    def test_verifier_fold_reads_the_loaded_context(self):
        """The verifier's read site (verifier.py's fingerprint_for_binding
        extra_key) folds the loaded app_context's source_sha256. Pinned at
        the source level (the house idiom: the assets allowlist test) —
        run_verification's harness is too heavy to drive end-to-end, and a
        re-implementation of the expression would be the hollow-test shape.
        The pin: the call site reads source_sha256 off the loaded
        app_context via getattr, inside the extra_key, alongside the
        analyze_fingerprint."""
        from pathlib import Path
        src = (Path(__file__).resolve().parent.parent / "core" /
               "verifier.py").read_text(encoding="utf-8")
        i = src.index("fingerprint_for_binding(")
        block = src[i:i + 2500]
        assert '"ctx_sources_sha256"' in block, "the verifier fold key is gone"
        assert "getattr(app_context, \"source_sha256\", None)" in block, (
            "the verifier fold no longer reads the loaded context's "
            "source_sha256 — a wiring drift keys None silently")


class TestGateWiring:
    def test_analyze_fingerprint_folds_the_sha(self):
        from core.analyzer import _analyze_fingerprint

        class _B:
            phase = "analyze"
            model = "m"
            provider_name = "p"
            base_url = None
            adapter = type("A", (), {"name": "x"})()
        fp_none = _analyze_fingerprint(_B())
        fp_sha = _analyze_fingerprint(_B(), ctx_sha="abc")
        assert "ctx_sources_sha256" not in fp_none.get("extra", {})
        assert fp_sha["extra"]["ctx_sources_sha256"] == "abc"
        assert fp_none["key_digest"] != fp_sha["key_digest"]

    def test_pre_fix_artifact_yields_none(self, tmp_path):
        """Backcompat: an old application_context.json without the field
        loads and yields None (no crash, one-time archive on first run)."""
        from context.application_context import load_context
        f = tmp_path / "application_context.json"
        f.write_text(json.dumps({"application_type": "cli_tool",
                                "purpose": "x", "source": "llm"}))
        ctx = load_context(f)
        assert ctx.source_sha256 is None
