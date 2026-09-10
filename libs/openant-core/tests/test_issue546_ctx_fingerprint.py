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
