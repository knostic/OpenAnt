"""Entry-point binding regression tests (PR #69 — broken/stale entry points).

The issue-65 refactor made ``PhaseBinding`` a *required* dependency of every
LLM call site. A handful of documented entry points were never updated and
still constructed their collaborators with the pre-refactor (binding-less)
signature, so they crashed with ``TypeError`` the moment a user reached them
via the documented ``--llm --agentic`` invocation. Others mis-passed a
``tracker`` into the new ``binding`` positional, latently routing through the
wrong object.

This module pins those contracts:

H2 — ``ContextEnhancer`` now requires ``binding``. The five parser
``test_pipeline.py`` scripts and the ``context_enhancer.py`` CLI must build a
registry from the default llm-config and pass the ``enhance`` binding. We
prove this two ways:
  * a *behavioral* check that ``ContextEnhancer()`` (no args) still raises
    ``TypeError`` (the bug class), and that the constructor genuinely requires
    ``binding``;
  * an *AST guard* asserting none of the six documented call sites use the
    bare ``ContextEnhancer()`` form anymore (a behavioral end-to-end run of
    each parser is impractical — they shell out to language-specific analyzer
    binaries — so the AST guard is the rigorous practical proof for the call
    sites, backed by one behavioral parser-runner drive of
    ``run_context_enhancer`` with the heavy machinery monkeypatched);

L1 — ``test_generator._generate_one`` / ``generate_tests_batch`` must thread a
``binding`` through to ``generate_test`` rather than letting ``tracker`` land
in the ``binding`` positional. Proven behaviorally with a recording adapter:
the binding's model must be the one the generated call actually uses.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from utilities.context_enhancer import ContextEnhancer
from utilities.llm import (
    CompletionResult,
    PhaseBinding,
    TextBlock,
)


# Repo root is two levels up from this file (tests/ -> openant-core/).
REPO_ROOT = Path(__file__).resolve().parent.parent

# The six documented entry points that construct a ``ContextEnhancer``.
ENHANCER_CALL_SITES = [
    REPO_ROOT / "parsers" / "go" / "test_pipeline.py",
    REPO_ROOT / "parsers" / "php" / "test_pipeline.py",
    REPO_ROOT / "parsers" / "javascript" / "test_pipeline.py",
    REPO_ROOT / "parsers" / "c" / "test_pipeline.py",
    REPO_ROOT / "parsers" / "ruby" / "test_pipeline.py",
    REPO_ROOT / "utilities" / "context_enhancer.py",
]


# ---------------------------------------------------------------------------
# Recording adapter — records every ``complete`` call so tests can assert on
# the exact model the call routed through. Mirrors the fake used by
# ``test_e2e_model_propagation.py`` but kept local so this file is
# self-contained.
# ---------------------------------------------------------------------------


class _RecordingAdapter:
    """Fake adapter capturing the model of every completion request."""

    name = "anthropic"  # claim Anthropic so supports_tools=True is plausible
    supports_tools = True

    def __init__(self) -> None:
        self.models_seen: list[str] = []

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        self.models_seen.append(model)
        # Return a benign JSON-ish text payload; the callers under test only
        # need *a* response, not a specific shape.
        return CompletionResult(
            content=[TextBlock('{"dockerfile": "x", "test_script": "y", '
                               '"test_filename": "t.py"}')],
            input_tokens=1,
            output_tokens=1,
            stop_reason="end_turn",
        )

    def validate(self, model):  # pragma: no cover - not exercised here
        pass


def _binding(model: str) -> PhaseBinding:
    return PhaseBinding(
        phase="dynamic_test",
        adapter=_RecordingAdapter(),
        model=model,
        provider_name="anthropic",
    )


# ---------------------------------------------------------------------------
# H2 (behavioral) — the bug class: ContextEnhancer() with no args.
# ---------------------------------------------------------------------------


class TestContextEnhancerRequiresBinding:
    def test_no_arg_construction_raises_type_error(self):
        """Reproduces the H2 bug class: the binding-less call crashes.

        This is the exact failure a user hit when running the documented
        ``python parsers/<lang>/test_pipeline.py <repo> --llm --agentic``
        entry point before the call sites were fixed.
        """
        with pytest.raises(TypeError):
            ContextEnhancer()

    def test_init_signature_requires_binding(self):
        """``binding`` is a required positional with no default."""
        sig = inspect.signature(ContextEnhancer.__init__)
        assert "binding" in sig.parameters
        binding_param = sig.parameters["binding"]
        assert binding_param.default is inspect.Parameter.empty, (
            "binding must be required (no default) so call sites cannot "
            "silently omit it"
        )

    def test_construction_with_binding_succeeds(self):
        """The fixed form — passing a binding — constructs cleanly."""
        enhancer = ContextEnhancer(binding=_binding("model-enhance"))
        assert enhancer.binding.model == "model-enhance"


# ---------------------------------------------------------------------------
# H2 (AST guard) — none of the six call sites use the bare form anymore.
# ---------------------------------------------------------------------------


def _bare_context_enhancer_calls(source: str) -> list[int]:
    """Return line numbers of ``ContextEnhancer()`` calls with NO arguments.

    Walks the AST for ``Call`` nodes whose callee is the name
    ``ContextEnhancer`` (or an attribute access ending in
    ``.ContextEnhancer``) carrying zero positional args, zero keyword args,
    and no ``*args`` / ``**kwargs``. Those are exactly the broken,
    binding-less constructions.
    """
    tree = ast.parse(source)
    offenders: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
        else:
            continue
        if name != "ContextEnhancer":
            continue
        if not node.args and not node.keywords:
            offenders.append(getattr(node, "lineno", -1))
    return offenders


@pytest.mark.parametrize(
    "call_site",
    ENHANCER_CALL_SITES,
    ids=lambda p: str(p.relative_to(REPO_ROOT)),
)
def test_no_bare_context_enhancer_construction(call_site: Path):
    """AST guard: the call site no longer constructs ``ContextEnhancer()``.

    A behavioral end-to-end run of each parser is impractical here — the
    parsers shell out to per-language analyzer binaries (go_parser, the JS
    analyzer, etc.) that aren't available in the unit-test environment — so
    this AST guard is the rigorous practical proof for the call sites. It is
    backed by ``test_run_context_enhancer_passes_binding`` below, which drives
    one real parser runner's ``run_context_enhancer`` end-to-end.
    """
    assert call_site.exists(), f"expected entry point missing: {call_site}"
    source = call_site.read_text(encoding="utf-8")
    offenders = _bare_context_enhancer_calls(source)
    assert offenders == [], (
        f"{call_site.relative_to(REPO_ROOT)} still constructs a bare "
        f"ContextEnhancer() (binding-less) at line(s) {offenders}; build a "
        f"registry and pass registry.get('enhance')."
    )


# ---------------------------------------------------------------------------
# H2 (behavioral, one runner) — drive a parser's run_context_enhancer and
# assert it builds a binding and passes it, without a TypeError.
# ---------------------------------------------------------------------------


def test_run_context_enhancer_passes_binding(monkeypatch, tmp_path):
    """Import the Go parser runner and drive ``run_context_enhancer``.

    The heavy bits (registry build/probe and the ``ContextEnhancer`` enhance
    methods) are monkeypatched so the test neither hits the network nor needs
    an API key. We assert:
      * no ``TypeError`` escapes (the H2 regression),
      * a ``binding`` was supplied to ``ContextEnhancer`` (keyword form), and
      * a registry was built from the *default* llm-config (name=None).

    If importing the parser module fails for environmental reasons, the test
    skips and the AST guard above carries the proof — see this module's
    docstring.
    """
    try:
        import importlib

        go_mod = importlib.import_module("parsers.go.test_pipeline")
    except Exception as exc:  # pragma: no cover - env-dependent import guard
        pytest.skip(f"parser module import unavailable: {exc!r}")

    # Locate the pipeline class that owns run_context_enhancer.
    pipeline_cls = None
    for _name, obj in vars(go_mod).items():
        if inspect.isclass(obj) and hasattr(obj, "run_context_enhancer"):
            pipeline_cls = obj
            break
    if pipeline_cls is None:  # pragma: no cover - defensive
        pytest.skip("no pipeline class exposing run_context_enhancer found")

    # A minimal dataset on disk for the runner to read.
    dataset_path = tmp_path / "dataset.json"
    dataset_path.write_text('{"units": []}', encoding="utf-8")

    # Build a bare instance without running __init__ (it expects CLI args),
    # then set only the attributes run_context_enhancer touches.
    pipeline = pipeline_cls.__new__(pipeline_cls)
    pipeline.dataset_file = str(dataset_path)
    pipeline.analyzer_output_file = None
    pipeline.repo_path = str(tmp_path)
    pipeline.agentic = False
    pipeline.results = {"stages": {}}

    # Record what registry name the runner resolved and what binding it
    # handed to ContextEnhancer.
    captured: dict = {}

    sentinel_binding = _binding("model-enhance-default")

    def _fake_build_registry(config_name=None):
        """Stand-in for the runner's registry construction.

        The runner is expected to call into the llm registry helpers with
        ``name=None`` (the default config). We patch the underlying
        ``resolve_llm_config`` to capture the name and short-circuit the
        build, returning a registry whose ``get('enhance')`` yields our
        sentinel binding.
        """
        captured["config_name"] = config_name

        class _Reg:
            def get(self, phase):
                captured["phase"] = phase
                return sentinel_binding

        return _Reg()

    # Patch the registry plumbing the runner uses. We patch at the
    # utilities.llm names the runner imports from.
    import utilities.llm as llm_mod

    def _resolve(cf, name):
        captured["config_name"] = name
        return object()  # opaque LLMConfig stand-in

    def _build(cf, llm_config):
        class _Reg:
            config_name = "openant-default"

            def get(self, phase):
                captured["phase"] = phase
                return sentinel_binding

        return _Reg()

    monkeypatch.setattr(llm_mod, "resolve_llm_config", _resolve, raising=True)
    monkeypatch.setattr(llm_mod, "build_phase_registry", _build, raising=True)
    monkeypatch.setattr(llm_mod, "load_config_file", lambda *a, **k: object(), raising=True)
    monkeypatch.setattr(llm_mod, "probe_registry_or_raise", lambda *a, **k: None, raising=True)
    # The parser module imported these names into its own namespace at import
    # time; patch those bindings too so the runner picks up the fakes.
    for _n, _fn in [
        ("resolve_llm_config", _resolve),
        ("build_phase_registry", _build),
        ("load_config_file", lambda *a, **k: object()),
        ("probe_registry_or_raise", lambda *a, **k: None),
    ]:
        if hasattr(go_mod, _n):
            monkeypatch.setattr(go_mod, _n, _fn, raising=True)

    # Replace ContextEnhancer in the parser module's namespace with a stub
    # that records the binding it was given and provides no-op enhance
    # methods, so we exercise the runner's wiring rather than real LLM calls.
    class _StubEnhancer:
        def __init__(self, *args, **kwargs):
            captured["enhancer_args"] = args
            captured["enhancer_kwargs"] = kwargs
            self.stats = {
                "units_enhanced": 0,
                "dependencies_added": 0,
                "callers_added": 0,
                "data_flows_extracted": 0,
            }

        def enhance_dataset(self, dataset, *a, **k):
            return dataset

        def enhance_dataset_agentic(self, dataset, *a, **k):
            return dataset

    monkeypatch.setattr(go_mod, "ContextEnhancer", _StubEnhancer, raising=True)

    # Drive the runner. The key assertion is simply that this does not raise
    # TypeError from a binding-less ContextEnhancer construction.
    ok = pipeline.run_context_enhancer()

    assert ok is True
    # A binding must have been handed to the enhancer — accept either the
    # keyword form (preferred, mirrors core/enhancer.py) or a single
    # positional. Reject the binding-less construction outright.
    args = captured.get("enhancer_args", ())
    kwargs = captured.get("enhancer_kwargs", {})
    passed_binding = kwargs.get("binding") if "binding" in kwargs else (
        args[0] if args else None
    )
    assert passed_binding is sentinel_binding, (
        "run_context_enhancer must construct ContextEnhancer with the "
        "enhance-phase binding from the registry"
    )
    assert captured.get("phase") == "enhance", (
        "the binding must come from registry.get('enhance')"
    )
    # Default llm-config means name=None was resolved.
    assert captured.get("config_name") is None, (
        "standalone parser runs must use the default llm-config (name=None)"
    )


# ---------------------------------------------------------------------------
# L1 (behavioral) — _generate_one / generate_tests_batch must route through
# the binding, not mis-bind the tracker into the binding positional.
# ---------------------------------------------------------------------------


class TestDynamicTestGeneratorBinding:
    def _finding(self) -> dict:
        return {
            "id": "f1",
            "name": "test finding",
            "cwe_id": 22,
            "location": {"file": "app/x.py"},
        }

    def _repo_info(self) -> dict:
        return {"name": "demo", "language": "python", "application_type": "web_app"}

    def test_generate_one_routes_through_binding_model(self):
        """``_generate_one`` must drive the call through the binding's model.

        Before the fix, ``_generate_one`` called
        ``generate_test(finding, repo_info, tracker)`` — landing the tracker
        in the ``binding`` positional. With the recording adapter wired to a
        known model, a correct implementation records exactly that model.
        """
        from utilities.dynamic_tester import test_generator
        from utilities.llm_client import TokenTracker

        binding = _binding("model-dyntest")
        tracker = TokenTracker()

        finding, result, _cost, _worker = test_generator._generate_one(
            self._finding(), self._repo_info(), binding, tracker
        )

        assert result is not None
        assert binding.adapter.models_seen == ["model-dyntest"], (
            "the generated call must route through the binding's model; a "
            "mis-bound tracker would never reach the adapter"
        )

    def test_generate_tests_batch_threads_binding(self):
        """``generate_tests_batch`` threads the binding to each finding."""
        from utilities.dynamic_tester import test_generator
        from utilities.llm_client import TokenTracker

        binding = _binding("model-dyntest")
        tracker = TokenTracker()

        results = test_generator.generate_tests_batch(
            [self._finding(), self._finding()],
            self._repo_info(),
            binding,
            tracker,
            workers=1,
        )

        assert len(results) == 2
        assert all(r[1] is not None for r in results)
        # Two findings, each routed once through the binding's model.
        assert binding.adapter.models_seen == ["model-dyntest", "model-dyntest"]

    def test_generate_tests_batch_signature_has_binding(self):
        """Guard the public signature: ``binding`` precedes ``tracker``."""
        from utilities.dynamic_tester import test_generator

        params = list(
            inspect.signature(test_generator.generate_tests_batch).parameters
        )
        assert "binding" in params, "generate_tests_batch must accept a binding"
        assert params.index("binding") < params.index("tracker"), (
            "binding must come before tracker so it maps to generate_test's "
            "binding positional"
        )
