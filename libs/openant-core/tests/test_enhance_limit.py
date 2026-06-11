"""Regression tests: `enhance` lacked a `--limit` (max-units) capability at all
three layers (Go CLI, Python CLI, core), while `analyze`/`scan` have it.

These tests cover the two Python layers behaviorally:
- the core `enhance_dataset(limit=N)` actually slices the dataset to N units (the LLM is stubbed);
- the CLI path `enhance ... --limit N` (parser `enhance_p` + `cmd_enhance`) forwards N to enhance_dataset.

(The Go layer is covered by apps/openant-cli/cmd/enhance_limit_test.go.)
"""
import sys

import core.enhancer as enh
import utilities.context_enhancer as _ce
import utilities.llm_client as _llm


_received = {}


class _DummyEnhancer:
    def __init__(self, **kw):
        pass

    def enhance_dataset(self, dataset, progress_callback=None, workers=8, **kw):
        _received["units"] = len(dataset.get("units", []))
        return dataset

    def enhance_dataset_agentic(self, dataset, **kw):
        _received["units"] = len(dataset.get("units", []))
        return dataset


def test_enhance_dataset_limit_slices_units(tmp_path, monkeypatch):
    five = [{"id": f"u{i}", "llm_context": {}} for i in range(5)]
    monkeypatch.setattr(enh, "read_json", lambda p: {"units": list(five)})
    monkeypatch.setattr(enh, "write_json", lambda p, d: None)
    monkeypatch.setattr(enh, "configure_rate_limiter", lambda **k: None)
    monkeypatch.setattr(_llm, "AnthropicClient", lambda **k: object())
    monkeypatch.setattr(_llm, "get_global_tracker", lambda: None)
    monkeypatch.setattr(_ce, "ContextEnhancer", _DummyEnhancer)

    _received.clear()
    res = enh.enhance_dataset(
        dataset_path=str(tmp_path / "x.json"),
        output_path=str(tmp_path / "out.json"),
        mode="single-shot",
        limit=2,
    )
    # The enhancer must RECEIVE only the limited units -- this guards the load-bearing
    # `dataset["units"] = units` slice (a local-only slice would leave 5 units reaching the enhancer).
    assert _received["units"] == 2, f"enhancer received {_received.get('units')} units, expected 2"
    assert res.units_enhanced == 2, f"limit=2 should enhance 2 of 5 units, got {res.units_enhanced}"


def test_enhance_cli_forwards_limit_end_to_end(tmp_path, monkeypatch):
    from openant import cli

    captured = {}

    def _fake_enhance_dataset(**kwargs):
        captured.update(kwargs)

        class _R:
            enhanced_dataset_path = str(tmp_path / "out.json")
            units_enhanced = 3
            error_count = 0
            classifications: dict = {}
            error_summary: dict = {}

            def to_dict(self):
                return {"units_enhanced": 3}

        return _R()

    # cmd_enhance does `from core.enhancer import enhance_dataset` at call time -> patch the source attr
    monkeypatch.setattr(enh, "enhance_dataset", _fake_enhance_dataset)
    monkeypatch.setattr(sys, "argv", ["openant", "enhance", str(tmp_path / "x.json"), "--limit", "3"])

    rc = cli.main()
    assert rc == 0, f"enhance command returned {rc}"
    assert captured.get("limit") == 3, \
        f"`enhance --limit 3` must forward limit=3 to enhance_dataset, got {captured.get('limit')!r}"
