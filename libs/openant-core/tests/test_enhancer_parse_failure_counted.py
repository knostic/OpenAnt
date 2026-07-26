"""enhancer-failed-context regression: a parse failure in the non-agentic enhancer
must increment stats['errors'] (like the exception branch), so the [Enhance] Errors
telemetry does not under-report parse failures. The unit still carries the error and is
not dropped — this is a telemetry-honesty guard, not a coverage change.
"""
from utilities import context_enhancer as ce
from utilities.context_enhancer import ContextEnhancer


def _enhancer():
    e = ContextEnhancer.__new__(ContextEnhancer)          # bypass binding-required ctor
    e.binding = object()
    e.tracker = None
    e.stats = {"units_processed": 0, "units_enhanced": 0, "errors": 0,
               "dependencies_added": 0, "callers_added": 0, "data_flows_extracted": 0}
    return e


def test_parse_failure_increments_errors(monkeypatch):
    # Force an unparseable LLM response -> _parse_json_response returns falsy -> else branch.
    monkeypatch.setattr(ce, "simple_text", lambda *a, **k: "this is not json {{{")
    e = _enhancer()
    unit = {"id": "f1", "code": {"primary_code": "def f(): pass"}}
    e.enhance_unit(unit, {})
    assert e.stats["errors"] == 1                          # parse failure counted
    assert e.stats["units_enhanced"] == 0                 # not counted as a success
    # unit still carries the error marker and is not dropped
    assert unit["llm_context"]["error"]["type"] == "parse_error"


def test_successful_parse_not_counted_as_error(monkeypatch):
    monkeypatch.setattr(ce, "simple_text",
                        lambda *a, **k: '{"missing_dependencies": [], "additional_callers": [], '
                                        '"data_flow": {}, "imports": [], "reasoning": "", "confidence": 0.5}')
    e = _enhancer()
    e.enhance_unit({"id": "f1", "code": {"primary_code": "x"}}, {})
    assert e.stats["errors"] == 0
    assert e.stats["units_enhanced"] == 1
