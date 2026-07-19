"""fa17 quarantine-not-drop: dropped non-dict elements are COUNTED + SURFACED + logged."""
import logging
from utilities.file_io import normalize_results
def test_dropped_counted_surfaced():
    obj={"results":[{"a":1},"poison",123,None,["x"]]}; normalize_results(obj)
    assert obj["results"]==[{"a":1}] and obj["_results_invalid_dropped"]==4
def test_clean_no_marker():
    obj={"results":[{"a":1}]}; normalize_results(obj); assert "_results_invalid_dropped" not in obj
def test_logged(caplog):
    with caplog.at_level(logging.WARNING, logger="openant.normalize"): normalize_results({"results":["bad"]})
    assert any("dropped" in r.message for r in caplog.records)
def test_non_list_marked():
    obj={"results":{"x":1}}; normalize_results(obj); assert obj["results"]==[] and obj["_results_invalid_dropped"]==1
