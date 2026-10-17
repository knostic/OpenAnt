"""Issue #745: a delegation-dismissed SAFE row names its sink-owner only in
prose — no consumer surface carries the edge, and when the sink-owner was
pruned the finding evaporates.

The corpus chain (the issue, a committed openbao scan): ``_buildUrl`` is
SAFE-by-delegation ("the actual open-redirect risk exists at the callers
(_redirect/_handleSuccess/_handleError)"), the CALLER rows ``_redirect`` /
``beforeModel`` were PRUNED from the dataset (a framework hook with no
static callers — its external_input signal does not promote), so no row
anywhere carried the judgment; Stage 2 wrote "a separate sink, not the
target function" and nothing chased it.

The contract locked here (the issue's ask):

* every SAFE row (the class where the concern went elsewhere) carries its
  followable edge as STRUCTURED fields — ``scope: function_local`` (the
  analysis scoping, true by construction) + ``deferred_to`` (the unit's
  dataset call edges in BOTH directions — the corpus's delegations go UP
  (the risk at the callers) and DOWN (the danger in a callee) — the same ids
  the result rows key on) — so a consumer follows the edge instead of
  parsing the reasoning prose;
* a named edge unit with NO result row (pruned or never analyzed) is
  surfaced as ``deferred_rowless`` — the evaporation case is
  distinguishable from an examined-and-safe one;
* non-safe verdicts carry NO deferral fields — the concern is HERE, in the
  row's own function (the class boundary);
* a malformed dataset metadata entry (direct_calls/direct_callers not a
  list) reads as no edge — never a crash, never a char-split (the #305
  convention).

Every drive runs the REAL ``cli.cmd_report_data`` (the report-data
subcommand the Go HTML renderer calls) over fixture scans — the fa17
convention this file family follows (the import inside each test, the
remediation-guidance LLM call stubbed at the module the function-level
import re-binds; everything else in the flow is the real report-data path).
The Go renderers (overview + reskin) carry the same edge — pinned on the Go
side (report_issue745_delegation_test.go).
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _unit(uid: str, direct_calls: list | None = None,
          direct_callers: list | None = None) -> dict:
    return {
        "id": uid,
        "code": {"primary_code": "def f(): ..."},
        "llm_context": {"reasoning": "context"},
        "metadata": {"direct_calls": direct_calls or [],
                      "direct_callers": direct_callers or []},
    }


def _result(route_key: str, verdict: str, reasoning: str = "r") -> dict:
    return {
        "route_key": route_key,
        "unit_id": route_key,
        "finding": verdict,
        "verdict": verdict,
        "attack_vector": "prompt-injection",
        "reasoning": reasoning,
        "verification": {"correct_finding": verdict},
    }


def _write_scan(tmp_path, results, units) -> types.SimpleNamespace:
    exp = tmp_path / "results.json"
    ds = tmp_path / "dataset.json"
    exp.write_text(json.dumps({
        "dataset": "issue-745",
        "code_by_route": {},
        "metrics": {},
        "results": results,
    }))
    ds.write_text(json.dumps({"units": units}))
    return types.SimpleNamespace(results=str(exp), dataset=str(ds))


def _row_for(findings, uid: str) -> dict:
    row = next((f for f in findings if f["function"] == uid), None)
    assert row is not None, (
        f"no row for {uid}: {[f['function'] for f in findings]}")
    return row


def test_safe_row_carries_the_followable_edge(tmp_path, capsys, monkeypatch):
    """The corpus's flagship chain: the SAFE HELPER's risk lives at its
    CALLERS (_redirect PRUNED — the evaporation case; _handleSuccess
    examined) — the caller direction, not the callee one."""
    import utilities.llm as _llm
    monkeypatch.setattr(_llm, "simple_text",
                        lambda binding, prompt, **kw: "<p>remediation</p>")
    from openant import cli

    args = _write_scan(
        tmp_path,
        results=[
            _result("app/api.js:_buildUrl", "safe",
                    reasoning="the actual open-redirect risk exists at "
                               "the callers (_redirect/_handleSuccess), "
                               "not here"),
            _result("app/api.js:_handleSuccess", "vulnerable"),
            # app/api.js:_redirect: NO result row — the pruned sink-owner
        ],
        units=[
            _unit("app/api.js:_buildUrl",
                  direct_callers=["app/api.js:_redirect",
                                  "app/api.js:_handleSuccess"]),
            _unit("app/api.js:_redirect"),
            _unit("app/api.js:_handleSuccess"),
        ])
    rc = cli.cmd_report_data(args)
    assert rc == 0
    findings = json.loads(capsys.readouterr().out.strip())["data"]["findings"]

    row = _row_for(findings, "_buildUrl")
    assert row.get("scope") == "function_local", (
        f"the SAFE row's analysis scope is not structured: {row!r}")
    assert row.get("deferred_to") == ["app/api.js:_redirect",
                                        "app/api.js:_handleSuccess"], (
        f"the delegation edge is not carried — the consumer must parse the "
        f"reasoning prose to find the callers the risk went to: {row!r}")
    assert row.get("deferred_rowless") == ["app/api.js:_redirect"], (
        f"the pruned sink-owner (no result row anywhere) is not surfaced — "
        f"the evaporation case is indistinguishable from an "
        f"examined-and-safe one: {row!r}")
    # the examined caller's row IS followable: it exists and is judged
    handle = _row_for(findings, "_handleSuccess")
    assert handle["verdict"] == "vulnerable"


def test_safe_row_carries_both_edge_directions(tmp_path, capsys, monkeypatch):
    """The other delegation shape: the danger in a CALLEE ("the dangerous
    operation lives in a helper this unit calls") — and the UNION when both
    directions delegate (deduped, order-stable: callees then callers)."""
    import utilities.llm as _llm
    monkeypatch.setattr(_llm, "simple_text",
                        lambda binding, prompt, **kw: "<p>remediation</p>")
    from openant import cli

    args = _write_scan(
        tmp_path,
        results=[
            _result("app/api.js:entry", "safe",
                    reasoning="the sink lives in the helper I call and at "
                               "my caller both"),
            _result("app/api.js:helper", "safe"),
            _result("app/api.js:caller", "safe"),
        ],
        units=[
            _unit("app/api.js:entry",
                  direct_calls=["app/api.js:helper"],
                  direct_callers=["app/api.js:caller", "app/api.js:helper"]),
            _unit("app/api.js:helper"),
            _unit("app/api.js:caller"),
        ])
    rc = cli.cmd_report_data(args)
    assert rc == 0
    findings = json.loads(capsys.readouterr().out.strip())["data"]["findings"]

    row = _row_for(findings, "entry")
    # the union: callees first, then callers, DEDUPED (helper appears in
    # both directions once)
    assert row.get("deferred_to") == ["app/api.js:helper",
                                        "app/api.js:caller"], (
        f"the both-directions union is not carried (deduped, "
        f"order-stable): {row!r}")
    assert row.get("deferred_rowless") == [], row


def test_safe_row_without_edges_carries_the_empty_shape(tmp_path, capsys, monkeypatch):
    """A SAFE row with no call edges carries the fields empty (the shape is
    consistent: scope present, deferred_to [], deferred_rowless []) — the
    consumer never has to probe for the keys."""
    import utilities.llm as _llm
    monkeypatch.setattr(_llm, "simple_text",
                        lambda binding, prompt, **kw: "<p>remediation</p>")
    from openant import cli

    args = _write_scan(
        tmp_path,
        results=[_result("app/api.js:lonely", "safe")],
        units=[_unit("app/api.js:lonely")])
    rc = cli.cmd_report_data(args)
    assert rc == 0
    findings = json.loads(capsys.readouterr().out.strip())["data"]["findings"]

    row = _row_for(findings, "lonely")
    assert row.get("scope") == "function_local", row
    assert row.get("deferred_to") == [], row
    assert row.get("deferred_rowless") == [], row


def test_safe_row_with_malformed_metadata_reads_no_edge(tmp_path, capsys, monkeypatch):
    """The #305 convention: a malformed dataset metadata entry reads as no
    edge — the report never dies, never char-splits a string value, and
    never str()-casts a garbage element (None/a bool/a dict) into a phantom
    edge id: direct_calls a STRING, direct_callers an INT, an edge list
    carrying garbage elements, metadata not a dict, and a unit with no
    metadata at all."""
    import utilities.llm as _llm
    monkeypatch.setattr(_llm, "simple_text",
                        lambda binding, prompt, **kw: "<p>remediation</p>")
    from openant import cli

    args = _write_scan(
        tmp_path,
        results=[
            _result("app/api.js:odd", "safe"),
            _result("app/api.js:worse", "safe"),
            _result("app/api.js:none", "safe"),
            _result("app/api.js:absent", "safe"),
        ],
        units=[
            # direct_calls a string (the char-split hazard), direct_callers
            # an int (not a list)
            {"id": "app/api.js:odd",
             "code": {"primary_code": "def odd(): ..."},
             "llm_context": {"reasoning": "context"},
             "metadata": {"direct_calls": "app/api.js:sink",
                          "direct_callers": 5}},
            # an edge list carrying garbage elements: None, a bool, a dict —
            # none of them str()-cast into a phantom id
            {"id": "app/api.js:worse",
             "code": {"primary_code": "def worse(): ..."},
             "llm_context": {"reasoning": "context"},
             "metadata": {"direct_calls": [None, True, {"z": 1}],
                          "direct_callers": ["app/api.js:real"]}},
            # metadata not a dict at all
            {"id": "app/api.js:none",
             "code": {"primary_code": "def none(): ..."},
             "llm_context": {"reasoning": "context"},
             "metadata": "not-a-dict"},
            # no metadata KEY at all
            {"id": "app/api.js:absent",
             "code": {"primary_code": "def absent(): ..."},
             "llm_context": {"reasoning": "context"}},
        ])
    rc = cli.cmd_report_data(args)
    assert rc == 0, (
        "a malformed dataset metadata entry must not kill the report "
        "(the #305 convention: never a crash)")
    findings = json.loads(capsys.readouterr().out.strip())["data"]["findings"]

    odd = _row_for(findings, "odd")
    assert odd.get("scope") == "function_local", odd
    assert odd.get("deferred_to") == [], (
        f"a string direct_calls char-split into the edge list: {odd!r}")
    assert odd.get("deferred_rowless") == [], odd

    worse = _row_for(findings, "worse")
    assert worse.get("deferred_to") == ["app/api.js:real"], (
        f"the garbage elements survived into the edge list (only the real "
        f"string id may): {worse!r}")

    none = _row_for(findings, "none")
    assert none.get("deferred_to") == [], none

    absent = _row_for(findings, "absent")
    assert absent.get("scope") == "function_local", absent
    assert absent.get("deferred_to") == [], absent
    assert absent.get("deferred_rowless") == [], absent


def test_non_safe_verdicts_carry_no_deferral(tmp_path, capsys, monkeypatch):
    """The class boundary: a non-safe verdict's concern is HERE, in the row's
    own function — no deferral fields (the lock against a blanket
    deferral that would misattribute concern-elsewhere to every row)."""
    import utilities.llm as _llm
    monkeypatch.setattr(_llm, "simple_text",
                        lambda binding, prompt, **kw: "<p>remediation</p>")
    from openant import cli

    args = _write_scan(
        tmp_path,
        results=[
            _result("app/api.js:vuln", "vulnerable"),
            _result("app/api.js:sink", "safe"),
        ],
        units=[
            _unit("app/api.js:vuln",
                  direct_calls=["app/api.js:sink"],
                  direct_callers=["app/api.js:sink"]),
            _unit("app/api.js:sink"),
        ])
    rc = cli.cmd_report_data(args)
    assert rc == 0
    findings = json.loads(capsys.readouterr().out.strip())["data"]["findings"]

    vuln = _row_for(findings, "vuln")
    assert "scope" not in vuln, (
        f"a non-safe verdict carries the scope field: {vuln!r}")
    assert "deferred_to" not in vuln, (
        f"a non-safe verdict carries the deferral fields: {vuln!r}")
    assert "deferred_rowless" not in vuln
    # the safe SINK row keeps the contract (the class is safe rows)
    sink = _row_for(findings, "sink")
    assert sink.get("scope") == "function_local", sink
    assert sink.get("deferred_to") == [], sink
