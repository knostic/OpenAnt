"""#739 — ``--limit N`` selects units by file-walk order, not analysis
priority: the raw head-slice took ``dataset.units[:N]`` — a limited run
silently measured whichever files the parser visited first (the campaign's
``--limit 3`` on OpenBao selected three ``api/auth/approle/*`` CLIENT-SDK
files while the 90 ``http_handler`` units — the server attack surface —
began at index 18; the scan read "0 findings" as a completed scan on a
target whose handlers were never analyzed).

THE RULING (the issue's shape 1 + the shape-2 label): the priority
available BEFORE enhancement is the structural one — the seeded entry
points (``is_entry_point``, stamped by the reachability filter / the
LLM-reachability promotions) and the call-graph edges
(``metadata.direct_calls``). The selection is a multi-source BFS from the
entry points (depth 0 = the seeds, depth 1 = their direct callees, ...),
original file order as the per-depth tiebreak (deterministic), unreachable
units last. When NO unit is seeded the order is UNCHANGED and the
reportable label says ``file-order-head-slice`` — a file-order sample
never reads as a priority-based one.

Shapes:
  S1 -- the WITNESS (assertion-red at base): the issue's own regression
        shape — a low-index trivial module + a high-index handler that an
        entry point calls: --limit 1 selects the HANDLER.
  S2 -- the seed itself first: a high-index is_entry_point unit wins over
        every file-earlier non-seed.
  S3 -- the BFS chain: seed -> callee -> callee-of-callee; limit 2 takes
        depth 0 + depth 1, never the file-order head.
  S4 -- the determinism control: same-depth units keep the file order.
  S5 -- the no-seeds fallback: the order UNCHANGED + the mode label
        file-order-head-slice.
  S6 -- unreachable units sort last (an island at index 0 loses to any
        entry-path unit).
  S7 -- the fa15 tolerance: non-dict rows, missing metadata, duplicate
        ids, id-less rows — no crash, no reorder of the pass-through rows.
  S8 -- the INTEGRATION witness: the REAL enhance_dataset (the registry
        stubbed, the ContextEnhancer stubbed) with --limit 1 on the
        synthetic corpus — the units the stub SEES are the priority
        selection.
  S9 -- the label control: limit_selection_mode over a seeded population
        reads entry-path-bfs; over a bare one, file-order-head-slice.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

def _unit(uid, *, entry=False, calls=None):  # noqa: E402
    u = {"id": uid, "unit_type": "function", "code": {"primary_code": "..."}}
    if entry:
        u["is_entry_point"] = True
    if calls is not None:
        u["metadata"] = {"direct_calls": calls}
    return u


# ---------------------------------------------------------------------------
# S1/S2/S3/S6 — the priority selection
# ---------------------------------------------------------------------------
def test_the_issue_regression_shape_limit_1_selects_the_handler():
    """The campaign's exact shape: the file-order head is a trivial client
    module; the entry point's callee — the handler — sits later. --limit 1
    must select the handler, never the file-order head."""
    units = [
        _unit("api/auth/approle/sdk_client.go:List"),   # index 0, trivial
        _unit("api/auth/approle/sdk_client.go:Read"),   # index 1, trivial
        _unit("http/handler.go:CreateUser",             # index 2: the seed
              entry=True),
        _unit("http/handler.go:CreateUser.writeDB",     # index 3: callee
              calls=[]),
    ]
    units[2]["metadata"] = {"direct_calls": ["http/handler.go:CreateUser.writeDB"]}
    from core.enhancer import select_units_for_limit
    selected = select_units_for_limit(units, 1)
    assert [u["id"] for u in selected] == ["http/handler.go:CreateUser"], (
        f"the limit selected the file-order head, not the entry point: "
        f"{[u['id'] for u in selected]!r}")


def test_the_seed_wins_over_file_earlier_units():
    units = [
        _unit("a/trivial.go:Do"), _unit("b/trivial.go:Do"),
        _unit("z/handler.go:Handle", entry=True),
    ]
    from core.enhancer import select_units_for_limit
    selected = select_units_for_limit(units, 1)
    assert [u["id"] for u in selected] == ["z/handler.go:Handle"]


def test_the_bfs_chain_takes_depths_in_order():
    units = [
        _unit("a/first.go:Irrelevant"),                     # file head
        _unit("m/deep.go:L3", calls=[]),                    # depth 3
        _unit("m/mid.go:L2", calls=["m/deep.go:L3"]),       # depth 2
        _unit("m/seed.go:L1", entry=True,
              calls=["m/mid.go:L2"]),                       # depth 0
        _unit("m/other.go:SameDepth"),                      # unreachable
    ]
    from core.enhancer import select_units_for_limit
    selected = select_units_for_limit(units, 2)
    assert [u["id"] for u in selected] == [
        "m/seed.go:L1", "m/mid.go:L2"], (
        f"the BFS depths came out of order: {[u['id'] for u in selected]!r}")


def test_unreachable_units_sort_last():
    units = [
        _unit("island/island.go:Alone", calls=[]),          # island at 0
        _unit("z/entry.go:Seed", entry=True, calls=[]),     # seed at 1
    ]
    from core.enhancer import select_units_for_limit
    selected = select_units_for_limit(units, 1)
    assert [u["id"] for u in selected] == ["z/entry.go:Seed"]


# ---------------------------------------------------------------------------
# S4/S5/S7 — the determinism/fallback/tolerance controls
# ---------------------------------------------------------------------------
def test_same_depth_keeps_the_file_order():
    units = [
        _unit("a.go:B", calls=[]), _unit("b.go:A", calls=[]),
        _unit("seed.go:S", entry=True,
              calls=["a.go:B", "b.go:A"]),
        _unit("z/last.go:Irrelevant", calls=[]),
    ]
    from core.enhancer import select_units_for_limit
    selected = select_units_for_limit(units, 3)
    assert [u["id"] for u in selected] == [
        "seed.go:S", "a.go:B", "b.go:A"], (
        "the per-depth tiebreak must keep the file order (determinism)")
    # and it is stable across calls (the reproducibility contract)
    again = select_units_for_limit(units, 3)
    assert [u["id"] for u in again] == [u["id"] for u in selected]
    # the limit DOES bind over the file-order population too (the fallback
    # slices, never passes the whole set through)
    no_seed = [_unit("a.go:A"), _unit("b.go:B"), _unit("c.go:C")]
    assert [u["id"] for u in select_units_for_limit(no_seed, 2)] == [
        "a.go:A", "b.go:B"]


def test_no_seeds_leaves_the_order_unchanged():
    units = [_unit("a.go:A"), _unit("b.go:B", calls=["a.go:A"]),
             _unit("c.go:C")]
    from core.enhancer import (LIMIT_MODE_FILE_ORDER,
                                limit_selection_mode,
                                select_units_for_limit)
    selected = select_units_for_limit(units, 3)
    assert [u["id"] for u in selected] == ["a.go:A", "b.go:B", "c.go:C"], (
        "a corpus with NO seeded entry points must keep the file order")
    assert limit_selection_mode(units) == LIMIT_MODE_FILE_ORDER
    # and the label still names the honest mode when the limit binds
    head = select_units_for_limit(units, 2)
    assert [u["id"] for u in head] == ["a.go:A", "b.go:B"]


def test_malformed_rows_pass_through_without_crashing():
    units = [
        None,                                   # the fa15 non-dict row
        "junk",                                 # another
        {"id": None, "metadata": "not-a-dict"}, # id-less, malformed metadata
        _unit("seed.go:S", entry=True, calls=None),   # no metadata key
        _unit("seed.go:S", entry=True, calls=[42, None, "x.go:X"]),  # dup id
        _unit("x.go:X", calls=[]),              # the callee from the junk edges
    ]
    from core.enhancer import select_units_for_limit
    selected = select_units_for_limit(units, 3)
    assert len(selected) == 3
    seeds = [u for u in selected
             if isinstance(u, dict) and u.get("is_entry_point")]
    assert seeds, "the seed must survive the malformed rows and rank first"


# ---------------------------------------------------------------------------
# S8/S9 — the integration + the label
# ---------------------------------------------------------------------------
def test_the_real_enhance_dataset_selects_by_priority(tmp_path, monkeypatch):
    """The REAL slice path: enhance_dataset(limit=1) on the synthetic
    corpus — the units the (stubbed) enhancer sees are the priority
    selection, and the mode line prints entry-path-bfs."""
    import core.enhancer as enh
    import utilities.context_enhancer as _ce
    from utilities.llm import PhaseBinding

    dataset_path = tmp_path / "dataset.json"
    units = [
        _unit("api/auth/approle/sdk_client.go:List"),        # file head
        _unit("http/handler.go:Handle", entry=True,
              calls=["http/handler.go:Handle.writeDB"]),
        _unit("http/handler.go:Handle.writeDB", calls=[]),
    ]
    dataset_path.write_text(json.dumps({
        "units": units, "metadata": {"repo": "synthetic"}}))

    seen = {}

    class _DummyEnhancer:
        def __init__(self, **kw):
            pass

        def enhance_dataset(self, dataset, progress_callback=None,
                            workers=8, **kw):
            seen["units"] = dataset.get("units")
            return {
                "units": dataset.get("units", []),
                "metadata": dataset.get("metadata", {}),
            }

        def enhance_dataset_agentic(self, dataset, **kw):
            return self.enhance_dataset(dataset, **kw)

    class _FakeAdapter:
        name = "anthropic"
        supports_tools = True

        def complete(self, **kw):  # pragma: no cover
            raise AssertionError("adapter.complete must not be called")

        def validate(self, model):  # pragma: no cover
            pass

    class _StubRegistry:
        config_name = "openant-default"

        def get(self, phase):
            return PhaseBinding(phase=phase, adapter=_FakeAdapter(),
                                model="claude-test", provider_name="anthropic")

    monkeypatch.setattr(_ce, "ContextEnhancer", _DummyEnhancer)

    import io, contextlib
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        out = enh.enhance_dataset(
            dataset_path=str(dataset_path),
            output_path=str(tmp_path / "enhanced.json"),
            analyzer_output_path=str(tmp_path / "analyzer.json"),
            registry=_StubRegistry(),
            limit=1,
        )
    got = [u["id"] for u in seen["units"]]
    assert got == ["http/handler.go:Handle"], (
        f"the REAL slice selected {got!r} — the file-order head, not the "
        f"entry point")
    assert "entry-path-bfs" in err.getvalue(), (
        "the mode line must name the selection mode")
    # the written dataset carries ONLY the selection
    written = json.loads((tmp_path / "enhanced.json").read_text())
    assert [u["id"] for u in written["units"]] == ["http/handler.go:Handle"]
    assert out is not None


def test_the_mode_label_reads_both_directions():
    from core.enhancer import (LIMIT_MODE_ENTRY_PATH, LIMIT_MODE_FILE_ORDER,
                                limit_selection_mode)
    assert limit_selection_mode(
        [_unit("a.go:A"), _unit("b.go:B", entry=True)]) == LIMIT_MODE_ENTRY_PATH
    assert limit_selection_mode(
        [_unit("a.go:A"), _unit("b.go:B")]) == LIMIT_MODE_FILE_ORDER
    assert limit_selection_mode([]) == LIMIT_MODE_FILE_ORDER


# ---------------------------------------------------------------------------
# S10 — the SCAN-PATH WIRING: the REAL scan_repository's enhance step
# carries limit_mode in its step report (present-only; the no-limit run
# gains no key)
# ---------------------------------------------------------------------------
def test_the_real_scan_labels_the_limit_mode(tmp_path, monkeypatch):
    """The write-site pin: the scanner's enhance step reads the STAMPED
    EnhanceResult.limit_mode (the slice site's own population) into its
    step-report summary — a limited run's report names WHAT the selection
    was (the shape-2 half), and a no-limit run's summary gains no key."""
    import core.parser_adapter as parser_adapter
    import core.enhancer as enhancer_mod
    from core.enhancer import LIMIT_MODE_ENTRY_PATH
    import utilities.llm as llm_mod
    from core import scanner as scanner_mod

    class _ParseResult:
        def __init__(self, output_dir):
            self.dataset_path = str(Path(output_dir) / "dataset.json")
            self.analyzer_output_path = str(Path(output_dir) / "analyzer.json")
            self.units_count = 2
            self.language = "python"
            self.processing_level = "reachable"

    def _fake_parse(*, output_dir, **kwargs):
        pr = _ParseResult(output_dir)
        units = [
            _unit("api/auth/approle/sdk_client.go:List"),
            _unit("http/handler.go:Handle", entry=True,
                  calls=["http/handler.go:Handle.writeDB"]),
            _unit("http/handler.go:Handle.writeDB", calls=[]),
        ]
        Path(pr.dataset_path).write_text(json.dumps({
            "units": units, "metadata": {}}))
        Path(pr.analyzer_output_path).write_text("{}")
        return pr

    def _fake_enhance(*, dataset_path, output_path, **kwargs):
        # the real selection runs inside enhance_dataset — call it
        units = json.loads(Path(dataset_path).read_text()).get("units", [])
        limit = kwargs.get("limit")
        mode = ""
        if limit:
            mode = enhancer_mod.limit_selection_mode(units)
            units = enhancer_mod.select_units_for_limit(units, limit)
        Path(output_path).write_text(json.dumps({"units": units}))
        from core.schemas import EnhanceResult as _ER
        return _ER(
            enhanced_dataset_path=output_path,
            units_enhanced=len(units), error_count=0,
            classifications={}, incomplete_count=0,
            total_units=len(units), limit_mode=mode)

    monkeypatch.setattr(parser_adapter, "parse_repository", _fake_parse)
    monkeypatch.setattr(enhancer_mod, "enhance_dataset", _fake_enhance)
    monkeypatch.setattr(
        llm_mod, "probe_registry_or_raise", lambda *a, **k: None)

    def _scan(limit):
        import contextlib, io
        out = tmp_path / f"out-{limit}"
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            r = scanner_mod.scan_repository(
                repo_path=str(tmp_path),
                output_dir=str(out),
                generate_context=False,
                enhance=True,
                verify=False,
                generate_report=False,
                dynamic_test=False,
                processing_level="reachable",
                limit=limit,
            )
        report = json.loads((out / "enhance.report.json").read_text())
        return r, report, err.getvalue()

    r1, rep1, err1 = _scan(1)
    # the limited run's enhance step carries the mode label
    assert rep1["summary"]["limit_mode"] == LIMIT_MODE_ENTRY_PATH, (
        f"the scan report lost the selection-mode label: "
        f"{rep1['summary'].get('limit_mode')!r}")
    assert "entry-path-bfs" in err1
    # and the enhanced set is the priority selection (the real selection ran)
    written = json.loads(Path(r1.enhanced_dataset_path).read_text())
    assert [u["id"] for u in written["units"]] == ["http/handler.go:Handle"]

    # the no-limit run gains NO key (present-only)
    _, rep2, _ = _scan(None)
    assert "limit_mode" not in rep2["summary"], (
        f"the no-limit run grew a limit_mode key: "
        f"{rep2['summary'].get('limit_mode')!r}")


# ---------------------------------------------------------------------------
# S11 — the T1-r1 F1 catch: the label is stamped over the population the
# slice ACTUALLY selected from (the #213 diff-selected subset), never the
# unfiltered corpus
# ---------------------------------------------------------------------------
def test_diff_mode_limit_label_matches_the_actual_selection(
        tmp_path, monkeypatch):
    """The F1 falsifier, executed: a diff-mode dataset whose FULL corpus
    carries an entry point but whose diff_selected subset does NOT — the
    selection is a file-order head slice over the subset, and the label
    must say file-order-head-slice (the pre-fix scanner read the
    unfiltered corpus and printed entry-path-bfs: the exact inversion the
    fix's own comment forbids)."""
    import core.enhancer as enh
    import utilities.context_enhancer as _ce
    from utilities.llm import PhaseBinding

    dataset_path = tmp_path / "dataset.json"
    units = [
        # the diff-selected subset: no seeds, file order = sdk first
        dict(_unit("api/auth/approle/sdk_client.go:List"),
             diff_selected=True),
        dict(_unit("api/auth/approle/sdk_client.go:Read"),
             diff_selected=True),
        # the full corpus's entry point — NOT diff-selected
        _unit("http/handler.go:Handle", entry=True),
    ]
    dataset_path.write_text(json.dumps({
        "units": units, "metadata": {"repo": "synthetic"}}))

    seen = {}

    class _DummyEnhancer:
        def __init__(self, **kw):
            pass

        def enhance_dataset(self, dataset, progress_callback=None,
                            workers=8, **kw):
            seen["units"] = dataset.get("units")
            return {
                "units": dataset.get("units", []),
                "metadata": dataset.get("metadata", {}),
            }

        def enhance_dataset_agentic(self, dataset, **kw):
            return self.enhance_dataset(dataset, **kw)

    class _FakeAdapter:
        name = "anthropic"
        supports_tools = True

        def complete(self, **kw):  # pragma: no cover
            raise AssertionError("adapter.complete must not be called")

        def validate(self, model):  # pragma: no cover
            pass

    class _StubRegistry:
        config_name = "openant-default"

        def get(self, phase):
            return PhaseBinding(phase=phase, adapter=_FakeAdapter(),
                                model="claude-test", provider_name="anthropic")

    monkeypatch.setattr(_ce, "ContextEnhancer", _DummyEnhancer)

    import io, contextlib
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        out = enh.enhance_dataset(
            dataset_path=str(dataset_path),
            output_path=str(tmp_path / "enhanced.json"),
            analyzer_output_path=str(tmp_path / "analyzer.json"),
            registry=_StubRegistry(),
            limit=1,
        )
    # the selection ran over the DIFF SUBSET (file order — no seeds there)
    got = [u["id"] for u in seen["units"]]
    assert got == ["api/auth/approle/sdk_client.go:List"], (
        f"the diff-mode selection left the subset: {got!r}")
    # the STAMP (the r2 R2-F1 catch: the stderr print predates the F1 fix,
    # so only the stamped field guards the producer half)
    assert out.limit_mode == "file-order-head-slice", (
        f"the stamped mode describes the wrong population: "
        f"{out.limit_mode!r}")
    # and the printed label matches the stamp
    assert "file-order-head-slice" in err.getvalue(), (
        "the diff-mode label must describe the subset's selection "
        f"(got stderr: {err.getvalue()[-200:]!r})")


# ---------------------------------------------------------------------------
# S12 — the SCAN-PATH F1 falsifier: the REAL enhance_dataset inside the
# REAL scan (the ContextEnhancer stubbed — the slice/stamp/scanner-read
# chain is all real), a diff-annotated dataset whose subset carries no
# seed while the corpus does. The step report's limit_mode must name the
# SUBSET's file-order selection — RED when the F1 defect (the label read
# over the unfiltered corpus) is re-introduced (the r2 isolating control).
# ---------------------------------------------------------------------------
def test_scan_path_diff_mode_label_is_the_subsets_selection(
        tmp_path, monkeypatch):
    import core.parser_adapter as parser_adapter
    import utilities.context_enhancer as _ce
    import utilities.llm as llm_mod
    from core import scanner as scanner_mod

    class _ParseResult:
        def __init__(self, output_dir):
            self.dataset_path = str(Path(output_dir) / "dataset.json")
            self.analyzer_output_path = str(Path(output_dir) / "analyzer.json")
            self.units_count = 2
            self.language = "python"
            self.processing_level = "reachable"

    def _fake_parse(*, output_dir, **kwargs):
        pr = _ParseResult(output_dir)
        units = [
            # the diff-selected subset: no seeds, file order = sdk first
            dict(_unit("api/auth/approle/sdk_client.go:List"),
                 diff_selected=True),
            dict(_unit("api/auth/approle/sdk_client.go:Read"),
                 diff_selected=True),
            # the corpus's entry point — NOT diff-selected
            _unit("http/handler.go:Handle", entry=True),
        ]
        Path(pr.dataset_path).write_text(json.dumps({
            "units": units, "metadata": {}}))
        Path(pr.analyzer_output_path).write_text("{}")
        return pr

    class _DummyEnhancer:
        def __init__(self, **kw):
            pass

        def enhance_dataset(self, dataset, progress_callback=None,
                            workers=8, **kw):
            return {
                "units": dataset.get("units", []),
                "metadata": dataset.get("metadata", {}),
            }

        def enhance_dataset_agentic(self, dataset, **kw):
            return self.enhance_dataset(dataset, **kw)

    monkeypatch.setattr(parser_adapter, "parse_repository", _fake_parse)
    monkeypatch.setattr(_ce, "ContextEnhancer", _DummyEnhancer)
    monkeypatch.setattr(
        llm_mod, "probe_registry_or_raise", lambda *a, **k: None)

    from core.enhancer import LIMIT_MODE_FILE_ORDER
    import contextlib, io
    out = tmp_path / "out-scan"
    with contextlib.redirect_stderr(io.StringIO()):
        scanner_mod.scan_repository(
            repo_path=str(tmp_path),
            output_dir=str(out),
            generate_context=False,
            enhance=True,
            verify=False,
            generate_report=False,
            dynamic_test=False,
            processing_level="reachable",
            limit=1,
        )
    report = json.loads((out / "enhance.report.json").read_text())
    summary = report.get("summary") or {}
    assert summary.get("limit_mode") == LIMIT_MODE_FILE_ORDER, (
        f"the scan report's label must describe the DIFF SUBSET's "
        f"selection (the F1 class): {summary.get('limit_mode')!r}")


# ---------------------------------------------------------------------------
# S13 — the serialization gate (the r3-predicted green survivor, killed):
# limit_mode is PRESENT-ONLY on the wire — an unlimited EnhanceResult
# serializes byte-identical to the pre-#739 shape; a stamped one carries it.
# ---------------------------------------------------------------------------
def test_limit_mode_serializes_present_only():
    from core.schemas import EnhanceResult

    unlimited = EnhanceResult(enhanced_dataset_path="x",
                               units_enhanced=1, total_units=1)
    d = unlimited.to_dict()
    assert "limit_mode" not in d, (
        f"the unlimited run grew a limit_mode key on the wire: {d!r}")
    stamped = EnhanceResult(enhanced_dataset_path="x",
                            units_enhanced=1, total_units=1,
                            limit_mode="entry-path-bfs")
    assert stamped.to_dict()["limit_mode"] == "entry-path-bfs"


# ---------------------------------------------------------------------------
# S14 — THE NON-BINDING LIMIT (the mislabel this PR's own intent forbids).
# `--limit N` with N >= len(units) selects NOTHING: select_units_for_limit
# early-returns the units unreordered and unsliced. The first cut still
# stamped `entry-path-bfs`, so the artifact claimed a priority selection that
# never ran -- verbatim the failure #739 exists to remove ("the mode is
# printed so a limited run never reads as a priority-based sample when it is
# not"). The label must name the truth: no selection ran.
# ---------------------------------------------------------------------------
def test_a_non_binding_limit_is_not_labelled_a_priority_selection():
    from core.enhancer import (LIMIT_MODE_ENTRY_PATH, LIMIT_MODE_NOT_BINDING,
                               limit_selection_mode, select_units_for_limit,
                               limit_mode_for)
    units = [_unit("a.go:A", entry=True, calls=["b.go:B"]),
             _unit("b.go:B"), _unit("c.go:C")]
    # the seeding predicate is unchanged: it answers "is there a BFS source?"
    assert limit_selection_mode(units) == LIMIT_MODE_ENTRY_PATH
    # but with a limit that does not bind, NOTHING is selected...
    assert select_units_for_limit(units, 10) == units
    # ...so the REPORTED mode must say so, not name a BFS that never ran.
    assert limit_mode_for(units, 10) == LIMIT_MODE_NOT_BINDING, (
        "a limit >= len(units) reordered and sliced nothing; labelling it "
        "entry-path-bfs is the exact mislabel #739 exists to remove")
    # the boundary: a limit that DOES bind keeps the priority label
    assert limit_mode_for(units, 2) == LIMIT_MODE_ENTRY_PATH
    # and the equality case selects nothing either (len == limit)
    assert limit_mode_for(units, 3) == LIMIT_MODE_NOT_BINDING
