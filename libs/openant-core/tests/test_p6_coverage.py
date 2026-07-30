"""P6 coverage-fill tests — real behaviors flagged untested by the test-exhaustiveness
audit (tester-expert + auditor). Each exercises the production code path, not a stub."""
import hashlib
import os
import sys
import pathlib

from context.repo_explorer import RepoExplorer, ExplorationBudget, MAX_TOTAL_BYTES, MAX_LIST_ENTRIES

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))  # sibling test-helper import


# --- threat_model: provenance carry-through onto the loaded context. load_threat_model
#     sets ctx.source_sha256 (tamper-evidence) + ctx.permissive_warnings (self-whitelisting
#     audit trail) — both "previously discarded"; nothing asserted they reach the context. ---
def test_threat_model_provenance_carries_onto_context(tmp_path):
    import context.threat_model as T
    from test_threat_model_schema import valid_model
    # a permissive model: every input source trusted -> warn_permissive fires
    # keep the source key the default attacker's entry_via references, but make it trusted
    model = valid_model(input_sources={"git_manifest_repo": {"trust": "trusted", "description": "operator config"}})
    md = T.render_threat_model_md(model)
    f = tmp_path / "OPENANT.THREATMODEL.md"
    f.write_text(md)
    ctx = T.load_threat_model(tmp_path)
    assert ctx is not None
    assert ctx.source_sha256 == hashlib.sha256(f.read_bytes()).hexdigest(), "sha256 tamper-evidence not carried"
    assert ctx.permissive_warnings, "permissive self-whitelisting warning not carried onto context"


def _explorer(tmp_path):
    return RepoExplorer(str(tmp_path), ExplorationBudget())


# --- repo_explorer: the total-read budget ceiling (the module's "bounds are not
#     optional / an unbounded loop is an unbounded bill" contract) was untested. ---
def test_repo_explorer_total_read_budget_exhaustion(tmp_path):
    (tmp_path / "f.txt").write_text("some content")
    ex = _explorer(tmp_path)
    ex.budget.bytes_read = MAX_TOTAL_BYTES          # simulate having spent the budget
    result = ex._read_file("f.txt")
    assert "error" in result and "budget" in result["error"].lower()
    assert ex.budget.exhausted is True
    # control: a fresh budget reads normally
    ex2 = _explorer(tmp_path)
    assert "error" not in ex2._read_file("f.txt")


# --- repo_explorer: list_dir must REPORT truncation (a partial survey presented as
#     complete is the module's stated core failure mode). ---
def test_repo_explorer_list_dir_reports_truncation(tmp_path):
    d = tmp_path / "many"
    d.mkdir()
    for i in range(MAX_LIST_ENTRIES + 5):
        (d / f"f{i:04d}.txt").write_text("x")
    out = _explorer(tmp_path)._list_dir("many")
    assert out.get("truncated") is True
    assert len(out["entries"]) <= MAX_LIST_ENTRIES
    # control: a small dir is not marked truncated
    small = tmp_path / "few"; small.mkdir()
    (small / "a.txt").write_text("x")
    assert _explorer(tmp_path)._list_dir("few").get("truncated") is False
