"""#706: the finding display IDs are identity-derived, not positional.

PR #416 implemented the join-key half of #314's third suggestion and deferred
the display half as "a schema-design change" — but the derivation now exists one
line above the positional ID, so the deferred half is a RENAME, not a
redesign. A positional ``VULN-NNN`` is not stable across runs: any change to
the finding set renumbers everything after the insertion point, and consumers
that carry an ID across runs (a triage spreadsheet, a suppression list, a
cross-reference in a disclosure body) silently retarget.

The falsifier (authored at filing): "a report whose operator-visible finding
IDs are identical across two runs of the same commit with a finding inserted
before them."

The fix: the display ID is the ``VULN-`` prefix + the leading hex of the
finding's own ``identity_key`` (the run-stable hash over file/function/CWE
that #416 already derives), extended on a within-run prefix collision. The
consumers are form-agnostic by construction (#416's dynamic-test join reads
the id from the pipeline output and verifies the ``identity_key``; the patch
CLI looks the finding up by its id string; the ``#N`` linkifier links the
report's positional anchors, not the ids) — the migration surface is the
producer, the comments, and the docs' examples.
"""

import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_CORE_ROOT))

from core.reporter import finding_identity_key  # noqa: E402
import core.reporter as _prod_reporter  # noqa: E402

assert _prod_reporter.finding_identity_key is finding_identity_key  # the prod module


def _entry(file_, func, cwe, name="vuln"):
    return {
        "route_key": f"{file_}:{func}",
        "finding": name,
        "cwe_id": cwe,
    }


def _display_id(file_, func, cwe, all_ids=(), seen=frozenset()):
    """The prod display-ID derivation (mirror of the reporter's loop body):
    VULN- + the identity_key's leading hex, the TWO-PASS width (unique
    against every OTHER identity in the set) + the exact-duplicate ladder.
    Kept in lockstep with reporter._finding_display_id."""
    key = finding_identity_key(file_, func, cwe)
    return _prod_reporter._finding_display_id(
        key, list(all_ids) or [key], seen)


# --- the falsifier: stable across runs with an insertion before ---

def test_ids_stable_across_runs_with_an_insertion_before():
    """THE #706 falsifier: run 1 finds A, B; run 2 (the same commit, one new
    finding BEFORE them) finds A, NEW, B. The operator-visible IDs of A and B
    are IDENTICAL across the runs — the positional form renumbered B."""
    assert hasattr(_prod_reporter, "_finding_display_id"), (
        "the identity-derived display-ID derivation is missing from the prod reporter")
    a1 = _display_id("a.py", "fa", 89)
    b1 = _display_id("b.py", "fb", 79)
    # the same identities in run 2 (the insertion changed neither)
    a2 = _display_id("a.py", "fa", 89)
    b2 = _display_id("b.py", "fb", 79)
    assert a1 == a2, f"A's ID moved across runs: {a1} -> {a2}"
    assert b1 == b2, f"B's ID moved across runs: {b1} -> {b2}"
    # and the insertion's own ID is distinct from both
    n = _display_id("c.py", "fc", 79)
    assert n not in (a1, b1)


def test_the_id_form_is_vuln_prefixed_identity_hex():
    """The display ID is the VULN- prefix + the identity_key's leading hex —
    the operator-visible token names the identity it came from."""
    assert hasattr(_prod_reporter, "_finding_display_id"), (
        "the identity-derived display-ID derivation is missing from the prod reporter")
    key = finding_identity_key("app.py", "run", 78)
    i = _display_id("app.py", "run", 78)
    assert i.startswith("VULN-"), f"the form lost its prefix: {i}"
    assert i[len("VULN-"):] in key, (
        f"the ID's body {i!r} is not a prefix of the identity {key!r}")


def test_distinct_identities_get_distinct_ids():
    """Two different findings (different file/function/CWE triples) never
    share a display ID in one run."""
    ids = {
        _display_id(f"f{i}.py", f"fn{i}", 79 + i)
        for i in range(8)
    }
    assert len(ids) == 8, f"a prefix collision fanned into ambiguity: {ids}"


# --- the collision extension (the same identity twice in one run) ---

def test_duplicate_identity_falls_to_the_positional_ladder():
    """A genuine duplicate (the same file/function/CWE twice in one run)
    must not share a display ID: the twin holds the width form; the second
    occurrence takes the #n positional ladder — deterministic within the
    run, never silent."""
    key = finding_identity_key("dup.py", "same", 89)
    first = _display_id("dup.py", "same", 89, all_ids=[key, key])
    second = _display_id("dup.py", "same", 89, all_ids=[key, key],
                         seen={first})
    assert first != second, (
        f"the duplicate shares the ID: {first} == {second}")
    assert second == f"VULN-{key}#2", (
        f"the ladder form drifted: {second}")
    # deterministic
    assert second == _display_id("dup.py", "same", 89, all_ids=[key, key],
                                 seen={first})


def test_prefix_collision_extends_both_sides():
    """The fable-r1 F1 pin: two DIFFERENT identities sharing a 6-hex
    prefix — BOTH extend to 8 (the short form names nobody; no silent
    retarget through the fix's own mechanism); the assignment is
    ORDER-INDEPENDENT (reversing the list changes neither id)."""
    # construct two file names whose identity keys share the 6-hex prefix
    # (search deterministically; the identity is sha256[:12] over the
    # file|func|cwe triple)
    import hashlib
    base = None
    for n in range(100000):
        f1 = f"m{n}.py"
        k1 = hashlib.sha256(f"{f1}|fx|79".encode()).hexdigest()[:12]
        for m in range(100):
            f2 = f"x{m}.py"
            k2 = hashlib.sha256(f"{f2}|fx|79".encode()).hexdigest()[:12]
            if k1[:6] == k2[:6] and k1 != k2:
                base = (f1, k1, f2, k2)
                break
        if base:
            break
    assert base, "no prefix-collision pair found (the search drifted)"
    f1, k1, f2, k2 = base
    i1 = _display_id(f1, "fx", 79, all_ids=[k1, k2])
    i2 = _display_id(f2, "fx", 79, all_ids=[k1, k2])
    # BOTH extend to 8: neither holds the 6-char form
    assert i1 == f"VULN-{k1[:8]}" and i2 == f"VULN-{k2[:8]}", (
        f"the pair did not both extend: {i1} / {i2}")
    # ORDER-INDEPENDENT: the reversed set gives the same ids
    i1r = _display_id(f1, "fx", 79, all_ids=[k2, k1])
    i2r = _display_id(f2, "fx", 79, all_ids=[k2, k1])
    assert (i1, i2) == (i1r, i2r), (
        f"the assignment is order-dependent: {(i1, i2)} vs {(i1r, i2r)}")


# --- the consumers: form-agnostic by construction, pinned ---

def test_the_dynamic_merge_still_verifies_by_identity():
    """#416's join (the generator's merge) reads the id from the pipeline
    output and verifies the identity_key — the new id form flows through
    unchanged. The merge's refusal rule (a stale results file) still holds."""
    import json
    import tempfile
    import os
    from report.generator import merge_dynamic_results
    assert hasattr(_prod_reporter, "_finding_display_id"), (
        "the identity-derived display-ID derivation is missing from the prod reporter")
    fid = _display_id("app.py", "run", 78)
    key = finding_identity_key("app.py", "run", 78)
    pipeline = {"findings": [{
        "id": fid, "identity_key": key,
        "name": "x", "short_name": "x",
        "location": {"file": "app.py", "function": "run"},
    }]}
    with tempfile.TemporaryDirectory() as d:
        po = os.path.join(d, "pipeline_output.json")
        with open(po, "w") as fh:
            json.dump(pipeline, fh)
        # a stale results file: the SAME id but a DIFFERENT identity
        with open(os.path.join(d, "dynamic_test_results.json"), "w") as fh:
            json.dump({"results": [{
                "finding_id": fid,
                "identity_key": finding_identity_key("other.py", "zzz", 1),
                "executed": True,
            }]}, fh)
        merged = merge_dynamic_results(json.loads(json.dumps(pipeline)), po)
        f0 = merged["findings"][0]
        assert "dynamic_testing" not in f0, (
            "the stale-file mis-join merged through the new id form")
        # the honest merge: the SAME identity, a CONFIRMED status
        with open(os.path.join(d, "dynamic_test_results.json"), "w") as fh:
            json.dump({"results": [{
                "finding_id": fid, "identity_key": key, "status": "CONFIRMED",
                "details": "the container reproduced it",
            }]}, fh)
        merged = merge_dynamic_results(json.loads(json.dumps(pipeline)), po)
        dt = merged["findings"][0].get("dynamic_testing")
        assert dt and dt.get("status") == "CONFIRMED", (
            f"the identity-agreeing merge failed through the new id form: {dt}")
        assert dt.get("identity_key") == key, "the join lost its audit trail"


def test_the_loop_dedups_a_duplicate_identitys_display_id(tmp_path):
    """The LOOP's seen-set update (the C4 row was green until this pin):
    a results file carrying the SAME finding identity TWICE (a genuine
    duplicate that survived dedup) must not emit two findings sharing a
    display ID — the second occurrence extends its prefix."""
    import json
    from utilities.file_io import write_json
    from core.reporter import build_pipeline_output
    assert hasattr(_prod_reporter, "_finding_display_id"), (
        "the identity-derived display-ID derivation is missing from the prod reporter")
    results = {
        "dataset": "test",
        "code_by_route": {"x.py:fx": "def fx(): pass"},
        "metrics": {},
        "confirmed_findings": [
            {"route_key": "x.py:fx", "unit_id": "x.py:fx",
             "verdict": "VULNERABLE", "finding": "vulnerable", "cwe_id": 89},
            {"route_key": "x.py:fx", "unit_id": "x.py:fx",
             "verdict": "VULNERABLE", "finding": "vulnerable", "cwe_id": 89},
        ],
    }
    rp = tmp_path / "results.json"
    write_json(rp, results)
    op = tmp_path / "pipeline_output.json"
    build_pipeline_output(str(rp), str(op), language="python", repo_name="t/r")
    out = json.loads(op.read_text())
    ids = [f["id"] for f in out["findings"]]
    assert len(ids) == 2 and ids[0] != ids[1], (
        f"the duplicate identity shares a display ID: {ids}")
    # both ids derive from the same identity key
    keys = {f["identity_key"] for f in out["findings"]}
    assert len(keys) == 1, "the fixture drifted from the duplicate shape"


def test_the_real_loop_falsifier_stable_with_an_insertion_before(tmp_path):
    """The fable-r1-F2/r2-F-B pin: the #706 falsifier through the REAL
    build_pipeline_output — two runs of the same commit, the second with a
    finding inserted BEFORE the survivors; the surviving ids IDENTICAL
    (the loop-level guard against a position leak into the identity
    derivation — the r2 mutant `_confirmed_identities[:i+1]` survived the
    helper-level pins undetected)."""
    import json
    from utilities.file_io import write_json
    from core.reporter import build_pipeline_output
    assert hasattr(_prod_reporter, "_finding_cwe"), (
        "the shared CWE extraction is missing from the prod reporter")
    run1 = [
        {"route_key": "a.py:fa", "unit_id": "a.py:fa", "verdict": "VULNERABLE",
         "finding": "vulnerable", "cwe_id": 89},
        {"route_key": "b.py:fb", "unit_id": "b.py:fb", "verdict": "VULNERABLE",
         "finding": "vulnerable", "cwe_id": 79},
    ]
    inserted = {"route_key": "c.py:fc", "unit_id": "c.py:fc",
                "verdict": "VULNERABLE", "finding": "vulnerable", "cwe_id": 79}
    run2 = [run1[0], inserted, run1[1]]
    ids = []
    for findings in (run1, run2):
        rp = tmp_path / f"results-{len(ids)}.json"
        write_json(rp, {"dataset": "t", "code_by_route": {}, "metrics": {},
                        "confirmed_findings": findings})
        op = tmp_path / f"po-{len(ids)}.json"
        build_pipeline_output(str(rp), str(op), language="python", repo_name="t/r")
        data = json.loads(op.read_text())
        by_route = {f["location"]["file"] + ":" + f["location"]["function"]: f["id"]
                   for f in data["findings"]}
        ids.append(by_route)
    assert ids[0]["a.py:fa"] == ids[1]["a.py:fa"], (
        f"A's ID moved across the runs: {ids[0]['a.py:fa']} -> {ids[1]['a.py:fa']}")
    assert ids[0]["b.py:fb"] == ids[1]["b.py:fb"], (
        f"B's ID moved across the runs: {ids[0]['b.py:fb']} -> {ids[1]['b.py:fb']}")
    assert ids[1]["c.py:fc"] not in ids[0].values(), (
        "the insertion's ID collides with a survivor's")


def test_the_real_loop_prefix_collision_never_retargets(tmp_path):
    """The fable-r1-F1 shape through the REAL loop: an inserted finding
    sharing a 6-hex identity prefix with a survivor — the survivor
    LENGTHENS (the disclosed residual), the short form names NOBODY, and
    no id ever names a different finding."""
    import json
    import hashlib
    from utilities.file_io import write_json
    from core.reporter import build_pipeline_output
    # the deterministic prefix-collision pair (the same search as the
    # helper-level pin)
    base = None
    for n in range(100000):
        f1 = f"m{n}.py"
        k1 = hashlib.sha256(f"{f1}|fx|79".encode()).hexdigest()[:12]
        for m in range(100):
            f2 = f"x{m}.py"
            k2 = hashlib.sha256(f"{f2}|fx|79".encode()).hexdigest()[:12]
            if k1[:6] == k2[:6] and k1 != k2:
                base = (f1, k1, f2, k2)
                break
        if base:
            break
    assert base
    f1, k1, f2, k2 = base
    alone = [{"route_key": f"{f1}:fx", "unit_id": f"{f1}:fx",
              "verdict": "VULNERABLE", "finding": "vulnerable", "cwe_id": 79}]
    pair = [alone[0], {"route_key": f"{f2}:fx", "unit_id": f"{f2}:fx",
                       "verdict": "VULNERABLE", "finding": "vulnerable",
                       "cwe_id": 79}]
    out = []
    for findings in (alone, pair):
        rp = tmp_path / f"r-{len(out)}.json"
        write_json(rp, {"dataset": "t", "code_by_route": {}, "metrics": {},
                        "confirmed_findings": findings})
        op = tmp_path / f"p-{len(out)}.json"
        build_pipeline_output(str(rp), str(op), language="python", repo_name="t/r")
        data = json.loads(op.read_text())
        out.append({f["location"]["file"]: f["id"] for f in data["findings"]})
    # run 1: f1 alone holds the 6-char form
    assert out[0][f1] == f"VULN-{k1[:6]}", out[0]
    # run 2: BOTH extend to 8 — the 6-char form names nobody
    assert out[1][f1] == f"VULN-{k1[:8]}", out[1]
    assert out[1][f2] == f"VULN-{k2[:8]}", out[1]
    assert f"VULN-{k1[:6]}" not in out[1].values(), (
        "the short form still names a finding after the colliding insertion")


def test_the_reporter_loop_emits_the_identity_form(tmp_path):
    """The producer loop itself (not just the derivation helper): a built
    pipeline_output carries VULN-<identity hex> ids — the positional
    f-string is gone. (The established _run_build shape, two findings.)"""
    import json
    from utilities.file_io import write_json
    from core.reporter import build_pipeline_output
    results = {
        "dataset": "test",
        "code_by_route": {"x.py:fx": "def fx(): pass", "y.py:fy": "def fy(): pass"},
        "metrics": {},
        "confirmed_findings": [
            {"route_key": "x.py:fx", "unit_id": "x.py:fx",
             "verdict": "VULNERABLE", "finding": "vulnerable", "cwe_id": 89},
            {"route_key": "y.py:fy", "unit_id": "y.py:fy",
             "verdict": "VULNERABLE", "finding": "vulnerable", "cwe_id": 79},
        ],
    }
    rp = tmp_path / "results.json"
    write_json(rp, results)
    op = tmp_path / "pipeline_output.json"
    build_pipeline_output(str(rp), str(op), language="python", repo_name="t/r")
    out = json.loads(op.read_text())
    ids = [f["id"] for f in out["findings"]]
    assert all(i.startswith("VULN-") for i in ids), ids
    for f in out["findings"]:
        assert f["id"][len("VULN-"):] in f["identity_key"], (
            f"the id {f['id']!r} is not derived from {f['identity_key']!r}")
    # the positional form is detectably gone: two findings, ids NOT 001/002
    assert "VULN-001" not in ids and "VULN-002" not in ids, (
        f"the positional form survived: {ids}")
