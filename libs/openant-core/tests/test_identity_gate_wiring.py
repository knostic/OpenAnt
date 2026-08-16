"""Wiring tests for the I2 gate: analyze->verify fingerprint fold and the
analyzer's results.json preservation. These exercise the seams the pipeline
uses without any billed API call.
"""

import json
import os
import types

from core import backend_identity as bi
from core.checkpoint import StepCheckpoint, FINGERPRINT_FILE


class _FakeAdapter:
    name = "anthropic"


def _binding(phase, model, base_url=None):
    return types.SimpleNamespace(
        phase=phase, model=model, provider_name="anthropic",
        adapter=_FakeAdapter(), base_url=base_url,
    )


def test_fingerprint_for_binding_reads_adapter_name():
    fp = bi.fingerprint_for_binding(_binding("analyze", "opus"), ["SYS", "USR"])
    assert fp["adapter_type"] == "anthropic"
    assert fp["model"] == "opus"
    assert fp["phase"] == "analyze"


def test_verify_fold_resets_stale_verify_checkpoints(tmp_path):
    """The demonstrated finding-1 corruption: verify adopts a stale checkpoint
    and overwrites the fresh Stage-1 verdict. Closed by folding the producing
    analyze run's fingerprint into verify's KEY — an analyze-model swap changes
    ``analyze_fingerprint``, so the verify checkpoints written against analyze
    run A are NOT adopted once results.json carries analyze run B.
    """
    cp = StepCheckpoint("Verify", str(tmp_path))
    cp.dir = os.path.join(str(tmp_path), "verify_checkpoints")  # the :88 override

    vbind = _binding("verify", "verify-model")
    tmpl = ["VERIFY-SYS"]

    # First run: analyze produced fingerprint A. Verify stamps + writes a unit.
    fp_a = bi.fingerprint_for_binding(
        vbind, tmpl, extra_key={"analyze_fingerprint": "ANALYZE-A"})
    r1 = cp.sync_identity(fp_a)
    assert r1["status"] == "new"
    cp.save("file.py:func", {"verification": {"correct_finding": "safe"},
                             "finding": "safe"})

    # Second run: analyze model swapped -> results.json now carries fingerprint B.
    fp_b = bi.fingerprint_for_binding(
        vbind, tmpl, extra_key={"analyze_fingerprint": "ANALYZE-B"})
    r2 = cp.sync_identity(fp_b)
    assert r2["status"] == "reset", "verify must NOT adopt across an analyze swap"
    assert r2["archived_to"] and os.path.isdir(r2["archived_to"])
    # Stale verify checkpoint preserved in the archive, gone from the live dir →
    # finding_verifier.py:624 can no longer overwrite the fresh verdict with it.
    assert cp.load() == {}
    assert any(f.startswith("file.py") or "file" in f
               for f in os.listdir(r2["archived_to"]))


def test_verify_fold_adopts_when_analyze_unchanged(tmp_path):
    """Same analyze fingerprint + same verify identity → adopt (no re-pay)."""
    cp = StepCheckpoint("Verify", str(tmp_path))
    cp.dir = os.path.join(str(tmp_path), "verify_checkpoints")
    vbind = _binding("verify", "verify-model")
    tmpl = ["VERIFY-SYS"]
    fp = bi.fingerprint_for_binding(
        vbind, tmpl, extra_key={"analyze_fingerprint": "ANALYZE-A"})
    cp.sync_identity(fp)
    cp.save("file.py:func", {"verification": {"correct_finding": "safe"}})
    r = cp.sync_identity(bi.fingerprint_for_binding(
        vbind, tmpl, extra_key={"analyze_fingerprint": "ANALYZE-A"}))
    assert r["status"] == "match"
    assert cp.count() == 1


# ---------------------------------------------------------------------------
# EDIT 1: config_base_url wired onto PhaseBinding + sanitized before the KEY
# ---------------------------------------------------------------------------

def test_base_url_discriminates_once_wired():
    a = bi.fingerprint_for_binding(
        _binding("analyze", "opus", base_url="https://gw-a/v1"), ["S", "U"])
    b = bi.fingerprint_for_binding(
        _binding("analyze", "opus", base_url="https://gw-b/v1"), ["S", "U"])
    assert a["config_base_url"] == "https://gw-a/v1"
    assert a["key_digest"] != b["key_digest"]


def test_base_url_same_same_digest():
    a = bi.fingerprint_for_binding(
        _binding("analyze", "opus", base_url="https://gw/v1"), ["S", "U"])
    b = bi.fingerprint_for_binding(
        _binding("analyze", "opus", base_url="https://gw/v1"), ["S", "U"])
    assert a["key_digest"] == b["key_digest"]


def test_none_base_url_digest_unchanged():
    """Default-config users keep base_url=None → digest identical to a raw
    build_fingerprint with config_base_url=None (zero spurious re-pay)."""
    wired = bi.fingerprint_for_binding(_binding("analyze", "opus"), ["S", "U"])
    raw = bi.build_fingerprint(
        phase="analyze", model="opus", provider_name="anthropic",
        adapter_type="anthropic", config_base_url=None,
        template_texts=["S", "U"])
    assert wired["key_digest"] == raw["key_digest"]


def test_base_url_credentials_never_persisted_to_sidecar(tmp_path):
    """The sidecar persists the raw KEY dict; a credential-bearing base_url must
    be sanitized (userinfo/query/fragment stripped) BEFORE it enters the KEY, so
    nothing secret ever hits disk."""
    cp = StepCheckpoint("analyze", str(tmp_path))
    fp = bi.fingerprint_for_binding(
        _binding("analyze", "opus",
                 base_url="https://user:pass@host/v1?api_key=SECRET#frag"),
        ["S", "U"])
    cp.sync_identity(fp)
    raw = open(os.path.join(cp.dir, FINGERPRINT_FILE)).read()
    for banned in ("user:pass", "SECRET", "api_key=", "#frag"):
        assert banned not in raw, f"{banned} leaked into the persisted sidecar"
    persisted = json.loads(raw)
    assert persisted["config_base_url"] == "https://host/v1"


# ---------------------------------------------------------------------------
# results.json preservation (_archive_stale_results)
# ---------------------------------------------------------------------------

def test_archive_stale_results_preserves_prior_report(tmp_path):
    from core.analyzer import _archive_stale_results
    results = os.path.join(str(tmp_path), "results.json")
    with open(results, "w") as fh:
        json.dump({"analyze_fingerprint": "OLD", "results": [1, 2, 3]}, fh)
    _archive_stale_results(str(tmp_path), "NEW")
    # Prior report preserved under its old fingerprint, not overwritten/deleted.
    assert not os.path.exists(results)
    archived = os.path.join(str(tmp_path), "results__OLD.json")
    assert os.path.isfile(archived)
    assert json.load(open(archived))["results"] == [1, 2, 3]


def test_archive_stale_results_noop_when_fingerprint_matches(tmp_path):
    from core.analyzer import _archive_stale_results
    results = os.path.join(str(tmp_path), "results.json")
    with open(results, "w") as fh:
        json.dump({"analyze_fingerprint": "SAME"}, fh)
    _archive_stale_results(str(tmp_path), "SAME")
    assert os.path.isfile(results)  # left in place — a resume, not a swap


def test_archive_stale_results_legacy_when_unstamped(tmp_path):
    from core.analyzer import _archive_stale_results
    results = os.path.join(str(tmp_path), "results.json")
    with open(results, "w") as fh:
        json.dump({"results": []}, fh)  # no analyze_fingerprint (pre-feature)
    _archive_stale_results(str(tmp_path), "NEW")
    assert os.path.isfile(os.path.join(str(tmp_path), "results__legacy.json"))


def test_archive_stale_results_uses_short_windows_safe_name(tmp_path):
    """EDIT 3: the full ``sha256:<hex>`` digest embeds a colon that breaks
    os.replace on Windows (OSError swallowed → the preservation silently fails).
    Use the same short form as _archive_dir: last ':'-segment, first 8 hex."""
    from core.analyzer import _archive_stale_results
    results = os.path.join(str(tmp_path), "results.json")
    old = "sha256:" + "a" * 64
    with open(results, "w") as fh:
        json.dump({"analyze_fingerprint": old, "results": [1]}, fh)
    _archive_stale_results(str(tmp_path), "sha256:" + "b" * 64)
    # No colon in any archived filename (Windows-safe), short 8-hex suffix.
    names = os.listdir(str(tmp_path))
    assert "results__aaaaaaaa.json" in names
    assert not any(":" in n for n in names)
    assert not os.path.exists(results)


def test_archive_stale_results_nonstring_stamp_does_not_crash(tmp_path):
    """A hand-corrupted non-string analyze_fingerprint must be treated as
    unstamped (→ results__legacy.json), never crash the best-effort archiver."""
    from core.analyzer import _archive_stale_results
    results = os.path.join(str(tmp_path), "results.json")
    with open(results, "w") as fh:
        json.dump({"analyze_fingerprint": 123, "results": ["x"]}, fh)
    _archive_stale_results(str(tmp_path), "NEW")  # must not raise
    assert os.path.isfile(os.path.join(str(tmp_path), "results__legacy.json"))


def test_archive_stale_results_never_clobbers_existing_archive(tmp_path):
    """Two distinct prior reports that map to the SAME archive name (an A->B->A
    config alternation, or two unstamped reports both -> results__legacy.json)
    must BOTH survive: the second appends -<n>, never overwriting the first."""
    from core.analyzer import _archive_stale_results
    d = str(tmp_path)
    results = os.path.join(d, "results.json")
    # First unstamped report -> results__legacy.json
    with open(results, "w") as fh:
        json.dump({"results": ["first"]}, fh)
    _archive_stale_results(d, "NEW")
    # A second, DIFFERENT unstamped report also wants results__legacy.json
    with open(results, "w") as fh:
        json.dump({"results": ["second"]}, fh)
    _archive_stale_results(d, "NEW")
    # Both preserved — neither clobbered.
    assert json.load(open(os.path.join(d, "results__legacy.json")))["results"] == ["first"]
    assert json.load(open(os.path.join(d, "results__legacy-1.json")))["results"] == ["second"]
