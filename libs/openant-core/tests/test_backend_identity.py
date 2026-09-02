"""Tests for the minimal I2 backend-identity adopt gate.

Covers the KEY fingerprint (core/backend_identity.py) and the
StepCheckpoint.sync_identity gate (core/checkpoint.py), including the
FAIL-CLOSED-on-corruption requirement (a corrupt sidecar must archive-and-
re-run, never adopt) and the results.json / preserve-not-destroy behaviour.
"""

import json
import os


from core import backend_identity as bi
from core.checkpoint import StepCheckpoint, _RESERVED_FILES, FINGERPRINT_FILE


# ---------------------------------------------------------------------------
# build_fingerprint / KEY
# ---------------------------------------------------------------------------

def _fp(**over):
    base = dict(
        phase="analyze",
        model="opus",
        provider_name="anthropic",
        adapter_type="anthropic",
        config_base_url=None,
        template_texts=["SYSTEM", "USER"],
    )
    base.update(over)
    return bi.build_fingerprint(**base)


def test_key_has_expected_fields_and_no_secrets():
    fp = _fp()
    for field in ("scheme_version", "phase", "model", "provider_name",
                  "adapter_type", "config_base_url", "templates_sha",
                  "key_digest"):
        assert field in fp, f"missing {field}"
    # No detection / endpoint / api_key leakage (explicitly excluded, minimal).
    blob = json.dumps(fp)
    for banned in ("detection", "effective_endpoint", "api_key", "endpoint",
                   "drift_log"):
        assert banned not in blob, f"{banned} must not be in the fingerprint"
    assert fp["key_digest"].startswith("sha256:")


def test_model_swap_changes_digest():
    assert _fp(model="opus")["key_digest"] != _fp(model="haiku")["key_digest"]


def test_provider_and_adapter_swap_change_digest():
    assert _fp(provider_name="a")["key_digest"] != _fp(provider_name="b")["key_digest"]
    assert _fp(adapter_type="anthropic")["key_digest"] != _fp(adapter_type="openai")["key_digest"]


def test_template_edit_changes_digest():
    # This is the user-prompt / system-prompt digest sensitivity (both folded
    # into templates_sha).
    assert _fp(template_texts=["SYSTEM", "USER"])["key_digest"] != \
        _fp(template_texts=["SYSTEM", "USER-EDITED"])["key_digest"]


def test_extra_key_folds_into_digest():
    a = _fp(extra_key={"analyze_fingerprint": "AAA"})
    b = _fp(extra_key={"analyze_fingerprint": "BBB"})
    assert a["key_digest"] != b["key_digest"]
    assert a["key_digest"] != _fp()["key_digest"]


def test_scheme_version_folds_into_digest(monkeypatch):
    d1 = _fp()["key_digest"]
    monkeypatch.setattr(bi, "FINGERPRINT_SCHEME_VERSION", 999)
    assert _fp()["key_digest"] != d1


def test_render_or_sentinel_failsafe():
    def boom():
        raise RuntimeError("cannot render")
    texts = bi.render_template_texts([lambda: "ok", boom])
    assert texts[0] == "ok"
    assert texts[1] == bi.UNRENDERABLE_SENTINEL
    # A sentinelled render must differ from the real one → forces re-run.
    assert _fp(template_texts=["ok", "ok"])["key_digest"] != \
        _fp(template_texts=["ok", bi.UNRENDERABLE_SENTINEL])["key_digest"]


# ---------------------------------------------------------------------------
# EDIT 1: config_base_url sanitizer
# ---------------------------------------------------------------------------

def test_sanitize_base_url_strips_userinfo_query_fragment():
    s = bi._sanitize_base_url("https://user:pass@host:8443/v1?api_key=SECRET#frag")
    assert s == "https://host:8443/v1"
    for banned in ("user", "pass", "SECRET", "frag", "@", "?", "#"):
        assert banned not in s


def test_sanitize_base_url_none_passthrough():
    assert bi._sanitize_base_url(None) is None


def test_sanitize_base_url_plain_unchanged():
    assert bi._sanitize_base_url("https://api.example.com/v1") == \
        "https://api.example.com/v1"


def test_sanitize_base_url_ipv6_rebracketed():
    # urlsplit's .hostname drops the [] form; we must re-bracket so the netloc
    # is well-formed AND userinfo is still dropped.
    s = bi._sanitize_base_url("https://user:pass@[::1]:8080/v1")
    assert s == "https://[::1]:8080/v1"
    assert "user" not in s and "pass" not in s


def test_sanitize_base_url_path_secret_is_named_residual():
    # DOCUMENTED residual: a credential embedded in the PATH is NOT stripped
    # (the path is load-bearing for discrimination). This test pins the residual
    # so the docstring stays honest — it is NOT a claim that path secrets are safe.
    s = bi._sanitize_base_url("https://gw.example/tok/sk-SECRET/v1")
    assert "sk-SECRET" in s  # path preserved verbatim (named residual)


def test_sanitize_base_url_invalid_port_forgoes_not_crashes():
    # p.port PARSES the port and raises ValueError on a bad one; the guard must
    # catch it and return None (forego discrimination), never crash the scan.
    assert bi._sanitize_base_url("https://host:99999/v1") is None
    assert bi._sanitize_base_url("https://host:notaport/v1") is None


# ---------------------------------------------------------------------------
# sync_identity gate
# ---------------------------------------------------------------------------

def _cp(tmp_path):
    cp = StepCheckpoint("analyze", str(tmp_path))
    return cp


def test_status_new_when_empty(tmp_path):
    cp = _cp(tmp_path)
    res = cp.sync_identity(_fp())
    assert res["status"] == "new"
    assert os.path.isfile(os.path.join(cp.dir, FINGERPRINT_FILE))


def test_status_match_adopts(tmp_path):
    cp = _cp(tmp_path)
    cp.save("u1", {"result": {"finding": "vulnerable"}})
    cp.sync_identity(_fp())  # stamp
    res = cp.sync_identity(_fp())  # same identity again
    assert res["status"] == "match"
    assert cp.count() == 1  # unit preserved, adopted


def test_status_legacy_adopts_when_units_but_no_sidecar(tmp_path):
    cp = _cp(tmp_path)
    cp.save("u1", {"result": {"finding": "vulnerable"}})
    # No sidecar yet.
    res = cp.sync_identity(_fp())
    assert res["status"] == "legacy"
    assert cp.count() == 1  # adopted, not archived
    assert os.path.isfile(os.path.join(cp.dir, FINGERPRINT_FILE))


def test_status_reset_archives_on_identity_change(tmp_path):
    cp = _cp(tmp_path)
    cp.save("u1", {"result": {"finding": "vulnerable"}})
    cp.sync_identity(_fp(model="opus"))  # stamp opus
    res = cp.sync_identity(_fp(model="haiku"))  # backend swap
    assert res["status"] == "reset"
    assert res["archived_to"] and os.path.isdir(res["archived_to"])
    # Old unit preserved in the archive, NOT destroyed.
    assert any(f.startswith("u1") for f in os.listdir(res["archived_to"]))
    # Fresh dir has the new sidecar and no adopted units.
    assert cp.count() == 0
    assert os.path.isfile(os.path.join(cp.dir, FINGERPRINT_FILE))


def test_fail_closed_on_corrupt_sidecar(tmp_path):
    """CRITICAL: a corrupt / unreadable sidecar must RESET (archive + re-run),
    never adopt the stale checkpoints."""
    cp = _cp(tmp_path)
    cp.save("u1", {"result": {"finding": "vulnerable"}})
    # Write a corrupt sidecar.
    with open(os.path.join(cp.dir, FINGERPRINT_FILE), "w") as fh:
        fh.write("{ this is not json ")
    res = cp.sync_identity(_fp())
    assert res["status"] == "reset", "corrupt sidecar must fail CLOSED (reset)"
    assert res["archived_to"] and os.path.isdir(res["archived_to"])
    assert cp.count() == 0  # stale units NOT adopted
    assert any(f.startswith("u1") for f in os.listdir(res["archived_to"]))


def test_reserved_files_excluded_from_counters(tmp_path):
    cp = _cp(tmp_path)
    cp.save("u1", {"result": {"finding": "vulnerable"}})
    cp.sync_identity(_fp())  # writes _fingerprint.json
    assert FINGERPRINT_FILE in _RESERVED_FILES
    assert cp.count() == 1  # sidecar not counted
    assert cp.exists is True
    st = StepCheckpoint.status(cp.dir)
    assert st["total_files"] == 1  # sidecar excluded from status counter
