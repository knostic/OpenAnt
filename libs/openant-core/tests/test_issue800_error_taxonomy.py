"""#800 end-to-end regression: a context-overflow 400 files under a
DISTINCT class from a transient 429 in ``_summary.json`` — the taxonomy
split at both classification sites (analyze + verify).

At the base, analyze and verify filed EVERY error under one hardcoded
``"api"`` bucket (``analyzer.py``'s and ``finding_verifier.py``'s
``_summary_callback``: ``_summary_error_breakdown["api"] = ... + 1``), so
the campaign's twelve permanent context-overflow 400s — deterministic
failures that re-error on every resume forever — were indistinguishable
in the artifact from the previous run's 4,894-error 402 storm. The two
demand opposite operator responses (never retry vs. retry later), which
is why the bucket name is the triage signal.

The fix: ``_summary_error_bucket`` (``utilities/context_enhancer.py``,
beside ``_build_error_info`` — the error-taxonomy home) classifies by the
campaign's executed message shapes plus the adapter's own structured
taxonomy, and BOTH callbacks file under its bucket:

* ``context_overflow`` — the permanent token-ceiling 400s: "prompt is
  too long" (Bedrock's wording), "maximum context length" (the
  unattributed shape), ``context_length_exceeded`` (Anthropic's literal);
* ``payload_too_large`` — the permanent byte-size 400s ("total text
  input size exceeds 8 MB");
* ``rate_limit`` — the transient 429s (the adapter's LLMRateLimitError
  via ``error_info["type"]``, or the string shapes);
* ``payment_required`` — the 402 billing class;
* ``api`` — the fallback (the legacy name; backwards-compatible).

The cap half of the issue (capping the analyze projection) is #721's own
territory and deliberately NOT absorbed here — this is the honesty fix.

Shapes:

  S1 -- the WITNESS (red at base): the analyze leg, driven end-to-end
        through the REAL run_analysis + StepCheckpoint (the #663
        pattern: _run_detection monkeypatched to return the campaign's
        error shapes) — the _summary.json's error_breakdown carries
        context_overflow DISTINCT from rate_limit (both "api" at base).
  S2 -- the WITNESS (red at base): the verify leg, driven through the
        REAL verify_batch + checkpoint (_verify_one monkeypatched to the
        error detail) — the same split on the sibling site.
  S3 -- the classifier's unit contract (the DECLARED ABSENCE at base:
        the classifier is NEW at this head — the lazy import fails on
        the base tree, recorded in the manifest's
        witnesses_not_declared_but_red; the >=1-assertion-red floor is
        carried by S1/S2): every campaign shape maps to its bucket; an
        unclassified error keeps the legacy "api" name; the payload,
        quota and 402 classes distinct; the structured routes work.
  S4 -- the WITNESS (red at base): the mixed-class retry — a 429 filed,
        retried, landing context_overflow; the first attempt's bucket is
        RETIRED (pop-at-zero) and the residual class re-filed, with
        sum(breakdown) == errors held through the pass.
  S5 -- the WITNESS (red at base): the REAL _verify_one quota drive —
        LLMRateLimitError(kind="quota") through the real path, the
        error_info stash fires, {'quota': 1}.
  S6 -- the r4-F1 REGRESSION LOCK (green at base AND head BY DESIGN): the
        DICT-typed error (the parse-failure producer's shape) through the
        REAL call sites — no crash, the phase completes, {'api': 1};
        its unit half carries the dict-shape contract, the r5-F3
        parse-position twins (a column-429/402 message files 'api') and
        the r5-F4 typed-throttle TPM shape.
"""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# The prod files under test (the real Python import route).
_PROD_HUNK_ANALYZER = "core/analyzer.py"
_PROD_HUNK_VERIFIER = "utilities/finding_verifier.py"


# ---------------------------------------------------------------------------
# S3 — the classifier's unit contract (the control: green at base AND head
# for the unclassified fallback; the shape assertions are the contract the
# witnesses depend on)
# ---------------------------------------------------------------------------

def test_the_classifier_contract():
    """S3: every campaign shape maps to its bucket — the two
    context-overflow wordings, the payload shape, the 429s (string +
    structured), the 402 — and an unclassified error keeps the legacy
    'api' name (backwards-compatible: the old consumers of the
    breakdown key see 'api' only for the unnamed class).
    The import is lazy: the classifier is NEW at this head, so the
    module-level import would make this node a base-run collection error
    (the #602-family convention); at base this node is the declared
    absence — see the manifest's witnesses_not_declared_but_red."""
    from utilities.context_enhancer import _summary_error_bucket
    assert _summary_error_bucket(
        "Error: prompt is too long: 1044255 tokens > 1000000 maximum"
    ) == "context_overflow"
    assert _summary_error_bucket(
        "Error: This endpoint's maximum context length is 1000000 tokens. "
        "However, you requested about 1662458 tokens"
    ) == "context_overflow"
    assert _summary_error_bucket(
        "anthropic: context_length_exceeded: prompt too long"
    ) == "context_overflow"
    assert _summary_error_bucket(
        "Error: total text input size exceeds 8 MB"
    ) == "payload_too_large"
    assert _summary_error_bucket(
        "Error code: 429 - {'type': 'rate_limit_error'}",
        {"type": "rate_limit", "kind": "throttle"},
    ) == "rate_limit"
    assert _summary_error_bucket("Error code: 429") == "rate_limit"
    assert _summary_error_bucket(
        "LLMRateLimitError: too many requests", None) == "rate_limit"
    # r1-F2: the word-bounded codes — a 402 body carrying "42900
    # tokens" must NOT file as rate_limit (the #292 unanchored-substring
    # lesson); the verify path's class-name prefix consumed
    assert _summary_error_bucket(
        "LLMAuthError: Error code: 402 - {'message': 'You requested up "
        "to 42900 tokens, but can only afford 1500.'}", None) == \
        "payment_required"
    assert _summary_error_bucket(
        "LLMResponseError: Error code: 502 - upstream error; request_id "
        "req_01 4290ab", None) == "api"
    # r1-F3: Google's first-class overflow wording
    assert _summary_error_bucket(
        "400 INVALID_ARGUMENT. {'error': {'code': 400, 'message': "
        "'The input token count (1234567) exceeds the maximum number of "
        "input tokens allowed (1048576).'}}",
        {"type": "api_status", "status_code": 400}) == "context_overflow"
    # r1-F4: the #663/#790 throttle/quota split — a quota is a hard
    # entitlement limit, never "retry later"
    assert _summary_error_bucket(
        "Error code: 429 - per-day limit",
        {"type": "rate_limit", "kind": "quota"}) == "quota"
    assert _summary_error_bucket("Error code: 402") == "payment_required"
    # r2-F2: Anthropic's input+max_tokens band wording
    assert _summary_error_bucket(
        "Error code: 400 - {'message': 'input length and `max_tokens` "
        "exceed context limit: 196721 + 8192 > 200000, decrease input "
        "length or `max_tokens` and try again'}",
        {"type": "api_status", "status_code": 400}) == "context_overflow"
    # r2-F4: the leading error code wins over a bounded code elsewhere
    assert _summary_error_bucket(
        "LLMAuthError: Error code: 402 - You requested up to 8192 "
        "tokens, but can only afford 429.", None) == "payment_required"
    # r3-F2: a leading NON-429/402 code resolves by itself — a 400/5xx
    # body carrying a standalone 429 elsewhere must NOT file rate_limit
    assert _summary_error_bucket(
        "LLMResponseError: Error code: 400 - invalid parameter 'n': 429",
        None) == "api"
    assert _summary_error_bucket(
        "LLMResponseError: Error code: 500 - too many requests queued "
        "upstream", None) == "api"
    assert _summary_error_bucket(
        "Error: 402 payment required to access this API") == "payment_required"
    # the fallback: the legacy name survives for the unnamed class
    assert _summary_error_bucket("some other failure") == "api"
    assert _summary_error_bucket(None, None) == "api"
    # the structured route alone (no message)
    assert _summary_error_bucket(None, {"status_code": 402}) == \
        "payment_required"
    assert _summary_error_bucket(None, {"status_code": 429}) == "rate_limit"


# ---------------------------------------------------------------------------
# S1 — the analyze leg (the witness)
# ---------------------------------------------------------------------------

def test_the_analyze_summary_splits_the_classes(tmp_path, monkeypatch):
    """S1: a context-overflow 400 files under 'context_overflow' and a
    transient 429 under 'rate_limit' — DISTINCT classes in the analyze
    phase's _summary.json (both under the single 'api' bucket at the
    base). Driven end-to-end through the REAL run_analysis +
    StepCheckpoint: _run_detection returns the campaign's error shapes
    (the #663 pattern), the REAL _summary_callback files them, and the
    summary on disk carries the split."""
    from core import analyzer
    from utilities.llm_client import reset_warning_state

    reset_warning_state()
    dataset_path = tmp_path / "dataset.json"
    dataset_path.write_text(json.dumps({"units": [
        {"id": "f:overflow_bedrock", "code": "x=1"},
        {"id": "f:overflow_openai", "code": "x=1"},
        {"id": "f:storm429", "code": "x=1"},
        {"id": "f:other", "code": "x=1"},
    ]}))
    _errors = {
        "f:overflow_bedrock":
            ("Error: prompt is too long: 1044255 tokens > 1000000 maximum",
             {"type": "api_status", "status_code": 400}),
        "f:overflow_openai":
            ("Error: This endpoint's maximum context length is 1000000 "
             "tokens. However, you requested about 1662458 tokens",
             {"type": "api_status", "status_code": 400}),
        "f:storm429":
            ("Error code: 429 - {'type': 'rate_limit_error'}",
             {"type": "rate_limit", "kind": "throttle"}),
        "f:other":
            ("Error: something unnamed",
             {"type": "api_status", "status_code": 500}),
    }

    def fake_process_unit(binding, unit, i, json_corrector, app_context,
                          max_tokens=None):
        # the campaign's twelve residual shapes, reduced to their distinct
        # classes; the error material rides the result dict the REAL
        # call sites read (error + error_info on the inner result)
        uid = unit["id"]
        msg, info = _errors[uid]
        result = {"unit_id": uid, "verdict": "ERROR", "finding": "error",
                  "error": msg, "error_info": info}
        return {"index": i, "result": result, "route_key": uid,
                "code_for_route": "", "finding": "error", "elapsed": 0.1,
                "error": None, "worker": "w", "usage": {}}

    monkeypatch.setattr(analyzer, "_process_unit", fake_process_unit)
    monkeypatch.setattr(analyzer, "_analyze_fingerprint",
                        lambda binding, ctx_sha=None:
                        {"key_digest": "sha256:test"})
    from utilities.llm import PhaseBinding

    class _Adapter:
        name = "anthropic"
        supports_tools = True
        pricing = {}

    class _FakeRegistry:
        def get(self, phase):
            return PhaseBinding(phase=phase, adapter=_Adapter(),
                                model="m", provider_name="anthropic")

    # BOTH call sites drive the callback: the sequential loop AND the
    # parallel as_completed loop (the E1/E2 class — a witness that
    # drives only one mode leaves the other's wiring untested)
    for workers in (1, 2):
        run_dir = tmp_path / f"out_w{workers}"
        analyzer.run_analysis(str(dataset_path), str(run_dir),
                              registry=_FakeRegistry(), workers=workers)
        reset_warning_state()
        summary = json.loads(
            (run_dir / "analyze_checkpoints" / "_summary.json").read_text())
        breakdown = summary.get("error_breakdown", {})
        # THE FALSIFIER: the context-overflow class DISTINCT from the 429
        assert breakdown.get("context_overflow") == 2, breakdown
        assert breakdown.get("rate_limit") == 1, breakdown
        assert breakdown.get("api") == 1, breakdown
        assert "api" in breakdown, (
            "the legacy name survives for the unnamed class")


# ---------------------------------------------------------------------------
# S2 — the verify leg (the witness)
# ---------------------------------------------------------------------------

def test_the_verify_summary_splits_the_classes(tmp_path, monkeypatch):
    """S2: the same split on the SIBLING classification site — the
    verify phase's _summary_callback (its own copy of the hardcoded
    'api' line at the base). Driven through the REAL verify_batch +
    StepCheckpoint: _verify_one monkeypatched to the error detail, the
    error material on the results (the #286 convention: the adapter-raise
    string on the result dict), the summary on disk carries the split."""
    from core.checkpoint import StepCheckpoint
    from utilities.finding_verifier import FindingVerifier
    from utilities.llm import PhaseBinding

    class _Adapter:
        name = "anthropic"
        supports_tools = True
        pricing = {}

    results = [
        {"unit_id": "v:overflow", "route_key": "v:overflow", "finding":
         "vulnerable", "error": "Error: prompt is too long: 1044255 "
         "tokens > 1000000 maximum"},
        {"unit_id": "v:storm429", "route_key": "v:storm429", "finding":
         "vulnerable", "error": "Error code: 429 - rate limit"},
    ]

    def fake_verify_one(self, result, code_by_route):
        result = result  # the result dict is the error carrier
        return (result.get("route_key", "unknown"), "error", 0.1, "w", {})

    monkeypatch.setattr(FindingVerifier, "_verify_one", fake_verify_one)

    class _Tracker:
        def get_unit_usage(self):
            return {"input_tokens": 1, "output_tokens": 1, "cost_usd": 0.0}

    verifier = FindingVerifier(
        index={}, binding=PhaseBinding(phase="verify", adapter=_Adapter(),
                                       model="m", provider_name="anthropic"),
        tracker=_Tracker(), verbose=False, app_context=None)
    # BOTH call sites: the sequential loop AND the parallel executor
    # loop (the E1/E2 class)
    for workers in (1, 2):
        run_dir = tmp_path / f"v_w{workers}"
        run_dir.mkdir()
        ckpt = StepCheckpoint("Verify", str(run_dir))
        verifier.verify_batch(
            [dict(r) for r in results], {}, progress_callback=None,
            workers=workers, checkpoint=ckpt)
        summary = json.loads(
            (run_dir / "Verify_checkpoints" / "_summary.json").read_text())
        breakdown = summary.get("error_breakdown", {})
        assert breakdown.get("context_overflow") == 1, breakdown
        assert breakdown.get("rate_limit") == 1, breakdown
        assert "api" not in breakdown or breakdown.get("api") == 0, breakdown


# ---------------------------------------------------------------------------
# S4 — r1-F1: the mixed-class retry (the storm-then-overflow pattern)
# ---------------------------------------------------------------------------

def test_the_retry_pass_files_the_residual_class(tmp_path, monkeypatch):
    """S4 (the r1-F1 catch): the FIRST-ATTEMPT class must retire with the
    first attempt. The issue's own pattern: run 2's 402 storm MASKED the
    overflow ("the other three were masked by run 2's 402 storm and
    surfaced as overflow in run 3") — in one run, a 429 first attempt
    (retryable -> the real retry pass fires) whose retry surfaces the
    permanent context-overflow 400 must file as context_overflow, the
    RESIDUAL class the operator needs — never as the transient
    first-attempt rate_limit. At the base both attempts filed "api" (no
    distinction); the pre-remediation head mislabeled the residual as
    rate_limit. Also pins the retire-on-success half: a retry that
    succeeds decrements BOTH the error count and its bucket."""
    from core import analyzer
    from utilities.llm_client import reset_warning_state

    reset_warning_state()
    dataset_path = tmp_path / "dataset.json"
    dataset_path.write_text(json.dumps({"units": [
        {"id": "f:storm_then_overflow", "code": "x=1"},
        {"id": "f:storm_then_safe", "code": "x=1"},
    ]}))

    # attempt 1: both units a retryable 429; the retry pass then fires
    # (rate_limiter.wait_if_needed monkeypatched to no-op)
    _attempts = {}

    def fake_process_unit(binding, unit, i, json_corrector, app_context,
                          max_tokens=None):
        uid = unit["id"]
        n = _attempts.get(uid, 0)
        _attempts[uid] = n + 1
        if n == 0:
            msg = "Error code: 429 - rate limit"
            info = {"type": "rate_limit", "kind": "throttle"}
        elif uid == "f:storm_then_overflow":
            # the retry surfaces the PERMANENT class (the issue's own
            # masked-by-the-storm pattern, in one run)
            msg = "Error: prompt is too long: 1044255 tokens > 1000000 maximum"
            info = {"type": "api_status", "status_code": 400}
        else:
            # the retry succeeds
            return {"index": i,
                    "result": {"unit_id": uid, "finding": "safe",
                               "verdict": "SAFE", "confidence": 90},
                    "route_key": uid, "code_for_route": "",
                    "finding": "safe", "elapsed": 0.1, "error": None,
                    "worker": "w", "usage": {}}
        result = {"unit_id": uid, "verdict": "ERROR", "finding": "error",
                  "error": msg, "error_info": info}
        return {"index": i, "result": result, "route_key": uid,
                "code_for_route": "", "finding": "error", "elapsed": 0.1,
                "error": None, "worker": "w", "usage": {}}

    monkeypatch.setattr(analyzer, "_process_unit", fake_process_unit)
    monkeypatch.setattr(analyzer, "_analyze_fingerprint",
                        lambda binding, ctx_sha=None:
                        {"key_digest": "sha256:test"})
    from utilities.rate_limiter import GlobalRateLimiter
    monkeypatch.setattr(GlobalRateLimiter, "wait_if_needed",
                        lambda self: None)
    from utilities.llm import PhaseBinding

    class _Adapter:
        name = "anthropic"
        supports_tools = True
        pricing = {}

    class _FakeRegistry:
        def get(self, phase):
            return PhaseBinding(phase=phase, adapter=_Adapter(),
                                model="m", provider_name="anthropic")

    run_dir = tmp_path / "out"
    analyzer.run_analysis(str(dataset_path), str(run_dir),
                          registry=_FakeRegistry(), workers=1)
    reset_warning_state()

    summary = json.loads(
        (run_dir / "analyze_checkpoints" / "_summary.json").read_text())
    breakdown = summary.get("error_breakdown", {})
    # THE RESIDUAL CLASS: the overflow 400 on retry — NOT the 429 the
    # first attempt filed (the falsifier's in-run violation at the
    # pre-remediation head: breakdown was {'rate_limit': 2})
    assert breakdown.get("context_overflow") == 1, breakdown
    assert "rate_limit" not in breakdown, (
        f"the first-attempt 429 must RETIRE with the first attempt — the "
        f"residual error is the retry's class, and a zeroed key drops "
        f"(the enhance precedent): {breakdown}")
    # the retire-on-success half: the storm_then_safe unit left BOTH the
    # error count and its bucket
    assert summary.get("errors") == 1, summary
    total_bucketed = sum(breakdown.values())
    assert total_bucketed == summary["errors"], (
        f"sum(breakdown) must equal errors after the retry pass: "
        f"{breakdown} vs errors={summary.get('errors')}")


# ---------------------------------------------------------------------------
# S5 — r2-F1: the REAL _verify_one stash (the verify-path quota leg)
# ---------------------------------------------------------------------------

def test_the_verify_quota_files_through_the_real_path(tmp_path, monkeypatch):
    """S5 (the r2-F1 catch): the verify-path error_info stash is
    BEHAVIORAL, not defense-in-depth — the #663/#790 throttle/quota KIND
    split is unreachable on the verify leg without it (the string arm
    cannot see error_info.kind: 'LLMRateLimitError: Error code: 429 -
    per-day limit' classifies as rate_limit, telling the operator 'retry
    later' for a class the retry gate refuses). Drives the REAL
    _verify_one — the adapter raises LLMRateLimitError(kind='quota'), the
    exception handler stashes _build_error_info(e), the callback files
    the structured route — and the summary carries {'quota': 1}."""
    from core.checkpoint import StepCheckpoint
    from utilities.finding_verifier import FindingVerifier
    from utilities.llm import PhaseBinding, LLMRateLimitError
    from utilities.llm_client import reset_warning_state

    reset_warning_state()

    class _Adapter:
        name = "anthropic"
        supports_tools = True
        pricing = {}

        def complete(self, **kw):
            raise LLMRateLimitError(
                "Error code: 429 - per-day limit reached",
                retry_after=0.0, kind="quota")

        def validate(self, model):
            pass

    class _Tracker:
        def start_unit_tracking(self):
            pass

        def get_unit_usage(self):
            return {"input_tokens": 1, "output_tokens": 1, "cost_usd": 0.0}

    run_dir = tmp_path / "v_quota"
    run_dir.mkdir()
    ckpt = StepCheckpoint("Verify", str(run_dir))
    verifier = FindingVerifier(
        index={}, binding=PhaseBinding(phase="verify", adapter=_Adapter(),
                                      model="m", provider_name="anthropic"),
        tracker=_Tracker(), verbose=False, app_context=None)
    results = [{"unit_id": "v:quota", "route_key": "v:quota",
                "finding": "vulnerable",
                "code": {"primary_code": "def f(): pass"},
                "vulnerabilities": [{"description": "d"}]}]
    verifier.verify_batch(results, {"v:quota": "def f(): pass"},
                          progress_callback=None, workers=1, checkpoint=ckpt)
    reset_warning_state()

    summary = json.loads(
        (run_dir / "Verify_checkpoints" / "_summary.json").read_text())
    breakdown = summary.get("error_breakdown", {})
    assert breakdown.get("quota") == 1, (
        f"the verify-path quota must file through the STRUCTURED route "
        f"(the stash); the string arm cannot see error_info.kind and "
        f"would file rate_limit (the r2-F1 catch): {breakdown}")




# ---------------------------------------------------------------------------
# S6 — r4-F1: the dict-typed error (the parse_error producer's shape)
# ---------------------------------------------------------------------------

def test_the_dict_typed_error_never_crashes_the_phase(tmp_path, monkeypatch):
    """S6 (the r4-F1 catch — a REGRESSION LOCK, green at base AND head by
    design): the analyze producer emits a DICT error for the
    unparseable-response class (analysis_core.py: "error": {"type":
    "parse_error", "message": ...} — the repo's own established shape;
    rate_limiter dispatches on dict-vs-str for exactly this producer).
    The pre-remediation head CRASHED the whole phase on it
    (AttributeError in the classifier, the summary left
    phase=in_progress, the retry pass that exists for this very class
    never ran); the base completed fine (the old callback never touched
    the error material). The lock: the dict shape files under the
    legacy 'api' class (backwards-compatible with the base's bucket for
    the parse errors) and the phase COMPLETES."""
    from core import analyzer
    from utilities.llm_client import reset_warning_state

    reset_warning_state()
    dataset_path = tmp_path / "dataset.json"
    dataset_path.write_text(json.dumps({"units": [
        {"id": "f:parsefail", "code": "x=1"},
    ]}))

    def fake_process_unit(binding, unit, i, json_corrector, app_context,
                          max_tokens=None):
        # the REAL dict-typed error shape the parse-failure producer emits
        result = {"unit_id": "f:parsefail", "verdict": "ERROR",
                  "finding": "error",
                  "error": {"type": "parse_error",
                            "message": "LLM returned unparseable content"},
                  "error_info": None}
        return {"index": i, "result": result, "route_key": "f:parsefail",
                "code_for_route": "", "finding": "error", "elapsed": 0.1,
                "error": None, "worker": "w", "usage": {}}

    monkeypatch.setattr(analyzer, "_process_unit", fake_process_unit)
    monkeypatch.setattr(analyzer, "_analyze_fingerprint",
                        lambda binding, ctx_sha=None:
                        {"key_digest": "sha256:test"})
    from utilities.llm import PhaseBinding

    class _Adapter:
        name = "anthropic"
        supports_tools = True
        pricing = {}

    class _FakeRegistry:
        def get(self, phase):
            return PhaseBinding(phase=phase, adapter=_Adapter(),
                                model="m", provider_name="anthropic")

    run_dir = tmp_path / "out"
    # MUST NOT RAISE (the pre-remediation head: AttributeError 'dict'
    # object has no attribute 'lower', the phase aborted)
    analyzer.run_analysis(str(dataset_path), str(run_dir),
                          registry=_FakeRegistry(), workers=1)
    reset_warning_state()

    summary = json.loads(
        (run_dir / "analyze_checkpoints" / "_summary.json").read_text())
    assert summary.get("errors") == 1, summary
    assert summary.get("error_breakdown") == {"api": 1}, (
        f"the dict-typed parse error files under the legacy class "
        f"(backwards-compatible): {summary.get('error_breakdown')}")


def test_the_classifier_accepts_the_dict_shape():
    """S6's unit half: the dict error message feeds the string arm and
    the dict itself serves as the structured error_info when none was
    passed (a rate_limit-kind-quota DICT files 'quota' — the same
    contract the string+info pair carries)."""
    from utilities.context_enhancer import _summary_error_bucket
    assert _summary_error_bucket(
        {"type": "parse_error", "message": "LLM returned unparseable"}
    ) == "api"
    assert _summary_error_bucket(
        {"type": "rate_limit", "kind": "quota", "message": "per-day cap"}
    ) == "quota"
    # R4-F2: the leading code right-bounded
    assert _summary_error_bucket("Error code: 4290 - foo") == "api"
    # R5-F3: a parse_error's message can embed a bare 3-digit number (a
    # JSONDecodeError position: "line 1 column 429 (char 428)") — the
    # parse failure is a PERMANENT producer fault and must NEVER file
    # under a transient class via the word-bounded code scan; the
    # structured dict NAMES its class, so the type is decisive.
    assert _summary_error_bucket(
        {"type": "parse_error",
         "message": "Expecting ',' delimiter: line 1 column 429 (char 428)"}
    ) == "api"
    assert _summary_error_bucket(
        {"type": "parse_error",
         "message": "Expecting value: line 1 column 402 (char 401)"}
    ) == "api"
    # R5-F4: a TYPED rate_limit (the adapter's own taxonomy) wins over the
    # payload-size signature — OpenAI's single-request-over-TPM 429 says
    # "Request too large for gpt-4o ... on tokens per min (TPM)" but the
    # retry gate retries it (the r1-F4 consistency: the breakdown must
    # agree with what the retry pass will do).
    assert _summary_error_bucket(
        "Request too large for gpt-4o on tokens per min (TPM): "
        "Limit 30000, Requested 46000",
        {"type": "rate_limit", "kind": "throttle"},
    ) == "rate_limit"
