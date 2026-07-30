"""Pipeline smoke test: does a real scan flag the planted vulns and clear the traps?

This is NOT an efficacy benchmark and produces NO recall/precision number. Six
textbook units on one blinded fixture cannot support a recall, precision, or
external-validity claim, and an earlier version of this file did exactly that —
it reported ``recall=1.0`` against a fixture whose docstrings literally captioned
each unit ``VULN`` / ``NOT A VULN``, so the "measurement" only proved a model can
read an English label. Those captions are gone (the fixture is blinded; the
expected outcomes live only in the sidecar oracle ``oracles/<fixture>.json``,
which is kept OUTSIDE the scanned fixture directory so the app-context survey
agent — which can list_dir and read_repo_file anything under the scanned tree —
cannot reach it. See ``oracle_path``.)

What remains is a SMOKE TEST with a binary contract:

    the pipeline must FLAG the three planted vulnerabilities, and
    the pipeline must CLEAR the three false-positive traps.

Pass/fail, per unit. Nothing is averaged into a headline number, because a number
from six hand-written units would invite exactly the over-claim this rewrite
removes.

It is deliberately NOT a pytest test: it costs money and needs a provider. Wire
it into a scheduled canary, not a merge gate. The PURE checking functions
(``read_results``, ``index_results``, ``evaluate``) take no provider and are unit
tested offline in ``tests/test_efficacy_score.py``.

## Why Stage 1 and Stage 2 are checked separately

Stage 1 (detection) and Stage 2 (attacker simulation) are evaluated separately so
a Stage-2 regression that suppresses a TRUE positive is distinguishable from
Stage 2 correctly removing a false positive — both look like "fewer findings",
only the first is the feature.

## Failure modes that are ERRORS, never a silent pass

* a missing ``results.json`` (the scan/pipeline failed) — NOT "zero recall";
* an expected unit absent from the results (the scan never analysed it —
  ``--level all`` is required so the unreachable traps are offered to Stage 1);
* the scanner flagging a unit the oracle does not cover (cannot be judged);
* a duplicate unit id in the results.

Each raises and exits non-zero, so a broken harness cannot masquerade as a
passing scan.

Usage:
    python tests/efficacy/score.py --fixture webapp                 # detection only
    python tests/efficacy/score.py --fixture webapp --verify        # + Stage 2
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE.parent.parent


class SmokeError(RuntimeError):
    """A harness/scan failure that must stop the smoke test, not score as 0."""


# --------------------------------------------------------------------------
# Pure functions — no provider, unit tested offline.
# --------------------------------------------------------------------------

def oracle_path(fixture: str) -> Path:
    """Location of the sidecar oracle — DELIBERATELY OUTSIDE the scanned tree.

    The oracle holds the answer key (``vulnerable: true`` per unit). It must not
    live under ``fixtures/<name>/`` (the directory the scanner walks): the
    app-context step's ``repo_explorer`` agent can ``list_dir`` and
    ``read_repo_file`` anything in the scanned tree, so an oracle placed there is
    reachable by the model even though it is not ``.py`` source. Keeping it in a
    sibling ``oracles/`` directory makes "never shown to the scanner" structural
    rather than a property of which file extensions the parser happens to skip.
    """
    return HERE / "oracles" / f"{fixture}.json"


def load_oracle(fixture: str) -> dict:
    """Load the sidecar oracle. It is never shown to the scanner."""
    return json.loads(oracle_path(fixture).read_text())


def unit_key(unit_id: str) -> str:
    """Normalise a scanner unit id to the oracle key form.

    Ids are ``relative/path.ext:function``. Merged multi-language datasets may
    namespace a colliding id as ``lang::path:func`` — strip that so a namespaced
    unit is not mistaken for an absent one.
    """
    return unit_id.split("::", 1)[-1]


def read_results(path: Path) -> list[dict]:
    """Read a results artifact's ``results`` list, or raise.

    A missing file is a scan/pipeline FAILURE, not an empty result set. The
    earlier harness returned ``{}`` here and let the confusion matrix report
    ``recall=0.0`` — a harness failure disguised as a product failure. This
    refuses instead.
    """
    if not path.is_file():
        raise SmokeError(
            f"results file missing: {path}. A missing results file means the scan "
            "or pipeline failed; that is an error, not zero recall."
        )
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        raise SmokeError(f"results file unreadable: {path}: {exc}") from exc
    results = data.get("results")
    if not isinstance(results, list):
        raise SmokeError(f"results file has no 'results' list: {path}")
    return results


def index_results(
    results: list[dict], field: str, positive: set[str]
) -> tuple[set[str], set[str]]:
    """Return ``(flagged_ids, all_ids)``; raise on a duplicate id.

    ``flagged_ids`` are the units whose ``field`` (``finding`` for Stage 1,
    ``verdict`` for Stage 2) is one of ``positive`` (compared by VALUE, upper-
    cased — never truthiness, because the string ``"safe"`` is truthy and once
    scored every cleared trap as a false alarm).
    """
    all_ids: set[str] = set()
    flagged: set[str] = set()
    for entry in results:
        if not isinstance(entry, dict):
            continue
        uid = unit_key(str(entry.get("unit_id") or entry.get("id") or ""))
        if not uid:
            continue
        if uid in all_ids:
            raise SmokeError(f"duplicate unit id in results: {uid}")
        all_ids.add(uid)
        if str(entry.get(field, "")).strip().upper() in positive:
            flagged.add(uid)
    return flagged, all_ids


def evaluate(oracle: dict, flagged: set[str], all_ids: set[str], stage: str) -> dict:
    """Binary smoke outcome for one stage against the sidecar oracle.

    Raises SmokeError if an expected unit is absent from the results, or the
    scanner flagged a unit the oracle does not cover — either makes the run
    unjudgeable and must not be silently smoothed into a pass.
    """
    units = oracle["units"]
    expected_vuln = {unit_key(k) for k, v in units.items() if v["vulnerable"]}
    expected_clean = {unit_key(k) for k, v in units.items() if not v["vulnerable"]}
    expected = expected_vuln | expected_clean

    absent = sorted(expected - all_ids)
    if absent:
        raise SmokeError(
            f"[{stage}] expected units absent from the results — the scan did not "
            f"analyse them (is --level all set, so the unreachable traps are "
            f"offered to Stage 1?): {absent}"
        )
    unknown = sorted(flagged - expected)
    if unknown:
        raise SmokeError(
            f"[{stage}] scanner flagged units the oracle does not cover, so the "
            f"result cannot be judged: {unknown}"
        )

    missed = sorted(expected_vuln - flagged)          # should flag, did not
    false_alarms = sorted(expected_clean & flagged)   # flagged a trap
    return {
        "stage": stage,
        "passed": not missed and not false_alarms,
        "flagged_vulns": sorted(expected_vuln & flagged),
        "missed_vulns": missed,
        "cleared_traps": sorted(expected_clean - flagged),
        "false_alarms": false_alarms,
    }


def verification_effect(stage1_flagged: set[str], stage2_flagged: set[str],
                        oracle: dict) -> dict:
    """What Stage 2 did to Stage 1's findings — the product thesis, as a check."""
    units = oracle["units"]
    expected_vuln = {unit_key(k) for k, v in units.items() if v["vulnerable"]}
    tp_suppressed = sorted((stage1_flagged & expected_vuln) - stage2_flagged)
    fp_removed = sorted((stage1_flagged - expected_vuln) - stage2_flagged)
    return {
        "true_positives_suppressed": tp_suppressed,
        "false_positives_removed": fp_removed,
        "verdict": (
            "HARMFUL: suppressed true positives" if tp_suppressed
            else "improves precision" if fp_removed
            else "no measurable effect on this fixture"
        ),
    }


# --------------------------------------------------------------------------
# The billed part.
# --------------------------------------------------------------------------

def run_scan(fixture_dir: Path, out_dir: Path, verify: bool) -> dict:
    """Run a real scan. This spends money."""
    # --level all is REQUIRED: the default (reachable) filters the unreachable
    # trap units out before analysis, so they would never be offered to Stage 1
    # and would score as free true negatives — a precision the scanner never
    # earned. --no-enhance/--no-report keep cost and noise down.
    cmd = [
        sys.executable, "-m", "openant.cli", "scan", str(fixture_dir),
        "--output", str(out_dir), "--level", "all", "--no-enhance", "--no-report",
    ]
    if verify:
        cmd.append("--verify")
    proc = subprocess.run(cmd, cwd=CORE, capture_output=True, text=True, timeout=3600)
    if proc.returncode not in (0, 1):  # 1 == vulnerabilities found
        raise SmokeError(f"scan failed ({proc.returncode}):\n{proc.stderr[-3000:]}")
    return {"returncode": proc.returncode}


def main() -> int:
    ap = argparse.ArgumentParser(description="Pipeline smoke test (not a benchmark).")
    ap.add_argument("--fixture", default="webapp")
    ap.add_argument("--output", default=None)
    ap.add_argument("--verify", action="store_true",
                    help="also run Stage 2 attacker simulation")
    args = ap.parse_args()

    oracle = load_oracle(args.fixture)
    fixture_dir = HERE / "fixtures" / args.fixture
    out_dir = Path(args.output) if args.output else HERE / "_runs" / args.fixture
    out_dir.mkdir(parents=True, exist_ok=True)

    meta = run_scan(fixture_dir, out_dir, args.verify)

    s1_flagged, s1_all = index_results(
        read_results(out_dir / "results.json"), "finding", {"VULNERABLE"})
    stage1 = evaluate(oracle, s1_flagged, s1_all, "stage1_detection")

    report = {
        "manifest": {
            "fixture": args.fixture,
            "fixture_version": oracle.get("version"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "code_revision": subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=CORE, capture_output=True, text=True
            ).stdout.strip(),
            "scan_returncode": meta["returncode"],
            "verify": args.verify,
        },
        "stage1_detection": stage1,
    }
    all_passed = stage1["passed"]

    if args.verify:
        s2_flagged, s2_all = index_results(
            read_results(out_dir / "results_verified.json"),
            "verdict", {"VULNERABLE", "EXPLOITABLE"})
        stage2 = evaluate(oracle, s2_flagged, s2_all, "stage2_verification")
        report["stage2_verification"] = stage2
        report["verification_effect"] = verification_effect(
            s1_flagged, s2_flagged, oracle)
        all_passed = all_passed and stage2["passed"]

    report["smoke_passed"] = all_passed
    out = out_dir / "smoke_report.json"
    out.write_text(json.dumps(report, indent=2))

    def line(r: dict) -> str:
        bits = [f"{r['stage']}: {'PASS' if r['passed'] else 'FAIL'}"]
        if r["missed_vulns"]:
            bits.append(f"MISSED {', '.join(r['missed_vulns'])}")
        if r["false_alarms"]:
            bits.append(f"FALSE ALARM {', '.join(r['false_alarms'])}")
        return " | ".join(bits)

    print(f"\n=== {args.fixture} smoke (fixture v{oracle.get('version')}) ===")
    print(line(stage1))
    if args.verify:
        print(line(report["stage2_verification"]))
        print(f"  verification effect: {report['verification_effect']['verdict']}")
    print(f"\nsmoke: {'PASS' if all_passed else 'FAIL'}   report: {out}")
    return 0 if all_passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SmokeError as exc:
        print(f"SMOKE ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
