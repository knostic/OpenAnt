"""Measure whether OpenAnt actually detects vulnerabilities.

Every other test in this repository checks that the plumbing works. None of them
check the product's central claim. A SAST scanner can be well packaged,
deterministic, observable, correctly exit-coded — and still be a poor scanner. The
test count says nothing about recall.

This is the smallest harness that produces real numbers, and it is deliberately
NOT a pytest test: it costs money, needs a provider, and its output is a
measurement to be tracked over time rather than a pass/fail gate. Wire it into a
scheduled canary, not a merge gate.

## What it measures, and why the split matters

Stage 1 (detection) and Stage 2 (attacker simulation) are scored **separately**.
That separation is the whole point. The product's thesis is that Stage 2 raises
precision by discarding findings an attacker could not actually reach. If you only
score the final output you cannot distinguish:

* Stage 2 working — it removed Stage 1 false positives;  from
* Stage 2 failing — it removed Stage 1 TRUE positives.

Both look like "fewer findings". Only the first is the feature. So the harness
reports, for each stage, what it did to the true positives and to the traps.

## The fixture design

Six units: three remotely-reachable vulnerabilities, and three that are shaped to
LOOK alarming — a subprocess call, a sqlite call, an f-string — but are not
attacker-reachable. Clean code that trivially looks clean measures nothing; the
traps are where a scanner earns its precision claim.

Usage:
    python tests/efficacy/score.py --fixture webapp
    python tests/efficacy/score.py --fixture webapp --stage1-only   # cheaper
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


def load_ground_truth(fixture: str) -> dict:
    return json.loads((HERE / "fixtures" / fixture / "ground_truth.json").read_text())


def unit_key(unit_id: str) -> str:
    """Normalise a scanner unit id to the ground-truth key form.

    Ids are ``relative/path.ext:function``. Merged multi-language datasets may
    namespace a colliding id as ``lang::path:func`` — strip that, or a namespaced
    unit would silently score as "not found" and be counted a false negative
    against the scanner unfairly.
    """
    return unit_id.split("::", 1)[-1]


def run_scan(fixture_dir: Path, out_dir: Path, stage1_only: bool) -> dict:
    """Run a real scan. This spends money."""
    # --level all is REQUIRED, not an optimisation. The default (reachable)
    # filters unreachable units out before analysis, and the trap units in this
    # fixture are deliberately unreachable — they would never be offered to Stage
    # 1, then score as free true negatives. That would report a precision the
    # scanner never earned.
    #
    # Verification is opt-IN (--verify), so the default run IS stage-1-only.
    # Dynamic testing is likewise opt-in and stays off; it needs Docker and adds
    # cost without bearing on detection quality.
    cmd = [
        sys.executable, "-m", "openant.cli", "scan", str(fixture_dir),
        "--output", str(out_dir), "--level", "all", "--no-enhance", "--no-report",
    ]
    if not stage1_only:
        cmd.append("--verify")
    proc = subprocess.run(cmd, cwd=CORE, capture_output=True, text=True, timeout=3600)
    if proc.returncode not in (0, 1):  # 1 == vulnerabilities found
        raise SystemExit(f"scan failed ({proc.returncode}):\n{proc.stderr[-3000:]}")
    return {"returncode": proc.returncode, "stderr_tail": proc.stderr[-2000:]}


def collect_findings(out_dir: Path) -> tuple[dict, dict]:
    """Return (stage1_by_unit, stage2_by_unit).

    Stage 1 = what detection flagged. Stage 2 = what verification kept. A unit
    present in stage1 and absent from stage2 was SUPPRESSED by verification —
    which is the measurement that matters most and the one a final-output-only
    score cannot see.
    """
    def flagged_in(filename: str, field: str, positive: set[str]) -> dict[str, dict]:
        """Units the named artifact marks positive.

        Two bugs are being deliberately avoided here, both of which this harness
        originally had and both of which produced a confidently wrong number:

        1. **Read the specific artifact, not rglob("*.json").** Stage 1 writes
           results.json and Stage 2 writes results_verified.json, and BOTH carry
           `finding` and `verdict` keys. Globbing merged them, so the two stages
           were mathematically guaranteed to score identically and the
           verification-effect measurement — the entire reason to separate them —
           could never show anything.

        2. **Compare the VALUE, never the truthiness.** `finding` is the string
           "vulnerable" or "safe". `if entry.get("finding")` is true for BOTH,
           because "safe" is a non-empty string. That scored every correctly-
           cleared trap as a false alarm and reported precision 0.5 for a run that
           actually scored 1.0 — a harness bug masquerading as a product defect,
           in the direction that looks like diligence.
        """
        path = out_dir / filename
        if not path.is_file():
            return {}
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
        out: dict[str, dict] = {}
        for entry in (data.get("results") or []):
            if not isinstance(entry, dict):
                continue
            uid = unit_key(str(entry.get("unit_id") or entry.get("id") or ""))
            value = str(entry.get(field, "")).strip().upper()
            if uid and value in positive:
                out[uid] = entry
        return out

    stage1 = flagged_in("results.json", "finding", {"VULNERABLE"})
    stage2 = flagged_in("results_verified.json", "verdict", {"VULNERABLE", "EXPLOITABLE"})
    return stage1, stage2


def score(truth: dict, flagged: set[str], label: str) -> dict:
    """Confusion matrix for one stage against ground truth."""
    units = truth["units"]
    expected_vuln = {k for k, v in units.items() if v["vulnerable"]}
    expected_safe = {k for k, v in units.items() if not v["vulnerable"]}

    tp = sorted(expected_vuln & flagged)
    fn = sorted(expected_vuln - flagged)
    fp = sorted(expected_safe & flagged)
    tn = sorted(expected_safe - flagged)

    recall = len(tp) / len(expected_vuln) if expected_vuln else None
    precision = len(tp) / (len(tp) + len(fp)) if (tp or fp) else None
    return {
        "stage": label,
        "recall": recall, "precision": precision,
        "true_positives": tp, "false_negatives": fn,
        "false_positives": fp, "true_negatives": tn,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--fixture", default="webapp")
    ap.add_argument("--output", default=None)
    ap.add_argument("--stage1-only", action="store_true",
                    help="skip verification (cheaper; halves the LLM spend)")
    args = ap.parse_args()

    truth = load_ground_truth(args.fixture)
    fixture_dir = HERE / "fixtures" / args.fixture
    out_dir = Path(args.output) if args.output else HERE / "_runs" / args.fixture
    out_dir.mkdir(parents=True, exist_ok=True)

    meta = run_scan(fixture_dir, out_dir, args.stage1_only)
    stage1, stage2 = collect_findings(out_dir)

    report = {
        # A run manifest, not just a score. A number without the model, prompts and
        # code revision that produced it cannot be compared to next month's number,
        # and comparability is the entire reason to measure.
        "manifest": {
            "fixture": args.fixture,
            "fixture_version": truth.get("version"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "code_revision": subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=CORE, capture_output=True, text=True
            ).stdout.strip(),
            "scan_returncode": meta["returncode"],
            "stage1_only": args.stage1_only,
        },
        "stage1_detection": score(truth, set(stage1), "stage1_detection"),
    }

    if not args.stage1_only:
        report["stage2_verification"] = score(truth, set(stage2), "stage2_verification")
        # The product thesis, stated as a measurement: verification should remove
        # false positives and keep true positives. Anything it removed from the TP
        # set is the scanner losing a real vulnerability it had already found —
        # strictly worse than never finding it, because the cost was paid.
        s1, s2 = set(stage1), set(stage2)
        expected_vuln = {k for k, v in truth["units"].items() if v["vulnerable"]}
        report["verification_effect"] = {
            "true_positives_suppressed": sorted((s1 & expected_vuln) - s2),
            "false_positives_removed": sorted((s1 - expected_vuln) - s2),
            "verdict": None,  # filled below
        }
        eff = report["verification_effect"]
        eff["verdict"] = (
            "improves precision" if eff["false_positives_removed"] and not eff["true_positives_suppressed"]
            else "HARMFUL: suppressed true positives" if eff["true_positives_suppressed"]
            else "no measurable effect"
        )

    out = out_dir / "efficacy_report.json"
    out.write_text(json.dumps(report, indent=2))

    s1 = report["stage1_detection"]
    print(f"\n=== {args.fixture} (fixture v{truth.get('version')}) ===")
    print(f"Stage 1 detection : recall={s1['recall']} precision={s1['precision']}")
    if s1["false_negatives"]:
        print(f"  MISSED          : {', '.join(s1['false_negatives'])}")
    if s1["false_positives"]:
        print(f"  false alarms    : {', '.join(s1['false_positives'])}")
    if "stage2_verification" in report:
        s2r = report["stage2_verification"]
        print(f"Stage 2 verified  : recall={s2r['recall']} precision={s2r['precision']}")
        print(f"  effect          : {report['verification_effect']['verdict']}")
    print(f"\nreport: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
