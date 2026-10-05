#!/usr/bin/env python3
"""
run_patcheval_python_37.py -- local batch runner for the 37 PatchEval-Verified
Python expansion cases in cfp_evaluation_cases.yaml.

Evaluation tooling only. For each expansion case it clones the manifest repo,
checks out the exact manifest SHA, and invokes run_traced.py unchanged:

  python3.12 run_traced.py --cve <CVE> --repo-root <repo> --output <out> \
      --blind-evaluation --blind-strip-same-repo-github-references

It never interprets Auto Patcher results; it only records process exit status
and run_traced's own run_manifest.json `status` field.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

TOOLS_DIR = Path(__file__).resolve().parent
CORE_DIR = TOOLS_DIR.parents[2]  # libs/openant-core
RUN_TRACED = TOOLS_DIR / "run_traced.py"
DEFAULT_MANIFEST = TOOLS_DIR / "cfp_evaluation_cases.yaml"
FIRST_EXPANSION_ID = "opendiamond-cve-2022-31506"
EXPECTED_TOTAL = 43
EXPECTED_EXPANSION = 37
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
STATUSES = (
    "COMPLETED", "SKIPPED_ALREADY_COMPLETE", "CHECKOUT_FAILED",
    "RUN_FAILED", "INCOMPLETE_EXISTING_OUTPUT",
)


class ManifestError(Exception):
    pass


def load_expansion_cases(manifest_path: Path) -> list[dict]:
    try:
        data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ManifestError(f"manifest does not parse: {exc}") from exc
    cases = data.get("cases") if isinstance(data, dict) else None
    if not isinstance(cases, list):
        raise ManifestError("manifest has no `cases` list")
    if len(cases) != EXPECTED_TOTAL:
        raise ManifestError(f"expected {EXPECTED_TOTAL} cases, found {len(cases)}")
    for i, c in enumerate(cases):
        if not isinstance(c, dict):
            raise ManifestError(f"case #{i + 1} is not a mapping")
        for key in ("id", "repo", "cve", "sha"):
            if not isinstance(c.get(key), str) or not c[key]:
                raise ManifestError(f"case #{i + 1} missing string field {key!r}")
    ids = [c["id"] for c in cases]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise ManifestError(f"duplicate case ids: {dupes}")
    bad = [c["id"] for c in cases if not SHA_RE.fullmatch(c["sha"])]
    if bad:
        raise ManifestError(f"sha not 40 lowercase hex: {bad}")
    if FIRST_EXPANSION_ID not in ids:
        raise ManifestError(f"{FIRST_EXPANSION_ID} not found")
    selected = cases[ids.index(FIRST_EXPANSION_ID):]
    if len(selected) != EXPECTED_EXPANSION:
        raise ManifestError(
            f"expected {EXPECTED_EXPANSION} expansion cases, found {len(selected)}"
        )
    return selected


def git(*args, cwd=None, timeout=1800) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=timeout,
    )


def freeze_openant_revision(manifest_path: Path) -> tuple[str, str]:
    """Returns (HEAD, porcelain). Raises if anything other than the
    evaluation manifest, its backup, or this runner is modified/untracked."""
    top = git("rev-parse", "--show-toplevel", cwd=CORE_DIR).stdout.strip()
    head = git("rev-parse", "HEAD", cwd=top)
    porcelain = git("status", "--porcelain", "--untracked-files=all", cwd=top)
    if head.returncode or porcelain.returncode:
        raise ManifestError("cannot read OpenAnt git state")
    allowed = set()
    for p in (DEFAULT_MANIFEST, Path(str(DEFAULT_MANIFEST) + ".pre-sha-expansion.bak"),
              manifest_path, Path(__file__)):
        try:
            allowed.add(str(Path(p).resolve().relative_to(Path(top).resolve())))
        except ValueError:
            pass
    offending = [
        line for line in porcelain.stdout.splitlines()
        if line[3:].strip('"') not in allowed
    ]
    if offending:
        raise ManifestError(
            "OpenAnt working tree has modifications outside the evaluation "
            "manifest:\n  " + "\n  ".join(offending)
        )
    return head.stdout.strip(), porcelain.stdout


def run_completed_ok(out_dir: Path) -> bool:
    """Evidence of a normal run_traced completion: its own success manifest."""
    m = out_dir / "trace" / "run_manifest.json"
    try:
        return json.loads(m.read_text(encoding="utf-8")).get("status") == "success"
    except (OSError, ValueError, AttributeError):
        return False


def read_run_manifest_status(out_dir: Path):
    try:
        return json.loads(
            (out_dir / "trace" / "run_manifest.json").read_text(encoding="utf-8")
        ).get("status")
    except (OSError, ValueError, AttributeError):
        return None


def prepare_checkout(case: dict, repo_dir: Path) -> tuple[str | None, str]:
    """Returns (verified HEAD or None, detail). Never substitutes a revision;
    never deletes an existing directory."""
    sha = case["sha"]
    if repo_dir.exists():
        head = git("rev-parse", "HEAD", cwd=repo_dir).stdout.strip()
        origin = git("remote", "get-url", "origin", cwd=repo_dir).stdout.strip()
        dirty = git("status", "--porcelain", cwd=repo_dir).stdout.strip()
        if head == sha and origin == case["repo"] and not dirty:
            return head, "reused existing clean checkout"
        return None, (f"existing repo dir not reusable (HEAD={head or '?'}, "
                      f"origin={origin or '?'}, dirty={bool(dirty)}); left untouched")
    repo_dir.parent.mkdir(parents=True, exist_ok=True)
    p = git("clone", "--quiet", "--no-checkout", case["repo"], str(repo_dir))
    if p.returncode:
        return None, f"clone failed: {p.stderr.strip()}"
    p = git("-c", "advice.detachedHead=false", "checkout", "--quiet", "--detach",
            f"{sha}^{{commit}}", cwd=repo_dir)
    if p.returncode:
        return None, f"checkout failed: {p.stderr.strip()}"
    head = git("rev-parse", "HEAD", cwd=repo_dir).stdout.strip()
    if head != sha:
        return None, f"HEAD {head!r} != manifest sha"
    return head, "cloned and checked out"


def write_reports(results_root: Path, batch: dict) -> None:
    (results_root / "batch_manifest.json").write_text(
        json.dumps(batch, indent=2), encoding="utf-8")
    lines = [
        "# PatchEval-Verified Python expansion batch (37 cases)", "",
        f"- Started: {batch['evaluation_started_at']}",
        f"- Finished: {batch.get('evaluation_finished_at') or '(in progress)'}",
        f"- OpenAnt HEAD: `{batch['openant_head']}`",
        f"- Manifest: `{batch['manifest_path']}`", "",
        "| # | Case | CVE | Batch status | Exit | run_manifest status | Output |",
        "|---|---|---|---|---|---|---|",
    ]
    for i, c in enumerate(batch["cases"], 1):
        lines.append(
            f"| {i:02d} | {c['id']} | {c['cve']} | {c['batch_status']} | "
            f"{c['process_exit_status']} | {c['run_manifest_status']} | `{c['output_dir']}` |"
        )
    lines += ["", "## Counts", ""]
    lines += [f"- {s}: {batch['counts'][s]}" for s in STATUSES]
    (results_root / "BATCH_SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    ap.add_argument("--repos-root", type=Path, default=Path("/tmp/patcheval-python-37-repos"))
    ap.add_argument("--results-root", type=Path, default=Path("/tmp/patcheval-python-37-eval"))
    ap.add_argument("--python", default="python3.12")
    ap.add_argument("--validate-only", action="store_true",
                    help="Validate manifest + OpenAnt state, print the plan; run nothing.")
    args = ap.parse_args(argv)
    manifest_path = args.manifest.resolve()

    try:
        selected = load_expansion_cases(manifest_path)
        head, porcelain = freeze_openant_revision(manifest_path)
    except ManifestError as exc:
        print(f"ABORT (nothing run): {exc}", file=sys.stderr)
        return 2

    print(f"OPENANT_HEAD: {head}")
    print("OPENANT_STATUS_PORCELAIN:\n" + (porcelain.rstrip() or "(clean)"))
    print(f"MANIFEST: {manifest_path}")
    print(f"SELECTED: {len(selected)} ({selected[0]['id']} .. {selected[-1]['id']})")
    n = len(selected)

    if args.validate_only:
        for i, c in enumerate(selected, 1):
            out = args.results_root / c["id"]
            state = ("would SKIP_ALREADY_COMPLETE" if run_completed_ok(out)
                     else "would be INCOMPLETE_EXISTING_OUTPUT" if out.exists()
                     else "would run")
            print(f"[{i:02d}/{n}] {c['id']} {c['cve']} {c['sha'][:12]} -> {state}")
        print("VALIDATE_ONLY: no case was run")
        return 0

    args.results_root.mkdir(parents=True, exist_ok=True)
    # Never overwrite a previous batch's records: archive them first.
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for name in ("batch_manifest.json", "BATCH_SUMMARY.md"):
        prev = args.results_root / name
        if prev.exists():
            prev.rename(prev.with_name(f"{prev.stem}.prev-{stamp}{prev.suffix}"))
    batch = {
        "evaluation_started_at": datetime.now(timezone.utc).isoformat(),
        "evaluation_finished_at": None,
        "openant_head": head,
        "openant_status_porcelain": porcelain,
        "manifest_path": str(manifest_path),
        "run_traced": str(RUN_TRACED),
        "run_traced_cwd": str(CORE_DIR),
        "total_selected_cases": n,
        "cases": [],
        "counts": {s: 0 for s in STATUSES},
    }

    for i, c in enumerate(selected, 1):
        out_dir = args.results_root / c["id"]
        repo_dir = args.repos_root / c["id"]
        rec = {
            "id": c["id"], "cve": c["cve"], "repo": c["repo"],
            "expected_sha": c["sha"], "verified_checkout_sha": None,
            "repo_dir": str(repo_dir), "output_dir": str(out_dir),
            "process_exit_status": None, "run_manifest_status": None,
            "batch_status": None, "detail": None,
            "started_at": datetime.now(timezone.utc).isoformat(), "finished_at": None,
        }
        print(f"[{i:02d}/{n}] {c['id']} ({c['cve']}) @ {c['sha']}", flush=True)
        try:
            if out_dir.exists():
                rec["run_manifest_status"] = read_run_manifest_status(out_dir)
                if run_completed_ok(out_dir):
                    rec["batch_status"] = "SKIPPED_ALREADY_COMPLETE"
                else:
                    rec["batch_status"] = "INCOMPLETE_EXISTING_OUTPUT"
                    rec["detail"] = "existing output preserved, not rerun"
            else:
                verified, detail = prepare_checkout(c, repo_dir)
                rec["verified_checkout_sha"], rec["detail"] = verified, detail
                if verified is None:
                    rec["batch_status"] = "CHECKOUT_FAILED"
                else:
                    out_dir.mkdir(parents=True)
                    cmd = [args.python, str(RUN_TRACED), "--cve", c["cve"],
                           "--repo-root", str(repo_dir), "--output", str(out_dir),
                           "--blind-evaluation", "--blind-strip-same-repo-github-references"]
                    (out_dir / "batch_command.json").write_text(
                        json.dumps({"cmd": cmd, "cwd": str(CORE_DIR)}, indent=2), encoding="utf-8")
                    with open(out_dir / "batch_stdout.log", "w") as so, \
                         open(out_dir / "batch_stderr.log", "w") as se:
                        proc = subprocess.run(cmd, cwd=CORE_DIR, stdout=so, stderr=se)
                    rec["process_exit_status"] = proc.returncode
                    rec["run_manifest_status"] = read_run_manifest_status(out_dir)
                    ok = proc.returncode == 0 and run_completed_ok(out_dir)
                    rec["batch_status"] = "COMPLETED" if ok else "RUN_FAILED"
        except Exception as exc:  # one case must never end the batch
            rec["batch_status"] = rec["batch_status"] or (
                "CHECKOUT_FAILED" if rec["verified_checkout_sha"] is None and not out_dir.exists()
                else "RUN_FAILED")
            rec["detail"] = f"{type(exc).__name__}: {exc}"
        rec["finished_at"] = datetime.now(timezone.utc).isoformat()
        batch["cases"].append(rec)
        batch["counts"][rec["batch_status"]] += 1
        write_reports(args.results_root, batch)
        print(f"[{i:02d}/{n}] {c['id']}: {rec['batch_status']}"
              + (f" (exit {rec['process_exit_status']})" if rec["process_exit_status"] is not None else "")
              + (f" -- {rec['detail']}" if rec["detail"] else ""), flush=True)

    batch["evaluation_finished_at"] = datetime.now(timezone.utc).isoformat()
    write_reports(args.results_root, batch)
    k = batch["counts"]
    print(f"\nTOTAL_SELECTED: {n}")
    for s in STATUSES:
        print(f"{s}: {k[s]}")
    finished = k["COMPLETED"] + k["SKIPPED_ALREADY_COMPLETE"] == n
    print(f"BATCH_FINISHED: {'YES' if finished else 'NO'}")
    return 0 if finished else 1


if __name__ == "__main__":
    sys.exit(main())
