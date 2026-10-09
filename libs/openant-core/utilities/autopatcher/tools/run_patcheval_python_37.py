#!/usr/bin/env python3
"""
run_patcheval_python_37.py -- compatibility wrapper: runs the 37
PatchEval-Verified Python expansion cases of cfp_evaluation_cases.yaml
(opendiamond-cve-2022-31506 onward, in manifest order) through
run_cve_batch.py, the standard real-CVE batch runner (same directory).

Everything else -- isolated per-case checkouts/outputs/CWDs, canonical
run_traced.py flags, --jobs, summaries, ZIP, --resume -- is
run_cve_batch.py's behavior; see RUN_CVE_BATCH.md. Every option other than
the ones below is passed through unchanged:

  --manifest PATH       manifest to select from (default cfp_evaluation_cases.yaml)
  --results-root DIR    accepted as an alias of run_cve_batch.py --batch-root

--repos-root is no longer supported: checkouts now live inside each case
attempt of the batch directory (one fresh clone per attempt).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

TOOLS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TOOLS_DIR.parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.autopatcher.tools import run_cve_batch  # noqa: E402

DEFAULT_MANIFEST = TOOLS_DIR / "cfp_evaluation_cases.yaml"
FIRST_EXPANSION_ID = "opendiamond-cve-2022-31506"
EXPECTED_EXPANSION = 37


def expansion_case_ids(manifest_path: Path) -> list:
    """The 37 expansion case ids, in manifest order. Full manifest validation
    is run_cve_batch's job; this only locates the selection."""
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    ids = [c.get("id") for c in (data or {}).get("cases") or [] if isinstance(c, dict)]
    if FIRST_EXPANSION_ID not in ids:
        raise run_cve_batch.ManifestError([f"{manifest_path}: {FIRST_EXPANSION_ID} not found"])
    selected = ids[ids.index(FIRST_EXPANSION_ID):]
    if len(selected) != EXPECTED_EXPANSION:
        raise run_cve_batch.ManifestError([
            f"{manifest_path}: expected {EXPECTED_EXPANSION} expansion cases from "
            f"{FIRST_EXPANSION_ID}, found {len(selected)}"
        ])
    return selected


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1], allow_abbrev=False)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--results-root", dest="batch_root")
    parser.add_argument("--repos-root", help=argparse.SUPPRESS)
    parser.add_argument("--case", action="append", default=None,
                        help="Restrict to these expansion case ids (each must be one of the 37).")
    args, passthrough = parser.parse_known_args(argv)
    if args.repos_root:
        parser.error("--repos-root is no longer supported: each case attempt gets its own fresh "
                     "checkout inside the batch directory (see RUN_CVE_BATCH.md)")

    def given(flag: str) -> bool:
        return any(a == flag or a.startswith(flag + "=") for a in passthrough)

    if args.batch_root:
        passthrough = ["--batch-root", args.batch_root, *passthrough]
    if given("--resume") or given("--summarize"):
        return run_cve_batch.main([*passthrough, *[a for c in args.case or [] for a in ("--case", c)]])
    try:
        ids = expansion_case_ids(args.manifest.resolve())
    except (OSError, yaml.YAMLError, run_cve_batch.ManifestError) as exc:
        print(f"ERROR: cannot select the {EXPECTED_EXPANSION} expansion cases: {exc}", file=sys.stderr)
        return 2
    if args.case:
        # --case narrows the 37; it must never add cases outside them.
        outside = [c for c in args.case if c not in ids]
        if outside:
            print(f"ERROR: --case {', '.join(outside)} is not one of the {EXPECTED_EXPANSION} PatchEval "
                  f"expansion cases. Nothing was run.", file=sys.stderr)
            return 2
        ids = [i for i in ids if i in set(args.case)]
    selection = [arg for case_id in ids for arg in ("--case", case_id)]
    if not given("--label"):
        passthrough = ["--label", "patcheval-python-37", *passthrough]
    return run_cve_batch.main(["--manifest", str(args.manifest), *selection, *passthrough])


if __name__ == "__main__":
    sys.exit(main())
