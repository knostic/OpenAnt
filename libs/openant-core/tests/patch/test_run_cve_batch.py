"""Hermetic tests for utilities/autopatcher/tools/run_cve_batch.py (and the
run_patcheval_python_37.py compatibility wrapper).

No network and no LLM calls: target repositories are local bare repos served
for https://github.com/<owner>/<repo>.git URLs through a test-only
GIT_CONFIG_GLOBAL `insteadOf` rule, and run_traced.py is replaced (via the
runner's hidden --run-traced hook) by a small fake that writes run_traced's
artifact shapes -- run_manifest.json, checkpoints.jsonl, a Trust Report
decision card, ./reports/debug artifacts and the stderr Trace Summary --
according to a per-CVE scenario file.
"""
from __future__ import annotations

import csv
import importlib.util
import io
import json
import os
import signal
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest
import yaml

from utilities.autopatcher.tools import run_cve_batch as rcb
from utilities.autopatcher.tools import run_patcheval_python_37 as wrapper

# The runner is POSIX-only (process groups, flock -- RUN_CVE_BATCH.md); the
# module itself still imports on Windows (see test_non_posix_host_is_refused).
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="run_cve_batch.py is POSIX-only")

TOOLS_DIR = Path(rcb.__file__).resolve().parent
REAL_MANIFEST = TOOLS_DIR / "cfp_evaluation_cases.yaml"

FAKE_RUN_TRACED = r'''
import argparse, json, os, subprocess, sys, time
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--cve", required=True)
parser.add_argument("--repo-root", required=True)
parser.add_argument("--output", required=True)
parser.add_argument("--context-budget-policy")
parser.add_argument("--max-context-budget-windows", type=int)
parser.add_argument("--blind-evaluation", action="store_true")
parser.add_argument("--blind-strip-same-repo-github-references", action="store_true")
parser.add_argument("--blind-filter-policy")
args = parser.parse_args()

scenario = json.loads(Path(os.environ["FAKE_SCENARIOS"]).read_text()).get(args.cve, {})
kind = scenario.get("kind", "outcome")
outcome = scenario.get("outcome", "ORANGE")


def log(event):
    record = {"event": event, "cve": args.cve, "time": time.time(), "pid": os.getpid(),
              "cwd": os.getcwd(), "repo_root": args.repo_root, "output": args.output,
              "argv": sys.argv[1:]}
    with open(os.environ["FAKE_INVOCATIONS"], "a") as fh:
        fh.write(json.dumps(record) + "\n")


log("start")
time.sleep(float(scenario.get("sleep", 0)))
print(f"fake stdout for {args.cve}")

out = Path(args.output)
trace, patch = out / "trace", out / "patch"
trace.mkdir(parents=True, exist_ok=True)
patch.mkdir(parents=True, exist_ok=True)
debug = Path.cwd() / "reports" / "debug"
debug.mkdir(parents=True, exist_ok=True)
debug_file = debug / f"context_selection_{args.cve}.json"
payload = {"cve": args.cve}
if kind == "leak_secret":
    payload["oops"] = os.environ["FAKE_LEAK_TOKEN"]
debug_file.write_text(json.dumps(payload))
head = subprocess.run(["git", "-C", args.repo_root, "rev-parse", "HEAD"],
                      capture_output=True, text=True).stdout.strip()
CARDS = {"GREEN": ("\U0001F7E2", "Deploy After Validation"), "YELLOW": ("\U0001F7E1", "Deploy With Caution"),
         "ORANGE": ("\U0001F7E0", "Manual Review Required"), "RED": ("\U0001F534", "Do Not Apply"),
         "GRAY": ("⚫", "No Patch Produced")}


def write_report():
    emoji, decision = CARDS[outcome]
    card = "## \U0001F7E3 SHIP IT" if kind == "bad_report" else f"## {emoji} {decision.upper()}"
    lines = ["# Auto Patcher MVP — Security Patch Report", "", card, "", "Patch applies cleanly.  ",
             f"Files changed: {0 if outcome == 'GRAY' else 1}", "", "---", "", "## Vulnerability summary", "",
             "Summary.", "", "## Patch Applicability", ""]
    lines.append("*(Skipped — planning_ungrounded: ungrounded_unresolvable.)*" if outcome == "GRAY"
                 else "**Result:** ✓ Patch applies cleanly to the target repository.")
    if outcome != "GRAY":
        rec = "Deploy After Validation" if kind == "inconsistent_report" else decision
        lines += ["", "## Recommendation", "", f"**{rec}**", "", "Reason."]
    (patch / f"{args.cve}-trust-report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (patch / f"{args.cve}-vulnerability.md").write_text("# vuln\n", encoding="utf-8")
    if kind == "investigation":
        inv = patch / f"{args.cve}-investigation"
        inv.mkdir()
        (inv / "dataset.json").write_text(json.dumps({"big": "x" * 2048}))


def write_manifest(status="success", **extra):
    stages = scenario.get("stages") or ["remediation_planning", "remediation_strategy", "patch_generation"]
    with open(trace / "checkpoints.jsonl", "w") as fh:
        for seq, stage in enumerate(stages, 1):
            fh.write(json.dumps({"seq": seq, "stage": stage}) + "\n")
    if outcome == "GRAY":
        executions = [
            {"execution_id": "001_repository_analysis_and_remediation_planning",
             "canonical_stage": "repository_analysis_and_remediation_planning",
             "outcome": "planning_ungrounded", "llm_calls": [{"seq": 1}]},
            {"execution_id": "002_remediation_strategy", "canonical_stage": "remediation_strategy",
             "outcome": "skipped_planning_ungrounded", "llm_calls": []},
        ]
    else:
        executions = [{"execution_id": "001_repository_analysis_and_remediation_planning",
                       "canonical_stage": "repository_analysis_and_remediation_planning",
                       "outcome": "generated", "llm_calls": [{"seq": 1}]}]
    blind = {"enabled": True, "rule_id": "blind-evaluation-filter/" + (args.blind_filter_policy or "v1"),
             "status": "unverified" if kind == "unblinded" else "verified",
             "pipeline_input_verified": True, "vulnerability_artifact_verified": True,
             "removed_count": 1, "error": None, "run_error": None,
             "same_repo_github_policy": {"enabled": bool(args.blind_strip_same_repo_github_references)}}
    data = {
        "status": status, "input_type": "cve", "input_id": "CVE-1999-0001" if kind == "wrong_cve" else args.cve,
        "repo_root": args.repo_root, "output_dir": args.output,
        "context_budget_policy": args.context_budget_policy,
        "max_context_budget_windows": args.max_context_budget_windows,
        "compare_existing_tests": False,
        "vulnerability_path": str(patch / f"{args.cve}-vulnerability.md"),
        "trust_report_path": str(patch / f"{args.cve}-trust-report.md"),
        "schema_version": 3, "kind": "full_run", "parent": None,
        "target_repository": {"repo_root": args.repo_root, "repo_commit": head},
        "openant": {"patcher_commit": scenario.get("patcher_commit")},
        "llm": {"provider": "mock" if kind == "mock_provider" else "anthropic", "model": "claude-test"},
        "executions": executions, "blind_evaluation": blind,
        "llm_call_count": len(stages) + (1 if kind == "count_mismatch" else 0),
        "checkpoints_file": "checkpoints.jsonl",
        "autopatcher_debug_artifacts": [str(debug_file)],
    }
    data.update(extra)
    (trace / "run_manifest.json").write_text(json.dumps(data, indent=2))
    return len(stages)


def fail_manifest(error_type, message):
    write_manifest(status="failed", error_type=error_type, error_message=message)


if kind == "crash":
    fail_manifest("RuntimeError", "boom")
    print("Traceback (most recent call last):\n  File \"x\", line 1\nRuntimeError: boom", file=sys.stderr)
    sys.exit(1)
if kind == "rate_limit":
    # The exact shape llm_client.call_llm re-raises an adapter LLMRateLimitError as.
    message = "Anthropic API call failed: Error code: 429 - {'type': 'error', 'error': {'type': 'rate_limit_error'}}"
    fail_manifest("RuntimeError", message)
    print("RuntimeError: " + message, file=sys.stderr)
    sys.exit(1)
if kind == "nvd_error":
    fail_manifest("CVEFetchError", "Failed to fetch CVE-2024-0001 from NVD: 429 Client Error: Too Many Requests")
    sys.exit(1)
if kind == "blind_abort":
    fail_manifest("BlindEvaluationError", "blind evaluation aborted: unsupported reference")
    print("Blind evaluation aborted.", file=sys.stderr)
    sys.exit(2)
if kind == "usage_error":
    print("error: --blind-strip-same-repo-github-references requires a GitHub origin", file=sys.stderr)
    sys.exit(2)
if kind == "hang":
    time.sleep(3600)
write_report()
if kind == "no_manifest":
    sys.exit(0)
if kind == "corrupt_manifest":
    (trace / "run_manifest.json").write_text("{not json")
    sys.exit(0)
calls = write_manifest(**({"openant": {"patcher_commit": "f" * 40}} if kind == "commit_mismatch" else {}))
if kind == "mutate_repo":
    (Path(args.repo_root) / "SURPRISE.txt").write_text("modified by the run\n")
shown_calls = 99 if kind == "summary_mismatch" else calls
print(f"Trace Summary\n" + "─" * 20 + f"\nLLM calls      {shown_calls}\nTokens         12,345\nCost           $0.12",
      file=sys.stderr)
log("end")
'''


class Env:
    def __init__(self, tmp_path: Path, monkeypatch):
        self.tmp = tmp_path
        self.github = tmp_path / "github"
        self.github.mkdir()
        self.batch_root = tmp_path / "batches"
        gitconfig = tmp_path / "gitconfig"
        gitconfig.write_text(
            f'[url "file://{self.github}/"]\n\tinsteadOf = https://github.com/\n'
            "[user]\n\tname = Test\n\temail = test@example.com\n[init]\n\tdefaultBranch = main\n"
        )
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig))
        monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
        monkeypatch.delenv("LLM_PROVIDER", raising=False)  # tests/patch/conftest.py sets mock
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))  # never read the real config.json
        self.scenario_file = tmp_path / "scenarios.json"
        self.scenario_file.write_text("{}")
        self.invocation_file = tmp_path / "invocations.jsonl"
        monkeypatch.setenv("FAKE_SCENARIOS", str(self.scenario_file))
        monkeypatch.setenv("FAKE_INVOCATIONS", str(self.invocation_file))
        self.fake = tmp_path / "fake_run_traced.py"
        self.fake.write_text(FAKE_RUN_TRACED, encoding="utf-8")
        self._repos = {}
        # Deterministic OpenAnt work-tree state: the suite must not depend on
        # the monorepo staying unchanged while it runs. Tests may replace
        # `openant_fingerprints` to simulate code changing mid-batch.
        self.openant_fingerprints = None
        self.openant_work_tree = "/openant"
        self.openant_calls = 0
        monkeypatch.setattr(rcb, "collect_openant_state", self._fake_openant_state)

    def _fake_openant_state(self) -> dict:
        self.openant_calls += 1
        fingerprint = "f" * 64
        if self.openant_fingerprints:
            fingerprint = self.openant_fingerprints[min(self.openant_calls, len(self.openant_fingerprints)) - 1]
        return {"work_tree": self.openant_work_tree, "head": "a" * 40, "dirty": False, "status_porcelain": [],
                "tracked_diff_sha256": None, "untracked_files": [], "fingerprint": fingerprint, "_diff": b""}

    def git(self, *args, cwd=None):
        return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()

    def repo(self, name: str, commits: int = 2) -> "tuple[str, list[str]]":
        """https://github.com/acme/<name>.git backed by a local bare repo."""
        if name in self._repos:
            return self._repos[name]
        work = self.tmp / "work" / name
        work.mkdir(parents=True)
        self.git("init", "-q", cwd=work)
        shas = []
        for i in range(commits):
            (work / "app.py").write_text(f"VERSION = {i}\n")
            self.git("add", "app.py", cwd=work)
            self.git("commit", "-q", "-m", f"commit {i}", cwd=work)
            shas.append(self.git("rev-parse", "HEAD", cwd=work))
        (self.github / "acme").mkdir(exist_ok=True)
        self.git("clone", "-q", "--bare", str(work), str(self.github / "acme" / f"{name}.git"))
        self._repos[name] = (f"https://github.com/acme/{name}.git", shas)
        return self._repos[name]

    def case(self, case_id: str, cve: str, repo: str = "widget", sha_index: int = 0, **extra) -> dict:
        url, shas = self.repo(repo)
        return {"id": case_id, "repo": url, "cve": cve, "sha": shas[sha_index], "language": "Python", **extra}

    def manifest(self, name: str, cases: list, **top) -> Path:
        path = self.tmp / name
        path.write_text(yaml.safe_dump({**top, "cases": cases}, sort_keys=False))
        return path

    def scenarios(self, mapping: dict) -> None:
        self.scenario_file.write_text(json.dumps(mapping))

    def run(self, *args) -> int:
        return rcb.main(["--run-traced", str(self.fake), "--batch-root", str(self.batch_root),
                         "--heartbeat-seconds", "0", *args])

    def invocations(self, event: str = "start") -> list:
        if not self.invocation_file.exists():
            return []
        rows = [json.loads(line) for line in self.invocation_file.read_text().splitlines() if line.strip()]
        return [r for r in rows if r["event"] == event]

    def batch(self, batch_id: str) -> "tuple[Path, dict, dict]":
        batch_dir = (self.batch_root / batch_id).resolve()
        manifest = json.loads((batch_dir / "batch_manifest.json").read_text())
        summary = json.loads((batch_dir / "batch_summary.json").read_text())
        return batch_dir, manifest, summary


@pytest.fixture
def env(tmp_path, monkeypatch):
    return Env(tmp_path, monkeypatch)


def rows_by_id(summary: dict) -> dict:
    return {row["case_id"]: row for row in summary["cases"]}


def dist(summary: dict, which: str) -> dict:
    return {r["category"]: (r["count"], r["percent"]) for r in summary["distribution"][which]["rows"]}


# ---------------------------------------------------------------------------
# Real manifest / wrapper / run_traced compatibility (no execution)
# ---------------------------------------------------------------------------

def test_real_cfp_manifest_validates(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    code = rcb.main(["--manifest", str(REAL_MANIFEST), "--validate-only", "--batch-root", str(tmp_path / "b")])
    out = capsys.readouterr().out
    assert code == 0
    assert "VALID: 43 case(s) from 1 manifest(s)" in out
    assert "--context-budget-policy always --max-context-budget-windows 10 --blind-evaluation "\
           "--blind-strip-same-repo-github-references" in out
    assert not (tmp_path / "b").exists()


def test_wrapper_selects_the_37_expansion_cases(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    code = wrapper.main(["--validate-only", "--results-root", str(tmp_path / "b")])
    out = capsys.readouterr().out
    assert code == 0
    assert "VALID: 37 case(s)" in out
    listed = [line.split()[2] for line in out.splitlines() if line.startswith("  [")]
    assert listed[0] == "opendiamond-cve-2022-31506" and listed[-1] == "mlflow-cve-2023-6831"
    assert "jupyter-notebook-cve-2020-26215" not in listed
    assert "patcheval-python-37" in out  # label folded into the would-be batch id


def test_wrapper_rejects_repos_root(capsys):
    with pytest.raises(SystemExit) as exc:
        wrapper.main(["--repos-root", "/tmp/x"])
    assert exc.value.code == 2


def test_non_posix_host_is_refused_before_anything_runs(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(rcb, "fcntl", None)  # what the guarded import yields on Windows
    code = rcb.main(["--manifest", str(REAL_MANIFEST), "--validate-only", "--batch-root", str(tmp_path / "b")])
    assert code == rcb.EXIT_INVALID_INPUT
    assert "requires POSIX" in capsys.readouterr().err
    assert not (tmp_path / "b").exists()


def test_real_run_traced_is_launched_with_canonical_flags_in_the_attempt_cwd(env, monkeypatch):
    """End-to-end with the REAL run_traced.py, stopping at its own pre-flight:
    in this hermetic git setup `git remote get-url origin` expands the test
    insteadOf rule to a file:// URL, so run_traced's same-repo GitHub check
    exits 2 before any NVD fetch, pipeline work or LLM call. Fail-closed even
    if run_traced's check order ever changes: the LLM is forced to mock and
    HTTP(S) goes to a dead proxy."""
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.setenv(var, "http://127.0.0.1:9")
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("no_proxy", "")
    m = env.manifest("m.yaml", [env.case("real", "CVE-2023-29159")])
    code = rcb.main(["--manifest", str(m), "--batch-root", str(env.batch_root), "--batch-id", "real",
                     "--heartbeat-seconds", "0", "--no-zip", "--allow-mock-llm"])
    assert code == 1
    batch_dir = env.batch("real")[0]
    attempt = batch_dir / "cases" / "real" / "attempt-01"
    result = json.loads((attempt / "result.json").read_text())
    assert result["command"]["argv"][1] == str(TOOLS_DIR / "run_traced.py")
    assert (result["failure_kind"], result["execution"]["exit_code"]) == ("run_traced_usage_error", 2)
    assert "requires --repo-root's `origin` remote to name a GitHub repository" in (attempt / "stderr.log").read_text()
    assert list((attempt / "cwd").iterdir()) == []


@pytest.mark.parametrize("policy", [None, "v2"])
def test_canonical_command_is_accepted_by_the_real_run_traced_parser(policy):
    spec = importlib.util.spec_from_file_location("run_traced_for_batch_test", TOOLS_DIR / "run_traced.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    flags = [*rcb.CONTEXT_BUDGET_FLAGS, *rcb.BLIND_FLAGS, *(["--blind-filter-policy", policy] if policy else [])]
    ns = module.build_parser().parse_args(["--cve", "CVE-2023-0001", "--repo-root", "/r", "--output", "/o", *flags])
    assert ns.context_budget_policy == "always" and ns.max_context_budget_windows == 10
    assert ns.blind_evaluation and ns.blind_strip_same_repo_github_references
    assert ns.blind_filter_policy == policy


# ---------------------------------------------------------------------------
# Input validation (nothing runs, no batch directory)
# ---------------------------------------------------------------------------

def _bad_case_manifests(env):
    good = env.case("widget-cve-2023-0001", "CVE-2023-0001")
    return {
        "malformed_yaml": ("cases: [\n  - id: x\n", "malformed YAML"),
        "duplicate_key": (f"cases:\n  - id: a\n    repo: {good['repo']}\n    cve: CVE-2023-0001\n"
                          f"    sha: {good['sha']}\n    sha: {good['sha']}\n", "duplicate key"),
        "missing_sha": ({**good, "sha": None}, "missing or empty string field `sha`"),
        "short_sha": ({**good, "sha": good["sha"][:12]}, "full 40-character"),
        "upper_sha": ({**good, "sha": good["sha"].upper()}, "full 40-character"),
        "http_url": ({**good, "repo": "http://github.com/acme/widget.git"}, "must be an https:// URL"),
        "credentials": ({**good, "repo": "https://user:tok@github.com/acme/widget.git"}, "credentials"),
        "non_github": ({**good, "repo": "https://gitlab.com/acme/widget.git"}, "must name a GitHub repository"),
        "bad_cve": ({**good, "cve": "cve-2023-1"}, "`cve` must look like"),
        "bad_id": ({**good, "id": "../escape"}, "`id` must be"),
        "advisory_file": ({**good, "advisory_file": "x.md"}, "file-mode advisory cases are not supported"),
        "bad_tags": ({**good, "tags": "a,b"}, "`tags` must be a list"),
    }


@pytest.mark.parametrize("name", [
    "malformed_yaml", "duplicate_key", "missing_sha", "short_sha", "upper_sha", "http_url", "credentials",
    "non_github", "bad_cve", "bad_id", "advisory_file", "bad_tags",
])
def test_invalid_manifest_aborts_before_running(env, capsys, name):
    content, expected = _bad_case_manifests(env)[name]
    path = env.tmp / f"{name}.yaml"
    if isinstance(content, str):
        path.write_text(content)
    else:
        path.write_text(yaml.safe_dump({"cases": [{k: v for k, v in content.items() if v is not None}]}))
    code = env.run("--manifest", str(path))
    err = capsys.readouterr().err
    assert code == 2
    assert expected in err
    assert "Nothing was run." in err
    assert not env.batch_root.exists()
    assert env.invocations() == []


def test_unknown_top_level_key_and_empty_cases(env, capsys):
    typo = env.tmp / "typo.yaml"
    typo.write_text(yaml.safe_dump({"case": [env.case("a", "CVE-2023-0001")]}))
    assert env.run("--manifest", str(typo)) == 2
    err = capsys.readouterr().err
    assert "unknown top-level key(s) ['case']" in err and "`cases` must be a non-empty list" in err


def test_duplicate_detection_across_manifests(env, capsys):
    a = env.manifest("a.yaml", [env.case("one", "CVE-2023-0001")])
    b = env.manifest("b.yaml", [env.case("ONE", "CVE-2023-0002", repo="gadget")])
    assert env.run("--manifest", str(a), "--manifest", str(b), "--validate-only") == 2
    assert "ids differ only by case" in capsys.readouterr().err

    c = env.manifest("c.yaml", [env.case("two", "CVE-2023-0001")])  # same CVE/repo/SHA as `one`
    assert env.run("--manifest", str(a), "--manifest", str(c), "--validate-only") == 2
    assert "same CVE at the same repository and SHA" in capsys.readouterr().err

    assert env.run("--manifest", str(a), "--manifest", str(a), "--validate-only") == 2
    assert "given more than once" in capsys.readouterr().err


def test_duplicate_cve_needs_explicit_flag(env, capsys):
    a = env.manifest("a.yaml", [env.case("one", "CVE-2023-0001")])
    b = env.manifest("b.yaml", [env.case("two", "CVE-2023-0001", repo="gadget")])
    assert env.run("--manifest", str(a), "--manifest", str(b), "--validate-only") == 2
    assert "--allow-duplicate-cve" in capsys.readouterr().err
    assert env.run("--manifest", str(a), "--manifest", str(b), "--validate-only", "--allow-duplicate-cve") == 0


def test_unknown_case_filter_and_llm_provider_overrides_are_refused(env, capsys, monkeypatch):
    m = env.manifest("m.yaml", [env.case("one", "CVE-2023-0001")])
    assert env.run("--manifest", str(m), "--case", "nope") == 2
    assert "--case 'nope' is not a case id" in capsys.readouterr().err
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    assert env.run("--manifest", str(m)) == 2
    assert "LLM_PROVIDER=mock" in capsys.readouterr().err
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")  # llm_client rejects every non-mock value
    assert env.run("--manifest", str(m)) == 2
    assert "every case would fail" in capsys.readouterr().err
    assert not env.batch_root.exists()


def test_allow_mock_llm_runs_and_flags_mock_results(env, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    m = env.manifest("m.yaml", [env.case("one", "CVE-2023-0001")])
    env.scenarios({"CVE-2023-0001": {"kind": "mock_provider"}})
    assert env.run("--manifest", str(m), "--batch-id", "b", "--allow-mock-llm", "--no-zip") == 0
    row = rows_by_id(env.batch("b")[2])["one"]
    assert any("not a real evaluation" in a for a in row["anomalies"])


def test_zip_failure_keeps_summaries_and_exits_4(env, monkeypatch, capsys):
    def broken_zip(*_args, **_kwargs):
        raise OSError("disk full")
    monkeypatch.setattr(rcb, "build_zip", broken_zip)
    m = env.manifest("m.yaml", [env.case("one", "CVE-2023-0001")])
    assert env.run("--manifest", str(m), "--batch-id", "b") == rcb.EXIT_ZIP_FAILED
    assert "results ZIP could not be created (OSError: disk full)" in capsys.readouterr().out
    _batch_dir, manifest, summary = env.batch("b")
    assert summary["status"] == "COMPLETE"
    assert manifest["sessions"][0]["zip"] == {"error": "OSError: disk full"}
    assert manifest["sessions"][0]["exit_code"] == rcb.EXIT_ZIP_FAILED
    assert manifest["sessions"][0]["in_progress"] is False


def test_signals_ignored_by_the_parent_stay_ignored():
    previous_hup = signal.signal(signal.SIGHUP, signal.SIG_IGN)  # what nohup does
    try:
        installed = rcb._install_signal_handlers({"signals": 0, "ctx": None})
        try:
            assert signal.getsignal(signal.SIGHUP) is signal.SIG_IGN
            assert signal.SIGHUP not in installed and signal.SIGTERM in installed
        finally:
            rcb._restore_signal_handlers(installed)
    finally:
        signal.signal(signal.SIGHUP, previous_hup)


# ---------------------------------------------------------------------------
# Execution, classification, statistics, reports
# ---------------------------------------------------------------------------

def test_single_manifest_every_outcome(env, capsys):
    cases = [env.case(f"case-{o.lower()}", f"CVE-2024-000{i}") for i, o in
             enumerate(["GREEN", "YELLOW", "ORANGE", "RED", "GRAY"], 1)]
    env.scenarios({c["cve"]: {"outcome": o} for c, o in zip(cases, ["GREEN", "YELLOW", "ORANGE", "RED", "GRAY"], strict=True)})
    m = env.manifest("m.yaml", cases)
    assert env.run("--manifest", str(m), "--batch-id", "b1", "--jobs", "2") == 0
    out = capsys.readouterr().out
    batch_dir, manifest, summary = env.batch("b1")
    assert summary["status"] == "COMPLETE"
    assert summary["counts"]["by_category"] == {"GREEN": 1, "YELLOW": 1, "ORANGE": 1, "RED": 1, "GRAY": 1,
                                                 "FAILED": 0, "INCOMPLETE": 0}
    assert summary["counts"]["patch_producing"] == 4 and summary["counts"]["no_patch"] == 1
    rows = rows_by_id(summary)
    assert rows["case-gray"]["reason"] == "planning_ungrounded: ungrounded_unresolvable"
    assert rows["case-gray"]["decision"] == "No Patch Produced"
    assert rows["case-green"]["llm_calls"] == 3 and rows["case-green"]["tokens"] == 12345
    assert summary["usage"]["total_tokens"] == 5 * 12345
    assert summary["blind_evaluation"]["verified"] == 5
    assert "DONE    case-gray" in out and "⚫ GRAY No Patch Produced" in out
    assert "ZIP" in out and "-results.zip" in out
    # per-case isolation artifacts
    attempt = batch_dir / "cases" / "case-green" / "attempt-01"
    assert (attempt / "stdout.log").read_text().strip() == "fake stdout for CVE-2024-0001"
    assert "Trace Summary" in (attempt / "stderr.log").read_text()
    command = json.loads((attempt / "command.json").read_text())
    assert command["cwd"] == str(attempt / "cwd")
    assert command["argv"][1] == str(env.fake.resolve())
    assert command["argv"][-6:] == list(rcb.CONTEXT_BUDGET_FLAGS) + list(rcb.BLIND_FLAGS)
    assert "FAKE_SCENARIOS" not in json.dumps(command)  # full environment never recorded
    result = json.loads((attempt / "result.json").read_text())
    assert result["checkout"]["verified_head"] == cases[0]["sha"] and result["checkout"]["clean"] is True
    assert result["checkout"]["post_run_clean"] is True
    assert (batch_dir / "cases" / "case-green" / "case.json").exists()
    assert manifest["run_config"]["expected_blind_rule_id"] == "blind-evaluation-filter/v1"
    assert manifest["sessions"][0]["openant"]["head"]
    # CSV and Markdown
    csv_rows = list(csv.DictReader(io.StringIO((batch_dir / "batch_results.csv").read_text())))
    assert [r["case_id"] for r in csv_rows] == [c["id"] for c in cases]
    assert csv_rows[4]["category"] == "GRAY" and csv_rows[4]["sha"] == cases[4]["sha"]
    md = (batch_dir / "batch_summary.md").read_text()
    assert "### A. All requested cases (denominator = 5)" in md
    assert "### B. Completed Auto Patcher executions only (denominator = 5)" in md
    assert f"`{cases[0]['sha']}`" in md and "`cases/case-green/attempt-01/`" in md


def test_gray_is_not_failure_and_one_failure_does_not_stop_others(env):
    cases = [env.case("gray", "CVE-2024-0001"), env.case("crash", "CVE-2024-0002"),
             env.case("orange", "CVE-2024-0003")]
    env.scenarios({"CVE-2024-0001": {"outcome": "GRAY"}, "CVE-2024-0002": {"kind": "crash"},
                   "CVE-2024-0003": {"outcome": "ORANGE"}})
    m = env.manifest("m.yaml", cases)
    assert env.run("--manifest", str(m), "--batch-id", "b", "--jobs", "2") == 1
    _batch_dir, _manifest, summary = env.batch("b")
    assert summary["status"] == "COMPLETE_WITH_FAILURES"
    rows = rows_by_id(summary)
    assert rows["gray"]["category"] == "GRAY" and rows["gray"]["status"] == "completed"
    assert rows["crash"]["category"] == "FAILED" and rows["crash"]["failure_kind"] == "run_traced_exception"
    assert "RuntimeError: boom" in rows["crash"]["reason"]
    assert rows["orange"]["category"] == "ORANGE"
    assert dist(summary, "all_requested")["GRAY"] == (1, 33.33)
    assert dist(summary, "all_requested")["FAILED"] == (1, 33.33)
    assert dist(summary, "completed_executions") == {"GREEN": (0, 0.0), "YELLOW": (0, 0.0), "ORANGE": (1, 50.0),
                                                     "RED": (0, 0.0), "GRAY": (1, 50.0)}
    assert summary["failures_by_kind"]["run_traced_exception"]["cases"] == ["crash"]


def test_failure_kinds_are_classified_from_evidence(env):
    expected = {
        "rate_limit": "provider_rate_limit",
        "nvd_error": "advisory_fetch_failed",
        "blind_abort": "blind_evaluation_aborted",
        "usage_error": "run_traced_usage_error",
        "no_manifest": "run_manifest_missing",
        "corrupt_manifest": "run_manifest_corrupt",
        "bad_report": "recommendation_unparseable",
        "inconsistent_report": "recommendation_inconsistent",
        "wrong_cve": "run_manifest_mismatch",
        "unblinded": "blind_evaluation_unverified",
    }
    cases = [env.case(kind.replace("_", "-"), f"CVE-2024-{i:04d}") for i, kind in enumerate(expected, 1)]
    env.scenarios({c["cve"]: {"kind": kind} for c, kind in zip(cases, expected, strict=True)})
    m = env.manifest("m.yaml", cases)
    assert env.run("--manifest", str(m), "--batch-id", "b", "--jobs", "2", "--no-zip") == 1
    rows = rows_by_id(env.batch("b")[2])
    for kind, failure_kind in expected.items():
        row = rows[kind.replace("_", "-")]
        assert (row["category"], row["failure_kind"]) == ("FAILED", failure_kind), (kind, row["reason"])


def test_checkout_failures_never_invoke_run_traced(env):
    good = env.case("missing-sha", "CVE-2024-0001")
    cases = [
        {**good, "sha": "0" * 40},
        {"id": "missing-repo", "repo": "https://github.com/acme/does-not-exist.git", "cve": "CVE-2024-0002",
         "sha": "1" * 40},
    ]
    m = env.manifest("m.yaml", cases)
    assert env.run("--manifest", str(m), "--batch-id", "b", "--no-zip") == 1
    rows = rows_by_id(env.batch("b")[2])
    assert rows["missing-sha"]["failure_kind"] == "revision_not_found"
    assert rows["missing-repo"]["failure_kind"] == "clone_failed"
    assert env.invocations() == []


@pytest.mark.parametrize("git_args_prefix, fake_stdout, expected_kind", [
    (["status"], " M app.py\n", "dirty_checkout"),
    (["rev-parse", "HEAD"], "0" * 40 + "\n", "sha_mismatch"),
    (["config", "--get", "remote.origin.url"], "https://github.com/evil/fork.git\n", "origin_mismatch"),
])
def test_checkout_verification_branches(env, monkeypatch, git_args_prefix, fake_stdout, expected_kind):
    real_run_git = rcb.run_git

    def tampering_run_git(ctx, key, args, cwd, timeout):
        result = real_run_git(ctx, key, args, cwd, timeout)
        if args[:len(git_args_prefix)] == git_args_prefix:
            return rcb._GitResult(0, fake_stdout, "")
        return result

    monkeypatch.setattr(rcb, "run_git", tampering_run_git)
    m = env.manifest("m.yaml", [env.case("one", "CVE-2024-0001")])
    assert env.run("--manifest", str(m), "--batch-id", "b", "--no-zip") == 1
    row = rows_by_id(env.batch("b")[2])["one"]
    assert (row["category"], row["failure_kind"]) == ("FAILED", expected_kind)
    assert env.invocations() == []  # run_traced never runs on an unverified checkout


def test_runner_exception_is_isolated_to_its_case(env, monkeypatch):
    real_prepare = rcb.prepare_checkout

    def flaky_prepare(ctx, case, repo_dir):
        if case["id"] == "boom":
            raise RuntimeError("simulated runner bug")
        return real_prepare(ctx, case, repo_dir)

    monkeypatch.setattr(rcb, "prepare_checkout", flaky_prepare)
    m = env.manifest("m.yaml", [env.case("boom", "CVE-2024-0001"), env.case("fine", "CVE-2024-0002")])
    assert env.run("--manifest", str(m), "--batch-id", "b", "--jobs", "2", "--no-zip") == 1
    batch_dir, _manifest, summary = env.batch("b")
    rows = rows_by_id(summary)
    assert rows["boom"]["failure_kind"] == "runner_exception" and "simulated runner bug" in rows["boom"]["reason"]
    assert "RuntimeError: simulated runner bug" in (batch_dir / "cases/boom/attempt-01/runner_error.txt").read_text()
    assert rows["fine"]["category"] == "ORANGE"


def _intervals(env) -> dict:
    starts = {r["cve"]: r for r in env.invocations("start")}
    ends = {r["cve"]: r for r in env.invocations("end")}
    return {cve: (starts[cve]["time"], ends[cve]["time"]) for cve in starts}


def test_jobs_2_runs_concurrently_with_isolated_paths(env):
    cases = [env.case("first", "CVE-2024-0001"), env.case("second", "CVE-2024-0002", repo="gadget")]
    env.scenarios({c["cve"]: {"sleep": 1.5} for c in cases})
    m = env.manifest("m.yaml", cases)
    assert env.run("--manifest", str(m), "--batch-id", "b", "--jobs", "2", "--no-zip") == 0
    batch_dir, _manifest, summary = env.batch("b")
    (s1, e1), (s2, e2) = _intervals(env).values()
    assert max(s1, s2) < min(e1, e2), "the two cases should overlap with --jobs 2"
    starts = env.invocations("start")
    for key in ("cwd", "output", "repo_root"):
        assert len({r[key] for r in starts}) == 2
    for row, inv in ((rows_by_id(summary)[c["id"]], next(r for r in starts if r["cve"] == c["cve"])) for c in cases):
        attempt = (batch_dir / row["attempt_dir"]).resolve()
        assert Path(inv["cwd"]).resolve() == attempt / "cwd"
        assert Path(inv["output"]).resolve() == attempt / "output"
        assert Path(inv["repo_root"]).resolve() == attempt / "repo"
        assert (attempt / "cwd" / "reports" / "debug" / f"context_selection_{row['cve']}.json").exists()
        assert row["anomalies"] == []
    assert summary["timing"]["parallel_speedup"] > 1.2


def test_jobs_1_runs_sequentially_and_report_order_is_manifest_order(env):
    cases = [env.case("slow", "CVE-2024-0001"), env.case("fast", "CVE-2024-0002")]
    env.scenarios({"CVE-2024-0001": {"sleep": 1.0}, "CVE-2024-0002": {"sleep": 0}})
    m = env.manifest("m.yaml", cases)
    assert env.run("--manifest", str(m), "--batch-id", "b", "--jobs", "1", "--no-zip") == 0
    (s1, e1), (s2, e2) = sorted(_intervals(env).values())
    assert s2 >= e1
    summary = env.batch("b")[2]
    assert [r["case_id"] for r in summary["cases"]] == ["slow", "fast"]

    # With --jobs 2 the fast case finishes first; the report order is unchanged.
    env.invocation_file.unlink()
    assert env.run("--manifest", str(m), "--batch-id", "b2", "--jobs", "2", "--no-zip") == 0
    assert [r["case_id"] for r in env.batch("b2")[2]["cases"]] == ["slow", "fast"]


def test_multiple_manifests_preserve_order_provenance_and_groups(env, monkeypatch):
    a = env.manifest("cfp.yaml", [env.case("a1", "CVE-2024-0001"), env.case("a2", "CVE-2024-0002")], group="CFP")
    b = env.manifest("release.yaml", [env.case("b1", "CVE-2024-0003", group="release-gate")])
    elsewhere = env.tmp / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)  # isolation must not depend on the shell's CWD
    assert env.run("--manifest", os.path.relpath(a, elsewhere), "--manifest", str(b),
                   "--batch-id", "b", "--no-zip") == 0
    batch_dir, manifest, summary = env.batch("b")
    assert [r["case_id"] for r in summary["cases"]] == ["a1", "a2", "b1"]
    assert [r["group"] for r in summary["cases"]] == ["CFP", "CFP", "release-gate"]
    assert {i["path"] for i in manifest["inputs"]} == {str(a.resolve()), str(b.resolve())}
    for inp in manifest["inputs"]:
        assert rcb.sha256_file(batch_dir / inp["copy"]) == inp["sha256"] == rcb.sha256_file(Path(inp["path"]))
    assert manifest["cases"][2]["source"]["manifest"] == str(b.resolve())
    assert {i["value"] for i in summary["breakdown"]["by_manifest"]} == {str(a.resolve()), str(b.resolve())}
    assert {i["value"] for i in summary["breakdown"]["by_group"]} == {"CFP", "release-gate"}
    for inv in env.invocations():
        assert Path(inv["cwd"]).resolve().is_relative_to(batch_dir)
    assert not (elsewhere / "reports").exists()


def test_case_filter_selects_subset_in_manifest_order(env):
    m = env.manifest("m.yaml", [env.case(f"c{i}", f"CVE-2024-000{i}") for i in range(1, 5)])
    assert env.run("--manifest", str(m), "--case", "c3", "--case", "c1", "--batch-id", "b", "--no-zip") == 0
    _batch_dir, manifest, summary = env.batch("b")
    assert [c["id"] for c in manifest["cases"]] == ["c1", "c3"]
    assert summary["counts"]["requested"] == 2


def test_anomalies_are_visible_but_do_not_fail_the_case(env):
    kinds = ["mutate_repo", "count_mismatch", "summary_mismatch", "commit_mismatch"]
    cases = [env.case(k.replace("_", "-"), f"CVE-2024-000{i}") for i, k in enumerate(kinds, 1)]
    env.scenarios({c["cve"]: {"kind": k} for c, k in zip(cases, kinds, strict=True)})
    m = env.manifest("m.yaml", cases)
    assert env.run("--manifest", str(m), "--batch-id", "b", "--no-zip") == 0
    summary = env.batch("b")[2]
    rows = rows_by_id(summary)
    assert all(r["category"] == "ORANGE" for r in rows.values())
    assert any("modified during the run" in a for a in rows["mutate-repo"]["anomalies"])
    assert any("checkpoints.jsonl records" in a for a in rows["count-mismatch"]["anomalies"])
    assert any("token/cost figures ignored" in a for a in rows["summary-mismatch"]["anomalies"])
    assert rows["summary-mismatch"]["tokens"] is None
    assert any("OpenAnt commit" in a for a in rows["commit-mismatch"]["anomalies"])
    assert len(summary["anomalies"]) >= 4


def test_timeout_kills_the_case(env):
    m = env.manifest("m.yaml", [env.case("hang", "CVE-2024-0001")])
    env.scenarios({"CVE-2024-0001": {"kind": "hang"}})
    started = time.monotonic()
    assert env.run("--manifest", str(m), "--batch-id", "b", "--case-timeout-minutes", "0.03", "--no-zip") == 1
    assert time.monotonic() - started < 30
    row = rows_by_id(env.batch("b")[2])["hang"]
    assert row["failure_kind"] == "timeout"
    pid = env.invocations()[0]["pid"]
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_jobs_above_validated_maximum_warns(env, capsys):
    m = env.manifest("m.yaml", [env.case("one", "CVE-2024-0001")])
    warning = f"above the experimentally validated maximum of {rcb.VALIDATED_MAX_JOBS}"
    at_max = str(rcb.VALIDATED_MAX_JOBS)
    assert env.run("--manifest", str(m), "--batch-id", "at", "--jobs", at_max, "--no-zip") == 0
    assert warning not in capsys.readouterr().out
    assert env.batch("at")[1]["sessions"][0]["jobs_validated"] is True
    above_max = str(rcb.VALIDATED_MAX_JOBS + 1)
    assert env.run("--manifest", str(m), "--batch-id", "above", "--jobs", above_max, "--no-zip") == 0
    assert warning in capsys.readouterr().out
    assert env.batch("above")[1]["sessions"][0]["jobs_validated"] is False


def test_existing_batch_dir_and_held_lock_are_refused(env, capsys):
    m = env.manifest("m.yaml", [env.case("one", "CVE-2024-0001")])
    assert env.run("--manifest", str(m), "--batch-id", "b", "--no-zip") == 0
    assert env.run("--manifest", str(m), "--batch-id", "b") == 2
    assert "already exists" in capsys.readouterr().err
    batch_dir = env.batch("b")[0]
    with rcb.BatchLock(rcb.BatchLayout(batch_dir)):
        assert env.run("--summarize", str(batch_dir)) == 2
    assert "in use by another runner" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# ZIP
# ---------------------------------------------------------------------------

def test_zip_contents_exclusions_and_secret_scan(env, monkeypatch, capsys):
    monkeypatch.setenv("FAKE_LEAK_TOKEN", "sk-test-THIS-IS-A-FAKE-SECRET-123456")
    cases = [env.case("normal", "CVE-2024-0001"), env.case("leaky", "CVE-2024-0002")]
    env.scenarios({"CVE-2024-0001": {"kind": "investigation"}, "CVE-2024-0002": {"kind": "leak_secret"}})
    m = env.manifest("m.yaml", cases)
    assert env.run("--manifest", str(m), "--batch-id", "zb") == 0
    batch_dir, manifest, _summary = env.batch("zb")
    zip_path = batch_dir / "zb-results.zip"
    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())
        contents = json.loads(zf.read("zb/zip_contents.json"))
    assert all(n.startswith("zb/") for n in names)
    a1 = "zb/cases/normal/attempt-01"
    for expected in ("zb/batch_manifest.json", "zb/batch_summary.md", "zb/batch_summary.json",
                     "zb/batch_results.csv", "zb/logs/batch.log", "zb/inputs/01-m.yaml", "zb/zip_contents.json",
                     "zb/cases/normal/case.json", f"{a1}/result.json", f"{a1}/command.json", f"{a1}/stdout.log",
                     f"{a1}/stderr.log", f"{a1}/output/trace/run_manifest.json", f"{a1}/output/trace/checkpoints.jsonl",
                     f"{a1}/output/patch/CVE-2024-0001-trust-report.md",
                     f"{a1}/cwd/reports/debug/context_selection_CVE-2024-0001.json"):
        assert expected in names, expected
    assert not any("/repo/" in n or "/.git/" in n or n.endswith("/repo") for n in names)
    assert not any("-investigation/" in n for n in names)
    assert "zb/cases/leaky/attempt-01/cwd/reports/debug/context_selection_CVE-2024-0002.json" not in names
    assert contents["excluded_investigation_files"][0]["path"].endswith("dataset.json")
    assert any("credential value" in w for w in contents["warnings"])
    assert manifest["packaging"]["size_bytes"] == zip_path.stat().st_size
    out = capsys.readouterr().out
    assert "sk-test-THIS-IS-A-FAKE-SECRET" not in out
    # The uncompressed batch is untouched (checkouts included).
    assert (batch_dir / "cases" / "normal" / "attempt-01" / "repo" / "app.py").exists()

    assert env.run("--summarize", str(batch_dir), "--zip-include-investigation") == 0
    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())
    assert f"{a1}/output/patch/CVE-2024-0001-investigation/dataset.json" in names


# ---------------------------------------------------------------------------
# Resume
# ---------------------------------------------------------------------------

def test_resume_skips_completed_and_reruns_failures_only_on_request(env, capsys):
    cases = [env.case("ok", "CVE-2024-0001"), env.case("flaky", "CVE-2024-0002")]
    env.scenarios({"CVE-2024-0002": {"kind": "rate_limit"}})
    m = env.manifest("m.yaml", cases)
    assert env.run("--manifest", str(m), "--batch-id", "r", "--no-zip") == 1
    batch_dir = env.batch("r")[0]
    assert len(env.invocations()) == 2

    assert env.run("--resume", str(batch_dir), "--no-zip") == 1
    out = capsys.readouterr().out
    assert "keep failure (provider_rate_limit)" in out and "skip: completed (ORANGE)" in out
    assert len(env.invocations()) == 2  # nothing reran
    assert env.batch("r")[1]["sessions"][1]["scheduled_cases"] == []

    env.scenarios({})
    assert env.run("--resume", str(batch_dir), "--rerun-failed", "--no-zip") == 0
    # The first session ran both cases concurrently, so only the multiset is stable.
    assert sorted(r["cve"] for r in env.invocations()) == ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0002"]
    _batch_dir, manifest, summary = env.batch("r")
    rows = rows_by_id(summary)
    assert rows["flaky"]["category"] == "ORANGE" and rows["flaky"]["attempts"] == 2
    assert [a["status"] for a in rows["flaky"]["all_attempts"]] == ["failed", "completed"]
    assert (batch_dir / "cases" / "flaky" / "attempt-01" / "result.json").exists()  # never deleted
    assert rows["ok"]["attempts"] == 1
    assert [s["kind"] for s in manifest["sessions"]] == ["initial", "resume", "resume"]


def test_resume_reruns_incomplete_and_invalid_completions(env, capsys):
    cases = [env.case(f"c{i}", f"CVE-2024-000{i}") for i in (1, 2, 3)]
    m = env.manifest("m.yaml", cases)
    assert env.run("--manifest", str(m), "--batch-id", "r", "--no-zip") == 0
    batch_dir = env.batch("r")[0]
    crashed = batch_dir / "cases" / "c1" / "attempt-01" / "result.json"
    data = json.loads(crashed.read_text())
    data["status"] = "running"  # what a hard-killed runner leaves behind
    crashed.write_text(json.dumps(data))
    (batch_dir / "cases" / "c2" / "attempt-01" / "output" / "patch" / "CVE-2024-0002-trust-report.md").unlink()

    assert env.run("--summarize", str(batch_dir), "--no-zip") == 3  # incomplete until resumed
    capsys.readouterr()
    assert env.run("--resume", str(batch_dir), "--validate-only") == 0
    out = capsys.readouterr().out
    assert "RUN: incomplete" in out and "RUN: invalid" in out and "skip: completed (ORANGE)" in out
    assert len(env.invocations()) == 3

    assert env.run("--resume", str(batch_dir), "--no-zip") == 0
    rows = rows_by_id(env.batch("r")[2])
    assert (rows["c1"]["attempts"], rows["c2"]["attempts"], rows["c3"]["attempts"]) == (2, 2, 1)
    assert all(r["category"] == "ORANGE" for r in rows.values())


def test_resume_refuses_changed_openant_code_unless_allowed(env, capsys):
    m = env.manifest("m.yaml", [env.case("one", "CVE-2024-0001")])
    assert env.run("--manifest", str(m), "--batch-id", "r", "--no-zip") == 0
    batch_dir, manifest, _summary = env.batch("r")
    manifest["sessions"][0]["openant"]["fingerprint"] = "0" * 64
    (batch_dir / "batch_manifest.json").write_text(json.dumps(manifest))
    assert env.run("--resume", str(batch_dir), "--no-zip") == 2
    assert "resuming would mix code versions" in capsys.readouterr().err
    assert env.run("--resume", str(batch_dir), "--no-zip", "--allow-openant-change") == 0


def test_resume_refuses_semantic_overrides(env, capsys):
    m = env.manifest("m.yaml", [env.case("one", "CVE-2024-0001")])
    assert env.run("--manifest", str(m), "--batch-id", "r", "--no-zip") == 0
    batch_dir = env.batch("r")[0]
    assert env.run("--resume", str(batch_dir), "--blind-filter-policy", "v2") == 2
    assert "cannot change on resume" in capsys.readouterr().err


def test_interrupt_then_resume(env):
    cases = [env.case("a", "CVE-2024-0001"), env.case("b", "CVE-2024-0002", repo="gadget")]
    env.scenarios({c["cve"]: {"sleep": 120} for c in cases})
    m = env.manifest("m.yaml", cases)
    proc = subprocess.Popen(
        [sys.executable, str(TOOLS_DIR / "run_cve_batch.py"), "--manifest", str(m), "--batch-id", "irq",
         "--batch-root", str(env.batch_root), "--run-traced", str(env.fake), "--heartbeat-seconds", "0",
         "--jobs", "2"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        deadline = time.monotonic() + 60
        while len(env.invocations()) < 2 and time.monotonic() < deadline:
            time.sleep(0.2)
        assert len(env.invocations()) == 2, "both cases should be running"
        proc.send_signal(signal.SIGINT)
        output, _ = proc.communicate(timeout=60)
    finally:
        if proc.poll() is None:
            proc.kill()
    assert proc.returncode == 130, output
    assert "INTERRUPT" in output
    batch_dir, _manifest, summary = env.batch("irq")
    assert summary["status"] == "INTERRUPTED"
    assert {r["status"] for r in summary["cases"]} == {"interrupted"}
    assert not (batch_dir / "irq-results.zip").exists()
    for inv in env.invocations():
        with pytest.raises(ProcessLookupError):
            os.kill(inv["pid"], 0)

    env.scenarios({})
    # The interrupted session ran in a subprocess with the REAL OpenAnt state;
    # this process uses the deterministic stub, so the fingerprints differ by
    # construction (that check has its own test).
    assert env.run("--resume", str(batch_dir), "--allow-openant-change") == 0
    _batch_dir, manifest, summary = env.batch("irq")
    assert summary["status"] == "COMPLETE"
    assert [r["attempts"] for r in summary["cases"]] == [2, 2]
    assert [s["result"] for s in manifest["sessions"]] == ["interrupted", "complete"]
    assert (batch_dir / "irq-results.zip").exists()


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def test_parse_trust_report_real_formats(tmp_path):
    orange = tmp_path / "orange.md"
    orange.write_text(
        "# Auto Patcher MVP — Security Patch Report\n\n## 🟠 MANUAL REVIEW REQUIRED\n\nPatch applies cleanly.  \n"
        "This is not a signal to deploy.  \nFiles changed: 1\n\n---\n\n## Recommendation\n\n"
        "**Manual Review Required**\n\nThe available evidence was insufficient.\n", encoding="utf-8")
    info = rcb.parse_trust_report(orange)
    assert (info["outcome"], info["decision"], info["files_changed"]) == ("ORANGE", "Manual Review Required", 1)
    assert info["parse_error"] is None and info["inconsistency"] is None

    gray = tmp_path / "gray.md"
    gray.write_text(
        "# Auto Patcher MVP — Security Patch Report\n\n## ⚫ NO PATCH PRODUCED\n\nFiles changed: 0\n\n---\n\n"
        "## Patch Applicability\n\n*(Skipped — planning_ungrounded: ungrounded_unresolvable.)*\n", encoding="utf-8")
    info = rcb.parse_trust_report(gray)
    assert info["outcome"] == "GRAY" and info["applicability_skip_reason"] == "planning_ungrounded: ungrounded_unresolvable"

    wrong_emoji = tmp_path / "wrong.md"
    wrong_emoji.write_text("# T\n\n## 🟢 DO NOT APPLY\n\n## Recommendation\n\n**Do Not Apply**\n", encoding="utf-8")
    assert "emoji" in rcb.parse_trust_report(wrong_emoji)["inconsistency"]
    assert rcb.parse_trust_report(tmp_path / "absent.md")["present"] is False


def test_trace_summary_error_kind_percent_and_retry_detection():
    usage = rcb.parse_trace_summary("noise\nTrace Summary\n────\nLLM calls      7\nTokens         123,393\nCost           $0.77\n")
    assert (usage["llm_calls"], usage["tokens"], usage["cost_usd"]) == (7, 123393, 0.77)
    assert rcb.parse_trace_summary("no summary here") is None
    assert rcb.error_kind("BlindEvaluationError", "x") == "blind_evaluation_aborted"
    assert rcb.error_kind("utilities.llm.adapter.LLMRateLimitError", "x") == "provider_rate_limit"
    # llm_client.call_llm wraps every adapter LLMError like this:
    assert rcb.error_kind("RuntimeError", "Anthropic API call failed: Error code: 529 - "
                                          "{'error': {'type': 'overloaded_error'}}") == "provider_rate_limit"
    assert rcb.error_kind("RuntimeError", "Anthropic API call failed: Error code: 500 - x") == "provider_error"
    assert rcb.error_kind("RuntimeError", "No usable credential for provider 'anthropic' (...)") == "provider_error"
    assert rcb.error_kind("RuntimeError", "LLM_MODEL='x' is no longer used") == "provider_error"
    assert rcb.error_kind("LLMAuthError", "bad key") == "provider_error"
    # Rate-limit wording outside a provider failure is not a provider rate limit.
    assert rcb.error_kind("CVEFetchError", "NVD returned HTTP 429 Too Many Requests") == "advisory_fetch_failed"
    assert rcb.error_kind("ValueError", "please add rate-limit handling") == "run_traced_exception"
    assert rcb.error_kind("RuntimeError", "boom: Error code: 429") == "run_traced_exception"
    assert rcb.error_kind("ValueError", "line 429 of a file") == "run_traced_exception"
    assert rcb.percent(1, 3) == 33.33 and rcb.percent(0, 0) is None
    assert rcb._sum_or_none([0, None, 0]) == 0 and rcb._sum_or_none([None]) is None
    facts = rcb.derived_run_facts(
        {"checkpoint_stages": ["remediation_planning", "remediation_planning_reattempt", "patch_generation",
                               "patch_generation_contract_retry", "challenger", "challenger"],
         "llm_call_count": 6, "executions": []}, None, "ORANGE")
    assert facts["retry_like_llm_calls"] == ["remediation_planning_reattempt", "patch_generation_contract_retry",
                                             "challenger (repeat)"]


# ---------------------------------------------------------------------------
# Regressions from the independent review
# ---------------------------------------------------------------------------

def test_wrapper_case_narrows_within_the_37_and_rejects_others(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    assert wrapper.main(["--case", "opendiamond-cve-2022-31506", "--validate-only",
                         "--results-root", str(tmp_path / "b")]) == 0
    assert "VALID: 1 case(s)" in capsys.readouterr().out
    assert wrapper.main(["--case", "jupyter-notebook-cve-2020-26215", "--validate-only"]) == 2
    assert "is not one of the 37 PatchEval expansion cases" in capsys.readouterr().err


def test_trust_report_parser_matches_the_real_pipeline_renderers(tmp_path):
    """Built from pipeline.py's own renderers, so a format change there fails
    here instead of silently misclassifying a batch. The fenced diff carries
    look-alike headings (a patched Markdown file) that must be ignored."""
    from utilities.autopatcher import pipeline

    signals = {"patch_integrity": {"value": "Clean"}}
    # A patched Markdown file: its diff context includes a bare " ```" line
    # (must not close the fence) and look-alike headings (must be ignored).
    decoy = ("## Proposed patch\n\n```diff\n--- a/README.md\n+++ b/README.md\n@@ -1,4 +1,5 @@\n ```\n"
             " ## Recommendation\n+## 🟢 DEPLOY AFTER VALIDATION\n+**Do Not Apply**\n ```\n```\n\n")
    for outcome in rcb.OUTCOMES:
        if outcome.patch_produced:
            recommendation = {"decision": outcome.decision, "reason": "Because."}
            card = pipeline._render_decision_card(recommendation, signals, [], ["app.py"])
            rec_block = pipeline._render_recommendation_block(recommendation)
        else:
            card, rec_block = pipeline._render_no_patch_card([]), ""
        path = tmp_path / f"{outcome.key}.md"
        path.write_text("# Auto Patcher MVP — Security Patch Report\n\n" + card + "\n" + decoy + rec_block,
                        encoding="utf-8")
        info = rcb.parse_trust_report(path)
        assert (info["outcome"], info["decision"], info["parse_error"], info["inconsistency"]) == \
               (outcome.key, outcome.decision, None, None), info


def test_indented_heading_lookalike_is_not_a_section(tmp_path):
    path = tmp_path / "r.md"
    path.write_text("# T\n\n## 🟢 DEPLOY AFTER VALIDATION\n\nFiles changed: 1\n\n## Proposed patch\n\n"
                    " ## Recommendation\n\n**Do Not Apply**\n\n## Recommendation\n\n**Deploy After Validation**\n",
                    encoding="utf-8")
    info = rcb.parse_trust_report(path)
    assert info["outcome"] == "GREEN" and info["inconsistency"] is None


def test_llm_model_is_refused(env, capsys, monkeypatch):
    monkeypatch.setenv("LLM_MODEL", "claude-x")
    m = env.manifest("m.yaml", [env.case("one", "CVE-2024-0001")])
    assert env.run("--manifest", str(m)) == 2
    assert "LLM_MODEL='claude-x'" in capsys.readouterr().err
    assert not env.batch_root.exists()


def test_yaml_merge_keys_are_supported(env, capsys):
    url, shas = env.repo("widget")
    path = env.tmp / "merge.yaml"
    path.write_text(
        "cases:\n"
        f"  - &first\n    id: one\n    repo: {url}\n    cve: CVE-2024-0001\n    sha: {shas[0]}\n    language: Python\n"
        f"  - <<: *first\n    id: two\n    cve: CVE-2024-0002\n    sha: {shas[1]}\n"
    )
    assert env.run("--manifest", str(path), "--validate-only") == 0
    assert "VALID: 2 case(s)" in capsys.readouterr().out


def test_resume_refuses_a_tampered_run_configuration(env, capsys):
    m = env.manifest("m.yaml", [env.case("one", "CVE-2024-0001")])
    assert env.run("--manifest", str(m), "--batch-id", "r", "--no-zip") == 0
    batch_dir, manifest, _summary = env.batch("r")
    manifest["run_config"]["run_traced_flags"].remove("--blind-strip-same-repo-github-references")
    (batch_dir / "batch_manifest.json").write_text(json.dumps(manifest))
    assert env.run("--resume", str(batch_dir), "--no-zip") == 2
    assert "no longer describes the canonical evaluation setup" in capsys.readouterr().err


def test_zip_holds_the_final_session_record(env):
    m = env.manifest("m.yaml", [env.case("one", "CVE-2024-0001")])
    assert env.run("--manifest", str(m), "--batch-id", "zz") == 0
    with zipfile.ZipFile(env.batch("zz")[0] / "zz-results.zip") as zf:
        session = json.loads(zf.read("zz/batch_summary.json"))["sessions"][0]
        md = zf.read("zz/batch_summary.md").decode("utf-8")
    assert (session["result"], session["exit_code"]) == ("complete", 0)
    assert "· running" not in md and "**Status: COMPLETE**" in md


def test_openant_change_during_a_session_is_flagged(env, capsys):
    env.openant_fingerprints = ["a" * 64, "b" * 64]  # session start sees A, everything later sees B
    m = env.manifest("m.yaml", [env.case("one", "CVE-2024-0001")])
    assert env.run("--manifest", str(m), "--batch-id", "oc", "--no-zip") == 0
    out = capsys.readouterr().out
    _batch_dir, manifest, summary = env.batch("oc")
    assert summary["openant"]["changed_during_batch"] is True
    assert summary["openant"]["cases_run_on_changed_code"] == ["one"]
    assert manifest["sessions"][0]["openant_end"]["changed_during_session"] is True
    assert any("OpenAnt work tree differed" in a for a in rows_by_id(summary)["one"]["anomalies"])
    assert "OpenAnt code changed during the batch" in out


def test_interrupt_cannot_be_swallowed_by_except_exception():
    assert issubclass(rcb.BatchInterrupted, BaseException)
    assert not issubclass(rcb.BatchInterrupted, Exception)


def test_stop_state_at_exit_decides_interrupted_versus_failed(tmp_path):
    base = dict(case={"id": "x", "cve": "CVE-2024-0001", "sha": "0" * 40},
                paths=rcb.attempt_paths(tmp_path / "attempt-01"), run_config={}, openant_head=None,
                checkout={"failure_kind": None}, run_manifest={"present": False}, trust_report=None,
                stderr_text="Traceback (most recent call last):\nRuntimeError: boom")
    genuine = rcb.classify_attempt(**base, execution={"exit_code": 1, "timed_out": False}, stop_requested=False)
    assert (genuine["status"], genuine["failure_kind"]) == ("failed", "run_traced_crashed")
    stopped = rcb.classify_attempt(**base, execution={"exit_code": -2, "timed_out": False}, stop_requested=True)
    assert stopped["status"] == "interrupted"
    finished = rcb.classify_attempt(**base, execution={"exit_code": 0, "timed_out": False}, stop_requested=True)
    assert finished["failure_kind"] == "run_manifest_missing"  # a run that exited 0 is judged on evidence


def test_broken_run_traced_environment_aborts_before_any_checkout(env, capsys):
    broken = env.tmp / "broken_run_traced.py"
    broken.write_text("raise SystemExit(3)\n")
    m = env.manifest("m.yaml", [env.case("one", "CVE-2024-0001")])
    code = rcb.main(["--manifest", str(m), "--run-traced", str(broken), "--batch-root", str(env.batch_root)])
    assert code == 2
    assert "--help` failed with exit 3" in capsys.readouterr().err
    assert not env.batch_root.exists()


def test_real_openant_state_shape():
    state = rcb.collect_openant_state()
    assert len(state["head"]) == 40 and len(state["fingerprint"]) == 64
    assert isinstance(state["_diff"], bytes) and isinstance(state["dirty"], bool)


def test_batch_root_inside_the_openant_tree_is_refused_unless_ignored(env, capsys):
    tree = env.tmp / "openant-tree"
    tree.mkdir()
    env.git("init", "-q", cwd=tree)
    (tree / ".gitignore").write_text("ignored/\n")
    env.openant_work_tree = str(tree.resolve())
    m = env.manifest("m.yaml", [env.case("one", "CVE-2024-0001")])
    assert rcb.main(["--manifest", str(m), "--run-traced", str(env.fake), "--validate-only",
                     "--batch-root", str(tree / "batches")]) == 2
    assert "inside the OpenAnt work tree" in capsys.readouterr().err
    assert rcb.main(["--manifest", str(m), "--run-traced", str(env.fake), "--validate-only",
                     "--batch-root", str(tree / "ignored" / "batches")]) == 0


def test_pipeline_import_probe_runs_for_the_canonical_run_traced(env, monkeypatch, capsys):
    """For the canonical run_traced.py the pre-flight also imports what it
    loads lazily (core.patch, the pipeline). OpenAnt is installed editable on
    dev machines, so the failure path is exercised by probing a module that
    cannot exist; a failing probe must stop the batch before any checkout."""
    monkeypatch.setattr(rcb, "RUN_TRACED", env.fake)  # treat the fake as the canonical script
    monkeypatch.setattr(rcb, "LAZY_IMPORT_PROBE", ("no_such_module_for_batch_probe",))
    m = env.manifest("m.yaml", [env.case("one", "CVE-2024-0001")])
    assert env.run("--manifest", str(m)) == 2
    assert "cannot import no_such_module_for_batch_probe" in capsys.readouterr().err
    assert not env.batch_root.exists()
    assert env.invocations() == []
