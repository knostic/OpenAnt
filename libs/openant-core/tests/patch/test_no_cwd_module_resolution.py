"""PR #763 review (blocker): importing the Auto Patcher pipeline must never
execute code from the analyzed repository.

`pipeline.py` used to `import scripts.constraint_signals` /
`scripts.remediation_signals` -- modules OpenAnt never shipped -- so the only
thing that could satisfy the import was a `scripts/` directory on sys.path,
e.g. the analyzed repository when `python -m openant patch` ran with the CWD
inside it.
"""

import ast
import os
import subprocess
import sys
from pathlib import Path

CORE_ROOT = Path(__file__).resolve().parents[2]

_PLANT = (
    "from pathlib import Path\n"
    "Path(__file__).with_name('MARKER_' + __name__.rsplit('.', 1)[-1]).write_text('x')\n"
    "def run_constraint_signals(*a, **k): return [{'injected': True}]\n"
    "def run_remediation_signals(*a, **k): return [{'injected': True}]\n"
)


def _hostile_repo(tmp_path):
    repo = tmp_path / "analyzed"
    (repo / "scripts").mkdir(parents=True)
    for name in ("constraint_signals", "remediation_signals"):
        (repo / "scripts" / f"{name}.py").write_text(_PLANT)
    return repo


def _run_in(repo, code):
    # CWD = analyzed repo and sys.path[0] = CWD, exactly as `python -m` /
    # `python -c` arrange it; the core is reachable via PYTHONPATH.
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=repo,
        env={
            **{k: v for k, v in os.environ.items() if k != "PYTHONSAFEPATH"},
            "PYTHONPATH": str(CORE_ROOT),
        },
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_pipeline_import_does_not_execute_repo_scripts(tmp_path):
    repo = _hostile_repo(tmp_path)
    proc = _run_in(
        repo,
        "import sys, utilities.autopatcher.pipeline as p\n"
        "print(p._STATIC_SIGNALS_AVAILABLE, 'scripts.constraint_signals' in sys.modules,"
        " p._run_constraint_signals('', None))\n",
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == ["False", "False", "[]"]
    assert not list((repo / "scripts").glob("MARKER_*"))


def test_planted_module_is_importable_from_that_cwd(tmp_path):
    # Positive control: the plant really is reachable from that CWD, so the
    # test above would have caught the old import.
    repo = _hostile_repo(tmp_path)
    proc = _run_in(repo, "import scripts.constraint_signals\n")
    assert proc.returncode == 0, proc.stderr
    assert (repo / "scripts" / "MARKER_constraint_signals").exists()


def test_no_production_module_imports_a_scripts_package():
    offenders = []
    for base in ("core", "utilities", "openant"):
        for path in (CORE_ROOT / base).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    names = [node.module]
                elif isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                if any(n == "scripts" or n.startswith("scripts.") for n in names):
                    offenders.append(f"{path.relative_to(CORE_ROOT)}:{node.lineno}")
    assert offenders == []
