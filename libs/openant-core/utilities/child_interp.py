"""#303: deterministic child-interpreter resolution.

The managed runtime is a single shared venv whose editable-install ``.pth``
points at exactly one ``openant-core`` checkout at a time, and a scan
re-points it to whichever clone is running (the anti-contamination mechanism
in ``apps/openant-cli/internal/python/runtime.go``). A scan also spawns child
Python interpreters *while it runs* — the per-language parser and the report
writers — and each resolves ``openant`` through that ``.pth`` at spawn time.
If a second session re-points the venv mid-scan, the first scan's later
children import a different checkout than their own parent did, silently.

The fix (the issue's suggestion 3): every child spawn passes an explicit
``PYTHONPATH`` holding the PARENT's resolved core root. ``PYTHONPATH`` entries
precede site-packages in ``sys.path``, so the ``.pth`` target cannot win —
the child resolves the parent's checkout by construction. The resolved path
is also recorded in ``scan.report.json`` (suggestion 1) so any residual skew
is detectable after the fact.
"""

from __future__ import annotations

import os
from pathlib import Path


def resolved_core_path() -> Path:
    """The openant-core root THIS interpreter resolved (not the ``.pth``).

    ``openant.__file__`` reflects whatever resolution produced this process —
    the editable target under the shared venv, a dev checkout under
    PYTHONPATH, or an installed wheel. Its parent directory IS the core root
    that produced this scan, which is exactly the provenance to hand to
    children and to record in the aggregate report.
    """
    import openant  # local import: avoids cycles at module import time
    return Path(openant.__file__).resolve().parents[1]


def child_interpreter_env() -> dict:
    """An env dict for child interpreters: the parent's core root prepended.

    ``PYTHONPATH`` precedes site-packages in the child's ``sys.path``, so the
    shared venv's editable ``.pth`` (which a concurrent session may re-point
    mid-scan) cannot redirect the child to a different checkout. Existing
    ``PYTHONPATH`` entries are preserved AFTER the core root. Returns a copy —
    the parent's environment is never mutated.
    """
    env = dict(os.environ)
    core = str(resolved_core_path())
    existing = env.get("PYTHONPATH", "")
    if existing:
        env["PYTHONPATH"] = f"{core}{os.pathsep}{existing}"
    else:
        env["PYTHONPATH"] = core
    return env
