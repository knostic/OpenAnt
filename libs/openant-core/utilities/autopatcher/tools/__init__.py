"""Developer/debug tooling for Auto Patcher: full-run tracing (run_traced.py)
and single-stage debug replay (run_stage.py).

Not part of the production pipeline import graph -- utilities.autopatcher.
pipeline never imports anything from this package, and nothing here is
imported by it. Both scripts are run directly (``python3.12
utilities/autopatcher/tools/run_traced.py ...``), not invoked via ``python
-m``; this package's only purpose is to give them a normal, tracked,
importable home next to the Auto Patcher subsystem they debug, instead of
a generic gitignored scratch directory.

See TRACING_AND_DEBUGGING.md in this same directory for the full workflow.
"""
