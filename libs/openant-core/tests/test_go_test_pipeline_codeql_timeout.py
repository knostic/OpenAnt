"""Regression: go test_pipeline CodeQL stage timeouts must not be inverted.

The CodeQL `database create` step (which COMPILES the source — the slower stage for compiled languages)
was given timeout=600s while `database analyze` got 1800s. The slower stage with the smaller budget times
out first; on timeout run_codeql_analysis records the codeql stage success=False and returns, the pipeline
prints "continuing with reachable units only" and proceeds, and apply_codeql_filter is skipped — so the
written dataset is reachable-only with CodeQL findings dropped. (The run reports success=False / exit 1, so
an exit-code CI gate still catches it; the harm is the silently-degraded artifact for any consumer that
reads the results rather than the exit code.) The create budget must be at least the analyze budget.

This reads the source (the timeout values are module constants) rather than importing test_pipeline, which
does module-level sys.path manipulation and shares its module name with the other parsers' test_pipeline.py.
"""
import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "parsers" / "go" / "test_pipeline.py"


def _const(name: str) -> int:
    m = re.search(rf"^{name}\s*=\s*(\d+)", SRC.read_text(), re.M)
    assert m, f"{name} constant not found in {SRC}"
    return int(m.group(1))


def test_codeql_db_create_timeout_not_less_than_analyze():
    create = _const("CODEQL_DB_CREATE_TIMEOUT_SECS")
    analyze = _const("CODEQL_ANALYZE_TIMEOUT_SECS")
    assert create >= analyze, (
        f"codeql DB-create timeout ({create}s) < analyze timeout ({analyze}s): the slower "
        f"compile-the-DB stage gets the smaller budget, so it times out first, the stage is "
        f"recorded failed, and the pipeline writes a reachable-only dataset with CodeQL findings "
        f"dropped"
    )


def test_codeql_timeouts_are_wired_to_the_constants():
    """The create/analyze subprocess calls must USE the constants, not inline literals — otherwise a
    future edit could revert a call site to timeout=600 while the constant stays 1800 and the value
    check above would still pass green. Pre-fix the call sites passed literal timeouts (no constants
    existed), so these assertions are RED before the fix and GREEN after — they lock the wiring, not
    just the values."""
    src = SRC.read_text()
    assert "timeout=CODEQL_DB_CREATE_TIMEOUT_SECS" in src, (
        "codeql `database create` must pass timeout=CODEQL_DB_CREATE_TIMEOUT_SECS, not an inline "
        "literal — otherwise the create budget can silently drift below analyze again"
    )
    assert "timeout=CODEQL_ANALYZE_TIMEOUT_SECS" in src, (
        "codeql `database analyze` must pass timeout=CODEQL_ANALYZE_TIMEOUT_SECS, not an inline "
        "literal"
    )
