"""#323: the blackout advisory reaches a deterministic surface.

When entry-point detection finds no seeds, `blackout_warning` fires. The advisory was written to
parse-stage stderr and `metadata.reachability_filter.warning`, and reached
`pipeline_stats.reachability_warnings` in pipeline_output.json — but NO deterministic
human- or CI-visible surface: the Go CLI's terminal summary never printed it, the exit
envelope did not carry it, and the only rendering in SUMMARY_REPORT.md was an *instruction to
an LLM* (model-discretionary). Two merged PRs (#233, #238) name this exact gap as a
deliberately-deferred follow-up.

The fix (the issue's suggestions):
- the advisory renders deterministically alongside `_context_provenance_header` (the same
  class of disclosure — "the scan may have covered nothing" — must not be suppressable by
  steering the report prompt);
- the Go CLI's `PrintScanSummaryV2` prints a reachable/original/reduction line and the
  warnings;
- the CLI exit envelope carries a `reachability` block so CI can read it without parsing
  report prose.
"""
import json
import shutil
import sys
from pathlib import Path

import pytest

CORE = str(Path(__file__).resolve().parents[2])  # libs/openant-core
if CORE not in sys.path:
    sys.path.insert(0, CORE)

from report.generator import _reachability_header  # noqa: E402


_PO_NO_WARNING = {
    "pipeline_stats": {
        "total_units": 10,
        "reachable_units": 3,
        "original_units": 10,
        "reachability_filter_applied": True,
        "reachability_reduction_percentage": 70.0,
        "reachability_warnings": [],
    }
}

_PO_BLACKOUT = {
    "pipeline_stats": {
        "total_units": 120,
        "reachable_units": 120,
        "original_units": 120,
        "reachability_filter_applied": True,
        "reachability_reduction_percentage": None,
        "reachability_warnings": [
            "entry-point seeding found no seeds in this repository; the "
            "reachability filter was blacked out and ALL units were kept"
        ],
    }
}


def test_blackout_warning_renders_deterministically():
    """The issue's headline: the only rendering was an LLM instruction
    (model-discretionary). The deterministic header renders the blackout
    advisory from pipeline_output.json fields — the report-prompt steering
    class the provenance banner already guards against."""
    header = _reachability_header(_PO_BLACKOUT)
    assert header != "", "the blackout advisory must render deterministically"
    low = header.lower()
    assert "blacked out" in low or "no seeds" in low


def test_no_warning_no_banner():
    """A clean run keeps the header silent (an un-filtered scan is not
    disclosed as warned)."""
    assert _reachability_header(_PO_NO_WARNING) == ""


def test_header_carries_the_counts():
    """The header includes the reachable/original counts (the operator sees
    the scope, not just the warning)."""
    header = _reachability_header(_PO_BLACKOUT)
    assert "120" in header


def test_go_formatter_prints_the_reachability_line():
    """The Go CLI's terminal summary: a Reachability line (reachable /
    original / reduction %) + the warnings. Drives the real
    PrintScanSummaryV2 with the envelope's data map shape."""
    import re
    import subprocess
    import tempfile

    src = Path(__file__).resolve().parents[3] / "apps" / "openant-cli"
    if not shutil.which("go"):
        pytest.skip("Go toolchain not available")
    # the python-test CI runners carry a PATH `go` OLDER than the module's
    # directive (ubuntu: 1.21 vs go.mod's 1.25.8, GOTOOLCHAIN=local) — skip
    # rather than fail: the Go CI jobs exercise the package with a proper
    # toolchain.
    ver = subprocess.run(["go", "version"], capture_output=True, text=True).stdout
    vm = re.search(r"go(\d+(?:\.\d+)+)", ver)
    want = re.search(r"^go\s+(\d+(?:\.\d+)*)",
                     (src / "go.mod").read_text(), re.M)

    def _vt(v):
        return tuple(int(x) for x in v.split("."))
    if vm and want and _vt(vm.group(1)) < _vt(want.group(1)):
        pytest.skip(f"go {vm.group(1)} older than the module's go {want.group(1)}")
    # wave r1: the package is COPIED to a temp dir — a SIGKILL/timeout mid-run
    # can no longer leave a stray _test.go in the source tree (the repo's
    # conformance/test_F1 precedent).
    go_out = Path(tempfile.mkdtemp()) / "pkg"
    shutil.copytree(src, go_out,
                    ignore=shutil.ignore_patterns("__pycache__", "node_modules",
                                                  "*.pyc"))
    probe = '''
package output

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/fatih/color"
)

func TestReachabilityLineZZ(t *testing.T) {
	data := map[string]any{}
	json.Unmarshal([]byte(`{
		"metrics": {"total": 3, "vulnerable": 0, "bypassable": 0, "protected": 0, "safe": 3, "inconclusive": 0, "errors": 0},
		"reachability": {"reachable_units": 120, "original_units": 120,
			"reachability_reduction_percentage": 33.3,
			"reachability_warnings": ["entry-point seeding found no seeds; the filter was blacked out"]}
	}`), &data)
	var buf bytes.Buffer
	oldOut := os.Stdout
	oldColor := color.Output
	r, w, _ := os.Pipe()
	os.Stdout = w
	color.Output = w
	PrintScanSummaryV2(data)
	w.Close()
	os.Stdout = oldOut
	color.Output = oldColor
	buf.ReadFrom(r)
	out := buf.String()
	if !strings.Contains(out, "Reachability") {
		t.Fatalf("no reachability line: %q", out)
	}
	if !strings.Contains(out, "120 of 120 units in scope (33.3% reduction)") {
		t.Fatalf("the counts/pct missing: %q", out)
	}
	if !strings.Contains(out, "blacked out") {
		t.Fatalf("the warning missing: %q", out)
	}
}
'''
    tfile = go_out / "internal" / "output" / "zz_reachability_probe_test.go"
    tfile.write_text(probe)
    try:
        r = subprocess.run(
            ["go", "test", "./internal/output/", "-run", "TestReachabilityLineZZ", "-count=1", "-v"],
            capture_output=True, text=True, cwd=go_out, timeout=300)
        assert "PASS" in r.stdout, r.stdout + r.stderr
    finally:
        tfile.unlink()


def test_envelope_carries_the_reachability_block():
    """The CLI exit envelope: the same surfacing pattern the diff block
    uses (cli.py reads pipeline_output.json and copies the block onto the
    payload). Pins the helper that builds the block."""
    import importlib

    cli_mod = importlib.import_module("openant.cli")

    # a filtered run with the blackout warning -> the block rides
    po = json.loads(json.dumps(_PO_BLACKOUT))
    blk = cli_mod._reachability_envelope_block(po)
    assert blk is not None
    assert blk["reachable_units"] == 120 and blk["original_units"] == 120
    assert any("blacked out" in w for w in blk["reachability_warnings"])

    # no filter applied AND no warnings -> no block (the clean path stays clean)
    po_clean = {"pipeline_stats": {"reachability_filter_applied": False}}
    assert cli_mod._reachability_envelope_block(po_clean) is None
    # wave r1 (three axes): the NO-RECORD warning class fires exactly when
    # filter_applied is False (reporter.py:659-664) — gating on the flag alone
    # silenced the warning that overstates coverage. Warnings carry the block.
    po_norec = {"pipeline_stats": {"reachability_filter_applied": False,
                                   "reachable_units": 10, "original_units": 10,
                                   "reachability_warnings": [
                                       "Reachability filtering was requested but no "
                                       "reachability_filter record was found; reachable_units "
                                       "falls back to total_units and may overstate reachability."]}}
    blk3 = cli_mod._reachability_envelope_block(po_norec)
    assert blk3 is not None, "the overstate-reachability warning must reach the envelope"
    assert any("overstate reachability" in w for w in blk3["reachability_warnings"])
    # a clean filtered scan's EMPTY warning list never rides as a bare [] key
    po_empty = {"pipeline_stats": {"reachability_filter_applied": True,
                                   "reachable_units": 5, "original_units": 5,
                                   "reachability_warnings": []}}
    blk4 = cli_mod._reachability_envelope_block(po_empty)
    assert blk4 is not None and "reachability_warnings" not in blk4

    # the counts-only shape (warnings absent) still rides present-only
    po_counts = {"pipeline_stats": {"reachability_filter_applied": True,
                                   "reachable_units": 3, "original_units": 10,
                                   "reachability_reduction_percentage": 70.0}}
    blk2 = cli_mod._reachability_envelope_block(po_counts)
    assert blk2 is not None
    assert blk2["reachable_units"] == 3 and blk2["original_units"] == 10
    assert "reachability_warnings" not in blk2  # absent stays absent
    assert blk2["reachability_reduction_percentage"] == 70.0
