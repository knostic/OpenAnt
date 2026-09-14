package output

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/fatih/color"
)

// captureUsageOutput runs fn capturing BOTH os.Stdout (fmt.Println — the
// value halves) and color.Output (the colored key prefixes) — PrintKeyValue
// writes to both, so a single pipe catches the full "Key: value" line.
func captureUsageOutput(fn func()) string {
	r, w, _ := os.Pipe()
	oldStdout, oldColorOut, oldNoColor := os.Stdout, color.Output, color.NoColor
	os.Stdout, color.Output, color.NoColor = w, w, true
	defer func() {
		os.Stdout, color.Output, color.NoColor = oldStdout, oldColorOut, oldNoColor
	}()
	fn()
	_ = w.Close()
	var buf strings.Builder
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

// TestReportSummaryRendersIncompleteness: #598 — the report renderer was
// the envelope's own consumer that dropped the metadata (and its cost>0
// gate vanished an incomplete $0 entirely). The label and the ids must
// reach the terminal.
func TestReportSummaryRendersIncompleteness(t *testing.T) {
	out := captureUsageOutput(func() {
		PrintReportSummary(map[string]any{
			"format":     "summary",
			"output_path": "/tmp/x",
			"usage": map[string]any{
				"total_cost_usd": 0.0,
				"cost_incomplete": true,
				"unpriced_models": []any{"claude-sonnet-4-6", "mystery/model"},
			},
		})
	})
	if !strings.Contains(out, "Cost (incomplete — at least one model unpriced)") {
		t.Fatalf("the incomplete label missing: %q", out)
	}
	if !strings.Contains(out, "claude-sonnet-4-6, mystery/model") {
		t.Fatalf("the unpriced ids missing: %q", out)
	}
}

// TestReportSummaryCompleteHasNoLabel: the control — a complete figure
// renders the plain Cost line and never the label.
func TestReportSummaryCompleteHasNoLabel(t *testing.T) {
	out := captureUsageOutput(func() {
		PrintReportSummary(map[string]any{
			"usage": map[string]any{"total_cost_usd": 0.0012},
		})
	})
	if strings.Contains(out, "incomplete") {
		t.Fatalf("a complete figure must not carry the label: %q", out)
	}
	if !strings.Contains(out, "Cost") {
		t.Fatalf("the cost line missing: %q", out)
	}
}

// TestScanSummaryRendersIncompleteness: the scan renderer (V1 — V2 shares
// the same block) carries the label + ids through the shared helper.
func TestScanSummaryRendersIncompleteness(t *testing.T) {
	out := captureUsageOutput(func() {
		PrintScanSummary(map[string]any{
			// PrintScanSummary early-returns without the metrics block.
			"metrics": map[string]any{"total": 3, "vulnerable": 0, "safe": 3},
			"usage": map[string]any{
				"total_cost_usd":      0.0,
				"total_input_tokens":  10,
				"total_output_tokens": 5,
				"cost_incomplete":     true,
				"unpriced_models":     []any{"x"},
			},
		})
	})
	if !strings.Contains(out, "Cost (incomplete — at least one model unpriced)") {
		t.Fatalf("the incomplete label missing: %q", out)
	}
	if !strings.Contains(out, "Unpriced models") {
		t.Fatalf("the unpriced ids line missing: %q", out)
	}
}
