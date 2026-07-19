package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fatih/color"
)

// captureHeaders runs fn and returns everything written to color.Output.
// Section headers (PrintHeader -> bold.Println) route through color.Output,
// so the distinctive header text is sufficient to identify which summary
// renderer ran.
func captureHeaders(fn func()) string {
	var buf bytes.Buffer
	prevOut, prevNoColor := color.Output, color.NoColor
	color.Output, color.NoColor = &buf, true
	defer func() { color.Output, color.NoColor = prevOut, prevNoColor }()
	fn()
	return buf.String()
}

// verifyResultData mimics the envelope `data` the Python backend returns for
// `analyze --verify`: a VerifyResult.to_dict() payload — note there is NO
// "metrics" key.
func verifyResultData() map[string]any {
	return map[string]any{
		"verified_results_path":     "/tmp/verified.json",
		"findings_input":            float64(3),
		"findings_verified":         float64(3),
		"agreed":                    float64(2),
		"disagreed":                 float64(1),
		"confirmed_vulnerabilities": float64(2),
	}
}

// analyzeResultData mimics the `analyze` (no --verify) envelope: an
// AnalysisResult with a "metrics" map.
func analyzeResultData() map[string]any {
	return map[string]any{
		"results_path": "/tmp/results.json",
		"metrics": map[string]any{
			"total":      float64(10),
			"vulnerable": float64(1),
			"protected":  float64(2),
			"safe":       float64(7),
		},
	}
}

// TestPrintAnalyzeResult_VerifyOutcomeNotDropped is the RED test: with
// --verify, the backend returns a verify result (no "metrics"), so the
// analyze summary silently drops it. The command must instead surface the
// Stage-2 verification outcome.
func TestPrintAnalyzeResult_VerifyOutcomeNotDropped(t *testing.T) {
	out := captureHeaders(func() { PrintAnalyzeResult(verifyResultData(), true) })
	if !strings.Contains(out, "Verification Results (Stage 2)") {
		t.Fatalf("analyze --verify dropped the Stage-2 outcome; expected the "+
			"verification summary, got output:\n%q", out)
	}
}

// TestPrintAnalyzeResult_PlainAnalyzeUsesAnalyzeSummary guards the non-verify
// path: a normal analyze result must still render the analysis summary.
func TestPrintAnalyzeResult_PlainAnalyzeUsesAnalyzeSummary(t *testing.T) {
	out := captureHeaders(func() { PrintAnalyzeResult(analyzeResultData(), false) })
	if !strings.Contains(out, "Analysis Results") {
		t.Fatalf("plain analyze should render the analysis summary, got:\n%q", out)
	}
}

// TestPrintAnalyzeResult_VerifySkippedFallsBackToAnalyze covers the edge case
// where --verify was requested but skipped (no --analyzer-output): Python
// falls through to emit an AnalysisResult (with "metrics"), so the analyze
// summary is the correct renderer even though verify==true.
func TestPrintAnalyzeResult_VerifySkippedFallsBackToAnalyze(t *testing.T) {
	out := captureHeaders(func() { PrintAnalyzeResult(analyzeResultData(), true) })
	if !strings.Contains(out, "Analysis Results") {
		t.Fatalf("verify-skipped path should fall back to the analysis summary, got:\n%q", out)
	}
}
