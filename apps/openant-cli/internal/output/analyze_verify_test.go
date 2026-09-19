package output

import (
	"bytes"
	"io"
	"os"
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

// captureAll runs fn and returns EVERYTHING written to both streams.
// #622: PrintKeyValue's value half routes through fmt.* to os.Stdout
// (formatter.go) while the colored key/label half routes through
// color.Output — captureHeaders alone sees no numbers, which is the
// vacuous-assertion trap this helper exists to close.
func captureAll(t *testing.T, fn func()) string {
	var colorBuf, stdBuf bytes.Buffer
	prevOut, prevNoColor := color.Output, color.NoColor
	color.Output, color.NoColor = &colorBuf, true
	defer func() { color.Output, color.NoColor = prevOut, prevNoColor }()

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	// Panic-safe: a panic inside fn must not leave os.Stdout pointed at a
	// dead pipe (the go tool would swallow the panic report itself).
	defer func() { os.Stdout = old }()
	done := make(chan struct{})
	go func() {
		io.Copy(&stdBuf, r)
		close(done)
	}()
	fn()
	w.Close()
	<-done
	return colorBuf.String() + stdBuf.String()
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

// --- #622: the protected-correction split must be explained on every display -

// TestPrintVerifySummary_622CompanionLines: a VerifyResult.to_dict envelope
// carrying BOTH reclassification siblings renders them beside "Disagreed
// (eliminated)" — without the companions the eliminated number is silently
// narrower than its parts.
func TestPrintVerifySummary_622CompanionLines(t *testing.T) {
	data := verifyResultData()
	data["disagreed_protected"] = float64(1)
	data["disagreed_inconclusive"] = float64(1)
	out := captureAll(t, func() { PrintVerifySummary(data) })
	if !strings.Contains(out, "Disagreed (eliminated): 1") {
		t.Fatalf("the residual disagreement must still render, got:\n%q", out)
	}
	if !strings.Contains(out, "Reclassified protected (verified protected-by-controls): 1") {
		t.Fatalf("the protected companion line is missing (a protected-by-controls "+
			"correction is NOT an eliminated false positive), got:\n%q", out)
	}
	if !strings.Contains(out, "Reclassified inconclusive (explicitly unconfirmable): 1") {
		t.Fatalf("the #509 sibling's companion line is missing, got:\n%q", out)
	}
}

// TestPrintVerifySummary_622OldEnvelopeDefaults: an OLD envelope (no sibling
// keys — pre-#622 artifacts) renders identically to before: the companions
// stay absent and the residual keeps its meaning (old artifacts carry the
// pre-split residual in `disagreed`).
func TestPrintVerifySummary_622OldEnvelopeDefaults(t *testing.T) {
	out := captureAll(t, func() { PrintVerifySummary(verifyResultData()) })
	if !strings.Contains(out, "Disagreed (eliminated): 1") {
		t.Fatalf("old envelope must render the residual, got:\n%q", out)
	}
	if strings.Contains(out, "Reclassified protected") {
		t.Fatalf("no sibling keys -> no companion lines (absent is 0, not a "+
			"guess), got:\n%q", out)
	}
}

// TestPrintScanSummary_622CompanionLine: the scan summary's
// "False positives eliminated" shrinks by exactly the protected split, so the
// companion line must name where they went. The fixture is internally
// consistent: verified=4 = agreed(1) + to-safe(2) + to-protected(1), with
// stage2_disagreed=2 (the residual) and the split=1.
func TestPrintScanSummary_622CompanionLine(t *testing.T) {
	data := map[string]any{
		"metrics": map[string]any{
			"total":                      float64(10),
			"vulnerable":                 float64(1),
			"protected":                  float64(4),
			"safe":                       float64(5),
			"verified":                   float64(4),
			"stage2_agreed":              float64(1),
			"stage2_disagreed":           float64(2),
			"stage2_disagreed_protected": float64(1),
		},
	}
	out := captureAll(t, func() { PrintScanSummary(data) })
	// PrintKeyValue routes the label through color.Output and the value
	// through os.Stdout — assert the labels on the one stream and the
	// ordered values (Safe 5, eliminated 2, reclassified 1) on the other.
	if !strings.Contains(out, "False positives eliminated") {
		t.Fatalf("the residual eliminated count must render, got:\n%q", out)
	}
	if !strings.Contains(out, "Reclassified protected (verified protected-by-controls)") {
		t.Fatalf("the scan-summary companion line is missing, got:\n%q", out)
	}
	if !strings.Contains(out, "5\n2\n1\n") {
		t.Fatalf("the ordered values must show the split (safe 5, eliminated 2, "+
			"reclassified 1), got:\n%q", out)
	}
}

// TestPrintScanSummaryV2_622SplitLine: the V2 scan summary's
// "Verified (Stage 2)" line must disclose the protected split — disjointly
// (the split is carved OUT of the disagreed figure, not a subset of it).
func TestPrintScanSummaryV2_622SplitLine(t *testing.T) {
	data := map[string]any{
		"metrics": map[string]any{
			"total":                      float64(10),
			"vulnerable":                 float64(1),
			"protected":                  float64(4),
			"safe":                       float64(5),
			"verified":                   float64(4),
			"stage2_agreed":              float64(1),
			"stage2_disagreed":           float64(2),
			"stage2_disagreed_protected": float64(1),
		},
	}
	out := captureAll(t, func() { PrintScanSummaryV2(data) })
	if !strings.Contains(out, "Reclassified protected") {
		t.Fatalf("the V2 split line is missing, got:\n%q", out)
	}
	if !strings.Contains(out, "1 (verified protected-by-controls; not counted in disagreed)") {
		t.Fatalf("the V2 split line must state the disjoint count, got:\n%q", out)
	}
}
