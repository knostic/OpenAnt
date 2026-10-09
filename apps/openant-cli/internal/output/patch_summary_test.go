package output

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/fatih/color"
)

// captureStdout redirects the real os.Stdout (not just color.Output) for
// the duration of fn and returns everything written to it. PrintPatchSummary
// mixes color.Output writes (PrintHeader's bold line) with plain fmt.Println
// writes (PrintKeyValue's value half) -- captureHeaders (analyze_verify_test.go)
// only sees the former, so full-content assertions need the real stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	// PrintHeader/PrintKeyValue split their output across two different
	// writers -- the colored half (bold.Println/cyan.Printf) goes through
	// color.Output, a separate io.Writer captured at init time that does
	// NOT track reassignments to the os.Stdout variable; the plain half
	// (fmt.Println) goes straight to whatever os.Stdout currently is. Both
	// must point at the same pipe for one ordered, complete capture.
	orig := os.Stdout
	origColorOutput := color.Output
	prevNoColor := color.NoColor
	os.Stdout, color.Output, color.NoColor = w, w, true
	fn()
	w.Close()
	os.Stdout, color.Output, color.NoColor = orig, origColorOutput, prevNoColor

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	return string(out)
}

func TestPrintPatchSummary_FindingMode(t *testing.T) {
	out := captureStdout(t, func() {
		PrintPatchSummary(map[string]any{
			"finding_id":        "F-001",
			"trust_report_path": "/tmp/out/patch/F-001-trust-report.md",
			"input_type":        "finding",
		})
	})

	if !strings.Contains(out, "Patch Trust Report") {
		t.Errorf("expected header %q in output, got:\n%s", "Patch Trust Report", out)
	}
	if !strings.Contains(out, "Finding") {
		t.Errorf("expected label %q in output, got:\n%s", "Finding", out)
	}
	if strings.Contains(out, "CVE") {
		t.Errorf("finding-mode output should not say CVE, got:\n%s", out)
	}
	if !strings.Contains(out, "F-001") {
		t.Errorf("expected finding id %q in output, got:\n%s", "F-001", out)
	}
	if !strings.Contains(out, "/tmp/out/patch/F-001-trust-report.md") {
		t.Errorf("expected report path in output, got:\n%s", out)
	}
}

func TestPrintPatchSummary_CVEMode(t *testing.T) {
	out := captureStdout(t, func() {
		PrintPatchSummary(map[string]any{
			"finding_id":        "CVE-2023-43804",
			"trust_report_path": "/tmp/out/patch/CVE-2023-43804-trust-report.md",
			"input_type":        "cve",
		})
	})

	if !strings.Contains(out, "CVE") {
		t.Errorf("expected label %q in output, got:\n%s", "CVE", out)
	}
	if !strings.Contains(out, "CVE-2023-43804") {
		t.Errorf("expected CVE id in output, got:\n%s", out)
	}
}
