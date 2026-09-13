package server

import (
	"html/template"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/knostic/open-ant-cli/internal/report"
	uifiles "github.com/knostic/open-ant-cli/ui"
)

// TestBrowserSmoke is the CSP's first real-browser enforcement pass (the
// #578 follow-up 1c) + the golden render oracle for vendored marked/DOMPurify
// bumps (4a). Env-gated: it needs node + playwright + a real Chromium, so it
// only runs in the dedicated CI job (OPENANT_BROWSER_TESTS=1) — everywhere
// else it skips. The Go side owns the fixtures (the seeded outDir + the
// job) and shells out to testdata/browser-smoke/browser_smoke.mjs, which
// drives the pages and asserts: zero CSP violations, the enforcing CSP
// header on every navigation, per-page readiness (the delegated listeners
// execute, the SSE done event arrives, Chart.js runs inline), the hard
// sanitization canaries, and the golden #content render.
func TestBrowserSmoke(t *testing.T) {
	if os.Getenv("OPENANT_BROWSER_TESTS") != "1" {
		t.Skip("CI-only: needs node + playwright + chromium (the browser-smoke job)")
	}

	outDir := t.TempDir()
	const id = "jx"
	// The four templates (same as New() — a zero-value Server nil-panics).
	tmplIndex, err := template.ParseFS(uifiles.FS, "index.html")
	if err != nil {
		t.Fatalf("parse index.html: %v", err)
	}
	tmplScan, err := template.ParseFS(uifiles.FS, "scan.html")
	if err != nil {
		t.Fatalf("parse scan.html: %v", err)
	}
	tmplSum, err := template.ParseFS(uifiles.FS, "summary.html")
	if err != nil {
		t.Fatalf("parse summary.html: %v", err)
	}
	tmplDisclosure, err := template.ParseFS(uifiles.FS, "disclosure.html")
	if err != nil {
		t.Fatalf("parse disclosure.html: %v", err)
	}
	s := &Server{
		outDir:         outDir,
		mgr:            newManager(t.TempDir()),
		csrfToken:      "tok",
		sem:            make(chan struct{}, 4),
		shutdownDone:   make(chan struct{}),
		tmplIndex:      tmplIndex,
		tmplScan:       tmplScan,
		tmplSum:        tmplSum,
		tmplDisclosure: tmplDisclosure,
	}

	// The seeded job — the HANDLERS read paths off the Job, not the disk:
	// without SummaryPath/ReportPath/DisclosurePaths every route 404s.
	goldenInput, err := os.ReadFile(filepath.Join("testdata", "browser-smoke", "golden_input.md"))
	if err != nil {
		t.Fatalf("read golden_input.md: %v", err)
	}
	sumPath := filepath.Join(outDir, id, "SUMMARY_REPORT.md")
	discPath := filepath.Join(outDir, id, "d.md")
	reportPath := filepath.Join(outDir, id, "report.html")
	for _, p := range []string{sumPath, discPath, reportPath} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	if err := os.WriteFile(sumPath, goldenInput, 0o644); err != nil {
		t.Fatalf("seed summary: %v", err)
	}
	if err := os.WriteFile(discPath, goldenInput, 0o644); err != nil {
		t.Fatalf("seed disclosure: %v", err)
	}
	// A REAL generated report (report.GenerateReskin) with NON-EMPTY chart
	// data — nil charts serialize as null and the datalabels formatter
	// crashes on them; and only the real report exercises the inline
	// Chart.js / no-unsafe-eval contract on /report.
	if err := report.GenerateReskin(report.ReportData{
		Title:     "browser-smoke",
		Timestamp: "2026-09-13",
		RepoName:  "example/repo",
		CommitSHA: "abc123def456",
		Language:  "go",
		Stats:     report.Stats{TotalUnits: 5, TotalFiles: 2, Vulnerable: 2, Secure: 3},
		UnitChart: report.ChartData{
			Labels: []string{"vulnerable", "not_vulnerable"},
			Data:   []int{2, 3},
			Colors: []string{"#b91c1c", "#16a34a"},
		},
		FileChart: report.ChartData{
			Labels: []string{"a.go", "b.go"},
			Data:   []int{3, 2},
			Colors: []string{"#2563eb", "#9333ea"},
		},
	}, reportPath); err != nil {
		t.Fatalf("GenerateReskin: %v", err)
	}
	j := &Job{
		ID:              id,
		Repo:            "https://example.com/org/repo",
		Status:          "done",
		StartedAt:       time.Now().Add(-time.Minute),
		SummaryPath:     sumPath,
		ReportPath:      reportPath,
		DisclosurePaths: []string{discPath},
		done:            make(chan struct{}),
	}
	s.mgr.add(j)

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	// Absolute paths: cmd.Dir points at the harness dir so node resolves
	// playwright from ITS node_modules — but the script args must not then
	// re-resolve relative to it (the doubled-path trap). Node resolves the
	// script's own imports relative to the SCRIPT's location, so the Dir
	// only needs to exist; the args are made absolute here.
	scriptAbs, err := filepath.Abs(filepath.Join("testdata", "browser-smoke", "browser_smoke.mjs"))
	if err != nil {
		t.Fatalf("abs script: %v", err)
	}
	goldenAbs, err := filepath.Abs(filepath.Join("testdata", "browser-smoke", "golden_expected.html"))
	if err != nil {
		t.Fatalf("abs golden: %v", err)
	}

	if os.Getenv("OPENANT_UPDATE_GOLDEN") != "1" {
		if _, err := os.Stat(goldenAbs); err != nil {
			t.Fatalf("the golden is missing (first run: OPENANT_BROWSER_TESTS=1 OPENANT_UPDATE_GOLDEN=1): %v", err)
		}
	}
	cmd := exec.Command("node", scriptAbs, srv.URL, goldenAbs)
	cmd.Dir = filepath.Dir(scriptAbs)
	cmd.Env = append(os.Environ(),
		"OPENANT_UPDATE_GOLDEN="+os.Getenv("OPENANT_UPDATE_GOLDEN"))
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		t.Logf("%s", out)
	}
	if err != nil {
		t.Fatalf("the browser smoke failed: %v\n%s", err, out)
	}
	if os.Getenv("OPENANT_UPDATE_GOLDEN") == "1" {
		t.Log("GOLDEN UPDATED — review the diff before committing")
	}
}
