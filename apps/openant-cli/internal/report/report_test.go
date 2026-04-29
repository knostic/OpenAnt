package report

import (
	"bytes"
	"strings"
	"testing"
)

func baseReportData() ReportData {
	return ReportData{
		Title:     "Security Analysis Report",
		Timestamp: "2026-04-28 10:00:00",
		RepoName:  "python-vuln",
		CommitSHA: "55cc12c59a6d7d159c1f64cd5f712a304f32d559",
		Language:  "python",
		Stats:     Stats{TotalUnits: 8, TotalFiles: 1, Vulnerable: 6, Bypassable: 0, Secure: 2},
		Categories: []Category{
			{Verdict: "vulnerable", Color: "#dc3545", Description: "x"},
		},
	}
}

func TestRenderOverviewFullScan(t *testing.T) {
	data := baseReportData()
	var buf bytes.Buffer
	if err := RenderOverview(data, &buf); err != nil {
		t.Fatalf("RenderOverview: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "python-vuln") {
		t.Error("expected repo name in output")
	}
	if !strings.Contains(out, data.ShortCommit()) {
		t.Error("expected short commit in output for full scan")
	}
	if strings.Contains(out, "Incremental") {
		t.Error("did not expect Incremental badge on full scan")
	}
}

func TestRenderOverviewIncrementalScan(t *testing.T) {
	data := baseReportData()
	data.Diff = &DiffInfo{
		Mode:             "incremental",
		BaseSHA:          "c9f255bb6e92d6f14ed34a769898a51ca6ccc112",
		HeadSHA:          "55cc12c59a6d7d159c1f64cd5f712a304f32d559",
		Scope:            "changed_functions",
		UnitsInDiff:      2,
		UnitsTotalParsed: 8,
		ChangedFiles:     1,
	}

	var buf bytes.Buffer
	if err := RenderOverview(data, &buf); err != nil {
		t.Fatalf("RenderOverview: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Incremental") {
		t.Error("expected Incremental badge")
	}
	if !strings.Contains(out, "c9f255bb..55cc12c5") {
		t.Errorf("expected git-style range c9f255bb..55cc12c5, got: %s", excerpt(out, "Incremental"))
	}
	if !strings.Contains(out, "2/8 units") {
		t.Errorf("expected '2/8 units', got: %s", excerpt(out, "Incremental"))
	}
}

func TestRenderReskinIncrementalScan(t *testing.T) {
	data := baseReportData()
	data.Diff = &DiffInfo{
		Mode:             "incremental",
		BaseSHA:          "c9f255bb6e92d6f14ed34a769898a51ca6ccc112",
		HeadSHA:          "55cc12c59a6d7d159c1f64cd5f712a304f32d559",
		Scope:            "callers",
		UnitsInDiff:      3,
		UnitsTotalParsed: 8,
		ChangedFiles:     1,
	}
	var buf bytes.Buffer
	if err := RenderReskin(data, &buf); err != nil {
		t.Fatalf("RenderReskin: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Incremental") {
		t.Error("reskin: expected Incremental badge")
	}
	if !strings.Contains(out, "c9f255bb..55cc12c5") {
		t.Error("reskin: expected git-style range")
	}
	if !strings.Contains(out, "3/8 units") {
		t.Error("reskin: expected '3/8 units'")
	}
}

func TestIsIncrementalAndRange(t *testing.T) {
	d := ReportData{}
	if d.IsIncremental() {
		t.Error("expected IsIncremental false on empty data")
	}
	d.Diff = &DiffInfo{Mode: "incremental", BaseSHA: "abcdef0123456789", HeadSHA: "fedcba9876543210"}
	if !d.IsIncremental() {
		t.Error("expected IsIncremental true")
	}
	if got := d.DiffRange(); got != "abcdef01..fedcba98" {
		t.Errorf("expected abcdef01..fedcba98, got %q", got)
	}
}

// excerpt returns a small slice of `out` around the first occurrence of `key`,
// for friendlier failure messages.
func excerpt(out, key string) string {
	idx := strings.Index(out, key)
	if idx < 0 {
		return "(not found)"
	}
	start := idx
	end := idx + 200
	if end > len(out) {
		end = len(out)
	}
	return out[start:end]
}
