package report

// #700: the HTML step rows carry the diagnostics the JSON lanes already
// carry. The Python projection (openant.cli._step_report_rows) threads the
// keys present-only; this file pins the Go half:
//
//   - StepReport gains the diagnostic fields (cost_incomplete,
//     unpriced_models, unpriced_cache_models, accounting_error,
//     signals_skipped_unknown_unit, units_newly_reachable,
//     excluded_directories);
//   - UnpricedModelsTitle builds the tooltip attribution;
//   - DiagnosticDetails composes the present-only detail line (the skip /
//     discovery counters, per language — never a cross-language sum);
//   - StatusColor knows "partial" (the orphaned #376/#285 follow-up: a
//     degraded step rendered GRAY beside skipped ones) — text-orange-500,
//     which IS in the vendored report.css (text-yellow-400 is not);
//   - BOTH templates render the incompleteness label beside Cost (with the
//     unpriced attribution in the title) and the detail line in the step
//     table AND the mobile card.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func stepRowReportData() ReportData {
	return ReportData{
		Title:     "Security Analysis Report",
		Timestamp: "2026-04-28 10:00:00",
		RepoName:  "python-vuln",
		CommitSHA: "55cc12c59a6d7d159c1f64cd5f712a304f32d559",
		Language:  "python",
		Stats:     Stats{TotalUnits: 8, TotalFiles: 1, Vulnerable: 6, Bypassable: 0, Secure: 2},
	}
}

// TestStepReportDecodesThePythonRowShape: the json tags ARE the
// Python->Go contract — the projection's exact row key set must bind the
// struct (a renamed tag silently drops the diagnostic at the decode, the
// exact loss this issue exists to remove, re-created one layer down).
func TestStepReportDecodesThePythonRowShape(t *testing.T) {
	const row = `{"step":"analyze","duration":"1.5m","cost":"$0.25","status":"success","timestamp":"t1","error_count":0,"errors":[],"skipped_reason":"","cost_incomplete":true,"unpriced_models":["mystery/model"],"unpriced_cache_models":["c/model"],"accounting_error":false,"signals_skipped_unknown_unit":3,"units_newly_reachable":12,"excluded_directories":["go 5","python 7"]}`
	var s StepReport
	if err := json.Unmarshal([]byte(row), &s); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !s.CostIncomplete || len(s.UnpricedModels) != 1 || s.UnpricedModels[0] != "mystery/model" {
		t.Errorf("the incompleteness keys did not bind: %+v", s)
	}
	if len(s.UnpricedCacheModels) != 1 || s.UnpricedCacheModels[0] != "c/model" {
		t.Errorf("the cache kind did not bind: %+v", s)
	}
	if s.SignalsSkippedUnknownUnit != 3 || s.UnitsNewlyReachable != 12 {
		t.Errorf("the counters did not bind: %+v", s)
	}
	if len(s.ExcludedDirectories) != 2 || s.ExcludedDirectories[0] != "go 5" || s.ExcludedDirectories[1] != "python 7" {
		t.Errorf("the display-ready exclusion segments did not bind: %+v", s)
	}
}

func TestStepReportStatusColorPartial(t *testing.T) {
	s := StepReport{Step: "verify", Status: "partial"}
	if got := s.StatusColor(); got != "text-orange-500" {
		t.Errorf("StatusColor(partial) = %q, want text-orange-500 (the vendored class; text-yellow-400 is absent from report.css)", got)
	}
	if got := (StepReport{Status: "success"}).StatusColor(); got != "text-green-400" {
		t.Errorf("StatusColor(success) = %q, want text-green-400", got)
	}
	if got := (StepReport{Status: "error"}).StatusColor(); got != "text-red-400" {
		t.Errorf("StatusColor(error) = %q, want text-red-400", got)
	}
	if got := (StepReport{Status: "skipped"}).StatusColor(); got != "text-gray-400" {
		t.Errorf("StatusColor(skipped) = %q, want text-gray-400", got)
	}
}

func TestStepReportDiagnosticDetails(t *testing.T) {
	s := StepReport{
		Step:                      "llm-reachability",
		SignalsSkippedUnknownUnit: 3,
		UnitsNewlyReachable:       12,
		ExcludedDirectories:       []string{"go 5", "python 7"},
	}
	d := s.DiagnosticDetails()
	for _, want := range []string{"3 signals skipped (unknown unit)", "12 newly reachable", "python 7", "go 5"} {
		if !strings.Contains(d, want) {
			t.Errorf("DiagnosticDetails missing %q in %q", want, d)
		}
	}
	if got := (StepReport{Step: "parse"}).DiagnosticDetails(); got != "" {
		t.Errorf("a clean step's details = %q, want empty", got)
	}
	if strings.Contains(d, "12 excluded") {
		t.Errorf("the cross-language total is forbidden (the #600 contract): %q", d)
	}
}

func TestStepReportUnpricedModelsTitle(t *testing.T) {
	s := StepReport{Step: "analyze", CostIncomplete: true, UnpricedModels: []string{"mystery/model"}}
	if got := s.UnpricedModelsTitle(); !strings.Contains(got, "unpriced: mystery/model") {
		t.Errorf("UnpricedModelsTitle = %q, want the attribution", got)
	}
	// F1: a cache-only incompleteness names its model under the cache kind —
	// never the false "unattributable" shape
	sCache := StepReport{CostIncomplete: true, UnpricedCacheModels: []string{"anthropic/claude-x"}}
	if got := sCache.UnpricedModelsTitle(); !strings.Contains(got, "cache-unpriced: anthropic/claude-x") {
		t.Errorf("the cache kind's model is dropped: %q", got)
	}
	// F1's sentinel half: the #605 accounting error names its CAUSE — a
	// per-model pricing-gap wording would be a lie
	sSentinel := StepReport{CostIncomplete: true, AccountingError: true}
	if got := sSentinel.UnpricedModelsTitle(); !strings.Contains(got, "accounting error") {
		t.Errorf("the sentinel's cause is misnamed: %q", got)
	}
	// F-A (the r2 catch): the PRODUCTION combos — the sentinel AND the
	// surviving ids (PR#661 F5) — carry BOTH facts, never the ids alone
	sCombo := StepReport{CostIncomplete: true, AccountingError: true,
		UnpricedCacheModels: []string{"c/b"}}
	gotCombo := sCombo.UnpricedModelsTitle()
	if !strings.Contains(gotCombo, "cache-unpriced: c/b") || !strings.Contains(gotCombo, "accounting error") {
		t.Errorf("the sentinel+ids combo dropped a fact: %q", gotCombo)
	}
	sCombo2 := StepReport{CostIncomplete: true, AccountingError: true,
		UnpricedModels: []string{"m/a"}}
	gotCombo2 := sCombo2.UnpricedModelsTitle()
	if !strings.Contains(gotCombo2, "unpriced: m/a") || !strings.Contains(gotCombo2, "accounting error") {
		t.Errorf("the sentinel+plain-ids combo dropped a fact: %q", gotCombo2)
	}
	// both kinds together: both names ride
	sBoth := StepReport{CostIncomplete: true, UnpricedModels: []string{"m/a"}, UnpricedCacheModels: []string{"c/b"}}
	got := sBoth.UnpricedModelsTitle()
	if !strings.Contains(got, "m/a") || !strings.Contains(got, "c/b") {
		t.Errorf("both kinds' models must ride: %q", got)
	}
	// the residual model-less shape degrades to the honest marker — its
	// TEXT is pinned (the C4 title-mutant catch: an empty return passed
	// the no-tail-suffix check vacuously) — never an empty "unpriced: " tail
	s2 := StepReport{CostIncomplete: true}
	if got := s2.UnpricedModelsTitle(); !strings.Contains(got, "unattributable") {
		t.Errorf("the residual marker's text is not pinned: %q", got)
	}
	if got := s2.UnpricedModelsTitle(); strings.HasSuffix(got, ": ") {
		t.Errorf("the no-models title left an empty list tail: %q", got)
	}
}

func renderOverviewWithData(t *testing.T, data ReportData) string {
	t.Helper()
	var buf bytes.Buffer
	if err := RenderOverview(data, &buf); err != nil {
		t.Fatalf("RenderOverview: %v", err)
	}
	return buf.String()
}

func renderReskinWithData(t *testing.T, data ReportData) string {
	t.Helper()
	var buf bytes.Buffer
	if err := RenderReskin(data, &buf); err != nil {
		t.Fatalf("RenderReskin: %v", err)
	}
	return buf.String()
}

func TestRenderOverviewStepRowDiagnostics(t *testing.T) {
	// the issue's exact shape: an incomplete mixed-cost step rendered as
	// "$0.25 / success" with no label and no attribution
	data := stepRowReportData()
	data.StepReports = []StepReport{{
		Step:                      "analyze",
		Duration:                  "1.5m",
		Cost:                      "$0.25",
		Status:                    "success",
		Timestamp:                 "t1",
		CostIncomplete:            true,
		UnpricedModels:            []string{"mystery/model"},
		SignalsSkippedUnknownUnit: 3,
		UnitsNewlyReachable:       12,
		ExcludedDirectories:       []string{"python 7"},
	}}
	out := renderOverviewWithData(t, data)
	if !strings.Contains(out, "$0.25") || !strings.Contains(out, "success") {
		t.Fatal("the base row must keep rendering")
	}
	if !strings.Contains(out, "incomplete") {
		t.Error("the incompleteness label is absent from the overview step row")
	}
	if !strings.Contains(out, "mystery/model") {
		t.Error("the unpriced-model attribution is absent (the tooltip)")
	}
	for _, want := range []string{"3 signals skipped (unknown unit)", "12 newly reachable", "python 7"} {
		if !strings.Contains(out, want) {
			t.Errorf("the detail line missing %q", want)
		}
	}
}

func TestRenderReskinStepRowDiagnostics(t *testing.T) {
	data := stepRowReportData()
	data.StepReports = []StepReport{{
		Step:                      "analyze",
		Duration:                  "1.5m",
		Cost:                      "$0.25",
		Status:                    "partial",
		Timestamp:                 "t1",
		CostIncomplete:            true,
		UnpricedModels:            []string{"mystery/model"},
		SignalsSkippedUnknownUnit: 3,
	}}
	out := renderReskinWithData(t, data)
	if !strings.Contains(out, "incomplete") {
		t.Error("the incompleteness label is absent from the reskin step row")
	}
	if !strings.Contains(out, "mystery/model") {
		t.Error("the unpriced-model attribution is absent from the reskin")
	}
	if !strings.Contains(out, "3 signals skipped (unknown unit)") {
		t.Error("the skip counter is absent from the reskin detail line")
	}
	if !strings.Contains(out, `text-orange-500 font-medium">partial`) {
		t.Error("the partial status renders gray — the StatusColor partial arm never landed (the bare class pin is vacuous: the reskin carries text-orange-500 statically elsewhere)")
	}
}

func stepRowCountRegion(out, open, close string) (string, bool) {
	i := strings.Index(out, open)
	if i < 0 {
		return "", false
	}
	j := strings.Index(out[i:], close)
	if j < 0 {
		return "", false
	}
	return out[i : i+j], true
}

// TestRenderStepRowSitesPerTemplate: each #700 template hunk gets its OWN
// discriminating pin — the coarse Contains(out, "incomplete") pins pass
// while THREE of the four sites are reverted (any one site satisfies
// them), so the per-site pins are what the fix-linkage actually holds:
// the Details header, the table row's label + details cell, the tfoot's
// 5-column alignment, and the mobile card's label + details block.
func TestRenderStepRowSitesPerTemplate(t *testing.T) {
	type pin struct{ name, want string }
	cases := []struct {
		tmpl   string
		render func(t *testing.T, data ReportData) string
		row    string
		pins   []pin
	}{
		{"overview", renderOverviewWithData, "3 signals skipped (unknown unit) · 12 newly reachable · excluded dirs: python 7", []pin{
			{"the Details header th", `text-gray-300 font-medium">Details</th>`},
			{"the table cost-cell label", `px-4">$0.25 <span class="text-xs text-orange-500"`},
			{"the table details cell", `px-4 text-xs text-gray-400">3 signals skipped (unknown unit) · 12 newly reachable · excluded dirs: python 7<`},
			{"the mobile card cost label", `text-gray-200">$0.25 <span class="text-xs text-orange-500"`},
			{"the mobile card details block", `mt-2"><span class="text-gray-400">Details</span>`},
		}},
		{"reskin", renderReskinWithData, "3 signals skipped (unknown unit) · 12 newly reachable · excluded dirs: python 7", []pin{
			{"the Details header th", `text-knostic-muted font-medium">Details</th>`},
			{"the table cost-cell label", `px-4">$0.25 <span class="text-xs text-orange-500"`},
			{"the table details cell", `px-4 text-xs text-knostic-muted">3 signals skipped (unknown unit) · 12 newly reachable · excluded dirs: python 7<`},
			{"the mobile card cost label", `text-knostic-navy">$0.25 <span class="text-xs text-orange-500"`},
			{"the mobile card details block", `mt-2"><span class="text-knostic-muted">Details</span>`},
		}},
	}
	for _, c := range cases {
		data := stepRowReportData()
		data.StepReports = []StepReport{{
			Step: "analyze", Duration: "1.5m", Cost: "$0.25", Status: "partial",
			Timestamp: "t1", CostIncomplete: true,
			UnpricedModels:            []string{"mystery/model"},
			SignalsSkippedUnknownUnit: 3,
			UnitsNewlyReachable:       12,
			ExcludedDirectories:       []string{"python 7"},
		}}
		out := c.render(t, data)
		if !strings.Contains(out, c.row) {
			t.Errorf("%s: the composed detail line %q is absent", c.tmpl, c.row)
		}
		for _, p := range c.pins {
			if !strings.Contains(out, p.want) {
				t.Errorf("%s: %s missing: %q", c.tmpl, p.name, p.want)
			}
		}
		// the tfoot alignment: exactly five tds in the step table's total row
		foot, ok := stepRowCountRegion(out, "<tfoot>", "</tfoot>")
		if !ok {
			t.Fatalf("%s: no tfoot found", c.tmpl)
		}
		if n := strings.Count(foot, "<td"); n != 5 {
			t.Errorf("%s: the tfoot carries %d tds, want 5 (the 5-column alignment)", c.tmpl, n)
		}
	}
}

func TestRenderStepRowsCleanStepStaysClean(t *testing.T) {
	// the present-only control: a clean step's row renders with NO label,
	// NO details content — in BOTH templates
	data := stepRowReportData()
	data.StepReports = []StepReport{{Step: "parse", Duration: "5.0s", Cost: "-", Status: "success"}}
	if out := renderOverviewWithData(t, data); strings.Contains(out, "incomplete") || strings.Contains(out, "signals skipped") {
		t.Error("the overview row of a clean step carries a diagnostic")
	}
	data2 := stepRowReportData()
	data2.StepReports = data.StepReports
	if out := renderReskinWithData(t, data2); strings.Contains(out, "incomplete") || strings.Contains(out, "signals skipped") {
		t.Error("the reskin row of a clean step carries a diagnostic")
	}
}
