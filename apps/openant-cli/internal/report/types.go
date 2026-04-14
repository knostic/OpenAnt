// Package report provides HTML report generation from pre-computed data.
package report

import (
	"fmt"
	"html/template"
	"strings"
)

// ReportData holds all pre-computed data needed to render the HTML overview report.
// This struct maps 1:1 to the JSON output of the Python `report-data` subcommand.
type ReportData struct {
	Title             string         `json:"title"`
	Timestamp         string         `json:"timestamp"`
	RepoName          string         `json:"repo_name"`
	CommitSHA         string         `json:"commit_sha"`
	Language          string         `json:"language"`
	RepoURL           string         `json:"repo_url"`
	TotalDurationS    float64        `json:"total_duration_seconds"`
	TotalCostUSD      float64        `json:"total_cost_usd"`
	Stats             Stats          `json:"stats"`
	UnitChart         ChartData      `json:"unit_chart"`
	FileChart         ChartData      `json:"file_chart"`
	RemediationHTML   string         `json:"remediation_html"`
	Findings          []Finding      `json:"findings"`
	FindingsByVerdict []FindingGroup `json:"findings_by_verdict"`
	StepReports       []StepReport   `json:"step_reports"`
	Categories        []Category     `json:"categories"`
}

// SafeRemediation returns the remediation HTML as a template.HTML
// so Go's html/template does not escape it.
func (d ReportData) SafeRemediation() template.HTML {
	return template.HTML(d.RemediationHTML)
}

// FormatDuration returns TotalDurationS as a human-readable string
// like "1d 2h 3m 4s", omitting leading zero components.
func (d ReportData) FormatDuration() string {
	total := int(d.TotalDurationS)
	if total <= 0 {
		return ""
	}
	days := total / 86400
	hours := (total % 86400) / 3600
	mins := (total % 3600) / 60
	secs := total % 60

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if mins > 0 {
		parts = append(parts, fmt.Sprintf("%dm", mins))
	}
	if secs > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%ds", secs))
	}
	return strings.Join(parts, " ")
}

// FormatTotalCost returns TotalCostUSD as "$X.XX", or "-" if zero.
func (d ReportData) FormatTotalCost() string {
	if d.TotalCostUSD <= 0 {
		return "-"
	}
	return fmt.Sprintf("$%.2f", d.TotalCostUSD)
}

// ShortCommit returns the first 10 characters of CommitSHA, or empty.
func (d ReportData) ShortCommit() string {
	if len(d.CommitSHA) > 10 {
		return d.CommitSHA[:10]
	}
	return d.CommitSHA
}

// FileURL constructs a browseable URL for a file path in the repo.
// Returns empty string if repo URL or commit SHA is missing.
func (d ReportData) FileURL(filePath string) string {
	if d.RepoURL == "" || d.CommitSHA == "" {
		return ""
	}
	base := strings.TrimRight(d.RepoURL, "/")
	base = strings.TrimSuffix(base, ".git")
	return base + "/blob/" + d.CommitSHA + "/" + filePath
}

// HasStepReports returns true if there are step reports to display.
func (d ReportData) HasStepReports() bool {
	return len(d.StepReports) > 0
}

// HasFindings returns true if there are findings to display.
func (d ReportData) HasFindings() bool {
	return len(d.Findings) > 0
}

// HasFindingGroups returns true if there are grouped findings to display.
func (d ReportData) HasFindingGroups() bool {
	return len(d.FindingsByVerdict) > 0
}

// Stats holds the summary statistics for the report header cards.
type Stats struct {
	TotalUnits int `json:"total_units"`
	TotalFiles int `json:"total_files"`
	Vulnerable int `json:"vulnerable"`
	Bypassable int `json:"bypassable"`
	Secure     int `json:"secure"`
}

// ChartData holds the data for a Chart.js pie chart.
type ChartData struct {
	Labels []string `json:"labels"`
	Data   []int    `json:"data"`
	Colors []string `json:"colors"`
}

// FindingGroup holds findings grouped by verdict for collapsible sections.
type FindingGroup struct {
	Verdict       string          `json:"verdict"`
	VerdictColor  string          `json:"verdict_color"`
	Count         int             `json:"count"`
	OpenByDefault bool            `json:"open_by_default"`
	Findings      []Finding       `json:"findings"`
	Subgroups     []FindingSubgroup `json:"subgroups"`
	HasSubgroups  bool            `json:"has_subgroups"`
}

// FindingSubgroup holds findings within a verdict group, sub-grouped by
// dynamic test outcome (e.g. "Confirmed", "Test error", "Not tested").
type FindingSubgroup struct {
	Label    string    `json:"label"`
	Findings []Finding `json:"findings"`
}

// Finding represents a single finding row in the report table.
type Finding struct {
	Number             int    `json:"number"`
	Verdict            string `json:"verdict"`
	VerdictColor       string `json:"verdict_color"`
	File               string `json:"file"`
	Function           string `json:"function"`
	AttackVector       string `json:"attack_vector"`
	Analysis           string `json:"analysis"`
	DynamicTestStatus  string `json:"dynamic_test_status"`
	DynamicTestDetails string `json:"dynamic_test_details"`
}

// HasDynamicTest returns true if this finding has dynamic test results.
func (f Finding) HasDynamicTest() bool {
	return f.DynamicTestStatus != ""
}

// DynamicTestColor returns a color for the dynamic test status badge.
func (f Finding) DynamicTestColor() string {
	switch f.DynamicTestStatus {
	case "CONFIRMED":
		return "#dc3545"
	case "NOT_REPRODUCED":
		return "#28a745"
	case "BLOCKED":
		return "#28a745"
	case "ERROR":
		return "#6c757d"
	case "INCONCLUSIVE":
		return "#fd7e14"
	default:
		return "#6c757d"
	}
}

// IsHighSeverity returns true for vulnerable/bypassable findings,
// used to auto-open their <details> accordion in the HTML report.
func (f Finding) IsHighSeverity() bool {
	switch f.Verdict {
	case "vulnerable", "bypassable":
		return true
	default:
		return false
	}
}

// StepReport holds display-ready data for a pipeline step.
type StepReport struct {
	Step      string `json:"step"`
	Duration  string `json:"duration"`
	Cost      string `json:"cost"`
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
}

// StatusColor returns a Tailwind text color class based on step status.
func (s StepReport) StatusColor() string {
	switch s.Status {
	case "success":
		return "text-green-400"
	case "error":
		return "text-red-400"
	default:
		return "text-gray-400"
	}
}

// Category holds a verdict category description for the legend table.
type Category struct {
	Verdict     string `json:"verdict"`
	Color       string `json:"color"`
	Description string `json:"description"`
}
