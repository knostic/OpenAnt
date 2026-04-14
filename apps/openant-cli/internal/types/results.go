// Package types defines the JSON structures returned by the Python CLI.
package types

// Envelope is the top-level JSON response from `python -m openant`.
// Every command returns this shape: { status, data, errors }.
type Envelope struct {
	Status string   `json:"status"` // "success" or "error"
	Data   any      `json:"data"`
	Errors []string `json:"errors"`
}

// ParseData is returned by the `parse` command.
type ParseData struct {
	DatasetPath string `json:"dataset_path"`
	RepoPath    string `json:"repo_path"`
	Language    string `json:"language"`
	Level       string `json:"processing_level"`
	UnitsCount  int    `json:"units_count"`
}

// AnalyzeData is returned by the `analyze` command.
type AnalyzeData struct {
	ResultsPath string          `json:"results_path"`
	Metrics     AnalysisMetrics `json:"metrics"`
	Usage       UsageInfo       `json:"usage"`
}

// AnalysisMetrics holds vulnerability counts from analysis.
type AnalysisMetrics struct {
	Total        int `json:"total"`
	Vulnerable   int `json:"vulnerable"`
	Bypassable   int `json:"bypassable"`
	Inconclusive int `json:"inconclusive"`
	Protected    int `json:"protected"`
	Safe         int `json:"safe"`
	Errors       int `json:"errors"`
	// Stage 2 metrics (optional)
	Verified        int `json:"verified"`
	Stage2Agreed    int `json:"stage2_agreed"`
	Stage2Disagreed int `json:"stage2_disagreed"`
}

// ReportData is returned by the `report` command.
type ReportData struct {
	OutputPath string    `json:"output_path"`
	Format     string    `json:"format"`
	Usage      UsageInfo `json:"usage"`
}

// ScanData is returned by the `scan` command (all-in-one pipeline).
type ScanData struct {
	OutputDir           string      `json:"output_dir"`
	DatasetPath         string      `json:"dataset_path"`
	EnhancedDatasetPath string      `json:"enhanced_dataset_path"`
	AnalyzerOutputPath  string      `json:"analyzer_output_path"`
	AppContextPath      string      `json:"app_context_path"`
	ResultsPath         string      `json:"results_path"`
	VerifiedResultsPath string      `json:"verified_results_path"`
	PipelineOutputPath  string      `json:"pipeline_output_path"`
	SummaryPath         string      `json:"summary_path"`
	DynamicTestPath     string      `json:"dynamic_test_path"`
	UnitsCount          int         `json:"units_count"`
	Language            string      `json:"language"`
	Metrics             ScanMetrics `json:"metrics"`
	Usage               UsageInfo   `json:"usage"`
	StepReports         []any       `json:"step_reports"`
	SkippedSteps        []string    `json:"skipped_steps"`
}

// ScanMetrics holds vulnerability counts from a full pipeline scan.
type ScanMetrics struct {
	Total           int `json:"total"`
	Vulnerable      int `json:"vulnerable"`
	Bypassable      int `json:"bypassable"`
	Inconclusive    int `json:"inconclusive"`
	Protected       int `json:"protected"`
	Safe            int `json:"safe"`
	Errors          int `json:"errors"`
	Verified        int `json:"verified"`
	Stage2Agreed    int `json:"stage2_agreed"`
	Stage2Disagreed int `json:"stage2_disagreed"`
}

// EnhanceData is returned by the `enhance` command.
type EnhanceData struct {
	EnhancedDatasetPath string         `json:"enhanced_dataset_path"`
	UnitsEnhanced       int            `json:"units_enhanced"`
	ErrorCount          int            `json:"error_count"`
	Classifications     map[string]int `json:"classifications"`
	Usage               UsageInfo      `json:"usage"`
}

// VerifyData is returned by the `verify` command.
type VerifyData struct {
	VerifiedResultsPath      string    `json:"verified_results_path"`
	FindingsInput            int       `json:"findings_input"`
	FindingsVerified         int       `json:"findings_verified"`
	Agreed                   int       `json:"agreed"`
	Disagreed                int       `json:"disagreed"`
	ConfirmedVulnerabilities int       `json:"confirmed_vulnerabilities"`
	Usage                    UsageInfo `json:"usage"`
}

// DynamicTestData is returned by the `dynamic-test` command.
type DynamicTestData struct {
	ResultsJSONPath string    `json:"results_json_path"`
	ResultsMDPath   string    `json:"results_md_path"`
	FindingsTested  int       `json:"findings_tested"`
	Confirmed       int       `json:"confirmed"`
	NotReproduced   int       `json:"not_reproduced"`
	Blocked         int       `json:"blocked"`
	Inconclusive    int       `json:"inconclusive"`
	Errors          int       `json:"errors"`
	Usage           UsageInfo `json:"usage"`
}

// UsageInfo tracks token usage and cost.
type UsageInfo struct {
	TotalCalls        int      `json:"total_calls"`
	TotalInputTokens  int      `json:"total_input_tokens"`
	TotalOutputTokens int      `json:"total_output_tokens"`
	TotalTokens       int      `json:"total_tokens"`
	TotalCostUSD      float64  `json:"total_cost_usd"`
	Models            []string `json:"models"`
}
