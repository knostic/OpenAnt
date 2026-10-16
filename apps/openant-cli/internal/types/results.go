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
	// #622: the protected split of stage2_disagreed — non-partition
	// telemetry. Forward-declared surface (this struct is not unmarshaled;
	// the formatter reads the untyped map) kept in sync with the Python
	// AnalysisMetrics field so the cross-language contract stays documented.
	Stage2DisagreedProtected int `json:"stage2_disagreed_protected"`
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
	// #307: the multi-language coverage fields the CHANGELOG claims.
	// NOTE (review finding, corrected): ScanData is not currently
	// unmarshaled anywhere in the CLI (the formatter renders the
	// untyped envelope), and ScanResult.to_dict serializes
	// per_language/parse_errors/excluded_languages/degraded but NOT
	// coverage — so these fields are FORWARD-DECLARED surface only:
	// they populate once a typed decode is wired (or from
	// pipeline_output.json, where the reporter emits them). They are
	// additive/omitempty and change nothing observable today.
	PerLanguage       map[string]any `json:"per_language,omitempty"`
	ParseErrors       []any          `json:"parse_errors,omitempty"`
	ExcludedLanguages map[string]any `json:"excluded_languages,omitempty"`
	Degraded          *bool          `json:"degraded,omitempty"`
	Coverage          map[string]any `json:"coverage,omitempty"`
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
	// #622: the protected split — mirrors AnalysisMetrics.
	Stage2DisagreedProtected int `json:"stage2_disagreed_protected"`
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
	VerifiedResultsPath string `json:"verified_results_path"`
	FindingsInput       int    `json:"findings_input"`
	FindingsVerified    int    `json:"findings_verified"`
	Agreed              int    `json:"agreed"`
	Disagreed           int    `json:"disagreed"`
	// #622: BOTH reclassification siblings — the Python VerifyResult.to_dict
	// envelope carries them (the "Disagreed (eliminated)" display's source);
	// without them the companion lines are unrenderable.
	DisagreedInconclusive    int       `json:"disagreed_inconclusive"`
	DisagreedProtected       int       `json:"disagreed_protected"`
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
	// #598: the incompleteness metadata — a dispatched model without a
	// pricing record means the cost figure is incomplete ($0 attributed,
	// the ids listed); the terminal cost line must never read as a
	// complete figure it is not.
	CostIncomplete bool     `json:"cost_incomplete,omitempty"`
	UnpricedModels []string `json:"unpriced_models,omitempty"`
	// #626: the cache line items. Without these the typed path silently
	// DROPPED them — the terminal renderer survived only because it reads
	// map[string]any. omitempty mirrors the Python side's present-only
	// envelope (core/schemas.py UsageInfo.to_dict), so a no-cache run
	// round-trips to exactly the pre-#626 key set.
	//
	// UnpricedCacheModels is NOT interchangeable with UnpricedModels: the
	// former is a PRICED model whose cache multipliers are absent, the
	// latter has no pricing record at all (its spend attributed $0 — a
	// lower bound). Never merge the two lists.
	//
	// PR#661 hunt F1: this doc used to add "(its cached traffic billed at
	// the full input rate — an upper bound)". That holds only for the
	// INCLUSIVE field shapes (openai cached_tokens, google
	// cached_content_token_count), whose cached tokens are already inside
	// the input count. For the EXCLUSIVE shapes (anthropic/bedrock
	// cache_read_input_tokens, DISJOINT from input_tokens) an absent
	// multiplier contributes $0 and the figure is a LOWER bound — and the
	// whole shipped bedrock census (11/11 priced, no cache block, exclusive
	// fields emitted) is in that case. These fields carry no
	// inclusion-shape discriminator, so no consumer may assert a direction
	// from them; see internal/output.renderCostBlock.
	TotalCacheReadTokens  int      `json:"total_cache_read_tokens,omitempty"`
	TotalCacheWriteTokens int      `json:"total_cache_write_tokens,omitempty"`
	UnpricedCacheModels   []string `json:"unpriced_cache_models,omitempty"`
}
