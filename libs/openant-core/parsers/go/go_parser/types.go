package main

// ScanResult represents the output of the repository scanner (Stage 1)
type ScanResult struct {
	Repository string         `json:"repository"`
	ScanTime   string         `json:"scan_time"`
	Files      []FileInfo     `json:"files"`
	Statistics ScanStatistics `json:"statistics"`
}

type FileInfo struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	Extension string `json:"extension"`
}

type ScanStatistics struct {
	TotalFiles          int            `json:"totalFiles"`
	ByExtension         map[string]int `json:"byExtension"`
	TotalSizeBytes      int64          `json:"totalSizeBytes"`
	DirectoriesScanned  int            `json:"directoriesScanned"`
	DirectoriesExcluded int            `json:"directoriesExcluded"`
}

// AnalyzerOutput represents the output of the function extractor (Stage 2)
// This format is compatible with OpenAnt's Stage 2 verification tools
type AnalyzerOutput struct {
	RepoRoot  string                  `json:"repoRoot"`
	Functions map[string]FunctionInfo `json:"functions"`
}

type FunctionInfo struct {
	Name       string   `json:"name"`
	Code       string   `json:"code"`
	StartLine  int      `json:"startLine"`
	EndLine    int      `json:"endLine"`
	UnitType   string   `json:"unitType"`
	ClassName  string   `json:"className,omitempty"` // For methods, this is the receiver type
	IsExported bool     `json:"isExported"`
	Package    string   `json:"package"`
	FilePath   string   `json:"filePath"`
	Receiver   string   `json:"receiver,omitempty"` // Receiver type for methods
	Parameters []string `json:"parameters,omitempty"`
	Returns    []string `json:"returns,omitempty"`
	IsAsync    bool     `json:"isAsync"`              // For goroutine detection
	Decorators []string `json:"decorators,omitempty"` // Go doesn't have decorators, but comments can serve similar purpose
}

// CallGraph represents the output of the call graph builder (Stage 3)
type CallGraph struct {
	CallGraph        map[string][]string `json:"call_graph"`         // func_id -> [called_func_ids]
	ReverseCallGraph map[string][]string `json:"reverse_call_graph"` // func_id -> [caller_func_ids]
	Statistics       CallGraphStats      `json:"statistics"`
}

type CallGraphStats struct {
	TotalEdges   int     `json:"total_edges"`
	AvgOutDegree float64 `json:"avg_out_degree"`
	MaxOutDegree int     `json:"max_out_degree"`
	TotalNodes   int     `json:"total_nodes"`
}

// Dataset represents the final OpenAnt-compatible output (Stage 4)
type Dataset struct {
	Name       string          `json:"name"`
	Repository string          `json:"repository"`
	Units      []Unit          `json:"units"`
	Statistics DatasetStats    `json:"statistics"`
	Metadata   DatasetMetadata `json:"metadata"`
}

type Unit struct {
	ID          string       `json:"id"`
	UnitType    string       `json:"unit_type"`
	Code        CodeBlock    `json:"code"`
	GroundTruth GroundTruth  `json:"ground_truth"`
	Metadata    UnitMetadata `json:"metadata"`
	LLMContext  *LLMContext  `json:"llm_context,omitempty"`
}

type CodeBlock struct {
	PrimaryCode        string             `json:"primary_code"`
	PrimaryOrigin      PrimaryOrigin      `json:"primary_origin"`
	Dependencies       []Dependency       `json:"dependencies"`
	DependencyMetadata DependencyMetadata `json:"dependency_metadata"`
}

type PrimaryOrigin struct {
	FilePath       string   `json:"file_path"`
	StartLine      int      `json:"start_line"`
	EndLine        int      `json:"end_line"`
	FunctionName   string   `json:"function_name"`
	ClassName      string   `json:"class_name,omitempty"`
	DepsInlined    bool     `json:"deps_inlined"`
	FilesIncluded  []string `json:"files_included"`
	OriginalLength int      `json:"original_length"`
	EnhancedLength int      `json:"enhanced_length"`
}

type Dependency struct {
	ID       string `json:"id"`
	FilePath string `json:"file_path"`
	Code     string `json:"code"`
}

type DependencyMetadata struct {
	Depth           int `json:"depth"`
	TotalUpstream   int `json:"total_upstream"`
	TotalDownstream int `json:"total_downstream"`
	DirectCalls     int `json:"direct_calls"`
	DirectCallers   int `json:"direct_callers"`
}

type GroundTruth struct {
	Status             string   `json:"status"`
	VulnerabilityTypes []string `json:"vulnerability_types"`
	Issues             []string `json:"issues"`
	AnnotationSource   *string  `json:"annotation_source"`
	AnnotationKey      *string  `json:"annotation_key"`
	Notes              *string  `json:"notes"`
}

type UnitMetadata struct {
	Generator     string   `json:"generator"`
	DirectCalls   []string `json:"direct_calls"`
	DirectCallers []string `json:"direct_callers"`
	Package       string   `json:"package,omitempty"`
	Receiver      string   `json:"receiver,omitempty"`
	IsExported    bool     `json:"is_exported"`
	Parameters    []string `json:"parameters,omitempty"`
	Returns       []string `json:"returns,omitempty"`
}

type LLMContext struct {
	Reasoning              string `json:"reasoning,omitempty"`
	SecurityClassification string `json:"security_classification,omitempty"`
}

type DatasetStats struct {
	TotalUnits          int            `json:"total_units"`
	ByType              map[string]int `json:"by_type"`
	UnitsWithUpstream   int            `json:"units_with_upstream"`
	UnitsWithDownstream int            `json:"units_with_downstream"`
	UnitsEnhanced       int            `json:"units_enhanced"`
	AvgUpstream         float64        `json:"avg_upstream"`
	AvgDownstream       float64        `json:"avg_downstream"`
	CallGraph           CallGraphStats `json:"call_graph"`
}

type DatasetMetadata struct {
	Generator       string `json:"generator"`
	GeneratedAt     string `json:"generated_at"`
	DependencyDepth int    `json:"dependency_depth"`
}

// Unit type constants
const (
	UnitTypeFunction    = "function"
	UnitTypeMethod      = "method"
	UnitTypeInit        = "init"
	UnitTypeMain        = "main"
	UnitTypeTest        = "test"
	UnitTypeHTTPHandler = "http_handler"
	UnitTypeCLIHandler  = "cli_handler"
	UnitTypeMiddleware  = "middleware"
)

// File boundary marker for enhanced code
const FileBoundary = "\n\n// ========== File Boundary ==========\n\n"
