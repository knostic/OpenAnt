package main

import (
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Generator creates OpenAnt-compatible dataset units
type Generator struct {
	repoPath  string
	maxDepth  int
	analyzer  *AnalyzerOutput
	callGraph *CallGraph
}

// NewGenerator creates a new unit generator
func NewGenerator(repoPath string, analyzer *AnalyzerOutput, callGraph *CallGraph, maxDepth int) *Generator {
	return &Generator{
		repoPath:  repoPath,
		maxDepth:  maxDepth,
		analyzer:  analyzer,
		callGraph: callGraph,
	}
}

// Generate creates the full dataset
func (g *Generator) Generate() *Dataset {
	units := make([]Unit, 0, len(g.analyzer.Functions))
	byType := make(map[string]int)
	unitsWithUpstream := 0
	unitsWithDownstream := 0
	unitsEnhanced := 0
	totalUpstream := 0
	totalDownstream := 0

	for funcID, funcInfo := range g.analyzer.Functions {
		unit := g.createUnit(funcID, funcInfo)
		units = append(units, unit)

		// Update statistics
		byType[unit.UnitType]++

		upstream := unit.Code.DependencyMetadata.TotalUpstream
		downstream := unit.Code.DependencyMetadata.TotalDownstream

		if upstream > 0 {
			unitsWithUpstream++
			totalUpstream += upstream
		}
		if downstream > 0 {
			unitsWithDownstream++
			totalDownstream += downstream
		}
		if unit.Code.PrimaryOrigin.DepsInlined {
			unitsEnhanced++
		}
	}

	// Sort units by ID for deterministic output
	sort.Slice(units, func(i, j int) bool {
		return units[i].ID < units[j].ID
	})

	// Calculate averages
	avgUpstream := 0.0
	avgDownstream := 0.0
	if len(units) > 0 {
		avgUpstream = float64(totalUpstream) / float64(len(units))
		avgDownstream = float64(totalDownstream) / float64(len(units))
	}

	return &Dataset{
		Name:       filepath.Base(g.repoPath),
		Repository: g.repoPath,
		Units:      units,
		Statistics: DatasetStats{
			TotalUnits:          len(units),
			ByType:              byType,
			UnitsWithUpstream:   unitsWithUpstream,
			UnitsWithDownstream: unitsWithDownstream,
			UnitsEnhanced:       unitsEnhanced,
			AvgUpstream:         avgUpstream,
			AvgDownstream:       avgDownstream,
			CallGraph:           g.callGraph.Statistics,
		},
		Metadata: DatasetMetadata{
			Generator:       "go_parser",
			GeneratedAt:     time.Now().Format(time.RFC3339),
			DependencyDepth: g.maxDepth,
		},
	}
}

func (g *Generator) createUnit(funcID string, funcInfo FunctionInfo) Unit {
	// Get direct calls and callers
	directCalls := g.callGraph.CallGraph[funcID]
	directCallers := g.callGraph.ReverseCallGraph[funcID]

	// Get all upstream dependencies (BFS)
	upstream := g.getUpstream(funcID)

	// Get all downstream callers (BFS)
	downstream := g.getDownstream(funcID)

	// Assemble enhanced code
	primaryCode, filesIncluded := g.assembleEnhancedCode(funcInfo, upstream)
	originalLength := len(funcInfo.Code)
	enhancedLength := len(primaryCode)
	depsInlined := enhancedLength > originalLength

	return Unit{
		ID:       funcID,
		UnitType: funcInfo.UnitType,
		Code: CodeBlock{
			PrimaryCode: primaryCode,
			PrimaryOrigin: PrimaryOrigin{
				FilePath:       funcInfo.FilePath,
				StartLine:      funcInfo.StartLine,
				EndLine:        funcInfo.EndLine,
				FunctionName:   funcInfo.Name,
				ClassName:      funcInfo.ClassName,
				DepsInlined:    depsInlined,
				FilesIncluded:  filesIncluded,
				OriginalLength: originalLength,
				EnhancedLength: enhancedLength,
			},
			Dependencies: []Dependency{},
			DependencyMetadata: DependencyMetadata{
				Depth:           g.maxDepth,
				TotalUpstream:   len(upstream),
				TotalDownstream: len(downstream),
				DirectCalls:     len(directCalls),
				DirectCallers:   len(directCallers),
			},
		},
		GroundTruth: GroundTruth{
			Status:             "UNKNOWN",
			VulnerabilityTypes: []string{},
			Issues:             []string{},
		},
		Metadata: UnitMetadata{
			Generator:     "go_parser",
			DirectCalls:   directCalls,
			DirectCallers: directCallers,
			Package:       funcInfo.Package,
			Receiver:      funcInfo.Receiver,
			IsExported:    funcInfo.IsExported,
			Parameters:    funcInfo.Parameters,
			Returns:       funcInfo.Returns,
		},
	}
}

// getUpstream returns all functions called by this function (BFS)
func (g *Generator) getUpstream(funcID string) []string {
	visited := make(map[string]bool)
	visited[funcID] = true

	queue := []struct {
		id    string
		depth int
	}{{funcID, 0}}

	var result []string

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current.depth >= g.maxDepth {
			continue
		}

		// Get functions called by current
		called := g.callGraph.CallGraph[current.id]
		for _, calledID := range called {
			if !visited[calledID] {
				visited[calledID] = true
				result = append(result, calledID)
				queue = append(queue, struct {
					id    string
					depth int
				}{calledID, current.depth + 1})
			}
		}
	}

	return result
}

// getDownstream returns all functions that call this function (BFS)
func (g *Generator) getDownstream(funcID string) []string {
	visited := make(map[string]bool)
	visited[funcID] = true

	queue := []struct {
		id    string
		depth int
	}{{funcID, 0}}

	var result []string

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current.depth >= g.maxDepth {
			continue
		}

		// Get functions that call current
		callers := g.callGraph.ReverseCallGraph[current.id]
		for _, callerID := range callers {
			if !visited[callerID] {
				visited[callerID] = true
				result = append(result, callerID)
				queue = append(queue, struct {
					id    string
					depth int
				}{callerID, current.depth + 1})
			}
		}
	}

	return result
}

// assembleEnhancedCode combines primary code with upstream dependencies
func (g *Generator) assembleEnhancedCode(funcInfo FunctionInfo, upstream []string) (string, []string) {
	var parts []string
	filesIncluded := []string{funcInfo.FilePath}
	seenFiles := map[string]bool{funcInfo.FilePath: true}

	// Start with primary code
	parts = append(parts, funcInfo.Code)

	// Add upstream dependencies
	for _, depID := range upstream {
		depInfo, ok := g.analyzer.Functions[depID]
		if !ok {
			continue
		}

		// Track files
		if !seenFiles[depInfo.FilePath] {
			seenFiles[depInfo.FilePath] = true
			filesIncluded = append(filesIncluded, depInfo.FilePath)
		}

		// Add dependency code with file boundary
		parts = append(parts, FileBoundary+depInfo.Code)
	}

	return strings.Join(parts, ""), filesIncluded
}
