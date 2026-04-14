// Package checkpoint provides auto-resume detection for LLM pipeline steps.
//
// When a step (enhance, analyze, verify) is interrupted, per-unit checkpoint
// files remain in {scanDir}/{step}_checkpoints/. On the next run the Go CLI
// detects these files and prompts the user to resume or start fresh.
//
// Checkpoint status (completed vs errored counts) is determined by calling
// the Python CLI's `checkpoint-status` command, which is the single source
// of truth for checkpoint semantics.
package checkpoint

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/knostic/open-ant-cli/internal/python"
)

const summaryFile = "_summary.json"

// Summary represents the _summary.json written by Python pipeline steps.
type Summary struct {
	Step           string         `json:"step"`
	Phase          string         `json:"phase"`
	Timestamp      string         `json:"timestamp"`
	TotalUnits     int            `json:"total_units"`
	Completed      int            `json:"completed"`
	Errors         int            `json:"errors"`
	ErrorBreakdown map[string]int `json:"error_breakdown"`
}

// Info describes an existing checkpoint directory.
type Info struct {
	Dir       string   // full path to the checkpoint dir
	Count     int      // number of successfully completed units
	Errors    int      // number of errored units
	Summary   *Summary // parsed _summary.json (may have counts overridden by Python)
}

// Phase returns the detected phase state as a human-readable string.
func (i *Info) Phase() string {
	if i.Summary == nil {
		return "legacy"
	}
	if i.Summary.Phase == "done" && i.Summary.Errors > 0 {
		return "done_with_errors"
	}
	return i.Summary.Phase // "in_progress" or "done"
}

// DetectViaPython checks for checkpoints by calling the Python CLI's
// checkpoint-status command for accurate completed/errored counts.
// Returns nil if no checkpoint is found or Python fails.
func DetectViaPython(pythonPath, scanDir, stepName string) *Info {
	dir := filepath.Join(scanDir, stepName+"_checkpoints")

	// Quick filesystem check: skip Python call if dir doesn't exist
	if _, err := os.Stat(dir); err != nil {
		return nil
	}

	// Call Python for accurate counts
	result, err := python.Invoke(pythonPath, []string{"checkpoint-status", dir}, "", true, "")
	if err != nil || result.Envelope.Status != "success" {
		// Python failed — fall back to simple file count
		return DetectFallback(scanDir, stepName)
	}

	// Parse the response data
	dataBytes, err := json.Marshal(result.Envelope.Data)
	if err != nil {
		return DetectFallback(scanDir, stepName)
	}

	var status struct {
		Step           string         `json:"step"`
		Completed      int            `json:"completed"`
		Errors         int            `json:"errors"`
		TotalFiles     int            `json:"total_files"`
		TotalUnits     int            `json:"total_units"`
		Phase          string         `json:"phase"`
		ErrorBreakdown map[string]int `json:"error_breakdown"`
	}
	if json.Unmarshal(dataBytes, &status) != nil {
		return DetectFallback(scanDir, stepName)
	}

	if status.TotalFiles == 0 {
		return nil
	}

	// If the previous run finished cleanly (phase=done, no errors), there's
	// nothing to resume — treat it as if there are no checkpoints. The
	// checkpoint files are preserved for audit/retro but don't trigger a prompt.
	if status.Phase == "done" && status.Errors == 0 {
		return nil
	}

	info := &Info{
		Dir:    dir,
		Count:  status.Completed,
		Errors: status.Errors,
		Summary: &Summary{
			Step:           status.Step,
			Phase:          status.Phase,
			TotalUnits:     status.TotalUnits,
			Completed:      status.Completed,
			Errors:         status.Errors,
			ErrorBreakdown: status.ErrorBreakdown,
		},
	}

	return info
}

// DetectFallback checks for checkpoints using only filesystem scanning.
// Used when Python is not available. Counts .json files without classifying
// completed vs errored — all files are counted as completed.
func DetectFallback(scanDir, stepName string) *Info {
	dir := filepath.Join(scanDir, stepName+"_checkpoints")

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	count := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") && e.Name() != summaryFile {
			count++
		}
	}
	if count == 0 {
		return nil
	}

	info := &Info{Dir: dir, Count: count}

	// Try to read _summary.json for phase state and total_units
	summaryPath := filepath.Join(dir, summaryFile)
	data, err := os.ReadFile(summaryPath)
	if err == nil {
		var s Summary
		if json.Unmarshal(data, &s) == nil {
			info.Summary = &s
		}
	}

	return info
}

// PromptResume asks the user whether to resume an interrupted run or start
// fresh. Returns true for resume, false for fresh start.
//
// In non-interactive mode (stdin is not a terminal, or quiet mode), defaults
// to resume.
func PromptResume(info *Info, stepName string, quiet bool) bool {
	if quiet || !isTerminal() {
		// Non-interactive: default to resume
		dim := color.New(color.Faint)
		dim.Fprintf(os.Stderr, "[%s] Auto-resuming from %d checkpointed units (non-interactive)\n",
			stepName, info.Count)
		return true
	}

	yellow := color.New(color.FgYellow, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	bold := color.New(color.Bold)

	fmt.Fprintln(os.Stderr)

	switch info.Phase() {
	case "in_progress":
		// Interrupted run — show progress out of total
		yellow.Fprintf(os.Stderr, "Previous %s run interrupted", stepName)
		s := info.Summary
		if info.Errors > 0 {
			fmt.Fprintf(os.Stderr, " (%d/%d completed, %d errors)\n",
				info.Count, s.TotalUnits, info.Errors)
		} else {
			fmt.Fprintf(os.Stderr, " (%d/%d completed)\n",
				info.Count, s.TotalUnits)
		}

	case "done_with_errors":
		// Ran to completion but had errors — different message
		red.Fprintf(os.Stderr, "Previous %s run completed with errors", stepName)
		s := info.Summary
		fmt.Fprintf(os.Stderr, " (%d/%d completed, %d errors)\n",
			info.Count, s.TotalUnits, info.Errors)

	case "done":
		// Clean completion — shouldn't normally get here (checkpoints cleaned up)
		yellow.Fprintf(os.Stderr, "Previous %s run completed", stepName)
		s := info.Summary
		fmt.Fprintf(os.Stderr, " (%d/%d completed)\n", info.Count, s.TotalUnits)

	default:
		// Legacy format (no _summary.json) or fallback
		yellow.Fprintf(os.Stderr, "Previous %s run found", stepName)
		if info.Errors > 0 {
			fmt.Fprintf(os.Stderr, " (%d completed, %d errors)\n", info.Count, info.Errors)
		} else {
			fmt.Fprintf(os.Stderr, " (~%d units)\n", info.Count)
		}
	}

	fmt.Fprintf(os.Stderr, "  Checkpoint: %s\n", info.Dir)
	fmt.Fprintln(os.Stderr)
	bold.Fprint(os.Stderr, "Resume where you left off? ")
	fmt.Fprint(os.Stderr, "[Y/n] (n = discard progress, start fresh) ")

	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))

	if answer == "" || answer == "y" || answer == "yes" {
		return true
	}
	return false
}

// Clean removes a checkpoint directory.
func Clean(dir string) error {
	return os.RemoveAll(dir)
}

// isTerminal checks if stdin is a terminal (not a pipe).
func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
