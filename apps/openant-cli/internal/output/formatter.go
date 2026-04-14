// Package output handles terminal output formatting.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/knostic/open-ant-cli/internal/types"
)

var (
	bold   = color.New(color.Bold)
	green  = color.New(color.FgGreen, color.Bold)
	red    = color.New(color.FgRed, color.Bold)
	yellow = color.New(color.FgYellow, color.Bold)
	cyan   = color.New(color.FgCyan)
	dim    = color.New(color.Faint)
)

// PrintJSON outputs the raw JSON envelope to stdout.
func PrintJSON(envelope types.Envelope) {
	data, _ := json.MarshalIndent(envelope, "", "  ")
	fmt.Println(string(data))
}

// PrintError outputs an error message to stderr.
func PrintError(msg string) {
	red.Fprintf(os.Stderr, "Error: ")
	fmt.Fprintln(os.Stderr, msg)
}

// PrintErrors outputs multiple error messages to stderr.
func PrintErrors(errors []string) {
	for _, e := range errors {
		PrintError(e)
	}
}

// PrintSuccess outputs a success message.
func PrintSuccess(msg string) {
	green.Print("✓ ")
	fmt.Println(msg)
}

// PrintWarning outputs a warning message to stderr.
func PrintWarning(msg string) {
	yellow.Fprintf(os.Stderr, "Warning: ")
	fmt.Fprintln(os.Stderr, msg)
}

// PrintHeader outputs a section header.
func PrintHeader(msg string) {
	fmt.Println()
	bold.Println(msg)
	fmt.Println(strings.Repeat("─", len(msg)))
}

// PrintKeyValue outputs a key-value pair.
func PrintKeyValue(key, value string) {
	cyan.Printf("  %s: ", key)
	fmt.Println(value)
}

// PrintScanSummary outputs a formatted summary of scan results.
func PrintScanSummary(data map[string]any) {
	metrics, ok := data["metrics"].(map[string]any)
	if !ok {
		return
	}

	PrintHeader("Scan Results")

	total := intFromAny(metrics["total"])
	vulnerable := intFromAny(metrics["vulnerable"])
	safe := intFromAny(metrics["safe"])
	unclear := intFromAny(metrics["inconclusive"])
	verified := intFromAny(metrics["verified"])
	falsePos := intFromAny(metrics["stage2_disagreed"])

	PrintKeyValue("Total units analyzed", fmt.Sprintf("%d", total))

	if vulnerable > 0 {
		red.Printf("  Vulnerable: ")
		fmt.Printf("%d", vulnerable)
		if verified > 0 {
			fmt.Printf(" (%d verified)", verified)
		}
		fmt.Println()
	} else {
		green.Printf("  Vulnerable: ")
		fmt.Println("0")
	}

	PrintKeyValue("Safe", fmt.Sprintf("%d", safe))

	if unclear > 0 {
		yellow.Printf("  Unclear: ")
		fmt.Printf("%d\n", unclear)
	}

	if falsePos > 0 {
		PrintKeyValue("False positives eliminated", fmt.Sprintf("%d", falsePos))
	}

	// Usage info
	if usage, ok := data["usage"].(map[string]any); ok {
		PrintHeader("Usage")
		cost := floatFromAny(usage["total_cost_usd"])
		inputTokens := intFromAny(usage["total_input_tokens"])
		outputTokens := intFromAny(usage["total_output_tokens"])

		PrintKeyValue("Cost", fmt.Sprintf("$%.4f", cost))
		PrintKeyValue("Tokens", fmt.Sprintf("%d input / %d output", inputTokens, outputTokens))
	}

	// Report paths
	if reports, ok := data["reports"].(map[string]any); ok {
		PrintHeader("Reports")
		if html, ok := reports["html_path"].(string); ok && html != "" {
			PrintKeyValue("HTML", html)
		}
		if csv, ok := reports["csv_path"].(string); ok && csv != "" {
			PrintKeyValue("CSV", csv)
		}
		if summary, ok := reports["summary_path"].(string); ok && summary != "" {
			PrintKeyValue("Summary", summary)
		}
	}

	fmt.Println()

	// Final verdict
	if vulnerable > 0 {
		red.Printf("⚠ Found %d vulnerabilit", vulnerable)
		if vulnerable == 1 {
			red.Println("y")
		} else {
			red.Println("ies")
		}
	} else {
		green.Println("✓ No vulnerabilities found")
	}
}

// PrintParseSummary outputs a formatted summary of parse results.
func PrintParseSummary(data map[string]any) {
	PrintHeader("Parse Results")
	if lang, ok := data["language"].(string); ok {
		PrintKeyValue("Language", lang)
	}
	if level, ok := data["processing_level"].(string); ok {
		PrintKeyValue("Processing level", level)
	}
	if units := intFromAny(data["units_count"]); units > 0 {
		PrintKeyValue("Units extracted", fmt.Sprintf("%d", units))
	}
	if path, ok := data["dataset_path"].(string); ok {
		PrintKeyValue("Output", path)
	}
	fmt.Println()
}

// PrintAnalyzeSummary outputs a formatted summary of analysis results.
func PrintAnalyzeSummary(data map[string]any) {
	metrics, ok := data["metrics"].(map[string]any)
	if !ok {
		return
	}

	PrintHeader("Analysis Results")
	total := intFromAny(metrics["total"])
	vulnerable := intFromAny(metrics["vulnerable"])
	bypassable := intFromAny(metrics["bypassable"])
	protected := intFromAny(metrics["protected"])
	safe := intFromAny(metrics["safe"])
	inconclusive := intFromAny(metrics["inconclusive"])
	errors := intFromAny(metrics["errors"])

	PrintKeyValue("Total units", fmt.Sprintf("%d", total))

	combined := vulnerable + bypassable
	if combined > 0 {
		red.Printf("  Vulnerable: %d\n", combined)
	} else {
		green.Printf("  Vulnerable: 0\n")
	}
	PrintKeyValue("Protected", fmt.Sprintf("%d", protected))
	PrintKeyValue("Safe", fmt.Sprintf("%d", safe))
	if inconclusive > 0 {
		yellow.Printf("  Inconclusive: %d\n", inconclusive)
	}
	if errors > 0 {
		yellow.Printf("  Errors: %d\n", errors)
	}

	if path, ok := data["results_path"].(string); ok {
		PrintKeyValue("Output", path)
	}
	fmt.Println()
}

// PrintReportSummary outputs a formatted summary of report generation.
func PrintReportSummary(data map[string]any) {
	PrintHeader("Report Generated")
	if format, ok := data["format"].(string); ok && format != "" {
		PrintKeyValue("Format", format)
	}
	if path, ok := data["output_path"].(string); ok && path != "" {
		PrintKeyValue("Output", path)
	}
	if path, ok := data["reskin_path"].(string); ok && path != "" {
		PrintKeyValue("Reskin", path)
	}
	if usage, ok := data["usage"].(map[string]any); ok {
		cost := floatFromAny(usage["total_cost_usd"])
		if cost > 0 {
			PrintKeyValue("Cost", fmt.Sprintf("$%.4f", cost))
		}
	}
	fmt.Println()
}

// PrintEnhanceSummary outputs a formatted summary of enhancement results.
func PrintEnhanceSummary(data map[string]any) {
	PrintHeader("Enhancement Results")

	units := intFromAny(data["units_enhanced"])
	errors := intFromAny(data["error_count"])
	PrintKeyValue("Units enhanced", fmt.Sprintf("%d", units))
	if errors > 0 {
		yellow.Printf("  Errors: %d\n", errors)
	}

	if classifications, ok := data["classifications"].(map[string]any); ok {
		PrintHeader("Classifications")
		for cls, count := range classifications {
			PrintKeyValue(cls, fmt.Sprintf("%d", intFromAny(count)))
		}
	}

	if path, ok := data["enhanced_dataset_path"].(string); ok {
		PrintKeyValue("Output", path)
	}
	fmt.Println()
}

// PrintVerifySummary outputs a formatted summary of verification results.
func PrintVerifySummary(data map[string]any) {
	PrintHeader("Verification Results (Stage 2)")

	input := intFromAny(data["findings_input"])
	verified := intFromAny(data["findings_verified"])
	agreed := intFromAny(data["agreed"])
	disagreed := intFromAny(data["disagreed"])
	confirmed := intFromAny(data["confirmed_vulnerabilities"])

	PrintKeyValue("Findings input", fmt.Sprintf("%d", input))
	PrintKeyValue("Findings verified", fmt.Sprintf("%d", verified))

	if agreed > 0 {
		red.Printf("  Agreed (confirmed): %d\n", agreed)
	}
	if disagreed > 0 {
		green.Printf("  Disagreed (eliminated): %d\n", disagreed)
	}

	fmt.Println()
	if confirmed > 0 {
		red.Printf("⚠ %d confirmed vulnerabilit", confirmed)
		if confirmed == 1 {
			red.Println("y")
		} else {
			red.Println("ies")
		}
	} else {
		green.Println("✓ No confirmed vulnerabilities")
	}

	if path, ok := data["verified_results_path"].(string); ok {
		PrintKeyValue("Output", path)
	}
	fmt.Println()
}

// PrintDynamicTestSummary outputs a formatted summary of dynamic test results.
func PrintDynamicTestSummary(data map[string]any) {
	PrintHeader("Dynamic Test Results")

	tested := intFromAny(data["findings_tested"])
	confirmed := intFromAny(data["confirmed"])
	notReproduced := intFromAny(data["not_reproduced"])
	blocked := intFromAny(data["blocked"])
	inconclusive := intFromAny(data["inconclusive"])
	errors := intFromAny(data["errors"])

	PrintKeyValue("Findings tested", fmt.Sprintf("%d", tested))

	if confirmed > 0 {
		red.Printf("  Confirmed: %d\n", confirmed)
	}
	if notReproduced > 0 {
		green.Printf("  Not reproduced: %d\n", notReproduced)
	}
	if blocked > 0 {
		yellow.Printf("  Blocked: %d\n", blocked)
	}
	if inconclusive > 0 {
		yellow.Printf("  Inconclusive: %d\n", inconclusive)
	}
	if errors > 0 {
		red.Printf("  Errors: %d\n", errors)
	}

	if path, ok := data["results_json_path"].(string); ok {
		PrintKeyValue("Results", path)
	}
	fmt.Println()
}

// PrintBuildOutputSummary outputs a formatted summary of pipeline output generation.
func PrintBuildOutputSummary(data map[string]any) {
	PrintHeader("Pipeline Output")

	findings := intFromAny(data["findings_count"])
	PrintKeyValue("Findings included", fmt.Sprintf("%d", findings))

	if path, ok := data["pipeline_output_path"].(string); ok {
		PrintKeyValue("Output", path)
	}
	fmt.Println()
}

// PrintScanSummaryV2 outputs a formatted summary of scan results using the
// updated pipeline output schema (Phase 9+).
func PrintScanSummaryV2(data map[string]any) {
	metrics, ok := data["metrics"].(map[string]any)
	if !ok {
		// Fall back to legacy format
		PrintScanSummary(data)
		return
	}

	PrintHeader("Scan Results")

	total := intFromAny(metrics["total"])
	vulnerable := intFromAny(metrics["vulnerable"])
	bypassable := intFromAny(metrics["bypassable"])
	protected := intFromAny(metrics["protected"])
	safe := intFromAny(metrics["safe"])
	inconclusive := intFromAny(metrics["inconclusive"])
	errors := intFromAny(metrics["errors"])
	verified := intFromAny(metrics["verified"])

	PrintKeyValue("Total units analyzed", fmt.Sprintf("%d", total))

	combined := vulnerable + bypassable
	if combined > 0 {
		red.Printf("  Vulnerable: %d\n", combined)
	} else {
		green.Printf("  Vulnerable: 0\n")
	}
	PrintKeyValue("Protected", fmt.Sprintf("%d", protected))
	PrintKeyValue("Safe", fmt.Sprintf("%d", safe))
	if inconclusive > 0 {
		yellow.Printf("  Inconclusive: %d\n", inconclusive)
	}
	if errors > 0 {
		yellow.Printf("  Errors: %d\n", errors)
	}
	if verified > 0 {
		agreed := intFromAny(metrics["stage2_agreed"])
		disagreed := intFromAny(metrics["stage2_disagreed"])
		PrintKeyValue("Verified (Stage 2)", fmt.Sprintf("%d (%d agreed, %d disagreed)",
			verified, agreed, disagreed))
	}

	// Usage info
	if usage, ok := data["usage"].(map[string]any); ok {
		PrintHeader("Usage")
		cost := floatFromAny(usage["total_cost_usd"])
		inputTokens := intFromAny(usage["total_input_tokens"])
		outputTokens := intFromAny(usage["total_output_tokens"])

		PrintKeyValue("Cost", fmt.Sprintf("$%.4f", cost))
		PrintKeyValue("Tokens", fmt.Sprintf("%d input / %d output", inputTokens, outputTokens))
	}

	// Output paths
	PrintHeader("Output Files")
	if dir, ok := data["output_dir"].(string); ok {
		PrintKeyValue("Directory", dir)
	}
	if path, ok := data["pipeline_output_path"].(string); ok && path != "" {
		PrintKeyValue("Pipeline output", path)
	}
	if path, ok := data["summary_path"].(string); ok && path != "" {
		PrintKeyValue("Summary report", path)
	}

	// Skipped steps
	if skipped, ok := data["skipped_steps"].([]any); ok && len(skipped) > 0 {
		names := make([]string, 0, len(skipped))
		for _, s := range skipped {
			if name, ok := s.(string); ok {
				names = append(names, name)
			}
		}
		if len(names) > 0 {
			dim.Printf("  Skipped: %s\n", strings.Join(names, ", "))
		}
	}

	fmt.Println()

	// Final verdict
	if combined > 0 {
		red.Printf("⚠ Found %d vulnerabilit", combined)
		if combined == 1 {
			red.Println("y")
		} else {
			red.Println("ies")
		}
	} else {
		green.Println("✓ No vulnerabilities found")
	}
}

// PrintVersion outputs version info.
func PrintVersion(version, goVersion, pythonVersion string) {
	bold.Printf("openant ")
	fmt.Println(version)
	dim.Printf("  Go:     %s\n", goVersion)
	if pythonVersion != "" {
		dim.Printf("  Python: %s\n", pythonVersion)
	}
}

// intFromAny extracts an int from a JSON-decoded any value (which is float64).
func intFromAny(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		return 0
	}
}

// floatFromAny extracts a float64 from a JSON-decoded any value.
func floatFromAny(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	default:
		return 0
	}
}
