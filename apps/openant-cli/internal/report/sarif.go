package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// sarifVersion is the SARIF spec version we emit. 2.1.0 is what GitHub Code
// Scanning, GitLab SAST, and most third-party SARIF consumers expect.
const sarifVersion = "2.1.0"

// sarifSchema points at the OASIS-published JSON schema for SARIF 2.1.0.
// Consumers that schema-validate the upload (e.g. GitHub Code Scanning's
// pre-ingest check) read this URL.
const sarifSchema = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"

// SARIFOptions controls extra metadata baked into the emitted log. All fields
// are optional; sensible defaults are chosen when empty.
type SARIFOptions struct {
	// ToolVersion is `tool.driver.version`. Defaults to "dev" when empty.
	ToolVersion string
	// InformationURI is `tool.driver.informationUri`. Points reviewers at
	// the project for context on the verdicts.
	InformationURI string
	// ToolName overrides `tool.driver.name`. Defaults to "OpenAnt".
	ToolName string
}

// BuildSARIF turns a ReportData (the same struct that drives the HTML report)
// into a SARIF 2.1.0 log. The returned value is plain map[string]any so it
// round-trips cleanly through json.Marshal — keeping the schema explicit at
// the call site instead of fragmenting it across a dozen typed structs.
func BuildSARIF(data ReportData, opts SARIFOptions) map[string]any {
	if opts.ToolName == "" {
		opts.ToolName = "OpenAnt"
	}
	if opts.ToolVersion == "" {
		opts.ToolVersion = "dev"
	}

	rules, ruleIndex := sarifRulesFor(data)
	results := make([]map[string]any, 0, len(data.Findings))
	for _, f := range data.Findings {
		results = append(results, sarifResultFor(f, ruleIndex))
	}

	driver := map[string]any{
		"name":            opts.ToolName,
		"version":         opts.ToolVersion,
		"semanticVersion": opts.ToolVersion,
		"rules":           rules,
	}
	if opts.InformationURI != "" {
		driver["informationUri"] = opts.InformationURI
	}

	run := map[string]any{
		"tool": map[string]any{
			"driver": driver,
		},
		"results": results,
	}
	if data.RepoURL != "" {
		// versionControlProvenance is consumed by GitHub Code Scanning to
		// associate the upload with a specific commit. Skip when we don't
		// have it rather than emitting an empty/misleading object.
		prov := map[string]any{
			"repositoryUri": data.RepoURL,
		}
		if data.CommitSHA != "" {
			prov["revisionId"] = data.CommitSHA
		}
		run["versionControlProvenance"] = []any{prov}
	}

	return map[string]any{
		"$schema": sarifSchema,
		"version": sarifVersion,
		"runs":    []any{run},
	}
}

// sarifRulesFor returns the SARIF `rules` array plus a map from verdict
// string to its index in that array. We synthesize one rule per distinct
// verdict (vulnerable, bypassable, …) since OpenAnt findings are not yet
// keyed by a stable per-rule taxonomy. Categories from ReportData supply
// the rule descriptions.
func sarifRulesFor(data ReportData) ([]map[string]any, map[string]int) {
	descByVerdict := make(map[string]string, len(data.Categories))
	for _, c := range data.Categories {
		descByVerdict[c.Verdict] = c.Description
	}

	seen := make(map[string]int)
	rules := make([]map[string]any, 0)
	for _, f := range data.Findings {
		v := normalizedVerdict(f.Verdict)
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = len(rules)

		desc := descByVerdict[v]
		if desc == "" {
			desc = fmt.Sprintf("Finding with verdict %q.", v)
		}

		rules = append(rules, map[string]any{
			"id":   "openant.verdict." + v,
			"name": "OpenAntVerdict_" + strings.ReplaceAll(v, "-", "_"),
			"shortDescription": map[string]any{
				"text": fmt.Sprintf("OpenAnt %s finding", v),
			},
			"fullDescription": map[string]any{
				"text": desc,
			},
			"defaultConfiguration": map[string]any{
				"level": sarifLevelForVerdict(v),
			},
			"properties": map[string]any{
				"verdict": v,
				"tags":    []string{"security", "openant"},
			},
		})
	}

	return rules, seen
}

// sarifResultFor renders a single Finding as a SARIF result object.
//
// We intentionally emit a file-scoped location with no startLine because the
// current Finding struct does not carry line numbers; emitting startLine: 1
// (or any synthetic value) would cause GitHub Code Scanning to anchor the
// alert to the wrong row, which is worse than no anchor at all. When line
// data lands in ReportData, the region payload here is the only place that
// needs to grow.
func sarifResultFor(f Finding, ruleIndex map[string]int) map[string]any {
	v := normalizedVerdict(f.Verdict)

	result := map[string]any{
		"ruleId": "openant.verdict." + v,
		"level":  sarifLevelForVerdict(v),
		"message": map[string]any{
			"text": findingMessage(f),
		},
		"locations": []any{
			sarifLocationFor(f),
		},
	}

	if idx, ok := ruleIndex[v]; ok {
		result["ruleIndex"] = idx
	}

	props := map[string]any{
		"verdict":  v,
		"function": f.Function,
	}
	if f.DynamicTestStatus != "" {
		props["dynamicTestStatus"] = f.DynamicTestStatus
	}
	if f.DynamicTestDetails != "" {
		props["dynamicTestDetails"] = f.DynamicTestDetails
	}
	result["properties"] = props

	// PartialFingerprints is what makes SARIF de-dup work across runs in
	// GitHub Code Scanning. Without these, the same finding from successive
	// scans shows up as a fresh alert each time.
	result["partialFingerprints"] = map[string]any{
		"openant/file/function/verdict/v1": fingerprintFor(f, v),
	}

	return result
}

// sarifLocationFor builds the SARIF `location` object for a finding. The
// physicalLocation has only artifactLocation + a logicalLocations entry for
// the function name (so SARIF consumers that care about logical scope still
// get something).
func sarifLocationFor(f Finding) map[string]any {
	loc := map[string]any{
		"physicalLocation": map[string]any{
			"artifactLocation": map[string]any{
				"uri":       sarifURI(f.File),
				"uriBaseId": "%SRCROOT%",
			},
		},
	}
	if f.Function != "" {
		loc["logicalLocations"] = []any{
			map[string]any{
				"name": f.Function,
				"kind": "function",
			},
		}
	}
	return loc
}

// findingMessage condenses the Finding's narrative fields into a single
// `message.text` line. SARIF allows arbitrary length here, but we cap so
// CI inboxes don't drown.
func findingMessage(f Finding) string {
	parts := []string{}
	if f.AttackVector != "" {
		parts = append(parts, strings.TrimSpace(f.AttackVector))
	}
	if f.Analysis != "" {
		parts = append(parts, strings.TrimSpace(f.Analysis))
	}
	if len(parts) == 0 {
		// Fall back so the result still passes SARIF schema validation,
		// which requires `message.text` to be non-empty.
		return fmt.Sprintf("OpenAnt %s finding in %s", f.Verdict, f.File)
	}
	msg := strings.Join(parts, "\n\n")
	const cap = 4096
	if len(msg) > cap {
		msg = msg[:cap-1] + "…"
	}
	return msg
}

// fingerprintFor returns a stable string used as the SARIF result's
// `partialFingerprints` value. Order of fields is fixed and explicit so
// that adding a new Finding field later cannot silently invalidate
// existing fingerprints.
func fingerprintFor(f Finding, verdict string) string {
	return fmt.Sprintf("%s|%s|%s", f.File, f.Function, verdict)
}

// sarifLevelForVerdict maps an OpenAnt verdict to a SARIF result.level.
// Vulnerable + bypassable surface as `error`. Inconclusive AND `error` (a
// disclosure-eligible analysis failure — see core/verdict_taxonomy.py
// PRODUCER_VERDICTS/DISCLOSURE_ELIGIBLE) surface as `warning` so they stay
// VISIBLE in Code Scanning's default view rather than silently vanishing;
// `unclear` (a non-taxonomy value) stays `warning` too — an out-of-taxonomy
// verdict is an anomaly that must be seen, never hidden (over-seed safety).
// Everything else (safe, protected, etc.) is `note` so it doesn't pollute
// alert lists.
func sarifLevelForVerdict(v string) string {
	switch v {
	case "vulnerable", "bypassable":
		return "error"
	case "inconclusive", "unclear", "error":
		return "warning"
	default:
		return "note"
	}
}

// normalizedVerdict trims/lowercases the verdict so casing or whitespace
// drift in upstream pipeline output cannot fan rules out.
func normalizedVerdict(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return "unknown"
	}
	return v
}

// sarifURI normalizes a file path into a SARIF artifactLocation.uri value.
// SARIF wants forward slashes and stable relative paths; we strip any
// leading "./" but otherwise preserve the path as-recorded so consumers can
// match it against the working tree.
func sarifURI(path string) string {
	p := strings.ReplaceAll(path, "\\", "/")
	p = strings.TrimPrefix(p, "./")
	return p
}

// GenerateSARIF renders a SARIF log to the given output path, creating
// parent directories as needed. The file is overwritten if present.
func GenerateSARIF(data ReportData, outputPath string, opts SARIFOptions) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	return RenderSARIF(data, f, opts)
}

// RenderSARIF writes a SARIF log to the given writer. Indented for human
// review; consumers that care about size can pass through `jq -c` to
// minify.
func RenderSARIF(data ReportData, w io.Writer, opts SARIFOptions) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(BuildSARIF(data, opts))
}
