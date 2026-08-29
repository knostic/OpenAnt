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

	// #305: the invocations block — the designated SARIF place a degraded
	// scan becomes visible on the one channel that turns into a merge gate.
	// executionSuccessful is FALSE when any step errored (per-step
	// error_count / errors) or any skipped step carries a FAILURE-class
	// reason; an operator opt-out (not_requested) or an auto-skip with no
	// candidates is a legitimate clean run, not a failure.
	invocation := map[string]any{
		"executionSuccessful": true,
	}
	var notifications []map[string]any
	warn := func(text string) {
		notifications = append(notifications, map[string]any{
			"level": "warning", // Code Scanning keeps warnings in the default view
			// descriptor is a reportingDescriptorReference per the SARIF 2.1.0
			// schema (additionalProperties: false — a `name` key here would be
			// schema-INVALID and risks the whole upload being rejected; the
			// text lives in message.text). Wave catch.
			"descriptor": map[string]any{"id": "OpenAnt"},
			"message":    map[string]any{"text": text},
		})
	}
	failureSkip := map[string]bool{
		"failed":             true,
		"module_unavailable": true,
		// wave catch: docker_unavailable is the same kind of involuntary
		// environment gap as module_unavailable (the dynamic-test step on a
		// runner without Docker) — it was silently passing as clean.
		"docker_unavailable": true,
	}
	execOK := true
	for _, sr := range data.StepReports {
		// wave catch: the synthetic `scan` aggregate row mirrors every real
		// step's errors — emitting it would duplicate each notification
		// under a step name that is not part of the pipeline vocabulary.
		if sr.Step == "scan" {
			continue
		}
		if sr.ErrorCount > 0 || len(sr.Errors) > 0 ||
			sr.Status == "error" || sr.Status == "partial" {
			execOK = false
			if sr.ErrorCount > 0 || len(sr.Errors) > 0 {
				detail := fmt.Sprintf("step %s: %d unit error(s)", sr.Step, sr.ErrorCount)
				if len(sr.Errors) > 0 {
					detail += " — " + strings.Join(sr.Errors, "; ")
				}
				warn(detail)
			} else {
				// wave catch: partial with no populated counts — degrade
				// visibly without a misleading "0 unit error(s)" text.
				warn(fmt.Sprintf("step %s: degraded (status %s)", sr.Step, sr.Status))
			}
		}
		if failureSkip[sr.SkippedReason] {
			execOK = false
			warn(fmt.Sprintf("step %s skipped: %s", sr.Step, sr.SkippedReason))
		}
	}
	for _, lang := range data.ExcludedLanguages {
		if lang == "" {
			continue
		}
		execOK = false
		warn(fmt.Sprintf("language excluded from analysis: %s", lang))
	}
	invocation["executionSuccessful"] = execOK
	if len(notifications) > 0 {
		invocation["toolExecutionNotifications"] = notifications
	}
	run["invocations"] = []any{invocation}

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
// We emit a file-scoped location, with a region ONLY when the finding
// carries a real line anchor (Finding.StartLine, threaded by the report-data
// projection — #305). Emitting startLine: 1 (or any synthetic value) would
// cause GitHub Code Scanning to anchor the alert to the wrong row, which is
// worse than no anchor at all, so a 0/unknown line stays file-scoped.
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
	// #305: line data now reaches ReportData (Finding.StartLine). Emit the
	// region ONLY when the anchor is real — the file-scoped location stands
	// when the line is unknown (0), per the no-synthetic-line rule above.
	if f.StartLine > 0 {
		loc["physicalLocation"].(map[string]any)["region"] = map[string]any{
			"startLine": f.StartLine,
		}
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
// Vulnerable + bypassable surface as `error`; inconclusive + error (a
// disclosure-eligible analysis failure — see core/verdict_taxonomy.py) as
// `warning` so they stay visible; everything else (safe, protected, etc.)
// as `note` so they don't pollute Code-Scanning alert lists.
func sarifLevelForVerdict(v string) string {
	switch v {
	case "vulnerable", "bypassable":
		return "error"
	// "error" is a real producer verdict (core/verdict_taxonomy.py: PRODUCER_VERDICTS
	// and DISCLOSURE_ELIGIBLE) meaning a unit whose analysis errored — surfaced so it
	// stays on the manual-triage radar. It must be VISIBLE, not "note" (which GitHub
	// Code Scanning filters from the default view). "unclear" is not a producer verdict,
	// so it has no dedicated arm.
	case "inconclusive", "error":
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
