package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func sarifFixtureData() ReportData {
	return ReportData{
		Title:     "demo",
		RepoName:  "knostic/demo",
		CommitSHA: "deadbeefcafebabe1234567890abcdefdeadbeef",
		RepoURL:   "https://github.com/knostic/demo",
		Language:  "python",
		Findings: []Finding{
			{
				Number:       1,
				Verdict:      "vulnerable",
				File:         "src/auth/login.py",
				Function:     "do_login",
				AttackVector: "Unsanitized input flows into eval().",
				Analysis:     "User-controlled username is passed to eval, allowing RCE.",
			},
			{
				Number:             2,
				Verdict:            "BYPASSABLE", // exercises normalizedVerdict
				File:               "./src/api/handler.py",
				Function:           "handle_get",
				AttackVector:       "Auth bypass via header injection.",
				DynamicTestStatus:  "CONFIRMED",
				DynamicTestDetails: "PoC succeeded.",
			},
			{
				Number:   3,
				Verdict:  "safe",
				File:     "src/util/helpers.py",
				Function: "noop",
			},
		},
		Categories: []Category{
			{Verdict: "vulnerable", Description: "Confirmed exploitable code path."},
			{Verdict: "bypassable", Description: "Has guard but reachable around it."},
			{Verdict: "safe", Description: "No exploitable path identified."},
		},
	}
}

func TestBuildSARIF_TopLevelEnvelope(t *testing.T) {
	got := BuildSARIF(sarifFixtureData(), SARIFOptions{ToolVersion: "1.2.3"})

	if got["version"] != sarifVersion {
		t.Fatalf("version: got %v, want %s", got["version"], sarifVersion)
	}
	if got["$schema"] != sarifSchema {
		t.Fatalf("$schema: got %v, want %s", got["$schema"], sarifSchema)
	}
	runs, ok := got["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("runs: expected one run, got %v", got["runs"])
	}
}

func TestBuildSARIF_DriverNameAndVersion(t *testing.T) {
	got := BuildSARIF(sarifFixtureData(), SARIFOptions{
		ToolVersion:    "1.2.3",
		InformationURI: "https://github.com/knostic/OpenAnt",
	})
	driver := got["runs"].([]any)[0].(map[string]any)["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "OpenAnt" {
		t.Errorf("driver.name: got %v, want OpenAnt", driver["name"])
	}
	if driver["version"] != "1.2.3" {
		t.Errorf("driver.version: got %v, want 1.2.3", driver["version"])
	}
	if driver["informationUri"] != "https://github.com/knostic/OpenAnt" {
		t.Errorf("driver.informationUri: got %v", driver["informationUri"])
	}
}

func TestBuildSARIF_RulesDeduplicatedByVerdict(t *testing.T) {
	got := BuildSARIF(sarifFixtureData(), SARIFOptions{})
	rules := got["runs"].([]any)[0].(map[string]any)["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]map[string]any)
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules (one per verdict), got %d", len(rules))
	}

	wantIDs := map[string]bool{
		"openant.verdict.vulnerable": false,
		"openant.verdict.bypassable": false,
		"openant.verdict.safe":       false,
	}
	for _, r := range rules {
		id, _ := r["id"].(string)
		if _, ok := wantIDs[id]; ok {
			wantIDs[id] = true
		}
	}
	for id, seen := range wantIDs {
		if !seen {
			t.Errorf("rule %s missing", id)
		}
	}
}

func TestBuildSARIF_ResultLevelMapping(t *testing.T) {
	got := BuildSARIF(sarifFixtureData(), SARIFOptions{})
	results := got["runs"].([]any)[0].(map[string]any)["results"].([]map[string]any)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	wantLevels := []string{"error", "error", "note"}
	for i, r := range results {
		if r["level"] != wantLevels[i] {
			t.Errorf("result[%d].level: got %v, want %s", i, r["level"], wantLevels[i])
		}
	}
}

func TestSarifLevelForVerdict_ErrorAndTaxonomy(t *testing.T) {
	cases := map[string]string{
		// exploitability-confirmed producer verdicts surface as error
		"vulnerable": "error",
		"bypassable": "error",
		// visible-but-not-over-claiming: inconclusive and error (a
		// disclosure-eligible analysis failure) must map to warning so
		// GitHub Code Scanning keeps them in the default view.
		"inconclusive": "warning",
		"error":        "warning",
		// benign / non-producer verdicts stay as note
		"safe":      "note",
		"protected": "note",
		// "unclear" is not a producer verdict; it must fall through to
		// the default arm, never a dedicated warning case.
		"unclear": "note",
		"":        "note",
	}
	for verdict, want := range cases {
		if got := sarifLevelForVerdict(verdict); got != want {
			t.Errorf("sarifLevelForVerdict(%q): got %q, want %q", verdict, got, want)
		}
	}
}

func TestBuildSARIF_FilePathsNormalized(t *testing.T) {
	got := BuildSARIF(sarifFixtureData(), SARIFOptions{})
	results := got["runs"].([]any)[0].(map[string]any)["results"].([]map[string]any)
	uri := results[1]["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)["uri"]
	if uri != "src/api/handler.py" {
		t.Errorf("artifactLocation.uri: got %q, want %q (./ should be stripped)", uri, "src/api/handler.py")
	}
}

func TestBuildSARIF_LogicalLocationCarriesFunction(t *testing.T) {
	got := BuildSARIF(sarifFixtureData(), SARIFOptions{})
	results := got["runs"].([]any)[0].(map[string]any)["results"].([]map[string]any)
	logicals, ok := results[0]["locations"].([]any)[0].(map[string]any)["logicalLocations"].([]any)
	if !ok || len(logicals) != 1 {
		t.Fatalf("logicalLocations missing on result[0]")
	}
	got0 := logicals[0].(map[string]any)
	if got0["name"] != "do_login" || got0["kind"] != "function" {
		t.Errorf("logicalLocations[0]: got %v", got0)
	}
}

func TestBuildSARIF_DynamicTestPropertiesPropagate(t *testing.T) {
	got := BuildSARIF(sarifFixtureData(), SARIFOptions{})
	results := got["runs"].([]any)[0].(map[string]any)["results"].([]map[string]any)
	props := results[1]["properties"].(map[string]any)
	if props["dynamicTestStatus"] != "CONFIRMED" {
		t.Errorf("dynamicTestStatus: got %v", props["dynamicTestStatus"])
	}
	if props["dynamicTestDetails"] != "PoC succeeded." {
		t.Errorf("dynamicTestDetails: got %v", props["dynamicTestDetails"])
	}
}

func TestBuildSARIF_PartialFingerprintsStable(t *testing.T) {
	got := BuildSARIF(sarifFixtureData(), SARIFOptions{})
	results := got["runs"].([]any)[0].(map[string]any)["results"].([]map[string]any)
	for _, r := range results {
		fps, ok := r["partialFingerprints"].(map[string]any)
		if !ok {
			t.Fatalf("partialFingerprints missing on %v", r["ruleId"])
		}
		if _, ok := fps["openant/file/function/verdict/v1"].(string); !ok {
			t.Fatalf("expected v1 fingerprint key on every result")
		}
	}
}

func TestBuildSARIF_VersionControlProvenanceWhenRepoURLPresent(t *testing.T) {
	got := BuildSARIF(sarifFixtureData(), SARIFOptions{})
	run := got["runs"].([]any)[0].(map[string]any)
	prov, ok := run["versionControlProvenance"].([]any)
	if !ok || len(prov) != 1 {
		t.Fatalf("expected versionControlProvenance with one entry")
	}
	entry := prov[0].(map[string]any)
	if entry["repositoryUri"] != "https://github.com/knostic/demo" {
		t.Errorf("repositoryUri: got %v", entry["repositoryUri"])
	}
	if entry["revisionId"] != "deadbeefcafebabe1234567890abcdefdeadbeef" {
		t.Errorf("revisionId: got %v", entry["revisionId"])
	}
}

func TestBuildSARIF_NoVCSWhenRepoURLEmpty(t *testing.T) {
	d := sarifFixtureData()
	d.RepoURL = ""
	got := BuildSARIF(d, SARIFOptions{})
	run := got["runs"].([]any)[0].(map[string]any)
	if _, has := run["versionControlProvenance"]; has {
		t.Fatalf("versionControlProvenance must be omitted when RepoURL is empty")
	}
}

func TestBuildSARIF_MessageFallbackWhenAttackVectorEmpty(t *testing.T) {
	d := ReportData{
		Findings: []Finding{
			{Verdict: "vulnerable", File: "src/x.py"},
		},
	}
	got := BuildSARIF(d, SARIFOptions{})
	results := got["runs"].([]any)[0].(map[string]any)["results"].([]map[string]any)
	msg := results[0]["message"].(map[string]any)["text"].(string)
	if msg == "" {
		t.Fatalf("message.text must never be empty per SARIF schema")
	}
	if !strings.Contains(msg, "src/x.py") {
		t.Errorf("expected fallback message to reference file path, got %q", msg)
	}
}

func TestBuildSARIF_MessageTruncationCap(t *testing.T) {
	huge := strings.Repeat("a", 8000)
	d := ReportData{
		Findings: []Finding{{Verdict: "vulnerable", File: "src/x.py", AttackVector: huge}},
	}
	got := BuildSARIF(d, SARIFOptions{})
	results := got["runs"].([]any)[0].(map[string]any)["results"].([]map[string]any)
	msg := results[0]["message"].(map[string]any)["text"].(string)
	if len(msg) >= len(huge) {
		t.Errorf("message must be truncated, got %d bytes", len(msg))
	}
}

func TestRenderSARIF_RoundTripsThroughJSONUnmarshal(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderSARIF(sarifFixtureData(), &buf, SARIFOptions{ToolVersion: "1.0.0"}); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}

	var anyVal map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &anyVal); err != nil {
		t.Fatalf("emitted SARIF must be valid JSON: %v", err)
	}
	if anyVal["version"] != sarifVersion {
		t.Errorf("round-trip version drift: %v", anyVal["version"])
	}
}

func TestNormalizedVerdict_HandlesEdgeCases(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"VULNERABLE", "vulnerable"},
		{"  Bypassable  ", "bypassable"},
		{"", "unknown"},
	}
	for _, c := range cases {
		if got := normalizedVerdict(c.in); got != c.want {
			t.Errorf("normalizedVerdict(%q): got %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSARIFURI_StripsLeadingDotSlashAndNormalizesBackslashes(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"./src/x.py", "src/x.py"},
		{`src\nested\file.py`, "src/nested/file.py"},
		{"src/x.py", "src/x.py"},
	}
	for _, c := range cases {
		if got := sarifURI(c.in); got != c.want {
			t.Errorf("sarifURI(%q): got %q, want %q", c.in, got, c.want)
		}
	}
}
