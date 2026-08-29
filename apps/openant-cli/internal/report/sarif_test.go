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

// ---------------------------------------------------------------------------
// #305: the invocations block — a degraded scan must be distinguishable from
// a clean one on the merge-gate channel.
// ---------------------------------------------------------------------------

func sarifInvocations(t *testing.T, sarif map[string]any) (map[string]any, []map[string]any) {
	t.Helper()
	runs := sarif["runs"].([]any)
	run := runs[0].(map[string]any)
	inv := run["invocations"].([]any)[0].(map[string]any)
	notifs, _ := inv["toolExecutionNotifications"].([]map[string]any)
	if inv["toolExecutionNotifications"] == nil {
		notifs = nil
	} else {
		// tolerate []any too depending on construction
		if asAny, ok := inv["toolExecutionNotifications"].([]any); ok {
			for _, n := range asAny {
				notifs = append(notifs, n.(map[string]any))
			}
		}
	}
	return inv, notifs
}

func TestSARIFCleanScanExecutionSuccessful(t *testing.T) {
	data := ReportData{Title: "t", RepoName: "r", Language: "go",
		StepReports: []StepReport{
			{Step: "parse", Status: "success"},
			{Step: "verify", Status: "skipped", SkippedReason: "no_candidates"},
		}}
	sarif := BuildSARIF(data, SARIFOptions{})
	inv, notifs := sarifInvocations(t, sarif)
	if inv["executionSuccessful"] != true {
		t.Errorf("clean scan (operator opt-out skip) must be executionSuccessful=true; got %v",
			inv["executionSuccessful"])
	}
	if notifs != nil {
		t.Errorf("clean scan carries no notifications; got %v", notifs)
	}
}

func TestSARIFErroredStepFailsExecution(t *testing.T) {
	data := ReportData{Title: "t", RepoName: "r", Language: "go",
		StepReports: []StepReport{
			{Step: "parse", Status: "success"},
			{Step: "verify", Status: "partial", ErrorCount: 48,
				Errors: []string{"adapter raise"}},
		}}
	sarif := BuildSARIF(data, SARIFOptions{})
	inv, notifs := sarifInvocations(t, sarif)
	if inv["executionSuccessful"] != false {
		t.Errorf("errored step must be executionSuccessful=false")
	}
	if len(notifs) == 0 {
		t.Fatalf("errored step must emit a warning notification")
	}
	found := false
	for _, n := range notifs {
		if n["level"] == "warning" {
			found = true
		}
	}
	if !found {
		t.Errorf("notifications must be at warning level (Code Scanning default view)")
	}
}

func TestSARIFFailureClassSkipFailsExecution(t *testing.T) {
	data := ReportData{Title: "t", RepoName: "r", Language: "go",
		StepReports: []StepReport{
			{Step: "parse", Status: "success"},
			{Step: "app-context", Status: "skipped", SkippedReason: "module_unavailable"},
		}}
	sarif := BuildSARIF(data, SARIFOptions{})
	inv, _ := sarifInvocations(t, sarif)
	if inv["executionSuccessful"] != false {
		t.Errorf("module_unavailable is a FAILURE-class skip: executionSuccessful=false")
	}
}

func TestSARIFExcludedLanguageFailsExecution(t *testing.T) {
	data := ReportData{Title: "t", RepoName: "r", Language: "go",
		StepReports:       []StepReport{{Step: "parse", Status: "success"}},
		ExcludedLanguages: []string{"swift"}}
	sarif := BuildSARIF(data, SARIFOptions{})
	inv, notifs := sarifInvocations(t, sarif)
	if inv["executionSuccessful"] != false {
		t.Errorf("an excluded language is a degradation: executionSuccessful=false")
	}
	if len(notifs) == 0 {
		t.Errorf("the excluded language must be notified")
	}
}

func TestSARIFRegionCarriesRealStartLine(t *testing.T) {
	data := ReportData{Title: "t", RepoName: "r", Language: "go",
		Findings: []Finding{{Number: 1, Verdict: "vulnerable", File: "a.go",
			Function: "f", StartLine: 42}},
		StepReports: []StepReport{{Step: "parse", Status: "success"}}}
	sarif := BuildSARIF(data, SARIFOptions{})
	res := sarif["runs"].([]any)[0].(map[string]any)["results"].([]map[string]any)[0]
	loc := res["locations"].([]any)[0].(map[string]any)
	phys := loc["physicalLocation"].(map[string]any)
	region, ok := phys["region"].(map[string]any)
	if !ok {
		t.Fatalf("a finding with StartLine=42 must carry region.startLine; got %v", phys)
	}
	if region["startLine"] != 42 {
		t.Errorf("region.startLine must be 42; got %v", region["startLine"])
	}
}

func TestSARIFNoRegionForUnknownLine(t *testing.T) {
	data := ReportData{Title: "t", RepoName: "r", Language: "go",
		Findings: []Finding{{Number: 1, Verdict: "vulnerable", File: "a.go",
			Function: "f", StartLine: 0}},
		StepReports: []StepReport{{Step: "parse", Status: "success"}}}
	sarif := BuildSARIF(data, SARIFOptions{})
	res := sarif["runs"].([]any)[0].(map[string]any)["results"].([]map[string]any)[0]
	loc := res["locations"].([]any)[0].(map[string]any)
	phys := loc["physicalLocation"].(map[string]any)
	if _, ok := phys["region"]; ok {
		t.Errorf("StartLine=0 (unknown) must stay file-scoped — no synthetic region")
	}
}

// wave catches (#305): the descriptor must be schema-valid (no `name`
// key — reportingDescriptorReference is additionalProperties:false), the
// scan mirror row must not duplicate notifications, docker_unavailable
// is a failure-class skip, and a partial-with-zero-counts step degrades
// visibly without a "0 unit error(s)" text.

func notificationTexts(t *testing.T, inv map[string]any) []string {
	t.Helper()
	var texts []string
	if raw, ok := inv["toolExecutionNotifications"]; ok && raw != nil {
		switch asTyped := raw.(type) {
		case []map[string]any:
			for _, nt := range asTyped {
				d := nt["descriptor"].(map[string]any)
				if _, hasName := d["name"]; hasName {
					t.Errorf("descriptor carries schema-invalid `name`; got %v", d)
				}
				m := nt["message"].(map[string]any)
				texts = append(texts, m["text"].(string))
			}
		case []any:
			for _, n := range asTyped {
				nt := n.(map[string]any)
				d := nt["descriptor"].(map[string]any)
				if _, hasName := d["name"]; hasName {
					t.Errorf("descriptor carries schema-invalid `name`; got %v", d)
				}
				m := nt["message"].(map[string]any)
				texts = append(texts, m["text"].(string))
			}
		}
	}
	return texts
}

func TestSARIFNotificationDescriptorIsSchemaValid(t *testing.T) {
	data := ReportData{Title: "t", RepoName: "r", Language: "go",
		StepReports: []StepReport{
			{Step: "verify", Status: "partial", ErrorCount: 3},
		}}
	sarif := BuildSARIF(data, SARIFOptions{})
	inv, _ := sarifInvocations(t, sarif)
	_ = notificationTexts(t, inv) // asserts descriptor shape inside
}

func TestSARIFScanMirrorRowDoesNotDuplicateNotifications(t *testing.T) {
	data := ReportData{Title: "t", RepoName: "r", Language: "go",
		StepReports: []StepReport{
			{Step: "verify", Status: "partial", ErrorCount: 48,
				Errors: []string{"adapter raise"}},
			// the synthetic aggregate row mirrors verify's errors
			{Step: "scan", Status: "partial", ErrorCount: 48,
				Errors: []string{"adapter raise"}},
		}}
	sarif := BuildSARIF(data, SARIFOptions{})
	inv, _ := sarifInvocations(t, sarif)
	texts := notificationTexts(t, inv)
	verifyNotifs := 0
	for _, txt := range texts {
		if len(txt) >= 11 && txt[:11] == "step verify" {
			verifyNotifs++
		}
		if len(txt) >= 10 && txt[:10] == "step scan:" {
			t.Errorf("the scan mirror row must not emit notifications; got %q", txt)
		}
	}
	if verifyNotifs != 1 {
		t.Errorf("exactly one verify notification expected; got %d (%v)",
			verifyNotifs, texts)
	}
}

func TestSARIFDockerUnavailableIsAFailureSkip(t *testing.T) {
	data := ReportData{Title: "t", RepoName: "r", Language: "go",
		StepReports: []StepReport{
			{Step: "parse", Status: "success"},
			{Step: "dynamic-test", Status: "skipped",
				SkippedReason: "docker_unavailable"},
		}}
	sarif := BuildSARIF(data, SARIFOptions{})
	inv, _ := sarifInvocations(t, sarif)
	if inv["executionSuccessful"] != false {
		t.Errorf("docker_unavailable (a runner without Docker) must be a failure-class skip")
	}
}

func TestSARIFPartialWithoutCountsDegradesVisibly(t *testing.T) {
	data := ReportData{Title: "t", RepoName: "r", Language: "go",
		StepReports: []StepReport{
			{Step: "verify", Status: "partial", ErrorCount: 0},
		}}
	sarif := BuildSARIF(data, SARIFOptions{})
	inv, _ := sarifInvocations(t, sarif)
	if inv["executionSuccessful"] != false {
		t.Errorf("a partial step must fail executionSuccessful even with no counts")
	}
	texts := notificationTexts(t, inv)
	found := false
	for _, txt := range texts {
		if txt == "step verify: degraded (status partial)" {
			found = true
		}
		if txt == "step verify: 0 unit error(s)" {
			t.Errorf("the misleading 0-error text must not appear; got %q", txt)
		}
	}
	if !found {
		t.Errorf("the degraded-status notification must appear; got %v", texts)
	}
}
