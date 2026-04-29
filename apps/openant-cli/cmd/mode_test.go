package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/knostic/open-ant-cli/internal/config"
)

func TestValidateModeFlags(t *testing.T) {
	cases := []struct {
		name    string
		opts    modeOpts
		wantErr string
	}{
		{name: "all empty", opts: modeOpts{}, wantErr: ""},
		{name: "full alone", opts: modeOpts{full: true}, wantErr: ""},
		{name: "incremental alone", opts: modeOpts{incremental: true}, wantErr: ""},
		{name: "diffBase alone", opts: modeOpts{diffBase: "origin/main"}, wantErr: ""},
		{name: "pr alone", opts: modeOpts{pr: 42}, wantErr: ""},

		{name: "full + incremental", opts: modeOpts{full: true, incremental: true}, wantErr: "cannot be combined"},
		{name: "full + diffBase", opts: modeOpts{full: true, diffBase: "x"}, wantErr: "cannot be combined"},
		{name: "full + pr", opts: modeOpts{full: true, pr: 1}, wantErr: "cannot be combined"},

		{name: "diffBase + pr", opts: modeOpts{diffBase: "x", pr: 1}, wantErr: "mutually exclusive"},
		{name: "incremental + diffBase", opts: modeOpts{incremental: true, diffBase: "x"}, wantErr: "mutually exclusive"},
		{name: "incremental + pr", opts: modeOpts{incremental: true, pr: 1}, wantErr: "mutually exclusive"},

		{name: "invalid scope", opts: modeOpts{scope: "everything"}, wantErr: "invalid --diff-scope"},
		{name: "valid scope", opts: modeOpts{scope: "callers"}, wantErr: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateModeFlags(tc.opts)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

func TestSelectModeExplicitFull(t *testing.T) {
	withTempHome(t)
	got, err := selectMode(modeOpts{full: true, projectName: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != config.ScanKindFull {
		t.Errorf("expected full, got %+v", got)
	}
}

func TestSelectModeExplicitDiffBase(t *testing.T) {
	withTempHome(t)
	got, err := selectMode(modeOpts{diffBase: "origin/main", projectName: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != config.ScanKindDiff || got.Base != "origin/main" {
		t.Errorf("unexpected decision: %+v", got)
	}
	if got.Scope == "" {
		t.Error("expected default scope to be applied")
	}
}

func TestSelectModeIncrementalUsesLatestSuccess(t *testing.T) {
	withTempHome(t)
	prev := &config.ScanMeta{
		Kind:      config.ScanKindFull,
		Commit:    "fullsha",
		StartedAt: time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339),
		Status:    config.ScanStatusSuccess,
		Language:  "python",
	}
	if err := config.SaveScanMeta("p", "fullshrt", prev); err != nil {
		t.Fatal(err)
	}

	got, err := selectMode(modeOpts{incremental: true, projectName: "p"})
	if err != nil {
		t.Fatalf("selectMode: %v", err)
	}
	if got.Kind != config.ScanKindDiff {
		t.Errorf("expected diff, got %s", got.Kind)
	}
	if got.Base != "fullsha" {
		t.Errorf("expected base=fullsha, got %s", got.Base)
	}
}

func TestSelectModeIncrementalErrorsWithoutBaseline(t *testing.T) {
	withTempHome(t)
	_, err := selectMode(modeOpts{incremental: true, projectName: "fresh"})
	if err == nil {
		t.Fatal("expected error when --incremental and no baseline")
	}
	if !strings.Contains(err.Error(), "no successful prior scan") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestSelectModeNoFlagsNoBaselineGoesFull(t *testing.T) {
	withTempHome(t)
	got, err := selectMode(modeOpts{projectName: "fresh"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != config.ScanKindFull {
		t.Errorf("first scan with no baseline should be full, got %s", got.Kind)
	}
}

// Reuse helper from scan_meta_test.go's withTempHome. The cmd package
// can't import _test.go files from another package, so we redeclare a
// minimal copy here.
func withTempHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	return dir
}

func TestPromptModeDefaultEnterIsFull(t *testing.T) {
	prev := &config.ScanMeta{
		Kind:      config.ScanKindFull,
		Commit:    "abc1234567890",
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		Status:    config.ScanStatusSuccess,
	}
	in := bytes.NewBufferString("\n") // user just hits Enter
	out := &bytes.Buffer{}
	got, err := promptMode(prev, "changed_functions", in, out)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != config.ScanKindFull {
		t.Errorf("expected full on Enter, got %s", got.Kind)
	}
	if !strings.Contains(out.String(), "Found previous scan") {
		t.Errorf("expected recap in prompt output, got: %q", out.String())
	}
}

func TestPromptModeIncrementalAnswer(t *testing.T) {
	prev := &config.ScanMeta{
		Kind:      config.ScanKindFull,
		Commit:    "abc1234567890",
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		Status:    config.ScanStatusSuccess,
	}
	in := bytes.NewBufferString("i\n")
	out := &bytes.Buffer{}
	got, err := promptMode(prev, "changed_functions", in, out)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != config.ScanKindDiff {
		t.Errorf("expected diff, got %s", got.Kind)
	}
	if got.Base != "abc1234567890" {
		t.Errorf("expected base from prev commit, got %s", got.Base)
	}
}

func TestResolveStepDiffOptsExplicitFlagsWin(t *testing.T) {
	withTempHome(t)
	// Create a meta.json kind=diff with one base, then pass an explicit
	// --diff-base override; the override must win.
	prev := &config.ScanMeta{
		Kind:      config.ScanKindDiff,
		Commit:    "current",
		Base:      "from-meta",
		Scope:     "callers",
		StartedAt: "2026-04-28T00:00:00Z",
		Status:    config.ScanStatusRunning,
		Language:  "python",
	}
	if err := config.SaveScanMeta("p", "currshort", prev); err != nil {
		t.Fatal(err)
	}
	ctx := &projectContext{Project: &config.Project{Name: "p", CommitSHAShort: "currshort"}}

	got, err := resolveStepDiffOpts(ctx, "explicit-base", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.base != "explicit-base" {
		t.Errorf("explicit flag should win, got base=%s", got.base)
	}
}

func TestResolveStepDiffOptsFallsBackToMeta(t *testing.T) {
	withTempHome(t)
	prev := &config.ScanMeta{
		Kind:      config.ScanKindDiff,
		Commit:    "current",
		Base:      "from-meta",
		Scope:     "callers",
		StartedAt: "2026-04-28T00:00:00Z",
		Status:    config.ScanStatusRunning,
		Language:  "python",
	}
	if err := config.SaveScanMeta("p", "currshort", prev); err != nil {
		t.Fatal(err)
	}
	ctx := &projectContext{Project: &config.Project{Name: "p", CommitSHAShort: "currshort"}}

	got, err := resolveStepDiffOpts(ctx, "", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.base != "from-meta" {
		t.Errorf("expected base from meta, got %s", got.base)
	}
	if got.scope != "callers" {
		t.Errorf("expected scope from meta, got %s", got.scope)
	}
}

func TestResolveStepDiffOptsFullMetaIsSilentFull(t *testing.T) {
	withTempHome(t)
	prev := &config.ScanMeta{
		Kind:      config.ScanKindFull,
		Commit:    "current",
		StartedAt: "2026-04-28T00:00:00Z",
		Status:    config.ScanStatusSuccess,
		Language:  "python",
	}
	if err := config.SaveScanMeta("p", "currshort", prev); err != nil {
		t.Fatal(err)
	}
	ctx := &projectContext{Project: &config.Project{Name: "p", CommitSHAShort: "currshort"}}

	got, err := resolveStepDiffOpts(ctx, "", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.base != "" || got.pr != 0 {
		t.Errorf("kind=full meta should produce empty diffOpts, got %+v", got)
	}
}

func TestResolveStepDiffOptsNoMetaIsSilentFull(t *testing.T) {
	withTempHome(t)
	ctx := &projectContext{Project: &config.Project{Name: "no-meta-here", CommitSHAShort: "deadbeef"}}
	got, err := resolveStepDiffOpts(ctx, "", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.base != "" {
		t.Errorf("missing meta should produce empty diffOpts, got %+v", got)
	}
}

func TestPromptModeRejectsBadAnswer(t *testing.T) {
	prev := &config.ScanMeta{
		Kind:      config.ScanKindFull,
		Commit:    "abc1234567890",
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	}
	in := bytes.NewBufferString("maybe\n")
	out := &bytes.Buffer{}
	_, err := promptMode(prev, "changed_functions", in, out)
	if err == nil {
		t.Fatal("expected error for bogus answer")
	}
	if !strings.Contains(err.Error(), "invalid answer") {
		t.Errorf("unexpected error: %v", err)
	}
}
