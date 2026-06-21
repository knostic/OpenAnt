package cmd

import (
	"strings"
	"testing"
)

// TestAnalyzeExploitableAllFlagDefined locks the flag-parity fix:
// the Go `analyze` command must expose
// `--exploitable-all`, mirroring the Python backend (cli.py analyze_p
// defines both --exploitable-all and --exploitable-only). Before the fix the
// Go CLI defined only --exploitable-only, so `analyze --exploitable-all`
// failed with "unknown flag".
func TestAnalyzeExploitableAllFlagDefined(t *testing.T) {
	flag := analyzeCmd.Flag("exploitable-all")
	if flag == nil {
		t.Fatal("analyzeCmd has no --exploitable-all flag (parity gap with Python backend)")
	}
	if got, want := flag.DefValue, "false"; got != want {
		t.Errorf("--exploitable-all default = %q, want %q", got, want)
	}
	// The control flag must still exist.
	if analyzeCmd.Flag("exploitable-only") == nil {
		t.Fatal("analyzeCmd lost its --exploitable-only flag")
	}
}

// TestAnalyzeExploitableAllForwardedToPython locks that the new flag is
// actually forwarded to the Python subprocess argv (not just defined). It
// exercises buildAnalyzePyArgs, the pure argv-builder helper (mirrors the
// buildParsePyArgs pattern), so a future refactor that drops the forwarding
// fails here.
func TestAnalyzeExploitableAllForwardedToPython(t *testing.T) {
	tests := []struct {
		name          string
		exploitAll    bool
		exploitOnly   bool
		wantAllInArgv bool
	}{
		{"exploitable-all forwarded", true, false, true},
		{"neither flag -> not forwarded", false, false, false},
		{"exploitable-only does not emit --exploitable-all", false, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			argv := buildAnalyzePyArgs(
				"ds.json", "out", false, "", "", "",
				tc.exploitOnly, tc.exploitAll, 0, "", 8, "", 30,
			)
			joined := strings.Join(argv, " ")
			got := false
			for _, a := range argv {
				if a == "--exploitable-all" {
					got = true
					break
				}
			}
			if got != tc.wantAllInArgv {
				t.Errorf("buildAnalyzePyArgs --exploitable-all present=%v, want %v; argv=%q", got, tc.wantAllInArgv, joined)
			}
		})
	}
}
