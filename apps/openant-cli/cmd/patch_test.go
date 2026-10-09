package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestBuildPatchPyArgsBaseline(t *testing.T) {
	args := buildPatchPyArgs("/scan/pipeline_output.json", "F-001", "", "", contextBudgetFlags{})
	want := []string{"patch", "/scan/pipeline_output.json", "--finding-id", "F-001"}
	if len(args) != len(want) {
		t.Fatalf("argv = %v, want %v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q (full=%v)", i, args[i], want[i], args)
		}
	}
}

func TestBuildPatchPyArgsWithRepoRootAndOutput(t *testing.T) {
	args := buildPatchPyArgs("/scan/pipeline_output.json", "F-001", "/repo", "/scan", contextBudgetFlags{})
	want := []string{
		"patch", "/scan/pipeline_output.json", "--finding-id", "F-001",
		"--repo-root", "/repo",
		"--output", "/scan",
	}
	if len(args) != len(want) {
		t.Fatalf("argv = %v, want %v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q (full=%v)", i, args[i], want[i], args)
		}
	}
}

func TestBuildPatchPyArgsOmitsRepoRootAndOutputWhenEmpty(t *testing.T) {
	args := buildPatchPyArgs("/scan/pipeline_output.json", "F-001", "", "", contextBudgetFlags{})
	if found, _ := findFlag(args, "--repo-root"); found {
		t.Errorf("did not expect --repo-root in pyArgs when unset, got %v", args)
	}
	if found, _ := findFlag(args, "--output"); found {
		t.Errorf("did not expect --output in pyArgs when unset, got %v", args)
	}
}

// ---------------------------------------------------------------------------
// --context-budget-policy / --max-context-budget-windows: transport-only
// forwarding. Go never validates these values -- see contextBudgetFlags and
// appendContextBudgetArgs in patch.go. Whether a flag is forwarded depends
// solely on *Set (i.e. cmd.Flags().Changed(...) at the real call site),
// never on the value itself.
// ---------------------------------------------------------------------------

func TestPatchCmdHasContextBudgetPolicyFlag(t *testing.T) {
	flag := patchCmd.Flags().Lookup("context-budget-policy")
	if flag == nil {
		t.Fatal("patchCmd is missing the --context-budget-policy flag")
	}
	if flag.DefValue != "" {
		t.Errorf("--context-budget-policy default should be empty, got %q", flag.DefValue)
	}
}

func TestPatchCmdHasMaxContextBudgetWindowsFlag(t *testing.T) {
	flag := patchCmd.Flags().Lookup("max-context-budget-windows")
	if flag == nil {
		t.Fatal("patchCmd is missing the --max-context-budget-windows flag")
	}
	if flag.DefValue != "0" {
		t.Errorf("--max-context-budget-windows default should be 0, got %q", flag.DefValue)
	}
}

func TestBuildPatchPyArgsForwardsPolicyWhenSet(t *testing.T) {
	args := buildPatchPyArgs("/scan/pipeline_output.json", "F-001", "", "", contextBudgetFlags{
		policy:    "always",
		policySet: true,
	})
	found, val := findFlag(args, "--context-budget-policy")
	if !found {
		t.Fatalf("expected --context-budget-policy in pyArgs, got %v", args)
	}
	if val != "always" {
		t.Errorf("--context-budget-policy = %q, want %q", val, "always")
	}
}

func TestBuildPatchPyArgsOmitsPolicyWhenNotSet(t *testing.T) {
	// Any string value in `policy` must be ignored when policySet is false --
	// forwarding is gated purely on *Set, never on the value.
	args := buildPatchPyArgs("/scan/pipeline_output.json", "F-001", "", "", contextBudgetFlags{
		policy:    "always",
		policySet: false,
	})
	if found, _ := findFlag(args, "--context-budget-policy"); found {
		t.Errorf("did not expect --context-budget-policy in pyArgs when policySet=false, got %v", args)
	}
}

func TestBuildPatchPyArgsForwardsMaxWindowsWhenSet(t *testing.T) {
	args := buildPatchPyArgs("/scan/pipeline_output.json", "F-001", "", "", contextBudgetFlags{
		maxWindows:    25,
		maxWindowsSet: true,
	})
	found, val := findFlag(args, "--max-context-budget-windows")
	if !found {
		t.Fatalf("expected --max-context-budget-windows in pyArgs, got %v", args)
	}
	if val != "25" {
		t.Errorf("--max-context-budget-windows = %q, want %q", val, "25")
	}
}

func TestBuildPatchPyArgsForwardsExplicitZeroMaxWindows(t *testing.T) {
	// An explicit 0 must still be forwarded -- Python is the only place
	// that rejects a non-positive value. Go must never swallow it.
	args := buildPatchPyArgs("/scan/pipeline_output.json", "F-001", "", "", contextBudgetFlags{
		maxWindows:    0,
		maxWindowsSet: true,
	})
	found, val := findFlag(args, "--max-context-budget-windows")
	if !found {
		t.Fatalf("expected --max-context-budget-windows in pyArgs even for an explicit 0, got %v", args)
	}
	if val != "0" {
		t.Errorf("--max-context-budget-windows = %q, want %q", val, "0")
	}
}

func TestBuildPatchPyArgsOmitsMaxWindowsWhenNotSet(t *testing.T) {
	args := buildPatchPyArgs("/scan/pipeline_output.json", "F-001", "", "", contextBudgetFlags{
		maxWindows:    10,
		maxWindowsSet: false,
	})
	if found, _ := findFlag(args, "--max-context-budget-windows"); found {
		t.Errorf("did not expect --max-context-budget-windows in pyArgs when maxWindowsSet=false, got %v", args)
	}
}

func TestPatchCmdHasFindingIDFlag(t *testing.T) {
	flag := patchCmd.Flags().Lookup("finding-id")
	if flag == nil {
		t.Fatal("patchCmd is missing the --finding-id flag")
	}
	if flag.DefValue != "" {
		t.Errorf("--finding-id default should be empty, got %q", flag.DefValue)
	}
}

func TestPatchCmdIsRegisteredOnRoot(t *testing.T) {
	var found *cobra.Command
	for _, c := range rootCmd.Commands() {
		if c.Name() == "patch" {
			found = c
			break
		}
	}
	if found == nil {
		t.Fatal("patch command not registered on rootCmd")
	}
	if found.Flags().Lookup("finding-id") == nil {
		t.Error("patch subcommand resolved from root is missing --finding-id flag")
	}
	if found.Flags().Lookup("cve") == nil {
		t.Error("patch subcommand resolved from root is missing --cve flag")
	}
}

// ---------------------------------------------------------------------------
// --cve support: argv construction, format validation, and flag registration.
// ---------------------------------------------------------------------------

func TestBuildPatchCVEPyArgsBaseline(t *testing.T) {
	args := buildPatchCVEPyArgs("CVE-2022-25883", "/repo", "", contextBudgetFlags{})
	want := []string{"patch", "--cve", "CVE-2022-25883", "--repo-root", "/repo"}
	if len(args) != len(want) {
		t.Fatalf("argv = %v, want %v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q (full=%v)", i, args[i], want[i], args)
		}
	}
}

func TestBuildPatchCVEPyArgsWithOutput(t *testing.T) {
	args := buildPatchCVEPyArgs("CVE-2022-25883", "/repo", "/scan", contextBudgetFlags{})
	want := []string{
		"patch", "--cve", "CVE-2022-25883",
		"--repo-root", "/repo",
		"--output", "/scan",
	}
	if len(args) != len(want) {
		t.Fatalf("argv = %v, want %v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q (full=%v)", i, args[i], want[i], args)
		}
	}
}

func TestBuildPatchCVEPyArgsOmitsOutputWhenEmpty(t *testing.T) {
	args := buildPatchCVEPyArgs("CVE-2022-25883", "/repo", "", contextBudgetFlags{})
	if found, _ := findFlag(args, "--output"); found {
		t.Errorf("did not expect --output in pyArgs when unset, got %v", args)
	}
}

// ---------------------------------------------------------------------------
// --context-budget-policy / --max-context-budget-windows in CVE mode: same
// transport-only forwarding contract as Finding mode (see equivalent tests
// above for buildPatchPyArgs).
// ---------------------------------------------------------------------------

func TestBuildPatchCVEPyArgsForwardsPolicyWhenSet(t *testing.T) {
	args := buildPatchCVEPyArgs("CVE-2022-25883", "/repo", "", contextBudgetFlags{
		policy:    "never",
		policySet: true,
	})
	found, val := findFlag(args, "--context-budget-policy")
	if !found {
		t.Fatalf("expected --context-budget-policy in pyArgs, got %v", args)
	}
	if val != "never" {
		t.Errorf("--context-budget-policy = %q, want %q", val, "never")
	}
}

func TestBuildPatchCVEPyArgsOmitsPolicyWhenNotSet(t *testing.T) {
	args := buildPatchCVEPyArgs("CVE-2022-25883", "/repo", "", contextBudgetFlags{
		policy:    "never",
		policySet: false,
	})
	if found, _ := findFlag(args, "--context-budget-policy"); found {
		t.Errorf("did not expect --context-budget-policy in pyArgs when policySet=false, got %v", args)
	}
}

func TestBuildPatchCVEPyArgsForwardsExplicitZeroMaxWindows(t *testing.T) {
	args := buildPatchCVEPyArgs("CVE-2022-25883", "/repo", "", contextBudgetFlags{
		maxWindows:    0,
		maxWindowsSet: true,
	})
	found, val := findFlag(args, "--max-context-budget-windows")
	if !found {
		t.Fatalf("expected --max-context-budget-windows in pyArgs even for an explicit 0, got %v", args)
	}
	if val != "0" {
		t.Errorf("--max-context-budget-windows = %q, want %q", val, "0")
	}
}

func TestBuildPatchCVEPyArgsOmitsMaxWindowsWhenNotSet(t *testing.T) {
	args := buildPatchCVEPyArgs("CVE-2022-25883", "/repo", "", contextBudgetFlags{
		maxWindows:    10,
		maxWindowsSet: false,
	})
	if found, _ := findFlag(args, "--max-context-budget-windows"); found {
		t.Errorf("did not expect --max-context-budget-windows in pyArgs when maxWindowsSet=false, got %v", args)
	}
}

func TestCveIDPatternAcceptsValidIDs(t *testing.T) {
	valid := []string{"CVE-2022-25883", "CVE-1999-0001", "CVE-2023-123456"}
	for _, id := range valid {
		if !cveIDPattern.MatchString(id) {
			t.Errorf("expected %q to match cveIDPattern", id)
		}
	}
}

func TestCveIDPatternRejectsInvalidIDs(t *testing.T) {
	invalid := []string{
		"CVE-22-25883",    // year not 4 digits
		"CVE-2022-123",    // sequence too short
		"cve-2022-25883",  // wrong case
		"CVE-2022",        // missing sequence
		"2022-25883",      // missing prefix
		"CVE-2022-25883x", // trailing garbage
		"",
	}
	for _, id := range invalid {
		if cveIDPattern.MatchString(id) {
			t.Errorf("expected %q to NOT match cveIDPattern", id)
		}
	}
}

// withPresentationFlags sets the package-level flag vars appendPresentationArgs
// reads (patchVerbose, quiet, jsonOutput), running fn with them, then
// restores the prior values -- these are cobra-bound globals shared across
// the whole cmd package's tests, so tests must not leak them.
func withPresentationFlags(t *testing.T, verbose, q, j bool, fn func()) {
	t.Helper()
	prevVerbose, prevQuiet, prevJSON := patchVerbose, quiet, jsonOutput
	patchVerbose, quiet, jsonOutput = verbose, q, j
	t.Cleanup(func() { patchVerbose, quiet, jsonOutput = prevVerbose, prevQuiet, prevJSON })
	fn()
}

func TestAppendPresentationArgs_Default(t *testing.T) {
	withPresentationFlags(t, false, false, false, func() {
		got := appendPresentationArgs([]string{"patch"})
		want := []string{"patch"}
		if len(got) != len(want) || got[0] != want[0] {
			t.Errorf("argv = %v, want %v (no presentation flags set)", got, want)
		}
	})
}

func TestAppendPresentationArgs_Verbose(t *testing.T) {
	withPresentationFlags(t, true, false, false, func() {
		got := appendPresentationArgs([]string{"patch"})
		want := []string{"patch", "--verbose"}
		if len(got) != len(want) || got[1] != want[1] {
			t.Errorf("argv = %v, want %v", got, want)
		}
	})
}

func TestAppendPresentationArgs_QuietForwardsQuiet(t *testing.T) {
	withPresentationFlags(t, false, true, false, func() {
		got := appendPresentationArgs([]string{"patch"})
		want := []string{"patch", "--quiet"}
		if len(got) != len(want) || got[1] != want[1] {
			t.Errorf("argv = %v, want %v", got, want)
		}
	})
}

func TestAppendPresentationArgs_JSONImpliesQuiet(t *testing.T) {
	withPresentationFlags(t, false, false, true, func() {
		got := appendPresentationArgs([]string{"patch"})
		want := []string{"patch", "--quiet"}
		if len(got) != len(want) || got[1] != want[1] {
			t.Errorf("argv = %v, want %v (--json alone must still forward --quiet)", got, want)
		}
	})
}

func TestAppendPresentationArgs_VerboseAndJSONBothForward(t *testing.T) {
	// Go never resolves the --verbose/--json precedence itself (Python's
	// progress.configure() does -- quiet wins there); Go's only job is to
	// forward both flags whenever both were requested.
	withPresentationFlags(t, true, false, true, func() {
		got := appendPresentationArgs([]string{"patch"})
		want := []string{"patch", "--verbose", "--quiet"}
		if len(got) != len(want) {
			t.Fatalf("argv = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("argv[%d] = %q, want %q (full=%v)", i, got[i], want[i], got)
			}
		}
	})
}

func TestPatchCmdHasVerboseFlag(t *testing.T) {
	flag := patchCmd.Flags().Lookup("verbose")
	if flag == nil {
		t.Fatal("patchCmd is missing the --verbose flag")
	}
	if flag.DefValue != "false" {
		t.Errorf("--verbose default should be false, got %q", flag.DefValue)
	}
}

func TestPatchCmdHasCVEFlag(t *testing.T) {
	flag := patchCmd.Flags().Lookup("cve")
	if flag == nil {
		t.Fatal("patchCmd is missing the --cve flag")
	}
	if flag.DefValue != "" {
		t.Errorf("--cve default should be empty, got %q", flag.DefValue)
	}
}
