package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// ---------------------------------------------------------------------------
// --level flag
// ---------------------------------------------------------------------------

func TestParseLevelFlagDefaultIsReachable(t *testing.T) {
	flag := parseCmd.Flag("level")
	if flag == nil {
		t.Fatal("parseCmd has no --level flag")
	}
	if got, want := flag.DefValue, "reachable"; got != want {
		t.Errorf("--level default = %q, want %q", got, want)
	}
}

func TestParseLevelFlagUsageMentionsChoices(t *testing.T) {
	flag := parseCmd.Flag("level")
	if flag == nil {
		t.Fatal("parseCmd has no --level flag")
	}
	for _, choice := range []string{"all", "reachable", "codeql", "exploitable"} {
		if !strings.Contains(flag.Usage, choice) {
			t.Errorf("--level usage missing %q: %q", choice, flag.Usage)
		}
	}
}

func TestBuildParsePyArgsLevelForwarding(t *testing.T) {
	tests := []struct {
		name      string
		level     string
		wantLevel bool // true if --level should appear in argv
	}{
		{"default reachable is omitted", "reachable", false},
		{"all is forwarded", "all", true},
		{"codeql is forwarded", "codeql", true},
		{"exploitable is forwarded", "exploitable", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := buildParsePyArgs("/repo", "/out", "", "auto", tc.level, "", false)
			gotLevel, gotValue := findFlag(args, "--level")
			if gotLevel != tc.wantLevel {
				t.Errorf("--level present = %v, want %v (argv=%v)", gotLevel, tc.wantLevel, args)
			}
			if tc.wantLevel && gotValue != tc.level {
				t.Errorf("--level value = %q, want %q (argv=%v)", gotValue, tc.level, args)
			}
		})
	}
}

func TestBuildParsePyArgsBaseline(t *testing.T) {
	args := buildParsePyArgs("/repo", "/out", "org-repo-abc1234", "python", "exploitable", "/tmp/manifest.json", false)
	want := []string{
		"parse", "/repo",
		"--output", "/out",
		"--name", "org-repo-abc1234",
		"--language", "python",
		"--level", "exploitable",
		"--diff-manifest", "/tmp/manifest.json",
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

// ---------------------------------------------------------------------------
// --fresh flag
// ---------------------------------------------------------------------------

func TestParseCmdHasFreshFlag(t *testing.T) {
	flag := parseCmd.Flags().Lookup("fresh")
	if flag == nil {
		t.Fatal("parseCmd is missing the --fresh flag")
	}
	if flag.Value.Type() != "bool" {
		t.Errorf("--fresh should be a bool flag, got type %q", flag.Value.Type())
	}
	if flag.DefValue != "false" {
		t.Errorf("--fresh default should be false, got %q", flag.DefValue)
	}
	if flag.Usage == "" {
		t.Error("--fresh flag is missing a usage/help string")
	}
}

func TestParseCmdFreshFlagInitialState(t *testing.T) {
	orig := parseFresh
	defer func() { parseFresh = orig }()

	parseFresh = false
	if parseFresh {
		t.Errorf("parseFresh should default to false, got true")
	}
}

func TestParseCmdFreshFlagParses(t *testing.T) {
	orig := parseFresh
	defer func() {
		parseFresh = orig
		_ = parseCmd.Flags().Set("fresh", "false")
	}()

	parseFresh = false
	if err := parseCmd.Flags().Set("fresh", "true"); err != nil {
		t.Fatalf("failed to set --fresh: %v", err)
	}
	if !parseFresh {
		t.Error("setting --fresh=true should make parseFresh true")
	}

	if err := parseCmd.Flags().Set("fresh", "false"); err != nil {
		t.Fatalf("failed to set --fresh=false: %v", err)
	}
	if parseFresh {
		t.Error("setting --fresh=false should make parseFresh false")
	}
}

func TestParsePyArgsIncludesFreshWhenSet(t *testing.T) {
	args := buildParsePyArgs("/some/repo", "/out", "", "auto", "reachable", "", true)

	found, _ := findFlag(args, "--fresh")
	if !found {
		t.Errorf("expected --fresh in pyArgs when fresh=true, got %v", args)
	}
}

func TestParsePyArgsOmitsFreshWhenUnset(t *testing.T) {
	args := buildParsePyArgs("/some/repo", "/out", "", "auto", "reachable", "", false)

	found, _ := findFlag(args, "--fresh")
	if found {
		t.Errorf("did not expect --fresh in pyArgs when fresh=false, got %v", args)
	}
}
func TestParseCmdIsRegisteredOnRoot(t *testing.T) {
	var found *cobra.Command
	for _, c := range rootCmd.Commands() {
		if c.Name() == "parse" {
			found = c
			break
		}
	}
	if found == nil {
		t.Fatal("parse command not registered on rootCmd")
	}
	if found.Flags().Lookup("fresh") == nil {
		t.Error("parse subcommand resolved from root is missing --fresh flag")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func findFlag(argv []string, name string) (bool, string) {
	for i, a := range argv {
		if a == name {
			if i+1 < len(argv) {
				return true, argv[i+1]
			}
			return true, ""
		}
	}
	return false, ""
}
