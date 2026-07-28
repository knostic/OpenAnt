package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestBuildPatchPyArgsBaseline(t *testing.T) {
	args := buildPatchPyArgs("/scan/pipeline_output.json", "F-001", "", "")
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
	args := buildPatchPyArgs("/scan/pipeline_output.json", "F-001", "/repo", "/scan")
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
	args := buildPatchPyArgs("/scan/pipeline_output.json", "F-001", "", "")
	if found, _ := findFlag(args, "--repo-root"); found {
		t.Errorf("did not expect --repo-root in pyArgs when unset, got %v", args)
	}
	if found, _ := findFlag(args, "--output"); found {
		t.Errorf("did not expect --output in pyArgs when unset, got %v", args)
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
}
