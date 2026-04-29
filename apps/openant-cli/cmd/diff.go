package cmd

import (
	"os"

	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/spf13/cobra"
)

var diffCmd = &cobra.Command{
	Use:   "diff [repository-path]",
	Short: "Scan only the code changed vs a base ref or GitHub PR",
	Long: `Diff runs the full scan pipeline but filters to units whose bodies
overlap a git diff hunk. One of --diff-base or --pr is required.

Examples:
  openant diff --diff-base origin/main
  openant diff --pr 123
  openant diff --diff-base HEAD~5 --diff-scope callers --verify

All scan flags (--level, --workers, --verify, etc.) work the same here.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if scanDiffBase == "" && scanPR == 0 {
			output.PrintError("openant diff requires --diff-base <ref> or --pr <N>")
			os.Exit(2)
		}
		runScan(cmd, args)
	},
}

func init() {
	registerScanFlags(diffCmd)
}
