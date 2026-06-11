package cmd

import "testing"

// The `enhance` command must expose a `--limit` flag for
// parity with `analyze`/`scan`, so a user can cost-limit / test-run enhancement on N units.
func TestEnhanceCommandHasLimitFlag(t *testing.T) {
	f := enhanceCmd.Flags().Lookup("limit")
	if f == nil {
		t.Fatal("enhance command is missing the --limit flag (parity with analyze/scan)")
	}
	if f.DefValue != "0" {
		t.Errorf("--limit default = %q, want \"0\" (0 = no limit)", f.DefValue)
	}
}
