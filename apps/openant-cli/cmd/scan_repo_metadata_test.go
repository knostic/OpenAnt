package cmd

import (
	"testing"

	"github.com/knostic/open-ant-cli/internal/config"
)

// TestScanRepoMetadataFlagsDefined locks the #539 flag-parity fix: the Go
// scan command exposes --repo-name/--repo-url/--commit-sha, mirroring the
// Python backend (cli.py scan_p defines all three). A bare-path scan has no
// project context, so the flags are the only way reports get metadata.
func TestScanRepoMetadataFlagsDefined(t *testing.T) {
	for _, name := range []string{"repo-name", "repo-url", "commit-sha"} {
		if scanCmd.Flag(name) == nil {
			t.Fatalf("scanCmd has no --%s (parity gap with the Python backend)", name)
		}
	}
}

// TestResolveRepoMetadata locks the precedence and the nil-context path
// (the #539 defect itself: a bare-path scan resolves to a nil context —
// the explicit flags must flow through alone).
func TestResolveRepoMetadata(t *testing.T) {
	tests := []struct {
		name                       string
		flagName, flagURL, flagSHA string
		ctx                        *projectContext
		wantName, wantURL, wantSHA string
	}{
		{
			name:     "bare path (nil ctx): flags flow through alone",
			ctx:      nil,
			flagName: "acme/app", flagURL: "https://x", flagSHA: "abc123",
			wantName: "acme/app", wantURL: "https://x", wantSHA: "abc123",
		},
		{
			name: "project ctx fills empty flags",
			ctx: &projectContext{Project: &config.Project{
				Name: "proj/app", RepoURL: "https://p", CommitSHA: "fff000",
			}},
			wantName: "proj/app", wantURL: "https://p", wantSHA: "fff000",
		},
		{
			name: "explicit flag wins over the project context",
			ctx: &projectContext{Project: &config.Project{
				Name: "proj/app", RepoURL: "https://p", CommitSHA: "fff000",
			}},
			flagName: "acme/app", flagSHA: "abc123",
			wantName: "acme/app", wantURL: "https://p", wantSHA: "abc123",
		},
		{
			name:     "nil Project inside a non-nil ctx",
			ctx:      &projectContext{},
			flagName: "acme/app",
			wantName: "acme/app",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, u, s := resolveRepoMetadata(tt.flagName, tt.flagURL, tt.flagSHA, tt.ctx)
			if n != tt.wantName || u != tt.wantURL || s != tt.wantSHA {
				t.Errorf("resolveRepoMetadata = (%q, %q, %q), want (%q, %q, %q)",
					n, u, s, tt.wantName, tt.wantURL, tt.wantSHA)
			}
		})
	}
}
