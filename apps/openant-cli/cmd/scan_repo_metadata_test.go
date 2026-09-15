package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/knostic/open-ant-cli/internal/git"
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
		name                                   string
		flagName, flagURL, flagSHA             string
		ctx                                    *projectContext
		detected                               string
		wantName, wantURL, wantSHA, wantWarnIn string
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
			detected: "fff000",
			wantName: "proj/app", wantURL: "https://p", wantSHA: "fff000",
		},
		{
			name: "explicit flag wins over the project context",
			ctx: &projectContext{Project: &config.Project{
				Name: "proj/app", RepoURL: "https://p", CommitSHA: "fff000",
			}},
			flagName: "acme/app", flagSHA: "abc123", detected: "fff000",
			wantName: "acme/app", wantURL: "https://p", wantSHA: "abc123",
			// The CI synthetic-merge shape: the flag differs from HEAD, warned.
			wantWarnIn: "stamp commit abc123 but the working tree is at fff000",
		},
		{
			name:     "nil Project inside a non-nil ctx",
			ctx:      &projectContext{},
			flagName: "acme/app",
			wantName: "acme/app",
		},
		{
			name:     "#557: bare-path git checkout falls to detection",
			ctx:      nil,
			detected: "abc123",
			wantSHA:  "abc123",
		},
		{
			name:     "#557: non-git path (empty detection) keeps empty",
			ctx:      nil,
			detected: "",
			wantSHA:  "",
		},
		{
			name: "#557: stale project SHA warns (the footgun)",
			ctx: &projectContext{Project: &config.Project{
				Name: "proj/app", CommitSHA: "old1111",
			}},
			detected: "new2222",
			wantName: "proj/app", wantSHA: "old1111",
			wantWarnIn: "stamp commit old1111 but the working tree is at new2222",
		},
		{
			name:    "#557: bare-path CI flag vs detection warns (the legit case)",
			ctx:     nil,
			flagSHA: "abc123", detected: "fff000",
			wantSHA:    "abc123",
			wantWarnIn: "stamp commit abc123 but the working tree is at fff000",
		},
		{
			name: "#557: the project-tier mismatch carries the remedy hint",
			ctx: &projectContext{Project: &config.Project{
				Name: "proj/app", CommitSHA: "old1111",
			}},
			detected: "new2222",
			wantName: "proj/app", wantSHA: "old1111",
			wantWarnIn: "re-run",
		},
		{
			name: "#557: the nogit sentinel never reaches the SHA",
			ctx: &projectContext{Project: &config.Project{
				Name: "proj/app", CommitSHA: "nogit",
			}},
			detected: "abc123",
			wantName: "proj/app", wantSHA: "abc123",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, u, s, warn := resolveRepoMetadata(tt.flagName, tt.flagURL, tt.flagSHA, tt.ctx, tt.detected)
			if n != tt.wantName || u != tt.wantURL || s != tt.wantSHA {
				t.Errorf("resolveRepoMetadata = (%q, %q, %q), want (%q, %q, %q)",
					n, u, s, tt.wantName, tt.wantURL, tt.wantSHA)
			}
			if tt.wantWarnIn != "" && !strings.Contains(warn, tt.wantWarnIn) {
				t.Errorf("warn = %q, want to contain %q", warn, tt.wantWarnIn)
			}
			if tt.wantWarnIn == "" && warn != "" {
				t.Errorf("unexpected warn %q", warn)
			}
		})
	}
}

// TestHeadSHA pins the detection helper: a real temp repo resolves; a repo
// SUBDIRECTORY resolves (init's os.Stat(.git) gate fails on subdirs —
// detection must not); a non-git dir yields "".
func TestHeadSHA(t *testing.T) {
	repoDir, _, headSHA := initCommitTestRepo(t)
	if got := git.HeadSHA(repoDir); got != headSHA {
		t.Errorf("HeadSHA(repo) = %q, want the fixture HEAD %q", got, headSHA)
	}
	if err := os.MkdirAll(filepath.Join(repoDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := git.HeadSHA(filepath.Join(repoDir, "sub")); got != headSHA {
		t.Errorf("HeadSHA(subdir) = %q, want %q (git -C resolves subdirs)", got, headSHA)
	}
	if got := git.HeadSHA(t.TempDir()); got != "" {
		t.Errorf("HeadSHA(non-git) = %q, want empty", got)
	}
	// An unborn repo (a fresh init, no commits): rev-parse HEAD errors —
	// the empty return is the proof (the review round's dead-guard catch).
	unborn := t.TempDir()
	if out, err := exec.Command("git", "-C", unborn, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	if got := git.HeadSHA(unborn); got != "" {
		t.Errorf("HeadSHA(unborn) = %q, want empty (rev-parse HEAD must error)", got)
	}
}
