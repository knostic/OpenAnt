package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/knostic/open-ant-cli/internal/git"
)

// TestResolveRepoMetadataNameTier pins #612's name tier: when no name was
// supplied (flag or project), the name derives from the WINNING URL
// (flag/project tiers included, not just detection) — a bare-path scan of
// a renamed checkout no longer stamps the checkout directory's basename
// into reports and the LLM disclosure prompt while a usable, normalized
// repository URL was available the whole time.
//
// The detected-URL inputs here are PRE-NORMALIZED by the caller
// (scan.go normalizes detection before the resolver runs — the resolver
// assigns detectedURL verbatim); the flag/project inputs normalize
// INSIDE the resolver, so scp/credential forms prove the normalized-form
// derivation end to end.
func TestResolveRepoMetadataNameTier(t *testing.T) {
	pctx := func(name, url string) *projectContext {
		return &projectContext{Project: &config.Project{Name: name, RepoURL: url}}
	}
	cases := []struct {
		name        string
		inName      string
		inURL       string
		ctx         *projectContext
		detectedURL string
		wantName    string
		wantURL     string
	}{
		{
			name:        "bare path with a detected remote derives the full slug",
			ctx:         &projectContext{Project: nil},
			detectedURL: "https://github.com/org/repo",
			wantName:    "org/repo",
			wantURL:     "https://github.com/org/repo",
		},
		{
			name:        "the flag name wins over a detected remote",
			inName:      "custom",
			ctx:         &projectContext{Project: nil},
			detectedURL: "https://github.com/org/repo",
			wantName:    "custom",
			wantURL:     "https://github.com/org/repo",
		},
		{
			name:        "the project tier name wins over a detected remote",
			ctx:         pctx("proj-name", ""),
			detectedURL: "https://github.com/org/repo",
			wantName:    "proj-name",
			wantURL:     "https://github.com/org/repo",
		},
		{
			name:        "a basename-shaped project name is preserved as-is",
			ctx:         pctx("core", ""),
			detectedURL: "https://github.com/org/repo",
			wantName:    "core",
			wantURL:     "https://github.com/org/repo",
		},
		{
			name:     "the project tier scp URL derives through normalization",
			ctx:      pctx("", "git@github.com:proj/repo.git"),
			wantName: "proj/repo",
			wantURL:  "https://github.com/proj/repo",
		},
		{
			name:     "a --repo-url flag with no name derives too",
			inURL:    "https://gitlab.com/g/sub/repo",
			ctx:      &projectContext{Project: nil},
			wantName: "g/sub/repo",
			wantURL:  "https://gitlab.com/g/sub/repo",
		},
		{
			name:        "the flag URL wins over detection for the name too",
			inURL:       "https://github.com/flag/repo",
			ctx:         &projectContext{Project: nil},
			detectedURL: "https://github.com/detected/repo",
			wantName:    "flag/repo",
			wantURL:     "https://github.com/flag/repo",
		},
		{
			name:        "host-only detection derives no name",
			ctx:         &projectContext{Project: nil},
			detectedURL: "https://github.com",
			wantName:    "",
			wantURL:     "https://github.com",
		},
		{
			name:        "a rejected flag URL (git://) leaves the name empty — never detection",
			inURL:       "git://github.com/org/repo",
			ctx:         &projectContext{Project: nil},
			detectedURL: "https://github.com/detected/repo",
			wantName:    "",
			wantURL:     "",
		},
		{
			name:        "a rejected PROJECT URL with usable detection leaves both empty",
			ctx:         pctx("", "git://github.com/org/repo"),
			detectedURL: "https://github.com/detected/repo",
			wantName:    "",
			wantURL:     "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, u, _, _ := resolveRepoMetadataFull(tc.inName, tc.inURL, "", tc.ctx, "", tc.detectedURL)
			if n != tc.wantName || u != tc.wantURL {
				t.Errorf("name tier = (%q, %q), want (%q, %q)", n, u, tc.wantName, tc.wantURL)
			}
		})
	}
}

// TestScanPathNameTierOnARenamedCheckout is the #612 acceptance seam
// (the Go half; the Python half pins the disclosure product arg): a REAL
// git checkout whose directory name (the tmp basename) disagrees with the
// origin remote, driven through the exact scan.go detection path — the
// derived name must be the remote's slug, never the checkout's basename.
func TestScanPathNameTierOnARenamedCheckout(t *testing.T) {
	dir, _, head := initCommitTestRepo(t)
	t.Logf("checkout basename: %s (must NOT become the repo name)", filepath.Base(dir))
	c := exec.Command("git", "remote", "add", "origin", "git@github.com:renamed-org/real-repo.git")
	c.Dir = dir
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("git remote add: %v: %s", err, out)
	}

	// the exact scan.go detection seam
	detectedURL := git.NormalizeRemote(git.RemoteURL(dir))
	name, url, sha, _ := resolveRepoMetadataFull("", "", "", nil, head, detectedURL)

	if name != "renamed-org/real-repo" {
		t.Errorf("name tier = %q, want renamed-org/real-repo (the remote slug, not the checkout basename %q)",
			name, filepath.Base(dir))
	}
	if url != "https://github.com/renamed-org/real-repo" {
		t.Errorf("URL tier = %q, want the normalized remote", url)
	}
	if sha != head {
		t.Errorf("SHA tier = %q, want the detected HEAD", sha)
	}
}

// TestRepoNameForwardingEqualsForm pins the argv-safety forwarding shape
// (source-level, the suite's convention for cross-module wiring): the
// name reaches Python as ONE argv element ("--repo-name=<name>"), never
// the two-token form that argparse misparses for "-"-leading values.
func TestRepoNameForwardingEqualsForm(t *testing.T) {
	src, err := os.ReadFile("scan.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(src, []byte(`pyArgs = append(pyArgs, "--repo-name="+repoName)`)) {
		t.Error("scan.go must forward the derived name in the =-form (a " +
			"\"-\"-leading value in the two-token form fails argparse)")
	}
}
