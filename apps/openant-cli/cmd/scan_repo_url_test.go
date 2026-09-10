package cmd

import (
	"strings"
	"testing"

	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/knostic/open-ant-cli/internal/git"
	"github.com/knostic/open-ant-cli/internal/report"
)

// TestNormalizeRemote pins the #562 matrix: every remote shape either
// normalizes to a plain https browse URL or yields "" (the honest absence).
func TestNormalizeRemote(t *testing.T) {
	tests := []struct{ name, in, want string }{
		// scp-form: the host after the LAST '@' before the ':'.
		{"scp", "git@github.com:org/repo.git", "https://github.com/org/repo"},
		{"scp smuggled userinfo", "git@evil@127.0.0.1:org/repo.git", "https://127.0.0.1/org/repo"},
		// ssh:// scheme.
		{"ssh scheme", "ssh://git@github.com/org/repo.git", "https://github.com/org/repo"},
		// Credentials NEVER persist (the leak hazard).
		{"https with token", "https://user:TOKEN@github.com/org/repo.git", "https://github.com/org/repo"},
		{"ssh with port (dropped)", "ssh://git@github.com:2222/org/repo.git", "https://github.com/org/repo"},
		// Plain https: passthrough (case/slash/git-suffix tidied).
		{"https", "https://github.com/org/repo", "https://github.com/org/repo"},
		{"https .git", "https://github.com/org/repo.git", "https://github.com/org/repo"},
		{"https trailing slash", "https://github.com/org/repo/", "https://github.com/org/repo"},
		// Non-browseable / unsafe: the honest absence.
		{"git scheme", "git://github.com/org/repo.git", ""},
		{"local path", "/work/repo", ""},
		{"relative scp-like no host", ":", ""},
		{"empty", "", ""},
		{"uppercase scheme", "HTTPS://github.com/org/repo", "https://github.com/org/repo"},
		{"http preserved", "http://gitea.internal/org/repo", "http://gitea.internal/org/repo"},
		{"https no path", "https://github.com", "https://github.com"},
		{"query dropped", "https://github.com/org/repo.git?x=1", "https://github.com/org/repo"},
		{"scp mixed case host", "git@GitHub.com:org/repo.git", "https://github.com/org/repo"},
		{"windows drive", "C:\\work\\repo", ""},
		{"flag unparseable", "git@github.com:not-a/repo/with/slash.git", "https://github.com/not-a/repo/with/slash"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := git.NormalizeRemote(tt.in); got != tt.want {
				t.Errorf("NormalizeRemote(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestResolveRepoMetadataURLTier pins the tier order for the URL (flag >
// project-normalized > detected) — the #562 extension of the #557 table.
func TestResolveRepoMetadataURLTier(t *testing.T) {
	// The project tier normalizes defensively (the init-recorded scp form).
	n, u, _, _ := resolveRepoMetadataFull("", "", "", &projectContext{
		Project: nil,
	}, "", "https://github.com/org/repo")
	if u != "https://github.com/org/repo" || n != "" {
		t.Errorf("bare-path detection = (%q, %q), want the detected URL only", n, u)
	}
	// The project tier's scp form is normalized, not passed through.
	_, u, _, _ = resolveRepoMetadataFull("", "", "",
		&projectContext{Project: &config.Project{
			Name: "p", RepoURL: "git@github.com:proj/repo.git",
			CommitSHA: "abc",
		}}, "", "")
	if u != "https://github.com/proj/repo" {
		t.Errorf("project scp url = %q, want the normalized https form", u)
	}
	// The explicit flag wins over detection.
	_, u, _, _ = resolveRepoMetadataFull("", "https://flag.example/x", "",
		nil, "", "https://github.com/org/repo")
	if u != "https://flag.example/x" {
		t.Errorf("flag url = %q, want the flag", u)
	}
}

// The gate fold (the astra round): the password-bearing scp shape must
// normalize to the honest absence — the pre-fold normalizer emitted
// "https://user/pass@host:path", leaking the credential text.
func TestFoldScpPasswordShapeRejected(t *testing.T) {
	if got := git.NormalizeRemote("user:pass@host:path"); got != "" {
		t.Errorf("NormalizeRemote(password-bearing scp) = %q, want \"\" (the honest absence)", got)
	}
	// the legitimate shapes unaffected
	if got := git.NormalizeRemote("git@host:org/repo.git"); got != "https://host/org/repo" {
		t.Errorf("legitimate scp broken: %q", got)
	}
	if got := git.NormalizeRemote("git@evil@127.0.0.1:org/repo.git"); got != "https://127.0.0.1/org/repo" {
		t.Errorf("last-@ rule broken: %q", got)
	}
}

// TestFileURLNormalizesDefensively pins the #568 render boundary: an
// scp-form or credential-bearing RepoURL from an old artifact never reaches
// the permalink (and never renders the credential).
func TestFileURLNormalizesDefensively(t *testing.T) {
	d := report.ReportData{CommitSHA: "abc123"}
	// An scp-form URL from an old pipeline_output: the permalink is the
	// normalized https form, never the raw scp.
	d.RepoURL = "git@github.com:org/repo.git"
	if got := d.FileURL("f.py"); got != "https://github.com/org/repo/blob/abc123/f.py" {
		t.Errorf("FileURL(scp) = %q, want the normalized permalink", got)
	}
	// A credential-bearing URL: the TOKEN never reaches the output.
	d.RepoURL = "https://user:TOKEN@github.com/org/repo"
	if got := d.FileURL("f.py"); strings.Contains(got, "TOKEN") || strings.Contains(got, "user:") {
		t.Errorf("FileURL(cred) = %q — the credential leaked", got)
	}
	// An unparseable URL: the honest absence (no broken link).
	d.RepoURL = "git://github.com/org/repo.git"
	if got := d.FileURL("f.py"); got != "" {
		t.Errorf("FileURL(git://) = %q, want empty", got)
	}
}
