package cmd

import (
	"testing"

	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/knostic/open-ant-cli/internal/git"
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
