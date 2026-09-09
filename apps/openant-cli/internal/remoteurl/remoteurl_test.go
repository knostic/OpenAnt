package remoteurl

import "testing"

// TestNormalize pins the #562/#568 matrix at the package's own home (the
// cmd-level TestNormalizeRemote exercises the same cases through the
// internal/git re-export; this is the canonical suite).
func TestNormalize(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"scp", "git@github.com:org/repo.git", "https://github.com/org/repo"},
		{"scp smuggled userinfo", "git@evil@127.0.0.1:org/repo.git", "https://127.0.0.1/org/repo"},
		{"ssh with port dropped", "ssh://git@github.com:2222/org/repo.git", "https://github.com/org/repo"},
		{"https with token", "https://user:TOKEN@github.com/org/repo.git", "https://github.com/org/repo"},
		{"https passthrough", "https://github.com/org/repo", "https://github.com/org/repo"},
		{"http preserved", "http://gitea.internal/org/repo", "http://gitea.internal/org/repo"},
		{"https no path", "https://github.com", "https://github.com"},
		{"query dropped", "https://github.com/org/repo.git?x=1", "https://github.com/org/repo"},
		{"scp mixed case host", "git@GitHub.com:org/repo.git", "https://github.com/org/repo"},
		{"windows drive", "C:\\work\\repo", ""},
		{"windows unc", "\\\\server\\share\\repo", ""},
		{"git scheme", "git://github.com/org/repo.git", ""},
		{"local path", "/work/repo", ""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Normalize(tt.in); got != tt.want {
				t.Errorf("Normalize(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
