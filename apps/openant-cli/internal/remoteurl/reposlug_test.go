package remoteurl

import "testing"

// TestRepoSlug is the canonical suite for the #612 name tier's helper.
//
// The contract: derive the repository DISPLAY name (the full path — a
// nested namespace keeps every segment) from a NORMALIZED URL; the
// honest absence ("") on any unusable path, never a truncated or
// invented identity. Not to be unified with config.DeriveProjectName
// (see the cross-references at both sites).
func TestRepoSlug(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"the plain github shape", "https://github.com/org/repo", "org/repo"},
		{"a nested gitlab namespace keeps every segment", "https://gitlab.com/g/sub/repo", "g/sub/repo"},
		{"single-segment hosts stay single", "https://host/repo", "repo"},
		{"host-only derives nothing", "https://github.com", ""},
		{"empty input", "", ""},
		{"trailing slash", "https://github.com/org/repo/", "org/repo"},
		{"a leading empty segment (interior)", "https://github.com/org//repo", ""},
		{"dot segment", "https://github.com/org/./repo", ""},
		{"dotdot segment", "https://github.com/../repo", ""},
		{"escaped dotdot decodes and hits the guard", "https://github.com/%2E%2E/repo", ""},
		{"an escaped separator degrades to a harmless separator (decoded)", "https://github.com/org%2Frepo", "org/repo"},
		{"a control character in the path", "https://github.com/org/re%00po", ""},
		{"spaces (percent-encoded prose) are not slug characters", "https://github.com/org/re%20po", ""},
		{"an unescaped space is not a slug character", "https://github.com/org/re po", ""},
		{"caps and digits and ._- are slug characters", "https://github.com/Org.R_e-po/x1", "Org.R_e-po/x1"},
		{"sr.ht tilde namespaces are real and derive", "https://git.sr.ht/~alice/repo", "~alice/repo"},
		{"a leading-hyphen segment is never a slug (argv safety)", "https://github.com/-repo", ""},
		{"a leading-hyphen segment mid-path is never a slug", "https://github.com/org/-repo", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RepoSlug(tc.in); got != tc.want {
				t.Errorf("RepoSlug(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
