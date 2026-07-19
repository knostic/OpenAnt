package config

import "testing"

// Regression: SSH-scheme git remotes were misparsed because the scp-like SSH
// branch greedily split on the scheme's first ':' (see gocli-derive-name-ssh-scheme-misparse).
func TestDeriveProjectName_SSHScheme(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"git@github.com:org/repo.git", "org/repo"},               // scp-like (already worked)
		{"ssh://git@github.com/org/repo.git", "org/repo"},         // ssh:// scheme
		{"ssh://git@github.com:22/org/repo.git", "org/repo"},      // ssh:// scheme with port
		{"https://user@github.com/org/repo.git", "org/repo"},      // https with userinfo
		{"https://github.com/grafana/grafana.git", "grafana/grafana"},
	}
	for _, c := range cases {
		got := DeriveProjectName(c.in)
		if got != c.want {
			t.Errorf("DeriveProjectName(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}
