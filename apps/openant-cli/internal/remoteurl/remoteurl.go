// Package remoteurl normalizes git remote URLs to plain browse URLs.
//
// #568: the render boundary (report permalinks, the SARIF repositoryUri,
// the server's pipeline-output patching) needs this defense without pulling
// internal/git (which carries exec + subprocess dependencies a render
// package should not acquire). The function is pure; the canonical
// implementation moved here from internal/git, which now re-exports it
// so existing callers are unaffected.
package remoteurl

import (
	"net/url"
	"strings"
)

// Normalize normalizes a git remote URL to a plain browse URL. Returns ""
// when the input cannot be normalized safely: git:// (deprecated), local
// paths, Windows drive paths, and anything unparseable — the honest absence
// is better than a broken or leaking link. Userinfo NEVER persists.
//
//   - scp-form "git@host:org/repo.git" -> "https://host/org/repo"
//   - ssh://git@host[:port]/org/repo    -> "https://host/org/repo" (the ssh
//     port is dropped — it is sshd's, not the browse UI's)
//   - https://user:TOKEN@host/org/repo -> "https://host/org/repo"
//   - http(s)://host/org/repo           -> itself (scheme preserved)
func Normalize(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// scp-form: no scheme, "[user@]host:path". Hand-parsed (net/url
	// cannot parse the scp form).
	if !strings.Contains(raw, "://") {
		// Windows paths (drive letters C:\, UNC \\server\share) are not
		// git remotes — the honest absence.
		if len(raw) >= 2 && raw[1] == ':' && (raw[0] >= 'A' && raw[0] <= 'Z' ||
			raw[0] >= 'a' && raw[0] <= 'z') {
			return ""
		}
		if strings.Contains(raw, `\\`) {
			return ""
		}
		i := strings.IndexByte(raw, ':')
		if i <= 0 || i+1 >= len(raw) {
			return ""
		}
		// The password shape ("user:pass@host:path"): a colon BEFORE the
		// first '@' is a credential separator, not the host-path separator
		// — the CI's catch. Reject (the honest absence) rather than emit
		// the credential text into a URL.
		if a := strings.IndexByte(raw, '@'); a >= 0 && a > i {
			return ""
		}
		rest := raw[i+1:]
		if rest == "" || strings.HasPrefix(rest, "/") {
			return "" // a Windows drive path (C:\...) or a bare scheme
		}
		host := scpHostRegion(raw)
		if host == "" || strings.ContainsAny(host, "[]") {
			return "" // bracketed IPv6 scp — unparseable by this rule
		}
		return "https://" + strings.ToLower(host) + "/" +
			strings.TrimSuffix(strings.Trim(rest, "/"), ".git")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		u.User = nil
		u.RawQuery = ""
		u.Fragment = ""
		u.RawFragment = ""
		u.Path = strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git")
		return u.String()
	case "ssh":
		host := u.Hostname()
		if host == "" {
			return ""
		}
		u.User = nil
		u.Host = host // drop the ssh port
		u.Scheme = "https"
		u.RawQuery = ""
		u.Fragment = ""
		u.RawFragment = ""
		u.Path = strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git")
		return u.String()
	default:
		return "" // git://, ftp://, file:// — not browseable
	}
}

// scpHostRegion extracts the host from an scp-style address using the
// scpHost parsing rule (the last '@' before the ':' path separator —
// "git@evil@127.0.0.1:path" must resolve to 127.0.0.1, not evil@...).
func scpHostRegion(repo string) string {
	limit := len(repo)
	if c := strings.IndexByte(repo, ':'); c >= 0 && c < limit {
		limit = c
	}
	s := repo[:limit]
	if a := strings.LastIndexByte(s, '@'); a >= 0 {
		s = s[a+1:]
	}
	if s == "" {
		return ""
	}
	return s
}
