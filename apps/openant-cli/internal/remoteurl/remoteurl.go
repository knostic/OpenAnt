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
// paths, Windows drive paths, bracketed IPv6 in the ssh/scp forms,
// non-URL-safe bytes in the host or the scp fold, and anything unparseable
// — the honest absence is better than a broken or leaking link. Userinfo
// NEVER persists.
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
		// The fold concatenates host and path into a URL — never emit
		// unvalidated text: a host or path with bytes outside the URL-safe
		// set (quotes, angle brackets, control bytes) is not a remote. The
		// honest absence beats a malformed or smuggled URL.
		if !scpURLSafe(host, false) || !scpURLSafe(rest, true) {
			return ""
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
		if u.Host == "" {
			return "" // empty authority — the path would masquerade as the host
		}
		// url.Parse deliberately accepts quote/angle bytes in the host —
		// never emit them (they break the URI and any artifact that embeds
		// it). The honest absence.
		if strings.ContainsAny(u.Host, "\"<>") {
			return ""
		}
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
		// A bracketed IPv6 host loses its brackets here (Hostname strips
		// them) — re-emitting it bracketless is a broken URL, so reject:
		// the honest absence.
		if strings.Contains(host, ":") {
			return ""
		}
		// Same hostile-byte gate as the http arm — url.Parse accepts
		// quote/angle bytes in the host; never emit them.
		if strings.ContainsAny(host, "\"<>") {
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

// scpURLSafe reports whether every byte of s is URL-safe for the scp fold —
// host: letters, digits, ".", "-", "_"; path additionally allows "/" and "~".
func scpURLSafe(s string, path bool) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '-' || c == '_':
		case path && (c == '/' || c == '~'):
		default:
			return false
		}
	}
	return true
}
