package server

import (
	"context"
	"testing"
)

// repoHostBlocked must reject loopback/link-local/metadata targets (SSRF) while
// allowing real remotes and private (internal) git hosts. Canonical IPs are
// classified by value (RFC1918/ULA allowed, loopback/link-local/metadata
// blocked); DNS names are resolved and checked; and ANY non-canonical numeric
// literal (the legacy inet_aton encodings — decimal/octal/hex/short-form/wrap)
// is blocked outright, since no real repo uses them and matching each encoding's
// resolved value was where every prior audit round found a bypass.
func TestRepoHostBlocked(t *testing.T) {
	ctx := context.Background()
	blocked := []string{
		// Canonical literals (baseline).
		"http://169.254.169.254/latest/meta-data/", // cloud metadata (link-local)
		"https://127.0.0.1/x.git",
		"http://localhost:3000/x.git",
		"https://[::1]/x.git",
		"git@127.0.0.1:x.git",
		"http://0.0.0.0/x.git",
		// Legacy numeric IPv4 encodings of 127.0.0.1 (net.ParseIP rejects these,
		// inet_aton/libcurl accept them).
		"http://2130706433/x.git",     // decimal
		"http://0x7f000001/x.git",     // hex (single field)
		"http://017700000001/x.git",   // octal (single field)
		"http://127.1/x.git",          // short form
		"git@2130706433:x.git",        // decimal over ssh host
		// Decimal encoding of 169.254.169.254 (cloud metadata).
		"http://2852039166/latest/meta-data/",
		// Integer >= 2^32: C inet_aton wraps mod 2^32, so 4294967296 -> 0.0.0.0,
		// which git connects to as loopback. Must be blocked.
		"http://4294967296/x.git",
		// Invalid-octal field: BSD/macOS resolver falls back to decimal, so
		// 127.0.0.09 -> 127.0.0.9 (loopback /8). Blocked via decimal fallback.
		"http://127.0.0.09/x.git",
		"http://127.0.0.08/x.git",
		// Valid-octal leading-zero field read as DECIMAL by macOS/BSD getaddrinfo:
		// 0127.0.0.1 -> 127.0.0.1 (loopback) though Go octal reads it as 87; and
		// 0169.0254.0169.0254 -> 169.254.169.254 (EC2 IMDS). Blocked via the
		// decimal candidate in the resolver superset.
		"http://0127.0.0.1/x.git",
		"http://0127.0.0.01/x.git",
		"http://0169.0254.0169.0254/latest/meta-data/",
		// Bare integer > 2^64 (overflows uint64): libcurl still wraps mod 2^32, so
		// 2^64 + 2130706433 -> 127.0.0.1. Must be blocked via big.Int parsing.
		"http://18446744075840258049/x.git",
		// Structural rule: ANY non-canonical numeric literal is blocked regardless
		// of what it resolves to, so no encoding can bypass. These are non-sensitive
		// as values but still refused because a real repo would use the canonical
		// form or a DNS name.
		"http://0xdeadbeef/x.git",       // hex of a public IP (222.173.190.239)
		"http://010.010.010.010/x.git",  // octal 8.8.8.8 / decimal 10.10.10.10
		"http://3232235521/x.git",       // decimal of 192.168.0.1 (canonical form allowed)
		// FQDN-root spellings.
		"http://localhost./x.git",
		"https://127.0.0.1./x.git",
		// RFC 6761 .localhost TLD resolves to loopback on Linux (systemd-resolved).
		"http://foo.localhost/x.git",
		"http://a.b.localhost:8080/x.git",
		"http://LOOP.LocalHost./x.git",
		// AWS IPv6 instance-metadata (ULA literal).
		"https://[fd00:ec2::254]/x.git",
		// IPv6 with a zone id: net.ParseIP rejects zoned literals, but git/libcurl
		// dial them — must strip the zone and block loopback/link-local/IMDS.
		"https://[::1%25lo0]/x.git",
		"https://[fe80::a9fe:a9fe%25en0]/x.git",
		"https://[fd00:ec2::254%25eth0]/x.git",
		// Alibaba Cloud ECS metadata (public RFC6598 literal).
		"http://100.100.100.200/latest/meta-data/",
		// scp-style bracketed IPv6 to loopback/link-local (plain colon-split
		// used to yield host "[" and allow these).
		"git@[::1]:x.git",
		"git@[::ffff:127.0.0.1]:x.git",
		"git@[fe80::1]:x.git",
		// Smuggled extra userinfo: ssh connects to the host after the LAST '@',
		// so scpHost must resolve these to the loopback/metadata host, not the
		// "evil@..." string that would dodge the guard.
		"git@evil@127.0.0.1:x.git",
		"git@evil@[::1]:x.git",
		"git@a@b@169.254.169.254:x.git",
		// Malformed userinfo: url.Parse errors but git/libcurl salvages the
		// trailing host and reaches loopback. Must fail closed.
		`http://example.com\@127.0.0.1/x.git`,
		// Non-ASCII (IDNA) host: a libidn2 git maps unicode label separators /
		// fullwidth digits to ASCII, dialing 127.0.0.1. Non-ASCII fails closed.
		"http://127。0。0。1/x.git",       // U+3002 ideographic dots
		"http://１２７．0．0．1/x.git", // fullwidth 127.0.0.1
	}
	for _, r := range blocked {
		if !repoHostBlocked(ctx, r) {
			t.Errorf("expected blocked, got allowed: %s", r)
		}
	}
	allowed := []string{
		"https://github.com/org/repo.git",
		"http://192.168.1.10/internal.git", // private RFC1918 — internal scans allowed
		"https://10.0.0.5/repo.git",
		"git@gitlab.internal:team/repo.git",
		"https://[fd12:3456:789a::1]/repo.git", // ULA private (not the IMDS literal) — allowed
	}
	for _, r := range allowed {
		if repoHostBlocked(ctx, r) {
			t.Errorf("expected allowed, got blocked: %s", r)
		}
	}
}
