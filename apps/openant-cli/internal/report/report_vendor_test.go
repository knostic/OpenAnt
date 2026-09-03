package report

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// The vendored, pinned libraries — the integrity side of #332 (wave r1,
// three axes): the sha256s are recorded in vendor/SOURCES.txt and ENFORCED
// here, so an upgrade is a reviewable two-line diff and in-git tampering is
// detectable ("trust whoever ran curl" was the pre-round state).
func TestVendoredReportScriptHashes(t *testing.T) {
	for name, want := range map[string]string{
		"tailwindcss-3.4.16.js":                  "3f81aa7f6ecdb1acc14c202e513dfee00b6c7703cd81ce1be25bf5215a92e8cb",
		"chart-4.4.7.umd.min.js":                 "206b6e8bb00fc7bba2c7ee80ca41db3e9e05ba7be0aa35abeba9cfd5357f5d0e",
		"chartjs-plugin-datalabels-2.9.4.min.js": "20c08f3d9c6d2ef76df6d6a6f1127c0013339fe32add24222276c398c6308c38",
	} {
		data, err := vendorFS.ReadFile("vendor/" + name)
		if err != nil {
			t.Fatalf("vendored script %s missing from the embed: %v", name, err)
		}
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		if got != want {
			t.Fatalf("%s sha256 mismatch: got %s want %s — the blob changed (upgrade? tampering? update vendor/SOURCES.txt deliberately)", name, got, want)
		}
		if len(data) < 10_000 {
			t.Fatalf("vendored script %s suspiciously small (%d bytes) — a stub would silently strip the report", name, len(data))
		}
	}
}

// The html/template breakout hazard (wave r1, three axes): template.JS is
// emitted VERBATIM, so a `</script` or an HTML comment open inside a vendored
// blob would terminate the script element and dump the rest of the library as
// page text. Upstream's build tooling escapes these today; this guard keeps
// it settled across version bumps (probed clean at vendoring time).
func TestVendoredScriptsCarryNoScriptBreakouts(t *testing.T) {
	for _, name := range []string{
		"tailwindcss-3.4.16.js",
		"chart-4.4.7.umd.min.js",
		"chartjs-plugin-datalabels-2.9.4.min.js",
	} {
		data, err := vendorFS.ReadFile("vendor/" + name)
		if err != nil {
			t.Fatalf("vendored script %s missing: %v", name, err)
		}
		s := strings.ToLower(string(data))
		if strings.Contains(s, "</script") {
			t.Fatalf("%s contains </script — template.JS emits verbatim; the inline block would terminate early", name)
		}
		if strings.Contains(s, "<!--") {
			t.Fatalf("%s contains an HTML comment open — the same breakout class", name)
		}
	}
}
