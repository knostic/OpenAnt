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
		"chart-4.5.1.umd.min.js":                 "48444a82d4edcb5bec0f1965faacdde18d9c17db3063d042abada2f705c9f54a",
		"chartjs-plugin-datalabels-2.2.0.min.js": "20c08f3d9c6d2ef76df6d6a6f1127c0013339fe32add24222276c398c6308c38",
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
		"chart-4.5.1.umd.min.js",
		"chartjs-plugin-datalabels-2.2.0.min.js",
	} {
		data, err := vendorFS.ReadFile("vendor/" + name)
		if err != nil {
			t.Fatalf("vendored script %s missing: %v", name, err)
		}
		// The guard exists because vendorJS emits template.JS verbatim — it
		// bypasses html/template contextual autoescaping, so the blobs
		// themselves must never contain HTML tokenizer hazards. All four
		// tokens below probed clean on the current blobs at vendoring time.
		s := strings.ToLower(string(data))
		if strings.Contains(s, "</script") {
			t.Fatalf("%s contains </script — template.JS emits verbatim; the inline block would terminate early", name)
		}
		if strings.Contains(s, "<!--") {
			t.Fatalf("%s contains an HTML comment open — the same breakout class", name)
		}
		if strings.Contains(s, "-->") {
			t.Fatalf("%s contains an HTML comment close — script-data-escaped state hazard, same breakout class", name)
		}
		if strings.Contains(s, "<script") {
			t.Fatalf("%s contains a nested <script open — script-data-double-escaped state hazard, same breakout class", name)
		}
	}
}
