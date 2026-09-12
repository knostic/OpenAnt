package report

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The provenance record must agree with the ENFORCED pins: a stale sha left
// in vendor/SOURCES.txt after a regen would make the "reviewable two-line
// diff" a lie, and a missing entry makes the record incomplete.
func TestVendorSourcesTxtMatchesPinTable(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("vendor", "SOURCES.txt"))
	if err != nil {
		t.Fatalf("vendor/SOURCES.txt: %v", err)
	}
	// CRLF-tolerant: SOURCES.txt is a TEXT file (the .gitattributes
	// binary-artifact rule covers only the vendored *.js) — a Windows
	// checkout converts it, and the \r would ride the \S+ capture into
	// the embedded-file lookup ("report.css\r") and fail it. Normalize.
	src := strings.ReplaceAll(string(raw), "\r\n", "\n")
	// Section model: `# <filename>` at column 0 opens a section; the
	// section's `#   sha256: X` line (indented) is its record.
	sections := map[string]string{} // filename -> sha256
	cur := ""
	for _, line := range strings.Split(src, "\n") {
		if m := regexp.MustCompile(`^# (\S+)$`).FindStringSubmatch(line); m != nil {
			cur = m[1]
			continue
		}
		if m := regexp.MustCompile(`^#\s+sha256: ([0-9a-f]{64})`).FindStringSubmatch(line); m != nil && cur != "" {
			sections[cur] = m[1]
		}
	}
	if len(sections) == 0 {
		t.Fatal("vendor/SOURCES.txt records no per-file sha256 sections — the provenance record is incomplete")
	}
	for name, sha := range sections {
		data, err := vendorFS.ReadFile("vendor/" + name)
		if err != nil {
			t.Errorf("SOURCES.txt section %q: not embedded (%v) — the record drifted or the file was renamed", name, err)
			continue
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != sha {
			t.Errorf("SOURCES.txt records sha256 %s for %s but the embedded bytes hash to %s — the record is stale (a regen without the record update?)", sha, name, hex.EncodeToString(sum[:]))
		}
	}
	// And the reverse: every embedded vendor file must have a section.
	entries, err := vendorFS.ReadDir("vendor")
	if err != nil {
		t.Fatalf("ReadDir vendor: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == "SOURCES.txt" {
			continue
		}
		if _, ok := sections[e.Name()]; !ok {
			t.Errorf("embedded vendor file %q has no SOURCES.txt section — the provenance record is incomplete", e.Name())
		}
	}
}

// The vendored, pinned libraries — the integrity side of #332 (wave r1,
// three axes): the sha256s are recorded in vendor/SOURCES.txt and ENFORCED
// here, so an upgrade is a reviewable two-line diff and in-git tampering is
// detectable ("trust whoever ran curl" was the pre-round state). The
// "Script" in these test names predates #540: report.css (a build-time CSS
// asset, not a JS script) shares the same integrity contract.
func TestVendoredReportScriptHashes(t *testing.T) {
	for name, want := range map[string]string{
		// #540: the prebuilt CSS (the choice-1 migration) — the sha pins the
		// exact build output; a regen updates it deliberately.
		"report.css":                             "9c146ec362d03090688714f48f0241b4262ea6b19c819bbe020c75a6526d477e",
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
		minSize := 10_000
		if name == "report.css" {
			// #540: the CSS is ~21KB (the build ruling: a loose floor, not
			// the anticipated size as a compatibility requirement).
			minSize = 8_000
		}
		if len(data) < minSize {
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
		"report.css",
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
		if name == "report.css" {
			// #540: the CSS embed's breakout is </style (template.CSS), the
			// same guard retargeted for the artifact class.
			if strings.Contains(s, "</style") {
				t.Fatalf("%s contains </style — template.CSS emits verbatim; the inline block would terminate early", name)
			}
		} else if strings.Contains(s, "</script") {
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
