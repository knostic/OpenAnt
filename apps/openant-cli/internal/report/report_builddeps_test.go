package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The security floors the report-CSS build's lockfile was regenerated to
// carry (dependabot #18 postcss-selector-parser, #19 source-map-js — both
// build-time-only: the shipped binary embeds the committed prebuilt
// vendor/report.css via report.go's go:embed, and neither package runs at
// report time).
//
// WHY THIS FILE EXISTS — the silent-regression hole, stated precisely:
// postcss-selector-parser 6.1.4 is the MAXIMUM 6.x ever published (no
// patched 6.x exists), and tailwindcss 3.4.19's parents depend on it
// through `^6` ranges. The only route to the patched 7.1.6 without the
// tailwind v4 config-format migration (capped <4 in renovate.json, on
// purpose) is an npm `overrides` block in tailwind/package.json plus a
// regenerated lock. The trap: **a regenerated package-lock.json does not
// record `overrides`** (verified: no `overrides` key appears anywhere in
// the committed lock, its root `packages[""]` entry included). So if that
// block is lost — a rebase, a merge resolution, a hand-edit — the state
// splits in two, and only ONE half is loud:
//
// STATE A — block lost, lock NOT regenerated (still pins 7.1.6).
// `npm ci` FAILS: without the override npm recomputes the ideal tree
// from the parents' `^6` ranges, wants 6.1.4, finds no such entry and
// refuses — "npm error code EUSAGE ... Missing:
// postcss-selector-parser@6.1.4 from lock file", exit 1, nothing
// installed (measured, npm 11.17.0). CI's report-css job catches this
// half on its own.
//
// STATE B — block lost AND the lock regenerated. THIS is the silent
// half. `npm install --package-lock-only` re-resolves to 6.1.4, and
// npm then places it at NESTED paths with NO hoisted entry at all
// (measured: node_modules/postcss-nested/node_modules/... and
// node_modules/tailwindcss/node_modules/...). `npm ci` then exits 0 and
// installs those vulnerable copies, and the build stays BYTE-IDENTICAL
// to the committed report.css (measured: cmp clean, sha256
// 9c146ec3...477e) because 7.1.6 and 6.1.4 emit the same CSS for these
// inputs. So the sha oracle (report_vendor_test.go), the version and
// palette freshness tests AND the "Report CSS reproducibility" job all
// stay green over a vulnerable tree. Asserting the RESOLVED versions
// recorded in the lock is the only assertion that sees it.
//
// `route` is the package's remediation route, quoted into the failure
// message: the two packages reach their floor by DIFFERENT mechanisms, and
// one shared message would misdescribe whichever it did not name.
var reportBuildLockFloors = map[string]struct {
	floor string
	route string
}{
	"postcss-selector-parser": {
		floor: "7.1.6",
		route: "forced by overrides[\"postcss-selector-parser\"] in tailwind/package.json (the parents range on ^6 and 6.1.4 is the last 6.x) — the known regression route is that block being dropped and the lock then regenerated, after which the resolution falls back to 6.1.4 at NESTED paths (no hoisted entry) and `npm ci` installs it with exit 0",
	},
	"source-map-js": {
		floor: "1.2.2",
		route: "reached WITHOUT an override — postcss ranges on ^1.2.1, so a lock regen picks up 1.2.2 on its own; a version below the floor here means the lock was reverted or hand-edited, not that an override was lost",
	},
}

// TestReportBuildLockSecurityFloors enforces the floors above against
// EVERY entry in the lock, not just the hoisted one. That is not a
// defensive hypothesis: in the measured STATE B regression above npm put
// psp 6.1.4 at TWO nested paths
// (node_modules/postcss-nested/node_modules/postcss-selector-parser and
// node_modules/tailwindcss/node_modules/postcss-selector-parser) and left
// NO hoisted node_modules/postcss-selector-parser entry at all — so a
// guard reading only the hoisted path would have found nothing to check
// at exactly the moment the tree went vulnerable.
func TestReportBuildLockSecurityFloors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("tailwind", "package-lock.json"))
	if err != nil {
		t.Fatalf("tailwind/package-lock.json: %v", err)
	}
	var lock struct {
		LockfileVersion int `json:"lockfileVersion"`
		Packages        map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		t.Fatalf("tailwind/package-lock.json parse: %v", err)
	}
	// The `packages` map is the lockfileVersion 2/3 layout. If npm ever
	// changes the layout this guard must be RETARGETED, not deleted —
	// fail loud rather than iterate an empty map and pass vacuously.
	if len(lock.Packages) == 0 {
		t.Fatalf("tailwind/package-lock.json carries no `packages` entries (lockfileVersion %d) — the lockfile layout this guard reads changed; retarget the guard, do not drop it", lock.LockfileVersion)
	}
	for name, want := range reportBuildLockFloors {
		seen := 0
		for path, pkg := range lock.Packages {
			if npmLockEntryName(path) != name {
				continue
			}
			seen++
			if !npmVersionAtLeast(pkg.Version, want.floor) {
				t.Errorf("tailwind/package-lock.json resolves %s to %q at entry %q, below the security floor %s.\n  How this floor is held: %s.\n  Regenerate with: cd apps/openant-cli/internal/report/tailwind && npm install --package-lock-only   (NEVER `npm install %s@%s` — that promotes a transitive package to a direct dependency)", name, pkg.Version, path, want.floor, want.route, name, want.floor)
			}
		}
		if seen == 0 {
			t.Errorf("%s has no entry in tailwind/package-lock.json — if the report build genuinely no longer depends on it, drop its floor from reportBuildLockFloors deliberately, in the same commit", name)
		}
	}
}

// TestReportBuildPackageJSONCarriesSelectorParserOverride is the EARLY
// warning for the same hole. The floor test above catches STATE B (the
// lock regenerated back down to 6.1.4); this one catches STATE A —
// override gone, lock not yet regenerated. STATE A is NOT silent: `npm
// ci` fails EUSAGE there, so the report-css job already goes red and this
// test is not the only guard. What it adds is a precise, actionable
// failure inside the Go suite — naming the dropped overrides block and
// its removal condition — rather than an opaque "Missing:
// postcss-selector-parser@6.1.4 from lock file" from a separate job, and
// it fires BEFORE anyone "fixes" that red by regenerating the lock, which
// is exactly the step that converts loud STATE A into silent STATE B.
//
// THE OVERRIDE'S DOCUMENTED LIFETIME (the removal condition, so this is
// not a pin nobody dares touch): output equivalence is not API
// compatibility. Remove the override — and this test with it, in one
// commit — when the report build no longer needs forcing, i.e. when
// tailwindcss/postcss/postcss-nested's own ranges accept >=7.1.6 (check:
// with the overrides block deleted, `npm install --package-lock-only`
// still resolves postcss-selector-parser >=7.1.6). Revalidate the CSS
// byte-identity whenever tailwindcss, postcss or postcss-nested move.
func TestReportBuildPackageJSONCarriesSelectorParserOverride(t *testing.T) {
	const pkgName = "postcss-selector-parser"
	raw, err := os.ReadFile(filepath.Join("tailwind", "package.json"))
	if err != nil {
		t.Fatalf("tailwind/package.json: %v", err)
	}
	// json.RawMessage, not string: npm's override values may be either a
	// version string or an object (the nested form, whose own version
	// lives under the "." key). Decoding the map as strings would make a
	// future second, nested override entry fail this test as a *parse*
	// error — misleading noise instead of a real signal.
	var pkg struct {
		Overrides map[string]json.RawMessage `json:"overrides"`
	}
	if err := json.Unmarshal(raw, &pkg); err != nil {
		t.Fatalf("tailwind/package.json parse: %v", err)
	}
	entry, ok := pkg.Overrides[pkgName]
	if !ok {
		t.Fatalf("tailwind/package.json has no overrides[%q] — 6.1.4 is the maximum 6.x and tailwind 3.4.19's parents range on ^6, so without the override the next `npm install` resolves back to the vulnerable 6.1.4 — and once the lock is regenerated to match, `npm ci` installs it with exit 0 over byte-identical CSS (STATE B at the top of this file). Restore it, or remove this test and the %s floor together if the dependency tree no longer needs forcing", pkgName, pkgName)
	}
	var got string
	if err := json.Unmarshal(entry, &got); err != nil {
		var nested struct {
			Dot string `json:"."`
		}
		if err2 := json.Unmarshal(entry, &nested); err2 != nil {
			t.Fatalf("overrides[%q] is neither a version string nor an object with a \".\" key: %s", pkgName, string(entry))
		}
		got = nested.Dot
	}
	if !npmVersionAtLeast(got, reportBuildLockFloors[pkgName].floor) {
		t.Errorf("tailwind/package.json overrides[%q] = %q, below the security floor %s", pkgName, got, reportBuildLockFloors[pkgName].floor)
	}
}

// TestNpmVersionAtLeast guards the GUARD: npmVersionAtLeast is the only
// thing standing between the two tests above and a vacuous pass, and a
// comparator that silently returned true for everything would disarm them
// both while staying green. The "below" rows are the mutations that
// matter.
func TestNpmVersionAtLeast(t *testing.T) {
	for _, tc := range []struct {
		got, floor string
		want       bool
	}{
		{"7.1.6", "7.1.6", true},   // exactly the floor
		{"7.1.7", "7.1.6", true},   // patch above
		{"7.2.0", "7.1.6", true},   // minor above
		{"8.0.0", "7.1.6", true},   // major above
		{"6.1.4", "7.1.6", false},  // the pre-remediation state
		{"7.1.5", "7.1.6", false},  // one patch below
		{"7.0.9", "7.1.6", false},  // minor below, patch above
		{"10.0.0", "9.1.6", true},  // numeric, not lexicographic
		{"9.0.0", "10.0.0", false}, // the same trap, inverted
		{"1.2.2", "1.2.2", true},
		{"1.2.1", "1.2.2", false},
		{"7.1.6-rc.1", "7.1.6", false}, // a prerelease is BELOW its release
		{"7.1.7-rc.1", "7.1.6", true},  // ...but above a lower floor
		{"", "7.1.6", false},           // unparseable -> fail loud
		{"7.1", "7.1.6", false},        // short form -> unparseable
		{"latest", "7.1.6", false},
		{"^7.1.6", "7.1.6", false}, // a RANGE is not a resolved version
	} {
		if got := npmVersionAtLeast(tc.got, tc.floor); got != tc.want {
			t.Errorf("npmVersionAtLeast(%q, %q) = %v, want %v", tc.got, tc.floor, got, tc.want)
		}
	}
}

// TestNpmLockEntryName pins the lock-key parsing the floor test depends
// on: a wrong answer here makes the floor scan skip the very entry it
// exists to check.
func TestNpmLockEntryName(t *testing.T) {
	for path, want := range map[string]string{
		"node_modules/postcss-selector-parser":                             "postcss-selector-parser",
		"node_modules/postcss-nested/node_modules/postcss-selector-parser": "postcss-selector-parser",
		"node_modules/@scope/pkg":                                          "@scope/pkg",
		"node_modules/a/node_modules/@scope/pkg":                           "@scope/pkg",
		"":                                                                 "", // the root project's own entry
		"apps/openant-cli/internal/report/tailwind":                        "", // a workspace path, not a dependency
		"node_modules/postcss-selector-parser-lookalike":                   "postcss-selector-parser-lookalike",
	} {
		if got := npmLockEntryName(path); got != want {
			t.Errorf("npmLockEntryName(%q) = %q, want %q", path, got, want)
		}
	}
}

// npmLockEntryName returns the package name a lockfileVersion 2/3
// `packages` key denotes: the segment after the LAST "node_modules/"
// ("node_modules/a/node_modules/@scope/b" -> "@scope/b"). The root
// project's own entry has the key "" and yields "".
func npmLockEntryName(path string) string {
	const marker = "node_modules/"
	if i := strings.LastIndex(path, marker); i >= 0 {
		return path[i+len(marker):]
	}
	return ""
}

// npmVersionAtLeast reports whether got >= floor for the plain
// MAJOR.MINOR.PATCH releases npm records in a lockfile. Two deliberate
// conservative readings: an UNPARSEABLE version returns false (fail loud,
// never silently green), and a PRERELEASE ("7.1.6-rc.1") never satisfies
// a floor equal to its own core, which is what semver ordering says and
// the safe reading for a security floor.
func npmVersionAtLeast(got, floor string) bool {
	g, gPre, okG := npmSemverCore(got)
	f, fPre, okF := npmSemverCore(floor)
	if !okG || !okF || fPre {
		return false
	}
	for i := range g {
		if g[i] != f[i] {
			return g[i] > f[i]
		}
	}
	return !gPre
}

// npmSemverCore splits "7.1.6-rc.1+build" into its numeric core and
// whether a prerelease/build suffix was present.
func npmSemverCore(v string) (core [3]int, hasSuffix bool, ok bool) {
	s := v
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s, hasSuffix = s[:i], true
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return core, hasSuffix, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return core, hasSuffix, false
		}
		core[i] = n
	}
	return core, hasSuffix, true
}
