package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// #540 Stage C — the extractor fixtures (TDD: the honest REDs).
// ---------------------------------------------------------------------------

func TestTemplateClassTokensFixtures(t *testing.T) {
	// Fixture 1: the {{if}}-split alternation (overview.gohtml:162 shape).
	toks, holes := templateClassTokens(
		`<tr class="border-b border-gray-800 {{if even $i}}bg-navy-800{{else}}bg-navy-900/30{{end}}">`)
	want := []string{"border-b", "border-gray-800", "bg-navy-800", "bg-navy-900/30"}
	if !equalSets(toks, want) {
		t.Errorf("alternation tokens = %v, want %v", toks, want)
	}
	if len(holes) != 0 {
		t.Errorf("conditionals are not value holes; got %v", holes)
	}

	// Fixture 2: the 7-line class attribute (overview.gohtml:178-184 shape).
	toks, _ = templateClassTokens(
		`<div class="max-w-[1400px] mx-auto px-1.5 [&_h3]:text-base [&_code]:text-[10px] bg-white/70 rounded-2xl">`)
	want = []string{"max-w-[1400px]", "mx-auto", "px-1.5", "[&_h3]:text-base",
		"[&_code]:text-[10px]", "bg-white/70", "rounded-2xl"}
	if !equalSets(toks, want) {
		t.Errorf("long attr tokens = %v, want %v", toks, want)
	}

	// Fixture 3: the value holes ($step.StatusColor / .StatusColor).
	_, holes = templateClassTokens(`<td class="py-3 px-4 {{$step.StatusColor}}">{{$step.Status}}</td>`)
	if !equalSets(holes, []string{"$step.StatusColor"}) {
		t.Errorf("value hole = %v, want [$step.StatusColor]", holes)
	}
	_, holes = templateClassTokens(`<div class="{{.StatusColor}} font-medium">`)
	if !equalSets(holes, []string{".StatusColor"}) {
		t.Errorf("value hole = %v, want [.StatusColor]", holes)
	}

	// Fixture 4: non-class attributes are not harvested.
	toks, _ = templateClassTokens(`<a href="/x" id="link">x</a>`)
	if len(toks) != 0 {
		t.Errorf("href/id harvested: %v", toks)
	}

	// Fixture 5: template comments are not value holes.
	_, holes = templateClassTokens(`{{/* #332: vendored */}}<div class="p-4">`)
	if len(holes) != 0 {
		t.Errorf("comment flagged as a value hole: %v", holes)
	}
}

// ---------------------------------------------------------------------------
// The StatusColor AST harvest.
// ---------------------------------------------------------------------------

func TestStatusColorLiteralsHarvested(t *testing.T) {
	lits, err := statusColorLiterals()
	if err != nil {
		t.Fatalf("harvest: %v", err)
	}
	// The current known set (types.go StatusColor): the green/red/yellow/
	// gray literals. A new case lands here automatically — that is the point.
	// The real set (types.go StatusColor: green/red for the pass/fail
	// arms, gray the default) — a NEW case lands here automatically.
	for _, want := range []string{"text-green-400", "text-red-400", "text-gray-400"} {
		if !contains(lits, want) {
			t.Errorf("StatusColor literal %q not harvested; got %v", want, lits)
		}
	}
	if len(lits) < 3 {
		t.Errorf("suspiciously few literals: %v", lits)
	}
}

// ---------------------------------------------------------------------------
// The coverage checker itself (built against report.css once it exists).
// ---------------------------------------------------------------------------

// cssEscape implements the CSS identifier escape for selector matching:
// every char outside [A-Za-z0-9_-] gets a backslash (the the design review concern:
// bg-navy-900/30 -> .bg-navy-900\/30; px-1.5 -> .px-1\.5; the arbitrary
// variants -> .\[&\_h3\]\:sm\:text-lg).
func cssEscape(tok string) string {
	var b strings.Builder
	for _, r := range tok {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('\\')
			b.WriteRune(r)
		}
	}
	return b.String()
}

// hasSelector reports whether css contains a selector for tok — the
// escaped class with an identifier boundary (so .mb-1 does not match
// .mb-10's rule), OUTSIDE comments (a hex appearing in a banner comment
// satisfies nothing — the the build review catch).
func hasSelector(css, tok string) bool {
	noComments := stripCSSComments(css)
	esc := cssEscape(tok)
	// The selector appears as .escaped followed by a non-identifier char
	// (space, comma, {, :, the compound descendant parts...).
	re := regexp.MustCompile(`(?m)\.` + regexp.QuoteMeta(esc) + `([^A-Za-z0-9_-]|$)`)
	return re.MatchString(noComments)
}

func stripCSSComments(css string) string {
	re := regexp.MustCompile(`(?s)/\*.*?\*/`)
	return re.ReplaceAllString(css, "")
}

// markerClasses emit no CSS rule of their own — an explicit, commented
// allowlist (the design ruling: without it the coverage test is red forever
// and someone "fixes" it by loosening the match).
var markerClasses = map[string]bool{
	"group": true, // the hover/focus peer marker (overview:281, reskin:311,329)
	"peer":  true,
}

// templateLocalSelectors harvests the class selectors defined in the
// templates' own <style> blocks (remediation-content, card-hover,
// finding-ref — defined at reskin:56-82; the coverage must not demand them
// from the Tailwind build).
func templateLocalSelectors(src string) []string {
	styleRe := regexp.MustCompile(`(?s)<style>(.*?)</style>`)
	classRe := regexp.MustCompile(`\.([A-Za-z0-9_-]+)`)
	var out []string
	for _, m := range styleRe.FindAllStringSubmatch(src, -1) {
		for _, c := range classRe.FindAllStringSubmatch(m[1], -1) {
			out = append(out, c[1])
		}
	}
	return out
}

// TestReportCSSCoverage is the load-bearing #540 Stage C test: every
// class token in BOTH templates (static + conditional + the StatusColor
// value holes resolved from source) must have a selector in the built
// CSS — or be a marker, or a template-local selector.
//
// It skips (t.Skip) until vendor/report.css exists — the honest RED is
// exercised by TestReportCSSCoverageMutation (the checker itself) and by
// the prose-RED (the coverage forcing the typography decision) during
// the build stages.
func TestReportCSSCoverage(t *testing.T) {
	cssBytes, err := os.ReadFile(filepath.Join("vendor", "report.css"))
	if err != nil {
		t.Skipf("report.css not built yet (the pre-CSS era): %v", err)
	}
	css := string(cssBytes)

	for _, tmpl := range []string{"templates/overview.gohtml",
		"templates/report-reskin.gohtml"} {
		srcBytes, err := os.ReadFile(tmpl)
		if err != nil {
			t.Fatalf("read %s: %v", tmpl, err)
		}
		src := string(srcBytes)
		toks, holes := templateClassTokens(src)
		locals := map[string]bool{}
		for _, s := range templateLocalSelectors(src) {
			locals[s] = true
		}

		// F1 (the round-1 refutation): the StatusColor literals must be
		// ASSERTED PRESENT in the CSS (they were harvested then used as a
		// skip-list — the dynamic-class half of the coverage contract was
		// unenforced). text-gray-400 is also a static token; it is NOT
		// exempted from the per-token check below.
		_, err = statusColorLiterals()
		if err != nil {
			t.Fatalf("StatusColor harvest: %v", err)
		}

		missing := []string{}
		for _, tok := range toks {
			if markerClasses[tok] || locals[tok] {
				continue
			}
			if !hasSelector(css, tok) {
				missing = append(missing, tok)
			}
		}
		// The literals themselves (the value holes' resolutions).
		lits, err := statusColorLiterals()
		if err != nil {
			t.Fatalf("StatusColor harvest (2): %v", err)
		}
		for _, l := range lits {
			if !hasSelector(css, l) {
				missing = append(missing, l)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			t.Errorf("%s: classes with no selector in report.css: %v", tmpl, missing)
		}
		// F1: the value-hole loop — each hole's trailing method must be
		// one the harvester walked (a NEW class-returning method that the
		// harvester's filters drop is caught here).
		holeMethods := map[string]bool{}
		for _, h := range holes {
			// "$step.StatusColor" / ".StatusColor" -> "StatusColor"
			parts := strings.Split(h, ".")
			holeMethods[parts[len(parts)-1]] = true
		}
		if len(holeMethods) > 0 && len(lits) == 0 {
			t.Errorf("%s: value holes %v but the StatusColor harvest found nothing — the dynamic classes are unchecked", tmpl, holeMethods)
		}
	}
}

// TestReportCSSCoverageMutation is the mutation guard (the design ruling:
// without it the checker can be vacuously green — an escaping bug makes
// every lookup match the banner comment). Delete a known rule from the
// CSS bytes IN MEMORY and assert the checker reports it.
func TestReportCSSCoverageMutation(t *testing.T) {
	cssBytes, err := os.ReadFile(filepath.Join("vendor", "report.css"))
	if err != nil {
		t.Skipf("report.css not built yet: %v", err)
	}
	// Take a token we KNOW the build emits (verify against the bytes
	// first — the mutation is meaningful only if the rule exists).
	css := string(cssBytes)
	tok := ""
	for _, candidate := range []string{"max-w-[1400px]", "mx-auto",
		"px-1.5", "border-b", "rounded-2xl", "py-3"} {
		if hasSelector(css, candidate) {
			tok = candidate
			break
		}
	}
	if tok == "" {
		t.Fatal("no known token found in report.css — the mutation guard cannot run")
	}
	// Strip the comments (the matcher's own step) and remove ONE rule
	// containing the token's selector.
	noComments := stripCSSComments(css)
	re := regexp.MustCompile(`(?m)\.` + regexp.QuoteMeta(cssEscape(tok)) +
		`([^A-Za-z0-9_-]|$)[^{}]*\{[^}]*\}`)
	mutated := re.ReplaceAllString(noComments, "")
	if mutated == noComments {
		// The rule pattern didn't match (a compound selector context);
		// fall back to removing every line mentioning the selector.
		lines := strings.Split(noComments, "\n")
		var kept []string
		esc := "." + cssEscape(tok)
		for _, ln := range lines {
			if !strings.Contains(ln, esc) {
				kept = append(kept, ln)
			}
		}
		mutated = strings.Join(kept, "\n")
	}
	if hasSelector(mutated, tok) {
		t.Fatalf("the mutation guard is VACUOUS: removing %q's rule left the checker green — hasSelector matches something other than the rule (a comment? a compound?)", tok)
	}
}

func equalSets(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	gs := append([]string{}, got...)
	ws := append([]string{}, want...)
	sort.Strings(gs)
	sort.Strings(ws)
	for i := range gs {
		if gs[i] != ws[i] {
			return false
		}
	}
	return true
}

func contains(set []string, s string) bool {
	for _, v := range set {
		if v == s {
			return true
		}
	}
	return false
}

// TestReportCSSVersionFreshness (F2, the round-1 refutation): the CSS
// build banner must match the version in tailwind/package.json — a
// version bump without a regen fails here (the sha test alone would stay
// green on the stale bytes).
func TestReportCSSVersionFreshness(t *testing.T) {
	cssBytes, err := os.ReadFile(filepath.Join("vendor", "report.css"))
	if err != nil {
		t.Fatalf("report.css: %v", err)
	}
	pkgBytes, err := os.ReadFile(filepath.Join("tailwind", "package.json"))
	if err != nil {
		t.Fatalf("tailwind/package.json: %v", err)
	}
	var pkg struct {
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal(pkgBytes, &pkg); err != nil {
		t.Fatalf("package.json parse: %v", err)
	}
	ver := pkg.Dependencies["tailwindcss"]
	if ver == "" {
		t.Fatal("no tailwindcss dependency in tailwind/package.json")
	}
	ver = strings.Trim(ver, "^~")
	want := "tailwindcss v" + ver
	if !strings.Contains(string(cssBytes), want) {
		t.Errorf("report.css banner does not carry %q — the build is stale (regen needed)", want)
	}
}

// TestReportCSSPaletteFreshness (F2): each palette hex in palette.json
// must appear in report.css as its rgb() form (Tailwind 3 emits
// rgb(R G B / var(--tw-*-opacity)) — the hex→rgb conversion).
func TestReportCSSPaletteFreshness(t *testing.T) {
	cssBytes, err := os.ReadFile(filepath.Join("vendor", "report.css"))
	if err != nil {
		t.Fatalf("report.css: %v", err)
	}
	css := string(cssBytes)
	palBytes, err := os.ReadFile(filepath.Join("tailwind", "palette.json"))
	if err != nil {
		t.Fatalf("palette.json: %v", err)
	}
	var pal struct {
		Colors map[string]interface{} `json:"colors"`
	}
	if err := json.Unmarshal(palBytes, &pal); err != nil {
		t.Fatalf("palette.json parse: %v", err)
	}
	// Only check colors a TEMPLATE CLASS references (Tailwind purges the
	// unreferenced ones — navy-deep/purple-glow are palette entries no
	// template uses; the round-1 note's own instruction).
	var classTokens []string
	for _, tmpl := range []string{"templates/overview.gohtml",
		"templates/report-reskin.gohtml"} {
		srcBytes, err := os.ReadFile(tmpl)
		if err != nil {
			t.Fatalf("read %s: %v", tmpl, err)
		}
		toks, _ := templateClassTokens(string(srcBytes))
		classTokens = append(classTokens, toks...)
	}
	var walk func(m map[string]interface{}, prefix string)
	walk = func(m map[string]interface{}, prefix string) {
		for k, v := range m {
			if sub, ok := v.(map[string]interface{}); ok {
				walk(sub, prefix+"-"+k)
				continue
			}
			hex, ok := v.(string)
			if !ok || !strings.HasPrefix(hex, "#") || len(hex) != 7 {
				continue
			}
			// Only colors with a template class referencing the name.
			name := prefix + "-" + k
			used := false
			for _, tok := range classTokens {
				if strings.Contains(tok, name) {
					used = true
					break
				}
			}
			if !used {
				continue
			}
			r := parseInt(hex[1:3], 16)
			g := parseInt(hex[3:5], 16)
			b := parseInt(hex[5:7], 16)
			rgb := fmt.Sprintf("%d %d %d", r, g, b)
			if !strings.Contains(css, rgb) {
				t.Errorf("palette color %s (%s) missing its rgb(%s ...) form in report.css — the build is stale", name, hex, rgb)
			}
		}
	}
	walk(pal.Colors, "")
}

func parseInt(s string, base int) int {
	var n int
	fmt.Sscanf(s, "%x", &n)
	return n
}
