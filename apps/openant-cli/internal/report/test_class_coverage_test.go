package report

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
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

	// Fixture 6: the self-closing-tag attr boundary (class="x"/> — the
	// `/` after the closing quote is a legal attr end; the boundary
	// alternation must accept it or the attr is reported unharvestable).
	UnharvestableClassAttrs = nil
	toks, _ = templateClassTokens(`<img class="w-8 rounded-full"/>`)
	want = []string{"w-8", "rounded-full"}
	if !equalSets(toks, want) {
		t.Errorf("self-closing attr tokens = %v, want %v", toks, want)
	}
	if len(UnharvestableClassAttrs) != 0 {
		t.Errorf("self-closing attr wrongly reported unharvestable: %v", UnharvestableClassAttrs)
	}
}

// ---------------------------------------------------------------------------
// The StatusColor AST harvest.
// ---------------------------------------------------------------------------

func TestStatusColorLiteralsHarvested(t *testing.T) {
	lits, _, err := statusColorLiterals()
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
	// (space, comma, {, :, the compound descendant parts...). A backslash
	// is NOT a boundary — it is an ESCAPE CONTINUATION: searching "max-w"
	// against `.max-w-\[1400px\]` must not match (that selector is the
	// different class max-w-[1400px]).
	re := regexp.MustCompile(`(?m)\.` + regexp.QuoteMeta(esc) + `([^A-Za-z0-9_\\-]|$)`)
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
	"group": true, // the hover/focus group marker (overview:265's class="...group")
}

// templateLocalSelectors harvests the class selectors defined in the
// templates' own <style> blocks (remediation-content, card-hover,
// finding-ref — defined at reskin:56-82; the coverage must not demand them
// from the Tailwind build).
func templateLocalSelectors(src string) []string {
	styleRe := regexp.MustCompile(`(?s)<style>(.*?)</style>`)
	// Selector-POSITION anchored, per rule HEADER: split the style body at
	// rule boundaries and harvest class-shaped names from the header text
	// only. A bare \.[A-Za-z0-9_-]+ over the whole BODY also matched
	// decimals in declaration values (1.5rem -> "5rem") and the literal
	// "css" of the vendorCSS action; and a single match-to-{ regex dropped
	// every selector after the first in comma-separated lists (.a, .b {).
	headerRe := regexp.MustCompile(`([^{}]+)\{`)
	nameRe := regexp.MustCompile(`\.([A-Za-z][A-Za-z0-9_-]*)`)
	var out []string
	for _, m := range styleRe.FindAllStringSubmatch(src, -1) {
		for _, h := range headerRe.FindAllStringSubmatch(m[1], -1) {
			for _, c := range nameRe.FindAllStringSubmatch(h[1], -1) {
				out = append(out, c[1])
			}
		}
	}
	return out
}

// TestReportCSSCoverage is the load-bearing #540 Stage C test: every
// class token in BOTH templates (static + conditional + the StatusColor
// value holes resolved from source) must have a selector in the built
// CSS — or be a marker, or a template-local selector.
//
// It fails hard now (report.css is go:embed'd, a missing file is a build failure) — the honest RED is
// exercised by TestReportCSSCoverageMutation (the checker itself) and by
// the prose-RED (the coverage forcing the typography decision) during
// the build stages.
func TestReportCSSCoverage(t *testing.T) {
	cssBytes, err := os.ReadFile(filepath.Join("vendor", "report.css"))
	if err != nil {
		t.Fatalf("report.css is go:embed'd — a missing file is a build failure: %v", err)
	}
	css := string(cssBytes)

	// Hoisted (round-2): the harvest runs ONCE, not per-template.
	lits, harvestedMethods, err := statusColorLiterals()
	if err != nil {
		t.Fatalf("StatusColor harvest: %v", err)
	}
	// The literals (the value holes' resolutions) — OUTSIDE the
	// per-template loop (template-independent; the loop reported twice).
	for _, l := range lits {
		if !hasSelector(css, l) {
			t.Errorf("StatusColor literal %q has no selector in report.css — the dynamic classes are unchecked", l)
		}
	}
	for _, tmpl := range []string{"templates/overview.gohtml",
		"templates/report-reskin.gohtml"} {
		srcBytes, err := os.ReadFile(tmpl)
		if err != nil {
			t.Fatalf("read %s: %v", tmpl, err)
		}
		src := string(srcBytes)
		UnharvestableClassAttrs = nil
		toks, holes := templateClassTokens(src)
		if len(UnharvestableClassAttrs) > 0 {
			t.Errorf("%s: class attributes with embedded quoted template literals are UNVERIFIABLE by the extractor (the attr regex mis-terminates): %q — rewrite the conditional without a quoted literal", tmpl, UnharvestableClassAttrs)
		}
		locals := map[string]bool{}
		for _, s := range templateLocalSelectors(src) {
			locals[s] = true
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
		if len(missing) > 0 {
			sort.Strings(missing)
			t.Errorf("%s: classes with no selector in report.css: %v", tmpl, missing)
		}
		// F1: the value-hole loop — each hole's trailing method must be
		// one the harvester walked (a NEW class-returning method that the
		// harvester's filters drop is caught here).
		// Round 2: the hole-harvester contract is STRUCTURAL — each
		// hole's trailing method name must be one whose literals the
		// go/ast harvester walked (a class-returning method WITHOUT
		// "color" in its name escapes the harvester's name filter; the
		// structural check catches that here, per-template).
		for _, h := range holes {
			parts := strings.Split(h, ".")
			methodName := parts[len(parts)-1]
			hm, ok := harvestedMethods[methodName]
			if !ok || !hm.walked {
				t.Errorf("%s: value hole %q references method %q which the go/ast harvester did NOT walk", tmpl, h, methodName)
				continue
			}
			if !hm.hasClassLits {
				t.Errorf("%s: value hole %q references method %q which yields NO class literals (hex-only or empty — it cannot resolve a class attribute)", tmpl, h, methodName)
			}
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
		t.Fatalf("report.css is go:embed'd — a missing file is a build failure: %v", err)
	}
	// Take a token we KNOW the build emits (verify against the bytes
	// first — the mutation is meaningful only if the rule exists).
	css := string(cssBytes)
	tok := ""
	for _, candidate := range []string{"max-w-[1400px]", "mx-auto", "border-b", "py-3"} {
		if hasSelector(css, candidate) {
			tok = candidate
			break
		}
	}
	if tok == "" {
		t.Fatal("no known token found in report.css — the mutation guard cannot run")
	}
	// Strip the comments (the matcher's own step) and remove ONE rule
	// containing the token's selector. The rule pattern's boundary is an
	// ALTERNATION, not a consumed character class: the old shape
	// `([^A-Za-z0-9_-]|$)[^{}]*\{...` consumed the `{` as the "boundary"
	// and then demanded a SECOND one — it never matched the real CSS, every
	// run fell into the line-wipe fallback, and hasSelector("") is
	// vacuously false: the guard passed while verifying nothing (caught by
	// the wipe guard this round). Case A: the rule body follows the
	// selector immediately; case B: a non-identifier boundary (the
	// backslash escape-continuation excluded, as in hasSelector) then the
	// rest of a compound selector then the rule; case C: end-of-line.
	noComments := stripCSSComments(css)
	re := regexp.MustCompile(`(?m)\.` + regexp.QuoteMeta(cssEscape(tok)) +
		`(?:\{[^}]*\}|[^A-Za-z0-9_\\-][^{}]*\{[^}]*\}|$)`)
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
		if len(kept) == len(lines) {
			t.Fatalf("the mutation fallback matched nothing for %q — the guard cannot verify", tok)
		}
		if len(kept) == 0 {
			// Minified CSS is ONE line: the line filter would wipe the whole
			// stylesheet, and hasSelector("") is vacuously false — the guard
			// would "pass" while verifying nothing.
			t.Fatalf("the mutation fallback would wipe the entire single-line stylesheet for %q — the rule regex missed and the line filter cannot operate; fix the rule pattern", tok)
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
		Colors       map[string]interface{} `json:"colors"`
		FontFamily   map[string][]string    `json:"fontFamily"`
		BorderRadius struct {
			Card string `json:"card"`
		} `json:"borderRadius"`
	}
	if err := json.Unmarshal(palBytes, &pal); err != nil {
		t.Fatalf("palette.json parse: %v", err)
	}
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
	// The StatusColor LITERAL channel counts as usage too: a palette color
	// referenced only from types.go (return "text-accent") would otherwise
	// skip its freshness check.
	if lits, _, err := statusColorLiterals(); err == nil {
		classTokens = append(classTokens, lits...)
	}
	// Only colors a TEMPLATE CLASS references (Tailwind purges the
	// unreferenced ones — navy-deep/purple-glow are palette entries no
	// template uses; the round-1 note's own instruction). The used-
	// determination requires the token to END with the palette name (after
	// stripping any /opacity suffix): a Contains match collides across
	// siblings — knostic-purple would be "used" by text-knostic-purple-hover
	// alone, and the hex-only leaf would skip its real staleness check.
	usedBy := func(name string) bool {
		for _, tok := range classTokens {
			base := strings.SplitN(tok, "/", 2)[0]
			if strings.HasSuffix(base, name) {
				return true
			}
		}
		return false
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
			name := prefix + "-" + k
			if !usedBy(name) {
				continue
			}
			r := parseInt(hex[1:3])
			g := parseInt(hex[3:5])
			b := parseInt(hex[5:7])
			rgb := fmt.Sprintf("%d %d %d", r, g, b)
			// The binding is SELECTOR-SCOPED with a right-BOUNDARY
			// expressed as an ALTERNATION (a consumed boundary char class
			// eats the rule-open and then demands a second one — the
			// same structural bug the mutation guard carried): case A,
			// the rule body follows the name directly; case B, a
			// non-identifier boundary char (the escape-continuation
			// excluded) then the rest of a compound selector then the
			// rule body. The boundary stops prefix siblings — knostic-border
			// must not be satisfied by .border-knostic-border-light's rule.
			// Case A: the rule body follows the name directly. Case B: a
			// separator boundary (NOT a rule-open — a `{` boundary is
			// case A's job; letting case B consume it let the span cross
			// into OTHER rules and satisfy the check from anywhere) then
			// the rest of the same compound selector (no braces) then the
			// rule body.
			// NB: the hyphen sits LAST in the boundary class — a `\\-\{`
			// sequence parses as a RANGE (backslash..brace) and `-` slips
			// through as a boundary, re-opening the sibling collision.
			ruleRe := regexp.MustCompile(`\.[^\{]*` + regexp.QuoteMeta(name) +
				`(?:\{[^\}]*rgb\(` + rgb + `|[^A-Za-z0-9_\\{-][^{}]*\{[^\}]*rgb\(` + rgb + `)`)
			if !ruleRe.MatchString(css) {
				t.Errorf("palette color %s (%s) missing its rgb(%s ...) form in a rule selecting %s — the build is stale or the values were swapped", name, hex, rgb, name)
			}
		}
	}
	walk(pal.Colors, "")

	// The NON-COLOR palette sections carry the same freshness contract —
	// bound to the RULE form, not presence-anywhere (.rounded-card's exact
	// declaration, so a swapped value or another rule's 9999px cannot
	// satisfy it).
	hasToken := func(tokName string) bool {
		for _, tok := range classTokens {
			base := strings.SplitN(tok, "/", 2)[0]
			if strings.HasSuffix(base, tokName) {
				return true
			}
		}
		return false
	}
	if hasToken("font-knostic") {
		wantStack := strings.Join(pal.FontFamily["knostic-sans"], ",")
		if wantStack == "" {
			t.Fatal("palette fontFamily['knostic-sans'] missing — the palette structure changed")
		}
		if !strings.Contains(css, ".font-knostic{font-family:"+wantStack) {
			t.Errorf("palette fontFamily knostic-sans should render as .font-knostic{font-family:%s — missing from report.css (stale build)", wantStack)
		}
	}
	if hasToken("rounded-card") {
		if pal.BorderRadius.Card == "" {
			t.Fatal("palette borderRadius.card missing — the palette structure changed")
		}
		if !strings.Contains(css, ".rounded-card{border-radius:"+pal.BorderRadius.Card) {
			t.Errorf("palette borderRadius card = %s should render in .rounded-card's exact rule — missing from report.css (stale build)", pal.BorderRadius.Card)
		}
	}
}

// The sanitization whitelist binds the STYLING coverage: every element
// remediationPolicy.AllowElements admits must have a styling hook for the
// remediation-content context — the prose-typography plugin once covered
// them; its removal (the #540 migration) silently cut several (blockquote,
// ol, pre-with-overflow, kbd/samp, h1/h2/h5/h6, the table family) until this
// contract pinned them. The coverage tests only verify classes the
// templates DO reference — they cannot catch a class that should exist but
// was silently deleted; this test is that missing direction.
func TestRemediationAllowElementsStyled(t *testing.T) {
	// The default-adequate set: browser defaults + the implicit table
	// structure (thead/tbody/tr carry no own styling in prose either; the
	// th/td borders style the family).
	defaultAdequate := map[string]bool{
		"br": true, "span": true, "em": true, "b": true, "i": true, "u": true,
		"thead": true, "tbody": true, "tr": true,
	}
	// Harvest the AllowElements call's string arguments from types.go (the
	// AST pattern of statuscolor_literals_test.go — the same file the
	// tailwind content list names; hand-copying the list would drift).
	fset := token.NewFileSet()
	f, perr := parser.ParseFile(fset, filepath.Join("types.go"), nil, 0)
	if perr != nil {
		t.Fatalf("parse types.go: %v", perr)
	}
	allowed := []string{}
	ast.Inspect(f, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := ce.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		// BOTH admission channels: AllowElements("p", ...) and the
		// AllowAttrs(...).OnElements("a") chain (bluemonday's OnElements
		// admits the element itself — the <a> escaped the first harvest
		// while links rendered unstyled under the preflight reset).
		if sel.Sel.Name != "AllowElements" && sel.Sel.Name != "OnElements" {
			return true
		}
		for _, arg := range ce.Args {
			if bl, ok := arg.(*ast.BasicLit); ok && bl.Kind == token.STRING {
				allowed = append(allowed, strings.Trim(bl.Value, "\"`"))
			}
		}
		return false
	})
	if len(allowed) == 0 {
		t.Fatal("AllowElements call not found in types.go — the sanitizer whitelist moved; update this harvest")
	}
	for _, el := range allowed {
		if defaultAdequate[el] {
			continue
		}
		// Per-TEMPLATE, DIV-SCOPED binding: the remediation-content DIV's
		// own class list must carry the element's [&_el]: hook (a whole-
		// file Contains would pass with the hook placed on any other
		// element; the compiled CSS alone would pass while one template's
		// port was silently cut).
		hook := "[&_" + el + "]:"
		for _, tmpl := range []string{"templates/overview.gohtml", "templates/report-reskin.gohtml"} {
			srcBytes, err := os.ReadFile(tmpl)
			if err != nil {
				t.Fatalf("read %s: %v", tmpl, err)
			}
			src := string(srcBytes)
			i := strings.Index(src, `class="remediation-content `)
			if i < 0 {
				t.Fatalf("%s: the remediation-content div not found", tmpl)
			}
			j := strings.Index(src[i:], `">`)
			if j < 0 {
				t.Fatalf("%s: the remediation-content div's class list unterminated", tmpl)
			}
			if !strings.Contains(src[i:i+j], hook) {
				t.Errorf("%s: AllowElements admits %q but the remediation-content div lacks its %q hook — the typography cut it silently; keep the port symmetric", tmpl, el, hook)
			}
		}
	}
}

// The escape-continuation boundary's own RED vector: the invariant
// (searching "max-w" must not false-match .max-w-\[1400px\]) was documented
// but never directly asserted — a future boundary "cleanup" would regress
// silently.
func TestHasSelectorEscapeContinuation(t *testing.T) {
	cssBytes, err := os.ReadFile(filepath.Join("vendor", "report.css"))
	if err != nil {
		t.Fatalf("report.css is go:embed'd — a missing file is a build failure: %v", err)
	}
	css := string(cssBytes)
	if hasSelector(css, "max-w") {
		t.Fatal("hasSelector(\"max-w\") false-matched — the escape continuation (\\.max-w-\\[1400px\\]) must not be a boundary hit")
	}
	if !hasSelector(css, "max-w-[1400px]") {
		t.Fatal("hasSelector(\"max-w-[1400px]\") missed the real selector — the boundary is over-strict")
	}
}

// The templates' hand-written <style> blocks hardcode palette colors (the
// prose styles outside the utility classes). Every hex and rgb(a) triple
// they use must come from palette.json — the "single source of truth"
// claim binds them too (a palette edit without a template update leaves
// them stale, and no other test watches them).
func TestTemplateStyleHexesComeFromPalette(t *testing.T) {
	palBytes, err := os.ReadFile(filepath.Join("tailwind", "palette.json"))
	if err != nil {
		t.Fatalf("palette.json: %v", err)
	}
	palText := string(palBytes)
	palHexes := map[string]bool{}
	for _, h := range regexp.MustCompile(`#[0-9a-fA-F]{6}\b`).FindAllString(palText, -1) {
		palHexes[strings.ToLower(h)] = true
	}
	palTriples := map[string]bool{}
	for h := range palHexes {
		r, g, b := parseInt(h[1:3]), parseInt(h[3:5]), parseInt(h[5:7])
		palTriples[fmt.Sprintf("%d,%d,%d", r, g, b)] = true
		palTriples[fmt.Sprintf("%d %d %d", r, g, b)] = true
	}
	// The one deliberate non-palette literal: plain white (Tailwind's own
	// base, not a palette decision — allowlisted with this reason).
	const allowWhite = "255,255,255"
	for _, tmpl := range []string{"templates/overview.gohtml",
		"templates/report-reskin.gohtml"} {
		srcBytes, err := os.ReadFile(tmpl)
		if err != nil {
			t.Fatalf("read %s: %v", tmpl, err)
		}
		src := string(srcBytes)
		for _, m := range regexp.MustCompile(`(?s)<style>(.*?)</style>`).FindAllStringSubmatch(src, -1) {
			block := m[1]
			for _, h := range regexp.MustCompile(`#[0-9a-fA-F]{6}\b`).FindAllString(block, -1) {
				if !palHexes[strings.ToLower(h)] {
					t.Errorf("%s: style block hex %s is not a palette value — add it to palette.json (the single source of truth) or change the style to a utility class", tmpl, h)
				}
			}
			for _, m3 := range regexp.MustCompile(`rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)`).FindAllStringSubmatch(block, -1) {
				triple := fmt.Sprintf("%s,%s,%s", m3[1], m3[2], m3[3])
				if triple == allowWhite {
					continue
				}
				if !palTriples[triple] {
					t.Errorf("%s: style block rgb(%s,...) does not derive from any palette hex — the palette is the single source of truth", tmpl, triple)
				}
			}
		}
	}
}

func parseInt(s string) int {
	var n int
	fmt.Sscanf(s, "%x", &n)
	return n
}

// The cascade-order contract, asserted instead of prose: the vendor CSS
// block precedes the hand-written <style> in the RENDERED output, so the
// hand-written rules win at equal specificity — the DELIBERATE reversal of
// the Play-CDN order (the runtime injection appended at head-end, AFTER the
// hand-written, so the compiler used to win; the collision set was checked
// at the migration: the two layers set disjoint properties on the shared
// selectors, so the reversal changes no rendered rule).
func TestVendorCSSPrecedesTemplateStyles(t *testing.T) {
	for name, fn := range map[string]func(ReportData, *strings.Builder) error{
		"overview": func(d ReportData, b *strings.Builder) error { return RenderOverview(d, b) },
		"reskin":   func(d ReportData, b *strings.Builder) error { return RenderReskin(d, b) },
	} {
		var b strings.Builder
		if err := fn(ReportData{Title: "t"}, &b); err != nil {
			t.Fatalf("%s render: %v", name, err)
		}
		out := b.String()
		vendor := strings.Index(out, "tailwindcss v") // the report.css build banner
		hand := strings.Index(out, ".finding-ref")    // the first hand-written rule body
		if vendor < 0 || hand < 0 {
			t.Fatalf("%s: the vendor banner or the hand-written rules are missing from the render (vendor@%d hand@%d)", name, vendor, hand)
		}
		if vendor > hand {
			t.Fatalf("%s: the vendor CSS block (%d) renders AFTER the hand-written styles (%d) — the cascade order inverted; the hand-written rules would lose at equal specificity", name, vendor, hand)
		}
	}
}
