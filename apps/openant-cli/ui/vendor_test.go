package ui

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
)

// #577: the vendored ui scripts carry the #332 discipline (the ui variant).
// Provenance lives in vendor/SOURCES.txt; the sha256 lock is ENFORCED here;
// the renovate notifier reaches this surface through the version-carrying
// file names — the #577 customManagers in renovate.json track the names in
// the REFERENCE files (the go:embed list in embed.go, the /assets script
// tags in summary.html + disclosure.html, the handleAsset case list in
// server.go, and this table), because **/vendor/** is renovate-ignored by
// the :ignoreModulesAndTests preset and the standard ignores are
// deliberately not overridden.
//
// DOMPurify is the SOLE XSS sanitizer for the untrusted-markdown render
// path (both pages render attacker-influenced markdown through
// marked.parse → DOMPurify.sanitize → innerHTML, and no CSP backstop
// exists — recorded as the #577 limitation in vendor/SOURCES.txt). The
// vendored bytes are therefore integrity-critical: an upgrade is the full
// recipe in ONE commit — the blob, this table's shas, vendor/SOURCES.txt,
// the go:embed list, the handleAsset case list, and both pages' script
// tags.

// uiVendorScripts is the ordered pin table. Order = script load order in
// the pages (marked loads before the inline render script runs; DOMPurify
// before the sanitize calls). banner is the upstream version-marker
// prefix; the expected version is DERIVED from the file name so a bump
// edits the name once, never a second hardcoded copy of the version.
var uiVendorScripts = []struct {
	name   string
	sha256 string
	banner string
}{
	{"marked-18.0.12.min.js", "fa0cfbf0181339312eaa3709b577ad698fc21a9baa42d580a3fd1f267b19b4a8", "marked v"},
	{"dompurify-3.4.15.min.js", "f263b05369e050fa175d4ecb9c9358eb4253602d510297adfb31df48b2f1c4d5", "DOMPurify "},
}

const uiVendorMinBytes = 10_000

// uiVersionSuffix: every vendored script must END in its version so the
// notifier can see it — the pre-#577 versionless names were structurally
// invisible (the exact gap this issue exists to close).
var uiVersionSuffix = regexp.MustCompile(`-([0-9]+\.[0-9]+\.[0-9]+)\.min\.js$`)

// readPage reads an embedded PAGE with CRLF normalized away. Text files
// convert on Windows checkouts (the same autocrlf hazard .gitattributes
// records for the vendor blobs — no *.html rule protects the pages) and
// go:embed embeds the converted bytes, so newline-sensitive pins must
// survive CRLF. (Vendored BLOB reads are deliberately NOT normalized —
// their bytes are sha-pinned raw.)
func readPage(t *testing.T, name string) string {
	t.Helper()
	data, err := FS.ReadFile(name)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return strings.ReplaceAll(string(data), "\r\n", "\n")
}

// The vendored bytes are pinned: sha256 recorded in vendor/SOURCES.txt for
// the reviewable two-line diff, ENFORCED here so in-git tampering and
// accidental re-vendors are detectable.
func TestVendoredUIScriptHashes(t *testing.T) {
	for _, s := range uiVendorScripts {
		data, err := FS.ReadFile("vendor/" + s.name)
		if err != nil {
			t.Fatalf("vendored script %s missing from the embed: %v", s.name, err)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != s.sha256 {
			t.Fatalf("%s sha256 mismatch: got %s want %s — the blob changed (upgrade? tampering? update vendor/SOURCES.txt + this table deliberately, in one commit)", s.name, got, s.sha256)
		}
		if len(data) < uiVendorMinBytes {
			t.Fatalf("vendored script %s suspiciously small (%d bytes) — a stub would silently strip the parser/sanitizer from the pages", s.name, len(data))
		}
	}
}

// The file name and the embedded version banner must agree — a mislabeled
// re-vendor (new name, old bytes) is exactly what the version-carrying
// rename must never allow.
func TestUIVendorBannersMatchFileNames(t *testing.T) {
	for _, s := range uiVendorScripts {
		m := uiVersionSuffix.FindStringSubmatch(s.name)
		if m == nil {
			t.Fatalf("%s: vendored script names must end in -<semver>.min.js (the notifier reads the version from the name)", s.name)
		}
		data, err := FS.ReadFile("vendor/" + s.name)
		if err != nil {
			t.Fatalf("vendored script %s missing from the embed: %v", s.name, err)
		}
		want := s.banner + m[1]
		if !strings.Contains(string(data), want) {
			t.Fatalf("%s: version banner %q not found in the blob — the file name and the embedded version disagree", s.name, want)
		}
	}
}

// The vendor-dir invariants: every script on disk AND in the embed is
// versioned and pinned, and the two sets are EQUAL. The disk walk is
// load-bearing: embed.go embeds an explicit file list, so a
// copy-instead-of-rename leftover on disk would be invisible to an
// embed-only walk — and would silently come back the next time someone
// "fixes" the embed list. SOURCES.txt is the one permitted non-script
// artifact (the provenance record).
func TestUIVendorDirVersionedAndPinned(t *testing.T) {
	checkEntry := func(name string) {
		if name == "SOURCES.txt" {
			return
		}
		if !strings.HasSuffix(name, ".js") {
			t.Errorf("vendor dir holds an unexpected artifact %q (only <name>-<semver>.min.js scripts + SOURCES.txt)", name)
			return
		}
		if uiVersionSuffix.FindStringSubmatch(name) == nil {
			t.Errorf("vendored script %q carries no version in its name — structurally invisible to the renovate notifier (the #577 gap)", name)
		}
		pinned := false
		for _, s := range uiVendorScripts {
			if s.name == name {
				pinned = true
				break
			}
		}
		if !pinned {
			t.Errorf("vendored script %q is not in the uiVendorScripts pin table — unpinned bytes are the pre-#577 state", name)
		}
	}

	embedSet := map[string]bool{}
	err := fs.WalkDir(FS, "vendor", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := path.Base(p)
		embedSet[name] = true
		checkEntry(name)
		return nil
	})
	if err != nil {
		t.Fatalf("walking the embedded vendor dir: %v", err)
	}
	if embedSet["SOURCES.txt"] {
		t.Error("the provenance record is EMBEDDED — it is not a runtime asset; remove it from the go:embed list")
	}

	entries, err := os.ReadDir("vendor") // in-package: cwd IS the ui package dir
	if err != nil {
		t.Fatalf("reading the on-disk vendor dir: %v", err)
	}
	diskSet := map[string]bool{}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue // editor/OS noise, never repo content (go:embed excludes dotfiles too)
		}
		if e.IsDir() {
			t.Errorf("vendor dir holds a subdirectory %q", e.Name())
			continue
		}
		diskSet[e.Name()] = true
		checkEntry(e.Name())
	}

	for name := range embedSet {
		if !diskSet[name] {
			t.Errorf("embedded %q has no on-disk counterpart — the embed and the tree disagree", name)
		}
	}
	for name := range diskSet {
		if name == "SOURCES.txt" {
			continue // the provenance record lives on disk; it is not a runtime asset and is not embedded
		}
		if !embedSet[name] {
			t.Errorf("on-disk %q is not embedded — the blob ships nowhere (or the go:embed list missed the rename)", name)
		}
	}
}

// Quote- and case-agnostic: HTML is case-insensitive and attributes may be
// single-quoted, unquoted, or carry whitespace — a src-only double-quoted
// regex is evaded by `<script SRC='x'>`, `<script src = "x">`, and
// `<SCRIPT SRC=x>`.
var uiAnyScriptSrc = regexp.MustCompile(`(?i)<script\b[^>]*\bsrc\s*=\s*["']?([^"'\s>]+)`)

var uiHttpsImport = regexp.MustCompile(`(?i)(import\s*\(?\s*["']https?://|from\s+["']https?://)`)

// No embedded page may load ANY script beyond the vendored set — any
// origin, any tag form, on any of the four embedded pages — and no page
// may open an external-dependency channel the src-tag guard cannot see
// (module scripts, https imports).
func TestUIPagesLoadNoExternalScripts(t *testing.T) {
	vendored := map[string]bool{}
	for _, s := range uiVendorScripts {
		vendored[s.name] = true
	}
	for _, page := range []string{"index.html", "scan.html", "summary.html", "disclosure.html"} {
		s := readPage(t, page)
		var srcTags []string
		for _, m := range uiAnyScriptSrc.FindAllStringSubmatch(s, -1) {
			src := m[1]
			if !strings.HasPrefix(src, "/assets/") || !vendored[strings.TrimPrefix(src, "/assets/")] {
				t.Fatalf("%s: script src %q — only the vendored /assets scripts are permitted (external origin or unknown vendor name)", page, src)
			}
			srcTags = append(srcTags, src)
		}
		if regexp.MustCompile(`(?i)\btype\s*=\s*["']?module\b`).MatchString(s) {
			t.Fatalf("%s: a module script is out of policy for the embedded pages (an import would be an external dependency the src guard cannot see)", page)
		}
		if uiHttpsImport.MatchString(s) {
			t.Fatalf("%s: an https import — an external dependency outside the vendored set", page)
		}
		// Non-script external-dependency channels (the report suite's own
		// lesson: a fonts.googleapis.com link survived a "vendored" claim):
		// stylesheets, preloads, CSS imports, and script-initiated http fetches.
		low := strings.ToLower(s)
		for _, bad := range []string{"<link", "@import"} {
			pat := regexp.MustCompile(`(?s)` + strings.ToLower(bad) + `[^>]*?(https?://|href=["']?http)`)
			if m := pat.FindString(low); m != "" {
				t.Fatalf("%s: external stylesheet/import reference %q — the pages must be self-contained", page, m)
			}
		}
		if regexp.MustCompile(`fetch\s*\(\s*["']https?://`).MatchString(low) {
			t.Fatalf("%s: a cross-origin fetch — an external dependency outside the vendored set", page)
		}
		// Total scheme-literal ban: the pages are self-contained; any
		// scheme-carrying literal (http(s), ws(s), ftp) beyond the
		// allowlisted placeholder is an external reference by SOME channel
		// (img src, XHR, WebSocket, Worker, sendBeacon...), and
		// protocol-relative references (`href=//host/...`) evade the scheme
		// prefix entirely — both the literal and the relative form are
		// banned. (An inert documentation hyperlink would also trip this —
		// a deliberate fail-loud choice: the pages have no docs links
		// today and adding one is a visible, reviewable change.)
		for _, m := range regexp.MustCompile(`(?i)\b(?:https?|wss?|ftp)://[^\s"'<>)]*`).FindAllString(low, -1) {
			if m != "https://github.com/org/repo" { // the scan-form placeholder in index.html
				t.Fatalf("%s: external URL literal %q — the pages must be self-contained (any channel)", page, m)
			}
		}
		// The attribute forms require their `=`, the CSS form its `(` — a
		// looser shape false-fires on the prose word "URL" before a JS
		// comment line. And ANY quoted "//host" string literal is banned
		// outright: it closes the JS-call shapes (fetch('//h'),
		// WebSocket, import), srcset, and @import — string literals the
		// pages never legitimately contain.
		if m := regexp.MustCompile(`(?i)(src|href|action)\s*=\s*["']?//|url\(\s*["']?//`).FindString(low); m != "" {
			t.Fatalf("%s: protocol-relative reference %q — the scheme-less form evades the literal ban", page, m)
		}
		if m := regexp.MustCompile(`["'\x60](?:\\?/){2}[a-z0-9.-]`).FindString(low); m != "" {
			t.Fatalf("%s: a quoted protocol-relative string literal %q — the scheme-less form inside any JS call, srcset, or @import evades the named guards (backticked and backslash-escaped spellings included)", page, m)
		}
		// The script-tag INVENTORY: every <script open in the page must be
		// accounted for as a vendored src tag, a NONCED inline open (the CSP
		// shape — #578 follow-up A: a bare <script> open is out of policy),
		// or (not yet present anywhere) an attribute-bearing open. This
		// closes the regex's documented boundary — an attribute value
		// containing '>' (e.g. data-x="a>b") can hide a tag from the src
		// regex, but not from the count.
		totalOpens := strings.Count(low, "<script")
		noncedOpens := strings.Count(low, `<script nonce=`)
		bareOpens := strings.Count(low, "<script>")
		if bareOpens != 0 {
			t.Fatalf("%s: %d bare <script> opens — the CSP policy requires every inline script to carry a nonce", page, bareOpens)
		}
		if totalOpens != len(srcTags)+noncedOpens {
			t.Fatalf("%s: %d <script opens but only %d src tags + %d nonced inline opens accounted — an unaccounted tag form (e.g. an attribute value containing '>') is present", page, totalOpens, len(srcTags), noncedOpens)
		}
	}
}

// The markdown pages must reference exactly the vendored script set,
// versioned, in load order, AND loaded BEFORE the inline script that
// consumes them: a "tags moved after the consumer" mutation preserves
// relative order while breaking rendering, so the position is pinned
// alongside the order.
func TestUIHTMLScriptsVersionedAndOrdered(t *testing.T) {
	var want []string
	for _, s := range uiVendorScripts {
		want = append(want, s.name)
	}
	for _, page := range []string{"summary.html", "disclosure.html"} {
		s := readPage(t, page)
		var got []string
		lastEnd := -1
		for _, m := range uiAnyScriptSrc.FindAllStringSubmatchIndex(s, -1) {
			src := s[m[2]:m[3]]
			got = append(got, strings.TrimPrefix(src, "/assets/"))
			lastEnd = m[1] // the whole-match end — never the capture-group end (a tag shape change would silently mis-position the pin)
		}
		if len(got) != len(want) {
			t.Fatalf("%s: script tags %v, want exactly the vendored set %v (an extra or missing vendor script)", page, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s: script tag %d = %q, want %q (versioned names + load order are pinned)", page, i+1, got[i], want[i])
			}
			if _, err := FS.ReadFile("vendor/" + got[i]); err != nil {
				t.Fatalf("%s: script tag references %q which is not in the embed: %v", page, got[i], err)
			}
		}
		// The consumer anchor is the FIRST inline <script> open — the
		// earliest executing consumer. A vendor tag inserted inside the
		// consumer body, or an inline script placed before the vendor tags,
		// both break this; the MD_SANITIZE index is the fallback anchor if
		// the open-tag shape ever changes.
		consumer := strings.Index(s, "<script>")
		if fb := strings.Index(s, "const MD_SANITIZE = {"); fb >= 0 && (consumer < 0 || fb < consumer) {
			consumer = fb
		}
		if consumer < 0 || lastEnd > consumer {
			t.Fatalf("%s: the vendored scripts end at byte %d but the consuming inline script starts at %d — marked/DOMPurify would be undefined when the consumer runs", page, lastEnd, consumer)
		}
	}
}

// The human-facing provenance record must agree with the ENFORCED pins: a
// stale sha left in vendor/SOURCES.txt after a sloppy bump would make the
// "reviewable two-line diff" a lie, and a missing entry makes the record
// incomplete.
func TestVendorSourcesTxtMatchesPinTable(t *testing.T) {
	raw, err := os.ReadFile("vendor/SOURCES.txt") // in-package: cwd IS the ui dir
	if err != nil {
		t.Fatalf("reading vendor/SOURCES.txt: %v", err)
	}
	sources := string(raw)
	// Each script's sha must appear within ITS OWN section (a name-check and
	// a sha-check anywhere in the file would pass a SWAPPED record).
	sectionFor := func(name string) string {
		i := strings.Index(sources, "# "+name)
		if i < 0 {
			return ""
		}
		rest := sources[i:]
		if j := regexp.MustCompile(`\n# [^ ]`).FindStringIndex(rest[1:]); j != nil {
			rest = rest[:1+j[0]]
		}
		return rest
	}
	pinned := map[string]bool{}
	for _, s := range uiVendorScripts {
		pinned[s.sha256] = true
		sec := sectionFor(s.name)
		if sec == "" {
			t.Errorf("vendor/SOURCES.txt has no section for %q — the provenance record is incomplete", s.name)
			continue
		}
		if !strings.Contains(sec, "sha256: "+s.sha256) {
			t.Errorf("vendor/SOURCES.txt: %s's section does not record its pinned sha256 — the reviewable record diverged (or the shas were swapped)", s.name)
		}
	}
	for _, m := range regexp.MustCompile(`sha256: ([0-9a-f]{64})`).FindAllStringSubmatch(sources, -1) {
		if !pinned[m[1]] {
			t.Errorf("vendor/SOURCES.txt records sha256 %s which no pin table entry enforces — a stale record (left over from a previous version?)", m[1])
		}
	}
}

// The sanitizer policy is the XSS boundary. Pin the MD_SANITIZE block
// cross-template (byte-equal), pin its inert FORBID floor, and pin its
// USE — a preserved-but-bypassed config block would silently decouple the
// pages from the sanitizer contract. Each page carries exactly ONE
// innerHTML sink (the primary render), pinned by count below.
func TestMDSanitizeConfigPinnedAndUsed(t *testing.T) {
	extract := func(page string) string {
		s := readPage(t, page)
		const def = "const MD_SANITIZE = {"
		i := strings.Index(s, def)
		if i < 0 {
			t.Fatalf("%s: the MD_SANITIZE definition is gone — the sanitizer policy block is load-bearing", page)
		}
		j := strings.Index(s[i:], "};")
		if j < 0 {
			t.Fatalf("%s: MD_SANITIZE block unterminated", page)
		}
		return s[i : i+j+2]
	}

	a, b := extract("summary.html"), extract("disclosure.html")
	if a != b {
		t.Fatalf("MD_SANITIZE diverged between the pages (one page silently weaker than the other is the classic drift):\nsummary.html:\n%s\ndisclosure.html:\n%s", a, b)
	}

	// THE GOLDEN BLOCK — the total form. Byte-equality against the pinned
	// policy closes every value-level and FORM-level mutation at once:
	// shorthand properties (ADD_ATTR,) and spread (...x,) carry neither a
	// colon nor a paren; colon-less method/getter keys carry no colon; any
	// added/removed/reordered key or list entry is a byte-diff. A
	// deliberate policy change updates the pages AND this golden together,
	// in one commit — the same two-place recipe as the sha pins. The named
	// floor/ceiling/key pins below stay as the diagnostic layer: they name
	// WHICH invariant moved when the golden is updated deliberately.
	const goldenMDSanitize = `const MD_SANITIZE = {
  ALLOWED_TAGS: ['h1','h2','h3','h4','h5','h6','p','br','hr','blockquote',
    'ul','ol','li','pre','code','em','strong','del','a','span','div',
    'table','thead','tbody','tr','th','td','sup','sub','kbd'],
  ALLOWED_ATTR: ['href','title','class','align','colspan','rowspan','target','rel'],
  FORBID_TAGS: ['style','form','input','button','textarea','select','option',
    'img','picture','source','svg','math','iframe','object','embed','link','base','meta','script'],
  FORBID_ATTR: ['style','src','srcset','action','formaction','background','poster','loading'],
  ALLOW_DATA_ATTR: false
};`
	if a != goldenMDSanitize {
		t.Fatalf("MD_SANITIZE is not byte-identical to the pinned golden policy — a value or FORM change (shorthand property, spread, colon-less key, added key) drifted; a deliberate change updates the pages and the golden together in one commit")
	}

	// The inert floor, asserted within FORBID_TAGS specifically (a tag
	// MOVED to the allowlist would otherwise still satisfy a whole-block
	// Contains). These are the beacon/defacement/phishing-vector classes
	// the block's own comment names; dropping any is a policy decision.
	fi := strings.Index(a, "FORBID_TAGS:")
	if fi < 0 {
		t.Fatal("MD_SANITIZE: FORBID_TAGS not found")
	}
	fend := strings.Index(a[fi:], "]")
	if fend < 0 {
		t.Fatal("MD_SANITIZE: FORBID_TAGS list unterminated")
	}
	forbid := a[fi : fi+fend]
	for _, tag := range []string{"style", "form", "input", "button", "textarea", "select", "option",
		"img", "picture", "source", "svg", "math", "iframe", "object", "embed", "link", "base", "meta", "script"} {
		if !strings.Contains(forbid, "'"+tag+"'") {
			t.Fatalf("MD_SANITIZE FORBID_TAGS lost %q — the inert allowlist floor was weakened", tag)
		}
	}

	// The policy KEY SET. DOMPurify merges ADD_TAGS/ADD_ATTR into the allow
	// sets and honours ALLOWED_URI_REGEXP/ADD_URI_SAFE_ATTR — keys outside
	// the five below can reopen channels none of the value-level pins see
	// (ADD_TAGS: ['script'] passes every other assertion in this test).
	// Extending the key set is a deliberate policy decision that must
	// update this allowlist.
	policyKeys := map[string]bool{
		"ALLOWED_TAGS": true, "ALLOWED_ATTR": true,
		"FORBID_TAGS": true, "FORBID_ATTR": true,
		"ALLOW_DATA_ATTR": true,
	}
	// The key match tolerates the quoted/whitespace/backtick JS spellings
	// of a key (`ADD_TAGS :`, `'ADD_TAGS':`, `["ADD_TAGS"]:`,
	// `[`+"`"+`ADD_TAGS`+"`"+`]:`) — a bare-identifier regex is evaded by
	// all four. The colon-LESS forms (method shorthand `ADD_TAGS(){…}`,
	// getters, computed keys) carry no colon at all — they are refused by
	// the exact-count + the paren ban below. Mutations AFTER the block are
	// refused by the identifier count in TestMDSanitizeConfigPinnedAndUsed.
	keyMatches := regexp.MustCompile("[\"'\\[\\x60]*([A-Z][A-Z_]+)[\"'\\]\\x60]*\\s*:").FindAllStringSubmatch(a, -1)
	if len(keyMatches) != len(policyKeys) {
		t.Fatalf("MD_SANITIZE carries %d key-colon matches, want exactly the pinned %d — a key was added, removed, or spelled colon-less (method shorthand/getters are refused by the paren ban)", len(keyMatches), len(policyKeys))
	}
	if strings.Count(a, "(") != 0 || strings.Count(a, ")") != 0 {
		t.Fatalf("MD_SANITIZE contains parentheses — the policy block is a plain object literal; a method shorthand (ADD_TAGS(){...} carries no colon and would be honoured by the sanitizer) is present")
	}
	for _, m := range keyMatches {
		if !policyKeys[m[1]] {
			t.Fatalf("MD_SANITIZE gained the policy key %q — keys outside the pinned five can reopen channels the value-level pins never see; extend policyKeys deliberately if this is intended", m[1])
		}
	}
	// Post-block mutation refusal — by IDENTIFIER COUNT, not spelling: any
	// aliasing/bracket/defineProperty/reassignment mutation must mention
	// the identifier one more time than the legitimate uses. A denylist of
	// spellings is evaded; a count is not.
	for _, page := range []string{"summary.html", "disclosure.html"} {
		ps := readPage(t, page)
		wantCount := map[string]int{"summary.html": 2, "disclosure.html": 2}[page]
		if got := strings.Count(ps, "MD_SANITIZE"); got != wantCount {
			t.Fatalf("%s: MD_SANITIZE appears %d times, want exactly %d — a post-block mutation (aliasing, bracket spelling, defineProperty, Object.assign) bypasses every pin on the block itself", page, got, wantCount)
		}
		// Same principle for DOMPurify, but the count is CODE-ONLY (line
		// comments stripped first): a prose mention ("DOMPurify's" in the
		// explanatory comment) is fungible — rewording the comment to free a
		// mention for a setConfig call would otherwise hold the count. The
		// legitimate code mentions are exactly the sanitize call sites
		// (summary: 1; disclosure: 1).
		codeOnly := regexp.MustCompile(`//[^\n]*`).ReplaceAllString(ps, "")
		wantDP := map[string]int{"summary.html": 1, "disclosure.html": 1}[page]
		if got := strings.Count(codeOnly, "DOMPurify"); got != wantDP {
			t.Fatalf("%s: DOMPurify appears %d times in code, want exactly %d — a reassignment (DOMPurify.sanitize=s=>s kills the sink while the pinned invocation string survives), an alias, or a config-API call in any spelling (setConfig deadens the per-call argument — the vendored blob: Ae?(ae=Ee,ce=we):rn(e); clearConfig resets the shared state; addHook re-allows) adds a code mention", page, got, wantDP)
		}
		// Prototype pollution needs NEITHER identifier. The vendored 3.4.15
		// clones configs onto Object.create(null) and reads own properties
		// only, so this is DEFENSE-IN-DEPTH (an upstream config-reader
		// change, typo-class writes), not a currently-live vector.
		for _, bad := range []string{"prototype", "__proto__"} {
			if strings.Contains(ps, bad) {
				t.Fatalf("%s: %q present — prototype writes are out of policy for the pages (defense-in-depth: the sanitizer's config plumbing must stay untouched from outside the pinned block)", page, bad)
			}
		}
	}

	// The ALLOW CEILING. In DOMPurify FORBID beats ALLOW (the element gate
	// short-circuits on the forbid check), so every floor-listed tag is
	// doubly covered; the ceiling below remains load-bearing for what no
	// floor covers — attributes (an on*-handler or URL-style attribute in
	// ALLOWED_ATTR is not undone by the FORBID_ATTR floor's list) — and as
	// belt-and-braces for tags. A legitimate future allowlist ADDITION
	// still passes; the never-allowed set must never appear.
	ai := strings.Index(a, "ALLOWED_TAGS:")
	if ai < 0 {
		t.Fatal("MD_SANITIZE: ALLOWED_TAGS not found")
	}
	aend := strings.Index(a[ai:], "]")
	if aend < 0 {
		t.Fatal("MD_SANITIZE: ALLOWED_TAGS list unterminated")
	}
	allowedTags := a[ai : ai+aend]
	for _, tag := range []string{"script", "iframe", "img", "form", "style", "svg", "math",
		"object", "embed", "link", "base", "meta", "input", "button", "textarea", "select", "option", "picture", "source"} {
		if strings.Contains(allowedTags, "'"+tag+"'") {
			t.Fatalf("MD_SANITIZE ALLOWED_TAGS gained %q — the allow ceiling was broken (the FORBID floor does not undo an explicit allow)", tag)
		}
	}
	oi := strings.Index(a, "ALLOWED_ATTR:")
	if oi < 0 {
		t.Fatal("MD_SANITIZE: ALLOWED_ATTR not found")
	}
	oend := strings.Index(a[oi:], "]")
	if oend < 0 {
		t.Fatal("MD_SANITIZE: ALLOWED_ATTR list unterminated")
	}
	allowedAttrs := a[oi : oi+oend]
	// Bare-name contains within the list segment: quote-agnostic (a
	// double-quoted or backticked "onclick" evades single-quote matching;
	// the bare name cannot — and the banned family names are distinctive).
	for _, attr := range []string{"src", "srcset", "style", "action", "formaction"} {
		if strings.Contains(allowedAttrs, attr) {
			t.Fatalf("MD_SANITIZE ALLOWED_ATTR gained %q — URL/style attrs in the allow ceiling break the boundary", attr)
		}
	}
	for _, m := range regexp.MustCompile(`on[a-z]+`).FindAllString(allowedAttrs, -1) {
		t.Fatalf("MD_SANITIZE ALLOWED_ATTR gained the event handler %q", m)
	}
	// ALLOW_DATA_ATTR is the one policy key with no structural pin — flip it
	// to true on both pages and every other assertion survives. Pin it.
	if !strings.Contains(a, "ALLOW_DATA_ATTR: false") {
		t.Fatal("MD_SANITIZE: ALLOW_DATA_ATTR must stay false (data-* attributes are an arbitrary-attribute channel)")
	}

	for _, page := range []string{"summary.html", "disclosure.html"} {
		s := readPage(t, page)
		if !strings.Contains(s, "DOMPurify.sanitize(marked.parse(markdown), MD_SANITIZE)") {
			t.Fatalf("%s: the primary sanitize invocation is gone — the policy block exists but the render path bypassed it", page)
		}
		// The single-sink pin: exactly ONE innerHTML write per page (the
		// primary sanitized render). The #578 cleanup round removed
		// disclosure.html's repository-URL rewrite — a regex-on-innerHTML
		// second sink that never matched its own target (the
		// **Repository:** line is the SUMMARY prompt's, prompts/summary.txt;
		// marked renders it as <strong> + a native GFM autolink before the
		// regex ever ran) and misfired only inside code spans. Any second
		// innerHTML write must re-open this pin deliberately.
		if got := strings.Count(s, "innerHTML"); got != 1 {
			t.Fatalf("%s: %d innerHTML writes, want exactly 1 (the primary sanitized render) — a second innerHTML sink must be re-justified and re-pinned deliberately", page, got)
		}
	}
}
