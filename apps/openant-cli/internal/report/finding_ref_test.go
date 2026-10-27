package report

import (
	"strings"
	"testing"
)

// TestFindingRefAnchorSurvivesSanitization — #711: the finding
// cross-reference contract, allowed end-to-end. The Python CLI linkifies
// the model's #N finding references into
// <a href="#finding-N" class="finding-ref">#N</a> and both templates
// render the matching id="finding-N" anchors on the finding <details>;
// until #711 this policy dropped the WHOLE anchor (no class attribute, no
// fragment href), leaving the .finding-ref rules dead and the operator
// reading plain text. The anchor must now survive — href AND class intact.
func TestFindingRefAnchorSurvivesSanitization(t *testing.T) {
	in := `<p>See <a href="#finding-4" class="finding-ref">#4</a> for details.</p>`
	out := string(ReportData{RemediationHTML: in}.SafeRemediation())
	if !strings.Contains(out, `href="#finding-4"`) {
		t.Fatalf("the finding-fragment href was stripped:\n IN : %s\n OUT: %s", in, out)
	}
	if !strings.Contains(out, `class="finding-ref"`) {
		t.Fatalf("the finding-ref class was stripped:\n IN : %s\n OUT: %s", in, out)
	}
	if !strings.Contains(out, ">#4</a>") {
		t.Fatalf("the anchor's text was altered:\n IN : %s\n OUT: %s", in, out)
	}
	// NOTE: RequireNoReferrerOnLinks adds rel="noreferrer" to every <a>,
	// including the same-document fragments — harmless for an in-document
	// navigation; disclosed here so the exact output shape is pinned.
	if !strings.Contains(out, `rel="noreferrer"`) {
		t.Fatalf("the referrer hardening disappeared from the links:\n OUT: %s", out)
	}
}

// TestFindingRefHostileHrefsAndClassesStillDie — the policy's widening is
// as narrow as the old surface: the class attribute accepts EXACTLY the
// finding-ref value, the href accepts the absolute http(s) links the
// policy always allowed plus the #finding-N fragments ONLY. Everything
// else — script URLs, foreign classes, non-fragment relative URLs,
// protocol-relative URLs, off-shaped fragments — dies.
func TestFindingRefHostileHrefsAndClassesStillDie(t *testing.T) {
	cases := []struct {
		name, in string
		mustNot  []string
	}{
		{"a javascript: href dies", `<a href="javascript:alert(1)" class="finding-ref">#4</a>`,
			[]string{"javascript:", `href="`}},
		{"a foreign class dies", `<a href="#finding-4" class="evil">#4</a>`,
			[]string{"class=\"evil\""}},
		{"a class with extra values dies", `<a href="#finding-4" class="finding-ref evil">#4</a>`,
			[]string{`class="finding-ref evil"`}},
		{"a relative non-fragment href dies", `<a href="page2.html">go</a>`,
			[]string{"href"}},
		{"a path-ascending href dies", `<a href="../x">go</a>`,
			[]string{"href"}},
		{"a protocol-relative href dies", `<a href="//evil.com/x">go</a>`,
			[]string{"href"}},
		{"an off-shaped fragment dies", `<a href="#finding-4evil" class="finding-ref">#4</a>`,
			[]string{`href="#finding-4evil"`}},
		{"a non-finding fragment dies", `<a href="#top">top</a>`,
			[]string{"href"}},
		{"an unknown scheme dies", `<a href="ftp://x/y">go</a>`,
			[]string{"href"}},
	}
	for _, c := range cases {
		out := string(ReportData{RemediationHTML: c.in}.SafeRemediation())
		for _, bad := range c.mustNot {
			if strings.Contains(out, bad) {
				t.Errorf("%s: %q survived:\n IN : %s\n OUT: %s", c.name, bad, c.in, out)
			}
		}
	}
}

// TestAbsoluteHttpLinksStillWork — the pre-#711 surface is unchanged: the
// absolute http(s) links survive with the referrer/target hardening.
// The r1-B1 regression set is pinned here too: the href pattern's http(s)
// half is deliberately PREFIX-shaped and case-insensitive so bluemonday's
// own validURL keeps tolerating exactly what it always did — uppercase
// schemes, whitespace-padded values, apostrophe/quote-bearing URLs (an
// earlier fully-anchored pattern here silently demoted all three to plain
// text).
func TestAbsoluteHttpLinksStillWork(t *testing.T) {
	in := `<p><a href="https://example.com/x">go</a></p>`
	out := string(ReportData{RemediationHTML: in}.SafeRemediation())
	if !strings.Contains(out, `href="https://example.com/x"`) {
		t.Fatalf("the absolute http link died:\n IN : %s\n OUT: %s", in, out)
	}
	if !strings.Contains(out, `rel="noreferrer noopener"`) || !strings.Contains(out, `target="_blank"`) {
		t.Fatalf("the fully-qualified link lost its hardening:\n OUT: %s", out)
	}

	// the r1-B1 regression corpus (every shape the pre-#711 policy accepted
	// via its value-less href rule + validURL's TrimSpace/url.Parse/escape):
	// each must STILL produce a working link, not plain text.
	oldTolerated := []struct{ name, href string }{
		{"an uppercase scheme", "HTTPS://EXAMPLE.COM/x"},
		{"a mixed-case scheme", "Https://example.com"},
		{"a whitespace-padded href", " https://example.com"},
		{"a trailing-space href", "https://example.com "},
		// the LITERAL forms (the r2-F2 catch: the percent-encoded spellings
		// pass even the regressed anchored pattern — inert pins; these are
		// the shapes the old policy's serializer survives — the apostrophe
		// entity-escaped, the quote and backtick percent-encoded — and the
		// r3-F3 note: the quote pin uses the &quot; form because a literal
		// " inside this test's double-quoted attribute wrapper truncates
		// the value at the HTML tokenizer (the pin never reached the
		// pattern — verified inert under the anchored mutant)
		{"an apostrophe-bearing URL", "https://en.wikipedia.org/wiki/Rock_'n'_Roll"},
		{"a quote-bearing URL", "https://example.com/a&quot;b"},
		{"a backtick-bearing URL", "https://example.com/`x`"},
		{"a unicode-whitespace-led href", "\u00a0https://example.com"},
	}
	for _, c := range oldTolerated {
		in := `<a href="` + c.href + `">t</a>`
		out := string(ReportData{RemediationHTML: in}.SafeRemediation())
		if !strings.Contains(out, "href=") {
			t.Errorf("%s was demoted to plain text (the r1-B1 regression):\n IN : %s\n OUT: %s", c.name, in, out)
		}
	}
}

// The falsifier's end-to-end form — "a rendered HTML report whose
// remediation section contains a working link to a finding anchor" — is
// the composition of the three pins above: the sanitized anchor survives
// with href AND class (TestFindingRefAnchorSurvivesSanitization), the
// hostile shapes die (TestFindingRefHostileHrefsAndClassesStillDie), and
// the href's target exists in both rendered templates
// (TestTemplatesRenderTheFindingAnchors).

// TestTemplatesRenderTheFindingAnchors — the href's TARGET exists: both
// templates render id="finding-N" on the finding <details>. If a template
// drops that id, the link renders but lands nowhere — the falsifier's
// "working link" breaks. Pinned by reading the template sources (the
// templates are embedded; the render harness covers the shape, this pins
// the anchor ids exist for the verdict-grouped findings in BOTH).
func TestTemplatesRenderTheFindingAnchors(t *testing.T) {
	sources := []struct {
		name, src string
		wantSites int
	}{
		{"templates/overview.gohtml", mustRead(t, templateFS, "templates/overview.gohtml"), 1},
		// the reskin renders TWO finding paths (the verdict-grouped
		// <details> and the flat list) — BOTH must carry the anchor id
		// (the r1-N1 catch: a Contains check let either silently drop)
		{"templates/report-reskin.gohtml", mustRead(t, reskinFS, "templates/report-reskin.gohtml"), 2},
	}
	for _, s := range sources {
		if got := strings.Count(s.src, `id="finding-{{$f.Number}}"`); got != s.wantSites {
			t.Errorf("%s carries %d finding anchor ids, want %d — a dropped site leaves the remediation links landing nowhere",
				s.name, got, s.wantSites)
		}
	}
}

func mustRead(t *testing.T, fsys interface {
	ReadFile(name string) ([]byte, error)
}, name string) string {
	t.Helper()
	b, err := fsys.ReadFile(name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(b)
}
