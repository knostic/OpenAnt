package server

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	uifiles "github.com/knostic/open-ant-cli/ui"
)

// TestMarkdownJSONScriptBreakout pins the script-block boundary of the
// markdown data channel (#578 follow-up 1b). The summary/disclosure pages
// embed the markdown as `const markdown = {{.MarkdownJSON}};` inside an
// inline <script> — template.JS is NOT re-escaped by html/template, so the
// only defense is json.Marshal's default HTML escaping (< > & become
// \u003c \u003e \u0026, so a `</script>` in the payload cannot terminate
// the element). A refactor to a different marshaler (or SetEscapeHTML(false))
// would silently reopen page truncation/self-DoS — this test fails RED that
// day. The CSP nonce policy (execution blocked) mitigates but does not
// prevent the truncation class; this pin is the boundary itself.
func TestMarkdownJSONScriptBreakout(t *testing.T) {
	tmplSum, err := template.ParseFS(uifiles.FS, "summary.html")
	if err != nil {
		t.Fatalf("parse summary.html: %v", err)
	}
	tmplDisclosure, err := template.ParseFS(uifiles.FS, "disclosure.html")
	if err != nil {
		t.Fatalf("parse disclosure.html: %v", err)
	}
	outDir := t.TempDir()
	s := &Server{
		outDir: outDir, mgr: newManager(t.TempDir()), csrfToken: "tok",
		sem: make(chan struct{}, 4), shutdownDone: make(chan struct{}),
		tmplSum:        tmplSum,
		tmplDisclosure: tmplDisclosure,
	}
	h := s.Handler()

	// The hostile payload: every shape that could terminate or hijack the
	// script element, plus the JSON/JS punctuation that could close the
	// const early.
	hostile := "</script><script>alert(1)</script>\n" +
		"</ScRiPt >\n" +
		"<!-- <script> --> <!--\n" +
		"-->\n" +
		"\u2028\u2029\n" +
		"\"; evil(); '\n" +
		"\\u003c/script\\u003e\n" +
		"</script"
	sumPath := filepath.Join(outDir, "jx", "SUMMARY_REPORT.md")
	j := &Job{ID: "jx", Repo: "https://example.com/o/r", Status: "done",
		SummaryPath: sumPath, done: make(chan struct{})}
	s.mgr.add(j)
	if err := writeOut(t, sumPath, hostile); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// The disclosure channel is an INDEPENDENT marshal call site
	// (handleDisclosure) feeding disclosure.html's const markdown — both
	// channels carry the pin (a drift in either marshal alone goes RED).
	discPath := filepath.Join(outDir, "jx", "d.md")
	if err := writeOut(t, discPath, hostile); err != nil {
		t.Fatalf("seed disclosure: %v", err)
	}
	j.DisclosurePaths = []string{discPath}

	for _, path := range []string{"/summary/jx", "/disclosure/jx/d.md"} {
		body := renderBody(t, h, path)
		assertChannelIntact(t, path, body, hostile)
	}
}

func renderBody(t *testing.T, h http.Handler, path string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "localhost:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d", path, rec.Code)
	}
	return rec.Body.String()
}

func assertChannelIntact(t *testing.T, path, body, hostile string) {
	t.Helper()

	// (1) The emitted literal round-trips: extract `const markdown = …;`
	// and json.Unmarshal back to the exact input (fable's oracle — strictly
	// stronger than an escape-string grep).
	// The literal ends with `";` at the end of ITS line (the page's own
	// `const markdown = …;` statement) — a payload's escaped `\"` cannot
	// terminate the match, and the payload's own content cannot contain a
	// raw newline-in-source that closes the line (json.Marshal escapes
	// \n as the two characters backslash-n).
	// Windows checkouts: the templates carry CRLF (no -text rule covers
	// *.html), so the terminator may be ";\r\n — tolerate the CR.
	m := regexp.MustCompile(`(?s)const markdown = ("[^\n]*");\r?\n`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("%s: the const markdown literal was not found in the rendered page", path)
	}
	var got string
	if err := json.Unmarshal([]byte(m[1]), &got); err != nil {
		t.Fatalf("%s: the markdown literal is not valid JSON (a truncation/breakout likely fired): %v", path, err)
	}
	if got != hostile {
		t.Fatalf("%s: the markdown literal does not round-trip: got %q want %q", path, got, hostile)
	}
	// (2) No un-escaped case-insensitive </script sequence outside the
	// literal: HTML tag names are case-insensitive — the count must hold
	// case-insensitively (each real open closes exactly once); a breakout
	// via ANY casing adds an extra occurrence.
	low := strings.ToLower(body)
	opens := strings.Count(low, "<script")
	closes := strings.Count(low, "</script")
	if closes != opens {
		t.Fatalf("%s: script-tag balance broken: %d opens vs %d closes — a payload-borne </script> (any casing) reached the document (page truncation/self-DoS)", path, opens, closes)
	}
}

func writeOut(t *testing.T, path, content string) error {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}
