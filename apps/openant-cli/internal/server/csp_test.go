package server

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	uifiles "github.com/knostic/open-ant-cli/ui"
)

// #578 follow-up A: the CSP contract. The four UI pages carry a per-response
// nonce (header == every inline script/style tag); /report/{id} carries the
// no-network policy; /assets carries none (not a document).
func TestCSPPoliciesPerRoute(t *testing.T) {
	// The templates are parsed from the ui embed (same as New()) — a
	// zero-value Server has nil templates and handleIndex would nil-panic.
	tmplIndex, err := template.ParseFS(uifiles.FS, "index.html")
	if err != nil {
		t.Fatalf("parse index.html: %v", err)
	}
	s := &Server{
		outDir:       t.TempDir(),
		mgr:          newManager(t.TempDir()),
		csrfToken:    "tok",
		sem:          make(chan struct{}, 4),
		shutdownDone: make(chan struct{}),
		tmplIndex:    tmplIndex,
	}
	h := s.Handler()
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "localhost:8080" // the rebinding guard 403s non-loopback Hosts
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	t.Run("index carries the nonce policy", func(t *testing.T) {
		rec := get("/")
		csp := rec.Header().Get("Content-Security-Policy")
		if csp == "" {
			t.Fatal("GET /: no Content-Security-Policy header")
		}
		m := regexp.MustCompile(`'nonce-([0-9a-f]+)'`).FindStringSubmatch(csp)
		if m == nil {
			t.Fatalf("GET /: CSP carries no nonce: %q", csp)
		}
		for _, want := range []string{
			"default-src 'none'",
			"script-src 'self' 'nonce-",
			"style-src 'self' 'nonce-",
			"connect-src 'self'",
			"form-action 'self'",
			"base-uri 'none'",
			"frame-ancestors 'none'",
		} {
			if !strings.Contains(csp, want) {
				t.Errorf("GET /: CSP missing %q in %q", want, csp)
			}
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("GET /: Cache-Control = %q, want no-store (a nonce is single-use)", cc)
		}
		body := rec.Body.String()
		if !strings.Contains(body, `<script nonce="`+m[1]+`">`) {
			t.Error("GET /: the inline script's nonce does not match the header's nonce — the page is CSP-dead")
		}
		if !strings.Contains(body, `<style nonce="`+m[1]+`">`) {
			t.Error("GET /: the inline style's nonce does not match the header's nonce")
		}
		if strings.Contains(body, "onclick=") {
			t.Error("GET /: inline event handlers survive — the nonce script-src blocks them, breaking the buttons")
		}
	})

	t.Run("nonces rotate per response", func(t *testing.T) {
		m1 := regexp.MustCompile(`'nonce-([0-9a-f]+)'`).FindStringSubmatch(get("/").Header().Get("Content-Security-Policy"))
		m2 := regexp.MustCompile(`'nonce-([0-9a-f]+)'`).FindStringSubmatch(get("/").Header().Get("Content-Security-Policy"))
		if m1 == nil || m2 == nil || m1[1] == m2[1] {
			t.Fatalf("nonce reuse across responses: %v vs %v", m1, m2)
		}
	})

	t.Run("report carries the no-network policy", func(t *testing.T) {
		csp := get("/report/none").Header().Get("Content-Security-Policy")
		for _, want := range []string{
			"default-src 'none'",
			"script-src 'unsafe-inline'",
			"style-src 'unsafe-inline'",
			"connect-src 'none'",
			"frame-ancestors 'none'",
		} {
			if !strings.Contains(csp, want) {
				t.Errorf("GET /report/: CSP missing %q in %q", want, csp)
			}
		}
		if strings.Contains(csp, "nonce-") {
			t.Errorf("GET /report/: the policy carries a nonce — the report is a pre-generated static file; a nonce here CSP-kills its inline scripts: %q", csp)
		}
	})

	t.Run("assets carry no CSP", func(t *testing.T) {
		rec := get("/assets/marked-18.0.12.min.js")
		if csp := rec.Header().Get("Content-Security-Policy"); csp != "" {
			t.Errorf("GET /assets: unexpected CSP on a non-document: %q", csp)
		}
		if xo := rec.Header().Get("X-Content-Type-Options"); xo != "nosniff" {
			t.Errorf("GET /assets: nosniff lost: %q", xo)
		}
	})
}
