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

// #578 follow-up A + 1a: the CSP contract. The four UI pages carry a
// per-response nonce (header == every inline script/style tag); /report/{id}
// carries the no-network policy; everything unwrapped carries the fail-closed
// default (inert on non-documents).
func TestCSPPoliciesPerRoute(t *testing.T) {
	// The templates are parsed from the ui embed (same as New()) — a
	// zero-value Server has nil templates and handleIndex would nil-panic.
	tmplIndex, err := template.ParseFS(uifiles.FS, "index.html")
	if err != nil {
		t.Fatalf("parse index.html: %v", err)
	}
	tmplScan, err := template.ParseFS(uifiles.FS, "scan.html")
	if err != nil {
		t.Fatalf("parse scan.html: %v", err)
	}
	s := &Server{
		outDir:       t.TempDir(),
		mgr:          newManager(t.TempDir()),
		csrfToken:    "tok",
		sem:          make(chan struct{}, 4),
		shutdownDone: make(chan struct{}),
		tmplIndex:    tmplIndex,
		tmplScan:     tmplScan,
	}
	h := s.Handler()
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "localhost:8080" // the rebinding guard 403s non-loopback Hosts
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	// A registered job so the scan/summary/disclosure routes render (the
	// handlers 404 without one).
	j := &Job{ID: "j1", Repo: "https://example.com/o/r", Status: "done", done: make(chan struct{})}
	s.mgr.add(j)

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

	t.Run("every UI page carries header/body nonce equality", func(t *testing.T) {
		// The scan page needs only the registered job; summary/disclosure
		// additionally need their artifacts on disk (the handlers 404
		// otherwise) — the nonce CONTRACT is asserted on the routes that
		// render; the template-side nonce pin (vendor_test.go's
		// zero-bare-opens + nonced inventory) covers the artifact-backed
		// pages' markup regardless.
		for _, path := range []string{"/", "/scan/j1"} {
			rec := get(path)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200", path, rec.Code)
			}
			csp := rec.Header().Get("Content-Security-Policy")
			m := regexp.MustCompile(`'nonce-([0-9a-f]+)'`).FindStringSubmatch(csp)
			if m == nil {
				t.Fatalf("GET %s: CSP carries no nonce: %q", path, csp)
			}
			body := rec.Body.String()
			if !strings.Contains(body, `<script nonce="`+m[1]+`">`) {
				t.Errorf("GET %s: the inline script's nonce does not match the header's nonce", path)
			}
			if !strings.Contains(body, `<style nonce="`+m[1]+`">`) {
				t.Errorf("GET %s: the inline style's nonce does not match the header's nonce", path)
			}
			if strings.Contains(body, "onclick=") {
				t.Errorf("GET %s: inline event handlers survive — the nonce script-src blocks them", path)
			}
		}
	})

	t.Run("summary and disclosure routes carry the nonce policy", func(t *testing.T) {
		// Even 404 responses from the UI-page routes carry the CSP header
		// (the middleware sets it before the handler) — this pins the
		// ROUTE classification (the wrapper fires on the route, by construction) for the artifact-backed pages.
		for _, path := range []string{"/summary/j1", "/disclosure/j1/d.md"} {
			csp := get(path).Header().Get("Content-Security-Policy")
			m := regexp.MustCompile(`'nonce-([0-9a-f]+)'`).FindStringSubmatch(csp)
			if m == nil {
				t.Errorf("GET %s: no nonce policy (the route is mis-classified): %q", path, csp)
			}
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

	t.Run("report policy needs no unsafe-eval", func(t *testing.T) {
		// #578-A review round: the report's three vendored blobs were
		// checked for eval/new Function (the CSP-kills-the-report hazard):
		// 0 matches in chart-4.5.1.umd.min.js, chartjs-plugin-datalabels-
		// 2.2.0.min.js, and tailwindcss-3.4.17.js (grep -o "new Function(\|
		// [^A-Za-z_.]eval(" over internal/report/vendor/*.js — 2026-09-12
		// receipt in the PR). The absence is NOT re-checked here (the blobs
		// are sha-pinned by the report side's own vendor discipline); this
		// test pins the POLICY SHAPE the absence justifies.
		if strings.Contains(get("/report/none").Header().Get("Content-Security-Policy"), "unsafe-eval") {
			t.Error("GET /report/: the policy carries unsafe-eval — the vendored blobs contain no eval shapes (checked at #578-A; re-justify on any blob bump)")
		}
	})

	t.Run("unwrapped routes carry the fail-closed default", func(t *testing.T) {
		// #578 follow-up 1a: assets and API routes now carry the
		// restrictive DEFAULT policy (inert on non-documents — CSP governs
		// document loads). The load-bearing direction: a future HTML route
		// registered WITHOUT a wrapper gets this too — scriptless and
		// unstyled (loud), never silently CSP-less.
		for _, path := range []string{"/assets/marked-18.0.12.min.js", "/disclosures/j1"} {
			csp := get(path).Header().Get("Content-Security-Policy")
			for _, want := range []string{
				"default-src 'none'",
				"script-src 'none'",
				"connect-src 'none'",
			} {
				if !strings.Contains(csp, want) {
					t.Errorf("GET %s: the fail-closed default is missing %q: %q", path, want, csp)
				}
			}
		}
		if xo := get("/assets/marked-18.0.12.min.js").Header().Get("X-Content-Type-Options"); xo != "nosniff" {
			t.Errorf("GET /assets: nosniff lost: %q", xo)
		}
	})

	t.Run("the scan-page 404 keeps the nonce policy (route-classified, not path-guessed)", func(t *testing.T) {
		// The wrapper fires on the ROUTE, so a 404 from a mis-typed scan id
		// still carries the nonce policy (previously isUIPage matched the
		// path prefix — same behavior, now by construction not heuristic).
		csp := get("/scan/nonexistent").Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "'nonce-") {
			t.Errorf("GET /scan/nonexistent: expected the nonce policy on the route's 404: %q", csp)
		}
		// The SSE logs route is NOT a UI page — it carries the default.
		cspLogs := get("/scan/j1/logs").Header().Get("Content-Security-Policy")
		if strings.Contains(cspLogs, "'nonce-") {
			t.Errorf("GET /scan/j1/logs: the SSE stream must not carry the nonce policy: %q", cspLogs)
		}
	})
}
