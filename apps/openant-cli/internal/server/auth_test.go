package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The securityHeaders middleware must reject a non-loopback Host on EVERY route
// (DNS-rebinding guard), while a loopback Host passes through.
func TestMiddlewareRejectsRebindingHost(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := securityHeaders(ok)
	for _, host := range []string{"evil.example.com", "evil.com:8080", "attacker.test", "127.0.0.1.evil.com:8080"} {
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 403 {
			t.Errorf("foreign Host %q = %d, want 403 (rebinding read not closed)", host, rec.Code)
		}
	}
	// Any loopback bind must be accepted (not just 127.0.0.1), or the guard would
	// 403 a server bound to 127.0.0.2; foreign names above still reject.
	for _, host := range []string{"127.0.0.1:8080", "localhost:8080", "LOCALHOST:8080", "[::1]:8080", "127.0.0.2:8080", "127.0.0.9:8080"} {
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == 403 {
			t.Errorf("loopback Host %q wrongly 403'd", host)
		}
	}
}

// sameOriginOK (the CSRF gate for mutations) must reject a missing token's
// preconditions: foreign Host, cross-site Sec-Fetch-Site, and a foreign Origin.
func TestSameOriginOKRejections(t *testing.T) {
	mk := func(host, sfs, origin string) *http.Request {
		r := httptest.NewRequest("POST", "/scan", nil)
		r.Host = host
		if sfs != "" {
			r.Header.Set("Sec-Fetch-Site", sfs)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		return r
	}
	if sameOriginOK(mk("evil.com", "", "")) {
		t.Error("foreign Host accepted by sameOriginOK")
	}
	if sameOriginOK(mk("127.0.0.1:8080", "cross-site", "")) {
		t.Error("cross-site Sec-Fetch-Site accepted")
	}
	if sameOriginOK(mk("127.0.0.1:8080", "", "http://evil.com")) {
		t.Error("foreign Origin accepted")
	}
	if !sameOriginOK(mk("127.0.0.1:8080", "same-origin", "http://127.0.0.1:8080")) {
		t.Error("legitimate same-origin request wrongly rejected")
	}
}

// An http(s) repo URL carrying userinfo must be rejected (it would be logged
// verbatim in meta.json/logs.txt/SSE/argv). Loopback Host + valid CSRF so the
// request reaches the credential check.
func TestRejectCredsInRepoURL(t *testing.T) {
	s := &Server{outDir: t.TempDir(), mgr: newManager(t.TempDir()), csrfToken: "tok", sem: make(chan struct{}, 4), shutdownDone: make(chan struct{})}
	req := httptest.NewRequest("POST", "/scan", formBody("csrf=tok&repo=https://user:secret@example.com/r.git"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()
	s.handleStartScan(rec, req)
	if rec.Code != 400 {
		t.Errorf("repo URL with credentials = %d, want 400", rec.Code)
	}
	if n := len(s.mgr.all()); n != 0 {
		t.Errorf("credential-bearing URL created %d job(s)", n)
	}
	// A malformed credential URL (bad %-escape) must ALSO be rejected (fail closed),
	// not slip past url.Parse into the logs.
	req2 := httptest.NewRequest("POST", "/scan", formBody("csrf=tok&repo=https://user:sec%ZZ@example.com/r.git"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Host = "127.0.0.1"
	rec2 := httptest.NewRecorder()
	s.handleStartScan(rec2, req2)
	if rec2.Code != 400 {
		t.Errorf("malformed credential URL = %d, want 400 (fail closed)", rec2.Code)
	}
}
