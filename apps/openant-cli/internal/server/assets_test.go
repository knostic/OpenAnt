package server

import (
	"bytes"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"

	uifiles "github.com/knostic/open-ant-cli/ui"
)

// #577: /assets serves ONLY the vendored ui scripts, by exact versioned
// name. The route is the serving half of the vendored-script governance:
// every script the embedded pages reference must be served byte-identically
// from the embed, the pre-#577 versionless names must be GONE (404, not
// aliased — an alias would defeat the versioned-name notifier), and the
// response carries the JS content type + nosniff (the blobs are external
// scripts, never inlined template.JS — the breakout class has no reach
// here).
func TestHandleAssetServesVersionedVendor(t *testing.T) {
	h := (&Server{}).Handler()

	served := 0
	err := fs.WalkDir(uifiles.FS, "vendor", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := path.Base(p)
		if !strings.HasSuffix(name, ".js") {
			return nil // SOURCES.txt — the provenance record, not a script
		}
		want, err := uifiles.FS.ReadFile(p)
		if err != nil {
			return err
		}
		req := httptest.NewRequest(http.MethodGet, "/assets/"+name, nil)
		req.Host = "localhost:8080" // the rebinding guard 403s non-loopback Hosts
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET /assets/%s = %d, want 200 (the embedded pages reference this script)", name, rec.Code)
			return nil
		}
		if !bytes.Equal(rec.Body.Bytes(), want) {
			t.Errorf("GET /assets/%s: served bytes differ from the embedded bytes — the serving path diverged from the pinned blob", name)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/javascript; charset=utf-8" {
			t.Errorf("GET /assets/%s Content-Type = %q, want application/javascript; charset=utf-8", name, ct)
		}
		if xo := rec.Header().Get("X-Content-Type-Options"); xo != "nosniff" {
			t.Errorf("GET /assets/%s: X-Content-Type-Options = %q, want nosniff (securityHeaders must cover the asset route)", name, xo)
		}
		served++
		return nil
	})
	if err != nil {
		t.Fatalf("walking the embedded vendor dir: %v", err)
	}
	if served == 0 {
		t.Fatal("no vendored scripts found in the embed")
	}

	// The retired pre-#577 versionless names, and the superseded
	// marked-12.0.2 (the 18.x re-vendor): 404, never aliased.
	for _, name := range []string{"marked.min.js", "purify.min.js", "marked-12.0.2.min.js"} {
		req := httptest.NewRequest(http.MethodGet, "/assets/"+name, nil)
		req.Host = "localhost:8080"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET /assets/%s = %d, want 404 (the versionless name must be retired, not aliased — an alias hides the version from the notifier)", name, rec.Code)
		}
	}
}

// The handleAsset allowlist and the embedded vendor set must agree EXACTLY:
// a case literal with no embedded file is a dead 200-route (harmless at
// runtime — ReadFile 404s — but it means the five-way rename consistency
// net drifted: embed list, page tags, pin table, this allowlist, and the
// renovate reference files are supposed to move together in one commit).
func TestHandleAssetAllowlistMatchesEmbeddedVendor(t *testing.T) {
	src, err := os.ReadFile("server.go") // in-package: cwd IS this package's dir
	if err != nil {
		t.Fatalf("reading server.go: %v", err)
	}
	s := string(src)
	i := strings.Index(s, "func (s *Server) handleAsset")
	if i < 0 {
		t.Fatal("handleAsset not found in server.go")
	}
	block := s[i:]
	if next := strings.Index(block[10:], "\nfunc "); next > 0 {
		block = block[:10+next]
	}
	allow := map[string]bool{}
	caseLine := regexp.MustCompile(`case [^:]+:`)
	quoted := regexp.MustCompile(`"([^"]+)"`)
	for _, line := range caseLine.FindAllString(block, -1) {
		for _, q := range quoted.FindAllStringSubmatch(line, -1) {
			allow[q[1]] = true
		}
	}
	if len(allow) == 0 {
		t.Fatal("no case literals found in handleAsset — the parser or the guard changed shape")
	}
	embedded := map[string]bool{}
	err = fs.WalkDir(uifiles.FS, "vendor", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".js") {
			return nil
		}
		embedded[path.Base(p)] = true
		return nil
	})
	if err != nil {
		t.Fatalf("walking the embedded vendor dir: %v", err)
	}
	for name := range allow {
		if !embedded[name] {
			t.Errorf("handleAsset allowlists %q but it is not embedded — the rename net drifted (a dead 200-route that 404s at ReadFile)", name)
		}
	}
	for name := range embedded {
		if !allow[name] {
			t.Errorf("embedded vendor script %q is not in the handleAsset allowlist — the pages reference it but the route would 404 it", name)
		}
	}
}
