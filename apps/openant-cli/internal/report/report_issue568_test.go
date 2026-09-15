package report

import (
	"bytes"
	"strings"
	"testing"
)

// #568: the render boundary never persists or leaks a raw remote. The reskin
// header link renders the normalized browse form; a credential-bearing URL
// never reaches the artifact; an unparseable remote renders the plain span
// (the honest absence), never a broken link.
func TestRenderReskinRepoURLNeverRaw(t *testing.T) {
	base := ReportData{
		Title:     "demo",
		RepoName:  "org/repo",
		CommitSHA: "abc123def456",
		RepoURL:   "https://user:TOKEN@github.com/org/repo",
		Language:  "go",
	}

	// A credential-bearing URL: the TOKEN never reaches the artifact; the
	// header link is the normalized browse form.
	var buf bytes.Buffer
	if err := RenderReskin(base, &buf); err != nil {
		t.Fatalf("RenderReskin: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "TOKEN") {
		t.Error("reskin: the credential leaked into the artifact")
	}
	if !strings.Contains(out, `href="https://github.com/org/repo"`) {
		t.Error("reskin: expected the normalized header link for the credential form")
	}

	// The scp form: normalized, never the raw remote, never a broken link.
	scp := base
	scp.RepoURL = "git@github.com:org/repo.git"
	buf.Reset()
	if err := RenderReskin(scp, &buf); err != nil {
		t.Fatalf("RenderReskin: %v", err)
	}
	out = buf.String()
	if strings.Contains(out, "ZgotmplZ") {
		t.Error("reskin: the scp form rendered a broken link")
	}
	if !strings.Contains(out, `href="https://github.com/org/repo"`) {
		t.Error("reskin: expected the normalized header link for the scp form")
	}

	// An unparseable remote: the honest absence — the plain span, no link.
	unparseable := base
	unparseable.RepoURL = "git://github.com/org/repo.git"
	buf.Reset()
	if err := RenderReskin(unparseable, &buf); err != nil {
		t.Fatalf("RenderReskin: %v", err)
	}
	out = buf.String()
	if strings.Contains(out, "ZgotmplZ") {
		t.Error("reskin: the unparseable form rendered a broken link")
	}
	if !strings.Contains(out, `<span title="Repository">`) {
		t.Error("reskin: the unparseable form must render the plain span (the honest absence)")
	}
	if !strings.Contains(out, "org/repo") {
		t.Error("reskin: RepoName must still render for the unparseable form")
	}

	// A clean URL keeps its link unchanged.
	clean := base
	clean.RepoURL = "https://github.com/org/repo"
	buf.Reset()
	if err := RenderReskin(clean, &buf); err != nil {
		t.Fatalf("RenderReskin: %v", err)
	}
	if !strings.Contains(buf.String(), `href="https://github.com/org/repo"`) {
		t.Error("reskin: the clean URL lost its header link")
	}
}

// TestBrowseURLNormalizesDefensively pins the method the reskin template
// consumes — same contract as FileURL's normalization.
func TestBrowseURLNormalizesDefensively(t *testing.T) {
	d := ReportData{RepoURL: "git@github.com:org/repo.git"}
	if got := d.BrowseURL(); got != "https://github.com/org/repo" {
		t.Errorf("BrowseURL(scp) = %q, want the normalized browse form", got)
	}
	d.RepoURL = "https://user:TOKEN@github.com/org/repo"
	if got := d.BrowseURL(); got != "https://github.com/org/repo" {
		t.Errorf("BrowseURL(cred) = %q, want the credential stripped", got)
	}
	d.RepoURL = "git://github.com/org/repo.git"
	if got := d.BrowseURL(); got != "" {
		t.Errorf("BrowseURL(git://) = %q, want the honest absence", got)
	}
}
