package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #568: patchPipelineOutput never writes a raw remote into
// pipeline_output.json's repository.url — an unparseable form is removed
// (the honest absence; sibling keys preserved), a parseable one carries the
// normalized browse form.
func TestPatchPipelineOutputNeverWritesRawRemote(t *testing.T) {
	writeFixture := func(t *testing.T, url string) string {
		t.Helper()
		dir := t.TempDir()
		obj := map[string]any{
			"repository": map[string]any{
				"name":     "org/repo",
				"url":      url,
				"language": "go",
			},
			"findings": []any{},
		}
		blob, err := json.MarshalIndent(obj, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "pipeline_output.json"), blob, 0o644); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	readRepo := func(t *testing.T, dir string) map[string]any {
		t.Helper()
		blob, err := os.ReadFile(filepath.Join(dir, "pipeline_output.json"))
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]any
		if err := json.Unmarshal(blob, &obj); err != nil {
			t.Fatal(err)
		}
		repo, _ := obj["repository"].(map[string]any)
		return repo
	}
	noop := func(string) {}

	// A credential-bearing but parseable remote: patched to the normalized
	// browse form — the credential never persists, sibling keys intact.
	dir := writeFixture(t, "https://user:TOKEN@github.com/org/repo")
	patchPipelineOutput(dir, "https://user:TOKEN@github.com/org/repo", noop)
	repo := readRepo(t, dir)
	if repo["url"] != "https://github.com/org/repo" {
		t.Errorf("credential form url = %v, want the normalized browse form", repo["url"])
	}
	if repo["name"] != "org/repo" || repo["language"] != "go" {
		t.Errorf("sibling keys damaged by the patch: %v", repo)
	}
	blob, err := os.ReadFile(filepath.Join(dir, "pipeline_output.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "TOKEN") {
		t.Error("the credential persisted in pipeline_output.json")
	}

	// The scp form: patched to the normalized browse form.
	dir = writeFixture(t, "git@github.com:org/repo.git")
	patchPipelineOutput(dir, "git@github.com:org/repo.git", noop)
	repo = readRepo(t, dir)
	if repo["url"] != "https://github.com/org/repo" {
		t.Errorf("scp url = %v, want the normalized browse form", repo["url"])
	}

	// The password-scp form (unparseable): the url key is removed.
	dir = writeFixture(t, "user:pass@host:path")
	patchPipelineOutput(dir, "user:pass@host:path", noop)
	repo = readRepo(t, dir)
	if _, has := repo["url"]; has {
		t.Errorf("password-scp url survived: %v", repo["url"])
	}

	// An already-normalized remote: passthrough.
	dir = writeFixture(t, "https://github.com/org/repo")
	patchPipelineOutput(dir, "https://github.com/org/repo", noop)
	repo = readRepo(t, dir)
	if repo["url"] != "https://github.com/org/repo" {
		t.Errorf("normalized url = %v, want passthrough", repo["url"])
	}

	// A local-path remote (unparseable): the url key is removed — a
	// filesystem path is not a browse URL, and a username inside it is
	// not rendered.
	dir = writeFixture(t, "/Users/alice/work/repo")
	patchPipelineOutput(dir, "/Users/alice/work/repo", noop)
	repo = readRepo(t, dir)
	if _, has := repo["url"]; has {
		t.Errorf("local-path url survived: %v", repo["url"])
	}
}
