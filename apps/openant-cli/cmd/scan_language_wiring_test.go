package cmd

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestOffPinWiringRejectsEndToEnd pins the WIRING (the M9-1 E1 class: the
// helper is tested, the cobra call is not). A subprocess drives the REAL
// `openant scan` command against a jailed HOME with a python-pinned project;
// the parent asserts the #667 rejection fires (exit 2, the #667 message)
// and that NOTHING was written (no dataset.json in the pin dir).
// The child form: OPENANT_TEST_RUN_SCAN=1 runs runScan directly.
func TestOffPinWiringRejectsEndToEnd(t *testing.T) {
	if os.Getenv("OPENANT_TEST_RUN_SCAN") == "1" {
		// the child: a bad -l on a python-pinned project; runScan exits 2
		// on the #667 rejection (or proceeds and the parent catches the exit 0)
		scanLanguage = os.Getenv("OPENANT_TEST_LANGUAGE")
		scanSkipDynamicTest = true // the docker check fires before the guard
		_ = scanCmd.Flags().Set("language", os.Getenv("OPENANT_TEST_LANGUAGE"))
		projectFlag = os.Getenv("OPENANT_TEST_PROJECT")
		runScan(scanCmd, []string{})
		return
	}

	// build a fake HOME with a python-pinned active project
	home := t.TempDir()
	openantDir := filepath.Join(home, ".openant", "projects", "org", "repo")
	if err := os.MkdirAll(filepath.Join(openantDir, "scans", "deadbeef", "python"), 0o755); err != nil {
		t.Fatal(err)
	}
	projJSON := `{"name":"org/repo","repo_path":"/tmp","source":"local","language":"python","commit_sha":"deadbeef","commit_sha_short":"deadbeef"}`
	if err := os.WriteFile(filepath.Join(openantDir, "project.json"), []byte(projJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	// the active-project pointer
	cfgDir := filepath.Join(home, ".config", "openant")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte(`{"active_project":"org/repo"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// the fake repo (a directory; the guard fires before the repo is touched)
	_ = t.TempDir() // the bare repo dir (the guard fires before any repo touch)

	for _, badLang := range []string{"go", "cobol"} {
		cmd := exec.Command(os.Args[0], "-test.run=TestOffPinWiringRejectsEndToEnd")
		cmd.Env = append(os.Environ(),
			"OPENANT_TEST_RUN_SCAN=1",
			"OPENANT_TEST_LANGUAGE="+badLang,
			"OPENANT_TEST_PROJECT=org/repo",
			"HOME="+home,
			"USERPROFILE="+home,
			"APPDATA="+home,
			"XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
			"GIT_CONFIG_NOSYSTEM=1",
		)
		out, err := cmd.CombinedOutput()

		// the assertion: the subprocess must have exited non-zero with the
		// #667 message (or at minimum, NOT exited 0 — if the wiring was
		// removed, runScan would proceed and hit a different error, but
		// the absence of the #667 message is the wiring-removed signal)
		full := string(out)
		// a supported off-pin (go) gets #667; an unsupported (cobol) gets
		// #691 — EITHER rejection proves the WIRING (the cobra call fires)
		has667 := strings.Contains(full, "issue #667")
		has691 := strings.Contains(full, "issue #691")
		if err == nil {
			t.Errorf("-l %s: the subprocess exited 0 — the guard did not fire (the E1 wiring class)", badLang)
		}
		if !has667 && !has691 {
			t.Errorf("-l %s: the output lacks both the #667 and #691 messages (the wiring is untested): %s", badLang, clipStr(full, 300))
		}
		// NOTHING written to the pin dir (the artifacts stay clean)
		dataset := filepath.Join(openantDir, "scans", "deadbeef", "python", "dataset.json")
		if _, statErr := os.Stat(dataset); statErr == nil {
			t.Errorf("-l %s: dataset.json WAS WRITTEN to the pin dir (the #667 in-place overwrite)", badLang)
		}
	}
}

func clipStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

var _ = context.Background // keep the import if unused by the child branch

func TestOffPinParseWiringRejectsEndToEnd(t *testing.T) {
	if os.Getenv("OPENANT_TEST_RUN_PARSE") == "1" {
		parseLanguage = os.Getenv("OPENANT_TEST_LANGUAGE")
		_ = parseCmd.Flags().Set("language", os.Getenv("OPENANT_TEST_LANGUAGE"))
		projectFlag = os.Getenv("OPENANT_TEST_PROJECT")
		runParse(parseCmd, []string{})
		return
	}

	home := t.TempDir()
	openantDir := filepath.Join(home, ".openant", "projects", "org", "repo")
	if err := os.MkdirAll(filepath.Join(openantDir, "scans", "deadbeef", "python"), 0o755); err != nil {
		t.Fatal(err)
	}
	projJSON := `{"name":"org/repo","repo_path":"/tmp","source":"local","language":"python","commit_sha":"deadbeef","commit_sha_short":"deadbeef"}`
	if err := os.WriteFile(filepath.Join(openantDir, "project.json"), []byte(projJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	cfgDir := filepath.Join(home, ".config", "openant")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte(`{"active_project":"org/repo"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, badLang := range []string{"go"} {
		cmd := exec.Command(os.Args[0], "-test.run=TestOffPinParseWiringRejectsEndToEnd")
		cmd.Env = append(os.Environ(),
			"OPENANT_TEST_RUN_PARSE=1",
			"OPENANT_TEST_LANGUAGE="+badLang,
			"OPENANT_TEST_PROJECT=org/repo",
			"HOME="+home,
			"USERPROFILE="+home,
			"APPDATA="+home,
			"XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
			"GIT_CONFIG_NOSYSTEM=1",
		)
		out, err := cmd.CombinedOutput()
		full := string(out)
		has667 := strings.Contains(full, "issue #667")
		if err == nil {
			t.Errorf("parse -l %s: the subprocess exited 0 — the guard did not fire (the parse wiring is untested)", badLang)
		}
		if !has667 {
			t.Errorf("parse -l %s: the output lacks the #667 message (the parse wiring is untested): %s", badLang, clipStr(full, 300))
		}
	}
}
