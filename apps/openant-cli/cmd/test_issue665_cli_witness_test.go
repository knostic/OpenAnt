package cmd

// #665 cycle 2, round 9 (the C4 route-C witnesses, the fable+astra talk's
// converged plan): runScan and runParse end in os.Exit and call the Python
// runtime, so no in-process battery could reach the --pr path-threading or
// the exit arms — the E1/E2 class that left four prod hunks uncovered. The
// patch_apikey pattern (cmd/patch_apikey_test.go) solves the same shape for
// `openant patch`: this test binary re-executes itself in two helper roles —
//   - "cli": drives the REAL rootCmd with the argv after "--";
//   - "python": impersonates the interpreter resolved through
//     OPENANT_PYTHON, answering the version/import probes and, on the
//     engine invocation (`-P -m openant <verb> <repoPath> ...`), recording
//     WHAT PATH THE ENGINE WAS HANDED (and whether the PR head's file is
//     present there) before emitting a chosen envelope shape.
// The witnesses then assert: the engine's input path is the ISOLATED
// worktree carrying the PR head (never the user's checkout), the user's
// tree never moved, and the workspace (worktree + unique ref) is GONE
// after every exit shape — success, invoke-error, and interrupted.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const (
	issue665RoleEnv     = "OPENANT_TEST_665_ROLE"
	issue665RecordEnv   = "OPENANT_TEST_665_RECORD"
	issue665ShapeEnv    = "OPENANT_TEST_665_SHAPE"
	issue665RoleCLI     = "cli"
	issue665RolePython  = "python"
	issue665SentinelKey = "openant-665-witness-sentinel-not-a-real-key"
)

// issue665EngineRecord is what the fake engine persists: the verb it was
// invoked as, the REPO PATH it was handed (the load-bearing assertion: the
// isolated worktree, not the user's checkout), and whether the PR head's
// committed file is present at that path.
type issue665EngineRecord struct {
	Verb            string `json:"verb"`
	RepoPath        string `json:"repo_path"`
	RepoIsUserClone bool   `json:"repo_is_user_clone"`
	PRFilePresent   bool   `json:"pr_file_present"`
	// #665 cycle 3 (the m10 catch): the --commit-sha the run threaded —
	// the detection stamps must name the SCANNED tree (the PR head), and
	// this field pins the threading end-to-end (detectedSHA from scanPath
	// -> resolveRepoMetadataFull -> pyArgs)
	CommitSHA string `json:"commit_sha"`
}

func init() {
	if os.Getenv(issue665RoleEnv) == issue665RolePython {
		os.Exit(issue665FakePython(os.Args[1:]))
	}
}

// issue665FakePython answers exactly the three interpreter invocations
// internal/python makes (checkPython, isOpenantImportable, Invoke) and
// fails loudly on anything else.
func issue665FakePython(args []string) int {
	switch {
	case len(args) == 1 && args[0] == "--version":
		fmt.Println("Python 3.12.0")
		return 0
	case len(args) >= 1 && args[0] == "-c":
		return 0
	case len(args) >= 5 && args[0] == "-P" && args[1] == "-m" && args[2] == "openant":
		verb := args[3]
		repoPath := args[4]
		userClone := os.Getenv("OPENANT_TEST_665_USERCLONE")
		prFile := "b.txt" // the PR-7 head's committed file (issue665Env)
		_, statErr := os.Stat(filepath.Join(repoPath, prFile))
		commitSHA := ""
		for i, a := range args {
			if a == "--commit-sha" && i+1 < len(args) {
				commitSHA = args[i+1]
			}
		}
		rec := issue665EngineRecord{
			Verb:            verb,
			RepoPath:        repoPath,
			RepoIsUserClone: repoPath == userClone,
			PRFilePresent:   statErr == nil,
			CommitSHA:       commitSHA,
		}
		data, err := json.Marshal(rec)
		if err == nil {
			err = os.WriteFile(os.Getenv(issue665RecordEnv), data, 0o600)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "fake python: cannot write record: %v\n", err)
			return 4
		}
		switch os.Getenv(issue665ShapeEnv) {
		case "engine-crash":
			// fable-F11: a SIGKILLed engine yields no envelope, which
			// Invoke turns into a Status:"error" RESULT (err == nil) — the
			// run flows the FINAL cleanup, not the err != nil arm (that
			// arm fires only on Start/wait failure, which the pre-validated
			// runtime makes unreachable here). This shape witnesses the
			// failed-envelope path and its exit 2.
			fmt.Fprintln(os.Stderr, "fake python: simulated engine crash")
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			return 7 // unreachable
		case "interrupted":
			fmt.Println(`{"status":"interrupted","data":{},"errors":[]}`)
			return 0
		default:
			fmt.Println(`{"status":"success","data":{},"errors":[]}`)
			return 0
		}
	default:
		fmt.Fprintf(os.Stderr, "fake python: unexpected invocation (%d args)\n", len(args))
		return 3
	}
}

// TestIssue665HelperCLI is the "cli" helper role re-executed by
// issue665RunCLI; a no-op in a normal test run.
func TestIssue665HelperCLI(t *testing.T) {
	if os.Getenv(issue665RoleEnv) != issue665RoleCLI {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `helper: no "--" before the CLI argv`)
		os.Exit(97)
	}
	os.Setenv(issue665RoleEnv, issue665RolePython)
	rootCmd.SetArgs(args[1:])
	if err := rootCmd.Execute(); err != nil {
		os.Exit(96)
	}
	os.Exit(98)
}

// issue665RunCLI re-executes this test binary as the real CLI with the fake
// interpreter pinned, then returns the engine's record and the CLI's exit
// code.
func issue665RunCLI(t *testing.T, userClone string, argv ...string) (issue665EngineRecord, int) {
	t.Helper()
	root := t.TempDir()
	record := filepath.Join(root, "engine-record.json")
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmdArgs := append([]string{
		"-test.run=TestIssue665HelperCLI",
		"--", "--api-key", issue665SentinelKey,
	}, argv...)
	proc := exec.Command(exe, cmdArgs...)
	proc.Env = append(os.Environ(),
		issue665RoleEnv+"="+issue665RoleCLI,
		issue665RecordEnv+"="+record,
		"OPENANT_PYTHON="+exe,
		"OPENANT_TEST_665_USERCLONE="+userClone,
	)
	out, err := proc.CombinedOutput()
	rc := 0
	if exit, ok := err.(*exec.ExitError); ok {
		rc = exit.ExitCode()
	} else if err != nil {
		t.Fatalf("re-exec the CLI: %v: %s", err, out)
	}
	raw, rerr := os.ReadFile(record)
	if rerr != nil {
		t.Fatalf("the engine never ran (no record; rc=%d): %s", rc, lastLines(out))
	}
	var rec issue665EngineRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("parse the engine record: %v", err)
	}
	return rec, rc
}

func lastLines(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) > 12 {
		lines = lines[len(lines)-12:]
	}
	return strings.Join(lines, "\n")
}

// issue665AssertCommon is the shared witness body: the engine parsed the
// ISOLATED worktree (never the user's clone, always carrying the PR head),
// the user's checkout never moved, and the workspace is gone after the run.
func issue665AssertCommon(t *testing.T, repoDir, base string, rec issue665EngineRecord) {
	t.Helper()
	if rec.RepoIsUserClone {
		t.Errorf("the engine was handed the USER's checkout (%s) — the path-threading is broken (the scratch must be the engine's tree)", rec.RepoPath)
	}
	if !strings.Contains(filepath.Base(filepath.Dir(rec.RepoPath)), "openant-pr-") &&
		!strings.Contains(filepath.Base(rec.RepoPath), "openant-pr-") {
		t.Errorf("the engine's path is not an openant scratch: %s", rec.RepoPath)
	}
	if !rec.PRFilePresent {
		t.Errorf("the PR head's committed file is absent from the engine's tree (%s) — the scan would read the wrong content", rec.RepoPath)
	}
	if got := issue665Rev(t, repoDir, "HEAD"); got != base {
		t.Errorf("the user's checkout moved: %s -> %s", base, got)
	}
	if refs := issue665PRRefs(t, repoDir); len(refs) != 0 {
		t.Errorf("the unique refs survived the run: %v", refs)
	}
	wl, err := exec.Command("git", "-C", repoDir, "worktree", "list", "--porcelain").Output()
	if err != nil {
		t.Fatalf("worktree list: %v", err)
	}
	for _, line := range strings.Split(string(wl), "\n") {
		if w, ok := strings.CutPrefix(line, "worktree "); ok {
			if strings.Contains(filepath.Base(strings.TrimSpace(w)), "openant-pr-") {
				t.Errorf("the scratch worktree survived the run: %s", strings.TrimSpace(w))
			}
		}
	}
}

// TestIssue665ScanPRCLIWitness drives the REAL `openant scan --pr` through
// the fake interpreter: the engine's record must show the isolated worktree
// carrying the PR head, and every exit shape must clean the workspace.
func TestIssue665ScanPRCLIWitness(t *testing.T) {
	for _, shape := range []struct {
		name string
		env  string
		want int
	}{
		{name: "success", env: "success", want: 0},
		{name: "engine-crash", env: "engine-crash", want: 2},
		{name: "interrupted", env: "interrupted", want: 130},
	} {
		t.Run(shape.name, func(t *testing.T) {
			repoDir, binDir, base, prHeads := issue665Env(t)
			issue665Preflight(t, binDir)
			out := t.TempDir()
			t.Setenv(issue665ShapeEnv, shape.env)
			rec, rc := issue665RunCLI(t, repoDir,
				"scan", repoDir, "--pr", "7", "--skip-dynamic-test", "-o", out, "--no-report")
			issue665AssertCommon(t, repoDir, base, rec)
			if rec.CommitSHA != "" && rec.CommitSHA != prHeads[7] {
				t.Errorf("the run threaded --commit-sha %s, want the PR head %s (the m10 class: the detection stamped the USER's tree)", rec.CommitSHA, prHeads[7])
			}
			if rec.Verb != "scan" {
				t.Errorf("the engine verb = %q, want scan", rec.Verb)
			}
			if rc != shape.want {
				t.Errorf("exit code = %d, want %d (the %s arm)", rc, shape.want, shape.name)
			}
		})
	}
}

// TestIssue665ParsePRCLIWitness drives the REAL `openant parse --pr`: the
// engine's record must show the isolated worktree, and the run must clean
// the workspace (the parse --pr path is the issue's own repro surface).
func TestIssue665ParsePRCLIWitness(t *testing.T) {
	for _, shape := range []struct {
		name string
		env  string
		want int
	}{
		{name: "success", env: "success", want: 0},
		{name: "engine-crash", env: "engine-crash", want: 2},
	} {
		t.Run(shape.name, func(t *testing.T) {
			repoDir, binDir, base, _ := issue665Env(t)
			issue665Preflight(t, binDir)
			out := t.TempDir()
			t.Setenv(issue665ShapeEnv, shape.env)
			rec, rc := issue665RunCLI(t, repoDir,
				"parse", repoDir, "--pr", "7", "-o", out)
			issue665AssertCommon(t, repoDir, base, rec)
			// NOTE (the r2 F1 catch): NO --commit-sha pin here — the parse
			// verb never threads a commit stamp (buildParsePyArgs emits no
			// --commit-sha), so a CommitSHA assertion would be vacuous.
			// The m10 pin is the SCAN arm's alone.
			if rec.Verb != "parse" {
				t.Errorf("the engine verb = %q, want parse", rec.Verb)
			}
			if rc != shape.want {
				t.Errorf("exit code = %d, want %d (the %s arm)", rc, shape.want, shape.name)
			}
		})
	}
}

// TestIssue665NonPRScanFallsBackToUserTree pins the threading's other side:
// WITHOUT --pr the engine reads the user's checkout itself — the scratch is
// a --pr-only behavior, never a default.
func TestIssue665NonPRScanFallsBackToUserTree(t *testing.T) {
	if os.Getenv(issue665RoleEnv) != "" {
		t.Skip("the helper roles must not run the witness drivers")
	}
	repoDir, binDir, base, _ := issue665Env(t)
	issue665Preflight(t, binDir)
	out := t.TempDir()
	t.Setenv(issue665ShapeEnv, "success")
	rec, _ := issue665RunCLI(t, repoDir,
		"scan", repoDir, "--skip-dynamic-test", "-o", out, "--no-report")
	if !rec.RepoIsUserClone {
		t.Errorf("a no-flag scan must read the user's checkout, got %s", rec.RepoPath)
	}
	if got := issue665Rev(t, repoDir, "HEAD"); got != base {
		t.Errorf("the user's checkout moved: %s -> %s", base, got)
	}
}
