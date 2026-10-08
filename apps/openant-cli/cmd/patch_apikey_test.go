package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// `openant patch --api-key`: an explicitly supplied root --api-key must reach
// the Python engine as ANTHROPIC_API_KEY on BOTH patch paths (Finding mode and
// CVE mode) -- the same transport every sibling command applies to an
// explicit flag. With no flag, patch must inject nothing and must not fail
// Go-side: Python owns provider/credential resolution (see runPatchFinding).
//
// runPatch always ends in os.Exit, so the CLI cannot run in-process. Instead
// this test binary re-executes itself in two helper roles, selected by
// patchAPIKeyRoleEnv -- plain Go, no shell shim, so the same test runs on the
// ubuntu/macOS/windows CI matrix without any real Python installed:
//
//   - "cli": TestPatchAPIKeyHelperCLI runs the real, unmodified rootCmd with
//     the argv after "--".
//   - "python": the init below impersonates the interpreter the CLI resolves
//     through OPENANT_PYTHON. It answers the version and import probes and,
//     on the engine invocation (`-P -m openant patch ...`), records ONLY
//     booleans about ANTHROPIC_API_KEY (compared by SHA-256 digest) before
//     emitting a success envelope.
//
// The sentinel key is never logged or persisted: assertions report booleans
// only, and child output surfaced on failure has the sentinel redacted.
// ---------------------------------------------------------------------------

const (
	patchAPIKeyRoleEnv       = "OPENANT_TEST_PATCH_APIKEY_ROLE"
	patchAPIKeyRecordEnv     = "OPENANT_TEST_PATCH_APIKEY_RECORD"
	patchAPIKeyWantDigestEnv = "OPENANT_TEST_PATCH_APIKEY_WANT_SHA256"

	patchAPIKeyRoleCLI    = "cli"
	patchAPIKeyRolePython = "python"

	// patchAPIKeySentinel is an obviously fake key; it is never a real
	// credential and must never appear in test output.
	patchAPIKeySentinel = "openant-patch-apikey-sentinel-not-a-real-key"
)

// patchAPIKeyRecord is everything the fake engine persists about its
// invocation: which patch path ran, plus booleans about ANTHROPIC_API_KEY --
// never the value, never a digest of it.
type patchAPIKeyRecord struct {
	Subcommand         string `json:"subcommand"`
	CVEMode            bool   `json:"cve_mode"`
	KeyPresent         bool   `json:"key_present"`
	KeyMatchesSentinel bool   `json:"key_matches_sentinel"`
}

func init() {
	// Must run before the testing package parses flags: the CLI invokes this
	// binary with interpreter argv (--version, -c ..., -P -m openant ...),
	// which the test flag parser would reject.
	if os.Getenv(patchAPIKeyRoleEnv) == patchAPIKeyRolePython {
		os.Exit(fakePythonForPatchAPIKey(os.Args[1:]))
	}
}

// fakePythonForPatchAPIKey answers exactly the three interpreter invocations
// `openant patch` makes (internal/python's checkPython, isOpenantImportable
// and Invoke) and fails loudly on anything else.
func fakePythonForPatchAPIKey(args []string) int {
	switch {
	case len(args) == 1 && args[0] == "--version":
		fmt.Println("Python 3.12.0") // checkPython: must report >= 3.11
		return 0
	case len(args) >= 1 && args[0] == "-c":
		// isOpenantImportable: report openant as installed so EnsureRuntime
		// keeps this binary and never creates a venv or runs pip.
		return 0
	case len(args) >= 4 && args[0] == "-P" && args[1] == "-m" && args[2] == "openant":
		key, set := os.LookupEnv("ANTHROPIC_API_KEY")
		sum := sha256.Sum256([]byte(key))
		rec := patchAPIKeyRecord{
			Subcommand:         args[3],
			CVEMode:            slices.Contains(args[4:], "--cve"),
			KeyPresent:         set && key != "",
			KeyMatchesSentinel: set && hex.EncodeToString(sum[:]) == os.Getenv(patchAPIKeyWantDigestEnv),
		}
		data, err := json.Marshal(rec)
		if err == nil {
			err = os.WriteFile(os.Getenv(patchAPIKeyRecordEnv), data, 0o600)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "fake python: cannot write record: %v\n", err)
			return 4
		}
		fmt.Println(`{"status":"success","data":{},"errors":[]}`)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "fake python: unexpected invocation (%d args)\n", len(args))
		return 3
	}
}

// TestPatchAPIKeyHelperCLI is not a test on its own: it is the "cli" helper
// role re-executed by runPatchAPIKeyCLI, and a no-op in a normal run.
func TestPatchAPIKeyHelperCLI(t *testing.T) {
	if os.Getenv(patchAPIKeyRoleEnv) != patchAPIKeyRoleCLI {
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
	// Every process the CLI spawns from here on -- the version probe, the
	// import probe and the engine invocation -- is the fake interpreter.
	t.Setenv(patchAPIKeyRoleEnv, patchAPIKeyRolePython)
	rootCmd.SetArgs(args[1:])
	if err := rootCmd.Execute(); err != nil {
		os.Exit(96)
	}
	// runPatch always exits the process itself; getting here means it never ran.
	os.Exit(98)
}

// patchAPIKeyModes are the two `openant patch` entry points. Each returns the
// subcommand argv for a run rooted at root; neither needs an active project.
var patchAPIKeyModes = []struct {
	name string
	cve  bool
	argv func(t *testing.T, root string) []string
}{
	{name: "finding", argv: func(t *testing.T, root string) []string {
		pipelineOutput := filepath.Join(root, "pipeline_output.json")
		if err := os.WriteFile(pipelineOutput, []byte(`{"findings":[]}`), 0o600); err != nil {
			t.Fatalf("write pipeline_output.json: %v", err)
		}
		return []string{"patch", pipelineOutput, "--finding-id", "VULN-001"}
	}},
	{name: "cve", cve: true, argv: func(t *testing.T, root string) []string {
		repo := filepath.Join(root, "repo")
		if err := os.MkdirAll(repo, 0o755); err != nil {
			t.Fatalf("mkdir repo: %v", err)
		}
		return []string{"patch", "--cve", "CVE-2022-25883", "--repo-root", repo}
	}},
}

// TestPatchForwardsExplicitAPIKey: `openant --api-key K patch ...` must hand K
// to the engine as ANTHROPIC_API_KEY on both paths. The regression passed a
// literal "" to python.Invoke, silently dropping the flag.
func TestPatchForwardsExplicitAPIKey(t *testing.T) {
	for _, mode := range patchAPIKeyModes {
		t.Run(mode.name, func(t *testing.T) {
			root := t.TempDir()
			argv := append([]string{"--api-key", patchAPIKeySentinel}, mode.argv(t, root)...)
			rec := runPatchAPIKeyCLI(t, root, argv...)
			assertPatchAPIKeyEngineRan(t, rec, mode.cve)
			if !rec.KeyPresent || !rec.KeyMatchesSentinel {
				t.Errorf("%s mode: explicit --api-key was not forwarded to the engine as ANTHROPIC_API_KEY (engine saw key_present=%v key_matches_sentinel=%v; want true/true)",
					mode.name, rec.KeyPresent, rec.KeyMatchesSentinel)
			}
		})
	}
}

// TestPatchWithoutAPIKeyFlagInjectsNoKey is the negative control: with no
// --api-key (and no key in the scrubbed env or the isolated config), patch
// must still reach the engine -- no Go-side preflight -- and inject no key.
func TestPatchWithoutAPIKeyFlagInjectsNoKey(t *testing.T) {
	for _, mode := range patchAPIKeyModes {
		t.Run(mode.name, func(t *testing.T) {
			root := t.TempDir()
			rec := runPatchAPIKeyCLI(t, root, mode.argv(t, root)...)
			assertPatchAPIKeyEngineRan(t, rec, mode.cve)
			if rec.KeyPresent {
				t.Errorf("%s mode: no --api-key was given, yet the engine received an ANTHROPIC_API_KEY (key_matches_sentinel=%v); patch must inject nothing without the flag",
					mode.name, rec.KeyMatchesSentinel)
			}
		})
	}
}

// assertPatchAPIKeyEngineRan pins that the engine saw the intended patch
// path, so neither test can pass by exercising the wrong entry point.
func assertPatchAPIKeyEngineRan(t *testing.T, rec patchAPIKeyRecord, wantCVE bool) {
	t.Helper()
	if rec.Subcommand != "patch" || rec.CVEMode != wantCVE {
		t.Fatalf("engine invoked as subcommand=%q cve_mode=%v; want subcommand=%q cve_mode=%v",
			rec.Subcommand, rec.CVEMode, "patch", wantCVE)
	}
}

// runPatchAPIKeyCLI runs `openant <cliArgs...>` in the "cli" helper role with
// the fake interpreter as OPENANT_PYTHON, ANTHROPIC_API_KEY scrubbed from the
// inherited env, and HOME plus every config dir pointed into root, so neither
// the developer's env nor their config.json can supply or mask a key. It
// returns what the fake engine recorded.
func runPatchAPIKeyCLI(t *testing.T, root string, cliArgs ...string) patchAPIKeyRecord {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	home := filepath.Join(root, "home")
	xdg := filepath.Join(root, "xdg")
	appData := filepath.Join(root, "appdata")
	for _, dir := range []string{home, xdg, appData} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	recordPath := filepath.Join(root, "engine-record.json")
	want := sha256.Sum256([]byte(patchAPIKeySentinel))

	env := patchAPIKeyEnvWithout(os.Environ(),
		"ANTHROPIC_API_KEY", "OPENANT_PYTHON",
		"HOME", "USERPROFILE", "XDG_CONFIG_HOME", "APPDATA",
		patchAPIKeyRoleEnv, patchAPIKeyRecordEnv, patchAPIKeyWantDigestEnv)
	env = append(env,
		patchAPIKeyRoleEnv+"="+patchAPIKeyRoleCLI,
		patchAPIKeyRecordEnv+"="+recordPath,
		patchAPIKeyWantDigestEnv+"="+hex.EncodeToString(want[:]),
		"OPENANT_PYTHON="+exe,
		"HOME="+home,
		"USERPROFILE="+home,
		"XDG_CONFIG_HOME="+xdg,
		"APPDATA="+appData,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, append([]string{"-test.run=^TestPatchAPIKeyHelperCLI$", "--"}, cliArgs...)...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openant patch helper process failed: %v\noutput (key redacted):\n%s", err, patchAPIKeyRedact(out))
	}
	data, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("the fake engine was never invoked, so patch never reached Python (%v)\noutput (key redacted):\n%s", err, patchAPIKeyRedact(out))
	}
	var rec patchAPIKeyRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("unreadable engine record: %v", err)
	}
	return rec
}

// patchAPIKeyEnvWithout returns a copy of env minus every entry named in
// keys, compared case-insensitively because Windows env names are.
func patchAPIKeyEnvWithout(env []string, keys ...string) []string {
	return slices.DeleteFunc(slices.Clone(env), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		return slices.ContainsFunc(keys, func(k string) bool { return strings.EqualFold(name, k) })
	})
}

// patchAPIKeyRedact masks the sentinel in child output surfaced on failure.
func patchAPIKeyRedact(out []byte) string {
	return strings.ReplaceAll(string(out), patchAPIKeySentinel, "<redacted>")
}
