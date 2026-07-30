package python

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// mergeEnv: pure helper, no subprocess involved.
// ---------------------------------------------------------------------------

func TestMergeEnv_OverrideWinsOverDuplicate(t *testing.T) {
	base := []string{"FOO=old", "BAR=unrelated"}
	got := mergeEnv(base, map[string]string{"FOO": "new"})

	want := map[string]string{"FOO": "new", "BAR": "unrelated"}
	assertEnvEquals(t, got, want)
}

func TestMergeEnv_UnrelatedValuesPreserved(t *testing.T) {
	base := []string{"A=1", "B=2", "C=3"}
	got := mergeEnv(base, map[string]string{"D": "4"})

	want := map[string]string{"A": "1", "B": "2", "C": "3", "D": "4"}
	assertEnvEquals(t, got, want)
}

func TestMergeEnv_EmptyOverridesReturnsBaseUnchanged(t *testing.T) {
	base := []string{"A=1"}
	got := mergeEnv(base, nil)
	if !reflect.DeepEqual(got, base) {
		t.Fatalf("mergeEnv with no overrides = %v, want unchanged %v", got, base)
	}
}

func TestMergeEnv_DoesNotMutateBaseSlice(t *testing.T) {
	base := []string{"FOO=old"}
	baseCopy := append([]string(nil), base...)
	_ = mergeEnv(base, map[string]string{"FOO": "new"})
	if !reflect.DeepEqual(base, baseCopy) {
		t.Fatalf("mergeEnv mutated its base input: got %v, want unchanged %v", base, baseCopy)
	}
}

func TestMergeEnv_DeterministicAcrossCalls(t *testing.T) {
	base := []string{"A=1"}
	overrides := map[string]string{"Z": "1", "M": "2", "A": "3"}
	first := mergeEnv(base, overrides)
	second := mergeEnv(base, overrides)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("mergeEnv is non-deterministic across identical calls:\n%v\n%v", first, second)
	}
}

func assertEnvEquals(t *testing.T, env []string, want map[string]string) {
	t.Helper()
	got := map[string]string{}
	for _, kv := range env {
		idx := strings.IndexByte(kv, '=')
		if idx < 0 {
			t.Fatalf("malformed env entry %q", kv)
		}
		got[kv[:idx]] = kv[idx+1:]
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("env = %v, want %v", got, want)
	}
}

// ---------------------------------------------------------------------------
// Invoke: extraEnv reaches the subprocess, overrides win, unrelated env is
// preserved, no global mutation, stdin is connected, secrets never leak into
// returned error text.
// ---------------------------------------------------------------------------

func writeEnvEchoScript(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("env-echo test uses a POSIX shell script")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "echo_env.sh")
	// Reads one optional stdin line and echoes both env vars and the stdin
	// line back in a success envelope, so a single subprocess run can assert
	// on env propagation and stdin connectivity together.
	script := "#!/bin/sh\n" +
		"read line\n" +
		"printf '{\"status\":\"success\",\"data\":{\"my_test_var\":\"%s\",\"my_other_var\":\"%s\",\"stdin_line\":\"%s\"},\"errors\":[]}\\n' " +
		"\"$MY_TEST_VAR\" \"$MY_OTHER_VAR\" \"$line\"\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}
	return path
}

func dataString(t *testing.T, res *InvokeResult, key string) string {
	t.Helper()
	m, ok := res.Envelope.Data.(map[string]any)
	if !ok {
		t.Fatalf("envelope data is not a map: %#v", res.Envelope.Data)
	}
	v, ok := m[key].(string)
	if !ok {
		t.Fatalf("envelope data[%q] missing or not a string: %#v", key, m)
	}
	return v
}

func TestInvoke_ExtraEnvReachesSubprocess(t *testing.T) {
	script := writeEnvEchoScript(t)
	res, err := Invoke(script, nil, "", true, "", map[string]string{"MY_TEST_VAR": "hello"})
	if err != nil {
		t.Fatalf("Invoke returned error: %v", err)
	}
	if got := dataString(t, res, "my_test_var"); got != "hello" {
		t.Fatalf("subprocess saw MY_TEST_VAR=%q, want %q", got, "hello")
	}
}

func TestInvoke_ExtraEnvOverridesExistingProcessValue(t *testing.T) {
	t.Setenv("MY_TEST_VAR", "original")
	script := writeEnvEchoScript(t)

	res, err := Invoke(script, nil, "", true, "", map[string]string{"MY_TEST_VAR": "override"})
	if err != nil {
		t.Fatalf("Invoke returned error: %v", err)
	}
	if got := dataString(t, res, "my_test_var"); got != "override" {
		t.Fatalf("subprocess saw MY_TEST_VAR=%q, want %q (override should win)", got, "override")
	}

	// The calling (test) process's own environment must be untouched.
	if got := os.Getenv("MY_TEST_VAR"); got != "original" {
		t.Fatalf("Invoke mutated this process's own MY_TEST_VAR to %q; must remain %q", got, "original")
	}
}

func TestInvoke_UnrelatedEnvValuesArePreserved(t *testing.T) {
	t.Setenv("MY_OTHER_VAR", "unrelated")
	script := writeEnvEchoScript(t)

	res, err := Invoke(script, nil, "", true, "", map[string]string{"MY_TEST_VAR": "hello"})
	if err != nil {
		t.Fatalf("Invoke returned error: %v", err)
	}
	if got := dataString(t, res, "my_other_var"); got != "unrelated" {
		t.Fatalf("subprocess saw MY_OTHER_VAR=%q, want unrelated value preserved", got)
	}
}

func TestInvoke_NoGlobalEnvironmentMutationFromExtraEnv(t *testing.T) {
	os.Unsetenv("MY_TEST_VAR_NEVER_SET")
	script := writeEnvEchoScript(t)

	_, err := Invoke(script, nil, "", true, "", map[string]string{"MY_TEST_VAR_NEVER_SET": "subprocess-only"})
	if err != nil {
		t.Fatalf("Invoke returned error: %v", err)
	}
	if _, ok := os.LookupEnv("MY_TEST_VAR_NEVER_SET"); ok {
		t.Fatalf("Invoke leaked an extraEnv-only variable into this process's own environment via os.Setenv")
	}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "MY_TEST_VAR_NEVER_SET=") {
			t.Fatalf("this process's os.Environ() unexpectedly contains MY_TEST_VAR_NEVER_SET")
		}
	}
}

func TestInvoke_StdinIsConnected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stdin-pipe test uses os.Pipe")
	}
	script := writeEnvEchoScript(t)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if _, err := w.WriteString("hello-from-test-stdin\n"); err != nil {
		t.Fatalf("write to pipe: %v", err)
	}
	w.Close()
	origStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = origStdin
		r.Close()
	})

	res, err := Invoke(script, nil, "", true, "", nil)
	if err != nil {
		t.Fatalf("Invoke returned error: %v", err)
	}
	if got := dataString(t, res, "stdin_line"); got != "hello-from-test-stdin" {
		t.Fatalf("subprocess read stdin line %q, want %q -- Invoke's cmd.Stdin is not connected", got, "hello-from-test-stdin")
	}
}

func writeFailingScript(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("failing-script test uses a POSIX shell script")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "fail.sh")
	// Exits 0 with no stdout at all -- Invoke's own empty-stdout handling
	// (see TestInvoke_EmptyStdoutSurfacesErrorCode) turns this into an error
	// envelope without this script ever needing to reference its env itself.
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}
	return path
}

func TestInvoke_SecretExtraEnvValueNeverAppearsInErrorText(t *testing.T) {
	script := writeFailingScript(t)
	const secret = "sk-super-secret-test-value"

	res, err := Invoke(script, nil, "", true, "", map[string]string{"ANTHROPIC_API_KEY": secret})
	if err != nil {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("Invoke's returned error contains the secret extraEnv value: %v", err)
		}
		return
	}
	for _, e := range res.Envelope.Errors {
		if strings.Contains(e, secret) {
			t.Fatalf("Invoke's error envelope contains the secret extraEnv value: %v", e)
		}
	}
}
