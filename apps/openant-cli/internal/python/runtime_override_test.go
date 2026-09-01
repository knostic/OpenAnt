package python

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// writeStubPython writes an executable that answers every probe the runtime
// makes (--version, the -c "from openant import __version__" import probe)
// the way a real Python would — the issue's own probe harness shape.
// writeStubPython answers BOTH probes (version + the openant import) — the
// self-sufficient override shape.
func writeStubPython(t *testing.T, dir, name, version string) string {
	return writeStubPythonProbe(t, dir, name, version, true)
}

// writeStubPythonProbe answers the version probe and, per importable, the
// openant-import probe — the "version-valid but NOT self-sufficient"
// override is the documented CI/container pin shape (wave r1, three axes).
func writeStubPythonProbe(t *testing.T, dir, name, version string, importable bool) string {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}
	script := "#!/bin/sh\n" +
		"case \"$*\" in *--version*) echo \"Python " + version + "\"; exit 0;; esac\n"
	if importable {
		script += "echo '3.14.0' # the __version__ probe's answer\nexit 0\n"
	} else {
		script += "echo 'ModuleNotFoundError: No module named openant' >&2\nexit 1\n"
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// A valid, explicitly-set OPENANT_PYTHON override must not be silently
// replaced by the managed venv (#437's live probe: the stub answered both
// probes, then the REAL venv parser ran — the override ignored, no warning,
// with the README documenting the opposite precedence).
func TestPreferVenvKeepsUsableOverride(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// The managed venv at $HOME/.openant/venv/bin/python — present and
	// answering every probe (the normal install state).
	venvBin := filepath.Join(home, ".openant", "venv", "bin")
	if err := os.MkdirAll(venvBin, 0o755); err != nil {
		t.Fatal(err)
	}
	venvPy := writeStubPython(t, venvBin, "python", "3.14.0")
	_ = venvPy

	override := writeStubPython(t, t.TempDir(), "stub-python", "3.14.0")
	t.Setenv("OPENANT_PYTHON", override)

	rt := preferVenv(&RuntimeInfo{Path: override, Major: 3, Minor: 14})
	if rt.Path != override {
		t.Fatalf("the explicit OPENANT_PYTHON override was silently replaced: want %q, got the venv %q — the README documents the override TAKES PRECEDENCE over the managed venv", override, rt.Path)
	}
}

// The non-override path is unchanged: a runtime detected from PATH (or the
// venv itself, freshly created by CheckOpenantInstalled) still prefers the
// managed venv — the #59 install-state semantics.
func TestPreferVenvStillPrefersVenvWithoutOverride(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	venvBin := filepath.Join(home, ".openant", "venv", "bin")
	if err := os.MkdirAll(venvBin, 0o755); err != nil {
		t.Fatal(err)
	}
	writeStubPython(t, venvBin, "python", "3.14.0")

	t.Setenv("OPENANT_PYTHON", "")
	rt := preferVenv(&RuntimeInfo{Path: "/usr/bin/python3", Major: 3, Minor: 14})
	if rt.Path == "/usr/bin/python3" {
		t.Fatalf("the managed venv must still be preferred when no override is active")
	}
}

// #437 (wave r1, three axes): a version-valid override WITHOUT openant is
// the documented CI/container pin shape — CheckOpenantInstalled bootstrapped
// the managed venv for exactly it (the local pythonPath reassignment cannot
// reach the caller), and keeping the bare override returned an interpreter
// that failed EVERY invocation. The venv — built FROM the override's
// interpreter — wins; the pin is honoured at the base level.
func TestPreferVenvFallsToVenvForNonImportableOverride(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	venvBin := filepath.Join(home, ".openant", "venv", "bin")
	if err := os.MkdirAll(venvBin, 0o755); err != nil {
		t.Fatal(err)
	}
	venvPy := writeStubPython(t, venvBin, "python", "3.14.0") // self-sufficient
	_ = venvPy

	override := writeStubPythonProbe(t, t.TempDir(), "bare-python", "3.14.0", false)
	t.Setenv("OPENANT_PYTHON", override)

	rt := preferVenv(&RuntimeInfo{Path: override, Major: 3, Minor: 14})
	if rt.Path == override {
		t.Fatalf("a non-importable override was kept: %q — CheckOpenantInstalled bootstrapped the venv for exactly this shape, and keeping the bare path yields ModuleNotFoundError on every run", override)
	}
}

// famD panel (sonnet): the deps-hash skip for an active override is
// end-to-end pinned — a STALE venv hash must not drive an install into the
// override interpreter (the hash is the venv's, not the override's).
func TestEnsureRuntime_SkipsDepsForOverride(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix venv-python path shape")
	}
	// a stale hash at the venv location that does NOT match the real one
	venv := t.TempDir()
	t.Setenv("HOME", filepath.Dir(venv)) // venvPython() = $HOME/.openant/venv
	fakeVenv := filepath.Join(filepath.Dir(venv), ".openant", "venv")
	_ = os.MkdirAll(fakeVenv, 0o755)
	_ = os.WriteFile(filepath.Join(fakeVenv, ".deps-hash"), []byte("stale-deadbeef"), 0o644)

	// an override that is a REAL usable python (the test binary's own interpreter is not available; use python3 from PATH if present)
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not on PATH")
	}
	t.Setenv("OPENANT_PYTHON", py)
	// the import probe must find the openant engine relative to this test's
	// own checkout (the repo layout), not require a pip install.
	if core := os.Getenv("OPENANT_CORE_PATH"); core == "" {
		t.Skip("OPENANT_CORE_PATH not set (repo-layout-dependent e2e)")
	}

	_, rterr := EnsureRuntime()
	if rterr != nil {
		t.Fatalf("EnsureRuntime with an override must not fail: %v", rterr)
	}
	// the stale venv hash must be UNTOUCHED (no install ran against it)
	h, _ := os.ReadFile(filepath.Join(fakeVenv, ".deps-hash"))
	if string(h) != "stale-deadbeef" {
		t.Fatalf("the venv hash must not be rewritten under an override: %q", h)
	}
}
