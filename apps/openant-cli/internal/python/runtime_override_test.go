package python

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// writeStubPython writes an executable that answers every probe the runtime
// makes (--version, the -c "from openant import __version__" import probe)
// the way a real Python would — the issue's own probe harness shape.
func writeStubPython(t *testing.T, dir, name, version string) string {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+
		"case \"$*\" in *--version*) echo \"Python "+version+"\"; exit 0;; esac\n"+
		"echo '3.14.0' # the __version__ probe's answer\n"+
		"exit 0\n"), 0o755); err != nil {
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
