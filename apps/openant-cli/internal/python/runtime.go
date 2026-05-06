// Package python handles Python runtime detection and validation.
package python

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// MinPythonMajor is the minimum required Python major version.
const MinPythonMajor = 3

// MinPythonMinor is the minimum required Python minor version.
const MinPythonMinor = 11

// RuntimeInfo holds information about the detected Python runtime.
type RuntimeInfo struct {
	Path    string // Full path to the Python binary
	Version string // Version string (e.g., "3.11.5")
	Major   int
	Minor   int
}

// pythonCandidates returns a list of Python binary names to search for, in order of preference.
func pythonCandidates() []string {
	return []string{"python3", "python"}
}

// venvDir returns the path to the managed venv: ~/.openant/venv/
func venvDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".openant", "venv")
}

// venvPython returns the path to the Python binary inside the managed venv.
func venvPython() string {
	return filepath.Join(venvDir(), "bin", "python")
}

// DetectRuntime finds a suitable Python 3.11+ installation.
//
// Search order:
//  1. OPENANT_PYTHON env var (if set and valid) — set this to pin a specific
//     interpreter for debugging, CI, or container use (e.g. OPENANT_PYTHON=python3.11).
//  2. Managed venv at ~/.openant/venv/ (if it exists and is valid)
//  3. python3 / python on PATH
//
// Note: the managed-venv path (strategy 2) uses "bin/python" which is correct
// on Linux/macOS. On Windows the venv layout uses "Scripts\python.exe"; users
// on Windows who rely on the managed venv should set OPENANT_PYTHON explicitly
// to point at the desired interpreter.
func DetectRuntime() (*RuntimeInfo, error) {
	// Strategy 0: honour explicit override via OPENANT_PYTHON env var.
	// If the override is set but unusable, warn and fall through rather than
	// silently using a different interpreter behind the caller's back.
	if override := os.Getenv("OPENANT_PYTHON"); override != "" {
		info, err := checkPython(override)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"warning: OPENANT_PYTHON=%q is not a usable Python binary (%v); ignoring override\n",
				override, err)
		} else if info.Major > MinPythonMajor || (info.Major == MinPythonMajor && info.Minor >= MinPythonMinor) {
			return info, nil
		} else {
			fmt.Fprintf(os.Stderr,
				"warning: OPENANT_PYTHON=%q is Python %s, below the required %d.%d; ignoring override\n",
				override, info.Version, MinPythonMajor, MinPythonMinor)
		}
	}

	// Strategy 1: check managed venv
	vp := venvPython()
	if fileExists(vp) {
		if info, err := checkPython(vp); err == nil {
			if info.Major > MinPythonMajor || (info.Major == MinPythonMajor && info.Minor >= MinPythonMinor) {
				return info, nil
			}
		}
	}

	// Strategy 2: check PATH
	for _, name := range pythonCandidates() {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}

		info, err := checkPython(path)
		if err != nil {
			continue
		}

		if info.Major > MinPythonMajor || (info.Major == MinPythonMajor && info.Minor >= MinPythonMinor) {
			return info, nil
		}
	}

	return nil, fmt.Errorf(
		"Python %d.%d+ is required but not found on PATH.\n"+
			"Install Python from https://python.org or use your system package manager.",
		MinPythonMajor, MinPythonMinor,
	)
}

// checkPython runs the given binary and extracts version info.
func checkPython(path string) (*RuntimeInfo, error) {
	out, err := exec.Command(path, "--version").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run %s: %w", path, err)
	}

	// Output is "Python X.Y.Z\n"
	version := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "Python "))
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("unexpected version format: %s", version)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid major version: %s", parts[0])
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid minor version: %s", parts[1])
	}

	return &RuntimeInfo{
		Path:    path,
		Version: version,
		Major:   major,
		Minor:   minor,
	}, nil
}

// CheckOpenant Installed verifies that the `openant` package is importable.
// If the package is missing, it attempts to:
//  1. Locate libs/openant-core
//  2. Create a managed venv at ~/.openant/venv/ (if not using one already)
//  3. Install openant into the venv
//
// On success, it updates the RuntimeInfo to point to the venv Python.
func CheckOpenantInstalled(pythonPath string) error {
	if isOpenantImportable(pythonPath) {
		return nil
	}

	// Not installed — try to find the source and install it.
	corePath, err := findOpenantCore()
	if err != nil {
		return fmt.Errorf(
			"openant Python package is not installed and could not be located automatically.\n"+
				"Install it with: pip install -e <path-to-openant-core>\n"+
				"(%s)", err,
		)
	}

	// If we're not already using the managed venv, create one and use it.
	vp := venvPython()
	if pythonPath != vp {
		fmt.Fprintln(os.Stderr, "Creating managed Python environment at ~/.openant/venv/...")
		if err := createVenv(pythonPath); err != nil {
			return fmt.Errorf(
				"failed to create venv at %s: %w\n"+
					"Try manually: %s -m venv %s && %s -m pip install -e %s",
				venvDir(), err, pythonPath, venvDir(), vp, corePath,
			)
		}
		pythonPath = vp
	}

	fmt.Fprintf(os.Stderr, "Installing openant from %s...\n", corePath)
	if err := installOpenant(pythonPath, corePath); err != nil {
		return fmt.Errorf(
			"failed to install openant from %s:\n  %w\n"+
				"Try manually: %s -m pip install -e %s",
			corePath, err, pythonPath, corePath,
		)
	}

	// Verify it actually worked.
	if !isOpenantImportable(pythonPath) {
		return fmt.Errorf(
			"pip install succeeded but `import openant` still fails.\n"+
				"Try manually: %s -m pip install -e %s",
			pythonPath, corePath,
		)
	}

	fmt.Fprintln(os.Stderr, "openant installed successfully.")
	return nil
}

// EnsureRuntime is a convenience that detects a runtime, ensures openant
// is installed (creating a venv if necessary), and returns the final
// RuntimeInfo pointing to the correct Python binary.
func EnsureRuntime() (*RuntimeInfo, error) {
	rt, err := DetectRuntime()
	if err != nil {
		return nil, err
	}

	if err := CheckOpenantInstalled(rt.Path); err != nil {
		return nil, err
	}

	// After CheckOpenantInstalled, the venv may have been created.
	// Re-detect to pick up the venv Python if it was just created.
	vp := venvPython()
	if rt.Path != vp && fileExists(vp) && isOpenantImportable(vp) {
		if info, err := checkPython(vp); err == nil {
			return info, nil
		}
	}

	return rt, nil
}

// createVenv creates a new venv at ~/.openant/venv/ using the given Python.
func createVenv(pythonPath string) error {
	dir := venvDir()
	if err := os.MkdirAll(filepath.Dir(dir), 0755); err != nil {
		return err
	}
	cmd := exec.Command(pythonPath, "-m", "venv", dir)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// isOpenantImportable returns true if `python -c "import openant"` succeeds.
func isOpenantImportable(pythonPath string) bool {
	cmd := exec.Command(pythonPath, "-c", "from openant import __version__")
	return cmd.Run() == nil
}

// installOpenant runs `python -m pip install -e <corePath>`.
func installOpenant(pythonPath, corePath string) error {
	cmd := exec.Command(pythonPath, "-m", "pip", "install", "-e", corePath)
	cmd.Stdout = os.Stderr // pip output goes to stderr so it doesn't pollute JSON stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// PipUninstall returns an *exec.Cmd that runs `python -m pip uninstall openant -y`.
func PipUninstall(pythonPath string) *exec.Cmd {
	cmd := exec.Command(pythonPath, "-m", "pip", "uninstall", "openant", "-y")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd
}

// findOpenantCore locates the libs/openant-core directory by checking:
//  1. Relative to the running executable (walk up looking for libs/openant-core/pyproject.toml)
//  2. Relative to the current working directory
func findOpenantCore() (string, error) {
	marker := filepath.Join("libs", "openant-core", "pyproject.toml")

	// Strategy 1: walk up from the executable.
	if exePath, err := os.Executable(); err == nil {
		exePath, _ = filepath.EvalSymlinks(exePath)
		dir := filepath.Dir(exePath)
		for range 6 { // at most 6 levels up
			candidate := filepath.Join(dir, "libs", "openant-core")
			if fileExists(filepath.Join(dir, marker)) {
				return candidate, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}

	// Strategy 2: walk up from CWD.
	if cwd, err := os.Getwd(); err == nil {
		dir := cwd
		for range 6 {
			candidate := filepath.Join(dir, "libs", "openant-core")
			if fileExists(filepath.Join(dir, marker)) {
				return candidate, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}

	return "", fmt.Errorf("could not find libs/openant-core from executable or working directory")
}

// fileExists is a small helper that returns true if path exists and is not a directory.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
