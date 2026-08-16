package checkpoint

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDetectFallbackExcludesFingerprintSidecar verifies the I2 backend-identity
// sidecar (_fingerprint.json) is NOT counted as a completed unit by the
// Python-less fallback scanner, mirroring the Python _RESERVED_FILES exclusion.
func TestDetectFallbackExcludesFingerprintSidecar(t *testing.T) {
	scanDir := t.TempDir()
	dir := filepath.Join(scanDir, "analyze_checkpoints")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("unit1.json")
	write("unit2.json")
	write(summaryFile)     // must be excluded
	write(fingerprintFile) // must be excluded (the new sidecar)

	info := DetectFallback(scanDir, "analyze")
	if info == nil {
		t.Fatal("expected non-nil Info")
	}
	if info.Count != 2 {
		t.Fatalf("expected 2 counted units (sidecars excluded), got %d", info.Count)
	}
}

func TestIsSidecar(t *testing.T) {
	for _, name := range []string{summaryFile, fingerprintFile} {
		if !isSidecar(name) {
			t.Errorf("%q should be a sidecar", name)
		}
	}
	if isSidecar("unit1.json") {
		t.Error("a per-unit file must not be a sidecar")
	}
}
