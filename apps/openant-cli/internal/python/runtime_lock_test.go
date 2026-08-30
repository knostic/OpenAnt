package python

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// #62 (ar7casper, the extra-care protocol): concurrent venv installs must
// serialize on an OS-level lock, mirroring the JS bootstrap's pattern.
// ---------------------------------------------------------------------------

func TestVenvInstallLockIsExclusive(t *testing.T) {
	dir := t.TempDir()
	acquired := make(chan struct{}, 1)
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- withVenvInstallLock(dir, func() error {
			acquired <- struct{}{}
			<-release
			return nil
		})
	}()
	<-acquired // the first locker holds the lock
	secondEntered := make(chan struct{})
	go func() {
		_ = withVenvInstallLock(dir, func() error { return nil })
		close(secondEntered)
	}()
	select {
	case <-secondEntered:
		t.Errorf("the second locker entered while the first held the lock")
	case <-time.After(200 * time.Millisecond):
		// still blocked — correct
	}
	close(release)
	<-firstDone
	<-secondEntered
}

func TestVenvInstallLockReleasesOnExit(t *testing.T) {
	dir := t.TempDir()
	if err := withVenvInstallLock(dir, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	// after release, a second acquisition completes immediately
	done := make(chan error, 1)
	go func() { done <- withVenvInstallLock(dir, func() error { return nil }) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
		// entered immediately — correct
	case <-time.After(2 * time.Second):
		t.Errorf("the lock did not release on exit")
	}
}

func TestVenvInstallLockBodyRunsUnderTheLock(t *testing.T) {
	dir := t.TempDir()
	probe := make(chan struct{})
	err := withVenvInstallLock(dir, func() error {
		// the lockfile must EXIST while the body runs — the lock target
		// is the same filesystem as the venv (the JS pattern's "next to
		// the install target").
		if _, err := os.Stat(filepath.Join(dir, ".deps-install.lock")); err != nil {
			t.Errorf("the lockfile must exist under the lock: %v", err)
		}
		close(probe)
		return nil
	})
	<-probe
	if err != nil {
		t.Fatal(err)
	}
}
