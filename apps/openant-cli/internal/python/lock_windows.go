//go:build windows

package python

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockFileExcl takes an exclusive lock (LockFileEx). Blocks until
// acquired — the JS bootstrap's msvcrt.locking(LK_LOCK) semantics.
func lockFileExcl(f *os.File) error {
	// A 1-byte exclusive lock at offset 0 — the same shape
	// parser_adapter.py's _file_lock uses (position 0, 1 byte, so
	// overlapping ranges across processes are exclusive).
	// Review fix: Go's stdlib syscall package on Windows exposes neither
	// LockFileEx nor LockFile (the original implementation and the first
	// stdlib retry never compiled on windows-latest CI). golang.org/x/sys
	// was already in the module graph — windows.LockFileEx is the
	// canonical binding.
	var ol windows.Overlapped
	return windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ol)
}

// unlockFile releases the lock.
func unlockFile(f *os.File) error {
	var ol windows.Overlapped
	return windows.UnlockFileEx(
		windows.Handle(f.Fd()), 0, 1, 0, &ol)
}
