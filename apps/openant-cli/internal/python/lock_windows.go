//go:build windows

package python

import (
	"os"
	"syscall"
)

// lockFileExcl takes an exclusive lock (LockFileEx). Blocks until
// acquired — the JS bootstrap's msvcrt.locking(LK_LOCK) semantics.
func lockFileExcl(f *os.File) error {
	// A 1-byte exclusive lock at offset 0 — the same shape
	// parser_adapter.py's _file_lock uses (position 0, 1 byte, so
	// overlapping ranges across processes are exclusive).
	ol := syscall.Overlapped{}
	return syscall.LockFileEx(
		syscall.Handle(f.Fd()),
		syscall.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ol)
}

// unlockFile releases the lock.
func unlockFile(f *os.File) error {
	ol := syscall.Overlapped{}
	return syscall.UnlockFileEx(
		syscall.Handle(f.Fd()), 0, &ol)
}
