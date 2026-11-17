//go:build !windows

package cmd

import (
	"os"
	"syscall"
)

// crashSelf is the engine-crash shape's abrupt death (POSIX): a SIGKILLed
// process yields no envelope on stdout. The windows twin
// (issue665_crash_windows_test.go) exits hard instead — syscall.Kill is
// POSIX-only and broke the windows vet (the cycle-3 CI catch).
func crashSelf() {
	_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
}
