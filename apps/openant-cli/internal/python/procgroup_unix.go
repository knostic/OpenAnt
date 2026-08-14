//go:build unix

package python

import (
	"os/exec"
	"syscall"
)

// setProcGroupKill runs the child in its own process group and, on context
// cancellation, SIGKILLs the whole group so descendants (parallel workers) die
// too. Unix-only; the non-unix build falls back to exec's default single-process
// kill.
func setProcGroupKill(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
}
