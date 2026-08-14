//go:build unix

package server

import (
	"os/exec"
	"syscall"
)

// oNoFollow makes os.OpenFile refuse a symlink at the final path component,
// atomically closing the check-then-open race. Unix-only; 0 elsewhere (the
// Lstat guard in openRegularInRoot still rejects symlinks, just non-atomically).
const oNoFollow = syscall.O_NOFOLLOW

// setProcGroupKill runs git in its own process group and SIGKILLs the whole
// group on cancel, so helpers (git-remote-https, ssh) die too.
func setProcGroupKill(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
}
