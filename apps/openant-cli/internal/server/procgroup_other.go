//go:build !unix

package server

import "os/exec"

// oNoFollow is 0 on non-unix (no portable O_NOFOLLOW); openRegularInRoot's Lstat
// symlink check is the cross-platform guard.
const oNoFollow = 0

// setProcGroupKill is a no-op on non-unix: exec.CommandContext's default cancel
// (kill the top process) applies.
func setProcGroupKill(cmd *exec.Cmd) {}
