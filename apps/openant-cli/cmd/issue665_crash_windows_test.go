//go:build windows

package cmd

import "os"

// crashSelf is the engine-crash shape's abrupt death (windows): a hard
// os.Exit with no stdout — the same no-envelope semantics as the POSIX
// SIGKILL twin.
func crashSelf() {
	os.Exit(7)
}
