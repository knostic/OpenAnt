package python

import (
	"strings"
	"testing"
)

// TestLineWriterLongLine guards against truncation of a stderr line that
// exceeds bufio.Scanner's default 64k token buffer. A long Python traceback
// on a single line must reach the terminal in full, not be silently dropped.
// (#431: the guarantee moved from streamStderr's bufio.Reader to the managed
// lineWriter that replaced it — a single partial line is buffered whole and
// flushed after Wait, with a 1MB cap for pathologically long lines.)
func TestLineWriterLongLine(t *testing.T) {
	const size = 200 * 1024 // > 64k default scanner buffer
	long := strings.Repeat("x", size)

	var got []string
	lw := &lineWriter{onLog: func(s string) { got = append(got, s) }}
	// delivered in small Write chunks, as os/exec's copy goroutine does
	for len(long) > 0 {
		n := 4096
		if n > len(long) {
			n = len(long)
		}
		if _, err := lw.Write([]byte(long[:n])); err != nil {
			t.Fatalf("Write: %v", err)
		}
		long = long[n:]
	}
	lw.flush()

	if len(got) != 1 || len(got[0]) != size {
		t.Fatalf("stderr line truncated: got %d line(s), first len %d, want one line of %d",
			len(got), len(got[0]), size)
	}
}
