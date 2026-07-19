package python

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// TestStreamStderrLongLine guards against truncation of a stderr line that
// exceeds bufio.Scanner's default 64k token buffer. A long Python traceback
// on a single line must reach os.Stderr in full, not be silently dropped.
func TestStreamStderrLongLine(t *testing.T) {
	const size = 200 * 1024 // > 64k default scanner buffer
	long := strings.Repeat("x", size)
	input := long + "\n"

	oldStderr := os.Stderr
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = pw

	var buf bytes.Buffer
	copyDone := make(chan struct{})
	go func() {
		defer close(copyDone)
		_, _ = io.Copy(&buf, pr)
	}()

	streamStderr(strings.NewReader(input), false)

	_ = pw.Close()
	os.Stderr = oldStderr
	<-copyDone
	_ = pr.Close()

	got := strings.TrimRight(buf.String(), "\n")
	if len(got) != size {
		t.Fatalf("stderr line truncated: got %d bytes, want %d", len(got), size)
	}
}
