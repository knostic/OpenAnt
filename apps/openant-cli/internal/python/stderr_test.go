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

// TestStreamStderrQuietSuppressesOutput is streamStderr's `quiet=true`
// counterpart to TestStreamStderrLongLine (which only exercises
// quiet=false): every line must still be fully read from the source reader
// (so the caller's pipe never blocks/backs up), but none of it should reach
// os.Stderr.
func TestStreamStderrQuietSuppressesOutput(t *testing.T) {
	input := "line one\nline two\nline three\n"

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

	streamStderr(strings.NewReader(input), true)

	_ = pw.Close()
	os.Stderr = oldStderr
	<-copyDone
	_ = pr.Close()

	if got := buf.String(); got != "" {
		t.Fatalf("quiet=true streamStderr wrote %q to stderr, want nothing", got)
	}
}
