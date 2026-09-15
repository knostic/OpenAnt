package python

import (
	"io"
	"os"
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

// TestInvokeQuietSuppressesStderr is the lineWriter-era counterpart to the
// old TestStreamStderrQuietSuppressesOutput. The quiet check itself moved
// out of any standalone stderr-writing function and into Invoke's onLog
// closure (invoke.go) that wraps the managed lineWriter -- lineWriter always
// calls onLog for every line regardless of quiet, so the suppression
// contract is only observable end-to-end through Invoke, not at the
// lineWriter unit level.
func TestInvokeQuietSuppressesStderr(t *testing.T) {
	s := writeScript(t, `printf '{"status":"success","errors":[]}'
echo "line one" >&2
echo "line two" >&2
`)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	old := os.Stderr
	os.Stderr = w
	res, invokeErr := Invoke(s, []string{"analyze", "."}, "", true, "", nil)
	os.Stderr = old
	_ = w.Close()
	b, _ := io.ReadAll(r)

	if invokeErr != nil {
		t.Fatalf("Invoke: %v", invokeErr)
	}
	if res.Envelope.Status != "success" {
		t.Fatalf("envelope status = %q, want success", res.Envelope.Status)
	}
	if got := string(b); got != "" {
		t.Fatalf("quiet=true: subprocess stderr reached os.Stderr: %q, want nothing", got)
	}
}

// TestInvokeNotQuietForwardsStderr is the quiet=false counterpart: ordinary
// subprocess stderr lines must still reach the terminal.
func TestInvokeNotQuietForwardsStderr(t *testing.T) {
	s := writeScript(t, `printf '{"status":"success","errors":[]}'
echo "line one" >&2
echo "line two" >&2
`)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	old := os.Stderr
	os.Stderr = w
	res, invokeErr := Invoke(s, []string{"analyze", "."}, "", false, "", nil)
	os.Stderr = old
	_ = w.Close()
	b, _ := io.ReadAll(r)

	if invokeErr != nil {
		t.Fatalf("Invoke: %v", invokeErr)
	}
	if res.Envelope.Status != "success" {
		t.Fatalf("envelope status = %q, want success", res.Envelope.Status)
	}
	got := string(b)
	if !strings.Contains(got, "line one") || !strings.Contains(got, "line two") {
		t.Fatalf("quiet=false: subprocess stderr not forwarded, got %q", got)
	}
}
