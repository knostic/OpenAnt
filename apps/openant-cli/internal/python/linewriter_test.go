package python

import (
	"strings"
	"testing"
)

// lineWriter must forward complete lines as they arrive (across arbitrary Write
// chunk boundaries), hold a trailing partial line until flush, and cap a single
// pathologically long line so a repo can't exhaust memory.
func TestLineWriter(t *testing.T) {
	var got []string
	w := &lineWriter{onLog: func(s string) { got = append(got, s) }}

	// Lines split across chunk boundaries.
	w.Write([]byte("alpha\nbra"))
	w.Write([]byte("vo\ncharlie\n"))
	w.Write([]byte("delta")) // partial, no newline yet
	if want := []string{"alpha", "bravo", "charlie"}; !equal(got, want) {
		t.Fatalf("mid-stream lines = %v, want %v", got, want)
	}
	w.flush() // emits the trailing partial
	if want := []string{"alpha", "bravo", "charlie", "delta"}; !equal(got, want) {
		t.Fatalf("after flush = %v, want %v", got, want)
	}

	// A >1MB partial line is emitted rather than buffered unboundedly.
	got = nil
	w2 := &lineWriter{onLog: func(s string) { got = append(got, s) }}
	w2.Write([]byte(strings.Repeat("x", 1024*1024+10)))
	if len(got) != 1 || len(got[0]) < 1024*1024 {
		t.Fatalf("oversized partial line not force-emitted: emitted %d line(s)", len(got))
	}

	// nil onLog must not panic.
	w3 := &lineWriter{}
	w3.Write([]byte("ignored\n"))
	w3.flush()
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
