package python

import (
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// TestInvoke_InterruptedFlagHasNoRace asserts that the `interrupted` flag —
// written by the SIGINT signal goroutine and read on the main goroutine after
// cmd.Wait — is synchronized. Under `go test -race` an unsynchronized bool
// (plain `interrupted := false` / `interrupted = true` / `if interrupted`)
// is reported as a DATA RACE, failing this test. With the atomic.Bool fix the
// accesses are ordered and the test passes.
//
// The test drives the real interrupt path: it starts Invoke on a subprocess
// that produces no stdout and sleeps well past the deadline, delivers a SIGINT
// to this process (signal.Notify inside Invoke intercepts it so the test
// runner is not killed), and waits for Invoke to return. Delivering the signal
// makes the goroutine execute `interrupted = true` concurrently with the main
// read, which is exactly what the race detector needs to observe.
func TestInvoke_InterruptedFlagHasNoRace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("interrupt-race test uses POSIX signals and a shell script")
	}

	hang := writeHangScript(t)

	// Backstop deadline so the test never hangs even if the signal path
	// somehow fails to terminate the subprocess.
	prev := defaultInvokeTimeout
	defaultInvokeTimeout = 8 * time.Second
	t.Cleanup(func() { defaultInvokeTimeout = prev })

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = Invoke(hang, []string{"parse", "."}, "", true, "")
	}()

	// Let Invoke start the subprocess and install its signal.Notify handler
	// before we deliver the interrupt.
	time.Sleep(300 * time.Millisecond)

	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess(self): %v", err)
	}
	if err := p.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("deliver SIGINT: %v", err)
	}

	select {
	case <-done:
		// Invoke returned after handling the interrupt. Under -race a data
		// race on `interrupted` (if unsynchronized) has already failed the test.
	case <-time.After(15 * time.Second):
		t.Fatalf("Invoke did not return after SIGINT within budget")
	}
}
