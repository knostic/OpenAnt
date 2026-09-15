package server

import (
	"testing"
)

// #320: the deadline kill maps to the DISTINCT "timeout" terminal state —
// the UI can say "timed out, raise the budget" and the slot-release story is
// visible — while a generic error stays "error" and a done scan "done".
func TestJobTimeoutStatus(t *testing.T) {
	j := &Job{Status: StatusRunning}
	j.setTimeout()
	if j.Status != StatusTimeout {
		t.Fatalf("a running job's deadline maps to timeout; got %q", j.Status)
	}
	// idempotent on a terminal state (a racing setError must not be overwritten)
	j2 := &Job{Status: StatusError}
	j2.setTimeout()
	if j2.Status != StatusError {
		t.Fatalf("an already-errored job must not become timeout; got %q", j2.Status)
	}
}
