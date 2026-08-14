package python

import (
	"testing"
	"time"
)

// The invoke timeout was a hardcoded 30m with no override, so a large-repo
// analyze/enhance that legitimately runs longer is killed mid-phase and its
// output is discarded. resolveInvokeTimeout lets an operator raise the budget
// via OPENANT_INVOKE_TIMEOUT (a Go duration like "2h", or a bare integer =
// seconds), falling back to the default when unset/invalid.

func TestResolveInvokeTimeout_EnvOverrides(t *testing.T) {
	cases := []struct {
		name string
		val  string
		want time.Duration
	}{
		{"duration form", "2h", 2 * time.Hour},
		{"minutes form", "90m", 90 * time.Minute},
		{"bare seconds", "5400", 5400 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("OPENANT_INVOKE_TIMEOUT", c.val)
			if got := resolveInvokeTimeout(); got != c.want {
				t.Fatalf("resolveInvokeTimeout()=%v, want %v", got, c.want)
			}
		})
	}
}

func TestResolveInvokeTimeout_UnsetUsesDefault(t *testing.T) {
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "")
	if got := resolveInvokeTimeout(); got != defaultInvokeTimeout {
		t.Fatalf("unset: resolveInvokeTimeout()=%v, want default %v", got, defaultInvokeTimeout)
	}
}

func TestResolveInvokeTimeout_InvalidFallsBackToDefault(t *testing.T) {
	for _, bad := range []string{"nonsense", "0", "-5", "12x"} {
		t.Setenv("OPENANT_INVOKE_TIMEOUT", bad)
		if got := resolveInvokeTimeout(); got != defaultInvokeTimeout {
			t.Fatalf("invalid %q: resolveInvokeTimeout()=%v, want default %v", bad, got, defaultInvokeTimeout)
		}
	}
}

func TestResolveInvokeTimeout_HugeSecondsDoesNotOverflow(t *testing.T) {
	// A bare-seconds integer so large that n*time.Second overflows int64 must
	// NOT wrap to a negative/near-zero duration (which would make the deadline
	// already-expired and kill the subprocess immediately — the exact failure
	// this knob prevents). Such values fall back to the default.
	for _, huge := range []string{
		"9999999999",           // ~292 years in seconds -> *1e9 overflows int64
		"99999999999999999999", // exceeds int range entirely
	} {
		t.Setenv("OPENANT_INVOKE_TIMEOUT", huge)
		got := resolveInvokeTimeout()
		if got <= 0 {
			t.Fatalf("huge %q: resolveInvokeTimeout()=%v is non-positive (overflow); "+
				"must fall back to a positive timeout", huge, got)
		}
		if got != defaultInvokeTimeout {
			t.Fatalf("huge %q: resolveInvokeTimeout()=%v, want default %v", huge, got, defaultInvokeTimeout)
		}
	}
}

// Wired proof: the env value must control the ACTUAL Invoke deadline, not just
// parse into a helper. With a large default and a tiny env override, a hung
// subprocess must be bounded by the ENV value. Pre-fix (env ignored) Invoke
// uses the 30s default and does NOT return within the budget -> RED.
func TestInvoke_EnvTimeoutBoundsHang(t *testing.T) {
	hang, _ := writeHangScript(t)

	prev := defaultInvokeTimeout
	defaultInvokeTimeout = 30 * time.Second // large, so only the env can make it fast
	t.Cleanup(func() { defaultInvokeTimeout = prev })
	t.Setenv("OPENANT_INVOKE_TIMEOUT", "500ms")

	const budget = 10 * time.Second // << 30s default, >> 500ms env deadline
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = Invoke(hang, []string{"parse", "."}, "", true, "")
	}()

	select {
	case <-done:
		// Returned within budget — the env timeout (500ms) bounded the hang.
	case <-time.After(budget):
		t.Fatalf("Invoke did not return within %v; OPENANT_INVOKE_TIMEOUT=500ms "+
			"was not wired into the deadline (default=%v)", budget, defaultInvokeTimeout)
	}
}
