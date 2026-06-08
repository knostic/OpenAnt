package config

import "testing"

// P2: MaskKey must never panic on a short key (key[:3] was out of range for
// len<3) and must never reveal a whole short key.
func TestMaskKey_ShortKeysDoNotPanicOrLeak(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "(not set)"},
		{"a", "****"},
		{"ab", "****"},
		{"abc", "****"},
		{"abcde", "****"},
		{"abcdefg", "****"}, // len 7, still < 8
	}
	for _, c := range cases {
		got := MaskKey(c.in) // must not panic
		if got != c.want {
			t.Errorf("MaskKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	// A realistic key is masked, not echoed back in full.
	const real = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"
	if MaskKey(real) == real {
		t.Error("long key was not masked")
	}
}
