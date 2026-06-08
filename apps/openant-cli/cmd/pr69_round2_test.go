package cmd

import (
	"strings"
	"testing"

	"github.com/knostic/open-ant-cli/internal/config"
)

// M-d: a blank API key means "read from the environment"; the wizard must
// skip the probe (which would 401 on an empty key) rather than dead-end.
func TestProbeAllPhases_SkipsBlankKey(t *testing.T) {
	providers := map[string]config.ProviderEntry{
		"anthropic": {Type: "anthropic", APIKey: "", BaseURL: ""},
	}
	phases := map[string]config.LLMPhaseRef{
		"analyze": {Provider: "anthropic", Model: "claude-x"},
	}
	if err := probeAllPhases(providers, phases); err != nil {
		t.Fatalf("blank key should skip the probe (no network, no error), got: %v", err)
	}
}

// Low: redactKeyParam must remove the key but not swallow the closing URL
// delimiter (`":`) in a *url.Error string.
func TestRedactKeyParam_StopsAtURLDelimiter(t *testing.T) {
	in := `Post "https://x/v1beta/models/m:generateContent?key=SECRETKEY123": dial tcp: refused`
	out := redactKeyParam(in)
	if strings.Contains(out, "SECRETKEY123") {
		t.Errorf("key not redacted: %s", out)
	}
	if !strings.Contains(out, "key=REDACTED") {
		t.Errorf("expected key=REDACTED, got: %s", out)
	}
	if !strings.Contains(out, `": dial tcp`) {
		t.Errorf("URL delimiter swallowed: %s", out)
	}
}
