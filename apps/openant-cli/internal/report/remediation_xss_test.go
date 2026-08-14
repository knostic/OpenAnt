package report

import (
	"strings"
	"testing"
)

// SafeRemediation renders LLM-authored HTML built from untrusted scanned-repo
// findings into a live report page. It must strip anything executable and keep
// only inert formatting.
func TestSafeRemediationStripsHostileHTML(t *testing.T) {
	hostile := []struct {
		name, in, mustNotContain string
	}{
		{"script tag", `<script>alert(1)</script><p>ok</p>`, "<script"},
		{"img onerror", `<img src=x onerror="alert(1)">`, "onerror"},
		{"javascript href", `<a href="javascript:alert(1)">x</a>`, "javascript:"},
		{"svg onload", `<svg onload=alert(1)></svg>`, "onload"},
		{"inline style expression", `<p style="width:expression(alert(1))">y</p>`, "expression"},
		{"iframe", `<iframe src="http://evil/"></iframe>`, "<iframe"},
		{"event handler on allowed tag", `<p onclick="alert(1)">y</p>`, "onclick"},
	}
	for _, tc := range hostile {
		t.Run(tc.name, func(t *testing.T) {
			d := ReportData{RemediationHTML: tc.in}
			got := strings.ToLower(string(d.SafeRemediation()))
			if strings.Contains(got, strings.ToLower(tc.mustNotContain)) {
				t.Fatalf("sanitized output still contains %q: %s", tc.mustNotContain, got)
			}
		})
	}
}

func TestSafeRemediationKeepsSafeFormatting(t *testing.T) {
	d := ReportData{RemediationHTML: `<p>Use <code>bcrypt</code>; see <a href="https://example.com/docs">the docs</a>.</p>`}
	got := string(d.SafeRemediation())
	for _, want := range []string{"<code>", "bcrypt", "<a", "https://example.com/docs"} {
		if !strings.Contains(got, want) {
			t.Errorf("safe formatting was stripped: missing %q in %s", want, got)
		}
	}
}
