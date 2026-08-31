package report

import (
	"strings"
	"testing"
)

// #332: the report templates loaded three third-party scripts from public
// CDNs with NO Subresource Integrity — chart.js carried no version at all,
// chartjs-plugin-datalabels pinned a major only, and cdn.tailwindcss.com is a
// mutable runtime generator (an SRI hash would break on upstream change). The
// page holds the findings of a security scan, is served by `openant serve`
// AND written to disk by `openant report` for direct file:// opening — so the
// pinned libraries are vendored into the binary and INLINED at render time:
// self-contained in every mode (served, disk, air-gapped), no route coupling,
// and no CDN negotiation. The alternative (serve via /assets like the ui
// package) breaks the standalone files the report command writes.
func TestRenderedReportHasNoCDNScripts(t *testing.T) {
	render := map[string]func(ReportData, *strings.Builder) error{
		"overview": func(d ReportData, b *strings.Builder) error { return RenderOverview(d, b) },
		"reskin":   func(d ReportData, b *strings.Builder) error { return RenderReskin(d, b) },
	}
	for name, fn := range render {
		var b strings.Builder
		if err := fn(ReportData{Title: "t"}, &b); err != nil {
			t.Fatalf("%s render: %v", name, err)
		}
		out := b.String()
		if strings.Contains(out, "https://cdn.") {
			t.Fatalf("%s: the rendered report still references a CDN script", name)
		}
		// The vendored scripts must be PRESENT, not merely the CDN absent —
		// markers come from the pinned files themselves (version banners),
		// which the templates' own inline config blocks cannot provide.
		for _, marker := range []string{"3.4.16", "Chart.js v4.4.7", "chartjs-plugin-datalabels"} {
			if !strings.Contains(out, marker) {
				t.Fatalf("%s: missing vendored-script marker %q (an empty inline would strip styling/charts silently)",
					name, marker)
			}
		}
	}
}

// The vendored, pinned libraries are embedded non-empty at build time.
func TestVendoredReportScriptsEmbedded(t *testing.T) {
	for _, name := range []string{
		"tailwindcss-3.4.16.js",
		"chart-4.4.7.umd.min.js",
		"chartjs-plugin-datalabels-2.2.0.min.js",
	} {
		data, err := vendorFS.ReadFile("vendor/" + name)
		if err != nil {
			t.Fatalf("vendored script %s missing from the embed: %v", name, err)
		}
		if len(data) < 10_000 {
			t.Fatalf("vendored script %s suspiciously small (%d bytes) — a stub would silently strip the report",
				name, len(data))
		}
	}
}
