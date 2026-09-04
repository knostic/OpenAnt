package report

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
)

//go:embed templates/overview.gohtml
var templateFS embed.FS

//go:embed templates/report-reskin.gohtml
var reskinFS embed.FS

// #332: the report templates' third-party scripts (tailwindcss, chart.js,
// chartjs-plugin-datalabels) are VENDORED at pinned versions — the CDN tags
// carried no SRI, chart.js no version at all, and cdn.tailwindcss.com is a
// mutable runtime generator. The report is served AND written to disk for
// direct file:// opening, so the scripts are INLINED at render time (template
// func returning template.JS): self-contained in every mode — served,
// standalone, air-gapped — with no route coupling.
//
//go:embed vendor/tailwindcss-3.4.19.js vendor/chart-4.5.1.umd.min.js vendor/chartjs-plugin-datalabels-2.2.0.min.js
var vendorFS embed.FS

// vendorScripts holds the embedded script contents. A wrong name in a
// template is a compile-time failure (go:embed), so the map is built once
// and the read cannot fail.
var vendorScripts = func() map[string]template.JS {
	m := make(map[string]template.JS, 3)
	for _, n := range []string{
		"tailwindcss-3.4.19.js",
		"chart-4.5.1.umd.min.js",
		"chartjs-plugin-datalabels-2.2.0.min.js",
	} {
		b, err := vendorFS.ReadFile("vendor/" + n)
		if err != nil {
			panic("vendored report script missing: " + n)
		}
		m[n] = template.JS(b)
	}
	return m
}()

var (
	overviewTmpl *template.Template
	reskinTmpl   *template.Template
)

func init() {
	funcMap := template.FuncMap{
		"toJSON": func(v any) template.JS {
			b, _ := json.Marshal(v)
			return template.JS(b)
		},
		"even": func(i int) bool {
			return i%2 == 0
		},
		// #332: inline a vendored, pinned script by file name — the rendered
		// report carries its own dependencies (no CDN, no SRI negotiation).
		// Wave r1 (three axes): return an ERROR on an unknown name — a map
		// miss returned the zero template.JS and the report rendered
		// unstyled/chartless SILENTLY (go:embed validates the directive's
		// patterns, not the string literal a template passes; a rename that
		// missed one of the template call sites compiled clean). template
		// execution now fails loud instead.
		"vendorJS": func(name string) (template.JS, error) {
			js, ok := vendorScripts[name]
			if !ok {
				return "", fmt.Errorf("report: no vendored script %q (vendor/ is missing the file, or the template's literal is stale)", name)
			}
			return js, nil
		},
	}

	overviewTmpl = template.Must(
		template.New("overview.gohtml").Funcs(funcMap).ParseFS(templateFS, "templates/overview.gohtml"),
	)

	reskinTmpl = template.Must(
		template.New("report-reskin.gohtml").Funcs(funcMap).ParseFS(reskinFS, "templates/report-reskin.gohtml"),
	)
}

// RenderOverview renders the HTML overview report to the given writer.
func RenderOverview(data ReportData, w io.Writer) error {
	return overviewTmpl.Execute(w, data)
}

// GenerateOverview renders the HTML overview report to a file.
func GenerateOverview(data ReportData, outputPath string) error {
	return generateToFile(overviewTmpl, data, outputPath)
}

// RenderReskin renders the Knostic-themed HTML report to the given writer.
func RenderReskin(data ReportData, w io.Writer) error {
	return reskinTmpl.Execute(w, data)
}

// GenerateReskin renders the Knostic-themed HTML report to a file.
func GenerateReskin(data ReportData, outputPath string) error {
	return generateToFile(reskinTmpl, data, outputPath)
}

// generateToFile renders a template to a file, creating parent directories as needed.
func generateToFile(tmpl *template.Template, data ReportData, outputPath string) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}
