package report

import (
	"embed"
	"encoding/json"
	"html/template"
	"io"
	"os"
	"path/filepath"
)

//go:embed templates/overview.gohtml
var templateFS embed.FS

//go:embed templates/report-reskin.gohtml
var reskinFS embed.FS

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
