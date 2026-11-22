// Package ui provides the embedded web UI templates for the openant serve command.
package ui

import "embed"

//go:embed index.html scan.html summary.html disclosure.html vendor/marked-18.1.1.min.js vendor/dompurify-3.5.0.min.js
var FS embed.FS
