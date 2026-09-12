// Package ui provides the embedded web UI templates for the openant serve command.
package ui

import "embed"

//go:embed index.html scan.html summary.html disclosure.html vendor/marked-18.0.12.min.js vendor/dompurify-3.4.15.min.js
var FS embed.FS
