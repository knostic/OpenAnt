// Package ui provides the embedded web UI templates for the openant serve command.
package ui

import "embed"

//go:embed index.html scan.html summary.html disclosure.html vendor/marked.min.js vendor/purify.min.js
var FS embed.FS
