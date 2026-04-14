// Package ui provides the embedded web UI templates for the openant serve command.
package ui

import "embed"

//go:embed index.html scan.html summary.html disclosure.html
var FS embed.FS
