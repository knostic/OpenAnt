package report

import (
	"regexp"
	"strings"
)

// templateClassTokens extracts every Tailwind class token from a Go
// html/template source: the static tokens in class="..." attributes, the
// tokens inside template conditionals ({{if}}/{{else}} branches — both
// sides count), and the VALUE HOLES ({{expr}} interpolations that resolve
// to class strings at render time — reported so the caller can resolve
// them from the Go source, e.g. StatusColor's literals).
//
// The four shapes in the real templates (fixture-tested in
// test_class_token_extraction_test.go):
//   - class="border-b border-gray-800 {{if even $i}}bg-navy-800{{else}}bg-navy-900/30{{end}}"
//     → tokens: border-b, border-gray-800, bg-navy-800, bg-navy-900/30
//   - class="py-3 px-4 {{$step.StatusColor}}" — a VALUE HOLE
//   - class="{{.StatusColor}} font-medium" — a VALUE HOLE + static tokens
//   - class="[&_h3]:text-base ..." — arbitrary variants are plain tokens
//
// Extraction strategy: strip the template actions ({{...}}) REPLACING them
// with spaces (so the glued tokens split), then split on whitespace; the
// actions themselves are scanned separately for the value-hole markers.
func templateClassTokens(src string) (tokens []string, valueHoles []string) {
	// Match every {{...}} action. Inside class attributes these are either
	// conditionals ({{if}}...{{else}}...{{end}}, whose branch text carries
	// tokens — captured by the strip-and-split below) or value holes
	// ({{expr}} interpolations, reported for Go-source resolution).
	actionRe := regexp.MustCompile(`\{\{[^}]*\}\}`)
	// Only class= attributes matter — for BOTH the tokens and the value
	// holes (a {{expr}} in text content, like {{$step.Status}}, is not a
	// class hole).
	classAttrRe := regexp.MustCompile(`class="([^"]*)"`)
	for _, m := range classAttrRe.FindAllStringSubmatch(src, -1) {
		attr := m[1]
		// The value holes: the non-conditional actions inside the attr.
		for _, a := range actionRe.FindAllString(attr, -1) {
			inner := strings.Trim(a, "{} ")
			if strings.HasPrefix(inner, "if ") || strings.HasPrefix(inner, "else") ||
				strings.HasPrefix(inner, "end") || strings.HasPrefix(inner, "/*") ||
				inner == "" {
				continue
			}
			valueHoles = append(valueHoles, strings.TrimSpace(inner))
		}
		// The tokens: the actions stripped to spaces (the glued-token fix).
		val := actionRe.ReplaceAllString(attr, " ")
		for _, tok := range strings.Fields(val) {
			tokens = append(tokens, tok)
		}
	}
	return tokens, valueHoles
}

// statusColorLiterals returns every string literal returned by the
// StatusColor method (and any sibling class-returning method) in the
// package source, harvested via go/ast — a new case at types.go cannot
// escape the coverage test (the design ruling: never hand-enumerate).
//
// The implementation lives in statuscolor_literals_test.go's test file
// (harvested there); this declaration keeps the contract discoverable.
