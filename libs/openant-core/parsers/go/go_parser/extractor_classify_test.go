package main

import "testing"

// Regression tests for F7 and F10 — over-broad unit-type classification in
// classifyUnitType, which seeds false remote-web entry points downstream.

// F10: a factory that *returns* http.HandlerFunc (no request-shaped params,
// no handler body) must NOT be classified http_handler — only a function that
// RECEIVES a request is a handler.
func TestFactoryReturningHandlerFuncIsNotHTTPHandler(t *testing.T) {
	e := NewExtractor(".")
	got := e.classifyUnitType(
		"NewLoggingHandler", "",
		[]string{"prefix string"},    // params: no request types
		[]string{"http.HandlerFunc"}, // returns a handler (factory)
		"{ return func(w http.ResponseWriter, r *http.Request) {} }",
		"x.go",
	)
	if got == UnitTypeHTTPHandler {
		t.Fatalf("factory returning http.HandlerFunc classified as %q, want != http_handler", got)
	}
}

// F7: an iterator/lexer whose body merely contains a "next(" call must NOT be
// classified middleware. Real middleware returns http.Handler/HandlerFunc or
// calls next.ServeHTTP / next(w, r) with an http signature.
func TestIteratorWithNextCallIsNotMiddleware(t *testing.T) {
	e := NewExtractor(".")
	got := e.classifyUnitType(
		"CutPrefix", "",
		[]string{"s string", "prefix string"}, // no http params
		[]string{"string", "bool"},            // no http returns
		"{ for next, hasNext := iter(); hasNext; { _ = next(); } ; return s, true }",
		"seq.go",
	)
	if got == UnitTypeMiddleware {
		t.Fatalf("iterator using next() classified as %q, want != middleware", got)
	}
}

// Guard against over-correction: a genuine net/http handler and genuine
// middleware must still be detected.
func TestGenuineHTTPHandlerStillDetected(t *testing.T) {
	e := NewExtractor(".")
	got := e.classifyUnitType(
		"ServeIndex", "",
		[]string{"w http.ResponseWriter", "r *http.Request"},
		[]string{},
		"{ w.Write([]byte(\"ok\")) }",
		"h.go",
	)
	if got != UnitTypeHTTPHandler {
		t.Fatalf("genuine handler classified as %q, want http_handler", got)
	}
}

func TestGenuineMiddlewareStillDetected(t *testing.T) {
	e := NewExtractor(".")
	got := e.classifyUnitType(
		"Logging", "",
		[]string{"next http.Handler"},
		[]string{"http.Handler"},
		"{ return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request){ next.ServeHTTP(w, r) }) }",
		"mw.go",
	)
	if got != UnitTypeMiddleware {
		t.Fatalf("genuine middleware classified as %q, want middleware", got)
	}
}
