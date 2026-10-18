package main

// Regression tests for issue #746: the Go call graph records NO edge when a
// method value is held in a STRUCT-LITERAL FIELD or a NAMED-FUNC-TYPE
// container — the dominant Vault/OpenBao handler-registration idiom
// (&framework.PathOperation{Callback: b.pathLoginUpdate},
// map[logical.Operation]framework.OperationFunc{...}). The registration
// function is kept while its handler gets `callers: []`, and the
// reachability filter then prunes the handler as an orphan.
//
// #746's measured stakes: of 318 framework.Path Callback handlers in one
// committed openbao scan, 253 of the 254 pruned had no recorded caller —
// the AppRole login handler among them.
//
// CONTRACT (the fix's whole surface):
//   - a method value in a struct-literal FIELD records an edge from the
//     enclosing function to the method (issue mechanism 1 + 3);
//   - a method value in a NAMED-func-type container records it too
//     (issue mechanism 2 — funcValuedElementType abstains on a named type);
//   - the edge lands in BOTH call_graph and reverse_call_graph (#392's
//     review finding (4): the #299 test re-asserted only the forward map);
//   - a plain FIELD selector in a composite literal records NOTHING (the
//     precision control — the resolution AND the cross-package package
//     gate are the type check, fable r1 F1(a));
//   - a package-level FUNCTION that merely shares a name records NOTHING
//     (#299's suggested-fix item 6: the name-collision decoy);
//   - an UNKNOWN receiver type records NOTHING (abstain over guess);
//   - a bare IDENT in a non-func-typed literal still records NOTHING
//     (#392's review finding (2): funcValuedElementType's shape guard,
//     which resolveSimpleCall's unique-name fallback makes necessary);
//   - an import-alias-qualified value ABSTAINS — a DOCUMENTED LIMITATION
//     asserted here so a future change to it is visible, not silent;
//   - the new edges are DETERMINISTIC across repeated parses (#747/#777:
//     the builder's known map-order instability class);
//   - the #299 container-dispatch control and the direct-call control keep
//     their edges (so a null result anywhere above is meaningful).

import (
	"os"
	"path/filepath"
	"testing"
)

// buildFullGraphForFiles runs the REAL production path — NewCallGraphBuilder
// + the real Extractor + BuildCallGraph, which calls buildIndexes and so
// populates importsByFile and containersByFile exactly as the binary does.
// It returns both maps, because a forward edge without its transpose is the
// C5-graph defect this suite must be able to see.
func buildFullGraphForFiles(t *testing.T, files map[string]string) (*CallGraph, *AnalyzerOutput) {
	t.Helper()
	dir := t.TempDir()
	paths := make([]string, 0, len(files))
	for name, src := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, full)
	}
	out, err := NewExtractor(dir).Extract(paths)
	if err != nil || out == nil {
		t.Fatalf("extract: %v", err)
	}
	cg, err := NewCallGraphBuilder(dir).BuildCallGraph(out)
	if err != nil {
		t.Fatalf("BuildCallGraph: %v", err)
	}
	return cg, out
}

func mv746HasEdge(cg *CallGraph, from, to string) bool {
	for _, t := range cg.CallGraph[from] {
		if t == to {
			return true
		}
	}
	return false
}

func mv746HasReverseEdge(cg *CallGraph, to, from string) bool {
	for _, c := range cg.ReverseCallGraph[to] {
		if c == from {
			return true
		}
	}
	return false
}

// mv746Src is the issue's own fixture (its published n1_probe.py), verbatim
// in shape: a struct-literal Callback field, a named-func-type map value,
// the #299 container-dispatch control and the direct-call control.
const mv746Src = `package fx

type Request struct{ Data map[string]string }
type Response struct{}
type OperationFunc func(*Request) (*Response, error)
type PathOperation struct{ Callback OperationFunc }
type Path struct {
	Operations map[string]*PathOperation
	Callbacks  map[string]OperationFunc
}
type backend struct{}

func (b *backend) pathLogin() *Path {
	return &Path{
		Operations: map[string]*PathOperation{
			"update": &PathOperation{Callback: b.pathLoginUpdate},
		},
		Callbacks: map[string]OperationFunc{
			"read": b.pathLoginRead,
		},
	}
}
func (b *backend) pathLoginUpdate(req *Request) (*Response, error) { return nil, nil }
func (b *backend) pathLoginRead(req *Request) (*Response, error)   { return nil, nil }

var tbl = map[string]func(){"a": handlerA}

func handlerA()                 {}
func dispatch(k string)         { tbl[k]() }
func control(b *backend)        { b.pathLoginDirect(nil) }

func (b *backend) pathLoginDirect(req *Request) (*Response, error) { return nil, nil }
`

// TestIssue746_TheHandlersAreExtractedAtAll is the precondition every other
// assertion rests on. #299's comment 1 withdrew a whole table row for
// exactly this reason: "A 'no callers' result on an unextracted function is
// meaningless." So prove extraction BEFORE reading any edge.
func TestIssue746_TheHandlersAreExtractedAtAll(t *testing.T) {
	_, out := buildFullGraphForFiles(t, map[string]string{"b.go": mv746Src})
	for _, want := range []string{
		"b.go:backend.pathLogin",
		"b.go:backend.pathLoginUpdate",
		"b.go:backend.pathLoginRead",
		"b.go:backend.pathLoginDirect",
		"b.go:handlerA",
		"b.go:dispatch",
		"b.go:control",
	} {
		if _, ok := out.Functions[want]; !ok {
			t.Fatalf("unit %q was never extracted — every edge assertion in this file would be vacuous", want)
		}
	}
}

// TestIssue746_TheControlsRecordTheirEdges is the harness control: both
// edges the issue reports as already-working must work here, or a False
// below means "broken harness", not "missing edge".
func TestIssue746_TheControlsRecordTheirEdges(t *testing.T) {
	cg, _ := buildFullGraphForFiles(t, map[string]string{"b.go": mv746Src})
	if !mv746HasEdge(cg, "b.go:dispatch", "b.go:handlerA") {
		t.Fatalf("the #299 container-dispatch control edge is MISSING (dispatch -> handlerA); graph=%v", cg.CallGraph)
	}
	if !mv746HasEdge(cg, "b.go:control", "b.go:backend.pathLoginDirect") {
		t.Fatalf("the direct-call control edge is MISSING (control -> pathLoginDirect); graph=%v", cg.CallGraph)
	}
}

// TestIssue746_StructLiteralFieldMethodValueRecordsEdge — the issue's
// mechanism 1 + 3: &PathOperation{Callback: b.pathLoginUpdate}.
func TestIssue746_StructLiteralFieldMethodValueRecordsEdge(t *testing.T) {
	cg, _ := buildFullGraphForFiles(t, map[string]string{"b.go": mv746Src})
	if !mv746HasEdge(cg, "b.go:backend.pathLogin", "b.go:backend.pathLoginUpdate") {
		t.Fatalf("the struct-literal Callback field edge is NOT recorded (pathLogin -> pathLoginUpdate); out-edges=%v",
			cg.CallGraph["b.go:backend.pathLogin"])
	}
}

// TestIssue746_NamedFuncTypeContainerMethodValueRecordsEdge — the issue's
// mechanism 2: map[string]OperationFunc{"read": b.pathLoginRead}, where the
// element type is a NAMED func type and funcValuedElementType abstains.
func TestIssue746_NamedFuncTypeContainerMethodValueRecordsEdge(t *testing.T) {
	cg, _ := buildFullGraphForFiles(t, map[string]string{"b.go": mv746Src})
	if !mv746HasEdge(cg, "b.go:backend.pathLogin", "b.go:backend.pathLoginRead") {
		t.Fatalf("the named-func-type map edge is NOT recorded (pathLogin -> pathLoginRead); out-edges=%v",
			cg.CallGraph["b.go:backend.pathLogin"])
	}
}

// TestIssue746_TheEdgeLandsInBothGraphs — #392's review finding (4): the
// #299 test asserted its reverse-graph claim against the FORWARD map. The
// reachability consumer builds its forward graph FROM the reverse map, so a
// forward edge without its transpose is invisible to the thing that matters.
func TestIssue746_TheEdgeLandsInBothGraphs(t *testing.T) {
	cg, _ := buildFullGraphForFiles(t, map[string]string{"b.go": mv746Src})
	for _, tgt := range []string{"b.go:backend.pathLoginUpdate", "b.go:backend.pathLoginRead"} {
		if !mv746HasReverseEdge(cg, tgt, "b.go:backend.pathLogin") {
			t.Fatalf("%s has NO recorded caller in reverse_call_graph (callers=%v) — the handler still prunes as an orphan",
				tgt, cg.ReverseCallGraph[tgt])
		}
	}
}

// mv746FieldDecoySrc: the PRECISION control. `cfg.Timeout` and `cfg.Name`
// are plain STRUCT FIELDS, not methods — a composite-literal selector that
// is a field read must record no edge. It also plants a package-level
// FUNCTION named Timeout, so the decoy is a genuine name collision: a fix
// that resolved selectors by bare name would fabricate an edge here.
const mv746FieldDecoySrc = `package fx

type Conf struct {
	Timeout int
	Name    string
}
type Out struct {
	T int
	N string
}

func Timeout() int { return 7 }
func Name() string { return "x" }

func build(cfg *Conf) *Out {
	return &Out{T: cfg.Timeout, N: cfg.Name}
}
`

func TestIssue746_FieldSelectorInCompositeLiteralRecordsNoEdge(t *testing.T) {
	cg, out := buildFullGraphForFiles(t, map[string]string{"c.go": mv746FieldDecoySrc})
	if _, ok := out.Functions["c.go:Timeout"]; !ok {
		t.Fatal("the decoy function c.go:Timeout was not extracted — the assertion would be vacuous")
	}
	for _, bad := range []string{"c.go:Timeout", "c.go:Name"} {
		if mv746HasEdge(cg, "c.go:build", bad) {
			t.Fatalf("FABRICATED EDGE: build -> %s. cfg.Timeout/cfg.Name are struct FIELDS; "+
				"#299's 2026-08-22 ruling: \"a fabricated edge is not a safe over-seed: it invents "+
				"reachability into a function that is never invoked\". out-edges=%v",
				bad, cg.CallGraph["c.go:build"])
		}
		if len(cg.ReverseCallGraph[bad]) != 0 {
			t.Fatalf("FABRICATED EDGE in the transpose: %s callers=%v", bad, cg.ReverseCallGraph[bad])
		}
	}
}

// mv746UnknownRecvSrc: the receiver's static type is unknowable to the body
// model (it comes back from a constructor CALL, which compositeTypeName
// deliberately refuses to infer), so no edge may be emitted.
const mv746UnknownRecvSrc = `package fx

type Hooks struct{ F func() }
type svc struct{}

func (s *svc) Run() {}

func newSvc() *svc { return &svc{} }

func wire() *Hooks {
	s := newSvc()
	return &Hooks{F: s.Run}
}
`

func TestIssue746_UnknownReceiverTypeRecordsNoEdge(t *testing.T) {
	cg, out := buildFullGraphForFiles(t, map[string]string{"d.go": mv746UnknownRecvSrc})
	if _, ok := out.Functions["d.go:svc.Run"]; !ok {
		t.Fatal("d.go:svc.Run was not extracted — the assertion would be vacuous")
	}
	if mv746HasEdge(cg, "d.go:wire", "d.go:svc.Run") {
		t.Fatalf("an UNKNOWN receiver type must abstain (compositeTypeName refuses to infer a call's "+
			"return type on purpose), but wire -> svc.Run was recorded; out-edges=%v", cg.CallGraph["d.go:wire"])
	}
}

// mv746IdentGuardSrc: #392's review finding (2) — a bare IDENT inside a
// NON-func-typed composite literal must stay unread, because
// resolveSimpleCall's "Priority 3: Unique name match" would otherwise
// fabricate an edge from an int-valued map to a same-named function.
const mv746IdentGuardSrc = `package fx

type T struct{ N int }

func limit() int { return 1 }

func sizes() map[string]int {
	limit := 5
	return map[string]int{"a": limit}
}
`

func TestIssue746_BareIdentInNonFuncTypedLiteralStillRecordsNoEdge(t *testing.T) {
	cg, out := buildFullGraphForFiles(t, map[string]string{"e.go": mv746IdentGuardSrc})
	if _, ok := out.Functions["e.go:limit"]; !ok {
		t.Fatal("e.go:limit was not extracted — the assertion would be vacuous")
	}
	if mv746HasEdge(cg, "e.go:sizes", "e.go:limit") {
		t.Fatalf("funcValuedElementType's shape guard REGRESSED: map[string]int{\"a\": limit} must not "+
			"read `limit` as a call target (#392 review finding (2)); out-edges=%v", cg.CallGraph["e.go:sizes"])
	}
}

// mv746ImportAliasSrc: the DOCUMENTED LIMITATION, asserted so that changing
// it is a visible test change rather than a silent behaviour drift. An
// import-alias-qualified value in a composite literal would have to resolve
// through resolvePackageCall — a disjoint surface under open review in
// #747 / PR #778 — so this fix deliberately abstains.
const mv746ImportAliasSrc = `package fx

import "fx/handlers"

type Route struct{ H func() }

func routes() *Route { return &Route{H: handlers.Login} }
`

const mv746ImportAliasDepSrc = `package handlers

func Login() {}
`

func TestIssue746_ImportAliasQualifiedCompositeValueAbstains_DocumentedLimitation(t *testing.T) {
	cg, out := buildFullGraphForFiles(t, map[string]string{
		"f.go":          mv746ImportAliasSrc,
		"handlers/h.go": mv746ImportAliasDepSrc,
	})
	if _, ok := out.Functions["handlers/h.go:Login"]; !ok {
		t.Fatal("handlers/h.go:Login was not extracted — the assertion would be vacuous")
	}
	if mv746HasEdge(cg, "f.go:routes", "handlers/h.go:Login") {
		t.Fatalf("DOCUMENTED LIMITATION CHANGED: an import-alias-qualified composite-literal value now "+
			"records an edge (routes -> handlers.Login). That is an IMPROVEMENT, not a failure — but it "+
			"crosses into resolvePackageCall, the surface under open review in #747/PR #778. Update this "+
			"test, the fix's comment, and the PR's Coordination section together; out-edges=%v",
			cg.CallGraph["f.go:routes"])
	}
}

// TestIssue746_TheNewEdgesAreDeterministic — #747 and #777 are both
// map-iteration-order instability in this very file. The fix's new edges
// resolve through resolveMethodCall, which PR #178 made a total order
// ("prefer a method in the caller's own package, then break ties by the
// lexicographically smallest funcID", callgraph.go's own comment). Assert
// that, rather than trusting it: two same-named methods on two same-named
// receiver types in different packages, built 12 times.
const mv746DeterminismSrc = `package fx

type store struct{}
type Hooks struct{ F func() }

func (s *store) Get() {}

func wire(s *store) *Hooks { return &Hooks{F: s.Get} }
`

const mv746DeterminismTwinSrc = `package other

type store struct{}

func (s *store) Get() {}
`

func TestIssue746_TheNewEdgesAreDeterministic(t *testing.T) {
	first := ""
	for i := 0; i < 12; i++ {
		cg, _ := buildFullGraphForFiles(t, map[string]string{
			"g.go":       mv746DeterminismSrc,
			"other/o.go": mv746DeterminismTwinSrc,
		})
		got := ""
		for _, tgt := range cg.CallGraph["g.go:wire"] {
			got += tgt + "|"
		}
		if i == 0 {
			first = got
			if got == "" {
				t.Fatalf("run %d: wire has NO out-edge at all — the method value in the struct literal was dropped", i)
			}
			continue
		}
		if got != first {
			t.Fatalf("NONDETERMINISTIC: run 0 gave %q, run %d gave %q (the #747/#777 map-order class)", first, i, got)
		}
	}
}

// mv746CrossPkgFieldSrc: fable cycle-8 r1 F1(a) — two packages each declare a
// type named `backend` (the Vault/OpenBao plugin convention). Package a's has
// a `view` FIELD; package z's has a `view()` METHOD. A composite-literal
// FIELD read `Out{V: b.view}` in package a must record NO edge: the receiver's
// bare type name collides repo-wide in methodsByType, so without the
// same-package gate the cross-package fallback (the smallest other-package
// funcID) fabricates `a/a.go:backend.make -> z/z.go:backend.view` for a read
// that never calls anything.
const mv746CrossPkgFieldASrc = `package a

type backend struct{ view string }
type Out struct{ V string }

func (b *backend) make() *Out {
	return &Out{V: b.view}
}
`

const mv746CrossPkgFieldZSrc = `package z

type backend struct{}

func (b *backend) view() string { return "" }
`

const mv746CrossPkgFieldESrc = `package e

type backend struct{}

func (b *backend) handle() string { return "" }
type Reg struct{ Callback func() string }

func reg() *Reg {
	b := &backend{}
	return &Reg{Callback: b.handle}
}
`

func TestIssue746_CrossPackageFieldReadRecordsNoEdge(t *testing.T) {
	cg, out := buildFullGraphForFiles(t, map[string]string{
		"a/a.go": mv746CrossPkgFieldASrc,
		"z/z.go": mv746CrossPkgFieldZSrc,
		"e/e.go": mv746CrossPkgFieldESrc,
	})
	if _, ok := out.Functions["z/z.go:backend.view"]; !ok {
		t.Fatal("the other package's method z/z.go:backend.view was not extracted — the assertion would be vacuous")
	}
	if mv746HasEdge(cg, "a/a.go:backend.make", "z/z.go:backend.view") {
		t.Fatalf("FABRICATED cross-package edge: a/a.go:backend.make -> z/z.go:backend.view. "+
			"b.view in package a reads a FIELD of a's own backend type; methodsByType keys the "+
			"BARE name repo-wide so the cross-package fallback fired. #299: a fabricated edge is "+
			"not a safe over-seed. out-edges=%v", cg.CallGraph["a/a.go:backend.make"])
	}
	if len(cg.ReverseCallGraph["z/z.go:backend.view"]) != 0 {
		t.Fatalf("FABRICATED transpose: z/z.go:backend.view callers=%v",
			cg.ReverseCallGraph["z/z.go:backend.view"])
	}
	// the same-package method value STILL resolves (the gate must not
	// over-tighten into a false negative on the issue's own shape)
	if !mv746HasEdge(cg, "e/e.go:reg", "e/e.go:backend.handle") {
		t.Fatalf("the same-package method value lost its edge — the gate over-tightened")
	}
}
