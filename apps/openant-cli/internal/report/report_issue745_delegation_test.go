package report

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// #745: the delegation-dismissed SAFE row's followable edge must REACH the
// rendered HTML — the consumer surface the issue names. The corpus chain:
// _buildUrl is SAFE-by-delegation ("the actual open-redirect risk exists at
// the callers (_redirect/_handleSuccess/_handleError)"), and _redirect was
// pruned from the dataset (a framework hook with no static callers) — so the
// row carries the caller edges as structured fields, the pruned sink-owner
// surfaced as rowless, distinguishable from an examined-and-safe one.
//
// The data is built the way the REAL consumer builds it: json.Unmarshal of
// the report-data blob the Python projection emits (the same keys, the same
// values) — the boundary the contract lives on (report.Finding's tags). Both
// templates (overview + reskin) iterate the grouped findings; both carry the
// delegation block.
const delegationReportDataJSON = `{
  "title": "Security Analysis Report",
  "repo_name": "issue-745",
  "findings_by_verdict": [
    {
      "verdict": "safe",
      "findings": [
        {
          "number": 1,
          "verdict": "safe",
          "file": "app/api.js",
          "function": "_buildUrl",
          "scope": "function_local",
          "deferred_to": ["app/api.js:_redirect", "app/api.js:_handleSuccess"],
          "deferred_rowless": ["app/api.js:_redirect"]
        }
      ]
    }
  ]
}`

// The SUBGROUPED reskin path (findings_by_verdict[].subgroups — the
// dynamic-test grouping the report-data projection builds) renders its own
// finding rows: the delegation block must reach BOTH template paths (the
// ungrouped and the subgrouped) or half the report loses the edge.
const subgroupedReportDataJSON = `{
  "title": "Security Analysis Report",
  "repo_name": "issue-745",
  "findings_by_verdict": [
    {
      "verdict": "safe",
      "findings": [],
      "subgroups": [
        {
          "label": "Not tested",
          "findings": [
            {
              "number": 3,
              "verdict": "safe",
              "file": "app/api.js",
              "function": "_buildUrl",
              "scope": "function_local",
              "deferred_to": ["app/api.js:_redirect", "app/api.js:_handleSuccess"],
              "deferred_rowless": ["app/api.js:_redirect"]
            }
          ]
        }
      ],
      "has_subgroups": true
    }
  ]
}`

func TestRenderDelegationEdgeOnSubgroupedReskin(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderReskin(unmarshalReportData(t, subgroupedReportDataJSON), &buf); err != nil {
		t.Fatalf("RenderReskin: %v", err)
	}
	assertDelegationEdge(t, buf.String())
}

// A non-safe verdict's blob carries no #745 fields at all (the Python side
// spreads {} for every non-safe verdict): the empty struct values render no
// delegation block.
const vulnerableReportDataJSON = `{
  "title": "Security Analysis Report",
  "repo_name": "issue-745",
  "findings_by_verdict": [
    {
      "verdict": "vulnerable",
      "findings": [
        {
          "number": 2,
          "verdict": "vulnerable",
          "file": "app/api.js",
          "function": "_redirect"
        }
      ]
    }
  ]
}`

func unmarshalReportData(t *testing.T, blob string) ReportData {
	t.Helper()
	var data ReportData
	if err := json.Unmarshal([]byte(blob), &data); err != nil {
		t.Fatalf("json.Unmarshal(report-data): %v", err)
	}
	return data
}

func TestRenderDelegationEdgeOnSafeRowsOverview(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderOverview(unmarshalReportData(t, delegationReportDataJSON), &buf); err != nil {
		t.Fatalf("RenderOverview: %v", err)
	}
	assertDelegationEdge(t, buf.String())
}

func TestRenderDelegationEdgeOnSafeRowsReskin(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderReskin(unmarshalReportData(t, delegationReportDataJSON), &buf); err != nil {
		t.Fatalf("RenderReskin: %v", err)
	}
	assertDelegationEdge(t, buf.String())
}

// The GATE pin: a SAFE row carrying scope but NO edges renders NO block —
// the block renders only when EDGES exist. Flipping the gate back to
// {{if $f.Scope}} (the pre-r3 shape) would render this row's block and fail
// this test: scope alone is not a delegation signal (every safe row carries
// scope).
const scopeOnlyReportDataJSON = `{
  "title": "Security Analysis Report",
  "repo_name": "issue-745",
  "findings_by_verdict": [
    {
      "verdict": "safe",
      "findings": [
        {
          "number": 4,
          "verdict": "safe",
          "file": "app/api.js",
          "function": "_selfSafe",
          "scope": "function_local",
          "deferred_to": [],
          "deferred_rowless": []
        }
      ]
    }
  ]
}`

func TestRenderNoBlockOnScopeWithoutEdges(t *testing.T) {
	for _, render := range []struct {
		name string
		fn   func(ReportData, io.Writer) error
	}{
		{"overview", RenderOverview},
		{"reskin", RenderReskin},
	} {
		var buf bytes.Buffer
		if err := render.fn(unmarshalReportData(t, scopeOnlyReportDataJSON), &buf); err != nil {
			t.Fatalf("%s: %v", render.name, err)
		}
		if strings.Contains(buf.String(), "Call edges") {
			t.Errorf("%s: a SAFE row with scope but NO edges rendered the block "+
				"(the gate must key on the edges, never the scope): %s",
				render.name, excerpt(buf.String(), "Call edges"))
		}
	}
}

func assertDelegationEdge(t *testing.T, out string) {
	t.Helper()
	for _, want := range []string{
		"Call edges",
		"function_local",
		"app/api.js:_redirect",
		"app/api.js:_handleSuccess",
		"no result row (pruned or never analyzed)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in the rendered finding row — the call edges must reach the HTML consumer: %s",
				want, excerpt(out, "Call edges"))
		}
	}
}

// A non-safe verdict renders NO call-edges block. The CLASS BOUNDARY itself
// lives in the producer (cli.py's conditional **-spread: only safe rows carry
// the fields); this lock is the consumer-side discriminator — it uniquely
// kills a verdict-keyed gate mutant (a template gating the block on
// (verdict == "safe" AND edges) renders nothing for the vulnerable row's
// EMPTY-OR-ABSENT fields, but a mutant keying ONLY on edges-with-no-verdict
// check renders for a fields-carrying vulnerable row — which the JSON
// boundary permits: the Go consumer accepts any blob). A vulnerable row
// carrying the fields is NOT the producer's shape; the lock pins that the
// RENDERER does not add a verdict gate the producer does not have.
func TestRenderNoDeferralOnNonSafeVerdicts(t *testing.T) {
	data := unmarshalReportData(t, vulnerableReportDataJSON)
	for _, render := range []struct {
		name string
		fn   func(ReportData, io.Writer) error
	}{
		{"overview", RenderOverview},
		{"reskin", RenderReskin},
	} {
		var buf bytes.Buffer
		if err := render.fn(data, &buf); err != nil {
			t.Fatalf("%s: %v", render.name, err)
		}
		if strings.Contains(buf.String(), "Call edges") {
			t.Errorf("%s: a non-safe verdict rendered the call-edges block: %s",
				render.name, excerpt(buf.String(), "Call edges"))
		}
	}
}
