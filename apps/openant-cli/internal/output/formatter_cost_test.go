package output

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/fatih/color"
)

// captureUsageOutput runs fn capturing BOTH os.Stdout (fmt.Println — the
// value halves) and color.Output (the colored key prefixes) — PrintKeyValue
// writes to both, so a single pipe catches the full "Key: value" line.
func captureUsageOutput(fn func()) string {
	r, w, _ := os.Pipe()
	oldStdout, oldColorOut, oldNoColor := os.Stdout, color.Output, color.NoColor
	os.Stdout, color.Output, color.NoColor = w, w, true
	defer func() {
		os.Stdout, color.Output, color.NoColor = oldStdout, oldColorOut, oldNoColor
	}()
	fn()
	_ = w.Close()
	var buf strings.Builder
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

// TestReportSummaryRendersIncompleteness: #598 — the report renderer was
// the envelope's own consumer that dropped the metadata (and its cost>0
// gate vanished an incomplete $0 entirely). The label and the ids must
// reach the terminal.
func TestReportSummaryRendersIncompleteness(t *testing.T) {
	out := captureUsageOutput(func() {
		PrintReportSummary(map[string]any{
			"format":      "summary",
			"output_path": "/tmp/x",
			"usage": map[string]any{
				"total_cost_usd":  0.0,
				"cost_incomplete": true,
				"unpriced_models": []any{"claude-sonnet-4-6", "mystery/model"},
			},
		})
	})
	if !strings.Contains(out, "Cost (incomplete — at least one model unpriced)") {
		t.Fatalf("the incomplete label missing: %q", out)
	}
	if !strings.Contains(out, "claude-sonnet-4-6, mystery/model") {
		t.Fatalf("the unpriced ids missing: %q", out)
	}
}

// TestReportSummaryCompleteHasNoLabel: the control — a complete figure
// renders the plain Cost line and never the label.
func TestReportSummaryCompleteHasNoLabel(t *testing.T) {
	out := captureUsageOutput(func() {
		PrintReportSummary(map[string]any{
			"usage": map[string]any{"total_cost_usd": 0.0012},
		})
	})
	if strings.Contains(out, "incomplete") {
		t.Fatalf("a complete figure must not carry the label: %q", out)
	}
	if !strings.Contains(out, "Cost") {
		t.Fatalf("the cost line missing: %q", out)
	}
}

// TestScanSummaryRendersIncompleteness: the scan renderer (V1 — V2 shares
// the same block) carries the label + ids through the shared helper.
func TestScanSummaryRendersIncompleteness(t *testing.T) {
	out := captureUsageOutput(func() {
		PrintScanSummary(map[string]any{
			// PrintScanSummary early-returns without the metrics block.
			"metrics": map[string]any{"total": 3, "vulnerable": 0, "safe": 3},
			"usage": map[string]any{
				"total_cost_usd":      0.0,
				"total_input_tokens":  10,
				"total_output_tokens": 5,
				"cost_incomplete":     true,
				"unpriced_models":     []any{"x"},
			},
		})
	})
	if !strings.Contains(out, "Cost (incomplete — at least one model unpriced)") {
		t.Fatalf("the incomplete label missing: %q", out)
	}
	if !strings.Contains(out, "Unpriced models") {
		t.Fatalf("the unpriced ids line missing: %q", out)
	}
}

// F661-2 (the #626 review): a cache-only incompleteness (unpriced_cache_models
// set, unpriced_models empty) must still name its models — the terminal
// printed "at least one model unpriced" with NO model before.
func TestRenderCostBlockNamesCacheUnpricedModels(t *testing.T) {
	usage := map[string]any{
		"total_cost_usd":        0.00976,
		"cost_incomplete":       true,
		"unpriced_models":       []any{},
		"unpriced_cache_models": []any{"gpt-4o"},
	}
	// renderCostBlock writes to stdout; assert through the same capture
	// the sibling tests use (the analyze_verify pattern).
	out := captureUsageOutput(func() { renderCostBlock(usage) })
	if !strings.Contains(out, "gpt-4o") {
		t.Fatalf("the cache-unpriced model is nameless in the cost block:\n%s", out)
	}
}

// FIX-2 (defect (a), the display conflation): the two incompleteness KINDS
// must never share one label.
//
//	unpriced_models        -> no pricing record at all. The model's spend is
//	                          attributed $0, so the figure is a LOWER bound.
//	unpriced_cache_models  -> the model IS priced; only its cache multipliers
//	                          are absent. Its error direction depends on the
//	                          provider's field shape (see F1 below).
//
// Before this fix renderCostBlock merged both id lists into one slice under
// one "Unpriced models:" label, so a priced model (gpt-4o: input $2.50 /
// output $10.00) was announced to the operator as unpriced, and a bounded
// error was indistinguishable in shape from a missing figure.
//
// RE-POINTED by PR#661 hunt F1, not deleted (the round-1 pattern for a guard
// whose fixture outlived its claim). This test's own assertion that the
// operator "must be told the direction" used to demand the literal string
// "upper bound". For THIS fixture — gpt-4o, an INCLUSIVE shape — an upper
// bound happens to be the true direction, which is exactly why the claim
// survived round 1: the fixture could not discriminate. The renderer cannot
// tell the two shapes apart (the envelope carries no inclusion-shape
// discriminator), so what it owes the operator is the condition plus the
// fact that the figure is bounded in an unknown direction. The direction
// claim itself is pinned where it IS derivable: the Python oracle
// test_exclusive_unpriced_cache_underreports_and_inclusive_overreports.
func TestCacheUnpricedNotLabelledUnpriced(t *testing.T) {
	// the executed A1 totals: OpenAI implicit cache, census pricing
	usage := map[string]any{
		"total_cost_usd":        0.0200,
		"cost_incomplete":       true,
		"unpriced_models":       []any{},
		"unpriced_cache_models": []any{"gpt-4o"},
	}
	out := captureUsageOutput(func() { renderCostBlock(usage) })
	if strings.Contains(out, "Unpriced models") {
		t.Fatalf("gpt-4o IS priced — calling it unpriced is a false statement "+
			"to the operator:\n%s", out)
	}
	if !strings.Contains(out, "gpt-4o") {
		t.Fatalf("the cache-unpriced model must still be named:\n%s", out)
	}
	if !strings.Contains(out, "ARE priced") {
		t.Fatalf("the operator must be told this model IS priced (only its "+
			"cache rates are missing) — that is the whole F661-2 fix:\n%s", out)
	}
	if !strings.Contains(out, "Cache rates not configured") {
		t.Fatalf("the cache kind needs its own named line:\n%s", out)
	}
}

// The #216/#598 guard, re-pointed at a TRULY unpriced fixture: a model with
// no pricing record at all must still be announced as unpriced, and the
// operator must be told that figure OMITS its spend (a lower bound).
func TestTrulyUnpricedStillLabelledUnpriced(t *testing.T) {
	// the executed A3 totals
	usage := map[string]any{
		"total_cost_usd":  0.0,
		"cost_incomplete": true,
		"unpriced_models": []any{"mystery-model"},
	}
	out := captureUsageOutput(func() { renderCostBlock(usage) })
	if !strings.Contains(out, "Unpriced models: mystery-model") {
		t.Fatalf("the #216/#598 unpriced line regressed:\n%s", out)
	}
	if strings.Contains(out, "Cache rates not configured") {
		t.Fatalf("no cache kind is present — the cache line must not print:\n%s", out)
	}
	if !strings.Contains(out, "incomplete") {
		t.Fatalf("the cost label must stay marked incomplete:\n%s", out)
	}
}

// Both kinds at once: two lines, two labels, and a cost label naming BOTH
// conditions — an operator must not have to guess which direction the
// figure errs in when it errs in both.
func TestBothUnpricedKindsRenderSeparately(t *testing.T) {
	usage := map[string]any{
		"total_cost_usd":        0.0200,
		"cost_incomplete":       true,
		"unpriced_models":       []any{"mystery-model"},
		"unpriced_cache_models": []any{"gpt-4o"},
	}
	out := captureUsageOutput(func() { renderCostBlock(usage) })
	if !strings.Contains(out, "Unpriced models: mystery-model") {
		t.Fatalf("the pricing-absent line missing:\n%s", out)
	}
	if !strings.Contains(out, "Cache rates not configured: gpt-4o") {
		t.Fatalf("the cache-absent line missing:\n%s", out)
	}
	// and the two ids must never appear on the same line
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "mystery-model") && strings.Contains(line, "gpt-4o") {
			t.Fatalf("the two KINDS are merged onto one line:\n%s", out)
		}
	}
}

// A complete figure must stay silent about both kinds (no new noise).
func TestNeitherKindRendersNothing(t *testing.T) {
	out := captureUsageOutput(func() {
		renderCostBlock(map[string]any{"total_cost_usd": 0.0012})
	})
	if strings.Contains(out, "Unpriced") || strings.Contains(out, "Cache rates") {
		t.Fatalf("a complete figure must carry neither line:\n%s", out)
	}
	if strings.Contains(out, "incomplete") {
		t.Fatalf("a complete figure must not be labelled incomplete:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// PR #661 HUNT F1 — the cache kind's bound DIRECTION is not one-directional.
//
// The round-1 label asserted "an upper bound" for every unpriced-cache
// figure. That holds only for the INCLUSIVE provider field shapes (openai
// cached_tokens / google cached_content_token_count: the cached tokens are
// already inside the reported input count, so an absent multiplier bills
// them at the FULL input rate — an over-estimate). For the EXCLUSIVE shapes
// (anthropic / bedrock cache_read_input_tokens, DISJOINT from input_tokens)
// an absent multiplier contributes $0 — the figure is a LOWER bound.
//
// Executed on the Python side (libs/openant-core, the shipped registry):
//
//	us.anthropic.claude-sonnet-4-6, 10k in / 1k out / 90k cache-read
//	formula = $0.049500   real bill = $0.079200   ratio = 0.625
//
// All 11 bedrock records ship priced with NO cache block and the bedrock
// adapter DOES emit the exclusive fields, so "upper bound" was false for
// the entire bedrock census. The envelope carries no inclusion-shape
// discriminator, so the renderer must not assert a direction it cannot
// know — it states the condition and that the figure may err either way.
// ---------------------------------------------------------------------------
func TestCacheUnpricedMakesNoUnconditionalUpperBoundClaim(t *testing.T) {
	usage := map[string]any{
		"total_cost_usd":           0.0495,
		"cost_incomplete":          true,
		"unpriced_models":          []any{},
		"unpriced_cache_models":    []any{"us.anthropic.claude-sonnet-4-6"},
		"total_cache_read_tokens":  90000,
		"total_cache_write_tokens": 0,
	}
	out := captureUsageOutput(func() { renderCostBlock(usage) })
	if strings.Contains(out, "upper bound") {
		t.Fatalf("the exclusive (anthropic/bedrock) shape's unpriced cache "+
			"tokens contribute $0 — the figure is a LOWER bound there, so "+
			"an unconditional \"upper bound\" is a false disclosure:\n%s", out)
	}
	if !strings.Contains(out, "us.anthropic.claude-sonnet-4-6") {
		t.Fatalf("the cache-unpriced model must still be named:\n%s", out)
	}
	if !strings.Contains(out, "Cache rates not configured") {
		t.Fatalf("the cache kind keeps its own named line:\n%s", out)
	}
	// the operator must still learn the figure is untrustworthy AND that the
	// error direction is not knowable from this artifact.
	if !strings.Contains(out, "under") || !strings.Contains(out, "over") {
		t.Fatalf("the cache line must say the figure may be under- OR "+
			"over-stated (the direction depends on the provider's field "+
			"shape, which this envelope does not carry):\n%s", out)
	}
}

// The #216 kind's direction claim is NOT affected: a model with no pricing
// record at all contributes $0, so that figure genuinely IS a lower bound.
// This pins that F1's correction did not flatten both kinds to "unknown".
func TestTrulyUnpricedKeepsItsLowerBoundDirection(t *testing.T) {
	usage := map[string]any{
		"total_cost_usd":  0.0,
		"cost_incomplete": true,
		"unpriced_models": []any{"mystery-model"},
	}
	out := captureUsageOutput(func() { renderCostBlock(usage) })
	if strings.Contains(out, "under- or over") {
		t.Fatalf("the #216 kind's direction IS known (a lower bound) — it "+
			"must not inherit the cache kind's indeterminacy:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// PR #661 HUNT L1 — the cache token counts never reached the terminal.
//
// The typed UsageInfo gained TotalCacheReadTokens / TotalCacheWriteTokens
// (results.go) and the step reports and scan.report.json carry them, but
// both summary renderers printed "Tokens: N input / M output" only. On the
// exclusive shapes those cached tokens are a SEPARATE line item, so an
// anthropic run showed "10000 input" against a cost covering 100000 tokens.
// ---------------------------------------------------------------------------
func TestTokensLineShowsTheCacheLineItems(t *testing.T) {
	usage := map[string]any{
		"total_input_tokens":       10000,
		"total_output_tokens":      1000,
		"total_cache_read_tokens":  90000,
		"total_cache_write_tokens": 2000,
	}
	out := captureUsageOutput(func() { renderTokensLine(usage) })
	for _, want := range []string{"10000 input", "1000 output",
		"90000 cache read", "2000 cache write"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q from the tokens line:\n%s", want, out)
		}
	}
}

// Present-only, exactly like the Python/JSON envelope: a run with no cache
// traffic must render the pre-#626 line byte-for-byte.
func TestTokensLineByteIdenticalWithoutCache(t *testing.T) {
	usage := map[string]any{
		"total_input_tokens":  10000,
		"total_output_tokens": 1000,
	}
	out := captureUsageOutput(func() { renderTokensLine(usage) })
	if !strings.Contains(out, "10000 input / 1000 output") {
		t.Fatalf("the pre-#626 tokens line regressed:\n%s", out)
	}
	if strings.Contains(out, "cache") {
		t.Fatalf("no cache traffic — no cache segment may print:\n%s", out)
	}
}

// A read-only cache run (cache_read > 0, no writes) must not assert a zero
// it never measured — the per-field present-only rule FIX-1 established for
// the Python envelope, applied to the display.
func TestTokensLinePresentOnlyPerField(t *testing.T) {
	usage := map[string]any{
		"total_input_tokens":      10000,
		"total_output_tokens":     1000,
		"total_cache_read_tokens": 90000,
	}
	out := captureUsageOutput(func() { renderTokensLine(usage) })
	if !strings.Contains(out, "90000 cache read") {
		t.Fatalf("the cache-read line item is missing:\n%s", out)
	}
	if strings.Contains(out, "cache write") {
		t.Fatalf("no cache WRITE traffic was measured — printing 0 asserts "+
			"a measurement that did not happen:\n%s", out)
	}
}
