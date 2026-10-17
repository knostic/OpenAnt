package types

import (
	"encoding/json"
	"testing"
)

// FIX-2 secondary (defect (a) drop #8): the typed UsageInfo struct silently
// DROPPED the #626 cache line items — anything decoding a result envelope
// through the struct (rather than map[string]any, which only the terminal
// renderer uses) lost the cache-read/write totals and the cache-unpriced
// ids entirely. The terminal path survived by accident, not by design.
//
// All four are `omitempty`, matching the Python side's present-only
// envelope (core/schemas.py UsageInfo.to_dict) — a no-cache run round-trips
// to exactly the pre-#626 key set.
func TestUsageInfoCarriesCacheLineItems(t *testing.T) {
	raw := []byte(`{"total_calls":1,"total_cost_usd":0.02,
		"cost_incomplete":true,"unpriced_models":[],
		"total_cache_read_tokens":4096,"total_cache_write_tokens":1000,
		"unpriced_cache_models":["gpt-4o"]}`)
	var u UsageInfo
	if err := json.Unmarshal(raw, &u); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if u.TotalCacheReadTokens != 4096 {
		t.Fatalf("cache read tokens dropped: %d", u.TotalCacheReadTokens)
	}
	if u.TotalCacheWriteTokens != 1000 {
		t.Fatalf("cache write tokens dropped: %d", u.TotalCacheWriteTokens)
	}
	if len(u.UnpricedCacheModels) != 1 || u.UnpricedCacheModels[0] != "gpt-4o" {
		t.Fatalf("cache-unpriced ids dropped: %v", u.UnpricedCacheModels)
	}
}

// The present-only round trip: a no-cache UsageInfo must re-serialize to the
// pre-#626 key set, so Go-written envelopes match Python-written ones.
func TestUsageInfoNoCacheRoundTripsWithoutCacheKeys(t *testing.T) {
	out, err := json.Marshal(UsageInfo{TotalCalls: 1, TotalCostUSD: 0.0525})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"total_cache_read_tokens",
		"total_cache_write_tokens", "unpriced_cache_models"} {
		if _, ok := back[k]; ok {
			t.Fatalf("a no-cache envelope must omit %q: %s", k, out)
		}
	}
}
