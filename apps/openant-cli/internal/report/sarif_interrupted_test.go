package report

import (
	"testing"
)

// #420 (wave r1, fable+opus): an INTERRUPTED step must gate the SARIF run as
// NOT executionSuccessful — the status carries empty errors/summary, so before
// the gate knew the word it matched no disjunct and produced the exact
// false-green #285/#305 exist to close. Consumer-level pin (the producer
// tests alone could not see the vocabulary split).
func TestSarifInterruptedStepIsFailure(t *testing.T) {
	for _, status := range []string{"interrupted", "error", "partial"} {
		sr := StepReport{Step: "verify", Status: status}
		if !stepReportIsFailure(sr) {
			t.Fatalf("status %q must be failure-class in the SARIF gate", status)
		}
	}
	sr := StepReport{Step: "parse", Status: "success"}
	if stepReportIsFailure(sr) {
		t.Fatalf("a successful step must not be failure-class")
	}
	sr2 := StepReport{Step: "parse", Status: "success", ErrorCount: 3}
	if !stepReportIsFailure(sr2) {
		t.Fatalf("unit errors must be failure-class regardless of status")
	}
}
