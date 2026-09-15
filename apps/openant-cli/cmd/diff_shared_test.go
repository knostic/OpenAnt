package cmd

import (
	"strings"
	"testing"
)

func TestDiffOptsValidateStaged(t *testing.T) {
	cases := []struct {
		name    string
		opts    diffOpts
		wantErr string
	}{
		{name: "staged only", opts: diffOpts{staged: true, scope: "changed_functions"}},
		{name: "staged + base", opts: diffOpts{staged: true, base: "origin/main", scope: "changed_functions"}, wantErr: "mutually exclusive"},
		{name: "staged + pr", opts: diffOpts{staged: true, pr: 9, scope: "changed_functions"}, wantErr: "mutually exclusive"},
		{name: "base + pr", opts: diffOpts{base: "x", pr: 9, scope: "changed_functions"}, wantErr: "mutually exclusive"},
		{name: "staged empty scope", opts: diffOpts{staged: true}, wantErr: "must not be empty"},
		{name: "staged invalid scope", opts: diffOpts{staged: true, scope: "everything"}, wantErr: "invalid --diff-scope"},
		{name: "nothing set is fine", opts: diffOpts{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.opts.validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

func TestDiffOptsIsSetStaged(t *testing.T) {
	if !(diffOpts{staged: true}).isSet() {
		t.Error("staged=true should be isSet()")
	}
	if (diffOpts{}).isSet() {
		t.Error("zero diffOpts should not be isSet()")
	}
}
