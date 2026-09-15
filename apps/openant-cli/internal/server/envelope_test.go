package server

import "testing"

// envelopeErrors must pull the CLI's error reasons out of the stdout envelope
// (the CLI prints failures as JSON on stdout; stderr may be empty), tolerating
// interleaved non-JSON log noise, and return nothing when there is no error.
func TestEnvelopeErrors(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
		want   []string
	}{
		{
			name:   "single error envelope",
			stdout: `{"status":"error","errors":["No supported source files found"]}`,
			want:   []string{"No supported source files found"},
		},
		{
			name:   "envelope after log noise on the same stream",
			stdout: "loading config...\nparsing repo\n{\"status\":\"error\",\"errors\":[\"boom\",\"and again\"]}\n",
			want:   []string{"boom", "and again"},
		},
		{
			name:   "success envelope carries no errors",
			stdout: `{"status":"success","data":{"x":1}}`,
			want:   nil,
		},
		{
			name:   "no json at all",
			stdout: "just some logs\nnothing structured here\n",
			want:   nil,
		},
		{
			name:   "last envelope wins when several are present",
			stdout: "{\"status\":\"error\",\"errors\":[\"first\"]}\n{\"status\":\"error\",\"errors\":[\"latest\"]}\n",
			want:   []string{"latest"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := envelopeErrors(tc.stdout)
			if len(got) != len(tc.want) {
				t.Fatalf("envelopeErrors() = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("envelopeErrors()[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}
