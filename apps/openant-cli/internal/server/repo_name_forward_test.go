package server

import (
	"os"
	"strings"
	"testing"
)

// #612 (the review round's fold): the server derives the scan's
// --repo-name from the SAME normalized URL it forwards — else the
// Python-side fallback stamps the clone dir's basename ("repo") as the
// scan's product identity (the disclosure prompt's product_name). The
// single-element =-form is the argparse lesson (a two-token
// leading-hyphen name kills the scan).
func TestServerForwardsDerivedRepoName(t *testing.T) {
	src := func() string {
		b, err := os.ReadFile("server.go")
		if err != nil {
			t.Fatalf("reading server.go: %v", err)
		}
		return string(b)
	}()
	i := strings.Index(src, "args = append(args, \"--repo-url\", _u)")
	if i < 0 {
		t.Fatal("the --repo-url forwarding site moved — update this pin")
	}
	block := src[i : i+600]
	if !strings.Contains(block, `"--repo-name="+_n`) {
		t.Fatal("the derived name is not forwarded alongside --repo-url (the #612 fold)")
	}
	if strings.Contains(block, `"--repo-name",`) {
		t.Fatal("the two-token --repo-name form is present — the argparse hazard")
	}
	if !strings.Contains(block, "RepoSlug(_u)") {
		t.Fatal("the name must derive from the SAME normalized URL (RepoSlug(_u))")
	}
}
