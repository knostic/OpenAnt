package cmd

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #691: `openant init -l <value>` validated nothing — the traversal form
// ('../../../../ESCAPED') escaped the artifacts dir and printed success,
// and the typo form ('-l Python') persisted garbage that surfaced only at
// every later scan, far from the cause. Two complementary controls:
// (1) the CLI boundary rejects anything but `auto` or a member of
//
//	languages.Supported() BEFORE any write;
//
// (2) config.ScanDir validates the language as a single safe path element
//
//	(the stale/migrated project.json defense) — that test lives beside
//	ScanDir in the config package.
func TestValidateInitLanguage(t *testing.T) {
	// auto is the multi-language pin — always legal.
	if err := validateInitLanguage("auto"); err != nil {
		t.Errorf("auto must pass (the multi-language pin): %v", err)
	}
	// The empty form is the flag's default path (normalized to auto
	// before the check) — never an escape.
	if err := validateInitLanguage(""); err != nil {
		t.Errorf("the empty form must pass (normalized to auto first): %v", err)
	}
	// A supported language, exact case.
	if err := validateInitLanguage("python"); err != nil {
		t.Errorf("a supported language must pass: %v", err)
	}

	// THE TYPO SHAPE: the miscased value must reject at the boundary,
	// never persist to print success at init and fail at every later scan.
	err := validateInitLanguage("Python")
	if err == nil {
		t.Fatal("the miscased '-l Python' must REJECT at the boundary (the " +
			"silently-persisted typo shape)")
	}
	if !strings.Contains(err.Error(), "supported") {
		t.Errorf("the rejection must name the supported set (got: %v)", err)
	}

	// THE TRAVERSAL SHAPE: the escape must reject at the boundary, before
	// any write — and the REMEDY must not steer the payload back into
	// init (the #667 F2 lesson: the message's remedy must never
	// prescribe `init -l <the bad value>`; naming the offending INPUT is
	// standard UX, prescribing it as the fix is the hole).
	err = validateInitLanguage("../../../../../../ESCAPED")
	if err == nil {
		t.Fatal("the traversal '-l' must REJECT at the boundary")
	}
	if strings.Contains(err.Error(), "init -l ../../") ||
		strings.Contains(err.Error(), "with -l ../../") {
		t.Errorf("the rejection must not prescribe the payload as the remedy (got: %v)", err)
	}
	if !strings.Contains(err.Error(), "auto") {
		t.Errorf("the rejection must name the honest remedy (auto) (got: %v)", err)
	}

	// Any unsupported value.
	if err := validateInitLanguage("cobol"); err == nil {
		t.Error("an unsupported language must reject")
	}

	// The registry-failure shape: when the supported set cannot be
	// derived, the boundary FAILS CLOSED on the non-auto form (the
	// #667 guard's registry fallthrough lets the off-pin message fire;
	// HERE no pin exists yet, so the honest answer is the refusal, never
	// a silent pass).
	err = validateInitLanguageRegistryDown("go", func() ([]string, error) {
		return nil, errRegistryDown
	})
	if err == nil {
		t.Error("a registry failure must FAIL CLOSED for a non-auto -l " +
			"(never persist an unvalidated value)")
	}
	// ...and auto still passes with the registry down (the multi-language
	// pin needs no membership check).
	if err := validateInitLanguageRegistryDown("auto", func() ([]string, error) {
		return nil, errRegistryDown
	}); err != nil {
		t.Errorf("auto must pass even with the registry down: %v", err)
	}
}

var errRegistryDown = &registryError{}

type registryError struct{}

func (*registryError) Error() string { return "registry unavailable (test)" }

// TestInitBoundaryRejectsBeforeWrite pins the WIRING (the T1's F2: the
// suite stayed green with the boundary CALL removed — the mutant binary
// re-exhibited both #691 shapes). The subprocess form is the honest pin
// for an os.Exit(2) path: the child drives runInit with a bad -l against
// a local repo + a jailed HOME; the parent asserts exit 2 AND that
// NOTHING was written (no project.json, no project dir) — and, per the
// F1 ordering, that no clone/pull could have run first.
func TestInitBoundaryRejectsBeforeWrite(t *testing.T) {
	if os.Getenv("OPENANT_TEST_RUN_INIT") == "1" {
		// the child: runInit exits 2 on the bad -l (or exits 0 and the
		// parent fails the assertion on the exit code)
		initLanguage = os.Getenv("OPENANT_TEST_INIT_LANGUAGE")
		runInit(initCmd, []string{os.Getenv("OPENANT_TEST_REPO")})
		return
	}
	repo, _, _ := initCommitTestRepo(t)
	for _, bad := range []string{"Python", "../../../../../../ESCAPED", "cobol"} {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		// THE JAILED HOME is captured — the walk must scope to the CHILD's
		// home, never the parent's real one (the first draft walked
		// os.Getenv("HOME") — the operator's whole home, a 4-minute
		// false-positive harvest)
		home := t.TempDir()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestInitBoundaryRejectsBeforeWrite")
		cmd.Env = append(os.Environ(),
			"OPENANT_TEST_RUN_INIT=1",
			"OPENANT_TEST_INIT_LANGUAGE="+bad,
			"OPENANT_TEST_REPO="+repo,
			"HOME="+home,
			"XDG_CONFIG_HOME="+home+"/.config",
		)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Errorf("-l %q: the boundary must exit non-zero (got 0)", bad)
		}
		if !strings.Contains(string(out), "supported") && !strings.Contains(string(out), "validated") {
			t.Errorf("-l %q: the child's output must carry the diagnosis (got: %s)", bad, out)
		}
		// NOTHING written: no project.json anywhere under the jailed HOME.
		_ = filepath.Walk(home, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.Name() == "project.json" {
				t.Errorf("-l %q: project.json WAS WRITTEN before the boundary refused (at %s)", bad, path)
			}
			return nil
		})
	}
	// THE F1 ORDERING PIN (the delta round's finding: the gate-moved-back
	// mutant passed the suite — the children above drive LOCAL repos, so
	// the clone/pull branch is invisible to them). The fourth child: the
	// REMOTE form with an UNREACHABLE target (no network) — with the gate
	// FIRST, a bad -l refuses before the project dir is even created; with
	// the gate back below the IsURL branch, MkdirAll creates projects/
	// before the clone fails. The parent asserts the jail holds NO
	// projects dir after the exit-2.
	home2 := t.TempDir()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel2()
	cmd2 := exec.CommandContext(ctx2, os.Args[0], "-test.run=TestInitBoundaryRejectsBeforeWrite")
	cmd2.Env = append(os.Environ(),
		"OPENANT_TEST_RUN_INIT=1",
		"OPENANT_TEST_INIT_LANGUAGE=Python",
		"OPENANT_TEST_REPO=https://127.0.0.1:1/unreachable/repo",
		"HOME="+home2,
		"XDG_CONFIG_HOME="+home2+"/.config",
	)
	out2, err2 := cmd2.CombinedOutput()
	if err2 == nil {
		t.Errorf("the remote-form bad -l must exit non-zero (got 0: %s)", out2)
	}
	if !strings.Contains(string(out2), "supported") {
		t.Errorf("the remote-form child must print the boundary diagnosis BEFORE the clone attempt (got: %s)", out2)
	}
	_ = filepath.Walk(home2, func(path string, info os.FileInfo, werr error) error {
		if werr != nil {
			return nil
		}
		if info.IsDir() && strings.Contains(path, "projects") {
			t.Errorf("the gate must fire BEFORE the project dir is created — found %s (the gate-late mutant)", path)
		}
		return nil
	})
}
