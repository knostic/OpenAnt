package server

import (
	"context"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func formBody(s string) io.ReadCloser { return io.NopCloser(strings.NewReader(s)) }

// While draining, handleStartScan must 503 without creating disk/manager state
// and without leaking a WaitGroup count (which would make WaitShutdown hang).
func TestDrainGateNoOrphanNoLeak(t *testing.T) {
	s := &Server{
		outDir: t.TempDir(), mgr: newManager(t.TempDir()), pythonPath: "/bin/false",
		sem: make(chan struct{}, 4), shutdownDone: make(chan struct{}),
		csrfToken: "tok", draining: true,
	}
	req := httptest.NewRequest("POST", "/scan", formBody("csrf=tok&repo=/tmp/x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()
	s.handleStartScan(rec, req)

	if rec.Code != 503 {
		t.Errorf("expected 503 while draining, got %d", rec.Code)
	}
	if n := len(s.mgr.all()); n != 0 {
		t.Errorf("draining 503 created %d job(s) (orphan state)", n)
	}
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("WaitGroup leaked on the drain path")
	}
}

// A job whose context is cancelled before it does real work must exit with a
// terminal status (not "running"), so an open SSE stream receives done.
func TestCancelledJobIsTerminal(t *testing.T) {
	s := &Server{
		outDir: t.TempDir(), mgr: newManager(t.TempDir()), pythonPath: "/bin/false",
		sem: make(chan struct{}, 4), shutdownDone: make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	job := &Job{ID: "aabbccdd11223344", Repo: "/nonexistent/local/path", Status: StatusRunning, Cancel: cancel, ctx: ctx, done: make(chan struct{})}
	s.mgr.add(job)
	s.wg.Add(1)
	cancel()

	done := make(chan struct{})
	go func() { s.runJob(job); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runJob hung on a cancelled job")
	}
	job.mu.Lock()
	st := job.Status
	job.mu.Unlock()
	if st == StatusRunning {
		t.Errorf("cancelled job left Status=running (SSE would tick forever)")
	}
}

// recoverJobs must only restore valid job-ID dirs (else they are undeletable)
// and must sanitize persisted log lines (a repo can write logs.txt) so a bare CR
// cannot inject an SSE field/event on replay.
func TestRecoverJobsHardening(t *testing.T) {
	dir := t.TempDir()
	hexID := "a1b2c3d4e5f60718"
	jd := filepath.Join(dir, hexID)
	os.MkdirAll(jd, 0750)
	os.WriteFile(filepath.Join(jd, "report.html"), []byte("<html>"), 0640)
	os.WriteFile(filepath.Join(jd, "logs.txt"), []byte("line1\rinjected\nline2\n"), 0640)
	os.MkdirAll(filepath.Join(dir, "NotAJob"), 0750)
	os.MkdirAll(filepath.Join(dir, "zzz"), 0750)

	s := &Server{outDir: dir, mgr: newManager(dir)}
	s.recoverJobs()

	if _, ok := s.mgr.get(hexID); !ok {
		t.Errorf("hex job %s not recovered", hexID)
	}
	for _, bad := range []string{"NotAJob", "zzz"} {
		if _, ok := s.mgr.get(bad); ok {
			t.Errorf("non-hex dir %q wrongly recovered (would be undeletable)", bad)
		}
	}
	job, _ := s.mgr.get(hexID)
	for _, l := range job.LogBuf {
		if strings.ContainsRune(l, '\r') {
			t.Errorf("bare CR survived in recovered log line: %q", l)
		}
	}
}

// handleDeleteScan must wait for the runner (done) to stop before RemoveAll, so
// a late write can't resurrect the deleted job. A recovered job (done==nil)
// deletes immediately.
func TestDeleteWaitsForRunner(t *testing.T) {
	s := &Server{
		outDir: t.TempDir(), mgr: newManager(t.TempDir()), csrfToken: "tok",
	}
	_, cancel := context.WithCancel(context.Background())
	job := &Job{ID: "abcdef0123456789", Status: StatusRunning, Cancel: cancel, done: make(chan struct{})}
	s.mgr.add(job)
	os.MkdirAll(filepath.Join(s.outDir, job.ID), 0750)

	req := httptest.NewRequest("DELETE", "/scan/"+job.ID, nil)
	req.SetPathValue("id", job.ID)
	req.Header.Set("X-CSRF-Token", "tok")
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()

	returned := make(chan struct{})
	go func() { s.handleDeleteScan(rec, req); close(returned) }()

	// Must still be waiting on the open done channel.
	select {
	case <-returned:
		t.Fatal("delete returned before the runner signaled done")
	case <-time.After(150 * time.Millisecond):
	}
	close(job.done) // runner finished
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("delete did not return after done closed")
	}
	if _, err := os.Stat(filepath.Join(s.outDir, job.ID)); !os.IsNotExist(err) {
		t.Errorf("job dir not removed after delete")
	}
}

// addLog must bound LogBuf memory by a HARD byte ceiling (projected-size check),
// cap-and-stop so SSE replay indices stay stable, and emit the marker once.
func TestAddLogByteCapIsStrict(t *testing.T) {
	j := &Job{}
	line := strings.Repeat("x", 64*1024) // 64 KiB lines
	for i := 0; i < 1000; i++ {          // 1000 * 64KiB = 64 MiB attempted, cap is 8 MiB
		j.addLog(line)
	}
	total := 0
	markers := 0
	for _, l := range j.LogBuf {
		total += len(l)
		if strings.HasPrefix(l, "[log truncated") {
			markers++
		}
	}
	const maxLogBytes = 8 << 20
	// Hard ceiling: payload bytes never exceed the cap (marker is tiny/excluded).
	if j.logBytes > maxLogBytes {
		t.Errorf("logBytes %d exceeded hard cap %d", j.logBytes, maxLogBytes)
	}
	if markers != 1 {
		t.Errorf("expected exactly one truncation marker, got %d", markers)
	}
	if !j.logCapped {
		t.Error("logCapped not set after hitting the cap")
	}
	// Cap-and-stop: once capped, further addLog is a no-op (SSE indices stable).
	n := len(j.LogBuf)
	j.addLog("after cap")
	if len(j.LogBuf) != n {
		t.Error("addLog appended after cap (SSE index instability)")
	}
	t.Logf("capped at logBytes=%d, lines=%d, total-incl-marker=%d", j.logBytes, len(j.LogBuf), total)
}

// A symlink planted in the output dir (disclosures/*.md, report.html, summary)
// must never be enumerated or served — it could point at a host secret. The job
// output dir holds files derived from an untrusted scanned repo.
func TestSymlinkOutputsRejected(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secret, []byte("HOST SECRET"), 0600)

	discDir := filepath.Join(root, "report", "disclosures")
	os.MkdirAll(discDir, 0750)
	os.WriteFile(filepath.Join(discDir, "DISCLOSURE_01_REAL.md"), []byte("# Real"), 0640)
	os.Symlink(secret, filepath.Join(discDir, "DISCLOSURE_99_EVIL.md"))

	got := findDisclosures(root)
	for _, p := range got {
		if strings.Contains(p, "EVIL") {
			t.Errorf("findDisclosures enumerated a symlink: %s", p)
		}
	}
	if len(got) != 1 {
		t.Errorf("expected 1 real disclosure, got %d: %v", len(got), got)
	}
	// The helper itself: symlink rejected, regular file within root accepted.
	if isRegularNoSymlink(root, filepath.Join(discDir, "DISCLOSURE_99_EVIL.md")) {
		t.Error("isRegularNoSymlink accepted a symlink")
	}
	if !isRegularNoSymlink(root, filepath.Join(discDir, "DISCLOSURE_01_REAL.md")) {
		t.Error("isRegularNoSymlink rejected a real file")
	}
}

// openRegularInRoot must refuse a symlink at read time (O_NOFOLLOW), closing the
// check-then-read TOCTOU: even if a path entered the allowlist as a regular file,
// a later swap to a symlink is refused atomically at open.
func TestOpenRegularInRootRefusesSymlink(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secret, []byte("HOST SECRET"), 0600)
	link := filepath.Join(root, "swapped.md")
	os.Symlink(secret, link)
	if f, _, err := openRegularInRoot(root, link); err == nil {
		f.Close()
		t.Error("openRegularInRoot opened a symlink (O_NOFOLLOW not effective)")
	}
	// a real regular file within root opens fine
	real := filepath.Join(root, "real.md")
	os.WriteFile(real, []byte("hi"), 0640)
	f, _, err := openRegularInRoot(root, real)
	if err != nil {
		t.Errorf("openRegularInRoot rejected a real file: %v", err)
	} else {
		f.Close()
	}
}
