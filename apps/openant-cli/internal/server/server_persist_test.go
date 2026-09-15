package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestPersistTerminalStatusMerges(t *testing.T) {
	// #320 wave r2: the terminal status merges into the creation meta —
	// the first persist clobbered it (a broken any()-cast reset the map;
	// the real e2e caught it: a restart loses the distinct timeout state).
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "meta.json"), []byte(`{"id":"x","repo":"r","started_at":"t"}`), 0640)
	j := &Job{mu: sync.Mutex{}, outDir: d}
	j.persistTerminalStatus("timeout")
	var m map[string]any
	data, _ := os.ReadFile(filepath.Join(d, "meta.json"))
	json.Unmarshal(data, &m)
	t.Logf("meta: %v", m)
	if m["status"] != "timeout" || m["id"] != "x" || m["repo"] != "r" {
		t.Fatalf("the merge lost keys: %v", m)
	}
}

// wave r3: the persisted status must round-TRIP — the reload path
// (recoverJobs) reads it back and a timed-out job stays timed-out across a
// restart instead of degrading to a generic error.
func TestPersistedStatusRestores(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "meta.json"),
		[]byte(`{"id":"x","repo":"r","started_at":"2026-08-31T00:00:00Z","status":"timeout"}`), 0640)
	// recoverJobs' meta read: the jobMeta round-trip carries the status
	data, _ := os.ReadFile(filepath.Join(d, "meta.json"))
	var m jobMeta
	if err := json.Unmarshal(data, &m); err != nil || m.Status != StatusTimeout {
		t.Fatalf("the persisted status must round-trip; got %+v err=%v", m, err)
	}
}

// wave r4 finding 1: the ACTUAL recoverJobs path — a timed-out job's meta
// (status: timeout, no report.html) must restore as StatusTimeout, not the
// report.html-inferred error.
func TestRecoverJobsRestoresTimeoutStatus(t *testing.T) {
	dir := t.TempDir()
	id := "deadbeef00112233"
	jobDir := filepath.Join(dir, id)
	if err := os.MkdirAll(jobDir, 0750); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(jobDir, "meta.json"),
		[]byte(`{"id":"`+id+`","repo":"r","started_at":"2026-08-31T00:00:00Z","status":"timeout"}`), 0640)

	s := &Server{outDir: dir, mgr: newManager(dir)}
	s.recoverJobs()

	job, ok := s.mgr.get(id)
	if !ok {
		t.Fatalf("the job was not recovered")
	}
	if job.Status != StatusTimeout {
		t.Fatalf("a persisted timeout must restore as timeout; got %q", job.Status)
	}
}
