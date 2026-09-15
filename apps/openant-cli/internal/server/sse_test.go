package server

import (
	"net/http/httptest"
	"testing"
)

// A crafted Last-Event-ID of MaxInt64 makes start=n+1 overflow negative; the
// resume handler must clamp it instead of panicking on initial[<0].
func TestScanLogsLastEventIDOverflow(t *testing.T) {
	s := &Server{mgr: newManager(t.TempDir())}
	job := &Job{ID: "a1b2c3d4e5f60718", Status: StatusDone, LogBuf: []string{"one", "two"}}
	s.mgr.add(job)

	for _, leid := range []string{"9223372036854775807", "-1", "notanumber", "1", ""} {
		req := httptest.NewRequest("GET", "/scan/"+job.ID+"/logs", nil)
		req.SetPathValue("id", job.ID)
		if leid != "" {
			req.Header.Set("Last-Event-ID", leid)
		}
		rec := httptest.NewRecorder()
		// Must not panic for any Last-Event-ID value.
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic with Last-Event-ID=%q: %v", leid, r)
				}
			}()
			s.handleScanLogs(rec, req)
		}()
	}
}
